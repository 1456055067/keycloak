//! Authorization endpoint handler.
//!
//! Implements GET/POST `/auth` for OAuth 2.0 and `OpenID` Connect authorization.
//!
//! Supports the following flows:
//! - Authorization Code Flow (`response_type=code`)
//! - Implicit Flow (`response_type=token` or `response_type=id_token`)
//! - Hybrid Flow (`response_type=code token`, `code id_token`, etc.)

use axum::{
    Form,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::error::OidcError;
use crate::request::AuthorizationRequest;
use crate::types::{CodeChallengeMethod, ResponseMode, ResponseTypes};

use super::state::{OidcState, RealmProvider};

/// Authorization code data stored between authorization and token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The authorization code value.
    pub code: String,

    /// Client ID that requested the code.
    pub client_id: String,

    /// Subject (user) ID.
    pub subject: String,

    /// Redirect URI used in the request.
    pub redirect_uri: String,

    /// Granted scopes.
    pub scope: String,

    /// Nonce from the authorization request (for OIDC).
    pub nonce: Option<String>,

    /// PKCE code challenge.
    pub code_challenge: Option<String>,

    /// PKCE code challenge method.
    pub code_challenge_method: Option<CodeChallengeMethod>,

    /// State parameter from the request.
    pub state: Option<String>,

    /// Session ID (if session-bound).
    pub session_id: Option<String>,

    /// Expiration timestamp (Unix epoch seconds).
    pub expires_at: i64,

    /// Whether this code has been used.
    pub used: bool,
}

/// Authorization response for successful authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// Authorization code (for code flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// Access token (for implicit/hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// Token type (typically "Bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// ID token (for OIDC implicit/hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,

    /// Token expiration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,

    /// State parameter from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Scope (if different from requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Session state for session management.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
}

/// Error response for authorization endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationErrorResponse {
    /// Error code.
    pub error: String,

    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// URI with more information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,

    /// State parameter from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// GET `/auth`
///
/// Authorization endpoint - initiates the authorization flow.
///
/// # Parameters
///
/// Required:
/// - `response_type`: "code", "token", "`id_token`", or combinations
/// - `client_id`: The client identifier
/// - `redirect_uri`: Where to redirect after authorization
/// - `scope`: Requested scopes (must include "openid" for OIDC)
///
/// Optional:
/// - `state`: CSRF protection (recommended)
/// - `nonce`: Replay protection (required for implicit/hybrid)
/// - `prompt`: "none", "login", "consent", "`select_account`"
/// - `code_challenge`: PKCE code challenge
/// - `code_challenge_method`: "plain" or "S256"
///
/// # Responses
///
/// - Redirect to login page (if authentication needed)
/// - Redirect to consent page (if consent needed)
/// - Redirect to `redirect_uri` with code/tokens (if `prompt=none` and authenticated)
/// - Error redirect (if validation fails)
pub async fn authorize_get<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    Query(request): Query<AuthorizationRequest>,
) -> impl IntoResponse {
    handle_authorization_request(&state, &realm, &request).await
}

/// POST `/auth`
///
/// Same as GET but accepts form-encoded parameters.
pub async fn authorize_post<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    Form(request): Form<AuthorizationRequest>,
) -> impl IntoResponse {
    handle_authorization_request(&state, &realm, &request).await
}

/// Handles the authorization request.
async fn handle_authorization_request<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &AuthorizationRequest,
) -> Response {
    // Validate the request and get redirect_uri early for error responses
    let redirect_uri = match validate_request_early(state, realm, request).await {
        Ok(uri) => uri,
        Err(err) => {
            // If we can't validate redirect_uri, show error page
            return error_page(&err);
        }
    };

    // Now we can redirect errors to the client
    let response_mode = determine_response_mode(request);

    // Full validation
    match validate_authorization_request(state, realm, request).await {
        Ok(()) => {}
        Err(err) => {
            return build_error_redirect(&redirect_uri, &err, request.state.as_deref(), response_mode);
        }
    }

    // Check if user is authenticated
    // TODO: Integrate with session management
    let user_authenticated = false;
    let user_id = "unknown"; // Would come from session

    // Handle prompt=none
    if request.is_prompt_none() {
        if !user_authenticated {
            return build_error_redirect(
                &redirect_uri,
                &OidcError::LoginRequired,
                request.state.as_deref(),
                response_mode,
            );
        }
        // TODO: Check if consent is already granted
        // For now, assume consent is not granted
        return build_error_redirect(
            &redirect_uri,
            &OidcError::ConsentRequired,
            request.state.as_deref(),
            response_mode,
        );
    }

    // If not authenticated, redirect to login
    if !user_authenticated {
        return redirect_to_login(realm, request);
    }

    // If consent required, redirect to consent page
    // TODO: Check if consent is already granted for these scopes
    if request.requires_consent() {
        return redirect_to_consent(realm, request);
    }

    // User is authenticated and consent is granted - generate response
    match generate_authorization_response(state, realm, request, user_id).await {
        Ok(response) => build_success_redirect(&redirect_uri, &response, response_mode),
        Err(err) => build_error_redirect(&redirect_uri, &err, request.state.as_deref(), response_mode),
    }
}

/// Early validation that must pass before we can redirect errors.
async fn validate_request_early<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &AuthorizationRequest,
) -> Result<String, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Validate client_id exists
    // TODO: Look up client in database
    if request.client_id.is_empty() {
        return Err(OidcError::InvalidRequest("client_id is required".to_string()));
    }

    // Validate redirect_uri
    let redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("redirect_uri is required".to_string()))?;

    // TODO: Verify redirect_uri is registered for this client
    // For now, just validate it's a valid URI
    if !redirect_uri.starts_with("http://") && !redirect_uri.starts_with("https://") {
        return Err(OidcError::InvalidRequest(
            "redirect_uri must be an absolute URI".to_string(),
        ));
    }

    Ok(redirect_uri.clone())
}

/// Full validation of authorization request.
#[allow(clippy::unused_async)]
async fn validate_authorization_request<R: RealmProvider>(
    _state: &OidcState<R>,
    _realm: &str,
    request: &AuthorizationRequest,
) -> Result<(), OidcError> {
    // Parse and validate response_type
    let response_types = ResponseTypes::from_str(&request.response_type)
        .map_err(|_| OidcError::UnsupportedResponseType(request.response_type.clone()))?;

    // Validate scope
    if request.scope.is_none() || request.scope.as_ref().is_some_and(String::is_empty) {
        return Err(OidcError::InvalidScope("scope is required".to_string()));
    }

    // For OIDC flows, validate openid scope is present
    let is_oidc = request.is_oidc_request();

    // Implicit and hybrid flows require nonce for OIDC
    if is_oidc
        && (response_types.is_implicit_flow() || response_types.is_hybrid_flow())
        && request.nonce.is_none()
    {
        return Err(OidcError::InvalidRequest(
            "nonce is required for implicit and hybrid flows".to_string(),
        ));
    }

    // Validate PKCE for code flows
    if response_types.is_code_flow() || response_types.is_hybrid_flow() {
        validate_pkce(request)?;
    }

    // Validate prompt combinations
    let prompts = request.prompt_values();
    if prompts.contains(&crate::types::Prompt::None) && prompts.len() > 1 {
        return Err(OidcError::InvalidRequest(
            "prompt=none cannot be combined with other prompt values".to_string(),
        ));
    }

    Ok(())
}

/// Validates PKCE parameters.
fn validate_pkce(request: &AuthorizationRequest) -> Result<(), OidcError> {
    match (&request.code_challenge, &request.code_challenge_method) {
        (Some(challenge), method) => {
            // Validate challenge format
            if challenge.len() < 43 || challenge.len() > 128 {
                return Err(OidcError::InvalidRequest(
                    "code_challenge must be between 43 and 128 characters".to_string(),
                ));
            }

            // Validate characters (base64url without padding)
            if !challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(OidcError::InvalidRequest(
                    "code_challenge contains invalid characters".to_string(),
                ));
            }

            // Default to S256 if method not specified
            let method = method.unwrap_or(CodeChallengeMethod::S256);

            // Warn if using plain (not recommended)
            if method == CodeChallengeMethod::Plain {
                // In production, might want to reject plain unless specifically allowed
                // For now, allow it but S256 is strongly recommended
            }

            Ok(())
        }
        (None, Some(_)) => {
            Err(OidcError::InvalidRequest(
                "code_challenge_method requires code_challenge".to_string(),
            ))
        }
        (None, None) => {
            // PKCE is optional but recommended
            // TODO: Make PKCE required for public clients
            Ok(())
        }
    }
}

/// Determines the response mode based on request and `response_type`.
fn determine_response_mode(request: &AuthorizationRequest) -> ResponseMode {
    // If explicitly specified, use that
    if let Some(mode) = &request.response_mode {
        return *mode;
    }

    // Parse response type to determine default
    let response_types = ResponseTypes::from_str(&request.response_type).unwrap_or_default();

    // Default modes:
    // - Code flow: query
    // - Implicit/Hybrid flow: fragment
    if response_types.is_code_flow() {
        ResponseMode::Query
    } else {
        ResponseMode::Fragment
    }
}

/// Generates the authorization response (code, tokens, etc.).
#[allow(clippy::unused_async)]
async fn generate_authorization_response<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &AuthorizationRequest,
    user_id: &str,
) -> Result<AuthorizationResponse, OidcError> {
    let response_types = ResponseTypes::from_str(&request.response_type)
        .map_err(|_| OidcError::UnsupportedResponseType(request.response_type.clone()))?;

    let mut response = AuthorizationResponse {
        code: None,
        access_token: None,
        token_type: None,
        id_token: None,
        expires_in: None,
        state: request.state.clone(),
        scope: request.scope.clone(),
        session_state: None,
    };

    // Generate authorization code for code and hybrid flows
    if response_types.0.contains(&crate::types::ResponseType::Code) {
        let code = generate_authorization_code(state, realm, request, user_id).await?;
        response.code = Some(code);
    }

    // Generate access token for implicit and hybrid flows
    if response_types.0.contains(&crate::types::ResponseType::Token) {
        let token_manager = state.realm_provider.get_token_manager(realm).await?;
        let token_response = token_manager
            .create_token_response(
                user_id,
                &request.client_id,
                request.scope.as_deref().unwrap_or("openid"),
                None, // session_id
                request.nonce.as_deref(),
                false, // don't include id_token here, handle separately
                false, // no refresh token in implicit flow
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create token: {e}")))?;

        response.access_token = Some(token_response.access_token);
        response.token_type = Some(token_response.token_type);
        response.expires_in = Some(token_response.expires_in);
    }

    // Generate ID token for OIDC flows that request it
    if response_types.0.contains(&crate::types::ResponseType::IdToken) {
        let token_manager = state.realm_provider.get_token_manager(realm).await?;

        // For hybrid flow with code, include c_hash
        // For implicit flow with access_token, include at_hash
        let token_response = token_manager
            .create_token_response(
                user_id,
                &request.client_id,
                request.scope.as_deref().unwrap_or("openid"),
                None, // session_id
                request.nonce.as_deref(),
                true,  // include id_token
                false, // no refresh token
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create id_token: {e}")))?;

        response.id_token = token_response.id_token;
    }

    Ok(response)
}

/// Generates an authorization code.
#[allow(clippy::unused_async)]
async fn generate_authorization_code<R: RealmProvider>(
    _state: &OidcState<R>,
    _realm: &str,
    request: &AuthorizationRequest,
    user_id: &str,
) -> Result<String, OidcError> {
    // Generate a secure random code
    use std::time::{SystemTime, UNIX_EPOCH};

    let code = generate_secure_code();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Safe conversion: current timestamp fits in i64 until year 292 billion
    #[allow(clippy::cast_possible_wrap)]
    let expires_at = (now_secs + 600) as i64; // 10 minute expiration

    let _auth_code = AuthorizationCode {
        code: code.clone(),
        client_id: request.client_id.clone(),
        subject: user_id.to_string(),
        redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
        scope: request.scope.clone().unwrap_or_default(),
        nonce: request.nonce.clone(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: request.code_challenge_method,
        state: request.state.clone(),
        session_id: None,
        expires_at,
        used: false,
    };

    // TODO: Store the authorization code
    // state.code_store.store_code(realm, &auth_code).await?;

    Ok(code)
}

/// Generates a cryptographically secure random code.
fn generate_secure_code() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // TODO: Use proper cryptographic random generator
    // For now, use a simple hash-based approach
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // In production, use: rand::thread_rng().sample_iter(&Alphanumeric).take(32).collect()
    format!("{timestamp:x}")
}

/// Builds a success redirect response.
fn build_success_redirect(
    redirect_uri: &str,
    response: &AuthorizationResponse,
    mode: ResponseMode,
) -> Response {
    let params = build_response_params(response);
    build_redirect(redirect_uri, &params, mode)
}

/// Builds an error redirect response.
fn build_error_redirect(
    redirect_uri: &str,
    error: &OidcError,
    state: Option<&str>,
    mode: ResponseMode,
) -> Response {
    let error_response = AuthorizationErrorResponse {
        error: error.error_code().to_string(),
        error_description: Some(error.to_string()),
        error_uri: None,
        state: state.map(ToString::to_string),
    };

    let params = build_error_params(&error_response);
    build_redirect(redirect_uri, &params, mode)
}

/// Builds response parameters for redirect.
fn build_response_params(response: &AuthorizationResponse) -> Vec<(String, String)> {
    let mut params = Vec::new();

    if let Some(ref code) = response.code {
        params.push(("code".to_string(), code.clone()));
    }
    if let Some(ref token) = response.access_token {
        params.push(("access_token".to_string(), token.clone()));
    }
    if let Some(ref token_type) = response.token_type {
        params.push(("token_type".to_string(), token_type.clone()));
    }
    if let Some(ref id_token) = response.id_token {
        params.push(("id_token".to_string(), id_token.clone()));
    }
    if let Some(expires_in) = response.expires_in {
        params.push(("expires_in".to_string(), expires_in.to_string()));
    }
    if let Some(ref state) = response.state {
        params.push(("state".to_string(), state.clone()));
    }
    if let Some(ref scope) = response.scope {
        params.push(("scope".to_string(), scope.clone()));
    }
    if let Some(ref session_state) = response.session_state {
        params.push(("session_state".to_string(), session_state.clone()));
    }

    params
}

/// Builds error parameters for redirect.
fn build_error_params(error: &AuthorizationErrorResponse) -> Vec<(String, String)> {
    let mut params = vec![("error".to_string(), error.error.clone())];

    if let Some(ref desc) = error.error_description {
        params.push(("error_description".to_string(), desc.clone()));
    }
    if let Some(ref uri) = error.error_uri {
        params.push(("error_uri".to_string(), uri.clone()));
    }
    if let Some(ref state) = error.state {
        params.push(("state".to_string(), state.clone()));
    }

    params
}

/// Builds a redirect response with the given parameters.
fn build_redirect(redirect_uri: &str, params: &[(String, String)], mode: ResponseMode) -> Response {
    let encoded_params: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    match mode {
        ResponseMode::Query => {
            let separator = if redirect_uri.contains('?') { "&" } else { "?" };
            let url = format!("{redirect_uri}{separator}{encoded_params}");
            Redirect::to(&url).into_response()
        }
        ResponseMode::Fragment => {
            let url = format!("{redirect_uri}#{encoded_params}");
            Redirect::to(&url).into_response()
        }
        ResponseMode::FormPost => {
            // Generate an HTML page that auto-submits a form
            let form_fields: String = params
                .iter()
                .map(|(k, v)| {
                    format!(
                        r#"<input type="hidden" name="{}" value="{}" />"#,
                        html_escape(k),
                        html_escape(v)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Submitting...</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{}">
{}
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>"#,
                html_escape(redirect_uri),
                form_fields
            );

            (StatusCode::OK, Html(html)).into_response()
        }
    }
}

/// Simple HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Redirects to the login page.
fn redirect_to_login(realm: &str, request: &AuthorizationRequest) -> Response {
    // Build the login URL with the original authorization parameters
    let auth_params = serde_urlencoded::to_string(request).unwrap_or_default();
    let login_url = format!(
        "/realms/{}/login?{}",
        urlencoding::encode(realm),
        auth_params
    );
    Redirect::to(&login_url).into_response()
}

/// Redirects to the consent page.
fn redirect_to_consent(realm: &str, request: &AuthorizationRequest) -> Response {
    let auth_params = serde_urlencoded::to_string(request).unwrap_or_default();
    let consent_url = format!(
        "/realms/{}/consent?{}",
        urlencoding::encode(realm),
        auth_params
    );
    Redirect::to(&consent_url).into_response()
}

/// Shows an error page when we can't redirect.
fn error_page(error: &OidcError) -> Response {
    let html = format!(
        r"<!DOCTYPE html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h1>Authorization Error</h1>
<p><strong>Error:</strong> {}</p>
<p><strong>Description:</strong> {}</p>
</body>
</html>",
        html_escape(error.error_code()),
        html_escape(&error.to_string())
    );

    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pkce_valid_challenge() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            scope: Some("openid".to_string()),
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            request: None,
            request_uri: None,
            claims: None,
        };

        assert!(validate_pkce(&request).is_ok());
    }

    #[test]
    fn validate_pkce_too_short() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            scope: Some("openid".to_string()),
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            code_challenge: Some("tooshort".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            request: None,
            request_uri: None,
            claims: None,
        };

        assert!(validate_pkce(&request).is_err());
    }

    #[test]
    fn determine_response_mode_defaults() {
        // Code flow defaults to query
        let code_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            code_challenge: None,
            code_challenge_method: None,
            request: None,
            request_uri: None,
            claims: None,
        };
        assert_eq!(determine_response_mode(&code_request), ResponseMode::Query);

        // Implicit flow defaults to fragment
        let implicit_request = AuthorizationRequest {
            response_type: "token".to_string(),
            ..code_request.clone()
        };
        assert_eq!(determine_response_mode(&implicit_request), ResponseMode::Fragment);

        // Explicit response_mode overrides default
        let explicit_request = AuthorizationRequest {
            response_type: "code".to_string(),
            response_mode: Some(ResponseMode::Fragment),
            ..code_request
        };
        assert_eq!(determine_response_mode(&explicit_request), ResponseMode::Fragment);
    }

    #[test]
    fn build_response_params_includes_all_fields() {
        let response = AuthorizationResponse {
            code: Some("test_code".to_string()),
            access_token: None,
            token_type: None,
            id_token: None,
            expires_in: None,
            state: Some("test_state".to_string()),
            scope: Some("openid".to_string()),
            session_state: None,
        };

        let params = build_response_params(&response);
        assert!(params.iter().any(|(k, v)| k == "code" && v == "test_code"));
        assert!(params.iter().any(|(k, v)| k == "state" && v == "test_state"));
        assert!(params.iter().any(|(k, v)| k == "scope" && v == "openid"));
    }

    #[test]
    fn html_escape_special_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape(r#"test"value"#), "test&quot;value");
    }
}
