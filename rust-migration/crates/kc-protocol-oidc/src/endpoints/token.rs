//! Token endpoint handler.
//!
//! Implements POST `/token` for all OAuth 2.0 grant types:
//! - `authorization_code`
//! - `client_credentials`
//! - `refresh_token`
//! - `password` (deprecated, but supported)
//! - `urn:ietf:params:oauth:grant-type:device_code`
//! - `urn:ietf:params:oauth:grant-type:token-exchange`

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::error::{ErrorResponse, OidcError};
use crate::request::TokenRequest;
use crate::token::TokenResponse;
use crate::types::GrantType;

use super::state::{OidcState, RealmProvider};

/// POST `/token`
///
/// Exchanges credentials for tokens based on the grant type.
///
/// # Supported Grant Types
///
/// - `authorization_code`: Exchange auth code for tokens
/// - `client_credentials`: Client authenticates directly
/// - `refresh_token`: Exchange refresh token for new tokens
/// - `password`: Username/password authentication (deprecated)
/// - `urn:ietf:params:oauth:grant-type:device_code`: Device authorization
/// - `urn:ietf:params:oauth:grant-type:token-exchange`: Token exchange (RFC 8693)
///
/// # Responses
///
/// - 200 OK: Token response JSON
/// - 400 Bad Request: Invalid request or grant
/// - 401 Unauthorized: Client authentication failed
/// - 500 Internal Server Error: Server error
pub async fn token<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> impl IntoResponse {
    match handle_token_request(&state, &realm, &headers, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// Handles the token request based on grant type.
async fn handle_token_request<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<TokenResponse, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Parse grant type
    let grant_type = request
        .parsed_grant_type()
        .map_err(|_| OidcError::UnsupportedGrantType(request.grant_type.clone()))?;

    // Authenticate client (extract from headers or form)
    let (client_id, client_secret) = extract_client_credentials(headers, request)?;

    // Handle based on grant type
    match grant_type {
        GrantType::AuthorizationCode => {
            handle_authorization_code_grant(state, realm, request, &client_id, client_secret.as_deref()).await
        }
        GrantType::ClientCredentials => {
            handle_client_credentials_grant(state, realm, &client_id, client_secret.as_deref(), request.scope.as_deref()).await
        }
        GrantType::RefreshToken => {
            handle_refresh_token_grant(state, realm, request, &client_id).await
        }
        GrantType::Password => {
            handle_password_grant(state, realm, request, &client_id).await
        }
        GrantType::DeviceCode => {
            handle_device_code_grant(state, realm, request, &client_id).await
        }
        GrantType::TokenExchange => {
            handle_token_exchange_grant(state, realm, request, &client_id).await
        }
    }
}

/// Extracts client credentials from Authorization header or form body.
fn extract_client_credentials(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<(String, Option<String>), OidcError> {
    // Try Authorization header first (Basic auth)
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OidcError::InvalidClient("invalid authorization header".to_string()))?;

        if let Some(basic_auth) = auth_str.strip_prefix("Basic ") {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                basic_auth.trim(),
            )
            .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

            let credentials = String::from_utf8(decoded)
                .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

            let (client_id, client_secret) = credentials
                .split_once(':')
                .ok_or_else(|| OidcError::InvalidClient("invalid basic auth format".to_string()))?;

            return Ok((
                urlencoding::decode(client_id)
                    .map_err(|_| OidcError::InvalidClient("invalid client_id encoding".to_string()))?
                    .to_string(),
                Some(
                    urlencoding::decode(client_secret)
                        .map_err(|_| OidcError::InvalidClient("invalid client_secret encoding".to_string()))?
                        .to_string(),
                ),
            ));
        }
    }

    // Fall back to form body
    let client_id = request
        .client_id
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("client_id is required".to_string()))?
        .clone();

    Ok((client_id, request.client_secret.clone()))
}

/// Handles authorization code grant.
#[allow(clippy::unused_async)]
async fn handle_authorization_code_grant<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &TokenRequest,
    client_id: &str,
    _client_secret: Option<&str>,
) -> Result<TokenResponse, OidcError> {
    // Validate required parameters
    let _code = request
        .code
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("code is required".to_string()))?;

    let _redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("redirect_uri is required".to_string()))?;

    // TODO: Implement authorization code validation
    // 1. Look up the code in the database
    // 2. Verify it hasn't expired
    // 3. Verify it matches the client_id
    // 4. Verify the redirect_uri matches
    // 5. Verify PKCE code_verifier if code_challenge was used
    // 6. Mark the code as used (single-use)

    // For now, return a placeholder implementation
    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Create a token response
    // In a real implementation, the subject would come from the stored auth code
    token_manager
        .create_token_response(
            "placeholder-subject", // Would come from stored auth code
            client_id,
            "openid", // Would come from stored auth code
            None,     // session_id
            None,     // nonce
            true,     // include_id_token
            true,     // include_refresh_token
        )
        .map_err(|e| OidcError::ServerError(format!("failed to create token: {e}")))
}

/// Handles client credentials grant.
#[allow(clippy::unused_async)]
async fn handle_client_credentials_grant<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scope: Option<&str>,
) -> Result<TokenResponse, OidcError> {
    // Client credentials grant requires client authentication
    let _secret = client_secret
        .ok_or_else(|| OidcError::InvalidClient("client_secret is required for client_credentials grant".to_string()))?;

    // TODO: Implement client authentication
    // 1. Look up the client in the database
    // 2. Verify the client_secret
    // 3. Verify the client is allowed to use client_credentials grant

    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // For client_credentials, the subject is the client itself
    // No ID token or refresh token is issued
    token_manager
        .create_token_response(
            client_id,                                  // subject is the service account
            client_id,
            scope.unwrap_or("openid"),
            None,  // no session
            None,  // no nonce
            false, // no ID token for client credentials
            false, // typically no refresh token for client credentials
        )
        .map_err(|e| OidcError::ServerError(format!("failed to create token: {e}")))
}

/// Handles refresh token grant.
#[allow(clippy::unused_async)]
async fn handle_refresh_token_grant<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &TokenRequest,
    client_id: &str,
) -> Result<TokenResponse, OidcError> {
    let refresh_token = request
        .refresh_token
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("refresh_token is required".to_string()))?;

    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Validate the refresh token
    let claims = token_manager
        .validate_refresh_token(refresh_token)
        .map_err(|e| OidcError::InvalidGrant(format!("invalid refresh token: {e}")))?;

    // Verify the client_id matches
    if claims.azp.as_deref() != Some(client_id) {
        return Err(OidcError::InvalidGrant("refresh token was not issued to this client".to_string()));
    }

    // TODO: Check if the session is still valid
    // TODO: Check if the refresh token has been revoked

    // Issue new tokens
    token_manager
        .create_token_response(
            &claims.sub,
            client_id,
            claims.scope.as_deref().unwrap_or("openid"),
            claims.sid.as_deref(),
            claims.nonce.as_deref(),
            true,  // include ID token if openid scope
            true,  // include new refresh token
        )
        .map_err(|e| OidcError::ServerError(format!("failed to create token: {e}")))
}

/// Handles password grant (deprecated but supported).
#[allow(clippy::unused_async)]
async fn handle_password_grant<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    request: &TokenRequest,
    client_id: &str,
) -> Result<TokenResponse, OidcError> {
    let _username = request
        .username
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("username is required".to_string()))?;

    let _password = request
        .password
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("password is required".to_string()))?;

    // TODO: Implement password authentication
    // 1. Look up the user by username
    // 2. Verify the password
    // 3. Check if the user is enabled
    // 4. Create a session

    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Placeholder - would use actual user ID from authentication
    token_manager
        .create_token_response(
            "placeholder-user-id",
            client_id,
            request.scope.as_deref().unwrap_or("openid"),
            None, // session_id
            None, // nonce
            true, // include ID token
            true, // include refresh token
        )
        .map_err(|e| OidcError::ServerError(format!("failed to create token: {e}")))
}

/// Handles device code grant (RFC 8628).
#[allow(clippy::unused_async)]
async fn handle_device_code_grant<R: RealmProvider>(
    _state: &OidcState<R>,
    _realm: &str,
    request: &TokenRequest,
    _client_id: &str,
) -> Result<TokenResponse, OidcError> {
    // Validate required parameters
    // Note: For device code grant, the client_id and device_code come from the
    // specialized DeviceTokenRequest struct, but we support the generic TokenRequest too
    let _device_code = request
        .code
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("device_code is required".to_string()))?;

    // TODO: Implement device code flow
    // 1. Look up the device code
    // 2. Check if user has authorized
    // 3. If pending, return authorization_pending error
    // 4. If denied, return access_denied error
    // 5. If authorized, issue tokens

    // For now, return authorization_pending (common case during polling)
    Err(OidcError::AccessDenied("authorization_pending".to_string()))
}

/// Handles token exchange grant (RFC 8693).
#[allow(clippy::unused_async)]
async fn handle_token_exchange_grant<R: RealmProvider>(
    _state: &OidcState<R>,
    _realm: &str,
    request: &TokenRequest,
    _client_id: &str,
) -> Result<TokenResponse, OidcError> {
    // Validate required parameters
    let _subject_token = request
        .subject_token
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("subject_token is required".to_string()))?;

    let _subject_token_type = request
        .subject_token_type
        .as_ref()
        .ok_or_else(|| OidcError::InvalidRequest("subject_token_type is required".to_string()))?;

    // TODO: Implement token exchange
    // 1. Validate the subject token
    // 2. Check if token exchange is allowed for this client
    // 3. Apply any policies
    // 4. Issue new token with appropriate claims

    Err(OidcError::UnsupportedGrantType("token exchange not yet implemented".to_string()))
}

/// Converts an `OidcError` to an HTTP response.
fn error_response(err: &OidcError) -> axum::response::Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let error_response = ErrorResponse {
        error: err.error_code().to_string(),
        error_description: Some(err.to_string()),
        error_uri: None,
    };
    (status, Json(error_response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    #[test]
    fn extract_basic_auth_credentials() {
        let mut headers = HeaderMap::new();
        // "client_id:client_secret" base64 encoded
        headers.insert(
            AUTHORIZATION,
            "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=".parse().unwrap(),
        );

        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            scope: None,
            refresh_token: None,
            username: None,
            password: None,
            code_verifier: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
        };

        let (client_id, client_secret) = extract_client_credentials(&headers, &request).unwrap();
        assert_eq!(client_id, "client_id");
        assert_eq!(client_secret, Some("client_secret".to_string()));
    }

    #[test]
    fn extract_form_credentials() {
        let headers = HeaderMap::new();
        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("form_client".to_string()),
            client_secret: Some("form_secret".to_string()),
            scope: None,
            refresh_token: None,
            username: None,
            password: None,
            code_verifier: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
        };

        let (client_id, client_secret) = extract_client_credentials(&headers, &request).unwrap();
        assert_eq!(client_id, "form_client");
        assert_eq!(client_secret, Some("form_secret".to_string()));
    }
}
