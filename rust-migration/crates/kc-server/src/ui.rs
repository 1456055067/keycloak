//! Login/Logout UI handlers.
//!
//! This module provides the HTML UI for authentication flows.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;

use kc_protocol_oidc::endpoints::{AuthCodeStore, StoredAuthCode, AuthCodeParams, UserAuthenticator, ClientAuthenticator};

use crate::state::AppState;

/// Scope information for consent screen.
#[derive(Debug, Clone)]
pub struct ScopeInfo {
    /// Scope name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    /// Realm name.
    pub realm_name: String,
    /// OAuth client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Response type (code, token, etc.).
    pub response_type: String,
    /// Requested scopes.
    pub scope: String,
    /// OAuth state parameter.
    pub state: Option<String>,
    /// OIDC nonce parameter.
    pub nonce: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<String>,
    /// Form action URL.
    pub action_url: String,
    /// Error message to display.
    pub error: Option<String>,
    /// Info message to display.
    pub info: Option<String>,
}

/// Logout page template.
#[derive(Template)]
#[template(path = "logout.html")]
pub struct LogoutTemplate {
    /// Realm name.
    pub realm_name: String,
    /// Whether logout is confirmed.
    pub confirmed: bool,
    /// Post-logout redirect URI.
    pub redirect_uri: Option<String>,
    /// ID token hint for logout.
    pub id_token_hint: Option<String>,
    /// OAuth state parameter.
    pub state: Option<String>,
    /// Form action URL.
    pub action_url: String,
}

/// Error page template.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    /// Realm name.
    pub realm_name: String,
    /// Error code.
    pub error: String,
    /// Error description.
    pub error_description: Option<String>,
    /// Redirect URI for "back" link.
    pub redirect_uri: Option<String>,
}

/// Query parameters for authorization request.
#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    /// Response type.
    pub response_type: Option<String>,
    /// Client ID.
    pub client_id: Option<String>,
    /// Redirect URI.
    pub redirect_uri: Option<String>,
    /// Requested scopes.
    pub scope: Option<String>,
    /// OAuth state.
    pub state: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<String>,
}

/// Form data for login submission.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Response type.
    pub response_type: String,
    /// Scopes.
    pub scope: String,
    /// OAuth state.
    pub state: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<String>,
}

/// Query parameters for logout request.
#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    /// ID token hint.
    pub id_token_hint: Option<String>,
    /// Post-logout redirect URI.
    pub post_logout_redirect_uri: Option<String>,
    /// OAuth state.
    pub state: Option<String>,
}

/// Form data for logout confirmation.
#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    /// ID token hint.
    pub id_token_hint: Option<String>,
    /// Post-logout redirect URI.
    pub post_logout_redirect_uri: Option<String>,
    /// OAuth state.
    pub state: Option<String>,
}

/// Shows the login page.
pub async fn login_page(
    State(_state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<AuthQuery>,
) -> Response {
    let response_type = query.response_type.unwrap_or_else(|| "code".to_string());
    let client_id = match query.client_id {
        Some(id) => id,
        None => {
            return render_error(
                &realm,
                "invalid_request",
                Some("Missing client_id parameter"),
                None,
            );
        }
    };
    let redirect_uri = match query.redirect_uri {
        Some(uri) => uri,
        None => {
            return render_error(
                &realm,
                "invalid_request",
                Some("Missing redirect_uri parameter"),
                None,
            );
        }
    };
    let scope = query.scope.unwrap_or_else(|| "openid".to_string());

    let template = LoginTemplate {
        realm_name: realm.clone(),
        client_id,
        redirect_uri,
        response_type,
        scope,
        state: query.state,
        nonce: query.nonce,
        code_challenge: query.code_challenge,
        code_challenge_method: query.code_challenge_method,
        action_url: format!("/realms/{}/login", realm),
        error: None,
        info: None,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Handles login form submission.
pub async fn login_submit(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Form(form): Form<LoginForm>,
) -> Response {
    let providers = &state.providers;

    // Authenticate user
    let user = match UserAuthenticator::authenticate(
        providers.as_ref(),
        &realm,
        &form.username,
        &form.password,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!("Authentication failed: {}", e);
            // Invalid credentials - show login page with error
            let template = LoginTemplate {
                realm_name: realm.clone(),
                client_id: form.client_id,
                redirect_uri: form.redirect_uri,
                response_type: form.response_type,
                scope: form.scope,
                state: form.state,
                nonce: form.nonce,
                code_challenge: form.code_challenge,
                code_challenge_method: form.code_challenge_method,
                action_url: format!("/realms/{}/login", realm),
                error: Some("Invalid username or password".to_string()),
                info: None,
            };
            return match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response(),
            };
        }
    };

    // Look up client to get client UUID
    let client = match ClientAuthenticator::authenticate(
        providers.as_ref(),
        &realm,
        &form.client_id,
        None,
        None,
        None,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Client lookup error: {}", e);
            return render_error(&realm, "invalid_client", Some("Unknown client"), None);
        }
    };

    // Generate authorization code
    let auth_code = kc_crypto::random::generate_auth_code();
    let code_params = AuthCodeParams {
        code: auth_code.clone(),
        realm_name: realm.clone(),
        client_id: form.client_id.clone(),
        client_uuid: client.id,
        user_id: user.id,
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope.clone(),
        ttl_seconds: state.config.auth_code_lifespan,
    };

    let mut stored_code = StoredAuthCode::new(code_params);
    stored_code.nonce.clone_from(&form.nonce);
    stored_code.code_challenge.clone_from(&form.code_challenge);
    if let Some(method) = &form.code_challenge_method {
        stored_code.code_challenge_method = match method.as_str() {
            "plain" => Some(kc_protocol_oidc::types::CodeChallengeMethod::Plain),
            _ => Some(kc_protocol_oidc::types::CodeChallengeMethod::S256),
        };
    }

    if let Err(e) = providers.auth_codes.store_code(&stored_code).await {
        tracing::error!("Code storage error: {}", e);
        return render_error(&realm, "server_error", Some("Code storage failed"), None);
    }

    // Build redirect URL with authorization code
    let mut redirect_url = match url::Url::parse(&form.redirect_uri) {
        Ok(u) => u,
        Err(_) => {
            return render_error(&realm, "invalid_request", Some("Invalid redirect_uri"), None);
        }
    };

    {
        let mut query_pairs = redirect_url.query_pairs_mut();
        query_pairs.append_pair("code", &auth_code);
        if let Some(ref s) = form.state {
            query_pairs.append_pair("state", s);
        }
    }

    Redirect::to(redirect_url.as_str()).into_response()
}

/// Shows the logout page.
pub async fn logout_page(
    State(_state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<LogoutQuery>,
) -> Response {
    let template = LogoutTemplate {
        realm_name: realm.clone(),
        confirmed: false,
        redirect_uri: query.post_logout_redirect_uri,
        id_token_hint: query.id_token_hint,
        state: query.state,
        action_url: format!("/realms/{}/protocol/openid-connect/logout", realm),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Handles logout form submission.
pub async fn logout_submit(
    State(_state): State<AppState>,
    Path(realm): Path<String>,
    Form(form): Form<LogoutForm>,
) -> Response {
    // In a full implementation, we would:
    // 1. Validate the id_token_hint if provided
    // 2. Invalidate the user's session
    // 3. Redirect to the post_logout_redirect_uri

    // For now, just show confirmation
    let template = LogoutTemplate {
        realm_name: realm.clone(),
        confirmed: true,
        redirect_uri: form.post_logout_redirect_uri,
        id_token_hint: None,
        state: form.state,
        action_url: String::new(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Renders an error page.
fn render_error(
    realm: &str,
    error: &str,
    error_description: Option<&str>,
    redirect_uri: Option<&str>,
) -> Response {
    let template = ErrorTemplate {
        realm_name: realm.to_string(),
        error: error.to_string(),
        error_description: error_description.map(String::from),
        redirect_uri: redirect_uri.map(String::from),
    };

    match template.render() {
        Ok(html) => (StatusCode::BAD_REQUEST, Html(html)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response(),
    }
}

/// Converts scopes to display information.
#[must_use]
pub fn scopes_to_info(scope: &str) -> Vec<ScopeInfo> {
    scope
        .split_whitespace()
        .filter_map(|s| {
            let description = match s {
                "openid" => "Verify your identity",
                "profile" => "Access your basic profile information (name, picture)",
                "email" => "Access your email address",
                "phone" => "Access your phone number",
                "address" => "Access your address",
                "offline_access" => "Access your data when you're not using the app",
                _ => return None,
            };
            Some(ScopeInfo {
                name: s.to_string(),
                description: description.to_string(),
            })
        })
        .collect()
}
