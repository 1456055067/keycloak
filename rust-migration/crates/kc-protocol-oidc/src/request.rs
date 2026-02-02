//! OIDC request types.
//!
//! Request types for OAuth 2.0 and `OpenID` Connect endpoints.

use serde::{Deserialize, Serialize};

use crate::types::{CodeChallengeMethod, Display, GrantType, Prompt, ResponseMode};

/// Authorization endpoint request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Response type (required).
    pub response_type: String,

    /// Client ID (required).
    pub client_id: String,

    /// Redirect URI (required for most flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Scope (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// State parameter (recommended for CSRF protection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Response mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,

    /// Nonce (required for implicit/hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Display mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// Prompt values (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    /// Maximum authentication age in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,

    /// UI locales (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<String>,

    /// ID token hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,

    /// Login hint (username or email).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,

    /// ACR values (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,

    // === PKCE Parameters ===
    /// PKCE code challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,

    /// PKCE code challenge method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<CodeChallengeMethod>,

    // === Request Object Parameters ===
    /// Request object (JWT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,

    /// Request URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<String>,

    // === Claims Parameter ===
    /// Claims request (JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<String>,
}

impl AuthorizationRequest {
    /// Parses the prompt parameter into individual values.
    #[must_use]
    pub fn prompt_values(&self) -> Vec<Prompt> {
        self.prompt
            .as_ref()
            .map(|p| {
                p.split_whitespace()
                    .filter_map(|s| match s {
                        "none" => Some(Prompt::None),
                        "login" => Some(Prompt::Login),
                        "consent" => Some(Prompt::Consent),
                        "select_account" => Some(Prompt::SelectAccount),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Checks if the prompt includes "none".
    #[must_use]
    pub fn is_prompt_none(&self) -> bool {
        self.prompt_values().contains(&Prompt::None)
    }

    /// Checks if login is required.
    #[must_use]
    pub fn requires_login(&self) -> bool {
        self.prompt_values().contains(&Prompt::Login)
    }

    /// Checks if consent is required.
    #[must_use]
    pub fn requires_consent(&self) -> bool {
        self.prompt_values().contains(&Prompt::Consent)
    }

    /// Returns the scopes as a vector.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_ref()
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// Checks if `openid` scope is requested.
    #[must_use]
    pub fn is_oidc_request(&self) -> bool {
        self.scopes().contains(&"openid")
    }
}

/// Token endpoint request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Grant type (required).
    pub grant_type: String,

    /// Authorization code (for `authorization_code` grant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// Redirect URI (for `authorization_code` grant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Client ID (if not using client authentication).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Client secret (for confidential clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Scope (for `client_credentials` grant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Refresh token (for `refresh_token` grant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Username (for password grant - deprecated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password (for password grant - deprecated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// PKCE code verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    // === Token Exchange Parameters (RFC 8693) ===
    /// Subject token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_token: Option<String>,

    /// Subject token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_token_type: Option<String>,

    /// Actor token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_token: Option<String>,

    /// Actor token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_token_type: Option<String>,

    /// Requested token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
}

impl TokenRequest {
    /// Parses the grant type.
    ///
    /// # Errors
    ///
    /// Returns an error if the grant type is unknown.
    pub fn parsed_grant_type(&self) -> Result<GrantType, String> {
        self.grant_type.parse()
    }
}

/// Introspection endpoint request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionRequest {
    /// The token to introspect (required).
    pub token: String,

    /// Token type hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,
}

/// Revocation endpoint request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// The token to revoke (required).
    pub token: String,

    /// Token type hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,
}

/// `UserInfo` endpoint request (extracted from Authorization header).
#[derive(Debug, Clone)]
pub struct UserInfoRequest {
    /// Access token.
    pub access_token: String,
}

/// End session (logout) request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndSessionRequest {
    /// ID token hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,

    /// Client ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Post-logout redirect URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uri: Option<String>,

    /// State.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// UI locales.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<String>,
}

/// Device authorization request (RFC 8628).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Client ID (required).
    pub client_id: String,

    /// Scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Device token request (RFC 8628).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    /// Grant type (must be `device_code`).
    pub grant_type: String,

    /// Device code.
    pub device_code: String,

    /// Client ID.
    pub client_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_request_prompt_parsing() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test".to_string(),
            redirect_uri: None,
            scope: Some("openid".to_string()),
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: Some("login consent".to_string()),
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

        let prompts = request.prompt_values();
        assert!(prompts.contains(&Prompt::Login));
        assert!(prompts.contains(&Prompt::Consent));
        assert!(request.requires_login());
        assert!(request.requires_consent());
    }

    #[test]
    fn authorization_request_scopes() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test".to_string(),
            redirect_uri: None,
            scope: Some("openid profile email".to_string()),
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

        let scopes = request.scopes();
        assert!(scopes.contains(&"openid"));
        assert!(scopes.contains(&"profile"));
        assert!(scopes.contains(&"email"));
        assert!(request.is_oidc_request());
    }
}
