//! OIDC protocol error types.
//!
//! Implements OAuth 2.0 and `OpenID` Connect error responses as defined in:
//! - RFC 6749 (OAuth 2.0)
//! - `OpenID` Connect Core 1.0

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// OIDC protocol errors.
#[derive(Debug, Error)]
pub enum OidcError {
    /// Invalid request parameters.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// Client authentication failed.
    #[error("invalid_client: {0}")]
    InvalidClient(String),

    /// Invalid or expired authorization grant.
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    /// Client is not authorized for this grant type.
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),

    /// Unsupported grant type.
    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),

    /// Invalid scope.
    #[error("invalid_scope: {0}")]
    InvalidScope(String),

    /// Unsupported response type.
    #[error("unsupported_response_type: {0}")]
    UnsupportedResponseType(String),

    /// Server error.
    #[error("server_error: {0}")]
    ServerError(String),

    /// Temporarily unavailable.
    #[error("temporarily_unavailable: {0}")]
    TemporarilyUnavailable(String),

    /// Access denied by resource owner.
    #[error("access_denied: {0}")]
    AccessDenied(String),

    /// Invalid token.
    #[error("invalid_token: {0}")]
    InvalidToken(String),

    /// Insufficient scope.
    #[error("insufficient_scope: {0}")]
    InsufficientScope(String),

    /// Login required.
    #[error("login_required")]
    LoginRequired,

    /// Consent required.
    #[error("consent_required")]
    ConsentRequired,

    /// Interaction required.
    #[error("interaction_required")]
    InteractionRequired,

    /// Token signing error.
    #[error("token signing failed: {0}")]
    TokenSigning(String),

    /// Token validation error.
    #[error("token validation failed: {0}")]
    TokenValidation(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl OidcError {
    /// Returns the OAuth 2.0 error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::UnsupportedResponseType(_) => "unsupported_response_type",
            Self::TemporarilyUnavailable(_) => "temporarily_unavailable",
            Self::AccessDenied(_) => "access_denied",
            Self::InvalidToken(_) => "invalid_token",
            Self::InsufficientScope(_) => "insufficient_scope",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::ServerError(_)
            | Self::TokenSigning(_)
            | Self::TokenValidation(_)
            | Self::Internal(_) => "server_error",
        }
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_)
            | Self::InvalidScope(_)
            | Self::UnsupportedGrantType(_)
            | Self::UnsupportedResponseType(_)
            | Self::InvalidGrant(_)
            | Self::LoginRequired
            | Self::ConsentRequired
            | Self::InteractionRequired => 400,
            Self::InvalidClient(_) | Self::InvalidToken(_) => 401,
            Self::AccessDenied(_)
            | Self::UnauthorizedClient(_)
            | Self::InsufficientScope(_) => 403,
            Self::ServerError(_)
            | Self::TokenSigning(_)
            | Self::TokenValidation(_)
            | Self::Internal(_) => 500,
            Self::TemporarilyUnavailable(_) => 503,
        }
    }

    /// Creates an error response for OAuth 2.0/OIDC.
    #[must_use]
    pub fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            error: self.error_code().to_string(),
            error_description: Some(self.to_string()),
            error_uri: None,
        }
    }
}

/// OAuth 2.0 error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code.
    pub error: String,

    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// URI with more information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

/// Result type for OIDC operations.
pub type OidcResult<T> = Result<T, OidcError>;
