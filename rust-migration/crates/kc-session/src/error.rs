//! Session error types.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session not found.
    #[error("Session not found: {0}")]
    NotFound(Uuid),

    /// Session expired.
    #[error("Session expired: {0}")]
    Expired(Uuid),

    /// Session is invalid or has been revoked.
    #[error("Session invalid: {0}")]
    Invalid(String),

    /// User is not authenticated.
    #[error("User not authenticated")]
    NotAuthenticated,

    /// Client session not found within user session.
    #[error("Client session not found for client: {0}")]
    ClientSessionNotFound(String),

    /// Authentication session not found or expired.
    #[error("Authentication session not found or expired")]
    AuthSessionNotFound,

    /// Session limit exceeded.
    #[error("Session limit exceeded for user: {0}")]
    LimitExceeded(Uuid),

    /// Storage error.
    #[error("Session storage error: {0}")]
    Storage(String),

    /// Internal error.
    #[error("Internal session error: {0}")]
    Internal(String),
}

impl SessionError {
    /// Checks if this is a not found error.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound(_) | Self::ClientSessionNotFound(_) | Self::AuthSessionNotFound
        )
    }

    /// Checks if this is an expiration error.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        matches!(self, Self::Expired(_))
    }
}

/// Result type for session operations.
pub type SessionResult<T> = Result<T, SessionError>;
