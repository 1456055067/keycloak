//! Error handling for Keycloak Rust.
//!
//! ## NIST 800-53 Rev5: SI-11 (Error Handling)
//!
//! Error messages are designed to be informative for debugging while not
//! exposing sensitive information to end users.

use thiserror::Error;

/// Result type alias using the Keycloak error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Keycloak operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Cache error.
    #[error("cache error: {0}")]
    Cache(String),

    /// Authentication error.
    ///
    /// ## NIST 800-53 Rev5: IA-6 (Authentication Feedback)
    ///
    /// Authentication errors use generic messages to prevent user enumeration.
    #[error("authentication failed")]
    Authentication,

    /// Authorization error.
    #[error("access denied")]
    Authorization,

    /// Cryptographic error.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// Resource not found.
    #[error("resource not found: {0}")]
    NotFound(String),

    /// Resource already exists.
    #[error("resource already exists: {0}")]
    AlreadyExists(String),

    /// Internal error.
    #[error("internal error")]
    Internal,
}

impl Error {
    /// Returns whether this error should be logged at error level.
    #[must_use]
    pub const fn is_server_error(&self) -> bool {
        matches!(self, Self::Database(_) | Self::Cache(_) | Self::Internal)
    }

    /// Returns whether this error represents a client error.
    #[must_use]
    pub const fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::Authentication
                | Self::Authorization
                | Self::Validation(_)
                | Self::NotFound(_)
                | Self::AlreadyExists(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_error_is_generic() {
        let error = Error::Authentication;
        // NIST 800-53 Rev5: IA-6 - Generic error message
        assert_eq!(error.to_string(), "authentication failed");
    }

    #[test]
    fn authorization_error_is_generic() {
        let error = Error::Authorization;
        assert_eq!(error.to_string(), "access denied");
    }

    #[test]
    fn internal_error_is_generic() {
        let error = Error::Internal;
        // Don't expose internal details
        assert_eq!(error.to_string(), "internal error");
    }
}
