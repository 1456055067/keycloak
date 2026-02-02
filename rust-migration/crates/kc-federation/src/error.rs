//! Federation error types.
//!
//! ## NIST 800-53 Rev5: AU-2 (Event Logging)
//!
//! Error types support audit logging with structured context for
//! security-relevant events like authentication failures.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during federation operations.
#[derive(Debug, Error)]
pub enum FederationError {
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Connection error to external system.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Authentication failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Invalid credentials format.
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    /// User not found in external system.
    #[error("User not found: {0}")]
    UserNotFound(String),

    /// User lookup error.
    #[error("User lookup error: {0}")]
    UserLookup(String),

    /// Attribute mapping error.
    #[error("Attribute mapping error: {0}")]
    AttributeMapping(String),

    /// Synchronization error.
    #[error("Synchronization error: {0}")]
    Sync(String),

    /// Operation not supported by this provider.
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// Provider is read-only.
    #[error("Provider is read-only: cannot {0}")]
    ReadOnly(String),

    /// TLS/SSL error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Protocol error (e.g., LDAP protocol error).
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Timeout error.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Internal error.
    #[error("Internal federation error: {0}")]
    Internal(String),

    /// Storage error when persisting federated users.
    #[error("Storage error: {0}")]
    Storage(#[from] kc_storage::StorageError),
}

impl FederationError {
    /// Creates a configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// Creates a connection error.
    #[must_use]
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Creates an authentication failed error.
    #[must_use]
    pub fn auth_failed(msg: impl Into<String>) -> Self {
        Self::AuthenticationFailed(msg.into())
    }

    /// Creates a user not found error.
    #[must_use]
    pub fn user_not_found(username: impl Into<String>) -> Self {
        Self::UserNotFound(username.into())
    }

    /// Creates a TLS error.
    #[must_use]
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Creates a read-only error.
    #[must_use]
    pub fn read_only(operation: impl Into<String>) -> Self {
        Self::ReadOnly(operation.into())
    }

    /// Creates a not supported error.
    #[must_use]
    pub fn not_supported(operation: impl Into<String>) -> Self {
        Self::NotSupported(operation.into())
    }

    /// Checks if this is an authentication error.
    #[must_use]
    pub const fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed(_) | Self::InvalidCredentials(_)
        )
    }

    /// Checks if this is a connection error.
    #[must_use]
    pub const fn is_connection_error(&self) -> bool {
        matches!(self, Self::Connection(_) | Self::Tls(_) | Self::Timeout(_))
    }

    /// Checks if this is a user not found error.
    #[must_use]
    pub const fn is_user_not_found(&self) -> bool {
        matches!(self, Self::UserNotFound(_))
    }
}

/// Result type for federation operations.
pub type FederationResult<T> = Result<T, FederationError>;

/// Context for federation errors (for audit logging).
#[derive(Debug, Clone)]
pub struct FederationErrorContext {
    /// Provider name.
    pub provider_name: String,
    /// Realm ID.
    pub realm_id: Uuid,
    /// Username (if applicable).
    pub username: Option<String>,
    /// IP address (if applicable).
    pub ip_address: Option<String>,
}

impl FederationErrorContext {
    /// Creates a new error context.
    #[must_use]
    pub fn new(provider_name: impl Into<String>, realm_id: Uuid) -> Self {
        Self {
            provider_name: provider_name.into(),
            realm_id,
            username: None,
            ip_address: None,
        }
    }

    /// Sets the username.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_categories() {
        assert!(FederationError::auth_failed("bad password").is_auth_error());
        assert!(FederationError::connection("refused").is_connection_error());
        assert!(FederationError::tls("cert invalid").is_connection_error());
        assert!(FederationError::user_not_found("jdoe").is_user_not_found());
    }

    #[test]
    fn error_context() {
        let ctx = FederationErrorContext::new("ldap", Uuid::now_v7())
            .with_username("jdoe")
            .with_ip("192.168.1.1");

        assert_eq!(ctx.provider_name, "ldap");
        assert_eq!(ctx.username, Some("jdoe".to_string()));
        assert_eq!(ctx.ip_address, Some("192.168.1.1".to_string()));
    }
}
