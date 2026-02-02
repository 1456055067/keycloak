//! LDAP-specific error types.
//!
//! ## Security Note
//!
//! Error messages must not leak sensitive information like
//! passwords, bind credentials, or internal LDAP structure.

use kc_federation::FederationError;
use thiserror::Error;

/// LDAP-specific errors.
#[derive(Debug, Error)]
pub enum LdapError {
    /// Invalid configuration.
    #[error("LDAP configuration error: {0}")]
    Configuration(String),

    /// Connection URL must use LDAPS.
    #[error("Security error: Only LDAPS is supported. URL must start with 'ldaps://'. STARTTLS and plain LDAP are not allowed.")]
    InsecureProtocol,

    /// Connection failed.
    #[error("LDAP connection failed: {0}")]
    Connection(String),

    /// TLS/SSL error.
    #[error("LDAP TLS error: {0}")]
    Tls(String),

    /// Bind (authentication) failed.
    #[error("LDAP bind failed: {0}")]
    Bind(String),

    /// Search operation failed.
    #[error("LDAP search failed: {0}")]
    Search(String),

    /// User not found.
    #[error("User not found: {0}")]
    UserNotFound(String),

    /// Invalid DN format.
    #[error("Invalid DN format: {0}")]
    InvalidDn(String),

    /// Attribute mapping error.
    #[error("Attribute mapping error: {0}")]
    AttributeMapping(String),

    /// Timeout error.
    #[error("LDAP operation timed out")]
    Timeout,

    /// Pool exhausted.
    #[error("Connection pool exhausted")]
    PoolExhausted,

    /// Protocol error from LDAP server.
    #[error("LDAP protocol error: {0}")]
    Protocol(String),

    /// Internal error.
    #[error("Internal LDAP error: {0}")]
    Internal(String),

    /// Underlying ldap3 error.
    #[error("LDAP error: {0}")]
    Ldap3(#[from] ldap3::LdapError),
}

impl LdapError {
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

    /// Creates a TLS error.
    #[must_use]
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Creates a user not found error.
    #[must_use]
    pub fn user_not_found(username: impl Into<String>) -> Self {
        Self::UserNotFound(username.into())
    }

    /// Creates an attribute mapping error.
    #[must_use]
    pub fn mapping(msg: impl Into<String>) -> Self {
        Self::AttributeMapping(msg.into())
    }

    /// Checks if this is a connection-related error.
    #[must_use]
    pub const fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::Connection(_) | Self::Tls(_) | Self::Timeout | Self::PoolExhausted
        )
    }

    /// Checks if this is a security-related error.
    #[must_use]
    pub const fn is_security_error(&self) -> bool {
        matches!(self, Self::InsecureProtocol | Self::Tls(_) | Self::Bind(_))
    }
}

/// Result type for LDAP operations.
pub type LdapResult<T> = Result<T, LdapError>;

impl From<LdapError> for FederationError {
    fn from(err: LdapError) -> Self {
        match err {
            LdapError::Configuration(msg) => FederationError::Configuration(msg),
            LdapError::InsecureProtocol => {
                FederationError::Configuration(err.to_string())
            }
            LdapError::Connection(msg) => FederationError::Connection(msg),
            LdapError::Tls(msg) => FederationError::Tls(msg),
            LdapError::Bind(msg) => FederationError::AuthenticationFailed(msg),
            LdapError::Search(msg) => FederationError::UserLookup(msg),
            LdapError::UserNotFound(username) => FederationError::UserNotFound(username),
            LdapError::InvalidDn(msg) => FederationError::AttributeMapping(msg),
            LdapError::AttributeMapping(msg) => FederationError::AttributeMapping(msg),
            LdapError::Timeout => FederationError::Timeout("LDAP operation".to_string()),
            LdapError::PoolExhausted => {
                FederationError::Connection("Connection pool exhausted".to_string())
            }
            LdapError::Protocol(msg) => FederationError::Protocol(msg),
            LdapError::Internal(msg) => FederationError::Internal(msg),
            LdapError::Ldap3(e) => FederationError::Protocol(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_categories() {
        assert!(LdapError::InsecureProtocol.is_security_error());
        assert!(LdapError::tls("cert invalid").is_security_error());
        assert!(LdapError::Bind("bad password".to_string()).is_security_error());

        assert!(LdapError::connection("refused").is_connection_error());
        assert!(LdapError::Timeout.is_connection_error());
        assert!(LdapError::PoolExhausted.is_connection_error());
    }

    #[test]
    fn insecure_protocol_message() {
        let err = LdapError::InsecureProtocol;
        let msg = err.to_string();
        assert!(msg.contains("LDAPS"));
        assert!(msg.contains("STARTTLS"));
    }
}
