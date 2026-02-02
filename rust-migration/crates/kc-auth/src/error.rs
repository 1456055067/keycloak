//! Authentication error types.

use std::fmt;

/// Authentication operation errors.
#[derive(Debug)]
pub enum AuthError {
    /// Invalid credentials provided.
    InvalidCredentials,
    /// User account is disabled.
    UserDisabled,
    /// User account is locked (temporary).
    UserLocked {
        /// When the lockout expires.
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// User account requires action before login.
    RequiredAction {
        /// The required action.
        action: String,
    },
    /// Session has expired.
    SessionExpired,
    /// Authentication flow error.
    FlowError(String),
    /// Invalid authentication state.
    InvalidState,
    /// Credential not found.
    CredentialNotFound,
    /// Invalid credential type.
    InvalidCredentialType,
    /// OTP verification failed.
    InvalidOtp,
    /// `WebAuthn` verification failed.
    WebAuthnFailed(String),
    /// Internal error.
    Internal(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid credentials"),
            Self::UserDisabled => write!(f, "user account is disabled"),
            Self::UserLocked { until } => {
                if let Some(time) = until {
                    write!(f, "user account is locked until {time}")
                } else {
                    write!(f, "user account is locked")
                }
            }
            Self::RequiredAction { action } => {
                write!(f, "required action before login: {action}")
            }
            Self::SessionExpired => write!(f, "session has expired"),
            Self::FlowError(msg) => write!(f, "authentication flow error: {msg}"),
            Self::InvalidState => write!(f, "invalid authentication state"),
            Self::CredentialNotFound => write!(f, "credential not found"),
            Self::InvalidCredentialType => write!(f, "invalid credential type"),
            Self::InvalidOtp => write!(f, "invalid one-time password"),
            Self::WebAuthnFailed(msg) => write!(f, "WebAuthn verification failed: {msg}"),
            Self::Internal(msg) => write!(f, "internal authentication error: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Result type for authentication operations.
pub type AuthResult<T> = Result<T, AuthError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = AuthError::InvalidCredentials;
        assert_eq!(err.to_string(), "invalid credentials");

        let err = AuthError::UserLocked { until: None };
        assert!(err.to_string().contains("locked"));
    }
}
