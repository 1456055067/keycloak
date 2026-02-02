//! Authenticator trait and implementations.
//!
//! Authenticators are pluggable components that perform specific
//! authentication steps (password verification, OTP, etc.).

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthResult;

/// Result of an authenticator execution.
#[derive(Debug, Clone)]
pub enum AuthenticatorResult {
    /// Authentication succeeded for this step.
    Success,
    /// Authentication failed.
    Failed {
        /// Error message.
        message: String,
    },
    /// User needs to provide additional input.
    Challenge {
        /// Challenge type.
        challenge_type: String,
        /// Additional data for the challenge.
        data: Option<serde_json::Value>,
    },
    /// Skip this authenticator (not applicable).
    Skip,
    /// Flow should be restarted.
    FlowReset,
}

impl AuthenticatorResult {
    /// Creates a success result.
    #[must_use]
    pub const fn success() -> Self {
        Self::Success
    }

    /// Creates a failed result.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
        }
    }

    /// Creates a challenge result.
    #[must_use]
    pub fn challenge(challenge_type: impl Into<String>) -> Self {
        Self::Challenge {
            challenge_type: challenge_type.into(),
            data: None,
        }
    }

    /// Creates a challenge result with data.
    #[must_use]
    pub fn challenge_with_data(challenge_type: impl Into<String>, data: serde_json::Value) -> Self {
        Self::Challenge {
            challenge_type: challenge_type.into(),
            data: Some(data),
        }
    }

    /// Creates a skip result.
    #[must_use]
    pub const fn skip() -> Self {
        Self::Skip
    }

    /// Creates a flow reset result.
    #[must_use]
    pub const fn flow_reset() -> Self {
        Self::FlowReset
    }

    /// Checks if this is a success result.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Checks if this is a failed result.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Checks if this is a challenge result.
    #[must_use]
    pub const fn is_challenge(&self) -> bool {
        matches!(self, Self::Challenge { .. })
    }
}

/// Authentication context passed to authenticators.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Realm ID.
    pub realm_id: Uuid,
    /// Client ID.
    pub client_id: Uuid,
    /// User ID (if known).
    pub user_id: Option<Uuid>,
    /// Session ID.
    pub session_id: Uuid,
    /// Current execution ID.
    pub execution_id: Uuid,
    /// Form data from the request.
    pub form_data: std::collections::HashMap<String, String>,
    /// Session notes.
    pub notes: std::collections::HashMap<String, String>,
}

impl AuthContext {
    /// Creates a new authentication context.
    #[must_use]
    pub fn new(realm_id: Uuid, client_id: Uuid, session_id: Uuid, execution_id: Uuid) -> Self {
        Self {
            realm_id,
            client_id,
            user_id: None,
            session_id,
            execution_id,
            form_data: std::collections::HashMap::new(),
            notes: std::collections::HashMap::new(),
        }
    }

    /// Sets the user ID.
    #[must_use]
    pub const fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Gets a form value.
    #[must_use]
    pub fn form_value(&self, key: &str) -> Option<&str> {
        self.form_data.get(key).map(String::as_str)
    }

    /// Gets a note value.
    #[must_use]
    pub fn note(&self, key: &str) -> Option<&str> {
        self.notes.get(key).map(String::as_str)
    }

    /// Sets a note value.
    pub fn set_note(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.notes.insert(key.into(), value.into());
    }
}

/// Authenticator trait.
///
/// Authenticators are executed during authentication flows to verify
/// user identity using various methods.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Returns the authenticator ID.
    fn id(&self) -> &'static str;

    /// Returns the display name.
    fn display_name(&self) -> &'static str;

    /// Checks if this authenticator requires a user to be set.
    fn requires_user(&self) -> bool {
        true
    }

    /// Checks if this authenticator is configurable.
    fn is_configurable(&self) -> bool {
        false
    }

    /// Authenticates the user.
    ///
    /// Called when the authenticator is first executed.
    async fn authenticate(&self, context: &mut AuthContext) -> AuthResult<AuthenticatorResult>;

    /// Handles a challenge response.
    ///
    /// Called when the user responds to a challenge.
    async fn action(&self, context: &mut AuthContext) -> AuthResult<AuthenticatorResult> {
        // Default implementation just calls authenticate
        self.authenticate(context).await
    }
}

/// Authenticator factory trait.
#[async_trait]
pub trait AuthenticatorFactory: Send + Sync {
    /// Returns the provider ID.
    fn id(&self) -> &'static str;

    /// Creates an authenticator instance.
    async fn create(&self) -> Box<dyn Authenticator>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticator_result_success() {
        let result = AuthenticatorResult::success();
        assert!(result.is_success());
        assert!(!result.is_failed());
    }

    #[test]
    fn authenticator_result_failed() {
        let result = AuthenticatorResult::failed("bad password");
        assert!(result.is_failed());
        assert!(!result.is_success());
    }

    #[test]
    fn authenticator_result_challenge() {
        let result = AuthenticatorResult::challenge("otp");
        assert!(result.is_challenge());
    }

    #[test]
    fn auth_context_notes() {
        let mut context = AuthContext::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );

        context.set_note("key", "value");
        assert_eq!(context.note("key"), Some("value"));
        assert_eq!(context.note("missing"), None);
    }
}
