//! Authentication flow state machine.
//!
//! Type-safe state machine for authentication flows, ensuring
//! valid state transitions at compile time.

use std::marker::PhantomData;

use uuid::Uuid;

use crate::error::{AuthError, AuthResult};

/// Authentication flow states.
pub mod states {
    /// Initial state - flow just started.
    #[derive(Debug, Clone, Copy)]
    pub struct Initial;

    /// Identifying state - collecting username.
    #[derive(Debug, Clone, Copy)]
    pub struct Identifying;

    /// Authenticating state - verifying credentials.
    #[derive(Debug, Clone, Copy)]
    pub struct Authenticating;

    /// Challenged state - waiting for user response (e.g., OTP).
    #[derive(Debug, Clone, Copy)]
    pub struct Challenged;

    /// Required actions state - user must complete actions.
    #[derive(Debug, Clone, Copy)]
    pub struct RequiredActions;

    /// Success state - authentication completed.
    #[derive(Debug, Clone, Copy)]
    pub struct Success;

    /// Failed state - authentication failed.
    #[derive(Debug, Clone, Copy)]
    pub struct Failed;
}

/// Authentication flow context.
///
/// The generic parameter `S` represents the current state,
/// ensuring type-safe state transitions.
#[derive(Debug)]
pub struct FlowContext<S> {
    /// Session ID for this flow.
    pub session_id: Uuid,
    /// Realm ID.
    pub realm_id: Uuid,
    /// Client ID.
    pub client_id: Uuid,
    /// User ID (set after identification).
    user_id: Option<Uuid>,
    /// Current execution in the flow.
    execution_id: Option<Uuid>,
    /// Error message (for failed state).
    error: Option<String>,
    /// Required actions to complete.
    required_actions: Vec<String>,
    /// Phantom data for state type.
    _state: PhantomData<S>,
}

impl FlowContext<states::Initial> {
    /// Creates a new authentication flow.
    #[must_use]
    pub fn new(realm_id: Uuid, client_id: Uuid) -> Self {
        Self {
            session_id: Uuid::now_v7(),
            realm_id,
            client_id,
            user_id: None,
            execution_id: None,
            error: None,
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Starts the identification phase.
    #[must_use]
    pub fn start_identification(self) -> FlowContext<states::Identifying> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: None,
            execution_id: None,
            error: None,
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl FlowContext<states::Identifying> {
    /// User identified, proceed to authentication.
    #[must_use]
    pub fn user_identified(self, user_id: Uuid) -> FlowContext<states::Authenticating> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: Some(user_id),
            execution_id: None,
            error: None,
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }

    /// User not found, fail the flow.
    #[must_use]
    pub fn user_not_found(self) -> FlowContext<states::Failed> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: None,
            execution_id: None,
            error: Some("user not found".to_string()),
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl FlowContext<states::Authenticating> {
    /// Authentication succeeded, check for required actions.
    #[must_use]
    pub fn authenticated(self, required_actions: Vec<String>) -> AuthenticatedResult {
        if required_actions.is_empty() {
            AuthenticatedResult::Success(FlowContext {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions: Vec::new(),
                _state: PhantomData,
            })
        } else {
            AuthenticatedResult::RequiredActions(FlowContext {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions,
                _state: PhantomData,
            })
        }
    }

    /// Challenge the user (e.g., for OTP).
    #[must_use]
    pub fn challenge(self, execution_id: Uuid) -> FlowContext<states::Challenged> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: self.user_id,
            execution_id: Some(execution_id),
            error: None,
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Authentication failed.
    #[must_use]
    pub fn failed(self, error: impl Into<String>) -> FlowContext<states::Failed> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: self.user_id,
            execution_id: None,
            error: Some(error.into()),
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl FlowContext<states::Challenged> {
    /// Challenge response accepted.
    #[must_use]
    pub fn challenge_accepted(self, required_actions: Vec<String>) -> AuthenticatedResult {
        if required_actions.is_empty() {
            AuthenticatedResult::Success(FlowContext {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions: Vec::new(),
                _state: PhantomData,
            })
        } else {
            AuthenticatedResult::RequiredActions(FlowContext {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions,
                _state: PhantomData,
            })
        }
    }

    /// Challenge response rejected.
    #[must_use]
    pub fn challenge_rejected(self, error: impl Into<String>) -> FlowContext<states::Failed> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: self.user_id,
            execution_id: None,
            error: Some(error.into()),
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Gets the execution ID for this challenge.
    #[must_use]
    pub const fn execution_id(&self) -> Option<Uuid> {
        self.execution_id
    }
}

impl FlowContext<states::RequiredActions> {
    /// Action completed, check if more actions remain.
    #[must_use]
    pub fn action_completed(mut self, action: &str) -> RequiredActionResult {
        self.required_actions.retain(|a| a != action);

        if self.required_actions.is_empty() {
            RequiredActionResult::Success(FlowContext {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions: Vec::new(),
                _state: PhantomData,
            })
        } else {
            RequiredActionResult::MoreActions(Self {
                session_id: self.session_id,
                realm_id: self.realm_id,
                client_id: self.client_id,
                user_id: self.user_id,
                execution_id: None,
                error: None,
                required_actions: self.required_actions,
                _state: PhantomData,
            })
        }
    }

    /// Gets the remaining required actions.
    #[must_use]
    pub fn required_actions(&self) -> &[String] {
        &self.required_actions
    }

    /// Action failed.
    #[must_use]
    pub fn action_failed(self, error: impl Into<String>) -> FlowContext<states::Failed> {
        FlowContext {
            session_id: self.session_id,
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: self.user_id,
            execution_id: None,
            error: Some(error.into()),
            required_actions: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl FlowContext<states::Success> {
    /// Gets the authenticated user ID.
    #[must_use]
    pub const fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    /// Converts to an auth result.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidState` if no user ID is set.
    pub fn into_result(self) -> AuthResult<Uuid> {
        self.user_id.ok_or(AuthError::InvalidState)
    }
}

impl FlowContext<states::Failed> {
    /// Gets the error message.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Converts to an auth error.
    #[must_use]
    pub fn into_error(self) -> AuthError {
        AuthError::FlowError(self.error.unwrap_or_else(|| "unknown error".to_string()))
    }
}

/// Result of authentication (may need required actions).
#[derive(Debug)]
pub enum AuthenticatedResult {
    /// Authentication complete, proceed to success.
    Success(FlowContext<states::Success>),
    /// User must complete required actions first.
    RequiredActions(FlowContext<states::RequiredActions>),
}

/// Result of completing a required action.
#[derive(Debug)]
pub enum RequiredActionResult {
    /// All actions complete, proceed to success.
    Success(FlowContext<states::Success>),
    /// More actions remain.
    MoreActions(FlowContext<states::RequiredActions>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_flow() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();

        let flow = FlowContext::new(realm_id, client_id);
        let flow = flow.start_identification();
        let flow = flow.user_identified(user_id);

        match flow.authenticated(vec![]) {
            AuthenticatedResult::Success(success) => {
                assert_eq!(success.user_id(), Some(user_id));
            }
            AuthenticatedResult::RequiredActions(_) => {
                panic!("expected success");
            }
        }
    }

    #[test]
    fn flow_with_required_actions() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();

        let flow = FlowContext::new(realm_id, client_id);
        let flow = flow.start_identification();
        let flow = flow.user_identified(user_id);

        match flow.authenticated(vec!["UPDATE_PASSWORD".to_string()]) {
            AuthenticatedResult::Success(_) => {
                panic!("expected required actions");
            }
            AuthenticatedResult::RequiredActions(actions) => {
                assert_eq!(actions.required_actions(), &["UPDATE_PASSWORD"]);

                match actions.action_completed("UPDATE_PASSWORD") {
                    RequiredActionResult::Success(success) => {
                        assert_eq!(success.user_id(), Some(user_id));
                    }
                    RequiredActionResult::MoreActions(_) => {
                        panic!("expected success after action");
                    }
                }
            }
        }
    }

    #[test]
    fn flow_with_challenge() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let execution_id = Uuid::now_v7();

        let flow = FlowContext::new(realm_id, client_id);
        let flow = flow.start_identification();
        let flow = flow.user_identified(user_id);
        let flow = flow.challenge(execution_id);

        assert_eq!(flow.execution_id(), Some(execution_id));

        match flow.challenge_accepted(vec![]) {
            AuthenticatedResult::Success(success) => {
                assert_eq!(success.user_id(), Some(user_id));
            }
            AuthenticatedResult::RequiredActions(_) => {
                panic!("expected success");
            }
        }
    }

    #[test]
    fn failed_flow() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();

        let flow = FlowContext::new(realm_id, client_id);
        let flow = flow.start_identification();
        let flow = flow.user_not_found();

        assert!(flow.error().is_some());
    }
}
