//! Authentication session model.
//!
//! Temporary sessions used during the authentication flow, before
//! a full user session is established.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An authentication session.
///
/// Represents the state of an ongoing authentication flow. This session
/// is temporary and is either converted to a [`UserSession`] upon successful
/// authentication or discarded on failure/timeout.
///
/// ## Flow
///
/// 1. Client redirects to Keycloak → `AuthenticationSession` created
/// 2. User completes authentication steps
/// 3. Authentication succeeds → `AuthenticationSession` converted to `UserSession`
/// 4. Authentication fails/times out → `AuthenticationSession` deleted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSession {
    // === Identity ===
    /// Unique session identifier (also used as tab ID in browser).
    pub id: Uuid,
    /// Root authentication session ID (for multi-tab scenarios).
    pub root_session_id: Uuid,
    /// Realm ID.
    pub realm_id: Uuid,

    // === Client Info ===
    /// Client that initiated the authentication.
    pub client_id: Uuid,
    /// Redirect URI for this authentication.
    pub redirect_uri: Option<String>,

    // === Authentication State ===
    /// Current execution ID in the authentication flow.
    pub auth_flow_id: Option<Uuid>,
    /// Current execution status.
    pub execution_status: HashMap<Uuid, ExecutionStatus>,
    /// User being authenticated (set after identification).
    pub authenticated_user_id: Option<Uuid>,

    // === Protocol Parameters ===
    /// Protocol (openid-connect, saml).
    pub protocol: String,
    /// Response type (code, token, `id_token`).
    pub response_type: Option<String>,
    /// Response mode (query, fragment, `form_post`).
    pub response_mode: Option<String>,
    /// Requested scopes.
    pub scopes: HashSet<String>,
    /// State parameter.
    pub state: Option<String>,
    /// Nonce parameter.
    pub nonce: Option<String>,

    // === PKCE ===
    /// Code challenge for PKCE.
    pub code_challenge: Option<String>,
    /// Code challenge method (S256 or plain).
    pub code_challenge_method: Option<String>,

    // === Required Actions ===
    /// Required actions that must be completed.
    pub required_actions: HashSet<String>,

    // === Timestamps ===
    /// When the session was created.
    pub created_at: DateTime<Utc>,

    // === Notes ===
    /// Session notes (key-value pairs for passing data between authenticators).
    pub notes: HashMap<String, String>,
    /// Client notes (passed back to client in response).
    pub client_notes: HashMap<String, String>,
    /// User session notes (will be copied to `UserSession` on success).
    pub user_session_notes: HashMap<String, String>,
}

/// Status of an authentication execution (step in the flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    /// Execution not yet started.
    #[default]
    NotStarted,
    /// Execution in progress.
    InProgress,
    /// Execution succeeded.
    Success,
    /// Execution was skipped.
    Skipped,
    /// Execution failed.
    Failed,
    /// Execution was challenged (waiting for user input).
    Challenged,
    /// User attempted but failed this execution.
    Attempted,
    /// Flow was reset.
    FlowReset,
}

impl AuthenticationSession {
    /// Creates a new authentication session.
    #[must_use]
    pub fn new(realm_id: Uuid, client_id: Uuid, protocol: impl Into<String>) -> Self {
        let id = Uuid::now_v7();
        Self {
            id,
            root_session_id: id, // Initially same as id
            realm_id,
            client_id,
            redirect_uri: None,
            auth_flow_id: None,
            execution_status: HashMap::new(),
            authenticated_user_id: None,
            protocol: protocol.into(),
            response_type: None,
            response_mode: None,
            scopes: HashSet::new(),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            required_actions: HashSet::new(),
            created_at: Utc::now(),
            notes: HashMap::new(),
            client_notes: HashMap::new(),
            user_session_notes: HashMap::new(),
        }
    }

    /// Sets the redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Sets the state parameter.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the nonce parameter.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the PKCE challenge.
    #[must_use]
    pub fn with_pkce(mut self, challenge: impl Into<String>, method: impl Into<String>) -> Self {
        self.code_challenge = Some(challenge.into());
        self.code_challenge_method = Some(method.into());
        self
    }

    /// Adds a scope.
    pub fn add_scope(&mut self, scope: impl Into<String>) {
        self.scopes.insert(scope.into());
    }

    /// Sets the authenticated user.
    pub const fn set_authenticated_user(&mut self, user_id: Uuid) {
        self.authenticated_user_id = Some(user_id);
    }

    /// Checks if a user has been authenticated.
    #[must_use]
    pub const fn is_user_authenticated(&self) -> bool {
        self.authenticated_user_id.is_some()
    }

    /// Sets the execution status for a step.
    pub fn set_execution_status(&mut self, execution_id: Uuid, status: ExecutionStatus) {
        self.execution_status.insert(execution_id, status);
    }

    /// Gets the execution status for a step.
    #[must_use]
    pub fn get_execution_status(&self, execution_id: Uuid) -> ExecutionStatus {
        self.execution_status
            .get(&execution_id)
            .copied()
            .unwrap_or_default()
    }

    /// Adds a required action.
    pub fn add_required_action(&mut self, action: impl Into<String>) {
        self.required_actions.insert(action.into());
    }

    /// Removes a required action.
    pub fn remove_required_action(&mut self, action: &str) {
        self.required_actions.remove(action);
    }

    /// Checks if all required actions are complete.
    #[must_use]
    pub fn are_required_actions_complete(&self) -> bool {
        self.required_actions.is_empty()
    }

    /// Sets a session note.
    pub fn set_note(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.notes.insert(key.into(), value.into());
    }

    /// Gets a session note.
    #[must_use]
    pub fn get_note(&self, key: &str) -> Option<&str> {
        self.notes.get(key).map(String::as_str)
    }

    /// Removes a session note.
    pub fn remove_note(&mut self, key: &str) -> Option<String> {
        self.notes.remove(key)
    }

    /// Sets a client note (passed back to client).
    pub fn set_client_note(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.client_notes.insert(key.into(), value.into());
    }

    /// Sets a user session note (copied to `UserSession` on success).
    pub fn set_user_session_note(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.user_session_notes.insert(key.into(), value.into());
    }

    /// Checks if PKCE is required for this session.
    #[must_use]
    pub const fn is_pkce_required(&self) -> bool {
        self.code_challenge.is_some()
    }

    /// Returns the session age in seconds.
    #[must_use]
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.created_at).num_seconds()
    }

    /// Checks if the session has expired.
    #[must_use]
    pub fn is_expired(&self, timeout_seconds: i64) -> bool {
        self.age_seconds() > timeout_seconds
    }
}

/// Well-known authentication session note keys.
pub mod notes {
    /// Error message from failed authentication.
    pub const AUTH_ERROR: &str = "AUTH_ERROR";
    /// Identity provider being used.
    pub const IDENTITY_PROVIDER: &str = "IDENTITY_PROVIDER";
    /// Login hint (pre-filled username).
    pub const LOGIN_HINT: &str = "login_hint";
    /// Prompt parameter (none, login, consent, `select_account`).
    pub const PROMPT: &str = "prompt";
    /// Max age parameter (seconds since last auth).
    pub const MAX_AGE: &str = "max_age";
    /// ACR values requested.
    pub const ACR_VALUES: &str = "acr_values";
    /// UI locales requested.
    pub const UI_LOCALES: &str = "ui_locales";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_auth_session() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();

        let session = AuthenticationSession::new(realm_id, client_id, "openid-connect");

        assert_eq!(session.realm_id, realm_id);
        assert_eq!(session.client_id, client_id);
        assert_eq!(session.protocol, "openid-connect");
        assert!(!session.is_user_authenticated());
    }

    #[test]
    fn pkce_support() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();

        let session = AuthenticationSession::new(realm_id, client_id, "openid-connect")
            .with_pkce("challenge123", "S256");

        assert!(session.is_pkce_required());
        assert_eq!(session.code_challenge, Some("challenge123".to_string()));
        assert_eq!(session.code_challenge_method, Some("S256".to_string()));
    }

    #[test]
    fn required_actions() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();

        let mut session = AuthenticationSession::new(realm_id, client_id, "openid-connect");

        assert!(session.are_required_actions_complete());

        session.add_required_action("UPDATE_PASSWORD");
        assert!(!session.are_required_actions_complete());

        session.remove_required_action("UPDATE_PASSWORD");
        assert!(session.are_required_actions_complete());
    }

    #[test]
    fn execution_status() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let exec_id = Uuid::now_v7();

        let mut session = AuthenticationSession::new(realm_id, client_id, "openid-connect");

        assert_eq!(
            session.get_execution_status(exec_id),
            ExecutionStatus::NotStarted
        );

        session.set_execution_status(exec_id, ExecutionStatus::Success);
        assert_eq!(
            session.get_execution_status(exec_id),
            ExecutionStatus::Success
        );
    }
}
