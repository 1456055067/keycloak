//! Client session model.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A client session within a user session.
///
/// Represents the authentication state between a user and a specific client.
/// Each client the user accesses during their SSO session gets its own
/// client session to track tokens, scopes, and other client-specific state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSession {
    // === Identity ===
    /// Unique client session identifier.
    pub id: Uuid,
    /// Parent user session ID.
    pub user_session_id: Uuid,
    /// Client ID (internal `UUID`).
    pub client_id: Uuid,
    /// Realm ID.
    pub realm_id: Uuid,

    // === Timestamps ===
    /// When the client session was created.
    pub created_at: DateTime<Utc>,
    /// When the session was last accessed.
    pub last_accessed: DateTime<Utc>,

    // === Protocol Info ===
    /// Protocol used (openid-connect, saml).
    pub protocol: String,
    /// Redirect URI used for this session.
    pub redirect_uri: Option<String>,
    /// Action being performed (if any).
    pub action: Option<String>,

    // === Scopes and Roles ===
    /// Granted scopes.
    pub scopes: HashSet<String>,
    /// Granted realm roles.
    pub realm_roles: HashSet<Uuid>,
    /// Granted client roles (`client_id` -> `role_ids`).
    pub client_roles: HashMap<Uuid, HashSet<Uuid>>,

    // === Token Info ===
    /// Current refresh token ID (for refresh token rotation).
    pub current_refresh_token: Option<String>,
    /// Current refresh token use count.
    pub current_refresh_token_use_count: i32,

    // === Notes ===
    /// Session notes (key-value pairs for custom data).
    pub notes: HashMap<String, String>,
}

impl ClientSession {
    /// Creates a new client session.
    #[must_use]
    pub fn new(
        user_session_id: Uuid,
        client_id: Uuid,
        realm_id: Uuid,
        protocol: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            user_session_id,
            client_id,
            realm_id,
            created_at: now,
            last_accessed: now,
            protocol: protocol.into(),
            redirect_uri: None,
            action: None,
            scopes: HashSet::new(),
            realm_roles: HashSet::new(),
            client_roles: HashMap::new(),
            current_refresh_token: None,
            current_refresh_token_use_count: 0,
            notes: HashMap::new(),
        }
    }

    /// Sets the redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Adds a scope.
    pub fn add_scope(&mut self, scope: impl Into<String>) {
        self.scopes.insert(scope.into());
    }

    /// Adds multiple scopes.
    pub fn add_scopes(&mut self, scopes: impl IntoIterator<Item = impl Into<String>>) {
        for scope in scopes {
            self.scopes.insert(scope.into());
        }
    }

    /// Checks if a scope is granted.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// Grants a realm role.
    pub fn grant_realm_role(&mut self, role_id: Uuid) {
        self.realm_roles.insert(role_id);
    }

    /// Grants a client role.
    pub fn grant_client_role(&mut self, client_id: Uuid, role_id: Uuid) {
        self.client_roles
            .entry(client_id)
            .or_default()
            .insert(role_id);
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

    /// Updates the last accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Sets the current refresh token.
    pub fn set_refresh_token(&mut self, token_id: impl Into<String>) {
        self.current_refresh_token = Some(token_id.into());
        self.current_refresh_token_use_count = 0;
    }

    /// Increments the refresh token use count.
    pub const fn increment_refresh_token_use(&mut self) {
        self.current_refresh_token_use_count += 1;
    }

    /// Checks if the refresh token has been reused too many times.
    #[must_use]
    pub const fn is_refresh_token_overused(&self, max_reuse: i32) -> bool {
        self.current_refresh_token_use_count > max_reuse
    }
}

/// Well-known client session note keys.
pub mod notes {
    /// The nonce used in the authentication request.
    pub const NONCE: &str = "nonce";
    /// The state parameter from the authentication request.
    pub const STATE: &str = "state";
    /// Code challenge for PKCE.
    pub const CODE_CHALLENGE: &str = "code_challenge";
    /// Code challenge method for PKCE.
    pub const CODE_CHALLENGE_METHOD: &str = "code_challenge_method";
    /// The authorization code.
    pub const CODE: &str = "code";
    /// Response type requested.
    pub const RESPONSE_TYPE: &str = "response_type";
    /// Response mode requested.
    pub const RESPONSE_MODE: &str = "response_mode";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_session() {
        let user_session_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();

        let session = ClientSession::new(user_session_id, client_id, realm_id, "openid-connect");

        assert_eq!(session.user_session_id, user_session_id);
        assert_eq!(session.client_id, client_id);
        assert_eq!(session.protocol, "openid-connect");
        assert!(session.scopes.is_empty());
    }

    #[test]
    fn scopes_management() {
        let user_session_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();

        let mut session =
            ClientSession::new(user_session_id, client_id, realm_id, "openid-connect");

        session.add_scope("openid");
        session.add_scopes(["profile", "email"]);

        assert!(session.has_scope("openid"));
        assert!(session.has_scope("profile"));
        assert!(session.has_scope("email"));
        assert!(!session.has_scope("address"));
    }

    #[test]
    fn refresh_token_tracking() {
        let user_session_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();

        let mut session =
            ClientSession::new(user_session_id, client_id, realm_id, "openid-connect");

        session.set_refresh_token("token-123");
        assert_eq!(session.current_refresh_token, Some("token-123".to_string()));
        assert_eq!(session.current_refresh_token_use_count, 0);

        session.increment_refresh_token_use();
        assert_eq!(session.current_refresh_token_use_count, 1);

        assert!(!session.is_refresh_token_overused(5));
        assert!(session.is_refresh_token_overused(0));
    }
}
