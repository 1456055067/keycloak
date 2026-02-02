//! User session (SSO session) model.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// State of a user session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    /// Session is active and valid.
    #[default]
    Active,
    /// Session is logged out but not yet expired.
    LoggedOut,
    /// Session is logged out via backchannel.
    LoggedOutUnconfirmed,
}

/// A user session (SSO session).
///
/// Represents an authenticated user's session across multiple clients.
/// Each user session can have multiple client sessions for different
/// applications the user has accessed.
///
/// ## NIST 800-63B Session Management
///
/// - Sessions have configurable idle and absolute timeouts
/// - Sessions can be revoked (logout)
/// - Session binding to IP is optional (for mobile users)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    // === Identity ===
    /// Unique session identifier.
    pub id: Uuid,
    /// Realm this session belongs to.
    pub realm_id: Uuid,
    /// User who owns this session.
    pub user_id: Uuid,

    // === Session State ===
    /// Current state of the session.
    pub state: SessionState,
    /// Whether this session used "Remember Me".
    pub remember_me: bool,

    // === Authentication Info ===
    /// Broker session ID (for federated logins).
    pub broker_session_id: Option<String>,
    /// Identity provider used for authentication.
    pub broker_user_id: Option<String>,
    /// Authentication method used.
    pub auth_method: Option<String>,

    // === Timestamps ===
    /// When the session was created.
    pub started_at: DateTime<Utc>,
    /// Last activity timestamp.
    pub last_activity: DateTime<Utc>,

    // === Client Info ===
    /// IP address of the client.
    pub ip_address: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,

    // === Notes ===
    /// Session notes (key-value pairs for custom data).
    pub notes: HashMap<String, String>,
}

impl UserSession {
    /// Creates a new user session.
    #[must_use]
    pub fn new(realm_id: Uuid, user_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            realm_id,
            user_id,
            state: SessionState::Active,
            remember_me: false,
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            started_at: now,
            last_activity: now,
            ip_address: None,
            user_agent: None,
            notes: HashMap::new(),
        }
    }

    /// Sets the remember me flag.
    #[must_use]
    pub const fn with_remember_me(mut self, remember_me: bool) -> Self {
        self.remember_me = remember_me;
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
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

    /// Updates the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Checks if the session is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Checks if the session has expired based on timeouts.
    ///
    /// ## Arguments
    ///
    /// * `idle_timeout` - Maximum idle time in seconds
    /// * `max_lifespan` - Maximum session lifespan in seconds
    #[must_use]
    pub fn is_expired(&self, idle_timeout: i64, max_lifespan: i64) -> bool {
        let now = Utc::now();

        // Check idle timeout
        let idle_seconds = (now - self.last_activity).num_seconds();
        if idle_seconds > idle_timeout {
            return true;
        }

        // Check max lifespan
        let age_seconds = (now - self.started_at).num_seconds();
        if age_seconds > max_lifespan {
            return true;
        }

        false
    }

    /// Marks the session as logged out.
    pub const fn logout(&mut self) {
        self.state = SessionState::LoggedOut;
    }

    /// Returns the session age in seconds.
    #[must_use]
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.started_at).num_seconds()
    }

    /// Returns the idle time in seconds.
    #[must_use]
    pub fn idle_seconds(&self) -> i64 {
        (Utc::now() - self.last_activity).num_seconds()
    }
}

/// Well-known session note keys.
pub mod notes {
    /// The client that initiated the authentication.
    pub const AUTH_CLIENT_ID: &str = "AUTH_CLIENT_ID";
    /// The identity provider alias used.
    pub const IDENTITY_PROVIDER: &str = "IDENTITY_PROVIDER";
    /// The external identity provider session ID.
    pub const IDENTITY_PROVIDER_SESSION_ID: &str = "IDENTITY_PROVIDER_SESSION_ID";
    /// The authentication context class reference.
    pub const ACR: &str = "ACR";
    /// Whether step-up authentication was performed.
    pub const LOA: &str = "LOA";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_active() {
        let realm_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let session = UserSession::new(realm_id, user_id);

        assert!(session.is_active());
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn session_notes() {
        let realm_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let mut session = UserSession::new(realm_id, user_id);

        session.set_note(notes::AUTH_CLIENT_ID, "my-app");
        assert_eq!(session.get_note(notes::AUTH_CLIENT_ID), Some("my-app"));
        assert_eq!(session.get_note("missing"), None);
    }

    #[test]
    fn session_logout() {
        let realm_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let mut session = UserSession::new(realm_id, user_id);

        assert!(session.is_active());
        session.logout();
        assert!(!session.is_active());
        assert_eq!(session.state, SessionState::LoggedOut);
    }

    #[test]
    fn session_expiration() {
        let realm_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let session = UserSession::new(realm_id, user_id);

        // Fresh session should not be expired with reasonable timeouts
        assert!(!session.is_expired(1800, 36000));

        // Session should be expired with negative timeout (already past)
        assert!(session.is_expired(-1, -1));
    }
}
