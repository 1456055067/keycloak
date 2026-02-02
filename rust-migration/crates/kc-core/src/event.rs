//! Event logging for Keycloak Rust.
//!
//! ## NIST 800-53 Rev5: AU-2 (Event Logging)
//!
//! This module provides structured event logging for security-relevant events.
//!
//! ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
//!
//! All events include:
//! - Timestamp (ISO 8601)
//! - Event type
//! - User identity (when available)
//! - Source IP (when available)
//! - Outcome (success/failure)
//! - Affected resources

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Event type categories.
///
/// ## NIST 800-53 Rev5: AU-2
///
/// Events to log:
/// - Authentication attempts (success/failure)
/// - Account creation/modification/deletion
/// - Privilege escalation
/// - Token issuance/revocation
/// - Administrative actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    // Authentication events
    /// User login attempt.
    Login,
    /// User login failed.
    LoginError,
    /// User logout.
    Logout,
    /// Token refresh.
    RefreshToken,
    /// Token refresh failed.
    RefreshTokenError,

    // Account events
    /// User registered.
    Register,
    /// User registration failed.
    RegisterError,
    /// User updated.
    UpdateProfile,
    /// Password updated.
    UpdatePassword,
    /// Password reset requested.
    ResetPassword,

    // Token events
    /// Token issued.
    CodeToToken,
    /// Token issuance failed.
    CodeToTokenError,
    /// Token revoked.
    RevokeGrant,
    /// Token introspected.
    IntrospectToken,

    // Administrative events
    /// Realm created.
    RealmCreated,
    /// Realm updated.
    RealmUpdated,
    /// Realm deleted.
    RealmDeleted,
    /// User created by admin.
    UserCreated,
    /// User updated by admin.
    UserUpdated,
    /// User deleted by admin.
    UserDeleted,
    /// Client created.
    ClientCreated,
    /// Client updated.
    ClientUpdated,
    /// Client deleted.
    ClientDeleted,

    // Role events
    /// Role created.
    RoleCreated,
    /// Role updated.
    RoleUpdated,
    /// Role deleted.
    RoleDeleted,

    // Group events
    /// Group created.
    GroupCreated,
    /// Group updated.
    GroupUpdated,
    /// Group deleted.
    GroupDeleted,

    // User-Role/Group membership events
    /// User added to group.
    UserJoinedGroup,
    /// User removed from group.
    UserLeftGroup,
    /// Role assigned to user.
    RoleAssignedToUser,
    /// Role unassigned from user.
    RoleUnassignedFromUser,

    // Client secret events
    /// Client secret regenerated.
    ClientSecretRegenerated,
}

/// Outcome of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventOutcome {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Failure,
}

/// A security event for audit logging.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: Uuid,

    /// Timestamp of the event (ISO 8601).
    pub timestamp: DateTime<Utc>,

    /// Type of event.
    pub event_type: EventType,

    /// Outcome of the event.
    pub outcome: EventOutcome,

    /// Realm ID where the event occurred.
    pub realm_id: Option<Uuid>,

    /// User ID associated with the event.
    pub user_id: Option<Uuid>,

    /// Client ID associated with the event.
    pub client_id: Option<String>,

    /// Source IP address.
    pub ip_address: Option<String>,

    /// Session ID.
    pub session_id: Option<String>,

    /// Error message (for failure events).
    pub error: Option<String>,

    /// Additional details as key-value pairs.
    pub details: Vec<(String, String)>,
}

impl Event {
    /// Creates a new event builder.
    #[must_use]
    pub const fn builder(event_type: EventType) -> EventBuilder {
        EventBuilder::new(event_type)
    }
}

/// Builder for creating events.
pub struct EventBuilder {
    event_type: EventType,
    outcome: EventOutcome,
    realm_id: Option<Uuid>,
    user_id: Option<Uuid>,
    client_id: Option<String>,
    ip_address: Option<String>,
    session_id: Option<String>,
    error: Option<String>,
    details: Vec<(String, String)>,
}

impl EventBuilder {
    /// Creates a new event builder.
    #[must_use]
    pub const fn new(event_type: EventType) -> Self {
        Self {
            event_type,
            outcome: EventOutcome::Success,
            realm_id: None,
            user_id: None,
            client_id: None,
            ip_address: None,
            session_id: None,
            error: None,
            details: Vec::new(),
        }
    }

    /// Sets the outcome to success.
    #[must_use]
    pub const fn success(mut self) -> Self {
        self.outcome = EventOutcome::Success;
        self
    }

    /// Sets the outcome to failure with an error message.
    #[must_use]
    pub fn failure(mut self, error: impl Into<String>) -> Self {
        self.outcome = EventOutcome::Failure;
        self.error = Some(error.into());
        self
    }

    /// Sets the realm ID.
    #[must_use]
    pub const fn realm(mut self, realm_id: Uuid) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    /// Sets the user ID.
    #[must_use]
    pub const fn user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Sets the client ID.
    #[must_use]
    pub fn client(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Adds a detail key-value pair.
    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.push((key.into(), value.into()));
        self
    }

    /// Builds the event.
    #[must_use]
    pub fn build(self) -> Event {
        Event {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            event_type: self.event_type,
            outcome: self.outcome,
            realm_id: self.realm_id,
            user_id: self.user_id,
            client_id: self.client_id,
            ip_address: self.ip_address,
            session_id: self.session_id,
            error: self.error,
            details: self.details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builder_creates_success_event() {
        let realm_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();

        let event = Event::builder(EventType::Login)
            .success()
            .realm(realm_id)
            .user(user_id)
            .ip_address("192.168.1.1")
            .build();

        assert_eq!(event.event_type, EventType::Login);
        assert_eq!(event.outcome, EventOutcome::Success);
        assert_eq!(event.realm_id, Some(realm_id));
        assert_eq!(event.user_id, Some(user_id));
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
        assert!(event.error.is_none());
    }

    #[test]
    fn event_builder_creates_failure_event() {
        let event = Event::builder(EventType::LoginError)
            .failure("invalid_credentials")
            .ip_address("10.0.0.1")
            .build();

        assert_eq!(event.event_type, EventType::LoginError);
        assert_eq!(event.outcome, EventOutcome::Failure);
        assert_eq!(event.error, Some("invalid_credentials".to_string()));
    }

    #[test]
    fn event_has_timestamp() {
        let before = Utc::now();
        let event = Event::builder(EventType::Logout).build();
        let after = Utc::now();

        assert!(event.timestamp >= before);
        assert!(event.timestamp <= after);
    }
}
