//! Admin event logging for the Admin API.
//!
//! Provides structured audit logging for administrative operations.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - AU-2: Event Logging
//! - AU-3: Content of Audit Records
//! - AU-12: Audit Generation

use kc_core::event::{Event, EventBuilder, EventType};
use uuid::Uuid;

use crate::auth::AdminAuth;

// ============================================================================
// Event Logger Trait
// ============================================================================

/// Trait for logging admin events.
///
/// Implementations can write to various destinations:
/// - Database (for queryable event store)
/// - Log file (for syslog/SIEM integration)
/// - Message queue (for real-time processing)
#[allow(async_fn_in_trait)]
pub trait AdminEventLogger: Send + Sync {
    /// Logs an admin event.
    ///
    /// # Errors
    ///
    /// Returns an error if the event could not be logged.
    async fn log(&self, event: Event) -> Result<(), EventLogError>;
}

/// Errors that can occur during event logging.
#[derive(Debug, thiserror::Error)]
pub enum EventLogError {
    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// In-Memory Logger (for testing)
// ============================================================================

/// In-memory event logger for testing.
#[derive(Debug, Default)]
pub struct InMemoryEventLogger {
    events: std::sync::RwLock<Vec<Event>>,
}

impl InMemoryEventLogger {
    /// Creates a new in-memory logger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all logged events.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.events.read().unwrap().clone()
    }

    /// Clears all logged events.
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
}

impl AdminEventLogger for InMemoryEventLogger {
    async fn log(&self, event: Event) -> Result<(), EventLogError> {
        self.events.write().unwrap().push(event);
        Ok(())
    }
}

// ============================================================================
// Tracing Logger
// ============================================================================

/// Event logger that writes to the tracing framework.
///
/// Events are logged as structured JSON at the INFO level.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingEventLogger;

impl TracingEventLogger {
    /// Creates a new tracing logger.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AdminEventLogger for TracingEventLogger {
    async fn log(&self, event: Event) -> Result<(), EventLogError> {
        tracing::info!(
            event_id = %event.id,
            event_type = ?event.event_type,
            outcome = ?event.outcome,
            realm_id = ?event.realm_id,
            user_id = ?event.user_id,
            client_id = ?event.client_id,
            ip_address = ?event.ip_address,
            error = ?event.error,
            "admin_event"
        );
        Ok(())
    }
}

// ============================================================================
// Admin Event Builder Helpers
// ============================================================================

/// Helper to build admin events with common context.
pub struct AdminEventBuilder {
    builder: EventBuilder,
    admin_user_id: Option<Uuid>,
    admin_username: Option<String>,
}

impl AdminEventBuilder {
    /// Creates a new admin event builder.
    #[must_use]
    pub fn new(event_type: EventType) -> Self {
        Self {
            builder: Event::builder(event_type),
            admin_user_id: None,
            admin_username: None,
        }
    }

    /// Sets the admin context from authentication.
    #[must_use]
    pub fn with_auth(mut self, auth: &AdminAuth) -> Self {
        self.admin_user_id = Some(auth.user_id);
        self.admin_username = Some(auth.username.clone());
        self.builder = self.builder.detail("admin_user_id", auth.user_id.to_string());
        self.builder = self.builder.detail("admin_username", auth.username.clone());
        self
    }

    /// Sets the realm context.
    #[must_use]
    pub fn realm(mut self, realm_id: Uuid) -> Self {
        self.builder = self.builder.realm(realm_id);
        self
    }

    /// Sets the target resource type.
    #[must_use]
    pub fn resource_type(mut self, resource_type: &str) -> Self {
        self.builder = self.builder.detail("resource_type", resource_type);
        self
    }

    /// Sets the target resource ID.
    #[must_use]
    pub fn resource_id(mut self, id: Uuid) -> Self {
        self.builder = self.builder.detail("resource_id", id.to_string());
        self
    }

    /// Sets the target resource name.
    #[must_use]
    pub fn resource_name(mut self, name: impl Into<String>) -> Self {
        self.builder = self.builder.detail("resource_name", name.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.builder = self.builder.ip_address(ip);
        self
    }

    /// Adds a detail key-value pair.
    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.builder = self.builder.detail(key, value);
        self
    }

    /// Marks the event as successful.
    #[must_use]
    pub fn success(mut self) -> Self {
        self.builder = self.builder.success();
        self
    }

    /// Marks the event as failed with an error message.
    #[must_use]
    pub fn failure(mut self, error: impl Into<String>) -> Self {
        self.builder = self.builder.failure(error);
        self
    }

    /// Builds the event.
    #[must_use]
    pub fn build(self) -> Event {
        self.builder.build()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Logs a realm creation event.
pub async fn log_realm_created(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    realm_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RealmCreated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("realm")
        .resource_id(realm_id)
        .resource_name(realm_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a realm update event.
pub async fn log_realm_updated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    realm_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RealmUpdated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("realm")
        .resource_id(realm_id)
        .resource_name(realm_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a realm deletion event.
pub async fn log_realm_deleted(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    realm_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RealmDeleted)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("realm")
        .resource_id(realm_id)
        .resource_name(realm_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a user creation event.
pub async fn log_user_created(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    user_id: Uuid,
    username: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::UserCreated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("user")
        .resource_id(user_id)
        .resource_name(username)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a user update event.
pub async fn log_user_updated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    user_id: Uuid,
    username: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::UserUpdated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("user")
        .resource_id(user_id)
        .resource_name(username)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a user deletion event.
pub async fn log_user_deleted(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    user_id: Uuid,
    username: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::UserDeleted)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("user")
        .resource_id(user_id)
        .resource_name(username)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a client creation event.
pub async fn log_client_created(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    client_uuid: Uuid,
    client_id: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::ClientCreated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("client")
        .resource_id(client_uuid)
        .resource_name(client_id)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a client update event.
pub async fn log_client_updated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    client_uuid: Uuid,
    client_id: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::ClientUpdated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("client")
        .resource_id(client_uuid)
        .resource_name(client_id)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a client deletion event.
pub async fn log_client_deleted(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    client_uuid: Uuid,
    client_id: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::ClientDeleted)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("client")
        .resource_id(client_uuid)
        .resource_name(client_id)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a role creation event.
pub async fn log_role_created(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    role_id: Uuid,
    role_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RoleCreated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("role")
        .resource_id(role_id)
        .resource_name(role_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a role update event.
pub async fn log_role_updated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    role_id: Uuid,
    role_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RoleUpdated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("role")
        .resource_id(role_id)
        .resource_name(role_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a role deletion event.
pub async fn log_role_deleted(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    role_id: Uuid,
    role_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::RoleDeleted)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("role")
        .resource_id(role_id)
        .resource_name(role_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a group creation event.
pub async fn log_group_created(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    group_id: Uuid,
    group_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::GroupCreated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("group")
        .resource_id(group_id)
        .resource_name(group_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a group update event.
pub async fn log_group_updated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    group_id: Uuid,
    group_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::GroupUpdated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("group")
        .resource_id(group_id)
        .resource_name(group_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a group deletion event.
pub async fn log_group_deleted(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    group_id: Uuid,
    group_name: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::GroupDeleted)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("group")
        .resource_id(group_id)
        .resource_name(group_name)
        .success()
        .build();
    logger.log(event).await
}

/// Logs a client secret regeneration event.
pub async fn log_client_secret_regenerated(
    logger: &impl AdminEventLogger,
    auth: &AdminAuth,
    realm_id: Uuid,
    client_uuid: Uuid,
    client_id: &str,
) -> Result<(), EventLogError> {
    let event = AdminEventBuilder::new(EventType::ClientSecretRegenerated)
        .with_auth(auth)
        .realm(realm_id)
        .resource_type("client")
        .resource_id(client_uuid)
        .resource_name(client_id)
        .success()
        .build();
    logger.log(event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_logger_stores_events() {
        let logger = InMemoryEventLogger::new();
        let event = Event::builder(EventType::RealmCreated).success().build();

        logger.log(event.clone()).await.unwrap();

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::RealmCreated);
    }

    #[test]
    fn admin_event_builder_with_auth() {
        let auth = AdminAuth {
            user_id: Uuid::now_v7(),
            username: "admin".to_string(),
            realm: "master".to_string(),
            target_realm: None,
            permissions: vec![],
            token: "test".to_string(),
        };

        let event = AdminEventBuilder::new(EventType::UserCreated)
            .with_auth(&auth)
            .realm(Uuid::now_v7())
            .resource_type("user")
            .resource_id(Uuid::now_v7())
            .resource_name("testuser")
            .success()
            .build();

        assert_eq!(event.event_type, EventType::UserCreated);
        assert!(event.details.iter().any(|(k, _)| k == "admin_username"));
        assert!(event.details.iter().any(|(k, _)| k == "resource_type"));
    }
}
