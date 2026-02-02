//! Keycloak session management.

use std::sync::Arc;

use parking_lot::RwLock;
use uuid::Uuid;

use crate::registry::SpiRegistry;

/// A Keycloak session represents a unit of work.
///
/// Sessions provide access to providers and manage transactions.
/// Each request typically gets its own session.
#[derive(Debug)]
pub struct KeycloakSession {
    /// Unique session identifier.
    id: Uuid,

    /// Reference to the SPI registry.
    registry: Arc<SpiRegistry>,

    /// Session attributes.
    attributes: RwLock<std::collections::HashMap<String, String>>,

    /// Whether this session has been closed.
    closed: RwLock<bool>,
}

impl KeycloakSession {
    /// Creates a new session.
    #[must_use]
    pub fn new(registry: Arc<SpiRegistry>) -> Self {
        Self {
            id: Uuid::now_v7(),
            registry,
            attributes: RwLock::new(std::collections::HashMap::new()),
            closed: RwLock::new(false),
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the SPI registry.
    #[must_use]
    pub const fn registry(&self) -> &Arc<SpiRegistry> {
        &self.registry
    }

    /// Sets a session attribute.
    pub fn set_attribute(&self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.write().insert(key.into(), value.into());
    }

    /// Gets a session attribute.
    #[must_use]
    pub fn get_attribute(&self, key: &str) -> Option<String> {
        self.attributes.read().get(key).cloned()
    }

    /// Removes a session attribute.
    pub fn remove_attribute(&self, key: &str) -> Option<String> {
        self.attributes.write().remove(key)
    }

    /// Returns whether the session has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed.read()
    }

    /// Closes the session.
    ///
    /// After closing, the session should not be used.
    pub fn close(&self) {
        *self.closed.write() = true;
    }
}

impl Drop for KeycloakSession {
    fn drop(&mut self) {
        if !*self.closed.read() {
            // Log warning about unclosed session in production
            self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_has_unique_id() {
        let registry = Arc::new(SpiRegistry::new());
        let session1 = KeycloakSession::new(Arc::clone(&registry));
        let session2 = KeycloakSession::new(Arc::clone(&registry));

        assert_ne!(session1.id(), session2.id());
    }

    #[test]
    fn session_attributes_work() {
        let registry = Arc::new(SpiRegistry::new());
        let session = KeycloakSession::new(registry);

        session.set_attribute("key", "value");
        assert_eq!(session.get_attribute("key"), Some("value".to_string()));

        let removed = session.remove_attribute("key");
        assert_eq!(removed, Some("value".to_string()));
        assert_eq!(session.get_attribute("key"), None);
    }

    #[test]
    fn session_can_be_closed() {
        let registry = Arc::new(SpiRegistry::new());
        let session = KeycloakSession::new(registry);

        assert!(!session.is_closed());
        session.close();
        assert!(session.is_closed());
    }
}
