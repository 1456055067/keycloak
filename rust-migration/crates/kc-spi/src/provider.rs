//! Provider traits for the SPI system.

use async_trait::async_trait;
use std::any::Any;
use std::fmt::Debug;
use thiserror::Error;

use crate::session::KeycloakSession;

/// Error type for SPI operations.
#[derive(Debug, Error)]
pub enum SpiError {
    /// Provider not found.
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    /// Provider initialization failed.
    #[error("provider initialization failed: {0}")]
    InitializationFailed(String),

    /// Provider creation failed.
    #[error("provider creation failed: {0}")]
    CreationFailed(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),
}

/// Base trait for all providers.
///
/// Providers are the core building blocks of Keycloak's extensibility.
/// Each provider implements a specific capability (authentication, storage, etc.).
///
/// ## Power of 10 Rule 1
///
/// Functions should not exceed 60 lines. Provider implementations should
/// delegate complex logic to helper functions.
pub trait Provider: Send + Sync + Debug + Any {
    /// Called when the provider is being closed.
    ///
    /// Use this to clean up any resources held by the provider.
    fn close(&self) {}

    /// Returns a reference to self as Any for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Returns a mutable reference to self as Any for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Metadata about a provider.
#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    /// Unique identifier for this provider.
    pub id: &'static str,

    /// Human-readable name.
    pub name: &'static str,

    /// Description of what this provider does.
    pub description: &'static str,

    /// Priority for ordering (higher = preferred).
    pub priority: i32,
}

/// Factory for creating provider instances.
///
/// Factories are singletons that create provider instances for each session.
/// They handle initialization and configuration of providers.
///
/// ## Lifecycle
///
/// 1. `init()` - Called once at startup with configuration
/// 2. `post_init()` - Called after all factories are initialized
/// 3. `create()` - Called for each session to create a provider instance
/// 4. `close()` - Called at shutdown
#[async_trait]
pub trait ProviderFactory<P: Provider>: Send + Sync + Debug {
    /// Returns the unique identifier for this factory.
    fn id(&self) -> &'static str;

    /// Returns metadata about providers created by this factory.
    fn metadata(&self) -> ProviderMetadata;

    /// Returns the priority for ordering (higher = preferred).
    fn order(&self) -> i32 {
        0
    }

    /// Initializes the factory with configuration.
    ///
    /// Called once at startup.
    ///
    /// ## Errors
    ///
    /// Returns an error if initialization fails.
    async fn init(&mut self, config: &dyn FactoryConfig) -> Result<(), SpiError>;

    /// Called after all factories have been initialized.
    ///
    /// Use this for cross-factory initialization that depends on other factories.
    ///
    /// ## Errors
    ///
    /// Returns an error if post-initialization fails.
    async fn post_init(&mut self) -> Result<(), SpiError> {
        Ok(())
    }

    /// Creates a new provider instance for the given session.
    ///
    /// ## Errors
    ///
    /// Returns an error if provider creation fails.
    async fn create(&self, session: &KeycloakSession) -> Result<P, SpiError>;

    /// Called when the factory is being shut down.
    fn close(&self) {}
}

/// Configuration interface for factory initialization.
pub trait FactoryConfig: Send + Sync {
    /// Gets a string configuration value.
    fn get(&self, key: &str) -> Option<&str>;

    /// Gets an integer configuration value.
    fn get_int(&self, key: &str, default: i32) -> i32 {
        self.get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Gets a boolean configuration value.
    fn get_bool(&self, key: &str, default: bool) -> bool {
        self.get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}

/// Definition of an SPI extension point.
///
/// An SPI defines a category of providers (e.g., "authenticator", "user-storage").
pub trait Spi: Send + Sync {
    /// Returns the unique name of this SPI.
    fn name(&self) -> &'static str;

    /// Returns whether this SPI is internal (not meant for external extension).
    fn is_internal(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestProvider {
        id: String,
    }

    impl Provider for TestProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    #[test]
    fn provider_can_be_downcast() {
        let provider = TestProvider {
            id: "test".to_string(),
        };

        let any_ref = provider.as_any();
        let downcast = any_ref.downcast_ref::<TestProvider>();

        assert!(downcast.is_some());
        assert_eq!(downcast.unwrap().id, "test");
    }
}
