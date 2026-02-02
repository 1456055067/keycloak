//! SPI Registry for managing provider factories.

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::provider::{Provider, ProviderFactory, ProviderMetadata, Spi, SpiError};

/// Registry for SPI provider factories.
///
/// The registry maintains a mapping of SPI types to their provider factories,
/// allowing dynamic lookup and creation of providers.
#[derive(Debug, Default)]
pub struct SpiRegistry {
    /// Map of SPI name to registered factories.
    factories: DashMap<&'static str, Vec<FactoryEntry>>,

    /// Default provider ID per SPI.
    defaults: RwLock<HashMap<&'static str, &'static str>>,
}

#[derive(Debug)]
struct FactoryEntry {
    id: &'static str,
    metadata: ProviderMetadata,
    #[allow(dead_code)]
    type_id: TypeId,
    #[allow(dead_code)]
    factory: Arc<dyn std::any::Any + Send + Sync>,
}

impl SpiRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a provider factory.
    ///
    /// ## Arguments
    ///
    /// * `spi` - The SPI this factory provides
    /// * `factory` - The factory to register
    pub fn register<P, F>(&self, spi: &dyn Spi, factory: F)
    where
        P: Provider + 'static,
        F: ProviderFactory<P> + 'static,
    {
        let metadata = factory.metadata();
        let entry = FactoryEntry {
            id: factory.id(),
            metadata,
            type_id: TypeId::of::<P>(),
            factory: Arc::new(factory),
        };

        self.factories.entry(spi.name()).or_default().push(entry);
    }

    /// Sets the default provider for an SPI.
    pub fn set_default(&self, spi_name: &'static str, provider_id: &'static str) {
        self.defaults.write().insert(spi_name, provider_id);
    }

    /// Gets the default provider ID for an SPI.
    #[must_use]
    pub fn get_default(&self, spi_name: &str) -> Option<&'static str> {
        self.defaults.read().get(spi_name).copied()
    }

    /// Lists all registered provider IDs for an SPI.
    #[must_use]
    pub fn list_providers(&self, spi_name: &str) -> Vec<&'static str> {
        self.factories
            .get(spi_name)
            .map(|entries| entries.iter().map(|e| e.id).collect())
            .unwrap_or_default()
    }

    /// Gets provider metadata by SPI and provider ID.
    #[must_use]
    pub fn get_metadata(&self, spi_name: &str, provider_id: &str) -> Option<ProviderMetadata> {
        self.factories.get(spi_name).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.id == provider_id)
                .map(|e| e.metadata.clone())
        })
    }

    /// Checks if a provider is registered.
    #[must_use]
    pub fn has_provider(&self, spi_name: &str, provider_id: &str) -> bool {
        self.factories
            .get(spi_name)
            .is_some_and(|entries| entries.iter().any(|e| e.id == provider_id))
    }

    /// Returns the number of registered providers for an SPI.
    #[must_use]
    pub fn provider_count(&self, spi_name: &str) -> usize {
        self.factories
            .get(spi_name)
            .map_or(0, |entries| entries.len())
    }

    /// Validates that required providers are registered.
    ///
    /// ## Errors
    ///
    /// Returns an error if a required provider is missing.
    pub fn validate_required(&self, requirements: &[(&str, &str)]) -> Result<(), SpiError> {
        for (spi_name, provider_id) in requirements {
            if !self.has_provider(spi_name, provider_id) {
                return Err(SpiError::ProviderNotFound(format!(
                    "{spi_name}:{provider_id}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct TestSpi;

    impl Spi for TestSpi {
        fn name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn registry_starts_empty() {
        let registry = SpiRegistry::new();
        assert_eq!(registry.provider_count("test"), 0);
    }

    #[test]
    fn can_set_and_get_default() {
        let registry = SpiRegistry::new();
        registry.set_default("test", "default-provider");
        assert_eq!(registry.get_default("test"), Some("default-provider"));
    }

    #[test]
    fn has_provider_returns_false_for_missing() {
        let registry = SpiRegistry::new();
        assert!(!registry.has_provider("test", "missing"));
    }

    #[test]
    fn validate_required_fails_for_missing() {
        let registry = SpiRegistry::new();
        let result = registry.validate_required(&[("test", "required")]);
        assert!(result.is_err());
    }
}
