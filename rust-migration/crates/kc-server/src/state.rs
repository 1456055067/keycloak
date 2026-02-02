//! Application state management.
//!
//! This module defines the shared state that is passed to all request handlers.

use std::sync::Arc;

use kc_protocol_oidc::endpoints::OidcState;

use crate::config::ServerConfig;
use crate::providers::StorageProviders;

/// Application state shared across all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// Server configuration.
    pub config: ServerConfig,

    /// Storage providers.
    pub providers: Arc<StorageProviders>,
}

impl AppState {
    /// Creates a new application state.
    pub fn new(config: ServerConfig, providers: Arc<StorageProviders>) -> Self {
        Self { config, providers }
    }

    /// Gets the OIDC state for the protocol endpoints.
    pub fn oidc_state(&self) -> OidcState<StorageProviders> {
        OidcState::from_arc(self.providers.clone())
    }

    /// Returns a reference to the storage providers.
    pub fn providers(&self) -> &StorageProviders {
        &self.providers
    }

    /// Returns the server configuration.
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }
}
