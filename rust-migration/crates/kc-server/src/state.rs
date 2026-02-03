//! Application state management.
//!
//! This module defines the shared state that is passed to all request handlers.

use std::sync::Arc;

use kc_admin_api::{ClientState, GroupState, RoleState, UserState};
use kc_protocol_oidc::endpoints::OidcState;
use kc_protocol_saml::endpoints::SamlState;
use kc_storage_sql::providers::{
    PgClientProvider, PgCredentialProvider, PgGroupProvider, PgRealmProvider, PgRoleProvider,
    PgUserProvider,
};

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

    /// Gets the SAML state for the protocol endpoints.
    pub fn saml_state(&self) -> SamlState<StorageProviders> {
        SamlState::new(self.providers.clone())
    }

    /// Returns a reference to the storage providers.
    pub fn providers(&self) -> &StorageProviders {
        &self.providers
    }

    /// Returns the server configuration.
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Gets the Admin API user state (for realm and user management).
    pub fn admin_user_state(
        &self,
    ) -> UserState<PgRealmProvider, PgUserProvider, PgCredentialProvider> {
        UserState::new(
            self.providers.realm.clone(),
            self.providers.user.clone(),
            self.providers.credential.clone(),
        )
    }

    /// Gets the Admin API client state (for client management).
    pub fn admin_client_state(&self) -> ClientState<PgRealmProvider, PgClientProvider> {
        ClientState::new(
            self.providers.realm.clone(),
            self.providers.client.clone(),
        )
    }

    /// Gets the Admin API role state (for role management).
    pub fn admin_role_state(
        &self,
    ) -> RoleState<PgRealmProvider, PgClientProvider, PgRoleProvider> {
        RoleState::new(
            self.providers.realm.clone(),
            self.providers.client.clone(),
            self.providers.role.clone(),
        )
    }

    /// Gets the Admin API group state (for group management).
    pub fn admin_group_state(&self) -> GroupState<PgRealmProvider, PgGroupProvider> {
        GroupState::new(
            self.providers.realm.clone(),
            self.providers.group.clone(),
        )
    }
}
