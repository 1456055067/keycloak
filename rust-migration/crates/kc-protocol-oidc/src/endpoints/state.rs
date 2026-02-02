//! Shared state for OIDC endpoints.

use async_trait::async_trait;
use std::sync::Arc;

use crate::discovery::ProviderMetadata;
use crate::error::OidcResult;
use crate::jwks::JsonWebKeySet;
use crate::token::TokenManager;

/// Provider trait for realm-specific operations.
///
/// Implement this trait to provide realm data from your storage layer.
#[async_trait]
pub trait RealmProvider: Send + Sync {
    /// Checks if a realm exists.
    async fn realm_exists(&self, realm_name: &str) -> OidcResult<bool>;

    /// Gets the issuer URL for a realm.
    fn get_issuer(&self, realm_name: &str) -> String;

    /// Gets the provider metadata for a realm.
    async fn get_provider_metadata(&self, realm_name: &str) -> OidcResult<ProviderMetadata>;

    /// Gets the JWKS for a realm.
    async fn get_jwks(&self, realm_name: &str) -> OidcResult<JsonWebKeySet>;

    /// Gets the token manager for a realm.
    async fn get_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>>;
}

/// Shared state for OIDC endpoints.
#[derive(Clone)]
pub struct OidcState<R: RealmProvider> {
    /// Realm provider for accessing realm-specific data.
    pub realm_provider: Arc<R>,
}

impl<R: RealmProvider> OidcState<R> {
    /// Creates a new OIDC state.
    pub fn new(realm_provider: R) -> Self {
        Self {
            realm_provider: Arc::new(realm_provider),
        }
    }

    /// Creates a new OIDC state from an Arc.
    pub const fn from_arc(realm_provider: Arc<R>) -> Self {
        Self { realm_provider }
    }
}
