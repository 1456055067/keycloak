//! Shared state for OIDC endpoints.

use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use kc_session::SessionProvider;

use crate::discovery::ProviderMetadata;
use crate::error::OidcResult;
use crate::jwks::JsonWebKeySet;
use crate::token::TokenManager;

use super::grants::{AuthCodeStore, ClientAuthenticator, UserAuthenticator};

/// Provider trait for realm-specific operations.
///
/// Implement this trait to provide realm data from your storage layer.
#[async_trait]
pub trait RealmProvider: Send + Sync {
    /// Checks if a realm exists.
    async fn realm_exists(&self, realm_name: &str) -> OidcResult<bool>;

    /// Gets the realm ID for a realm name.
    async fn get_realm_id(&self, realm_name: &str) -> OidcResult<Uuid>;

    /// Gets the issuer URL for a realm.
    fn get_issuer(&self, realm_name: &str) -> String;

    /// Gets the provider metadata for a realm.
    async fn get_provider_metadata(&self, realm_name: &str) -> OidcResult<ProviderMetadata>;

    /// Gets the JWKS for a realm.
    async fn get_jwks(&self, realm_name: &str) -> OidcResult<JsonWebKeySet>;

    /// Gets the token manager for a realm.
    async fn get_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>>;
}

/// Simple shared state for OIDC endpoints.
///
/// This is the basic state that works with discovery, JWKS, and other
/// endpoints that only need realm information.
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

/// Enhanced state for token endpoint with full grant handling capabilities.
///
/// This state extends the basic `OidcState` with session management, client
/// authentication, user authentication, and authorization code storage.
///
/// Use this state when you need to support all OAuth 2.0 grant types with
/// proper session management.
#[derive(Clone)]
pub struct TokenEndpointState<R, S, C, U, A>
where
    R: RealmProvider,
    S: SessionProvider,
    C: ClientAuthenticator,
    U: UserAuthenticator,
    A: AuthCodeStore,
{
    /// Realm provider for accessing realm-specific data.
    pub realm_provider: Arc<R>,

    /// Session provider for managing user and client sessions.
    pub session_provider: Arc<S>,

    /// Client authenticator for token endpoint.
    pub client_authenticator: Arc<C>,

    /// User authenticator for password grant.
    pub user_authenticator: Arc<U>,

    /// Authorization code store.
    pub auth_code_store: Arc<A>,
}

impl<R, S, C, U, A> TokenEndpointState<R, S, C, U, A>
where
    R: RealmProvider,
    S: SessionProvider,
    C: ClientAuthenticator,
    U: UserAuthenticator,
    A: AuthCodeStore,
{
    /// Creates a new token endpoint state with all providers.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(
        realm_provider: Arc<R>,
        session_provider: Arc<S>,
        client_authenticator: Arc<C>,
        user_authenticator: Arc<U>,
        auth_code_store: Arc<A>,
    ) -> Self {
        Self {
            realm_provider,
            session_provider,
            client_authenticator,
            user_authenticator,
            auth_code_store,
        }
    }

    /// Gets the underlying realm provider.
    pub const fn realm(&self) -> &Arc<R> {
        &self.realm_provider
    }

    /// Gets the session provider.
    pub const fn sessions(&self) -> &Arc<S> {
        &self.session_provider
    }
}
