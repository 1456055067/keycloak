//! Admin API state management.
//!
//! Defines the shared state structure for the Admin API endpoints.

use std::sync::Arc;

use kc_storage::{
    ClientProvider, CredentialProvider, GroupProvider, RealmProvider, RoleProvider, UserProvider,
};

/// Admin API application state.
///
/// Contains all providers needed by the Admin API endpoints.
/// Uses `Arc` for thread-safe shared ownership.
pub struct AdminState<R, U, C, Ro, G, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    C: ClientProvider,
    Ro: RoleProvider,
    G: GroupProvider,
    Cr: CredentialProvider,
{
    /// Realm storage provider.
    pub realm_provider: Arc<R>,
    /// User storage provider.
    pub user_provider: Arc<U>,
    /// Client storage provider.
    pub client_provider: Arc<C>,
    /// Role storage provider.
    pub role_provider: Arc<Ro>,
    /// Group storage provider.
    pub group_provider: Arc<G>,
    /// Credential storage provider.
    pub credential_provider: Arc<Cr>,
}

// Manual Clone implementation that doesn't require T: Clone for Arc<T>
impl<R, U, C, Ro, G, Cr> Clone for AdminState<R, U, C, Ro, G, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    C: ClientProvider,
    Ro: RoleProvider,
    G: GroupProvider,
    Cr: CredentialProvider,
{
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
            user_provider: Arc::clone(&self.user_provider),
            client_provider: Arc::clone(&self.client_provider),
            role_provider: Arc::clone(&self.role_provider),
            group_provider: Arc::clone(&self.group_provider),
            credential_provider: Arc::clone(&self.credential_provider),
        }
    }
}

impl<R, U, C, Ro, G, Cr> AdminState<R, U, C, Ro, G, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    C: ClientProvider,
    Ro: RoleProvider,
    G: GroupProvider,
    Cr: CredentialProvider,
{
    /// Creates a new admin state with all providers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm_provider: Arc<R>,
        user_provider: Arc<U>,
        client_provider: Arc<C>,
        role_provider: Arc<Ro>,
        group_provider: Arc<G>,
        credential_provider: Arc<Cr>,
    ) -> Self {
        Self {
            realm_provider,
            user_provider,
            client_provider,
            role_provider,
            group_provider,
            credential_provider,
        }
    }
}

/// Simplified state for realm-only operations.
pub struct RealmState<R>
where
    R: RealmProvider,
{
    /// Realm storage provider.
    pub realm_provider: Arc<R>,
}

impl<R: RealmProvider> Clone for RealmState<R> {
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
        }
    }
}

impl<R> RealmState<R>
where
    R: RealmProvider,
{
    /// Creates a new realm-only state.
    pub fn new(realm_provider: Arc<R>) -> Self {
        Self { realm_provider }
    }
}

/// State for user operations (requires realm context).
pub struct UserState<R, U, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    /// Realm storage provider (for realm validation).
    pub realm_provider: Arc<R>,
    /// User storage provider.
    pub user_provider: Arc<U>,
    /// Credential storage provider.
    pub credential_provider: Arc<Cr>,
}

impl<R, U, Cr> Clone for UserState<R, U, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
            user_provider: Arc::clone(&self.user_provider),
            credential_provider: Arc::clone(&self.credential_provider),
        }
    }
}

impl<R, U, Cr> UserState<R, U, Cr>
where
    R: RealmProvider,
    U: UserProvider,
    Cr: CredentialProvider,
{
    /// Creates a new user state.
    pub fn new(
        realm_provider: Arc<R>,
        user_provider: Arc<U>,
        credential_provider: Arc<Cr>,
    ) -> Self {
        Self {
            realm_provider,
            user_provider,
            credential_provider,
        }
    }
}

/// State for client operations (requires realm context).
pub struct ClientState<R, C>
where
    R: RealmProvider,
    C: ClientProvider,
{
    /// Realm storage provider (for realm validation).
    pub realm_provider: Arc<R>,
    /// Client storage provider.
    pub client_provider: Arc<C>,
}

impl<R, C> Clone for ClientState<R, C>
where
    R: RealmProvider,
    C: ClientProvider,
{
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
            client_provider: Arc::clone(&self.client_provider),
        }
    }
}

impl<R, C> ClientState<R, C>
where
    R: RealmProvider,
    C: ClientProvider,
{
    /// Creates a new client state.
    pub fn new(realm_provider: Arc<R>, client_provider: Arc<C>) -> Self {
        Self {
            realm_provider,
            client_provider,
        }
    }
}

/// State for role operations (requires realm and client context).
pub struct RoleState<R, C, Ro>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    /// Realm storage provider (for realm validation).
    pub realm_provider: Arc<R>,
    /// Client storage provider (for client role operations).
    pub client_provider: Arc<C>,
    /// Role storage provider.
    pub role_provider: Arc<Ro>,
}

impl<R, C, Ro> Clone for RoleState<R, C, Ro>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
            client_provider: Arc::clone(&self.client_provider),
            role_provider: Arc::clone(&self.role_provider),
        }
    }
}

impl<R, C, Ro> RoleState<R, C, Ro>
where
    R: RealmProvider,
    C: ClientProvider,
    Ro: RoleProvider,
{
    /// Creates a new role state.
    pub fn new(
        realm_provider: Arc<R>,
        client_provider: Arc<C>,
        role_provider: Arc<Ro>,
    ) -> Self {
        Self {
            realm_provider,
            client_provider,
            role_provider,
        }
    }
}

/// State for group operations (requires realm context).
pub struct GroupState<R, G>
where
    R: RealmProvider,
    G: GroupProvider,
{
    /// Realm storage provider (for realm validation).
    pub realm_provider: Arc<R>,
    /// Group storage provider.
    pub group_provider: Arc<G>,
}

impl<R, G> Clone for GroupState<R, G>
where
    R: RealmProvider,
    G: GroupProvider,
{
    fn clone(&self) -> Self {
        Self {
            realm_provider: Arc::clone(&self.realm_provider),
            group_provider: Arc::clone(&self.group_provider),
        }
    }
}

impl<R, G> GroupState<R, G>
where
    R: RealmProvider,
    G: GroupProvider,
{
    /// Creates a new group state.
    pub fn new(realm_provider: Arc<R>, group_provider: Arc<G>) -> Self {
        Self {
            realm_provider,
            group_provider,
        }
    }
}
