//! Session provider trait.

use async_trait::async_trait;
use uuid::Uuid;

use crate::auth_session::AuthenticationSession;
use crate::client_session::ClientSession;
use crate::error::SessionResult;
use crate::user_session::UserSession;

/// Provider for session storage and management.
///
/// Implementations may use in-memory storage, distributed cache (Redis),
/// or database storage depending on deployment requirements.
#[async_trait]
pub trait SessionProvider: Send + Sync {
    // === User Session Operations ===

    /// Creates a new user session.
    async fn create_user_session(&self, session: &UserSession) -> SessionResult<()>;

    /// Gets a user session by ID.
    async fn get_user_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<UserSession>>;

    /// Updates a user session.
    async fn update_user_session(&self, session: &UserSession) -> SessionResult<()>;

    /// Removes a user session.
    async fn remove_user_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()>;

    /// Gets all user sessions for a user.
    async fn get_user_sessions_by_user(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
    ) -> SessionResult<Vec<UserSession>>;

    /// Gets all user sessions for a client.
    async fn get_user_sessions_by_client(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
        max_results: Option<usize>,
        offset: Option<usize>,
    ) -> SessionResult<Vec<UserSession>>;

    /// Counts active sessions for a user.
    async fn count_user_sessions(&self, realm_id: Uuid, user_id: Uuid) -> SessionResult<u64>;

    /// Removes all sessions for a user.
    async fn remove_user_sessions(&self, realm_id: Uuid, user_id: Uuid) -> SessionResult<()>;

    /// Removes all sessions for a realm.
    async fn remove_all_sessions(&self, realm_id: Uuid) -> SessionResult<()>;

    // === Client Session Operations ===

    /// Creates a client session within a user session.
    async fn create_client_session(&self, session: &ClientSession) -> SessionResult<()>;

    /// Gets a client session by ID.
    async fn get_client_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<ClientSession>>;

    /// Gets all client sessions for a user session.
    async fn get_client_sessions(
        &self,
        realm_id: Uuid,
        user_session_id: Uuid,
    ) -> SessionResult<Vec<ClientSession>>;

    /// Updates a client session.
    async fn update_client_session(&self, session: &ClientSession) -> SessionResult<()>;

    /// Removes a client session.
    async fn remove_client_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()>;

    // === Authentication Session Operations ===

    /// Creates an authentication session.
    async fn create_auth_session(&self, session: &AuthenticationSession) -> SessionResult<()>;

    /// Gets an authentication session by ID.
    async fn get_auth_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<AuthenticationSession>>;

    /// Updates an authentication session.
    async fn update_auth_session(&self, session: &AuthenticationSession) -> SessionResult<()>;

    /// Removes an authentication session.
    async fn remove_auth_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()>;

    // === Offline Session Operations ===

    /// Creates an offline user session.
    async fn create_offline_session(&self, session: &UserSession) -> SessionResult<()>;

    /// Gets an offline session by ID.
    async fn get_offline_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<UserSession>>;

    /// Gets offline sessions for a user.
    async fn get_offline_sessions_by_user(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
    ) -> SessionResult<Vec<UserSession>>;

    /// Removes an offline session.
    async fn remove_offline_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()>;

    // === Session Expiration ===

    /// Removes expired sessions.
    ///
    /// Returns the number of sessions removed.
    async fn remove_expired_sessions(&self, realm_id: Uuid) -> SessionResult<u64>;
}

/// Statistics about sessions.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Total active user sessions.
    pub active_user_sessions: u64,
    /// Total active client sessions.
    pub active_client_sessions: u64,
    /// Total offline sessions.
    pub offline_sessions: u64,
}
