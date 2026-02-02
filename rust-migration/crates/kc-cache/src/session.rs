//! Session cache operations.
//!
//! Specialized caching for user sessions, client sessions, and authentication sessions.

use std::time::Duration;

use async_trait::async_trait;

use crate::error::CacheResult;

/// Session cache provider for managing user sessions.
///
/// This trait provides session-specific caching operations optimized
/// for the session management use cases in Keycloak.
#[async_trait]
pub trait SessionCacheProvider: Send + Sync {
    /// Stores a user session.
    async fn store_user_session(
        &self,
        realm_id: &str,
        session_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets a user session.
    async fn get_user_session(&self, realm_id: &str, session_id: &str)
        -> CacheResult<Option<Vec<u8>>>;

    /// Deletes a user session.
    async fn delete_user_session(&self, realm_id: &str, session_id: &str) -> CacheResult<()>;

    /// Updates the TTL for a user session (touch).
    async fn touch_user_session(
        &self,
        realm_id: &str,
        session_id: &str,
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets all session IDs for a user.
    async fn get_user_sessions_by_user(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> CacheResult<Vec<String>>;

    /// Gets all session IDs for a client.
    async fn get_user_sessions_by_client(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> CacheResult<Vec<String>>;

    /// Stores a client session.
    async fn store_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets a client session.
    async fn get_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>>;

    /// Deletes a client session.
    async fn delete_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<()>;

    /// Gets all client sessions for a user session.
    async fn get_client_sessions(
        &self,
        realm_id: &str,
        user_session_id: &str,
    ) -> CacheResult<Vec<(String, Vec<u8>)>>;

    /// Stores an authentication session (temporary, during auth flow).
    async fn store_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets an authentication session.
    async fn get_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
    ) -> CacheResult<Option<Vec<u8>>>;

    /// Deletes an authentication session.
    async fn delete_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
    ) -> CacheResult<()>;

    /// Deletes all sessions for a realm.
    async fn clear_realm_sessions(&self, realm_id: &str) -> CacheResult<u64>;

    /// Deletes all sessions for a user.
    async fn clear_user_sessions(&self, realm_id: &str, user_id: &str) -> CacheResult<u64>;

    /// Gets count of active sessions in a realm.
    async fn count_realm_sessions(&self, realm_id: &str) -> CacheResult<u64>;
}

/// Offline session cache provider.
///
/// Offline sessions persist beyond the user's browser session and are used
/// for refresh token grants when the user is not actively using the application.
#[async_trait]
pub trait OfflineSessionCacheProvider: Send + Sync {
    /// Stores an offline user session.
    async fn store_offline_session(
        &self,
        realm_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> CacheResult<()>;

    /// Gets an offline user session.
    async fn get_offline_session(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>>;

    /// Deletes an offline user session.
    async fn delete_offline_session(&self, realm_id: &str, session_id: &str) -> CacheResult<()>;

    /// Stores an offline client session.
    async fn store_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
        data: &[u8],
    ) -> CacheResult<()>;

    /// Gets an offline client session.
    async fn get_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>>;

    /// Deletes an offline client session.
    async fn delete_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<()>;

    /// Gets all offline sessions for a user.
    async fn get_offline_sessions_by_user(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> CacheResult<Vec<String>>;
}
