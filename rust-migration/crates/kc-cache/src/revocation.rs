//! Token revocation cache.
//!
//! Tracks revoked tokens and "not-before" policies for token invalidation.

use std::time::Duration;

use async_trait::async_trait;

use crate::error::CacheResult;

/// Token revocation cache provider.
///
/// Tracks revoked tokens and realm/client "not-before" timestamps
/// to invalidate tokens issued before a certain time.
#[async_trait]
pub trait RevocationCacheProvider: Send + Sync {
    /// Revokes a specific token by its JTI (JWT ID).
    ///
    /// The `ttl` should match the token's remaining lifetime.
    async fn revoke_token(&self, jti: &str, ttl: Duration) -> CacheResult<()>;

    /// Checks if a token is revoked.
    async fn is_token_revoked(&self, jti: &str) -> CacheResult<bool>;

    /// Sets the "not-before" timestamp for a realm.
    ///
    /// All tokens issued before this timestamp are considered invalid.
    async fn set_realm_not_before(&self, realm_id: &str, not_before: i64) -> CacheResult<()>;

    /// Gets the "not-before" timestamp for a realm.
    async fn get_realm_not_before(&self, realm_id: &str) -> CacheResult<Option<i64>>;

    /// Sets the "not-before" timestamp for a client.
    async fn set_client_not_before(
        &self,
        realm_id: &str,
        client_id: &str,
        not_before: i64,
    ) -> CacheResult<()>;

    /// Gets the "not-before" timestamp for a client.
    async fn get_client_not_before(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> CacheResult<Option<i64>>;

    /// Sets the "not-before" timestamp for a user.
    ///
    /// Used when a user's password is changed or they explicitly log out everywhere.
    async fn set_user_not_before(
        &self,
        realm_id: &str,
        user_id: &str,
        not_before: i64,
    ) -> CacheResult<()>;

    /// Gets the "not-before" timestamp for a user.
    async fn get_user_not_before(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> CacheResult<Option<i64>>;

    /// Clears all revocation data for a realm.
    async fn clear_realm_revocations(&self, realm_id: &str) -> CacheResult<()>;
}

/// Single logout (SLO) cache provider.
///
/// Tracks logout requests for backchannel logout propagation.
#[async_trait]
pub trait LogoutCacheProvider: Send + Sync {
    /// Records a logout request for backchannel propagation.
    async fn record_logout(
        &self,
        realm_id: &str,
        session_id: &str,
        logout_token: &str,
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets pending logout requests for a client.
    async fn get_pending_logouts(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> CacheResult<Vec<String>>;

    /// Marks a logout as delivered to a client.
    async fn mark_logout_delivered(
        &self,
        realm_id: &str,
        session_id: &str,
        client_id: &str,
    ) -> CacheResult<()>;

    /// Checks if logout was delivered to a client.
    async fn is_logout_delivered(
        &self,
        realm_id: &str,
        session_id: &str,
        client_id: &str,
    ) -> CacheResult<bool>;
}
