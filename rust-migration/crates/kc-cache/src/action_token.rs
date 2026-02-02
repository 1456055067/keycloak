//! Action token cache.
//!
//! Caching for single-use action tokens (password reset, email verification, etc.).

use std::time::Duration;

use async_trait::async_trait;

use crate::error::CacheResult;

/// Action token cache provider.
///
/// Action tokens are single-use tokens for operations like password reset,
/// email verification, and other one-time actions.
#[async_trait]
pub trait ActionTokenCacheProvider: Send + Sync {
    /// Stores an action token.
    ///
    /// The token should only be usable once and expires after the TTL.
    async fn store_action_token(
        &self,
        token_id: &str,
        action_type: &str,
        user_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()>;

    /// Gets and consumes an action token.
    ///
    /// Returns the token data if valid, and marks it as used.
    /// Subsequent calls with the same token ID will return `None`.
    async fn consume_action_token(&self, token_id: &str) -> CacheResult<Option<Vec<u8>>>;

    /// Checks if an action token exists and is valid (not consumed).
    async fn is_action_token_valid(&self, token_id: &str) -> CacheResult<bool>;

    /// Invalidates all action tokens for a user.
    ///
    /// Used when a user changes their password or email.
    async fn invalidate_user_action_tokens(
        &self,
        user_id: &str,
        action_type: Option<&str>,
    ) -> CacheResult<u64>;
}

/// Login failure tracking cache.
///
/// Tracks failed login attempts for brute force protection.
#[async_trait]
pub trait LoginFailureCacheProvider: Send + Sync {
    /// Records a failed login attempt.
    async fn record_failure(
        &self,
        realm_id: &str,
        user_id: &str,
        ip_address: &str,
    ) -> CacheResult<u32>;

    /// Gets the number of failed attempts for a user.
    async fn get_failure_count(&self, realm_id: &str, user_id: &str) -> CacheResult<u32>;

    /// Gets the number of failed attempts from an IP address.
    async fn get_ip_failure_count(&self, realm_id: &str, ip_address: &str) -> CacheResult<u32>;

    /// Clears failed attempts for a user (after successful login).
    async fn clear_failures(&self, realm_id: &str, user_id: &str) -> CacheResult<()>;

    /// Checks if a user is temporarily locked out.
    async fn is_user_locked(&self, realm_id: &str, user_id: &str) -> CacheResult<bool>;

    /// Checks if an IP address is temporarily blocked.
    async fn is_ip_blocked(&self, realm_id: &str, ip_address: &str) -> CacheResult<bool>;

    /// Sets a temporary lockout for a user.
    async fn lock_user(&self, realm_id: &str, user_id: &str, duration: Duration)
    -> CacheResult<()>;

    /// Sets a temporary block for an IP address.
    async fn block_ip(
        &self,
        realm_id: &str,
        ip_address: &str,
        duration: Duration,
    ) -> CacheResult<()>;
}
