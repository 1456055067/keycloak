//! Redis session cache implementation.

use std::time::Duration;

use async_trait::async_trait;
use fred::prelude::*;
use fred::types::scan::Scanner;
use futures::TryStreamExt;
use kc_cache::{CacheResult, OfflineSessionCacheProvider, SessionCacheProvider};

use crate::config::RedisConfig;
use crate::error::from_redis_error;

/// Safely convert seconds to i64 for Redis expiration.
#[allow(clippy::cast_possible_wrap)]
const fn seconds_to_i64(seconds: u64) -> i64 {
    seconds as i64
}

/// Redis-based session cache provider.
pub struct RedisSessionCache {
    client: Client,
    config: RedisConfig,
}

impl RedisSessionCache {
    /// Creates a new Redis session cache.
    pub const fn new(client: Client, config: RedisConfig) -> Self {
        Self { client, config }
    }

    fn key(&self, parts: &[&str]) -> String {
        let key = parts.join(":");
        self.config.prefixed_key(&key)
    }

    /// Collects keys from a scan pattern.
    async fn scan_keys(&self, pattern: &str) -> CacheResult<Vec<String>> {
        let mut scanner = self.client.scan(pattern, None, None);
        let mut keys = Vec::new();

        while let Some(result) = scanner.try_next().await.map_err(from_redis_error)? {
            if let Some(page) = result.results() {
                for value in page {
                    if let Some(s) = value.as_str() {
                        keys.push(s.to_string());
                    }
                }
            }
        }

        Ok(keys)
    }
}

#[async_trait]
impl SessionCacheProvider for RedisSessionCache {
    async fn store_user_session(
        &self,
        realm_id: &str,
        session_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()> {
        let key = self.key(&["session", realm_id, session_id]);
        let seconds = seconds_to_i64(ttl.as_secs().max(1));

        self.client
            .set::<(), _, _>(
                &key,
                data.to_vec(),
                Some(Expiration::EX(seconds)),
                None,
                false,
            )
            .await
            .map_err(from_redis_error)
    }

    async fn get_user_session(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>> {
        let key = self.key(&["session", realm_id, session_id]);
        self.client.get(&key).await.map_err(from_redis_error)
    }

    async fn delete_user_session(&self, realm_id: &str, session_id: &str) -> CacheResult<()> {
        let key = self.key(&["session", realm_id, session_id]);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn touch_user_session(
        &self,
        realm_id: &str,
        session_id: &str,
        ttl: Duration,
    ) -> CacheResult<()> {
        let key = self.key(&["session", realm_id, session_id]);
        let seconds = seconds_to_i64(ttl.as_secs().max(1));
        self.client
            .expire::<(), _>(&key, seconds, None)
            .await
            .map_err(from_redis_error)
    }

    async fn get_user_sessions_by_user(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> CacheResult<Vec<String>> {
        let key = self.key(&["user-sessions", realm_id, user_id]);
        self.client.smembers(&key).await.map_err(from_redis_error)
    }

    async fn get_user_sessions_by_client(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> CacheResult<Vec<String>> {
        let key = self.key(&["client-sessions", realm_id, client_id]);
        self.client.smembers(&key).await.map_err(from_redis_error)
    }

    async fn store_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()> {
        let key = self.key(&[
            "client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        let seconds = seconds_to_i64(ttl.as_secs().max(1));

        self.client
            .set::<(), _, _>(
                &key,
                data.to_vec(),
                Some(Expiration::EX(seconds)),
                None,
                false,
            )
            .await
            .map_err(from_redis_error)
    }

    async fn get_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>> {
        let key = self.key(&[
            "client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        self.client.get(&key).await.map_err(from_redis_error)
    }

    async fn delete_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<()> {
        let key = self.key(&[
            "client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn get_client_sessions(
        &self,
        realm_id: &str,
        user_session_id: &str,
    ) -> CacheResult<Vec<(String, Vec<u8>)>> {
        let pattern = self.key(&["client-session", realm_id, user_session_id, "*"]);
        let keys = self.scan_keys(&pattern).await?;

        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(data) = self
                .client
                .get::<Option<Vec<u8>>, _>(&key)
                .await
                .map_err(from_redis_error)?
            {
                // Extract client_session_id from key
                if let Some(client_session_id) = key.rsplit(':').next() {
                    results.push((client_session_id.to_string(), data));
                }
            }
        }

        Ok(results)
    }

    async fn store_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
        data: &[u8],
        ttl: Duration,
    ) -> CacheResult<()> {
        let key = self.key(&["auth-session", realm_id, root_session_id, tab_id]);
        let seconds = seconds_to_i64(ttl.as_secs().max(1));

        self.client
            .set::<(), _, _>(
                &key,
                data.to_vec(),
                Some(Expiration::EX(seconds)),
                None,
                false,
            )
            .await
            .map_err(from_redis_error)
    }

    async fn get_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
    ) -> CacheResult<Option<Vec<u8>>> {
        let key = self.key(&["auth-session", realm_id, root_session_id, tab_id]);
        self.client.get(&key).await.map_err(from_redis_error)
    }

    async fn delete_auth_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
        tab_id: &str,
    ) -> CacheResult<()> {
        let key = self.key(&["auth-session", realm_id, root_session_id, tab_id]);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn clear_realm_sessions(&self, realm_id: &str) -> CacheResult<u64> {
        let pattern = self.key(&["session", realm_id, "*"]);
        let keys = self.scan_keys(&pattern).await?;

        if keys.is_empty() {
            return Ok(0);
        }

        let count = keys.len() as u64;
        self.client
            .del::<(), _>(keys)
            .await
            .map_err(from_redis_error)?;

        Ok(count)
    }

    async fn clear_user_sessions(&self, realm_id: &str, user_id: &str) -> CacheResult<u64> {
        let session_ids = self.get_user_sessions_by_user(realm_id, user_id).await?;

        if session_ids.is_empty() {
            return Ok(0);
        }

        let keys: Vec<String> = session_ids
            .iter()
            .map(|sid| self.key(&["session", realm_id, sid]))
            .collect();

        let count = keys.len() as u64;
        self.client
            .del::<(), _>(keys)
            .await
            .map_err(from_redis_error)?;

        // Clean up the user-sessions set
        let user_sessions_key = self.key(&["user-sessions", realm_id, user_id]);
        self.client
            .del::<(), _>(&user_sessions_key)
            .await
            .map_err(from_redis_error)?;

        Ok(count)
    }

    async fn count_realm_sessions(&self, realm_id: &str) -> CacheResult<u64> {
        let pattern = self.key(&["session", realm_id, "*"]);
        let keys = self.scan_keys(&pattern).await?;
        Ok(keys.len() as u64)
    }
}

#[async_trait]
impl OfflineSessionCacheProvider for RedisSessionCache {
    async fn store_offline_session(
        &self,
        realm_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> CacheResult<()> {
        let key = self.key(&["offline-session", realm_id, session_id]);
        self.client
            .set::<(), _, _>(&key, data.to_vec(), None, None, false)
            .await
            .map_err(from_redis_error)
    }

    async fn get_offline_session(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>> {
        let key = self.key(&["offline-session", realm_id, session_id]);
        self.client.get(&key).await.map_err(from_redis_error)
    }

    async fn delete_offline_session(&self, realm_id: &str, session_id: &str) -> CacheResult<()> {
        let key = self.key(&["offline-session", realm_id, session_id]);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn store_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
        data: &[u8],
    ) -> CacheResult<()> {
        let key = self.key(&[
            "offline-client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        self.client
            .set::<(), _, _>(&key, data.to_vec(), None, None, false)
            .await
            .map_err(from_redis_error)
    }

    async fn get_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<Option<Vec<u8>>> {
        let key = self.key(&[
            "offline-client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        self.client.get(&key).await.map_err(from_redis_error)
    }

    async fn delete_offline_client_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        client_session_id: &str,
    ) -> CacheResult<()> {
        let key = self.key(&[
            "offline-client-session",
            realm_id,
            user_session_id,
            client_session_id,
        ]);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn get_offline_sessions_by_user(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> CacheResult<Vec<String>> {
        let key = self.key(&["offline-user-sessions", realm_id, user_id]);
        self.client.smembers(&key).await.map_err(from_redis_error)
    }
}
