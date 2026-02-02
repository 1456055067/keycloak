//! Redis cache provider implementation.

use std::time::Duration;

use async_trait::async_trait;
use fred::cmd;
use fred::prelude::*;
use fred::types::scan::Scanner;
use futures::TryStreamExt;
use kc_cache::{
    AtomicCacheProvider, CacheError, CacheProvider, CacheResult, HashCacheProvider,
    SetCacheProvider,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::config::RedisConfig;
use crate::error::{from_redis_error, from_serde_error};

/// Redis-based cache provider.
pub struct RedisCacheProvider {
    client: Client,
    config: RedisConfig,
}

impl RedisCacheProvider {
    /// Creates a new Redis cache provider.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub async fn new(config: RedisConfig) -> CacheResult<Self> {
        let redis_config = Config::from_url(&config.connection_url())
            .map_err(|e| CacheError::Configuration(e.to_string()))?;

        let client = Client::new(
            redis_config,
            None,
            None,
            Some(ReconnectPolicy::new_exponential(0, 1000, 30_000, 2)),
        );

        client.init().await.map_err(from_redis_error)?;

        Ok(Self { client, config })
    }

    /// Returns the underlying Redis client.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Formats a key with the configured prefix.
    fn key(&self, key: &str) -> String {
        self.config.prefixed_key(key)
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

/// Safely convert seconds to i64 for Redis expiration.
#[allow(clippy::cast_possible_wrap)]
const fn seconds_to_i64(seconds: u64) -> i64 {
    seconds as i64
}

/// Safely convert i64 TTL to u64 for Duration.
#[allow(clippy::cast_sign_loss)]
const fn ttl_to_u64(ttl: i64) -> u64 {
    ttl as u64
}

#[async_trait]
impl CacheProvider for RedisCacheProvider {
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send,
    {
        let key = self.key(key);
        let value: Option<String> = self.client.get(&key).await.map_err(from_redis_error)?;

        match value {
            Some(v) => {
                let parsed: T = serde_json::from_str(&v).map_err(from_serde_error)?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<()>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(value).map_err(from_serde_error)?;

        match ttl {
            Some(duration) => {
                let seconds = seconds_to_i64(duration.as_secs().max(1));
                self.client
                    .set::<(), _, _>(
                        &key,
                        serialized,
                        Some(Expiration::EX(seconds)),
                        None,
                        false,
                    )
                    .await
                    .map_err(from_redis_error)
            }
            None => self
                .client
                .set::<(), _, _>(&key, serialized, None, None, false)
                .await
                .map_err(from_redis_error),
        }
    }

    async fn delete(&self, key: &str) -> CacheResult<()> {
        let key = self.key(key);
        self.client
            .del::<(), _>(&key)
            .await
            .map_err(from_redis_error)
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let key = self.key(key);
        let count: i64 = self.client.exists(&key).await.map_err(from_redis_error)?;
        Ok(count > 0)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> CacheResult<()> {
        let key = self.key(key);
        let seconds = seconds_to_i64(ttl.as_secs().max(1));
        let result: bool = self
            .client
            .expire(&key, seconds, None)
            .await
            .map_err(from_redis_error)?;

        if result {
            Ok(())
        } else {
            Err(CacheError::NotFound)
        }
    }

    async fn ttl(&self, key: &str) -> CacheResult<Option<Duration>> {
        let key = self.key(key);
        let ttl: i64 = self.client.ttl(&key).await.map_err(from_redis_error)?;

        if ttl < 0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs(ttl_to_u64(ttl))))
        }
    }

    async fn delete_pattern(&self, pattern: &str) -> CacheResult<u64> {
        let pattern = self.key(pattern);
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

    async fn clear(&self) -> CacheResult<()> {
        let args: Vec<String> = vec![];
        self.client
            .custom::<(), _>(cmd!("FLUSHDB"), args)
            .await
            .map_err(from_redis_error)
    }
}

#[async_trait]
impl AtomicCacheProvider for RedisCacheProvider {
    async fn incr(&self, key: &str, delta: i64) -> CacheResult<i64> {
        let key = self.key(key);
        self.client
            .incr_by(&key, delta)
            .await
            .map_err(from_redis_error)
    }

    async fn decr(&self, key: &str, delta: i64) -> CacheResult<i64> {
        let key = self.key(key);
        self.client
            .decr_by(&key, delta)
            .await
            .map_err(from_redis_error)
    }

    async fn set_nx<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<bool>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(value).map_err(from_serde_error)?;

        let expiration = ttl.map(|d| Expiration::EX(seconds_to_i64(d.as_secs().max(1))));

        let result: Option<String> = self
            .client
            .set(&key, serialized, expiration, Some(SetOptions::NX), false)
            .await
            .map_err(from_redis_error)?;

        Ok(result.is_some())
    }

    async fn get_del<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send,
    {
        let key = self.key(key);
        let value: Option<String> = self.client.getdel(&key).await.map_err(from_redis_error)?;

        match value {
            Some(v) => {
                let parsed: T = serde_json::from_str(&v).map_err(from_serde_error)?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl HashCacheProvider for RedisCacheProvider {
    async fn hget<T>(&self, key: &str, field: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send,
    {
        let key = self.key(key);
        let value: Option<String> = self
            .client
            .hget(&key, field)
            .await
            .map_err(from_redis_error)?;

        match value {
            Some(v) => {
                let parsed: T = serde_json::from_str(&v).map_err(from_serde_error)?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    async fn hset<T>(&self, key: &str, field: &str, value: &T) -> CacheResult<()>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(value).map_err(from_serde_error)?;
        self.client
            .hset::<(), _, _>(&key, (field, serialized))
            .await
            .map_err(from_redis_error)
    }

    async fn hdel(&self, key: &str, field: &str) -> CacheResult<()> {
        let key = self.key(key);
        self.client
            .hdel::<(), _, _>(&key, field)
            .await
            .map_err(from_redis_error)
    }

    async fn hgetall<T>(&self, key: &str) -> CacheResult<Vec<(String, T)>>
    where
        T: DeserializeOwned + Send,
    {
        let key = self.key(key);
        let values: std::collections::HashMap<String, String> = self
            .client
            .hgetall(&key)
            .await
            .map_err(from_redis_error)?;

        let mut result = Vec::with_capacity(values.len());
        for (field, value) in values {
            let parsed: T = serde_json::from_str(&value).map_err(from_serde_error)?;
            result.push((field, parsed));
        }

        Ok(result)
    }

    async fn hexists(&self, key: &str, field: &str) -> CacheResult<bool> {
        let key = self.key(key);
        self.client
            .hexists(&key, field)
            .await
            .map_err(from_redis_error)
    }
}

#[async_trait]
impl SetCacheProvider for RedisCacheProvider {
    async fn sadd<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(member).map_err(from_serde_error)?;
        let added: i64 = self
            .client
            .sadd(&key, serialized)
            .await
            .map_err(from_redis_error)?;
        Ok(added > 0)
    }

    async fn srem<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(member).map_err(from_serde_error)?;
        let removed: i64 = self
            .client
            .srem(&key, serialized)
            .await
            .map_err(from_redis_error)?;
        Ok(removed > 0)
    }

    async fn sismember<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync,
    {
        let key = self.key(key);
        let serialized = serde_json::to_string(member).map_err(from_serde_error)?;
        self.client
            .sismember(&key, serialized)
            .await
            .map_err(from_redis_error)
    }

    async fn smembers<T>(&self, key: &str) -> CacheResult<Vec<T>>
    where
        T: DeserializeOwned + Send,
    {
        let key = self.key(key);
        let members: Vec<String> = self.client.smembers(&key).await.map_err(from_redis_error)?;

        let mut result = Vec::with_capacity(members.len());
        for member in members {
            let parsed: T = serde_json::from_str(&member).map_err(from_serde_error)?;
            result.push(parsed);
        }

        Ok(result)
    }

    async fn scard(&self, key: &str) -> CacheResult<u64> {
        let key = self.key(key);
        self.client.scard(&key).await.map_err(from_redis_error)
    }
}
