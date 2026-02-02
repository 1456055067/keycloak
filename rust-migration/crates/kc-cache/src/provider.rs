//! Cache provider traits.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

use crate::error::CacheResult;

/// Cache provider trait for key-value caching.
///
/// Implementations must be thread-safe and support concurrent access.
/// All operations are async to support both local and distributed caches.
///
/// ## Type Parameters
///
/// Cache operations work with any type that implements `Serialize` + `DeserializeOwned`.
/// The cache implementation is responsible for serialization/deserialization.
#[async_trait]
pub trait CacheProvider: Send + Sync {
    /// Gets a value from the cache.
    ///
    /// Returns `None` if the key doesn't exist or has expired.
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send;

    /// Sets a value in the cache with optional TTL.
    ///
    /// If `ttl` is `None`, the value will not expire automatically.
    async fn set<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<()>
    where
        T: Serialize + Sync;

    /// Deletes a value from the cache.
    ///
    /// Returns `Ok(())` even if the key doesn't exist.
    async fn delete(&self, key: &str) -> CacheResult<()>;

    /// Checks if a key exists in the cache.
    async fn exists(&self, key: &str) -> CacheResult<bool>;

    /// Sets the TTL for an existing key.
    ///
    /// Returns `CacheError::NotFound` if the key doesn't exist.
    async fn expire(&self, key: &str, ttl: Duration) -> CacheResult<()>;

    /// Gets the remaining TTL for a key.
    ///
    /// Returns `None` if the key doesn't exist or has no TTL.
    async fn ttl(&self, key: &str) -> CacheResult<Option<Duration>>;

    /// Deletes all keys matching a pattern.
    ///
    /// Pattern syntax depends on the implementation (e.g., glob for Redis).
    async fn delete_pattern(&self, pattern: &str) -> CacheResult<u64>;

    /// Clears all keys in the cache.
    ///
    /// Use with caution in production!
    async fn clear(&self) -> CacheResult<()>;
}

/// Extended cache operations for atomic updates.
#[async_trait]
pub trait AtomicCacheProvider: CacheProvider {
    /// Atomically increments a counter.
    ///
    /// Creates the key with value 1 if it doesn't exist.
    async fn incr(&self, key: &str, delta: i64) -> CacheResult<i64>;

    /// Atomically decrements a counter.
    ///
    /// Creates the key with value -1 if it doesn't exist.
    async fn decr(&self, key: &str, delta: i64) -> CacheResult<i64>;

    /// Sets a value only if the key doesn't exist.
    ///
    /// Returns `true` if the value was set, `false` if the key already existed.
    async fn set_nx<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<bool>
    where
        T: Serialize + Sync;

    /// Gets and deletes a value atomically.
    async fn get_del<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send;
}

/// Hash operations for structured data.
#[async_trait]
pub trait HashCacheProvider: CacheProvider {
    /// Gets a field from a hash.
    async fn hget<T>(&self, key: &str, field: &str) -> CacheResult<Option<T>>
    where
        T: DeserializeOwned + Send;

    /// Sets a field in a hash.
    async fn hset<T>(&self, key: &str, field: &str, value: &T) -> CacheResult<()>
    where
        T: Serialize + Sync;

    /// Deletes a field from a hash.
    async fn hdel(&self, key: &str, field: &str) -> CacheResult<()>;

    /// Gets all fields and values from a hash.
    async fn hgetall<T>(&self, key: &str) -> CacheResult<Vec<(String, T)>>
    where
        T: DeserializeOwned + Send;

    /// Checks if a field exists in a hash.
    async fn hexists(&self, key: &str, field: &str) -> CacheResult<bool>;
}

/// Set operations for collections.
#[async_trait]
pub trait SetCacheProvider: CacheProvider {
    /// Adds a member to a set.
    async fn sadd<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync;

    /// Removes a member from a set.
    async fn srem<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync;

    /// Checks if a member exists in a set.
    async fn sismember<T>(&self, key: &str, member: &T) -> CacheResult<bool>
    where
        T: Serialize + Sync;

    /// Gets all members of a set.
    async fn smembers<T>(&self, key: &str) -> CacheResult<Vec<T>>
    where
        T: DeserializeOwned + Send;

    /// Gets the number of members in a set.
    async fn scard(&self, key: &str) -> CacheResult<u64>;
}
