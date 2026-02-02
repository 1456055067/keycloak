//! # kc-cache-redis
//!
//! Redis cache implementation for Keycloak Rust.
//!
//! This crate provides Redis-based caching using the `fred` crate,
//! implementing the cache traits defined in `kc-cache`.
//!
//! ## Features
//!
//! - Connection pooling with automatic reconnection
//! - TLS support
//! - Redis Cluster support
//! - Redis Sentinel support
//! - Key prefixing for multi-tenant deployments
//!
//! ## Example
//!
//! ```ignore
//! use kc_cache_redis::{RedisCacheProvider, RedisConfig};
//! use kc_cache::CacheProvider;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = RedisConfig::default()
//!         .host("localhost")
//!         .port(6379);
//!
//!     let cache = RedisCacheProvider::new(config).await?;
//!
//!     cache.set("key", &"value", Some(Duration::from_secs(3600))).await?;
//!     let value: Option<String> = cache.get("key").await?;
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod config;
pub mod error;
pub mod provider;
pub mod session;

pub use config::{RedisConfig, SentinelConfig};
pub use provider::RedisCacheProvider;
pub use session::RedisSessionCache;
