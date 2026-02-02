//! # kc-cache
//!
//! Cache abstraction traits for Keycloak Rust.
//!
//! This crate defines the interfaces for caching used throughout Keycloak.
//! The primary implementation is Redis-based (see `kc-cache-redis`).
//!
//! ## Cache Providers
//!
//! - [`CacheProvider`] - Basic key-value cache operations
//! - [`AtomicCacheProvider`] - Atomic operations (increment, set-if-not-exists)
//! - [`HashCacheProvider`] - Hash/map operations
//! - [`SetCacheProvider`] - Set operations
//!
//! ## Specialized Caches
//!
//! - [`SessionCacheProvider`] - User and client session caching
//! - [`OfflineSessionCacheProvider`] - Offline session storage
//! - [`RevocationCacheProvider`] - Token revocation tracking
//! - [`ActionTokenCacheProvider`] - Single-use action tokens
//! - [`LoginFailureCacheProvider`] - Brute force protection
//!
//! ## Example
//!
//! ```ignore
//! use kc_cache::{CacheProvider, CacheResult};
//! use std::time::Duration;
//!
//! async fn cache_user(cache: &impl CacheProvider, user_id: &str, data: &User) -> CacheResult<()> {
//!     cache.set(
//!         &format!("user:{user_id}"),
//!         data,
//!         Some(Duration::from_secs(3600)),
//!     ).await
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod action_token;
pub mod error;
pub mod provider;
pub mod revocation;
pub mod session;

pub use action_token::{ActionTokenCacheProvider, LoginFailureCacheProvider};
pub use error::{CacheError, CacheResult};
pub use provider::{AtomicCacheProvider, CacheProvider, HashCacheProvider, SetCacheProvider};
pub use revocation::{LogoutCacheProvider, RevocationCacheProvider};
pub use session::{OfflineSessionCacheProvider, SessionCacheProvider};
