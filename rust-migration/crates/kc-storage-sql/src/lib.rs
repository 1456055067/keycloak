//! # kc-storage-sql
//!
//! SQLx-based storage implementation for Keycloak Rust.
//!
//! This crate provides `PostgreSQL` storage using `SQLx`.
//!
//! ## Features
//!
//! - Full implementation of all storage provider traits
//! - Connection pooling with configurable limits
//! - JSON storage for complex types (attributes, policies)
//! - Optimized queries with proper indexing support
//!
//! ## Usage
//!
//! ```ignore
//! use kc_storage_sql::{create_pool, PoolConfig};
//! use kc_storage_sql::providers::*;
//!
//! // Create connection pool
//! let config = PoolConfig::default();
//! let pool = create_pool("postgres://localhost/keycloak", config).await?;
//!
//! // Create providers
//! let realm_provider = PgRealmProvider::new(pool.clone());
//! let user_provider = PgUserProvider::new(pool.clone());
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

mod client;
mod convert;
mod credential;
mod entities;
mod error;
mod group;
mod pool;
mod realm;
mod role;
mod user;

// Re-export pool utilities
pub use pool::{PoolConfig, create_pool};

// Re-export error utilities
pub use error::from_sqlx_error;

/// `PostgreSQL` storage provider implementations.
pub mod providers {
    pub use crate::client::PgClientProvider;
    pub use crate::credential::PgCredentialProvider;
    pub use crate::group::PgGroupProvider;
    pub use crate::realm::PgRealmProvider;
    pub use crate::role::PgRoleProvider;
    pub use crate::user::PgUserProvider;
}

pub use providers::*;
