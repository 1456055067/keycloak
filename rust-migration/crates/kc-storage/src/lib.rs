//! # kc-storage
//!
//! Storage abstraction traits for Keycloak Rust.
//!
//! This crate defines the storage provider interfaces that must be
//! implemented by concrete storage backends (SQL, JPA, etc.).
//!
//! ## Provider Traits
//!
//! - [`RealmProvider`] - CRUD operations for realms
//! - [`UserProvider`] - CRUD operations for users
//! - [`ClientProvider`] - CRUD operations for clients
//! - [`RoleProvider`] - CRUD operations for roles
//! - [`GroupProvider`] - CRUD operations for groups
//! - [`CredentialProvider`] - CRUD operations for credentials

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod client;
pub mod credential;
pub mod error;
pub mod group;
pub mod realm;
pub mod role;
pub mod user;

pub use client::ClientProvider;
pub use credential::CredentialProvider;
pub use error::StorageError;
pub use group::GroupProvider;
pub use realm::RealmProvider;
pub use role::RoleProvider;
pub use user::UserProvider;
