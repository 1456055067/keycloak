//! # kc-model
//!
//! Domain models for Keycloak Rust (User, Realm, Client, etc.).
//!
//! This crate defines the core domain entities used throughout Keycloak.
//!
//! ## Entity Hierarchy
//!
//! - [`Realm`] - Top-level container for all other entities
//! - [`User`] - User accounts within a realm
//! - [`Client`] - OAuth/OIDC clients
//! - [`Role`] - Realm or client roles for authorization
//! - [`Group`] - User groups with hierarchical structure
//!
//! ## Design Principles
//!
//! - All entities use UUID v7 for IDs (time-ordered)
//! - Timestamps use `DateTime<Utc>` for consistency
//! - Optional fields use `Option<T>`
//! - Collections use `Vec<T>` or `HashMap<K, V>`

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod client;
pub mod credential;
pub mod group;
pub mod realm;
pub mod role;
pub mod user;

pub use client::{Client, ClientType, Protocol};
pub use credential::{Credential, CredentialType};
pub use group::Group;
pub use realm::{OtpPolicy, Realm, SslRequired};
pub use role::Role;
pub use user::{FederatedIdentity, User, UserAttribute};
