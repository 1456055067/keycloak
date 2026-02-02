//! # kc-federation-ldap
//!
//! LDAP federation provider for Keycloak Rust.
//!
//! This crate provides LDAP user federation using the `ldap3` crate.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management
//! - SC-8: Transmission Confidentiality
//! - SC-13: Cryptographic Protection
//!
//! ## Security Requirements
//!
//! **CRITICAL**: This implementation enforces LDAPS-only connections.
//!
//! - Only `ldaps://` URLs are accepted
//! - STARTTLS is NOT supported (insecure upgrade path)
//! - Plain `ldap://` is NOT supported
//!
//! This ensures all LDAP traffic is encrypted from connection start,
//! preventing credential interception.
//!
//! ## Example
//!
//! ```ignore
//! use kc_federation_ldap::{LdapProvider, LdapConfig};
//!
//! let config = LdapConfig::builder()
//!     .connection_url("ldaps://ldap.example.com:636")
//!     .bind_dn("cn=admin,dc=example,dc=com")
//!     .bind_credential("admin_password")
//!     .users_dn("ou=users,dc=example,dc=com")
//!     .build()?;
//!
//! let provider = LdapProvider::new(config).await?;
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod config;
pub mod connection;
pub mod error;
pub mod mapper;
pub mod provider;
pub mod search;

// Re-export commonly used types
pub use config::{LdapConfig, LdapConfigBuilder, LdapVendor, RdnAttribute, UsernameAttribute};
pub use connection::LdapConnectionPool;
pub use error::{LdapError, LdapResult};
pub use mapper::{LdapGroupMapper, LdapRoleMapper, LdapUserAttributeMapper};
pub use provider::LdapStorageProvider;
