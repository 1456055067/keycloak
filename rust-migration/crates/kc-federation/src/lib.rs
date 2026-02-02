//! # kc-federation
//!
//! User federation framework for Keycloak Rust.
//!
//! This crate provides the base traits and types for user federation providers,
//! enabling integration with external identity stores like LDAP and Active Directory.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management
//! - AC-2: Account Management
//!
//! ## Overview
//!
//! Federation providers allow Keycloak to delegate user storage and authentication
//! to external systems. Users from federated sources appear as normal Keycloak users
//! but their data is sourced from (and optionally synchronized to) the external store.
//!
//! ## Key Concepts
//!
//! - **UserStorageProvider**: Main trait for user lookup and authentication delegation
//! - **CredentialValidator**: Trait for validating credentials against external systems
//! - **FederationMapper**: Trait for mapping attributes between systems
//! - **ImportSynchronization**: Trait for bulk import/sync operations
//! - **EditMode**: Controls write-back behavior (ReadOnly, Writable, Unsynced)
//!
//! ## Example
//!
//! ```ignore
//! use kc_federation::{UserStorageProvider, EditMode, FederationConfig};
//!
//! // Configure federation provider
//! let config = FederationConfig::builder()
//!     .name("corporate-ldap")
//!     .priority(0)
//!     .edit_mode(EditMode::ReadOnly)
//!     .build();
//!
//! // Provider implementation handles user lookup
//! let user = provider.get_user_by_username(realm_id, "jdoe").await?;
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod config;
pub mod error;
pub mod mapper;
pub mod provider;
pub mod sync;

// Re-export commonly used types
pub use config::{EditMode, FederationConfig, FederationConfigBuilder};
pub use error::{FederationError, FederationResult};
pub use mapper::{AttributeMapper, FederationMapper, GroupMapper, RoleMapper};
pub use provider::{CredentialValidator, ImportedUserValidation, UserStorageProvider};
pub use sync::{ChangedSyncResult, FullSyncResult, ImportSynchronization, SyncMode, SyncResult};
