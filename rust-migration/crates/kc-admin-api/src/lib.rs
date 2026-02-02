//! # kc-admin-api
//!
//! Admin REST API for Keycloak Rust.
//!
//! This crate provides the administrative API endpoints for managing
//! Keycloak resources (realms, users, clients, roles, groups).
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - AC-2: Account Management
//! - AC-3: Access Enforcement
//! - AC-6: Least Privilege
//!
//! ## Modules
//!
//! - [`dto`] - Data Transfer Objects for API requests/responses
//! - [`error`] - Error types and HTTP error responses
//! - [`router`] - Axum router and HTTP handlers
//! - [`state`] - Application state management
//!
//! ## Quick Start
//!
//! ```ignore
//! use kc_admin_api::{admin_router, UserState};
//! use std::sync::Arc;
//!
//! // Create providers (implementation-specific)
//! let realm_provider = Arc::new(MyRealmProvider::new());
//! let user_provider = Arc::new(MyUserProvider::new());
//! let credential_provider = Arc::new(MyCredentialProvider::new());
//!
//! // Create state
//! let state = UserState::new(realm_provider, user_provider, credential_provider);
//!
//! // Create router
//! let app = admin_router().with_state(state);
//!
//! // Run server
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! axum::serve(listener, app).await?;
//! ```
//!
//! ## API Endpoints
//!
//! ### Realms
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/admin/realms` | List all realms |
//! | POST | `/admin/realms` | Create a new realm |
//! | GET | `/admin/realms/{realm}` | Get realm by name |
//! | PUT | `/admin/realms/{realm}` | Update a realm |
//! | DELETE | `/admin/realms/{realm}` | Delete a realm |
//!
//! ### Users
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/admin/realms/{realm}/users` | List/search users |
//! | POST | `/admin/realms/{realm}/users` | Create a new user |
//! | GET | `/admin/realms/{realm}/users/{id}` | Get user by ID |
//! | PUT | `/admin/realms/{realm}/users/{id}` | Update a user |
//! | DELETE | `/admin/realms/{realm}/users/{id}` | Delete a user |

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod dto;
pub mod error;
pub mod router;
pub mod state;

// Re-export commonly used types
pub use dto::{
    CreateRealmRequest, CreateUserRequest, RealmRepresentation, RealmSummary,
    UpdateRealmRequest, UpdateUserRequest, UserRepresentation, UserSearchParams,
};
pub use error::{AdminError, AdminResult, ErrorResponse};
pub use router::{admin_router, realm_router, user_router};
pub use state::{AdminState, RealmState, UserState};
