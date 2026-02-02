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
//! - [`auth`] - Authentication and authorization middleware
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
//!
//! ### Clients
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/admin/realms/{realm}/clients` | List/search clients |
//! | POST | `/admin/realms/{realm}/clients` | Create a new client |
//! | GET | `/admin/realms/{realm}/clients/{id}` | Get client by ID |
//! | PUT | `/admin/realms/{realm}/clients/{id}` | Update a client |
//! | DELETE | `/admin/realms/{realm}/clients/{id}` | Delete a client |
//! | GET | `/admin/realms/{realm}/clients/{id}/client-secret` | Get client secret |
//! | POST | `/admin/realms/{realm}/clients/{id}/client-secret` | Regenerate client secret |
//!
//! ### Roles
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/admin/realms/{realm}/roles` | List realm roles |
//! | POST | `/admin/realms/{realm}/roles` | Create a realm role |
//! | GET | `/admin/realms/{realm}/roles/{role-name}` | Get realm role by name |
//! | PUT | `/admin/realms/{realm}/roles/{role-name}` | Update a realm role |
//! | DELETE | `/admin/realms/{realm}/roles/{role-name}` | Delete a realm role |
//! | GET | `/admin/realms/{realm}/roles/{role-name}/composites` | Get composite roles |
//! | POST | `/admin/realms/{realm}/roles/{role-name}/composites` | Add composite roles |
//! | DELETE | `/admin/realms/{realm}/roles/{role-name}/composites` | Remove composite roles |
//! | GET | `/admin/realms/{realm}/clients/{id}/roles` | List client roles |
//! | POST | `/admin/realms/{realm}/clients/{id}/roles` | Create a client role |
//! | GET | `/admin/realms/{realm}/clients/{id}/roles/{role-name}` | Get client role by name |
//! | PUT | `/admin/realms/{realm}/clients/{id}/roles/{role-name}` | Update a client role |
//! | DELETE | `/admin/realms/{realm}/clients/{id}/roles/{role-name}` | Delete a client role |
//!
//! ### Groups
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/admin/realms/{realm}/groups` | List/search groups |
//! | POST | `/admin/realms/{realm}/groups` | Create a top-level group |
//! | GET | `/admin/realms/{realm}/groups/count` | Count groups in realm |
//! | GET | `/admin/realms/{realm}/groups/{id}` | Get group by ID |
//! | PUT | `/admin/realms/{realm}/groups/{id}` | Update a group |
//! | DELETE | `/admin/realms/{realm}/groups/{id}` | Delete a group |
//! | GET | `/admin/realms/{realm}/groups/{id}/children` | Get child groups |
//! | POST | `/admin/realms/{realm}/groups/{id}/children` | Create a child group |
//! | GET | `/admin/realms/{realm}/groups/{id}/members` | Get group members |

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod auth;
pub mod dto;
pub mod error;
pub mod events;
pub mod import_export;
pub mod router;
pub mod state;

// Re-export commonly used types
pub use auth::{
    auth_middleware, require_any_permission, require_permission, AdminAuth, AuthState, Permission,
    SimpleTokenValidator, TokenValidator,
};
pub use dto::{
    ClientRepresentation, ClientSearchParams, ClientSecretResponse, ClientSummary,
    CompositeRolesRequest, CreateClientRequest, CreateGroupRequest, CreateRealmRequest,
    CreateRoleRequest, CreateUserRequest, GroupMemberCount, GroupRepresentation, GroupSearchParams,
    RealmRepresentation, RealmSummary, RoleRepresentation, RoleSearchParams, UpdateClientRequest,
    UpdateGroupRequest, UpdateRealmRequest, UpdateRoleRequest, UpdateUserRequest,
    UserRepresentation, UserSearchParams,
};
pub use error::{AdminError, AdminResult, ErrorResponse};
pub use events::{
    AdminEventBuilder, AdminEventLogger, EventLogError, InMemoryEventLogger, TracingEventLogger,
};
pub use import_export::{
    ClientExport, CredentialExport, ExportOptions, ImportOptions, ImportResult,
    ProtocolMapperExport, RealmExport, RoleExport, RolesExport, UserExport,
};
pub use router::{
    admin_client_router, admin_group_router, admin_role_router, admin_router, client_role_router,
    client_router, group_router, realm_role_router, realm_router, user_router,
};
pub use state::{AdminState, ClientState, GroupState, RealmState, RoleState, UserState};
