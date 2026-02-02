//! Data Transfer Objects (DTOs) for the Admin API.
//!
//! These types define the request and response formats for the API.
//! They are separate from domain models to allow API evolution
//! without affecting internal structures.

pub mod client;
pub mod realm;
pub mod role;
pub mod user;

pub use client::{
    ClientRepresentation, ClientSearchParams, ClientSecretResponse, ClientSummary,
    CreateClientRequest, UpdateClientRequest,
};
pub use realm::{
    CreateRealmRequest, RealmRepresentation, RealmSummary, UpdateRealmRequest,
};
pub use role::{
    CompositeRolesRequest, CreateRoleRequest, RoleRepresentation, RoleSearchParams,
    UpdateRoleRequest,
};
pub use user::{
    CreateUserRequest, UpdateUserRequest, UserRepresentation, UserSearchParams,
};
