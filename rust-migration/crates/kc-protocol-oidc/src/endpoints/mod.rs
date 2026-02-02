//! OIDC endpoint handlers for Axum.
//!
//! This module provides HTTP handlers for all `OpenID` Connect endpoints:
//! - Authorization (`/auth`)
//! - Discovery (`.well-known/openid-configuration`)
//! - JWKS (`/certs`)
//! - Token (`/token`)
//! - `UserInfo` (`/userinfo`)
//! - Introspection (`/token/introspect`)
//! - Revocation (`/revoke`)
//!
//! ## Router Setup
//!
//! Use [`oidc_router`] to create a configured Axum router with all endpoints.
//!
//! ```rust,ignore
//! use kc_protocol_oidc::endpoints::oidc_router;
//!
//! let app = Router::new()
//!     .nest("/realms/:realm/protocol/openid-connect", oidc_router())
//!     .with_state(app_state);
//! ```

mod authorization;
mod discovery;
mod introspection;
mod revocation;
mod router;
mod state;
mod token;
mod userinfo;

// Re-export types from authorization module
pub use authorization::{AuthorizationCode, AuthorizationResponse};

// Re-export the router and state
pub use router::oidc_router;
pub use state::{OidcState, RealmProvider};
