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
pub mod client_auth;
mod discovery;
pub mod grants;
mod introspection;
mod revocation;
mod router;
mod state;
mod token;
mod userinfo;

// Re-export types from authorization module
pub use authorization::{
    AuthorizationCode, AuthorizationEndpointState, AuthorizationResponse, AuthSessionContext,
    ClientProvider, authorize_get_with_sessions, authorize_post_with_sessions,
};

// Re-export grant types
pub use grants::{
    AuthCodeParams, AuthCodeStore, AuthenticatedClient, AuthenticatedUser, AuthorizationCodeGrant,
    ClientAuthMethod, ClientAuthenticator, ClientCredentialsGrant, GrantContext, GrantResult,
    InMemoryAuthCodeStore, PasswordGrant, PkceVerifier, RefreshTokenGrant, SessionTimeouts,
    StoredAuthCode, UserAuthenticator,
};

// Re-export client auth types
pub use client_auth::{extract_credentials, StorageClientAuthenticator, CLIENT_ASSERTION_TYPE_JWT};

// Re-export the router and state
pub use router::oidc_router;
pub use state::{OidcState, RealmProvider, TokenEndpointState};

// Re-export token endpoint handlers
pub use token::{token, token_with_sessions};

// Re-export userinfo endpoint types and handlers
pub use userinfo::{
    AddressClaim, UserInfoData, UserInfoEndpointState, UserInfoProvider, UserInfoResponse,
    userinfo_get_with_provider, userinfo_post_with_provider,
};

// Re-export introspection endpoint types and handlers
pub use introspection::{IntrospectionEndpointState, introspect_with_auth};

// Re-export revocation endpoint types and handlers
pub use revocation::{
    InMemoryTokenBlocklist, RevocationEndpointState, TokenBlocklist, revoke_with_blocklist,
};
