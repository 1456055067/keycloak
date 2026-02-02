//! OIDC router configuration.
//!
//! Provides the Axum router for all OIDC endpoints.

use axum::{Router, routing::{get, post}};

use super::discovery::{jwks, well_known};
use super::introspection::introspect;
use super::revocation::revoke;
use super::state::{OidcState, RealmProvider};
use super::token::token;
use super::userinfo::{userinfo_get, userinfo_post};

/// Creates the OIDC protocol router.
///
/// # Endpoints
///
/// The router provides the following endpoints (relative to the mount point):
///
/// | Method | Path                             | Handler     | Description                    |
/// |--------|----------------------------------|-------------|--------------------------------|
/// | GET    | `/:realm/.well-known/openid-configuration` | `well_known` | Discovery document     |
/// | GET    | `/:realm/protocol/openid-connect/certs`    | `jwks`       | JSON Web Key Set       |
/// | POST   | `/:realm/protocol/openid-connect/token`    | `token`      | Token endpoint         |
/// | GET    | `/:realm/protocol/openid-connect/userinfo` | `userinfo`   | `UserInfo` (GET)       |
/// | POST   | `/:realm/protocol/openid-connect/userinfo` | `userinfo`   | `UserInfo` (POST)      |
/// | POST   | `/:realm/protocol/openid-connect/token/introspect` | `introspect` | Introspection |
/// | POST   | `/:realm/protocol/openid-connect/revoke`   | `revoke`     | Token revocation       |
///
/// # Usage
///
/// ```rust,ignore
/// use kc_protocol_oidc::endpoints::{oidc_router, OidcState};
///
/// let state = OidcState::new(realm_provider);
/// let app = Router::new()
///     .merge(oidc_router())
///     .with_state(state);
/// ```
///
/// # Note
///
/// The authorization endpoint (`/auth`) requires UI interaction and should be
/// implemented separately with proper session management and login flows.
pub fn oidc_router<R: RealmProvider + Clone + 'static>() -> Router<OidcState<R>> {
    Router::new()
        // Discovery endpoints
        .route(
            "/realms/:realm/.well-known/openid-configuration",
            get(well_known::<R>),
        )
        .route(
            "/realms/:realm/protocol/openid-connect/certs",
            get(jwks::<R>),
        )
        // Token endpoints
        .route(
            "/realms/:realm/protocol/openid-connect/token",
            post(token::<R>),
        )
        .route(
            "/realms/:realm/protocol/openid-connect/token/introspect",
            post(introspect::<R>),
        )
        .route(
            "/realms/:realm/protocol/openid-connect/revoke",
            post(revoke::<R>),
        )
        // `UserInfo` endpoint
        .route(
            "/realms/:realm/protocol/openid-connect/userinfo",
            get(userinfo_get::<R>).post(userinfo_post::<R>),
        )
}

#[cfg(test)]
mod tests {
    // Router tests would require setting up a mock RealmProvider
    // and using axum-test or tower-test for integration testing
}
