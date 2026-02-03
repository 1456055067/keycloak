//! SAML router configuration.
//!
//! Provides the Axum router for all SAML endpoints.

use axum::{Router, routing::get};

use super::metadata::idp_metadata;
use super::sls::{sls_post, sls_redirect};
use super::sso::{sso_post, sso_redirect};
use super::state::{SamlRealmProvider, SamlState};

/// Creates the SAML protocol router.
///
/// # Endpoints
///
/// The router provides the following endpoints:
///
/// | Method   | Path                                          | Handler       | Description                    |
/// |----------|-----------------------------------------------|---------------|--------------------------------|
/// | GET      | `/realms/{realm}/protocol/saml/descriptor`    | `idp_metadata`| IdP metadata                   |
/// | GET/POST | `/realms/{realm}/protocol/saml`               | `sso`         | Single Sign-On service         |
/// | GET/POST | `/realms/{realm}/protocol/saml/logout`        | `sls`         | Single Logout service          |
///
/// # Usage
///
/// ```rust,ignore
/// use kc_protocol_saml::endpoints::{saml_router, SamlState};
///
/// let state = SamlState::new(realm_provider);
/// let app = Router::new()
///     .merge(saml_router())
///     .with_state(state);
/// ```
pub fn saml_router<R: SamlRealmProvider + Clone + 'static>() -> Router<SamlState<R>> {
    Router::new()
        // IdP Metadata
        .route(
            "/realms/{realm}/protocol/saml/descriptor",
            get(idp_metadata::<R>),
        )
        // Single Sign-On Service
        .route(
            "/realms/{realm}/protocol/saml",
            get(sso_redirect::<R>).post(sso_post::<R>),
        )
        // Single Logout Service
        .route(
            "/realms/{realm}/protocol/saml/logout",
            get(sls_redirect::<R>).post(sls_post::<R>),
        )
}

#[cfg(test)]
mod tests {
    // Router tests would require setting up a mock SamlRealmProvider
    // and using axum-test or tower-test for integration testing
}
