//! SAML endpoint handlers.
//!
//! This module provides Axum HTTP handlers for SAML endpoints:
//!
//! - **SSO Endpoint** - Single Sign-On service (receives AuthnRequests)
//! - **SLS Endpoint** - Single Logout Service (handles logout)
//! - **Metadata Endpoint** - Serves IdP metadata
//!
//! # Example
//!
//! ```rust,ignore
//! use kc_protocol_saml::endpoints::saml_router;
//! use axum::Router;
//!
//! let app = Router::new()
//!     .merge(saml_router())
//!     .with_state(saml_state);
//! ```

mod metadata;
mod router;
mod sls;
mod sso;
mod state;

pub use metadata::*;
pub use router::*;
pub use sls::*;
pub use sso::*;
pub use state::*;
