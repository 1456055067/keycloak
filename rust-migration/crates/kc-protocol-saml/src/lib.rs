//! SAML 2.0 Protocol Implementation for Keycloak Rust.
//!
//! This crate provides a complete SAML 2.0 implementation including:
//!
//! - **AuthnRequest parsing and validation** - Handle incoming authentication requests
//! - **SAML Response/Assertion generation** - Create signed SAML responses
//! - **XML signature** - Sign and validate XML documents using XML-DSig
//! - **POST and Redirect bindings** - Support for both SAML binding types
//! - **Single Logout (SLO)** - Handle logout requests and responses
//!
//! # Architecture
//!
//! The crate is organized into several modules:
//!
//! - [`types`] - Core SAML types and data structures
//! - [`signature`] - XML signature signing and validation
//! - [`bindings`] - POST and Redirect binding implementations
//! - [`endpoints`] - Axum HTTP handlers for SAML endpoints
//! - [`error`] - Error types for SAML operations
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
//!
//! # SAML Specifications
//!
//! This implementation follows these specifications:
//!
//! - [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
//! - [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
//! - [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
//! - [XML Signature](https://www.w3.org/TR/xmldsig-core1/)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bindings;
pub mod endpoints;
pub mod error;
pub mod signature;
pub mod types;

pub use error::{SamlError, SamlResult};
pub use types::*;
