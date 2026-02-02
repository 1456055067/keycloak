//! # kc-protocol-oidc
//!
//! `OpenID` Connect protocol implementation for Keycloak Rust.
//!
//! This crate implements the OIDC specification including:
//! - Authorization endpoint
//! - Token endpoint
//! - `UserInfo` endpoint
//! - JWKS endpoint
//!
//! ## CNSA 2.0 Compliance
//!
//! Only ES384, ES512, RS384, RS512, PS384, PS512 signing algorithms are supported.
//! ES256, RS256, PS256 are explicitly forbidden.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

// OIDC protocol will be implemented in Phase 4
