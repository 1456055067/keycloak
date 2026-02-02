//! # kc-crypto
//!
//! Cryptographic operations for Keycloak Rust using aws-lc-rs.
//!
//! ## CNSA 2.0 Compliance
//!
//! This crate enforces CNSA 2.0 requirements:
//! - **NO P-256** - Only P-384 and P-521 curves are permitted
//! - **NO SHA-256** - Minimum hash is SHA-384
//! - **RSA minimum 3072 bits** - 4096 recommended
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - SC-12: Cryptographic key management
//! - SC-13: Cryptographic protection

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod algorithm;
pub mod hash;
pub mod signature;

pub use algorithm::{HashAlgorithm, SignatureAlgorithm};
pub use hash::{hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512, sha256, sha384, sha512};
