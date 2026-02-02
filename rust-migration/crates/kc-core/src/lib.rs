//! # kc-core
//!
//! Core utilities, configuration, and error handling for Keycloak Rust.
//!
//! This crate provides foundational types and utilities used across all other
//! Keycloak Rust crates.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - AU-2: Event logging framework
//! - SI-11: Error handling

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod config;
pub mod error;
pub mod event;

pub use config::Config;
pub use error::{Error, Result};
