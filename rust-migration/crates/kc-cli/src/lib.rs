//! # kc-cli
//!
//! CLI tools for Keycloak Rust administration.
//!
//! This crate provides command-line utilities for:
//! - Realm management (create, list, update, delete)
//! - User management (create, list, update, delete)
//! - Client management (create, list, update, delete)
//! - Export/Import operations
//! - Cryptographic utilities (key generation, token inspection)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
pub mod output;

pub use cli::Cli;
pub use config::CliConfig;
pub use error::{CliError, CliResult};
