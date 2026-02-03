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
// Allow some clippy lints for now - these are stylistic and will be addressed later
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::future_not_send)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::unused_async)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::format_collect)]
#![allow(clippy::use_self)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::branches_sharing_code)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
pub mod output;

pub use cli::Cli;
pub use config::CliConfig;
pub use error::{CliError, CliResult};
