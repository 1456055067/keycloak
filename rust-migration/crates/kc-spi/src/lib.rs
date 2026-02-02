//! # kc-spi
//!
//! Service Provider Interface (SPI) traits for Keycloak Rust extensibility.
//!
//! This crate defines the core abstractions for the plugin system, allowing
//! custom implementations of authentication, storage, and other components.
//!
//! ## Design
//!
//! The SPI pattern uses Rust traits instead of Java interfaces:
//! - [`Provider`] - Base trait for all provider implementations
//! - [`ProviderFactory`] - Factory trait for creating provider instances
//! - [`Spi`] - Definition of an SPI extension point

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod provider;
pub mod registry;
pub mod session;

pub use provider::{Provider, ProviderFactory, ProviderMetadata, Spi};
pub use registry::SpiRegistry;
pub use session::KeycloakSession;
