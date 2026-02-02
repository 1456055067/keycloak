//! End-to-End Integration Tests
//!
//! These tests validate the complete Keycloak Rust system using
//! testcontainers for ephemeral PostgreSQL instances.

mod common;
mod auth_flows;
mod admin_api;
mod token_operations;
