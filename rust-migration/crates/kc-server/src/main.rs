//! # Keycloak Rust Server
//!
//! Main entry point for the Keycloak Rust server.

#![forbid(unsafe_code)]
#![deny(warnings)]

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Keycloak Rust starting...");

    // Server implementation will be added in later phases
    tracing::info!("Server not yet implemented - Phase 1 complete");

    Ok(())
}
