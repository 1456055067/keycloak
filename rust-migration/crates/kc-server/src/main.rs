//! # Keycloak Rust Server
//!
//! Main entry point for the Keycloak Rust server.

#![forbid(unsafe_code)]
#![deny(warnings)]

use kc_server::{Server, ServerConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = ServerConfig::from_env()?;

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Keycloak Rust v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Starting server on {}:{}", config.host, config.port);

    // Create and run server
    let server = Server::new(config).await?;
    server.run().await?;

    Ok(())
}
