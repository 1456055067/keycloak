//! # kc-server
//!
//! Main Axum server for Keycloak Rust.
//!
//! This crate provides the unified HTTP server combining:
//! - OIDC protocol endpoints (discovery, token, userinfo, etc.)
//! - Admin REST API endpoints (realms, users, clients, etc.)
//! - Health check and metrics endpoints
//!
//! ## Architecture
//!
//! The server is built around the concept of providers that are injected at
//! runtime. This allows for different storage backends and deployment configurations.
//!
//! ## Usage
//!
//! ```ignore
//! use kc_server::{Server, ServerConfig};
//!
//! let config = ServerConfig::from_env()?;
//! let server = Server::new(config).await?;
//! server.run().await?;
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod config;
pub mod providers;
pub mod router;
pub mod state;

pub use config::ServerConfig;
pub use router::create_router;
pub use state::AppState;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::providers::StorageProviders;

/// The Keycloak Rust server.
pub struct Server {
    config: ServerConfig,
    pool: PgPool,
}

impl Server {
    /// Creates a new server instance.
    ///
    /// This initializes the database connection pool and validates the configuration.
    pub async fn new(config: ServerConfig) -> anyhow::Result<Self> {
        // Create database pool configuration
        let pool_config = kc_storage_sql::PoolConfig::new(&config.database_url)
            .max_connections(config.db_max_connections)
            .min_connections(config.db_min_connections)
            .connect_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600));

        // Create database pool
        let pool = kc_storage_sql::create_pool(&pool_config).await?;

        tracing::info!("Database connection pool created");

        Ok(Self { config, pool })
    }

    /// Runs the server.
    ///
    /// This starts the HTTP server and blocks until it receives a shutdown signal.
    pub async fn run(self) -> anyhow::Result<()> {
        // Create storage providers
        let providers = StorageProviders::new(self.pool.clone());

        // Set the base URL
        providers.set_base_url(&self.config.base_url).await;

        // Create app state
        let state = AppState::new(self.config.clone(), Arc::new(providers));

        // Create router
        let app = create_router(state);

        // Bind to address
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port).parse()?;
        let listener = TcpListener::bind(addr).await?;

        tracing::info!("Server listening on http://{}", addr);

        // Run server with graceful shutdown
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        tracing::info!("Server shutdown complete");
        Ok(())
    }

    /// Returns the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Returns the server configuration.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Creates a test router without starting the server.
    ///
    /// This is useful for integration testing.
    pub fn test_router(&self) -> Router {
        let providers = StorageProviders::new(self.pool.clone());
        let state = AppState::new(self.config.clone(), Arc::new(providers));
        create_router(state)
    }
}

/// Waits for a shutdown signal.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
