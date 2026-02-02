//! Database connection pool management.

use std::time::Duration;

use kc_storage::StorageError;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Database pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Database connection URL.
    pub url: String,
    /// Maximum number of connections.
    pub max_connections: u32,
    /// Minimum number of connections.
    pub min_connections: u32,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Idle connection timeout.
    pub idle_timeout: Duration,
    /// Maximum connection lifetime.
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/keycloak".to_string(),
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

impl PoolConfig {
    /// Creates a new pool configuration.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Sets the maximum number of connections.
    #[must_use]
    pub const fn max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the minimum number of connections.
    #[must_use]
    pub const fn min_connections(mut self, min: u32) -> Self {
        self.min_connections = min;
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the idle timeout.
    #[must_use]
    pub const fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }
}

/// Creates a `PostgreSQL` connection pool.
///
/// # Errors
///
/// Returns an error if the pool cannot be created.
pub async fn create_pool(config: &PoolConfig) -> Result<PgPool, StorageError> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(Some(config.idle_timeout))
        .max_lifetime(Some(config.max_lifetime))
        .connect(&config.url)
        .await
        .map_err(|e| StorageError::Connection(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 1);
    }

    #[test]
    fn pool_config_builder() {
        let config = PoolConfig::new("postgres://localhost/test")
            .max_connections(20)
            .min_connections(5);

        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);
        assert_eq!(config.url, "postgres://localhost/test");
    }
}
