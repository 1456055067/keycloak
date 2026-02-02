//! Redis connection configuration.

use serde::{Deserialize, Serialize};

/// Redis connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis server host.
    #[serde(default = "default_host")]
    pub host: String,
    /// Redis server port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Redis password (optional).
    pub password: Option<String>,
    /// Redis database number.
    #[serde(default)]
    pub database: u8,
    /// Use TLS for connection.
    #[serde(default)]
    pub tls: bool,
    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Connection timeout in milliseconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    /// Command timeout in milliseconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_ms: u64,
    /// Key prefix for all cache keys.
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    /// Redis cluster mode.
    #[serde(default)]
    pub cluster: bool,
    /// Sentinel configuration (optional).
    pub sentinel: Option<SentinelConfig>,
}

/// Redis Sentinel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Sentinel master name.
    pub master_name: String,
    /// Sentinel nodes.
    pub nodes: Vec<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            password: None,
            database: 0,
            tls: false,
            pool_size: default_pool_size(),
            connect_timeout_ms: default_connect_timeout(),
            command_timeout_ms: default_command_timeout(),
            key_prefix: default_key_prefix(),
            cluster: false,
            sentinel: None,
        }
    }
}

impl RedisConfig {
    /// Creates a new Redis configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Redis host.
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Sets the Redis port.
    #[must_use]
    pub const fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the Redis password.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets the Redis database number.
    #[must_use]
    pub const fn database(mut self, database: u8) -> Self {
        self.database = database;
        self
    }

    /// Enables TLS.
    #[must_use]
    pub const fn tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    /// Sets the connection pool size.
    #[must_use]
    pub const fn pool_size(mut self, size: usize) -> Self {
        self.pool_size = size;
        self
    }

    /// Sets the key prefix.
    #[must_use]
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Builds the Redis connection URL.
    #[must_use]
    pub fn connection_url(&self) -> String {
        let scheme = if self.tls { "rediss" } else { "redis" };
        let auth = self
            .password
            .as_ref()
            .map(|p| format!(":{p}@"))
            .unwrap_or_default();
        format!(
            "{scheme}://{auth}{host}:{port}/{db}",
            host = self.host,
            port = self.port,
            db = self.database
        )
    }

    /// Formats a key with the configured prefix.
    #[must_use]
    pub fn prefixed_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", self.key_prefix, key)
        }
    }
}

fn default_host() -> String {
    "localhost".to_string()
}

const fn default_port() -> u16 {
    6379
}

const fn default_pool_size() -> usize {
    10
}

const fn default_connect_timeout() -> u64 {
    5000
}

const fn default_command_timeout() -> u64 {
    2000
}

fn default_key_prefix() -> String {
    "kc".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = RedisConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6379);
        assert_eq!(config.database, 0);
        assert!(!config.tls);
    }

    #[test]
    fn connection_url() {
        let config = RedisConfig::default();
        assert_eq!(config.connection_url(), "redis://localhost:6379/0");

        let config = RedisConfig::default()
            .host("redis.example.com")
            .port(6380)
            .password("secret")
            .database(1)
            .tls(true);
        assert_eq!(
            config.connection_url(),
            "rediss://:secret@redis.example.com:6380/1"
        );
    }

    #[test]
    fn prefixed_key() {
        let config = RedisConfig::default();
        assert_eq!(config.prefixed_key("user:123"), "kc:user:123");

        let config = RedisConfig::default().key_prefix("");
        assert_eq!(config.prefixed_key("user:123"), "user:123");
    }
}
