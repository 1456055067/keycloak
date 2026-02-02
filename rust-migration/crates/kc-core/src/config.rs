//! Configuration management for Keycloak Rust.
//!
//! Supports loading configuration from environment variables, files, and CLI arguments.

use serde::{Deserialize, Serialize};

/// Main configuration structure for Keycloak.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration.
    pub server: ServerConfig,
    /// Database configuration.
    pub database: DatabaseConfig,
    /// Cache configuration.
    pub cache: CacheConfig,
    /// Cryptographic configuration.
    pub crypto: CryptoConfig,
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to.
    pub host: String,
    /// Port to bind to.
    pub port: u16,
    /// Base URL for the server.
    pub base_url: String,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database connection URL.
    pub url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of connections in the pool.
    pub min_connections: u32,
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Redis connection URL.
    pub redis_url: String,
}

/// Cryptographic configuration.
///
/// ## CNSA 2.0 Compliance
///
/// All cryptographic operations must use CNSA 2.0 approved algorithms:
/// - Minimum curve: P-384 (NO P-256)
/// - Minimum hash: SHA-384 (NO SHA-256)
/// - Minimum RSA: 3072 bits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default signing algorithm (must be ES384, ES512, RS384, RS512, PS384, or PS512).
    pub default_signature_algorithm: String,
    /// RSA key size in bits (minimum 3072).
    pub rsa_key_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                base_url: "http://localhost:8080".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://localhost/keycloak".to_string(),
                max_connections: 10,
                min_connections: 1,
            },
            cache: CacheConfig {
                redis_url: "redis://localhost:6379".to_string(),
            },
            crypto: CryptoConfig {
                // CNSA 2.0: ES384 is the default (P-384 curve, SHA-384 hash)
                default_signature_algorithm: "ES384".to_string(),
                // CNSA 2.0: Minimum RSA key size is 3072 bits
                rsa_key_size: 4096,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_cnsa_compliant() {
        let config = Config::default();

        // CNSA 2.0: Must use ES384 or higher
        assert!(
            config.crypto.default_signature_algorithm == "ES384"
                || config.crypto.default_signature_algorithm == "ES512"
                || config.crypto.default_signature_algorithm == "RS384"
                || config.crypto.default_signature_algorithm == "RS512"
                || config.crypto.default_signature_algorithm == "PS384"
                || config.crypto.default_signature_algorithm == "PS512",
            "Default signature algorithm must be CNSA 2.0 compliant"
        );

        // CNSA 2.0: RSA key size must be at least 3072 bits
        assert!(
            config.crypto.rsa_key_size >= 3072,
            "RSA key size must be at least 3072 bits for CNSA 2.0 compliance"
        );
    }
}
