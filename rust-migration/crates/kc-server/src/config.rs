//! Server configuration.
//!
//! Configuration is loaded from environment variables with sensible defaults.

use std::time::Duration;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server host to bind to.
    pub host: String,

    /// Server port.
    pub port: u16,

    /// Base URL for the server (used in generated URLs).
    pub base_url: String,

    /// Database connection URL.
    pub database_url: String,

    /// Minimum database connections.
    pub db_min_connections: u32,

    /// Maximum database connections.
    pub db_max_connections: u32,

    /// Redis URL (optional, for distributed caching).
    pub redis_url: Option<String>,

    /// Access token lifespan in seconds.
    pub access_token_lifespan: i64,

    /// Refresh token lifespan in seconds.
    pub refresh_token_lifespan: i64,

    /// ID token lifespan in seconds.
    pub id_token_lifespan: i64,

    /// Authorization code lifespan in seconds.
    pub auth_code_lifespan: i64,

    /// Session idle timeout in seconds.
    pub session_idle_timeout: i64,

    /// Session maximum lifespan in seconds.
    pub session_max_lifespan: i64,

    /// CORS allowed origins (comma-separated).
    pub cors_origins: Vec<String>,

    /// Enable admin API.
    pub admin_api_enabled: bool,

    /// Log level.
    pub log_level: String,
}

impl ServerConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        let host = std::env::var("KC_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = std::env::var("KC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let base_url = std::env::var("KC_BASE_URL")
            .unwrap_or_else(|_| format!("http://{}:{}", host, port));

        let database_url = std::env::var("DATABASE_URL").map_err(|_| {
            anyhow::anyhow!("DATABASE_URL environment variable is required")
        })?;

        let db_min_connections = std::env::var("KC_DB_MIN_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let db_max_connections = std::env::var("KC_DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let redis_url = std::env::var("REDIS_URL").ok();

        let access_token_lifespan = std::env::var("KC_ACCESS_TOKEN_LIFESPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300); // 5 minutes

        let refresh_token_lifespan = std::env::var("KC_REFRESH_TOKEN_LIFESPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1800); // 30 minutes

        let id_token_lifespan = std::env::var("KC_ID_TOKEN_LIFESPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300); // 5 minutes

        let auth_code_lifespan = std::env::var("KC_AUTH_CODE_LIFESPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60); // 1 minute

        let session_idle_timeout = std::env::var("KC_SESSION_IDLE_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1800); // 30 minutes

        let session_max_lifespan = std::env::var("KC_SESSION_MAX_LIFESPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(36000); // 10 hours

        let cors_origins = std::env::var("KC_CORS_ORIGINS")
            .map(|s| s.split(',').map(str::trim).map(String::from).collect())
            .unwrap_or_else(|_| vec!["*".to_string()]);

        let admin_api_enabled = std::env::var("KC_ADMIN_API_ENABLED")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        Ok(Self {
            host,
            port,
            base_url,
            database_url,
            db_min_connections,
            db_max_connections,
            redis_url,
            access_token_lifespan,
            refresh_token_lifespan,
            id_token_lifespan,
            auth_code_lifespan,
            session_idle_timeout,
            session_max_lifespan,
            cors_origins,
            admin_api_enabled,
            log_level,
        })
    }

    /// Creates a configuration for testing.
    #[must_use]
    pub fn for_testing(database_url: &str) -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 0, // Random port
            base_url: "http://localhost:8080".to_string(),
            database_url: database_url.to_string(),
            db_min_connections: 1,
            db_max_connections: 5,
            redis_url: None,
            access_token_lifespan: 300,
            refresh_token_lifespan: 1800,
            id_token_lifespan: 300,
            auth_code_lifespan: 60,
            session_idle_timeout: 1800,
            session_max_lifespan: 36000,
            cors_origins: vec!["*".to_string()],
            admin_api_enabled: true,
            log_level: "debug".to_string(),
        }
    }

    /// Returns the access token duration.
    #[must_use]
    pub fn access_token_duration(&self) -> Duration {
        Duration::from_secs(self.access_token_lifespan as u64)
    }

    /// Returns the refresh token duration.
    #[must_use]
    pub fn refresh_token_duration(&self) -> Duration {
        Duration::from_secs(self.refresh_token_lifespan as u64)
    }

    /// Returns the ID token duration.
    #[must_use]
    pub fn id_token_duration(&self) -> Duration {
        Duration::from_secs(self.id_token_lifespan as u64)
    }

    /// Returns the authorization code duration.
    #[must_use]
    pub fn auth_code_duration(&self) -> Duration {
        Duration::from_secs(self.auth_code_lifespan as u64)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            database_url: "postgres://localhost/keycloak".to_string(),
            db_min_connections: 1,
            db_max_connections: 10,
            redis_url: None,
            access_token_lifespan: 300,
            refresh_token_lifespan: 1800,
            id_token_lifespan: 300,
            auth_code_lifespan: 60,
            session_idle_timeout: 1800,
            session_max_lifespan: 36000,
            cors_origins: vec!["*".to_string()],
            admin_api_enabled: true,
            log_level: "info".to_string(),
        }
    }
}
