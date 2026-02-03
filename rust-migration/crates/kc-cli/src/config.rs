//! CLI configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Server URL (e.g., http://localhost:8080).
    #[serde(default = "default_server_url")]
    pub server_url: String,

    /// Database URL for direct database access.
    pub database_url: Option<String>,

    /// Default realm to operate on.
    pub default_realm: Option<String>,

    /// Output format.
    #[serde(default)]
    pub output_format: OutputFormat,

    /// Authentication configuration.
    pub auth: Option<AuthConfig>,
}

/// Default server URL.
fn default_server_url() -> String {
    "http://localhost:8080".to_string()
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            database_url: None,
            default_realm: None,
            output_format: OutputFormat::default(),
            auth: None,
        }
    }
}

impl CliConfig {
    /// Loads configuration from file.
    pub fn load() -> crate::CliResult<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Self = toml::from_str(&content).map_err(|e| {
                crate::CliError::Config(format!("failed to parse config: {e}"))
            })?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Saves configuration to file.
    pub fn save(&self) -> crate::CliResult<()> {
        let config_path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self).map_err(|e| {
            crate::CliError::Config(format!("failed to serialize config: {e}"))
        })?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    /// Gets the configuration file path.
    pub fn config_path() -> crate::CliResult<PathBuf> {
        let home = dirs_next::home_dir()
            .ok_or_else(|| crate::CliError::Config("could not determine home directory".to_string()))?;
        Ok(home.join(".keycloak").join("kc.toml"))
    }

    /// Gets the effective realm (from args or config).
    pub fn effective_realm(&self, arg_realm: Option<&str>) -> Option<String> {
        arg_realm
            .map(|s| s.to_string())
            .or_else(|| self.default_realm.clone())
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable table format.
    #[default]
    Table,
    /// JSON format.
    Json,
    /// YAML format.
    Yaml,
    /// Quiet (minimal output).
    Quiet,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Client ID for authentication.
    pub client_id: String,
    /// Client secret (if confidential client).
    pub client_secret: Option<String>,
    /// Username for password grant.
    pub username: Option<String>,
    /// Cached access token.
    #[serde(skip_serializing)]
    pub access_token: Option<String>,
    /// Cached refresh token.
    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,
}
