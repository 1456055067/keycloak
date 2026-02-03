//! Configuration management commands.

use crate::cli::ConfigCommand;
use crate::config::OutputFormat;
use crate::output::{info, success};
use crate::CliConfig;

/// Runs a config command.
pub fn run_config(cmd: ConfigCommand, config: &mut CliConfig) -> crate::CliResult<()> {
    match cmd {
        ConfigCommand::Show => show_config(config),
        ConfigCommand::Set { key, value } => set_config(config, &key, &value),
        ConfigCommand::Init => init_config(config),
    }
}

/// Shows the current configuration.
fn show_config(config: &CliConfig) -> crate::CliResult<()> {
    let config_path = CliConfig::config_path()?;

    info(&format!("Configuration file: {}", config_path.display()));
    println!();
    println!("server_url: {}", config.server_url);

    if let Some(db) = &config.database_url {
        // Mask the password in the database URL
        let masked = mask_password(db);
        println!("database_url: {}", masked);
    }

    if let Some(realm) = &config.default_realm {
        println!("default_realm: {}", realm);
    }

    println!("output_format: {:?}", config.output_format);

    if config.auth.is_some() {
        println!("auth: configured");
    }

    Ok(())
}

/// Sets a configuration value.
fn set_config(config: &mut CliConfig, key: &str, value: &str) -> crate::CliResult<()> {
    match key {
        "server_url" | "server" => {
            config.server_url = value.to_string();
        }
        "database_url" | "database" => {
            config.database_url = Some(value.to_string());
        }
        "default_realm" | "realm" => {
            if value.is_empty() || value == "none" {
                config.default_realm = None;
            } else {
                config.default_realm = Some(value.to_string());
            }
        }
        "output_format" | "output" => {
            config.output_format = match value.to_lowercase().as_str() {
                "table" => OutputFormat::Table,
                "json" => OutputFormat::Json,
                "yaml" => OutputFormat::Yaml,
                "quiet" => OutputFormat::Quiet,
                _ => {
                    return Err(crate::CliError::InvalidArgument(format!(
                        "Unknown output format: {}. Supported: table, json, yaml, quiet",
                        value
                    )));
                }
            };
        }
        _ => {
            return Err(crate::CliError::InvalidArgument(format!(
                "Unknown configuration key: {}. Known keys: server_url, database_url, default_realm, output_format",
                key
            )));
        }
    }

    config.save()?;
    success(&format!("Set {} = {}", key, value));
    Ok(())
}

/// Initializes configuration interactively.
fn init_config(config: &mut CliConfig) -> crate::CliResult<()> {
    let config_path = CliConfig::config_path()?;

    info("Initializing Keycloak CLI configuration...");
    println!();

    // Server URL
    print!("Server URL [{}]: ", config.server_url);
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    {
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            config.server_url = trimmed.to_string();
        }
    }

    // Default realm
    let current_realm = config.default_realm.as_deref().unwrap_or("(none)");
    print!("Default realm [{}]: ", current_realm);
    std::io::Write::flush(&mut std::io::stdout())?;
    input.clear();
    std::io::stdin().read_line(&mut input)?;
    {
        let trimmed = input.trim();
        if !trimmed.is_empty() && trimmed != "(none)" {
            config.default_realm = Some(trimmed.to_string());
        }
    }

    // Output format
    print!("Output format (table/json/yaml/quiet) [{:?}]: ", config.output_format);
    std::io::Write::flush(&mut std::io::stdout())?;
    input.clear();
    std::io::stdin().read_line(&mut input)?;
    {
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            config.output_format = match trimmed.to_lowercase().as_str() {
                "table" => OutputFormat::Table,
                "json" => OutputFormat::Json,
                "yaml" => OutputFormat::Yaml,
                "quiet" => OutputFormat::Quiet,
                _ => config.output_format,
            };
        }
    }

    // Save configuration
    config.save()?;

    println!();
    success(&format!("Configuration saved to: {}", config_path.display()));
    Ok(())
}

/// Masks the password in a database URL.
fn mask_password(url: &str) -> String {
    // Simple password masking - look for :password@ pattern
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            // Check if there's a // before the colon (indicating protocol)
            let protocol_end = url.find("://").map(|p| p + 3).unwrap_or(0);
            if colon_pos > protocol_end {
                // There's a password
                return format!("{}:****{}", &url[..colon_pos], &url[at_pos..]);
            }
        }
    }
    url.to_string()
}

/// Status command.
pub async fn run_status(
    config: &CliConfig,
    server: Option<&str>,
) -> crate::CliResult<()> {
    let client = super::ApiClient::new(config, server)?;
    let base_url = client.base_url();

    info(&format!("Checking server status at {}...", base_url));

    // Try health endpoint
    match client.get::<serde_json::Value>("/health").await {
        Ok(health) => {
            success("Server is reachable");
            println!();

            if let Some(status) = health.get("status").and_then(|v| v.as_str()) {
                println!("Status: {}", status);
            }

            // Try to get realm count
            match client.get::<Vec<serde_json::Value>>("/admin/realms").await {
                Ok(realms) => {
                    println!("Realms: {}", realms.len());
                }
                Err(_) => {
                    println!("Realms: (requires authentication)");
                }
            }
        }
        Err(e) => {
            crate::output::error(&format!("Server is not reachable: {}", e));
        }
    }

    Ok(())
}
