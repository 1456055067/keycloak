//! Realm management commands.

use serde::{Deserialize, Serialize};
use tabled::Tabled;

use crate::cli::RealmCommand;
use crate::config::OutputFormat;
use crate::output::{confirm, error, output, output_single, success};
use crate::CliConfig;

use super::ApiClient;

/// Realm representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct RealmDisplay {
    /// Realm name.
    pub name: String,
    /// Display name.
    #[tabled(rename = "Display Name")]
    #[serde(default)]
    pub display_name: String,
    /// Whether the realm is enabled.
    pub enabled: bool,
}

/// Create realm request.
#[derive(Debug, Serialize)]
struct CreateRealmRequest {
    name: String,
    display_name: Option<String>,
    enabled: bool,
}

/// Runs a realm command.
pub async fn run_realm(
    cmd: RealmCommand,
    config: &CliConfig,
    server: Option<&str>,
    output_format: OutputFormat,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    match cmd {
        RealmCommand::List => list_realms(&client, output_format).await,
        RealmCommand::Get { name } => get_realm(&client, &name, output_format).await,
        RealmCommand::Create {
            name,
            display_name,
            enabled,
        } => create_realm(&client, &name, display_name.as_deref(), enabled).await,
        RealmCommand::Update {
            name,
            display_name,
            enabled,
        } => update_realm(&client, &name, display_name.as_deref(), enabled).await,
        RealmCommand::Delete { name, force } => delete_realm(&client, &name, force).await,
    }
}

/// Lists all realms.
async fn list_realms(client: &ApiClient, format: OutputFormat) -> crate::CliResult<()> {
    let realms: Vec<RealmDisplay> = client.get("/admin/realms").await?;
    output(&realms, format)
}

/// Gets a realm by name.
async fn get_realm(client: &ApiClient, name: &str, format: OutputFormat) -> crate::CliResult<()> {
    let realm: RealmDisplay = client.get(&format!("/admin/realms/{}", name)).await?;
    output_single(&realm, format)
}

/// Creates a new realm.
async fn create_realm(
    client: &ApiClient,
    name: &str,
    display_name: Option<&str>,
    enabled: bool,
) -> crate::CliResult<()> {
    let request = CreateRealmRequest {
        name: name.to_string(),
        display_name: display_name.map(|s| s.to_string()),
        enabled,
    };

    client.post_no_response("/admin/realms", &request).await?;
    success(&format!("Realm '{}' created successfully", name));
    Ok(())
}

/// Updates a realm.
async fn update_realm(
    client: &ApiClient,
    name: &str,
    display_name: Option<&str>,
    enabled: Option<bool>,
) -> crate::CliResult<()> {
    // First get the current realm
    let mut realm: serde_json::Value = client.get(&format!("/admin/realms/{}", name)).await?;

    // Update fields
    if let Some(dn) = display_name {
        realm["display_name"] = serde_json::Value::String(dn.to_string());
    }
    if let Some(e) = enabled {
        realm["enabled"] = serde_json::Value::Bool(e);
    }

    client.put(&format!("/admin/realms/{}", name), &realm).await?;
    success(&format!("Realm '{}' updated successfully", name));
    Ok(())
}

/// Deletes a realm.
async fn delete_realm(client: &ApiClient, name: &str, force: bool) -> crate::CliResult<()> {
    if !force {
        if !confirm(&format!("Are you sure you want to delete realm '{}'?", name))? {
            error("Operation cancelled");
            return Ok(());
        }
    }

    client.delete(&format!("/admin/realms/{}", name)).await?;
    success(&format!("Realm '{}' deleted successfully", name));
    Ok(())
}
