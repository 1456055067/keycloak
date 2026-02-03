//! Role management commands.

use serde::{Deserialize, Serialize};
use tabled::Tabled;

use crate::cli::RoleCommand;
use crate::config::OutputFormat;
use crate::output::{confirm, error, output, success};
use crate::CliConfig;

use super::ApiClient;

/// Role representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct RoleDisplay {
    /// Role ID.
    pub id: String,
    /// Role name.
    pub name: String,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Whether it's a composite role.
    #[serde(default)]
    pub composite: bool,
}

/// Create role request.
#[derive(Debug, Serialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
}

/// Runs a role command.
pub async fn run_role(
    cmd: RoleCommand,
    config: &CliConfig,
    server: Option<&str>,
    realm_arg: Option<&str>,
    output_format: OutputFormat,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    match cmd {
        RoleCommand::List { realm, client: client_id } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            list_roles(&client, &realm, client_id.as_deref(), output_format).await
        }
        RoleCommand::Create {
            name,
            realm,
            client: client_id,
            description,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            create_role(&client, &realm, &name, client_id.as_deref(), description.as_deref()).await
        }
        RoleCommand::Delete {
            name,
            realm,
            client: client_id,
            force,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            delete_role(&client, &realm, &name, client_id.as_deref(), force).await
        }
    }
}

/// Gets the effective realm.
fn get_realm(config: &CliConfig, realm_arg: Option<&str>) -> crate::CliResult<String> {
    config
        .effective_realm(realm_arg)
        .ok_or_else(|| crate::CliError::InvalidArgument("realm is required".to_string()))
}

/// Lists roles in a realm or client.
async fn list_roles(
    client: &ApiClient,
    realm: &str,
    client_id: Option<&str>,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let path = if let Some(cid) = client_id {
        // Find internal client ID first
        let internal_id = find_client_id(client, realm, cid).await?;
        format!("/admin/realms/{}/clients/{}/roles", realm, internal_id)
    } else {
        format!("/admin/realms/{}/roles", realm)
    };

    let roles: Vec<RoleDisplay> = client.get(&path).await?;
    output(&roles, format)
}

/// Creates a role.
async fn create_role(
    client: &ApiClient,
    realm: &str,
    name: &str,
    client_id: Option<&str>,
    description: Option<&str>,
) -> crate::CliResult<()> {
    let request = CreateRoleRequest {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
    };

    let path = if let Some(cid) = client_id {
        let internal_id = find_client_id(client, realm, cid).await?;
        format!("/admin/realms/{}/clients/{}/roles", realm, internal_id)
    } else {
        format!("/admin/realms/{}/roles", realm)
    };

    client.post_no_response(&path, &request).await?;

    if let Some(cid) = client_id {
        success(&format!("Client role '{}' created in client '{}'", name, cid));
    } else {
        success(&format!("Realm role '{}' created successfully", name));
    }
    Ok(())
}

/// Deletes a role.
async fn delete_role(
    client: &ApiClient,
    realm: &str,
    name: &str,
    client_id: Option<&str>,
    force: bool,
) -> crate::CliResult<()> {
    if !force {
        let msg = if let Some(cid) = client_id {
            format!(
                "Are you sure you want to delete client role '{}' from '{}'?",
                name, cid
            )
        } else {
            format!("Are you sure you want to delete realm role '{}'?", name)
        };

        if !confirm(&msg)? {
            error("Operation cancelled");
            return Ok(());
        }
    }

    let path = if let Some(cid) = client_id {
        let internal_id = find_client_id(client, realm, cid).await?;
        format!(
            "/admin/realms/{}/clients/{}/roles/{}",
            realm, internal_id, name
        )
    } else {
        format!("/admin/realms/{}/roles/{}", realm, name)
    };

    client.delete(&path).await?;
    success(&format!("Role '{}' deleted successfully", name));
    Ok(())
}

/// Finds a client by client_id and returns its internal ID.
async fn find_client_id(
    api_client: &ApiClient,
    realm: &str,
    client_id: &str,
) -> crate::CliResult<String> {
    #[derive(Deserialize)]
    struct ClientInfo {
        id: String,
        client_id: String,
    }

    let clients: Vec<ClientInfo> = api_client
        .get(&format!(
            "/admin/realms/{}/clients?clientId={}",
            realm,
            urlencoding::encode(client_id)
        ))
        .await?;

    clients
        .into_iter()
        .find(|c| c.client_id == client_id)
        .map(|c| c.id)
        .ok_or_else(|| crate::CliError::NotFound {
            resource_type: "Client".to_string(),
            id: client_id.to_string(),
        })
}
