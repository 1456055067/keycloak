//! Group management commands.

use serde::{Deserialize, Serialize};
use tabled::Tabled;

use crate::cli::GroupCommand;
use crate::config::OutputFormat;
use crate::output::{confirm, error, output, success};
use crate::CliConfig;

use super::ApiClient;

/// Group representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct GroupDisplay {
    /// Group ID.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Path in the group hierarchy.
    pub path: String,
}

/// Group member representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct GroupMemberDisplay {
    /// User ID.
    pub id: String,
    /// Username.
    pub username: String,
    /// Email.
    #[serde(default)]
    pub email: String,
}

/// Create group request.
#[derive(Debug, Serialize)]
struct CreateGroupRequest {
    name: String,
}

/// Runs a group command.
pub async fn run_group(
    cmd: GroupCommand,
    config: &CliConfig,
    server: Option<&str>,
    realm_arg: Option<&str>,
    output_format: OutputFormat,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    match cmd {
        GroupCommand::List { realm, search } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            list_groups(&client, &realm, search, output_format).await
        }
        GroupCommand::Create { name, realm, parent } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            create_group(&client, &realm, &name, parent.as_deref()).await
        }
        GroupCommand::Delete { id, realm, force } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            delete_group(&client, &realm, &id, force).await
        }
        GroupCommand::Members { id, realm } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            list_members(&client, &realm, &id, output_format).await
        }
    }
}

/// Gets the effective realm.
fn get_realm(config: &CliConfig, realm_arg: Option<&str>) -> crate::CliResult<String> {
    config
        .effective_realm(realm_arg)
        .ok_or_else(|| crate::CliError::InvalidArgument("realm is required".to_string()))
}

/// Lists groups in a realm.
async fn list_groups(
    client: &ApiClient,
    realm: &str,
    search: Option<String>,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let path = if let Some(s) = search {
        format!(
            "/admin/realms/{}/groups?search={}",
            realm,
            urlencoding::encode(&s)
        )
    } else {
        format!("/admin/realms/{}/groups", realm)
    };

    let groups: Vec<GroupDisplay> = client.get(&path).await?;
    output(&groups, format)
}

/// Creates a group.
async fn create_group(
    client: &ApiClient,
    realm: &str,
    name: &str,
    parent_id: Option<&str>,
) -> crate::CliResult<()> {
    let request = CreateGroupRequest {
        name: name.to_string(),
    };

    let path = if let Some(pid) = parent_id {
        format!("/admin/realms/{}/groups/{}/children", realm, pid)
    } else {
        format!("/admin/realms/{}/groups", realm)
    };

    client.post_no_response(&path, &request).await?;
    success(&format!("Group '{}' created successfully", name));
    Ok(())
}

/// Deletes a group.
async fn delete_group(
    client: &ApiClient,
    realm: &str,
    id: &str,
    force: bool,
) -> crate::CliResult<()> {
    if !force {
        if !confirm(&format!("Are you sure you want to delete group '{}'?", id))? {
            error("Operation cancelled");
            return Ok(());
        }
    }

    client
        .delete(&format!("/admin/realms/{}/groups/{}", realm, id))
        .await?;
    success(&format!("Group '{}' deleted successfully", id));
    Ok(())
}

/// Lists group members.
async fn list_members(
    client: &ApiClient,
    realm: &str,
    group_id: &str,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let path = format!("/admin/realms/{}/groups/{}/members", realm, group_id);
    let members: Vec<GroupMemberDisplay> = client.get(&path).await?;
    output(&members, format)
}
