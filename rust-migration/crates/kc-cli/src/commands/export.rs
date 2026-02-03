//! Export command implementation.

use serde::{Deserialize, Serialize};

use crate::cli::ExportArgs;
use crate::output::{info, success};
use crate::CliConfig;

use super::ApiClient;

/// Realm export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct RealmExport {
    /// Realm name.
    pub realm: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    pub enabled: bool,
    /// Users (if included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserExport>>,
    /// Clients (if included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ClientExport>>,
    /// Realm roles (if included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<RolesExport>,
    /// Groups (if included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupExport>>,
}

/// User export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserExport {
    /// Username.
    pub username: String,
    /// Email.
    pub email: Option<String>,
    /// First name.
    pub first_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Whether the user is enabled.
    pub enabled: bool,
    /// Email verified.
    pub email_verified: bool,
    /// Realm roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_roles: Option<Vec<String>>,
    /// Client roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_roles: Option<std::collections::HashMap<String, Vec<String>>>,
    /// Groups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

/// Client export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientExport {
    /// Client ID.
    pub client_id: String,
    /// Name.
    pub name: Option<String>,
    /// Whether the client is enabled.
    pub enabled: bool,
    /// Whether it's a public client.
    pub public_client: bool,
    /// Redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Web origins.
    pub web_origins: Vec<String>,
}

/// Roles export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct RolesExport {
    /// Realm roles.
    pub realm: Vec<RoleExport>,
    /// Client roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<std::collections::HashMap<String, Vec<RoleExport>>>,
}

/// Role export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct RoleExport {
    /// Role name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Whether it's composite.
    pub composite: bool,
    /// Composite roles (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composites: Option<Vec<String>>,
}

/// Group export structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupExport {
    /// Group name.
    pub name: String,
    /// Path.
    pub path: String,
    /// Subgroups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subgroups: Option<Vec<GroupExport>>,
}

/// Runs the export command.
pub async fn run_export(
    args: ExportArgs,
    config: &CliConfig,
    server: Option<&str>,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    let realms_to_export = if let Some(realm) = &args.realm {
        vec![realm.clone()]
    } else {
        // Get all realms
        #[derive(Deserialize)]
        struct RealmInfo {
            name: String,
        }
        let realms: Vec<RealmInfo> = client.get("/admin/realms").await?;
        realms.into_iter().map(|r| r.name).collect()
    };

    let mut exports = Vec::new();

    for realm in &realms_to_export {
        info(&format!("Exporting realm '{}'...", realm));
        let export = export_realm(&client, realm, &args).await?;
        exports.push(export);
    }

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&exports)?;

    // Output
    if let Some(file) = &args.file {
        std::fs::write(file, &json)?;
        success(&format!("Exported {} realm(s) to '{}'", exports.len(), file));
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Exports a single realm.
async fn export_realm(
    client: &ApiClient,
    realm: &str,
    args: &ExportArgs,
) -> crate::CliResult<RealmExport> {
    // Get realm info
    #[derive(Deserialize)]
    struct RealmInfo {
        name: String,
        display_name: Option<String>,
        enabled: bool,
    }

    let realm_info: RealmInfo = client.get(&format!("/admin/realms/{}", realm)).await?;

    let mut export = RealmExport {
        realm: realm_info.name,
        display_name: realm_info.display_name,
        enabled: realm_info.enabled,
        users: None,
        clients: None,
        roles: None,
        groups: None,
    };

    // Export users
    if args.users {
        export.users = Some(export_users(client, realm).await?);
    }

    // Export clients
    if args.clients {
        export.clients = Some(export_clients(client, realm).await?);
    }

    // Export roles
    if args.roles {
        export.roles = Some(export_roles(client, realm).await?);
    }

    // Export groups
    if args.groups {
        export.groups = Some(export_groups(client, realm).await?);
    }

    Ok(export)
}

/// Exports users from a realm.
async fn export_users(client: &ApiClient, realm: &str) -> crate::CliResult<Vec<UserExport>> {
    #[derive(Deserialize)]
    struct User {
        username: String,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        enabled: bool,
        email_verified: Option<bool>,
    }

    let users: Vec<User> = client
        .get(&format!("/admin/realms/{}/users?max=10000", realm))
        .await?;

    Ok(users
        .into_iter()
        .map(|u| UserExport {
            username: u.username,
            email: u.email,
            first_name: u.first_name,
            last_name: u.last_name,
            enabled: u.enabled,
            email_verified: u.email_verified.unwrap_or(false),
            realm_roles: None,
            client_roles: None,
            groups: None,
        })
        .collect())
}

/// Exports clients from a realm.
async fn export_clients(client: &ApiClient, realm: &str) -> crate::CliResult<Vec<ClientExport>> {
    #[derive(Deserialize)]
    struct Client {
        client_id: String,
        name: Option<String>,
        enabled: bool,
        public_client: Option<bool>,
        redirect_uris: Option<Vec<String>>,
        web_origins: Option<Vec<String>>,
    }

    let clients: Vec<Client> = client
        .get(&format!("/admin/realms/{}/clients", realm))
        .await?;

    Ok(clients
        .into_iter()
        .map(|c| ClientExport {
            client_id: c.client_id,
            name: c.name,
            enabled: c.enabled,
            public_client: c.public_client.unwrap_or(false),
            redirect_uris: c.redirect_uris.unwrap_or_default(),
            web_origins: c.web_origins.unwrap_or_default(),
        })
        .collect())
}

/// Exports roles from a realm.
async fn export_roles(client: &ApiClient, realm: &str) -> crate::CliResult<RolesExport> {
    #[derive(Deserialize)]
    struct Role {
        name: String,
        description: Option<String>,
        composite: bool,
    }

    let realm_roles: Vec<Role> = client
        .get(&format!("/admin/realms/{}/roles", realm))
        .await?;

    let roles = RolesExport {
        realm: realm_roles
            .into_iter()
            .map(|r| RoleExport {
                name: r.name,
                description: r.description,
                composite: r.composite,
                composites: None,
            })
            .collect(),
        client: None, // TODO: Export client roles
    };

    Ok(roles)
}

/// Exports groups from a realm.
async fn export_groups(client: &ApiClient, realm: &str) -> crate::CliResult<Vec<GroupExport>> {
    #[derive(Deserialize)]
    struct Group {
        name: String,
        path: String,
        #[serde(rename = "subGroups")]
        sub_groups: Option<Vec<Group>>,
    }

    fn convert_group(g: Group) -> GroupExport {
        GroupExport {
            name: g.name,
            path: g.path,
            subgroups: g.sub_groups.map(|sg| sg.into_iter().map(convert_group).collect()),
        }
    }

    let groups: Vec<Group> = client
        .get(&format!("/admin/realms/{}/groups", realm))
        .await?;

    Ok(groups.into_iter().map(convert_group).collect())
}
