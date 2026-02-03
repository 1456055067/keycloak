//! Client management commands.

use serde::{Deserialize, Serialize};
use tabled::Tabled;

use crate::cli::ClientCommand;
use crate::config::OutputFormat;
use crate::output::{confirm, error, output, output_single, success};
use crate::CliConfig;

use super::ApiClient;

/// Client representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct ClientDisplay {
    /// Internal ID.
    pub id: String,
    /// Client ID.
    #[tabled(rename = "Client ID")]
    pub client_id: String,
    /// Client name.
    #[serde(default)]
    pub name: String,
    /// Whether the client is enabled.
    pub enabled: bool,
    /// Whether it's a public client.
    #[tabled(rename = "Public")]
    #[serde(default)]
    pub public_client: bool,
}

/// Create client request.
#[derive(Debug, Serialize)]
struct CreateClientRequest {
    client_id: String,
    name: Option<String>,
    enabled: bool,
    public_client: bool,
    redirect_uris: Vec<String>,
    web_origins: Vec<String>,
}

/// Client secret response.
#[derive(Debug, Deserialize)]
struct ClientSecretResponse {
    value: String,
}

/// Runs a client command.
pub async fn run_client(
    cmd: ClientCommand,
    config: &CliConfig,
    server: Option<&str>,
    realm_arg: Option<&str>,
    output_format: OutputFormat,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    match cmd {
        ClientCommand::List { realm, search, max } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            list_clients(&client, &realm, search, max, output_format).await
        }
        ClientCommand::Get { client_id, realm } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            get_client(&client, &realm, &client_id, output_format).await
        }
        ClientCommand::Create {
            client_id,
            realm,
            name,
            public,
            redirect_uris,
            web_origins,
            enabled,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            create_client(
                &client,
                &realm,
                &client_id,
                name.as_deref(),
                public,
                redirect_uris.as_deref(),
                web_origins.as_deref(),
                enabled,
            )
            .await
        }
        ClientCommand::Delete {
            client_id,
            realm,
            force,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            delete_client(&client, &realm, &client_id, force).await
        }
        ClientCommand::GetSecret { client_id, realm } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            get_client_secret(&client, &realm, &client_id).await
        }
        ClientCommand::RegenerateSecret { client_id, realm } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            regenerate_client_secret(&client, &realm, &client_id).await
        }
    }
}

/// Gets the effective realm.
fn get_realm(config: &CliConfig, realm_arg: Option<&str>) -> crate::CliResult<String> {
    config
        .effective_realm(realm_arg)
        .ok_or_else(|| crate::CliError::InvalidArgument("realm is required".to_string()))
}

/// Finds a client by client_id and returns its internal ID.
async fn find_client_id(
    api_client: &ApiClient,
    realm: &str,
    client_id: &str,
) -> crate::CliResult<String> {
    let clients: Vec<ClientDisplay> = api_client
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

/// Lists clients in a realm.
async fn list_clients(
    client: &ApiClient,
    realm: &str,
    search: Option<String>,
    max: u32,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let mut query = vec![format!("max={}", max)];

    if let Some(s) = search {
        query.push(format!("search={}", urlencoding::encode(&s)));
    }

    let path = format!("/admin/realms/{}/clients?{}", realm, query.join("&"));
    let clients: Vec<ClientDisplay> = client.get(&path).await?;
    output(&clients, format)
}

/// Gets a client by client_id.
async fn get_client(
    client: &ApiClient,
    realm: &str,
    client_id: &str,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let internal_id = find_client_id(client, realm, client_id).await?;
    let c: ClientDisplay = client
        .get(&format!("/admin/realms/{}/clients/{}", realm, internal_id))
        .await?;
    output_single(&c, format)
}

/// Creates a new client.
#[allow(clippy::too_many_arguments)]
async fn create_client(
    client: &ApiClient,
    realm: &str,
    client_id: &str,
    name: Option<&str>,
    public: bool,
    redirect_uris: Option<&str>,
    web_origins: Option<&str>,
    enabled: bool,
) -> crate::CliResult<()> {
    let request = CreateClientRequest {
        client_id: client_id.to_string(),
        name: name.map(|s| s.to_string()),
        enabled,
        public_client: public,
        redirect_uris: redirect_uris
            .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
            .unwrap_or_default(),
        web_origins: web_origins
            .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
            .unwrap_or_default(),
    };

    client
        .post_no_response(&format!("/admin/realms/{}/clients", realm), &request)
        .await?;
    success(&format!("Client '{}' created successfully", client_id));

    // If not public, get and display the secret
    if !public {
        if let Ok(internal_id) = find_client_id(client, realm, client_id).await {
            if let Ok(secret) = get_secret(client, realm, &internal_id).await {
                println!("Client secret: {}", secret);
            }
        }
    }

    Ok(())
}

/// Deletes a client.
async fn delete_client(
    client: &ApiClient,
    realm: &str,
    client_id: &str,
    force: bool,
) -> crate::CliResult<()> {
    if !force {
        if !confirm(&format!(
            "Are you sure you want to delete client '{}'?",
            client_id
        ))?
        {
            error("Operation cancelled");
            return Ok(());
        }
    }

    let internal_id = find_client_id(client, realm, client_id).await?;
    client
        .delete(&format!("/admin/realms/{}/clients/{}", realm, internal_id))
        .await?;
    success(&format!("Client '{}' deleted successfully", client_id));
    Ok(())
}

/// Gets the client secret.
async fn get_client_secret(client: &ApiClient, realm: &str, client_id: &str) -> crate::CliResult<()> {
    let internal_id = find_client_id(client, realm, client_id).await?;
    let secret = get_secret(client, realm, &internal_id).await?;
    println!("{}", secret);
    Ok(())
}

/// Regenerates the client secret.
async fn regenerate_client_secret(
    client: &ApiClient,
    realm: &str,
    client_id: &str,
) -> crate::CliResult<()> {
    let internal_id = find_client_id(client, realm, client_id).await?;

    let response: ClientSecretResponse = client
        .post(
            &format!(
                "/admin/realms/{}/clients/{}/client-secret",
                realm, internal_id
            ),
            &serde_json::Value::Null,
        )
        .await?;

    success(&format!("Client secret regenerated for '{}'", client_id));
    println!("New secret: {}", response.value);
    Ok(())
}

/// Internal helper to get client secret.
async fn get_secret(client: &ApiClient, realm: &str, internal_id: &str) -> crate::CliResult<String> {
    let response: ClientSecretResponse = client
        .get(&format!(
            "/admin/realms/{}/clients/{}/client-secret",
            realm, internal_id
        ))
        .await?;
    Ok(response.value)
}
