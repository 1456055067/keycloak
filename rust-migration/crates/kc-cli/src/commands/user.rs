//! User management commands.

use serde::{Deserialize, Serialize};
use tabled::Tabled;

use crate::cli::UserCommand;
use crate::config::OutputFormat;
use crate::output::{confirm, error, output, output_single, prompt_password, success};
use crate::CliConfig;

use super::ApiClient;

/// User representation for display.
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct UserDisplay {
    /// User ID.
    pub id: String,
    /// Username.
    pub username: String,
    /// Email address.
    #[serde(default)]
    pub email: String,
    /// First name.
    #[tabled(rename = "First Name")]
    #[serde(default)]
    pub first_name: String,
    /// Last name.
    #[tabled(rename = "Last Name")]
    #[serde(default)]
    pub last_name: String,
    /// Whether the user is enabled.
    pub enabled: bool,
}

/// Create user request.
#[derive(Debug, Serialize)]
struct CreateUserRequest {
    username: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: bool,
}

/// Runs a user command.
pub async fn run_user(
    cmd: UserCommand,
    config: &CliConfig,
    server: Option<&str>,
    realm_arg: Option<&str>,
    output_format: OutputFormat,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    match cmd {
        UserCommand::List {
            realm,
            search,
            username,
            email,
            max,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            list_users(&client, &realm, search, username, email, max, output_format).await
        }
        UserCommand::Get { id, realm } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            get_user(&client, &realm, &id, output_format).await
        }
        UserCommand::Create {
            username,
            realm,
            email,
            first_name,
            last_name,
            enabled,
            password,
            temporary_password,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            create_user(
                &client,
                &realm,
                &username,
                email.as_deref(),
                first_name.as_deref(),
                last_name.as_deref(),
                enabled,
                password.as_deref(),
                temporary_password,
            )
            .await
        }
        UserCommand::Update {
            id,
            realm,
            email,
            first_name,
            last_name,
            enabled,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            update_user(
                &client,
                &realm,
                &id,
                email.as_deref(),
                first_name.as_deref(),
                last_name.as_deref(),
                enabled,
            )
            .await
        }
        UserCommand::Delete { id, realm, force } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            delete_user(&client, &realm, &id, force).await
        }
        UserCommand::SetPassword {
            id,
            realm,
            password,
            temporary,
        } => {
            let realm = get_realm(config, realm.as_deref().or(realm_arg))?;
            set_password(&client, &realm, &id, password.as_deref(), temporary).await
        }
    }
}

/// Gets the effective realm.
fn get_realm(config: &CliConfig, realm_arg: Option<&str>) -> crate::CliResult<String> {
    config
        .effective_realm(realm_arg)
        .ok_or_else(|| crate::CliError::InvalidArgument("realm is required".to_string()))
}

/// Lists users in a realm.
async fn list_users(
    client: &ApiClient,
    realm: &str,
    search: Option<String>,
    username: Option<String>,
    email: Option<String>,
    max: u32,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let mut query = vec![format!("max={}", max)];

    if let Some(s) = search {
        query.push(format!("search={}", urlencoding::encode(&s)));
    }
    if let Some(u) = username {
        query.push(format!("username={}", urlencoding::encode(&u)));
    }
    if let Some(e) = email {
        query.push(format!("email={}", urlencoding::encode(&e)));
    }

    let path = format!("/admin/realms/{}/users?{}", realm, query.join("&"));
    let users: Vec<UserDisplay> = client.get(&path).await?;
    output(&users, format)
}

/// Gets a user by ID.
async fn get_user(
    client: &ApiClient,
    realm: &str,
    id: &str,
    format: OutputFormat,
) -> crate::CliResult<()> {
    let user: UserDisplay = client
        .get(&format!("/admin/realms/{}/users/{}", realm, id))
        .await?;
    output_single(&user, format)
}

/// Creates a new user.
#[allow(clippy::too_many_arguments)]
async fn create_user(
    client: &ApiClient,
    realm: &str,
    username: &str,
    email: Option<&str>,
    first_name: Option<&str>,
    last_name: Option<&str>,
    enabled: bool,
    password: Option<&str>,
    temporary_password: bool,
) -> crate::CliResult<()> {
    let request = CreateUserRequest {
        username: username.to_string(),
        email: email.map(|s| s.to_string()),
        first_name: first_name.map(|s| s.to_string()),
        last_name: last_name.map(|s| s.to_string()),
        enabled,
    };

    // Create user
    client
        .post_no_response(&format!("/admin/realms/{}/users", realm), &request)
        .await?;

    success(&format!("User '{}' created successfully", username));

    // Set password if provided
    let pwd = if let Some(p) = password {
        p.to_string()
    } else {
        // Prompt for password
        let p = prompt_password("Enter password: ")?;
        let confirm_pwd = prompt_password("Confirm password: ")?;
        if p != confirm_pwd {
            return Err(crate::CliError::Validation("Passwords do not match".to_string()));
        }
        p
    };

    // Find the user ID
    let users: Vec<UserDisplay> = client
        .get(&format!(
            "/admin/realms/{}/users?username={}",
            realm,
            urlencoding::encode(username)
        ))
        .await?;

    if let Some(user) = users.first() {
        set_user_password(client, realm, &user.id, &pwd, temporary_password).await?;
    }

    Ok(())
}

/// Updates a user.
async fn update_user(
    client: &ApiClient,
    realm: &str,
    id: &str,
    email: Option<&str>,
    first_name: Option<&str>,
    last_name: Option<&str>,
    enabled: Option<bool>,
) -> crate::CliResult<()> {
    // First get the current user
    let mut user: serde_json::Value = client
        .get(&format!("/admin/realms/{}/users/{}", realm, id))
        .await?;

    // Update fields
    if let Some(e) = email {
        user["email"] = serde_json::Value::String(e.to_string());
    }
    if let Some(fn_) = first_name {
        user["first_name"] = serde_json::Value::String(fn_.to_string());
    }
    if let Some(ln) = last_name {
        user["last_name"] = serde_json::Value::String(ln.to_string());
    }
    if let Some(e) = enabled {
        user["enabled"] = serde_json::Value::Bool(e);
    }

    client
        .put(&format!("/admin/realms/{}/users/{}", realm, id), &user)
        .await?;
    success(&format!("User '{}' updated successfully", id));
    Ok(())
}

/// Deletes a user.
async fn delete_user(client: &ApiClient, realm: &str, id: &str, force: bool) -> crate::CliResult<()> {
    if !force {
        if !confirm(&format!("Are you sure you want to delete user '{}'?", id))? {
            error("Operation cancelled");
            return Ok(());
        }
    }

    client
        .delete(&format!("/admin/realms/{}/users/{}", realm, id))
        .await?;
    success(&format!("User '{}' deleted successfully", id));
    Ok(())
}

/// Sets a user's password.
async fn set_password(
    client: &ApiClient,
    realm: &str,
    id: &str,
    password: Option<&str>,
    temporary: bool,
) -> crate::CliResult<()> {
    let pwd = if let Some(p) = password {
        p.to_string()
    } else {
        let p = prompt_password("Enter new password: ")?;
        let confirm_pwd = prompt_password("Confirm password: ")?;
        if p != confirm_pwd {
            return Err(crate::CliError::Validation("Passwords do not match".to_string()));
        }
        p
    };

    set_user_password(client, realm, id, &pwd, temporary).await?;
    success(&format!("Password for user '{}' set successfully", id));
    Ok(())
}

/// Internal helper to set user password.
async fn set_user_password(
    client: &ApiClient,
    realm: &str,
    user_id: &str,
    password: &str,
    temporary: bool,
) -> crate::CliResult<()> {
    #[derive(Serialize)]
    struct PasswordRequest {
        #[serde(rename = "type")]
        type_: String,
        value: String,
        temporary: bool,
    }

    let request = PasswordRequest {
        type_: "password".to_string(),
        value: password.to_string(),
        temporary,
    };

    client
        .put(
            &format!("/admin/realms/{}/users/{}/reset-password", realm, user_id),
            &request,
        )
        .await
}
