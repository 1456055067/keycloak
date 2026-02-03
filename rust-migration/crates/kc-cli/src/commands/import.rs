//! Import command implementation.

use crate::cli::ImportArgs;
use crate::output::{info, success, warning};
use crate::CliConfig;

use super::export::{ClientExport, GroupExport, RealmExport, RoleExport, UserExport};
use super::ApiClient;

/// Import statistics.
#[derive(Default)]
struct ImportStats {
    realms_created: u32,
    realms_skipped: u32,
    users_created: u32,
    users_skipped: u32,
    clients_created: u32,
    clients_skipped: u32,
    roles_created: u32,
    roles_skipped: u32,
    groups_created: u32,
    groups_skipped: u32,
}

/// Runs the import command.
pub async fn run_import(
    args: ImportArgs,
    config: &CliConfig,
    server: Option<&str>,
) -> crate::CliResult<()> {
    let client = ApiClient::new(config, server)?;

    // Read and parse the import file
    let content = std::fs::read_to_string(&args.file)?;
    let realms: Vec<RealmExport> = serde_json::from_str(&content)?;

    info(&format!(
        "Importing {} realm(s) from '{}'...",
        realms.len(),
        args.file
    ));

    let mut stats = ImportStats::default();

    for realm_export in realms {
        let realm_name = if let Some(target) = &args.realm {
            target.clone()
        } else {
            realm_export.realm.clone()
        };

        import_realm(&client, &realm_export, &realm_name, &args, &mut stats).await?;
    }

    // Print summary
    println!();
    success("Import complete!");
    println!("  Realms:  {} created, {} skipped", stats.realms_created, stats.realms_skipped);
    println!("  Users:   {} created, {} skipped", stats.users_created, stats.users_skipped);
    println!("  Clients: {} created, {} skipped", stats.clients_created, stats.clients_skipped);
    println!("  Roles:   {} created, {} skipped", stats.roles_created, stats.roles_skipped);
    println!("  Groups:  {} created, {} skipped", stats.groups_created, stats.groups_skipped);

    Ok(())
}

/// Imports a single realm.
async fn import_realm(
    client: &ApiClient,
    export: &RealmExport,
    realm_name: &str,
    args: &ImportArgs,
    stats: &mut ImportStats,
) -> crate::CliResult<()> {
    info(&format!("Processing realm '{}'...", realm_name));

    // Check if realm exists
    let realm_exists = client
        .get::<serde_json::Value>(&format!("/admin/realms/{}", realm_name))
        .await
        .is_ok();

    if realm_exists {
        if args.skip_existing {
            warning(&format!("Realm '{}' exists, skipping", realm_name));
            stats.realms_skipped += 1;
            return Ok(());
        } else if !args.overwrite {
            warning(&format!(
                "Realm '{}' exists, use --skip-existing or --overwrite",
                realm_name
            ));
            stats.realms_skipped += 1;
            return Ok(());
        }
        // Overwrite mode - update the realm
        let update = serde_json::json!({
            "display_name": export.display_name,
            "enabled": export.enabled
        });
        client
            .put(&format!("/admin/realms/{}", realm_name), &update)
            .await?;
    } else {
        // Create new realm
        let create = serde_json::json!({
            "name": realm_name,
            "display_name": export.display_name,
            "enabled": export.enabled
        });
        client.post_no_response("/admin/realms", &create).await?;
        stats.realms_created += 1;
    }

    // Import roles first (users may reference them)
    if let Some(roles) = &export.roles {
        for role in &roles.realm {
            import_role(client, realm_name, role, args, stats).await?;
        }
    }

    // Import groups
    if let Some(groups) = &export.groups {
        for group in groups {
            import_group(client, realm_name, group, None, args, stats).await?;
        }
    }

    // Import clients
    if let Some(clients) = &export.clients {
        for c in clients {
            import_client(client, realm_name, c, args, stats).await?;
        }
    }

    // Import users last
    if let Some(users) = &export.users {
        for user in users {
            import_user(client, realm_name, user, args, stats).await?;
        }
    }

    Ok(())
}

/// Imports a user.
async fn import_user(
    client: &ApiClient,
    realm: &str,
    user: &UserExport,
    args: &ImportArgs,
    stats: &mut ImportStats,
) -> crate::CliResult<()> {
    // Check if user exists
    let existing: Vec<serde_json::Value> = client
        .get(&format!(
            "/admin/realms/{}/users?username={}",
            realm,
            urlencoding::encode(&user.username)
        ))
        .await?;

    let user_exists = existing.iter().any(|u| {
        u.get("username")
            .and_then(|v| v.as_str())
            .map(|s| s == user.username)
            .unwrap_or(false)
    });

    if user_exists {
        if args.skip_existing {
            stats.users_skipped += 1;
            return Ok(());
        } else if !args.overwrite {
            stats.users_skipped += 1;
            return Ok(());
        }
        // TODO: Update user
        stats.users_skipped += 1;
    } else {
        let create = serde_json::json!({
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "enabled": user.enabled,
            "emailVerified": user.email_verified
        });
        client
            .post_no_response(&format!("/admin/realms/{}/users", realm), &create)
            .await?;
        stats.users_created += 1;
    }

    Ok(())
}

/// Imports a client.
async fn import_client(
    client: &ApiClient,
    realm: &str,
    c: &ClientExport,
    args: &ImportArgs,
    stats: &mut ImportStats,
) -> crate::CliResult<()> {
    // Check if client exists
    let existing: Vec<serde_json::Value> = client
        .get(&format!(
            "/admin/realms/{}/clients?clientId={}",
            realm,
            urlencoding::encode(&c.client_id)
        ))
        .await?;

    let client_exists = existing.iter().any(|cl| {
        cl.get("clientId")
            .and_then(|v| v.as_str())
            .map(|s| s == c.client_id)
            .unwrap_or(false)
    });

    if client_exists {
        if args.skip_existing {
            stats.clients_skipped += 1;
            return Ok(());
        } else if !args.overwrite {
            stats.clients_skipped += 1;
            return Ok(());
        }
        // TODO: Update client
        stats.clients_skipped += 1;
    } else {
        let create = serde_json::json!({
            "clientId": c.client_id,
            "name": c.name,
            "enabled": c.enabled,
            "publicClient": c.public_client,
            "redirectUris": c.redirect_uris,
            "webOrigins": c.web_origins
        });
        client
            .post_no_response(&format!("/admin/realms/{}/clients", realm), &create)
            .await?;
        stats.clients_created += 1;
    }

    Ok(())
}

/// Imports a role.
async fn import_role(
    client: &ApiClient,
    realm: &str,
    role: &RoleExport,
    args: &ImportArgs,
    stats: &mut ImportStats,
) -> crate::CliResult<()> {
    // Check if role exists
    let role_exists = client
        .get::<serde_json::Value>(&format!("/admin/realms/{}/roles/{}", realm, role.name))
        .await
        .is_ok();

    if role_exists {
        if args.skip_existing || !args.overwrite {
            stats.roles_skipped += 1;
            return Ok(());
        }
        // TODO: Update role
        stats.roles_skipped += 1;
    } else {
        let create = serde_json::json!({
            "name": role.name,
            "description": role.description
        });
        client
            .post_no_response(&format!("/admin/realms/{}/roles", realm), &create)
            .await?;
        stats.roles_created += 1;
    }

    Ok(())
}

/// Imports a group.
fn import_group<'a>(
    client: &'a ApiClient,
    realm: &'a str,
    group: &'a GroupExport,
    parent_id: Option<&'a str>,
    args: &'a ImportArgs,
    stats: &'a mut ImportStats,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::CliResult<()>> + Send + 'a>> {
    Box::pin(async move {
        // Check if group with this path exists
        let existing: Vec<serde_json::Value> = client
            .get(&format!(
                "/admin/realms/{}/groups?search={}",
                realm,
                urlencoding::encode(&group.name)
            ))
            .await?;

        let existing_group = existing.iter().find(|g| {
            g.get("path")
                .and_then(|v| v.as_str())
                .map(|s| s == group.path)
                .unwrap_or(false)
        });

        let group_id = if let Some(g) = existing_group {
            if args.skip_existing || !args.overwrite {
                stats.groups_skipped += 1;
                g.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else {
                // TODO: Update group
                stats.groups_skipped += 1;
                g.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
            }
        } else {
            let create = serde_json::json!({
                "name": group.name
            });

            let path = if let Some(pid) = parent_id {
                format!("/admin/realms/{}/groups/{}/children", realm, pid)
            } else {
                format!("/admin/realms/{}/groups", realm)
            };

            client.post_no_response(&path, &create).await?;
            stats.groups_created += 1;

            // Find the created group ID
            let groups: Vec<serde_json::Value> = client
                .get(&format!(
                    "/admin/realms/{}/groups?search={}",
                    realm,
                    urlencoding::encode(&group.name)
                ))
                .await?;

            groups
                .iter()
                .find(|g| {
                    g.get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s == group.path)
                        .unwrap_or(false)
                })
                .and_then(|g| g.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        };

        // Import subgroups
        if let (Some(subgroups), Some(gid)) = (&group.subgroups, group_id) {
            for subgroup in subgroups {
                import_group(client, realm, subgroup, Some(&gid), args, stats).await?;
            }
        }

        Ok(())
    })
}
