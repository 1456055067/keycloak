//! Role domain model.
//!
//! Roles are used for role-based access control (RBAC).
//! They can be realm-level or client-level roles.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Keycloak role.
///
/// Roles represent permissions that can be assigned to users or groups.
/// They can be realm roles (apply across the realm) or client roles
/// (specific to a particular client application).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// Role name (unique within realm or client).
    pub name: String,
    /// Role description.
    pub description: Option<String>,

    // === Scope ===
    /// Realm this role belongs to.
    pub realm_id: Uuid,
    /// Client this role belongs to (None for realm roles).
    pub client_id: Option<Uuid>,

    // === Timestamps ===
    /// When the role was created.
    pub created_at: DateTime<Utc>,
    /// When the role was last updated.
    pub updated_at: DateTime<Utc>,

    // === Composite Roles ===
    /// Composite role IDs (roles that this role includes).
    pub composite_roles: Vec<Uuid>,

    // === Custom Attributes ===
    /// Custom role attributes.
    pub attributes: HashMap<String, Vec<String>>,
}

impl Role {
    /// Creates a new realm role.
    #[must_use]
    pub fn new_realm_role(realm_id: Uuid, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: None,
            realm_id,
            client_id: None,
            created_at: now,
            updated_at: now,
            composite_roles: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Creates a new client role.
    #[must_use]
    pub fn new_client_role(realm_id: Uuid, client_id: Uuid, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: None,
            realm_id,
            client_id: Some(client_id),
            created_at: now,
            updated_at: now,
            composite_roles: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Adds a composite role.
    #[must_use]
    pub fn with_composite(mut self, role_id: Uuid) -> Self {
        self.composite_roles.push(role_id);
        self
    }

    /// Checks if this is a realm role.
    #[must_use]
    pub const fn is_realm_role(&self) -> bool {
        self.client_id.is_none()
    }

    /// Checks if this is a client role.
    #[must_use]
    pub const fn is_client_role(&self) -> bool {
        self.client_id.is_some()
    }

    /// Checks if this is a composite role.
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        !self.composite_roles.is_empty()
    }

    /// Gets the full role name (`client_id.role_name` for client roles).
    #[must_use]
    pub fn full_name(&self, client_id_str: Option<&str>) -> String {
        match (&self.client_id, client_id_str) {
            (Some(_), Some(client)) => format!("{}.{}", client, self.name),
            _ => self.name.clone(),
        }
    }
}

/// Well-known realm role names.
pub mod realm_roles {
    /// Default role assigned to all users.
    pub const DEFAULT_ROLES: &str = "default-roles";
    /// Offline access role (for refresh tokens).
    pub const OFFLINE_ACCESS: &str = "offline_access";
    /// UMA authorization role.
    pub const UMA_AUTHORIZATION: &str = "uma_authorization";
}

/// Well-known client role names for realm-management client.
pub mod realm_management_roles {
    /// View realm settings.
    pub const VIEW_REALM: &str = "view-realm";
    /// Manage realm settings.
    pub const MANAGE_REALM: &str = "manage-realm";
    /// View users.
    pub const VIEW_USERS: &str = "view-users";
    /// Manage users.
    pub const MANAGE_USERS: &str = "manage-users";
    /// View clients.
    pub const VIEW_CLIENTS: &str = "view-clients";
    /// Manage clients.
    pub const MANAGE_CLIENTS: &str = "manage-clients";
    /// View events.
    pub const VIEW_EVENTS: &str = "view-events";
    /// Manage events.
    pub const MANAGE_EVENTS: &str = "manage-events";
    /// View identity providers.
    pub const VIEW_IDENTITY_PROVIDERS: &str = "view-identity-providers";
    /// Manage identity providers.
    pub const MANAGE_IDENTITY_PROVIDERS: &str = "manage-identity-providers";
    /// View authorization.
    pub const VIEW_AUTHORIZATION: &str = "view-authorization";
    /// Manage authorization.
    pub const MANAGE_AUTHORIZATION: &str = "manage-authorization";
    /// Query users.
    pub const QUERY_USERS: &str = "query-users";
    /// Query clients.
    pub const QUERY_CLIENTS: &str = "query-clients";
    /// Query groups.
    pub const QUERY_GROUPS: &str = "query-groups";
    /// Query realms.
    pub const QUERY_REALMS: &str = "query-realms";
    /// Impersonate users.
    pub const IMPERSONATION: &str = "impersonation";
    /// Realm admin (all permissions).
    pub const REALM_ADMIN: &str = "realm-admin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_role_creation() {
        let realm_id = Uuid::now_v7();
        let role = Role::new_realm_role(realm_id, "admin");

        assert_eq!(role.name, "admin");
        assert!(role.is_realm_role());
        assert!(!role.is_client_role());
        assert!(!role.is_composite());
    }

    #[test]
    fn client_role_creation() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let role = Role::new_client_role(realm_id, client_id, "manager");

        assert_eq!(role.name, "manager");
        assert!(!role.is_realm_role());
        assert!(role.is_client_role());
        assert_eq!(role.client_id, Some(client_id));
    }

    #[test]
    fn composite_role() {
        let realm_id = Uuid::now_v7();
        let sub_role_id = Uuid::now_v7();

        let role = Role::new_realm_role(realm_id, "super-admin").with_composite(sub_role_id);

        assert!(role.is_composite());
        assert!(role.composite_roles.contains(&sub_role_id));
    }

    #[test]
    fn full_name_formatting() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();

        let realm_role = Role::new_realm_role(realm_id, "admin");
        assert_eq!(realm_role.full_name(None), "admin");

        let client_role = Role::new_client_role(realm_id, client_id, "manager");
        assert_eq!(client_role.full_name(Some("my-app")), "my-app.manager");
    }
}
