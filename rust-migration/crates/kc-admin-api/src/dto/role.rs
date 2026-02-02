//! Role DTOs for the Admin API.

use std::collections::HashMap;

use chrono::Utc;
use kc_model::Role;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create a new realm role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoleRequest {
    /// Role name (required, unique within scope).
    pub name: String,
    /// Role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom role attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
}

impl CreateRoleRequest {
    /// Converts this request to a realm role.
    #[must_use]
    pub fn into_realm_role(self, realm_id: Uuid) -> Role {
        let mut role = Role::new_realm_role(realm_id, self.name);
        role.description = self.description;
        role.attributes = self.attributes;
        role
    }

    /// Converts this request to a client role.
    #[must_use]
    pub fn into_client_role(self, realm_id: Uuid, client_id: Uuid) -> Role {
        let mut role = Role::new_client_role(realm_id, client_id, self.name);
        role.description = self.description;
        role.attributes = self.attributes;
        role
    }
}

/// Request to update a role.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoleRequest {
    /// Role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom role attributes (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateRoleRequest {
    /// Applies this update to an existing role.
    pub fn apply_to(&self, role: &mut Role) {
        if let Some(ref v) = self.name {
            role.name = v.clone();
        }
        if let Some(ref v) = self.description {
            role.description = Some(v.clone());
        }
        if let Some(ref v) = self.attributes {
            role.attributes = v.clone();
        }
        role.updated_at = Utc::now();
    }
}

/// Full role representation for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRepresentation {
    /// Unique identifier.
    pub id: Uuid,
    /// Role name.
    pub name: String,
    /// Role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this is a composite role.
    pub composite: bool,
    /// Whether this is a client role.
    pub client_role: bool,
    /// Container ID (realm ID for realm roles, client ID for client roles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<Uuid>,
    /// Custom role attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
}

impl From<Role> for RoleRepresentation {
    fn from(role: Role) -> Self {
        let composite = role.is_composite();
        let client_role = role.is_client_role();
        Self {
            id: role.id,
            name: role.name,
            description: role.description,
            composite,
            client_role,
            container_id: role.client_id,
            attributes: role.attributes,
        }
    }
}

/// Query parameters for role search.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleSearchParams {
    /// Search string (matches role name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Brief representation (excludes attributes).
    #[serde(default)]
    pub brief_representation: bool,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// Starting offset for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<usize>,
}

impl RoleSearchParams {
    /// Converts to storage search criteria for realm roles.
    #[must_use]
    pub fn into_realm_criteria(self) -> kc_storage::role::RoleSearchCriteria {
        let mut criteria = kc_storage::role::RoleSearchCriteria::realm_roles_only();
        if let Some(s) = self.search {
            criteria = criteria.search(s);
        }
        if let Some(m) = self.max {
            criteria = criteria.max_results(m);
        }
        if let Some(f) = self.first {
            criteria = criteria.offset(f);
        }
        criteria
    }

    /// Converts to storage search criteria for client roles.
    #[must_use]
    pub fn into_client_criteria(self, client_id: Uuid) -> kc_storage::role::RoleSearchCriteria {
        let mut criteria = kc_storage::role::RoleSearchCriteria::client_roles_only(client_id);
        if let Some(s) = self.search {
            criteria = criteria.search(s);
        }
        if let Some(m) = self.max {
            criteria = criteria.max_results(m);
        }
        if let Some(f) = self.first {
            criteria = criteria.offset(f);
        }
        criteria
    }
}

/// Request to add/remove composite roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeRolesRequest {
    /// Role representations to add/remove.
    pub roles: Vec<RoleRepresentation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_role_request_to_realm_role() {
        let realm_id = Uuid::now_v7();
        let req = CreateRoleRequest {
            name: "admin".to_string(),
            description: Some("Administrator role".to_string()),
            attributes: HashMap::new(),
        };

        let role = req.into_realm_role(realm_id);
        assert_eq!(role.name, "admin");
        assert_eq!(role.description, Some("Administrator role".to_string()));
        assert!(role.is_realm_role());
        assert!(!role.is_client_role());
    }

    #[test]
    fn create_role_request_to_client_role() {
        let realm_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let req = CreateRoleRequest {
            name: "manager".to_string(),
            description: None,
            attributes: HashMap::new(),
        };

        let role = req.into_client_role(realm_id, client_id);
        assert_eq!(role.name, "manager");
        assert!(role.is_client_role());
        assert_eq!(role.client_id, Some(client_id));
    }

    #[test]
    fn update_role_request_applies() {
        let realm_id = Uuid::now_v7();
        let mut role = Role::new_realm_role(realm_id, "user");

        let update = UpdateRoleRequest {
            name: Some("member".to_string()),
            description: Some("Member role".to_string()),
            ..Default::default()
        };

        update.apply_to(&mut role);
        assert_eq!(role.name, "member");
        assert_eq!(role.description, Some("Member role".to_string()));
    }

    #[test]
    fn role_representation_from_role() {
        let realm_id = Uuid::now_v7();
        let role = Role::new_realm_role(realm_id, "admin")
            .with_description("Administrator");

        let repr = RoleRepresentation::from(role);
        assert_eq!(repr.name, "admin");
        assert_eq!(repr.description, Some("Administrator".to_string()));
        assert!(!repr.composite);
        assert!(!repr.client_role);
    }

    #[test]
    fn role_representation_from_composite_role() {
        let realm_id = Uuid::now_v7();
        let sub_role_id = Uuid::now_v7();
        let role = Role::new_realm_role(realm_id, "super-admin")
            .with_composite(sub_role_id);

        let repr = RoleRepresentation::from(role);
        assert!(repr.composite);
    }
}
