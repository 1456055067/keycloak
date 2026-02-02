//! Group DTOs for the Admin API.

use std::collections::HashMap;

use chrono::Utc;
use kc_model::Group;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create a new group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    /// Group name (required, unique within same level).
    pub name: String,
    /// Group description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom group attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
}

impl CreateGroupRequest {
    /// Converts this request to a top-level group.
    #[must_use]
    pub fn into_group(self, realm_id: Uuid) -> Group {
        let mut group = Group::new(realm_id, self.name);
        group.description = self.description;
        group.attributes = self.attributes;
        group
    }

    /// Converts this request to a child group.
    #[must_use]
    pub fn into_child_group(self, realm_id: Uuid, parent_id: Uuid) -> Group {
        let mut group = Group::new_child(realm_id, parent_id, self.name);
        group.description = self.description;
        group.attributes = self.attributes;
        group
    }
}

/// Request to update a group.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    /// Group name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom group attributes (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateGroupRequest {
    /// Applies this update to an existing group.
    pub fn apply_to(&self, group: &mut Group) {
        if let Some(ref v) = self.name {
            group.name = v.clone();
        }
        if let Some(ref v) = self.description {
            group.description = Some(v.clone());
        }
        if let Some(ref v) = self.attributes {
            group.attributes = v.clone();
        }
        group.updated_at = Utc::now();
    }
}

/// Full group representation for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRepresentation {
    /// Unique identifier.
    pub id: Uuid,
    /// Group name.
    pub name: String,
    /// Group path (e.g., "/parent/child").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Group description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parent group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    /// Custom group attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
    /// Realm roles assigned to this group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_roles: Vec<String>,
    /// Client roles assigned to this group (client_id -> role names).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_roles: HashMap<String, Vec<String>>,
    /// Child groups (for hierarchical representation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_groups: Vec<GroupRepresentation>,
}

impl From<Group> for GroupRepresentation {
    fn from(group: Group) -> Self {
        Self {
            id: group.id,
            name: group.name,
            path: None, // Path is computed separately
            description: group.description,
            parent_id: group.parent_id,
            attributes: group.attributes,
            realm_roles: Vec::new(), // Role names need separate lookup
            client_roles: HashMap::new(),
            sub_groups: Vec::new(), // Children loaded separately
        }
    }
}

impl GroupRepresentation {
    /// Sets the computed path.
    #[must_use]
    pub fn with_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    /// Adds a child group.
    pub fn add_child(&mut self, child: GroupRepresentation) {
        self.sub_groups.push(child);
    }
}

/// Query parameters for group search.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSearchParams {
    /// Search string (matches group name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Filter by exact name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<bool>,
    /// Filter to top-level groups only.
    #[serde(default)]
    pub top_level_only: bool,
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

impl GroupSearchParams {
    /// Converts to storage search criteria.
    #[must_use]
    pub fn into_criteria(self) -> kc_storage::group::GroupSearchCriteria {
        let mut criteria = if self.top_level_only {
            kc_storage::group::GroupSearchCriteria::top_level()
        } else {
            kc_storage::group::GroupSearchCriteria::new()
        };

        if let Some(s) = self.search {
            if self.exact.unwrap_or(false) {
                criteria = criteria.name(s);
            } else {
                criteria = criteria.search(s);
            }
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

/// Response for group member count.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberCount {
    /// Number of members in the group.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_group_request_to_group() {
        let realm_id = Uuid::now_v7();
        let req = CreateGroupRequest {
            name: "engineering".to_string(),
            description: Some("Engineering team".to_string()),
            attributes: HashMap::new(),
        };

        let group = req.into_group(realm_id);
        assert_eq!(group.name, "engineering");
        assert_eq!(group.description, Some("Engineering team".to_string()));
        assert!(group.is_top_level());
    }

    #[test]
    fn create_group_request_to_child_group() {
        let realm_id = Uuid::now_v7();
        let parent_id = Uuid::now_v7();
        let req = CreateGroupRequest {
            name: "backend".to_string(),
            description: None,
            attributes: HashMap::new(),
        };

        let group = req.into_child_group(realm_id, parent_id);
        assert_eq!(group.name, "backend");
        assert!(!group.is_top_level());
        assert_eq!(group.parent_id, Some(parent_id));
    }

    #[test]
    fn update_group_request_applies() {
        let realm_id = Uuid::now_v7();
        let mut group = Group::new(realm_id, "team");

        let update = UpdateGroupRequest {
            name: Some("new-team".to_string()),
            description: Some("Updated description".to_string()),
            ..Default::default()
        };

        update.apply_to(&mut group);
        assert_eq!(group.name, "new-team");
        assert_eq!(group.description, Some("Updated description".to_string()));
    }

    #[test]
    fn group_representation_from_group() {
        let realm_id = Uuid::now_v7();
        let group = Group::new(realm_id, "admins")
            .with_description("Administrators");

        let repr = GroupRepresentation::from(group);
        assert_eq!(repr.name, "admins");
        assert_eq!(repr.description, Some("Administrators".to_string()));
        assert!(repr.path.is_none()); // Path computed separately
    }

    #[test]
    fn group_representation_with_path() {
        let realm_id = Uuid::now_v7();
        let group = Group::new(realm_id, "team");

        let repr = GroupRepresentation::from(group).with_path("/org/team".to_string());
        assert_eq!(repr.path, Some("/org/team".to_string()));
    }
}
