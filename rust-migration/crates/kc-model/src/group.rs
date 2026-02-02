//! Group domain model.
//!
//! Groups provide a way to organize users and assign roles
//! to multiple users at once. Groups can be hierarchical.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Keycloak group.
///
/// Groups allow organizing users into logical units and assigning
/// roles to all members of a group. Groups can have a hierarchical
/// structure (parent-child relationships).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// Group name.
    pub name: String,
    /// Group description.
    pub description: Option<String>,

    // === Hierarchy ===
    /// Realm this group belongs to.
    pub realm_id: Uuid,
    /// Parent group ID (None for top-level groups).
    pub parent_id: Option<Uuid>,

    // === Timestamps ===
    /// When the group was created.
    pub created_at: DateTime<Utc>,
    /// When the group was last updated.
    pub updated_at: DateTime<Utc>,

    // === Custom Attributes ===
    /// Custom group attributes.
    pub attributes: HashMap<String, Vec<String>>,

    // === Role Mappings ===
    /// Realm roles assigned to this group.
    pub realm_roles: Vec<Uuid>,
    /// Client roles assigned to this group (`client_id` -> `role_ids`).
    pub client_roles: HashMap<Uuid, Vec<Uuid>>,
}

impl Group {
    /// Creates a new top-level group.
    #[must_use]
    pub fn new(realm_id: Uuid, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: None,
            realm_id,
            parent_id: None,
            created_at: now,
            updated_at: now,
            attributes: HashMap::new(),
            realm_roles: Vec::new(),
            client_roles: HashMap::new(),
        }
    }

    /// Creates a new child group.
    #[must_use]
    pub fn new_child(realm_id: Uuid, parent_id: Uuid, name: impl Into<String>) -> Self {
        let mut group = Self::new(realm_id, name);
        group.parent_id = Some(parent_id);
        group
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Adds a realm role to the group.
    #[must_use]
    pub fn with_realm_role(mut self, role_id: Uuid) -> Self {
        self.realm_roles.push(role_id);
        self
    }

    /// Adds a client role to the group.
    #[must_use]
    pub fn with_client_role(mut self, client_id: Uuid, role_id: Uuid) -> Self {
        self.client_roles
            .entry(client_id)
            .or_default()
            .push(role_id);
        self
    }

    /// Checks if this is a top-level group.
    #[must_use]
    pub const fn is_top_level(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Checks if this group has a specific realm role.
    #[must_use]
    pub fn has_realm_role(&self, role_id: Uuid) -> bool {
        self.realm_roles.contains(&role_id)
    }

    /// Checks if this group has a specific client role.
    #[must_use]
    pub fn has_client_role(&self, client_id: Uuid, role_id: Uuid) -> bool {
        self.client_roles
            .get(&client_id)
            .is_some_and(|roles| roles.contains(&role_id))
    }

    /// Gets the path from root to this group.
    ///
    /// Note: This only returns the immediate path component.
    /// Full path resolution requires access to parent groups.
    #[must_use]
    pub fn path_component(&self) -> String {
        format!("/{}", self.name)
    }

    /// Sets an attribute value.
    pub fn set_attribute(&mut self, name: impl Into<String>, values: Vec<String>) {
        self.attributes.insert(name.into(), values);
    }

    /// Gets an attribute value.
    #[must_use]
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }

    /// Gets the first value of an attribute.
    #[must_use]
    pub fn get_first_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
}

/// Helper struct for building group hierarchies.
#[derive(Debug, Clone)]
pub struct GroupPath {
    /// Path segments from root to leaf.
    pub segments: Vec<String>,
}

impl GroupPath {
    /// Parses a group path string (e.g., "/parent/child/grandchild").
    #[must_use]
    pub fn parse(path: &str) -> Self {
        let segments: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Self { segments }
    }

    /// Returns the path as a string.
    #[must_use]
    pub fn to_path_string(&self) -> String {
        if self.segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }

    /// Returns the parent path.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.segments.len() <= 1 {
            None
        } else {
            Some(Self {
                segments: self.segments[..self.segments.len() - 1].to_vec(),
            })
        }
    }

    /// Returns the leaf (last segment).
    #[must_use]
    pub fn leaf(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// Returns the depth (number of segments).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.segments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_group_creation() {
        let realm_id = Uuid::now_v7();
        let group = Group::new(realm_id, "admins");

        assert_eq!(group.name, "admins");
        assert!(group.is_top_level());
        assert_eq!(group.path_component(), "/admins");
    }

    #[test]
    fn child_group_creation() {
        let realm_id = Uuid::now_v7();
        let parent_id = Uuid::now_v7();
        let group = Group::new_child(realm_id, parent_id, "developers");

        assert_eq!(group.name, "developers");
        assert!(!group.is_top_level());
        assert_eq!(group.parent_id, Some(parent_id));
    }

    #[test]
    fn role_mappings() {
        let realm_id = Uuid::now_v7();
        let role_id = Uuid::now_v7();
        let client_id = Uuid::now_v7();
        let client_role_id = Uuid::now_v7();

        let group = Group::new(realm_id, "team")
            .with_realm_role(role_id)
            .with_client_role(client_id, client_role_id);

        assert!(group.has_realm_role(role_id));
        assert!(group.has_client_role(client_id, client_role_id));
        assert!(!group.has_realm_role(Uuid::now_v7()));
    }

    #[test]
    fn group_path_parsing() {
        let path = GroupPath::parse("/org/team/subteam");

        assert_eq!(path.segments, vec!["org", "team", "subteam"]);
        assert_eq!(path.to_path_string(), "/org/team/subteam");
        assert_eq!(path.leaf(), Some("subteam"));
        assert_eq!(path.depth(), 3);

        let parent = path.parent().unwrap();
        assert_eq!(parent.to_path_string(), "/org/team");
    }

    #[test]
    fn group_attributes() {
        let realm_id = Uuid::now_v7();
        let mut group = Group::new(realm_id, "team");

        group.set_attribute("department", vec!["Engineering".to_string()]);

        assert_eq!(group.get_first_attribute("department"), Some("Engineering"));
        assert_eq!(group.get_attribute("missing"), None);
    }
}
