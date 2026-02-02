//! LDAP-specific attribute mappers.
//!
//! Maps LDAP attributes to Keycloak user model.

use std::collections::HashMap;

use kc_federation::mapper::{AttributeMapper, FederationMapper, GroupMapper, MapperConfig, RoleMapper};
use kc_federation::FederationResult;
use kc_model::User;
use uuid::Uuid;

use crate::config::LdapConfig;
use crate::search::LdapEntry;

// ============================================================================
// LDAP User Attribute Mapper
// ============================================================================

/// Maps LDAP user attributes to Keycloak user model.
#[derive(Debug, Clone)]
pub struct LdapUserAttributeMapper {
    config: LdapConfig,
}

impl LdapUserAttributeMapper {
    /// Creates a new LDAP user attribute mapper.
    #[must_use]
    pub const fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    /// Maps an LDAP entry to a Keycloak User.
    #[must_use]
    pub fn map_to_user(&self, realm_id: Uuid, entry: &LdapEntry, provider_id: &str) -> User {
        let username = entry
            .get_attr(self.config.username_attribute.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut user = User::new(realm_id, &username);

        // Set basic attributes
        user.email = entry.get_attr(&self.config.email_attribute).map(String::from);
        user.first_name = entry
            .get_attr(&self.config.first_name_attribute)
            .map(String::from);
        user.last_name = entry
            .get_attr(&self.config.last_name_attribute)
            .map(String::from);

        // Set federation link
        user.federation_link = Some(provider_id.to_string());

        // Store external ID in attributes for reference
        if let Some(external_id) = entry.external_id(&self.config.uuid_attribute) {
            user.attributes
                .insert("LDAP_ID".to_string(), vec![external_id]);
        }

        // Store DN for authentication
        user.attributes
            .insert("LDAP_ENTRY_DN".to_string(), vec![entry.dn.clone()]);

        user
    }

    /// Updates an existing user with LDAP data.
    pub fn update_user(&self, user: &mut User, entry: &LdapEntry) {
        // Update email
        if let Some(email) = entry.get_attr(&self.config.email_attribute) {
            user.email = Some(email.to_string());
        }

        // Update names
        if let Some(first) = entry.get_attr(&self.config.first_name_attribute) {
            user.first_name = Some(first.to_string());
        }
        if let Some(last) = entry.get_attr(&self.config.last_name_attribute) {
            user.last_name = Some(last.to_string());
        }
    }

    /// Maps Keycloak user attributes to LDAP format.
    #[must_use]
    pub fn map_to_ldap(&self, user: &User) -> HashMap<String, Vec<String>> {
        let mut attrs = HashMap::new();

        // Username
        attrs.insert(
            self.config.username_attribute.as_str().to_string(),
            vec![user.username.clone()],
        );

        // Email
        if let Some(email) = &user.email {
            attrs.insert(self.config.email_attribute.clone(), vec![email.clone()]);
        }

        // Names
        if let Some(first) = &user.first_name {
            attrs.insert(
                self.config.first_name_attribute.clone(),
                vec![first.clone()],
            );
        }
        if let Some(last) = &user.last_name {
            attrs.insert(self.config.last_name_attribute.clone(), vec![last.clone()]);
        }

        // Full name (cn)
        if let Some(full_name) = user.full_name() {
            attrs.insert("cn".to_string(), vec![full_name]);
        }

        attrs
    }
}

impl FederationMapper for LdapUserAttributeMapper {
    fn mapper_type(&self) -> &'static str {
        "ldap-user-attribute-mapper"
    }

    fn display_name(&self) -> &'static str {
        "LDAP User Attribute Mapper"
    }

    fn help_text(&self) -> &'static str {
        "Maps LDAP user attributes to Keycloak user model"
    }
}

impl AttributeMapper for LdapUserAttributeMapper {
    fn import_attributes(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        user: &mut User,
        _config: &MapperConfig,
    ) -> FederationResult<()> {
        // Email
        if let Some(values) = external_attributes.get(&self.config.email_attribute) {
            user.email = values.first().cloned();
        }

        // First name
        if let Some(values) = external_attributes.get(&self.config.first_name_attribute) {
            user.first_name = values.first().cloned();
        }

        // Last name
        if let Some(values) = external_attributes.get(&self.config.last_name_attribute) {
            user.last_name = values.first().cloned();
        }

        Ok(())
    }

    fn export_attributes(
        &self,
        user: &User,
        _config: &MapperConfig,
    ) -> FederationResult<HashMap<String, Vec<String>>> {
        Ok(self.map_to_ldap(user))
    }
}

// ============================================================================
// LDAP Group Mapper
// ============================================================================

/// Maps LDAP groups to Keycloak groups.
#[derive(Debug, Clone)]
pub struct LdapGroupMapper {
    /// LDAP attribute containing group membership.
    pub membership_attribute: String,

    /// DN suffix to strip from group names.
    pub groups_dn: String,

    /// Whether to preserve group hierarchy.
    pub preserve_hierarchy: bool,
}

impl Default for LdapGroupMapper {
    fn default() -> Self {
        Self {
            membership_attribute: "memberOf".to_string(),
            groups_dn: String::new(),
            preserve_hierarchy: true,
        }
    }
}

impl LdapGroupMapper {
    /// Creates a new group mapper.
    #[must_use]
    pub fn new(groups_dn: impl Into<String>) -> Self {
        Self {
            groups_dn: groups_dn.into(),
            ..Default::default()
        }
    }

    /// Extracts group names from member DNs.
    #[must_use]
    pub fn extract_group_names(&self, member_of_dns: &[String]) -> Vec<String> {
        member_of_dns
            .iter()
            .filter_map(|dn| self.extract_cn_from_dn(dn))
            .collect()
    }

    /// Extracts CN from a DN.
    fn extract_cn_from_dn(&self, dn: &str) -> Option<String> {
        // Parse "cn=GroupName,ou=groups,dc=example,dc=com"
        for part in dn.split(',') {
            let part = part.trim();
            if let Some(cn) = part.strip_prefix("cn=").or_else(|| part.strip_prefix("CN=")) {
                return Some(cn.to_string());
            }
        }
        None
    }
}

impl FederationMapper for LdapGroupMapper {
    fn mapper_type(&self) -> &'static str {
        "ldap-group-mapper"
    }

    fn display_name(&self) -> &'static str {
        "LDAP Group Mapper"
    }

    fn help_text(&self) -> &'static str {
        "Maps LDAP group membership to Keycloak groups"
    }
}

impl GroupMapper for LdapGroupMapper {
    fn get_groups(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        _config: &MapperConfig,
    ) -> FederationResult<Vec<String>> {
        let member_dns = external_attributes
            .get(&self.membership_attribute)
            .cloned()
            .unwrap_or_default();

        Ok(self.extract_group_names(&member_dns))
    }

    fn get_membership_values(
        &self,
        _group_ids: &[Uuid],
        _config: &MapperConfig,
    ) -> FederationResult<Vec<String>> {
        // This would need to convert Keycloak group IDs to LDAP DNs
        // For now, return empty (read-only mode)
        Ok(vec![])
    }
}

// ============================================================================
// LDAP Role Mapper
// ============================================================================

/// Maps LDAP group membership to Keycloak roles.
#[derive(Debug, Clone)]
pub struct LdapRoleMapper {
    /// LDAP attribute containing role information.
    pub role_attribute: String,

    /// Prefix to strip from role names.
    pub role_prefix: Option<String>,

    /// Whether to use group membership as roles.
    pub use_group_membership: bool,
}

impl Default for LdapRoleMapper {
    fn default() -> Self {
        Self {
            role_attribute: "memberOf".to_string(),
            role_prefix: None,
            use_group_membership: true,
        }
    }
}

impl LdapRoleMapper {
    /// Creates a new role mapper.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a mapper that uses a specific attribute.
    #[must_use]
    pub fn from_attribute(attribute: impl Into<String>) -> Self {
        Self {
            role_attribute: attribute.into(),
            ..Default::default()
        }
    }

    /// Extracts role names from values.
    #[must_use]
    pub fn extract_roles(&self, values: &[String]) -> Vec<String> {
        values
            .iter()
            .filter_map(|v| {
                // Try to extract CN from DN
                let role_name = if v.contains(',') {
                    // Looks like a DN
                    self.extract_cn_from_dn(v)
                } else {
                    Some(v.clone())
                };

                // Apply prefix stripping if configured
                role_name.map(|name| {
                    if let Some(prefix) = &self.role_prefix {
                        name.strip_prefix(prefix).unwrap_or(&name).to_string()
                    } else {
                        name
                    }
                })
            })
            .collect()
    }

    /// Extracts CN from a DN.
    fn extract_cn_from_dn(&self, dn: &str) -> Option<String> {
        for part in dn.split(',') {
            let part = part.trim();
            if let Some(cn) = part.strip_prefix("cn=").or_else(|| part.strip_prefix("CN=")) {
                return Some(cn.to_string());
            }
        }
        None
    }
}

impl FederationMapper for LdapRoleMapper {
    fn mapper_type(&self) -> &'static str {
        "ldap-role-mapper"
    }

    fn display_name(&self) -> &'static str {
        "LDAP Role Mapper"
    }

    fn help_text(&self) -> &'static str {
        "Maps LDAP group membership to Keycloak roles"
    }
}

impl RoleMapper for LdapRoleMapper {
    fn get_roles(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        _config: &MapperConfig,
    ) -> FederationResult<Vec<String>> {
        let values = external_attributes
            .get(&self.role_attribute)
            .cloned()
            .unwrap_or_default();

        Ok(self.extract_roles(&values))
    }

    fn get_membership_values(
        &self,
        _role_names: &[String],
        _config: &MapperConfig,
    ) -> FederationResult<Vec<String>> {
        // Read-only for now
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_mapper_extracts_cn() {
        let mapper = LdapGroupMapper::new("ou=groups,dc=example,dc=com");

        let dns = vec![
            "cn=Admins,ou=groups,dc=example,dc=com".to_string(),
            "cn=Users,ou=groups,dc=example,dc=com".to_string(),
            "CN=Special Group,ou=groups,dc=example,dc=com".to_string(),
        ];

        let groups = mapper.extract_group_names(&dns);

        assert_eq!(groups.len(), 3);
        assert!(groups.contains(&"Admins".to_string()));
        assert!(groups.contains(&"Users".to_string()));
        assert!(groups.contains(&"Special Group".to_string()));
    }

    #[test]
    fn role_mapper_extracts_roles() {
        let mapper = LdapRoleMapper::new();

        let values = vec![
            "cn=app_admin,ou=roles,dc=example,dc=com".to_string(),
            "cn=app_user,ou=roles,dc=example,dc=com".to_string(),
        ];

        let roles = mapper.extract_roles(&values);

        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&"app_admin".to_string()));
        assert!(roles.contains(&"app_user".to_string()));
    }

    #[test]
    fn role_mapper_strips_prefix() {
        let mut mapper = LdapRoleMapper::new();
        mapper.role_prefix = Some("app_".to_string());

        let values = vec!["app_admin".to_string(), "app_user".to_string()];

        let roles = mapper.extract_roles(&values);

        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&"admin".to_string()));
        assert!(roles.contains(&"user".to_string()));
    }
}
