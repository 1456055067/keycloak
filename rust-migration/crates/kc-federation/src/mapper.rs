//! Federation mappers for attribute transformation.
//!
//! Mappers transform attributes between external identity stores
//! and Keycloak's internal user model.

use std::collections::HashMap;

use kc_model::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::FederationResult;

// ============================================================================
// Mapper Configuration
// ============================================================================

/// Configuration for a federation mapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapperConfig {
    /// Mapper ID.
    pub id: Uuid,

    /// Mapper name.
    pub name: String,

    /// Mapper type.
    pub mapper_type: String,

    /// Provider ID this mapper belongs to.
    pub provider_id: Uuid,

    /// Mapper-specific configuration.
    pub config: HashMap<String, String>,
}

impl MapperConfig {
    /// Creates a new mapper config.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        mapper_type: impl Into<String>,
        provider_id: Uuid,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            mapper_type: mapper_type.into(),
            provider_id,
            config: HashMap::new(),
        }
    }

    /// Adds a config value.
    #[must_use]
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Gets a config value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(String::as_str)
    }

    /// Gets a config value as bool.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.config.get(key).and_then(|v| v.parse().ok())
    }
}

// ============================================================================
// Federation Mapper Trait
// ============================================================================

/// Base trait for all federation mappers.
pub trait FederationMapper: Send + Sync {
    /// Returns the mapper type identifier.
    fn mapper_type(&self) -> &'static str;

    /// Returns the display name for this mapper.
    fn display_name(&self) -> &'static str;

    /// Returns help text describing this mapper.
    fn help_text(&self) -> &'static str;
}

// ============================================================================
// Attribute Mapper
// ============================================================================

/// Direction of attribute mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttributeMappingDirection {
    /// Import from external store to Keycloak.
    #[default]
    Import,

    /// Export from Keycloak to external store.
    Export,

    /// Both import and export.
    Both,
}

/// Mapper for user attributes.
///
/// Maps attributes from external identity store entries to Keycloak user attributes.
pub trait AttributeMapper: FederationMapper {
    /// Maps attributes from external data to a Keycloak user.
    ///
    /// # Parameters
    ///
    /// - `external_attributes`: Raw attributes from the external store
    /// - `user`: The Keycloak user to update
    /// - `config`: Mapper configuration
    fn import_attributes(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        user: &mut User,
        config: &MapperConfig,
    ) -> FederationResult<()>;

    /// Maps attributes from a Keycloak user to external format.
    ///
    /// Returns the attributes to write to the external store.
    fn export_attributes(
        &self,
        user: &User,
        config: &MapperConfig,
    ) -> FederationResult<HashMap<String, Vec<String>>>;

    /// Returns the mapping direction.
    fn direction(&self) -> AttributeMappingDirection {
        AttributeMappingDirection::Import
    }
}

// ============================================================================
// Built-in Attribute Mappers
// ============================================================================

/// Maps a single attribute from external store to user attribute.
#[derive(Debug, Clone, Default)]
pub struct UserAttributeMapper;

impl UserAttributeMapper {
    /// Config key for external attribute name.
    pub const EXTERNAL_ATTRIBUTE: &'static str = "ldap.attribute";

    /// Config key for Keycloak attribute name.
    pub const USER_ATTRIBUTE: &'static str = "user.model.attribute";

    /// Config key for whether attribute is read-only.
    pub const READ_ONLY: &'static str = "read.only";

    /// Config key for whether attribute is always read from LDAP.
    pub const ALWAYS_READ: &'static str = "always.read.value.from.ldap";
}

impl FederationMapper for UserAttributeMapper {
    fn mapper_type(&self) -> &'static str {
        "user-attribute-ldap-mapper"
    }

    fn display_name(&self) -> &'static str {
        "User Attribute"
    }

    fn help_text(&self) -> &'static str {
        "Maps a single user attribute from LDAP to Keycloak"
    }
}

impl AttributeMapper for UserAttributeMapper {
    fn import_attributes(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        user: &mut User,
        config: &MapperConfig,
    ) -> FederationResult<()> {
        let external_attr = config.get(Self::EXTERNAL_ATTRIBUTE).ok_or_else(|| {
            crate::error::FederationError::AttributeMapping(
                "Missing external attribute config".to_string(),
            )
        })?;

        let user_attr = config.get(Self::USER_ATTRIBUTE).ok_or_else(|| {
            crate::error::FederationError::AttributeMapping(
                "Missing user attribute config".to_string(),
            )
        })?;

        if let Some(values) = external_attributes.get(external_attr) {
            // Handle built-in attributes specially
            match user_attr {
                "firstName" => {
                    user.first_name = values.first().cloned();
                }
                "lastName" => {
                    user.last_name = values.first().cloned();
                }
                "email" => {
                    user.email = values.first().cloned();
                }
                "username" => {
                    if let Some(v) = values.first() {
                        user.username = v.clone();
                    }
                }
                _ => {
                    // Custom attribute
                    user.attributes.insert(user_attr.to_string(), values.clone());
                }
            }
        }

        Ok(())
    }

    fn export_attributes(
        &self,
        user: &User,
        config: &MapperConfig,
    ) -> FederationResult<HashMap<String, Vec<String>>> {
        let mut result = HashMap::new();

        let external_attr = config.get(Self::EXTERNAL_ATTRIBUTE).ok_or_else(|| {
            crate::error::FederationError::AttributeMapping(
                "Missing external attribute config".to_string(),
            )
        })?;

        let user_attr = config.get(Self::USER_ATTRIBUTE).ok_or_else(|| {
            crate::error::FederationError::AttributeMapping(
                "Missing user attribute config".to_string(),
            )
        })?;

        // Get value from user
        let values: Option<Vec<String>> = match user_attr {
            "firstName" => user.first_name.clone().map(|v| vec![v]),
            "lastName" => user.last_name.clone().map(|v| vec![v]),
            "email" => user.email.clone().map(|v| vec![v]),
            "username" => Some(vec![user.username.clone()]),
            _ => user.attributes.get(user_attr).cloned(),
        };

        if let Some(vals) = values {
            result.insert(external_attr.to_string(), vals);
        }

        Ok(result)
    }
}

/// Maps full name (combines first and last name).
#[derive(Debug, Clone, Default)]
pub struct FullNameMapper;

impl FullNameMapper {
    /// Config key for external full name attribute.
    pub const EXTERNAL_ATTRIBUTE: &'static str = "ldap.full.name.attribute";
}

impl FederationMapper for FullNameMapper {
    fn mapper_type(&self) -> &'static str {
        "full-name-ldap-mapper"
    }

    fn display_name(&self) -> &'static str {
        "Full Name"
    }

    fn help_text(&self) -> &'static str {
        "Maps full name (cn) to first name and last name"
    }
}

impl AttributeMapper for FullNameMapper {
    fn import_attributes(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        user: &mut User,
        config: &MapperConfig,
    ) -> FederationResult<()> {
        let attr_name = config
            .get(Self::EXTERNAL_ATTRIBUTE)
            .unwrap_or("cn");

        if let Some(values) = external_attributes.get(attr_name) {
            if let Some(full_name) = values.first() {
                // Split full name into first and last
                let parts: Vec<&str> = full_name.splitn(2, ' ').collect();
                if !parts.is_empty() {
                    user.first_name = Some(parts[0].to_string());
                }
                if parts.len() > 1 {
                    user.last_name = Some(parts[1].to_string());
                }
            }
        }

        Ok(())
    }

    fn export_attributes(
        &self,
        user: &User,
        config: &MapperConfig,
    ) -> FederationResult<HashMap<String, Vec<String>>> {
        let mut result = HashMap::new();

        let attr_name = config
            .get(Self::EXTERNAL_ATTRIBUTE)
            .unwrap_or("cn");

        if let Some(full_name) = user.full_name() {
            result.insert(attr_name.to_string(), vec![full_name]);
        }

        Ok(result)
    }
}

// ============================================================================
// Group Mapper
// ============================================================================

/// Mapper for group membership.
pub trait GroupMapper: FederationMapper {
    /// Gets group IDs for a user from external store.
    fn get_groups(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        config: &MapperConfig,
    ) -> FederationResult<Vec<String>>;

    /// Gets external group membership values for a user.
    fn get_membership_values(
        &self,
        group_ids: &[Uuid],
        config: &MapperConfig,
    ) -> FederationResult<Vec<String>>;
}

// ============================================================================
// Role Mapper
// ============================================================================

/// Mapper for role assignments.
pub trait RoleMapper: FederationMapper {
    /// Gets role names for a user from external store.
    fn get_roles(
        &self,
        external_attributes: &HashMap<String, Vec<String>>,
        config: &MapperConfig,
    ) -> FederationResult<Vec<String>>;

    /// Gets external role membership values for a user.
    fn get_membership_values(
        &self,
        role_names: &[String],
        config: &MapperConfig,
    ) -> FederationResult<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_attribute_mapper_imports() {
        let mapper = UserAttributeMapper;
        let provider_id = Uuid::now_v7();

        let config = MapperConfig::new("email-mapper", "user-attribute-ldap-mapper", provider_id)
            .with_config(UserAttributeMapper::EXTERNAL_ATTRIBUTE, "mail")
            .with_config(UserAttributeMapper::USER_ATTRIBUTE, "email");

        let mut external_attrs = HashMap::new();
        external_attrs.insert("mail".to_string(), vec!["john@example.com".to_string()]);

        let realm_id = Uuid::now_v7();
        let mut user = User::new(realm_id, "john");

        mapper
            .import_attributes(&external_attrs, &mut user, &config)
            .unwrap();

        assert_eq!(user.email, Some("john@example.com".to_string()));
    }

    #[test]
    fn full_name_mapper_splits_name() {
        let mapper = FullNameMapper;
        let provider_id = Uuid::now_v7();

        let config = MapperConfig::new("fullname-mapper", "full-name-ldap-mapper", provider_id)
            .with_config(FullNameMapper::EXTERNAL_ATTRIBUTE, "cn");

        let mut external_attrs = HashMap::new();
        external_attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);

        let realm_id = Uuid::now_v7();
        let mut user = User::new(realm_id, "john");

        mapper
            .import_attributes(&external_attrs, &mut user, &config)
            .unwrap();

        assert_eq!(user.first_name, Some("John".to_string()));
        assert_eq!(user.last_name, Some("Doe".to_string()));
    }
}
