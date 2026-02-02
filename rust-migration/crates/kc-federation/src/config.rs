//! Federation provider configuration.
//!
//! Configuration types for user federation providers.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Edit mode for federated users.
///
/// Controls whether changes to users are written back to the external store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EditMode {
    /// Users are read-only. Changes in Keycloak are not written back.
    /// This is the safest mode for directory services.
    #[default]
    ReadOnly,

    /// Users are writable. Changes in Keycloak are written back to the external store.
    Writable,

    /// Users are imported but not synchronized.
    /// Changes are stored locally in Keycloak and not written back.
    Unsynced,
}

impl EditMode {
    /// Returns true if the mode allows writes to the external store.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Writable)
    }

    /// Returns true if the mode is read-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    /// Returns true if users are stored locally (unsynced).
    #[must_use]
    pub const fn is_unsynced(&self) -> bool {
        matches!(self, Self::Unsynced)
    }
}

/// Import strategy for federated users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImportMode {
    /// Import users on demand when they authenticate.
    #[default]
    OnDemand,

    /// Import all users during synchronization.
    Import,

    /// Do not import users (query-only mode).
    NoImport,
}

/// Cache policy for federated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CachePolicy {
    /// Cache with default TTL.
    Default,

    /// Never cache (always query external store).
    NoCache,

    /// Cache with custom TTL.
    Custom {
        /// Maximum cache age in seconds.
        max_lifespan_secs: u64,
    },
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::Default
    }
}

/// Base configuration for all federation providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Unique identifier for this provider configuration.
    pub id: Uuid,

    /// Realm this provider belongs to.
    pub realm_id: Uuid,

    /// Provider type (e.g., "ldap", "kerberos").
    pub provider_type: String,

    /// Display name.
    pub name: String,

    /// Priority for user lookup (lower = higher priority).
    pub priority: i32,

    /// Edit mode.
    pub edit_mode: EditMode,

    /// Import mode.
    pub import_mode: ImportMode,

    /// Cache policy.
    pub cache_policy: CachePolicy,

    /// Whether the provider is enabled.
    pub enabled: bool,

    /// Provider-specific configuration.
    pub config: HashMap<String, String>,

    /// Connection timeout.
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,

    /// Read timeout.
    #[serde(with = "humantime_serde")]
    pub read_timeout: Duration,
}

impl FederationConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder() -> FederationConfigBuilder {
        FederationConfigBuilder::new()
    }

    /// Gets a config value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(String::as_str)
    }

    /// Gets a config value as bool.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.config.get(key).and_then(|v| v.parse().ok())
    }

    /// Gets a config value as i32.
    #[must_use]
    pub fn get_i32(&self, key: &str) -> Option<i32> {
        self.config.get(key).and_then(|v| v.parse().ok())
    }
}

/// Builder for FederationConfig.
#[derive(Debug, Default)]
pub struct FederationConfigBuilder {
    id: Option<Uuid>,
    realm_id: Option<Uuid>,
    provider_type: Option<String>,
    name: Option<String>,
    priority: i32,
    edit_mode: EditMode,
    import_mode: ImportMode,
    cache_policy: CachePolicy,
    enabled: bool,
    config: HashMap<String, String>,
    connection_timeout: Duration,
    read_timeout: Duration,
}

impl FederationConfigBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            connection_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            ..Default::default()
        }
    }

    /// Sets the ID.
    #[must_use]
    pub fn id(mut self, id: Uuid) -> Self {
        self.id = Some(id);
        self
    }

    /// Sets the realm ID.
    #[must_use]
    pub fn realm_id(mut self, realm_id: Uuid) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    /// Sets the provider type.
    #[must_use]
    pub fn provider_type(mut self, provider_type: impl Into<String>) -> Self {
        self.provider_type = Some(provider_type.into());
        self
    }

    /// Sets the name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the priority.
    #[must_use]
    pub const fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the edit mode.
    #[must_use]
    pub const fn edit_mode(mut self, mode: EditMode) -> Self {
        self.edit_mode = mode;
        self
    }

    /// Sets the import mode.
    #[must_use]
    pub const fn import_mode(mut self, mode: ImportMode) -> Self {
        self.import_mode = mode;
        self
    }

    /// Sets the cache policy.
    #[must_use]
    pub const fn cache_policy(mut self, policy: CachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    /// Sets whether the provider is enabled.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Adds a config value.
    #[must_use]
    pub fn config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    pub const fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Sets the read timeout.
    #[must_use]
    pub const fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Builds the configuration.
    ///
    /// # Panics
    ///
    /// Panics if required fields are not set.
    #[must_use]
    pub fn build(self) -> FederationConfig {
        FederationConfig {
            id: self.id.unwrap_or_else(Uuid::now_v7),
            realm_id: self.realm_id.expect("realm_id is required"),
            provider_type: self.provider_type.expect("provider_type is required"),
            name: self.name.expect("name is required"),
            priority: self.priority,
            edit_mode: self.edit_mode,
            import_mode: self.import_mode,
            cache_policy: self.cache_policy,
            enabled: self.enabled,
            config: self.config,
            connection_timeout: self.connection_timeout,
            read_timeout: self.read_timeout,
        }
    }
}

/// Serde support for Duration using humantime format.
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_mode_properties() {
        assert!(EditMode::ReadOnly.is_read_only());
        assert!(!EditMode::ReadOnly.is_writable());

        assert!(EditMode::Writable.is_writable());
        assert!(!EditMode::Writable.is_read_only());

        assert!(EditMode::Unsynced.is_unsynced());
    }

    #[test]
    fn config_builder() {
        let realm_id = Uuid::now_v7();

        let config = FederationConfig::builder()
            .realm_id(realm_id)
            .provider_type("ldap")
            .name("Corporate LDAP")
            .priority(0)
            .edit_mode(EditMode::ReadOnly)
            .config("connection_url", "ldaps://ldap.example.com:636")
            .build();

        assert_eq!(config.realm_id, realm_id);
        assert_eq!(config.name, "Corporate LDAP");
        assert_eq!(config.priority, 0);
        assert!(config.edit_mode.is_read_only());
        assert_eq!(
            config.get("connection_url"),
            Some("ldaps://ldap.example.com:636")
        );
    }
}
