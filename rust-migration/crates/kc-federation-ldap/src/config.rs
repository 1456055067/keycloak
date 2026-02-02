//! LDAP provider configuration.
//!
//! ## Security Requirements
//!
//! **CRITICAL**: Only LDAPS (LDAP over TLS) is supported.
//!
//! - Connection URLs MUST start with `ldaps://`
//! - STARTTLS is NOT supported (vulnerable to downgrade attacks)
//! - Plain `ldap://` is NOT supported (credentials transmitted in cleartext)

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{LdapError, LdapResult};

// ============================================================================
// LDAP Vendor
// ============================================================================

/// Known LDAP directory vendors.
///
/// Different vendors have different schemas and behaviors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LdapVendor {
    /// Generic LDAP (RFC 4510 compliant).
    #[default]
    Other,

    /// Microsoft Active Directory.
    ActiveDirectory,

    /// Red Hat Directory Server / 389 Directory Server.
    Rhds,

    /// OpenLDAP.
    OpenLdap,

    /// Oracle Directory Server.
    Oracle,

    /// IBM Security Directory Server.
    Ibm,
}

impl LdapVendor {
    /// Returns the default UUID attribute for this vendor.
    #[must_use]
    pub const fn uuid_attribute(&self) -> &'static str {
        match self {
            Self::ActiveDirectory => "objectGUID",
            Self::Rhds => "nsUniqueId",
            Self::OpenLdap => "entryUUID",
            Self::Oracle => "orclGUID",
            Self::Ibm => "ibm-entryUUID",
            Self::Other => "entryUUID",
        }
    }

    /// Returns the default user object class for this vendor.
    #[must_use]
    pub const fn user_object_class(&self) -> &'static str {
        match self {
            Self::ActiveDirectory => "person",
            _ => "inetOrgPerson",
        }
    }

    /// Returns the default group object class for this vendor.
    #[must_use]
    pub const fn group_object_class(&self) -> &'static str {
        match self {
            Self::ActiveDirectory => "group",
            _ => "groupOfNames",
        }
    }

    /// Returns the default membership attribute for this vendor.
    #[must_use]
    pub const fn membership_attribute(&self) -> &'static str {
        match self {
            Self::ActiveDirectory => "memberOf",
            _ => "memberOf",
        }
    }
}

// ============================================================================
// Username and RDN Attributes
// ============================================================================

/// Attribute used for username lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsernameAttribute {
    /// uid attribute (common for Unix/Linux).
    Uid,
    /// cn attribute (Common Name).
    Cn,
    /// sAMAccountName (Active Directory).
    SamAccountName,
    /// mail attribute (email as username).
    Mail,
    /// Custom attribute name.
    Custom(String),
}

impl Default for UsernameAttribute {
    fn default() -> Self {
        Self::Uid
    }
}

impl UsernameAttribute {
    /// Returns the LDAP attribute name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Uid => "uid",
            Self::Cn => "cn",
            Self::SamAccountName => "sAMAccountName",
            Self::Mail => "mail",
            Self::Custom(name) => name,
        }
    }
}

/// Attribute used for RDN (Relative Distinguished Name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RdnAttribute {
    /// uid=value.
    Uid,
    /// cn=value.
    Cn,
    /// Custom attribute.
    Custom(String),
}

impl Default for RdnAttribute {
    fn default() -> Self {
        Self::Uid
    }
}

impl RdnAttribute {
    /// Returns the LDAP attribute name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Uid => "uid",
            Self::Cn => "cn",
            Self::Custom(name) => name,
        }
    }
}

// ============================================================================
// LDAP Configuration
// ============================================================================

/// LDAP provider configuration.
///
/// ## Security Requirements
///
/// The `connection_url` MUST use the `ldaps://` scheme.
/// Any attempt to use `ldap://` or STARTTLS will be rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    // === Connection ===
    /// LDAP server URL (MUST be ldaps://).
    pub connection_url: String,

    /// Bind DN for service account.
    pub bind_dn: String,

    /// Bind credential (password).
    #[serde(skip_serializing)]
    pub bind_credential: String,

    // === TLS ===
    /// Whether to validate server certificates.
    /// Should always be true in production.
    pub validate_certificates: bool,

    /// Path to trusted CA certificate file (PEM format).
    pub trust_store_path: Option<String>,

    // === Directory Structure ===
    /// Base DN for user searches.
    pub users_dn: String,

    /// User object class filter.
    pub user_object_classes: Vec<String>,

    /// Base DN for group searches.
    pub groups_dn: Option<String>,

    /// Group object class filter.
    pub group_object_classes: Vec<String>,

    // === Attributes ===
    /// LDAP vendor.
    pub vendor: LdapVendor,

    /// Attribute for username lookup.
    pub username_attribute: UsernameAttribute,

    /// Attribute for RDN.
    pub rdn_attribute: RdnAttribute,

    /// UUID attribute for external ID.
    pub uuid_attribute: String,

    /// Email attribute.
    pub email_attribute: String,

    /// First name attribute.
    pub first_name_attribute: String,

    /// Last name attribute.
    pub last_name_attribute: String,

    // === Search ===
    /// Custom user search filter.
    pub custom_user_filter: Option<String>,

    /// Search scope.
    pub search_scope: SearchScope,

    /// Maximum users to return in a search.
    pub max_results: usize,

    // === Connection Pool ===
    /// Minimum connections in pool.
    pub pool_min_size: usize,

    /// Maximum connections in pool.
    pub pool_max_size: usize,

    /// Connection timeout.
    pub connection_timeout: Duration,

    /// Read timeout for operations.
    pub read_timeout: Duration,

    // === Sync ===
    /// Whether periodic sync is enabled.
    pub sync_enabled: bool,

    /// Full sync period in seconds.
    pub full_sync_period: u64,

    /// Changed sync period in seconds.
    pub changed_sync_period: u64,
}

/// LDAP search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SearchScope {
    /// Search only the base DN.
    Base,
    /// Search one level below the base DN.
    OneLevel,
    /// Search the entire subtree.
    #[default]
    Subtree,
}

impl SearchScope {
    /// Converts to ldap3 scope.
    #[must_use]
    pub fn to_ldap3(&self) -> ldap3::Scope {
        match self {
            Self::Base => ldap3::Scope::Base,
            Self::OneLevel => ldap3::Scope::OneLevel,
            Self::Subtree => ldap3::Scope::Subtree,
        }
    }
}

impl LdapConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder() -> LdapConfigBuilder {
        LdapConfigBuilder::new()
    }

    /// Validates the configuration.
    ///
    /// ## Security
    ///
    /// This method enforces LDAPS-only connections.
    pub fn validate(&self) -> LdapResult<()> {
        // CRITICAL: Enforce LDAPS-only
        self.validate_ldaps_url(&self.connection_url)?;

        // Validate bind DN
        if self.bind_dn.is_empty() {
            return Err(LdapError::config("bind_dn cannot be empty"));
        }

        // Validate users DN
        if self.users_dn.is_empty() {
            return Err(LdapError::config("users_dn cannot be empty"));
        }

        // Validate user object classes
        if self.user_object_classes.is_empty() {
            return Err(LdapError::config("user_object_classes cannot be empty"));
        }

        Ok(())
    }

    /// Validates that a URL uses LDAPS.
    ///
    /// ## Security
    ///
    /// **CRITICAL**: Only `ldaps://` URLs are accepted.
    /// - `ldap://` is rejected (cleartext credentials)
    /// - STARTTLS is not supported (vulnerable to downgrade attacks)
    fn validate_ldaps_url(&self, url: &str) -> LdapResult<()> {
        let url_lower = url.to_lowercase();

        // Must start with ldaps://
        if !url_lower.starts_with("ldaps://") {
            return Err(LdapError::InsecureProtocol);
        }

        // Additional validation: ensure it's a valid URL format
        if url.len() <= 8 {
            // "ldaps://" is 8 chars
            return Err(LdapError::config("Invalid LDAPS URL: missing host"));
        }

        Ok(())
    }

    /// Gets the search filter for users.
    #[must_use]
    pub fn user_search_filter(&self) -> String {
        let object_classes: Vec<String> = self
            .user_object_classes
            .iter()
            .map(|c| format!("(objectClass={c})"))
            .collect();

        let base_filter = if object_classes.len() == 1 {
            object_classes[0].clone()
        } else {
            format!("(&{})", object_classes.join(""))
        };

        match &self.custom_user_filter {
            Some(custom) => format!("(&{base_filter}{custom})"),
            None => base_filter,
        }
    }

    /// Gets the full user search filter with username.
    #[must_use]
    pub fn user_by_username_filter(&self, username: &str) -> String {
        let base = self.user_search_filter();
        let username_attr = self.username_attribute.as_str();
        // Escape special characters in username
        let escaped = ldap_escape(username);
        format!("(&{base}({username_attr}={escaped}))")
    }

    /// Gets the full user search filter with email.
    #[must_use]
    pub fn user_by_email_filter(&self, email: &str) -> String {
        let base = self.user_search_filter();
        let escaped = ldap_escape(email);
        format!("(&{base}({}={escaped}))", self.email_attribute)
    }
}

/// Escapes special characters in LDAP filter values.
fn ldap_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => result.push_str("\\5c"),
            '*' => result.push_str("\\2a"),
            '(' => result.push_str("\\28"),
            ')' => result.push_str("\\29"),
            '\0' => result.push_str("\\00"),
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// Configuration Builder
// ============================================================================

/// Builder for LDAP configuration.
#[derive(Debug, Default)]
pub struct LdapConfigBuilder {
    connection_url: Option<String>,
    bind_dn: Option<String>,
    bind_credential: Option<String>,
    validate_certificates: bool,
    trust_store_path: Option<String>,
    users_dn: Option<String>,
    user_object_classes: Vec<String>,
    groups_dn: Option<String>,
    group_object_classes: Vec<String>,
    vendor: LdapVendor,
    username_attribute: UsernameAttribute,
    rdn_attribute: RdnAttribute,
    uuid_attribute: Option<String>,
    email_attribute: String,
    first_name_attribute: String,
    last_name_attribute: String,
    custom_user_filter: Option<String>,
    search_scope: SearchScope,
    max_results: usize,
    pool_min_size: usize,
    pool_max_size: usize,
    connection_timeout: Duration,
    read_timeout: Duration,
    sync_enabled: bool,
    full_sync_period: u64,
    changed_sync_period: u64,
}

impl LdapConfigBuilder {
    /// Creates a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            validate_certificates: true,
            user_object_classes: vec!["inetOrgPerson".to_string()],
            group_object_classes: vec!["groupOfNames".to_string()],
            email_attribute: "mail".to_string(),
            first_name_attribute: "givenName".to_string(),
            last_name_attribute: "sn".to_string(),
            max_results: 1000,
            pool_min_size: 1,
            pool_max_size: 10,
            connection_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            full_sync_period: 86400,  // 1 day
            changed_sync_period: 3600, // 1 hour
            ..Default::default()
        }
    }

    /// Sets the connection URL (must be ldaps://).
    #[must_use]
    pub fn connection_url(mut self, url: impl Into<String>) -> Self {
        self.connection_url = Some(url.into());
        self
    }

    /// Sets the bind DN.
    #[must_use]
    pub fn bind_dn(mut self, dn: impl Into<String>) -> Self {
        self.bind_dn = Some(dn.into());
        self
    }

    /// Sets the bind credential (password).
    #[must_use]
    pub fn bind_credential(mut self, credential: impl Into<String>) -> Self {
        self.bind_credential = Some(credential.into());
        self
    }

    /// Sets whether to validate certificates.
    #[must_use]
    pub const fn validate_certificates(mut self, validate: bool) -> Self {
        self.validate_certificates = validate;
        self
    }

    /// Sets the trust store path.
    #[must_use]
    pub fn trust_store_path(mut self, path: impl Into<String>) -> Self {
        self.trust_store_path = Some(path.into());
        self
    }

    /// Sets the users DN.
    #[must_use]
    pub fn users_dn(mut self, dn: impl Into<String>) -> Self {
        self.users_dn = Some(dn.into());
        self
    }

    /// Sets the user object classes.
    #[must_use]
    pub fn user_object_classes(mut self, classes: Vec<String>) -> Self {
        self.user_object_classes = classes;
        self
    }

    /// Sets the groups DN.
    #[must_use]
    pub fn groups_dn(mut self, dn: impl Into<String>) -> Self {
        self.groups_dn = Some(dn.into());
        self
    }

    /// Sets the LDAP vendor.
    #[must_use]
    pub const fn vendor(mut self, vendor: LdapVendor) -> Self {
        self.vendor = vendor;
        self
    }

    /// Sets the username attribute.
    #[must_use]
    pub fn username_attribute(mut self, attr: UsernameAttribute) -> Self {
        self.username_attribute = attr;
        self
    }

    /// Sets the RDN attribute.
    #[must_use]
    pub fn rdn_attribute(mut self, attr: RdnAttribute) -> Self {
        self.rdn_attribute = attr;
        self
    }

    /// Sets the UUID attribute.
    #[must_use]
    pub fn uuid_attribute(mut self, attr: impl Into<String>) -> Self {
        self.uuid_attribute = Some(attr.into());
        self
    }

    /// Sets the custom user search filter.
    #[must_use]
    pub fn custom_user_filter(mut self, filter: impl Into<String>) -> Self {
        self.custom_user_filter = Some(filter.into());
        self
    }

    /// Sets the search scope.
    #[must_use]
    pub const fn search_scope(mut self, scope: SearchScope) -> Self {
        self.search_scope = scope;
        self
    }

    /// Sets the maximum results.
    #[must_use]
    pub const fn max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Sets the connection pool sizes.
    #[must_use]
    pub const fn pool_size(mut self, min: usize, max: usize) -> Self {
        self.pool_min_size = min;
        self.pool_max_size = max;
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

    /// Enables periodic synchronization.
    #[must_use]
    pub const fn sync_enabled(mut self, enabled: bool) -> Self {
        self.sync_enabled = enabled;
        self
    }

    /// Builds and validates the configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing
    /// - Connection URL does not use LDAPS
    pub fn build(self) -> LdapResult<LdapConfig> {
        let uuid_attr = self
            .uuid_attribute
            .unwrap_or_else(|| self.vendor.uuid_attribute().to_string());

        let config = LdapConfig {
            connection_url: self
                .connection_url
                .ok_or_else(|| LdapError::config("connection_url is required"))?,
            bind_dn: self
                .bind_dn
                .ok_or_else(|| LdapError::config("bind_dn is required"))?,
            bind_credential: self
                .bind_credential
                .ok_or_else(|| LdapError::config("bind_credential is required"))?,
            validate_certificates: self.validate_certificates,
            trust_store_path: self.trust_store_path,
            users_dn: self
                .users_dn
                .ok_or_else(|| LdapError::config("users_dn is required"))?,
            user_object_classes: self.user_object_classes,
            groups_dn: self.groups_dn,
            group_object_classes: self.group_object_classes,
            vendor: self.vendor,
            username_attribute: self.username_attribute,
            rdn_attribute: self.rdn_attribute,
            uuid_attribute: uuid_attr,
            email_attribute: self.email_attribute,
            first_name_attribute: self.first_name_attribute,
            last_name_attribute: self.last_name_attribute,
            custom_user_filter: self.custom_user_filter,
            search_scope: self.search_scope,
            max_results: self.max_results,
            pool_min_size: self.pool_min_size,
            pool_max_size: self.pool_max_size,
            connection_timeout: self.connection_timeout,
            read_timeout: self.read_timeout,
            sync_enabled: self.sync_enabled,
            full_sync_period: self.full_sync_period,
            changed_sync_period: self.changed_sync_period,
        };

        // Validate configuration (includes LDAPS check)
        config.validate()?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ldap_url() {
        let result = LdapConfig::builder()
            .connection_url("ldap://ldap.example.com:389") // NOT LDAPS!
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, LdapError::InsecureProtocol));
    }

    #[test]
    fn rejects_starttls_url() {
        // STARTTLS would use ldap:// and upgrade, which we don't support
        let result = LdapConfig::builder()
            .connection_url("ldap://ldap.example.com:389")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, LdapError::InsecureProtocol));
    }

    #[test]
    fn accepts_ldaps_url() {
        let result = LdapConfig::builder()
            .connection_url("ldaps://ldap.example.com:636")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn ldap_escape_special_chars() {
        assert_eq!(ldap_escape("john*"), "john\\2a");
        assert_eq!(ldap_escape("(admin)"), "\\28admin\\29");
        assert_eq!(ldap_escape("user\\name"), "user\\5cname");
        assert_eq!(ldap_escape("normal"), "normal");
    }

    #[test]
    fn user_search_filter() {
        let config = LdapConfig::builder()
            .connection_url("ldaps://ldap.example.com:636")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build()
            .unwrap();

        let filter = config.user_by_username_filter("jdoe");
        assert!(filter.contains("uid=jdoe"));
        assert!(filter.contains("objectClass=inetOrgPerson"));
    }

    #[test]
    fn vendor_defaults() {
        assert_eq!(LdapVendor::ActiveDirectory.uuid_attribute(), "objectGUID");
        assert_eq!(LdapVendor::OpenLdap.uuid_attribute(), "entryUUID");
        assert_eq!(
            LdapVendor::ActiveDirectory.user_object_class(),
            "person"
        );
    }
}
