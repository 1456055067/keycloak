//! Import/Export functionality for realm configuration.
//!
//! Provides JSON-based import and export of Keycloak realm configurations,
//! including users, clients, roles, and groups.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::{
    ClientRepresentation, GroupRepresentation, RealmRepresentation, RoleRepresentation,
    UserRepresentation,
};

// ============================================================================
// Realm Export Format
// ============================================================================

/// Complete realm export including all resources.
///
/// This format is compatible with Keycloak's JSON import/export format
/// for realm configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmExport {
    /// Realm configuration.
    #[serde(flatten)]
    pub realm: RealmRepresentation,

    /// Users in the realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserExport>,

    /// Clients in the realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<ClientExport>,

    /// Realm-level roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<RolesExport>,

    /// Top-level groups (with nested children).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupRepresentation>,

    /// Default roles assigned to new users.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_roles: Vec<String>,

    /// Default groups assigned to new users.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_groups: Vec<String>,
}

impl RealmExport {
    /// Creates a new realm export.
    #[must_use]
    pub fn new(realm: RealmRepresentation) -> Self {
        Self {
            realm,
            users: Vec::new(),
            clients: Vec::new(),
            roles: None,
            groups: Vec::new(),
            default_roles: Vec::new(),
            default_groups: Vec::new(),
        }
    }

    /// Adds users to the export.
    #[must_use]
    pub fn with_users(mut self, users: Vec<UserExport>) -> Self {
        self.users = users;
        self
    }

    /// Adds clients to the export.
    #[must_use]
    pub fn with_clients(mut self, clients: Vec<ClientExport>) -> Self {
        self.clients = clients;
        self
    }

    /// Adds roles to the export.
    #[must_use]
    pub fn with_roles(mut self, roles: RolesExport) -> Self {
        self.roles = Some(roles);
        self
    }

    /// Adds groups to the export.
    #[must_use]
    pub fn with_groups(mut self, groups: Vec<GroupRepresentation>) -> Self {
        self.groups = groups;
        self
    }
}

// ============================================================================
// User Export Format
// ============================================================================

/// User representation for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserExport {
    /// User representation.
    #[serde(flatten)]
    pub user: UserRepresentation,

    /// Credentials for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialExport>,

    /// Realm roles assigned to this user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_roles: Vec<String>,

    /// Client roles assigned to this user (client_id -> role names).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_roles: HashMap<String, Vec<String>>,

    /// Groups this user belongs to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl UserExport {
    /// Creates a new user export from a user representation.
    #[must_use]
    pub fn new(user: UserRepresentation) -> Self {
        Self {
            user,
            credentials: Vec::new(),
            realm_roles: Vec::new(),
            client_roles: HashMap::new(),
            groups: Vec::new(),
        }
    }

    /// Adds credentials to the user export.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Vec<CredentialExport>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Adds realm roles to the user export.
    #[must_use]
    pub fn with_realm_roles(mut self, roles: Vec<String>) -> Self {
        self.realm_roles = roles;
        self
    }

    /// Adds client roles to the user export.
    #[must_use]
    pub fn with_client_roles(mut self, client_id: String, roles: Vec<String>) -> Self {
        self.client_roles.insert(client_id, roles);
        self
    }

    /// Adds groups to the user export.
    #[must_use]
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }
}

/// Credential representation for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialExport {
    /// Credential type (e.g., "password", "otp").
    #[serde(rename = "type")]
    pub credential_type: String,

    /// Hashed credential value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashed_salted_value: Option<String>,

    /// Salt used for hashing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,

    /// Hash iterations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_iterations: Option<u32>,

    /// Algorithm used for hashing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// Whether this is a temporary credential.
    #[serde(default)]
    pub temporary: bool,

    /// Credential creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_date: Option<i64>,

    /// User-friendly label for the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,

    /// Secret data (for OTP, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_data: Option<String>,

    /// Credential-specific data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<String>,
}

impl CredentialExport {
    /// Creates a new password credential export.
    #[must_use]
    pub fn password(hashed_value: String, algorithm: String) -> Self {
        Self {
            credential_type: "password".to_string(),
            hashed_salted_value: Some(hashed_value),
            salt: None,
            hash_iterations: None,
            algorithm: Some(algorithm),
            temporary: false,
            created_date: None,
            user_label: None,
            secret_data: None,
            credential_data: None,
        }
    }

    /// Creates a temporary password credential export.
    #[must_use]
    pub fn temporary_password(hashed_value: String, algorithm: String) -> Self {
        Self {
            credential_type: "password".to_string(),
            hashed_salted_value: Some(hashed_value),
            salt: None,
            hash_iterations: None,
            algorithm: Some(algorithm),
            temporary: true,
            created_date: None,
            user_label: None,
            secret_data: None,
            credential_data: None,
        }
    }
}

// ============================================================================
// Client Export Format
// ============================================================================

/// Client representation for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientExport {
    /// Client representation.
    #[serde(flatten)]
    pub client: ClientRepresentation,

    /// Protocol mappers configured for this client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_mappers: Vec<ProtocolMapperExport>,

    /// Service account roles (for service accounts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_roles: Option<ServiceAccountRolesExport>,
}

impl ClientExport {
    /// Creates a new client export from a client representation.
    #[must_use]
    pub fn new(client: ClientRepresentation) -> Self {
        Self {
            client,
            protocol_mappers: Vec::new(),
            service_account_roles: None,
        }
    }

    /// Adds protocol mappers to the client export.
    #[must_use]
    pub fn with_protocol_mappers(mut self, mappers: Vec<ProtocolMapperExport>) -> Self {
        self.protocol_mappers = mappers;
        self
    }
}

/// Protocol mapper representation for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMapperExport {
    /// Mapper ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,

    /// Mapper name.
    pub name: String,

    /// Protocol (e.g., "openid-connect").
    pub protocol: String,

    /// Mapper type (e.g., "oidc-usermodel-attribute-mapper").
    pub protocol_mapper: String,

    /// Whether consent is required for this mapper.
    #[serde(default)]
    pub consent_required: bool,

    /// Mapper configuration.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, String>,
}

/// Service account roles for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountRolesExport {
    /// Realm roles assigned to the service account.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_roles: Vec<String>,

    /// Client roles assigned to the service account (client_id -> role names).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_roles: HashMap<String, Vec<String>>,
}

// ============================================================================
// Roles Export Format
// ============================================================================

/// Roles container for import/export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RolesExport {
    /// Realm-level roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm: Vec<RoleExport>,

    /// Client-level roles (client_id -> roles).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client: HashMap<String, Vec<RoleExport>>,
}

impl RolesExport {
    /// Creates a new empty roles export.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds realm roles.
    #[must_use]
    pub fn with_realm_roles(mut self, roles: Vec<RoleExport>) -> Self {
        self.realm = roles;
        self
    }

    /// Adds client roles for a specific client.
    #[must_use]
    pub fn with_client_roles(mut self, client_id: String, roles: Vec<RoleExport>) -> Self {
        self.client.insert(client_id, roles);
        self
    }
}

/// Role representation for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleExport {
    /// Role representation.
    #[serde(flatten)]
    pub role: RoleRepresentation,

    /// Composite roles (names of roles that are part of this role).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub composites: Vec<String>,
}

impl RoleExport {
    /// Creates a new role export from a role representation.
    #[must_use]
    pub fn new(role: RoleRepresentation) -> Self {
        Self {
            role,
            composites: Vec::new(),
        }
    }

    /// Adds composite roles.
    #[must_use]
    pub fn with_composites(mut self, composites: Vec<String>) -> Self {
        self.composites = composites;
        self
    }
}

// ============================================================================
// Import Options
// ============================================================================

/// Options for realm import.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOptions {
    /// Whether to skip existing resources (default: false, will fail on conflict).
    #[serde(default)]
    pub skip_existing: bool,

    /// Whether to overwrite existing resources.
    #[serde(default)]
    pub overwrite_existing: bool,

    /// Whether to import users.
    #[serde(default = "default_true")]
    pub import_users: bool,

    /// Whether to import clients.
    #[serde(default = "default_true")]
    pub import_clients: bool,

    /// Whether to import roles.
    #[serde(default = "default_true")]
    pub import_roles: bool,

    /// Whether to import groups.
    #[serde(default = "default_true")]
    pub import_groups: bool,

    /// Whether to import credentials (password hashes).
    #[serde(default)]
    pub import_credentials: bool,
}

fn default_true() -> bool {
    true
}

impl ImportOptions {
    /// Creates new import options with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            skip_existing: false,
            overwrite_existing: false,
            import_users: true,
            import_clients: true,
            import_roles: true,
            import_groups: true,
            import_credentials: false,
        }
    }

    /// Sets whether to skip existing resources.
    #[must_use]
    pub fn skip_existing(mut self, skip: bool) -> Self {
        self.skip_existing = skip;
        self
    }

    /// Sets whether to overwrite existing resources.
    #[must_use]
    pub fn overwrite_existing(mut self, overwrite: bool) -> Self {
        self.overwrite_existing = overwrite;
        self
    }
}

/// Result of an import operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Number of users imported.
    pub users_imported: usize,
    /// Number of users skipped (existing).
    pub users_skipped: usize,
    /// Number of clients imported.
    pub clients_imported: usize,
    /// Number of clients skipped (existing).
    pub clients_skipped: usize,
    /// Number of roles imported.
    pub roles_imported: usize,
    /// Number of roles skipped (existing).
    pub roles_skipped: usize,
    /// Number of groups imported.
    pub groups_imported: usize,
    /// Number of groups skipped (existing).
    pub groups_skipped: usize,
    /// Errors encountered during import.
    pub errors: Vec<String>,
}

impl ImportResult {
    /// Creates a new empty import result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an error to the result.
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Returns whether the import was fully successful (no errors).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }
}

// ============================================================================
// Export Options
// ============================================================================

/// Options for realm export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOptions {
    /// Whether to export users.
    #[serde(default = "default_true")]
    pub export_users: bool,

    /// Whether to export clients.
    #[serde(default = "default_true")]
    pub export_clients: bool,

    /// Whether to export roles.
    #[serde(default = "default_true")]
    pub export_roles: bool,

    /// Whether to export groups.
    #[serde(default = "default_true")]
    pub export_groups: bool,

    /// Whether to export credentials (password hashes).
    /// WARNING: This includes sensitive data!
    #[serde(default)]
    pub export_credentials: bool,

    /// Whether to export client secrets.
    /// WARNING: This includes sensitive data!
    #[serde(default)]
    pub export_client_secrets: bool,
}

impl ExportOptions {
    /// Creates new export options with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            export_users: true,
            export_clients: true,
            export_roles: true,
            export_groups: true,
            export_credentials: false,
            export_client_secrets: false,
        }
    }

    /// Sets whether to export credentials.
    #[must_use]
    pub fn export_credentials(mut self, export: bool) -> Self {
        self.export_credentials = export;
        self
    }

    /// Sets whether to export client secrets.
    #[must_use]
    pub fn export_client_secrets(mut self, export: bool) -> Self {
        self.export_client_secrets = export;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::RealmRepresentation;

    #[test]
    fn realm_export_serialization() {
        let realm = RealmRepresentation {
            id: Uuid::now_v7(),
            realm: "test".to_string(),
            display_name: Some("Test Realm".to_string()),
            enabled: true,
            ..Default::default()
        };

        let export = RealmExport::new(realm);
        let json = serde_json::to_string_pretty(&export).unwrap();

        assert!(json.contains("\"realm\": \"test\""));
        assert!(json.contains("\"enabled\": true"));
    }

    #[test]
    fn import_options_defaults() {
        let options = ImportOptions::new();

        assert!(!options.skip_existing);
        assert!(!options.overwrite_existing);
        assert!(options.import_users);
        assert!(options.import_clients);
        assert!(options.import_roles);
        assert!(options.import_groups);
        assert!(!options.import_credentials);
    }

    #[test]
    fn export_options_defaults() {
        let options = ExportOptions::new();

        assert!(options.export_users);
        assert!(options.export_clients);
        assert!(options.export_roles);
        assert!(options.export_groups);
        assert!(!options.export_credentials);
        assert!(!options.export_client_secrets);
    }

    #[test]
    fn import_result_tracks_errors() {
        let mut result = ImportResult::new();
        assert!(result.is_success());

        result.add_error("User 'john' already exists");
        assert!(!result.is_success());
        assert_eq!(result.errors.len(), 1);
    }
}
