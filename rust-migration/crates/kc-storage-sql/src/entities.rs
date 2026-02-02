//! Database entity types for `SQLx`.
//!
//! These types map directly to database rows and are converted
//! to/from domain models.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Database row for realms.
#[derive(Debug, Clone, FromRow)]
#[allow(clippy::struct_excessive_bools)]
pub struct RealmRow {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ssl_required: String,
    pub password_policy: Option<String>,
    pub otp_policy: sqlx::types::Json<serde_json::Value>,
    pub not_before: i64,
    pub registration_allowed: bool,
    pub registration_email_as_username: bool,
    pub verify_email: bool,
    pub reset_password_allowed: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub remember_me: bool,
    pub edit_username_allowed: bool,
    pub access_token_lifespan: i32,
    pub access_token_lifespan_implicit: i32,
    pub access_code_lifespan: i32,
    pub access_code_lifespan_user_action: i32,
    pub access_code_lifespan_login: i32,
    pub sso_session_idle_timeout: i32,
    pub sso_session_max_lifespan: i32,
    pub sso_session_idle_timeout_remember_me: i32,
    pub sso_session_max_lifespan_remember_me: i32,
    pub offline_session_idle_timeout: i32,
    pub offline_session_max_lifespan: i32,
    pub login_theme: Option<String>,
    pub account_theme: Option<String>,
    pub admin_theme: Option<String>,
    pub email_theme: Option<String>,
    pub events_enabled: bool,
    pub events_expiration: i64,
    pub admin_events_enabled: bool,
    pub admin_events_details_enabled: bool,
    pub events_listeners: sqlx::types::Json<Vec<String>>,
    pub enabled_event_types: sqlx::types::Json<Vec<String>>,
    pub internationalization_enabled: bool,
    pub default_locale: Option<String>,
    pub supported_locales: sqlx::types::Json<Vec<String>>,
    pub browser_flow: Option<Uuid>,
    pub registration_flow: Option<Uuid>,
    pub direct_grant_flow: Option<Uuid>,
    pub reset_credentials_flow: Option<Uuid>,
    pub client_authentication_flow: Option<Uuid>,
    pub default_role_id: Option<Uuid>,
    pub default_groups: sqlx::types::Json<Vec<Uuid>>,
    pub smtp_config: sqlx::types::Json<serde_json::Value>,
    pub attributes: sqlx::types::Json<serde_json::Value>,
}

/// Database row for users.
#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub username: String,
    pub enabled: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub not_before: i64,
    pub federation_link: Option<String>,
    pub service_account_client_link: Option<Uuid>,
    pub required_actions: sqlx::types::Json<Vec<String>>,
    pub attributes: sqlx::types::Json<serde_json::Value>,
}

/// Database row for federated identities.
#[derive(Debug, Clone, FromRow)]
pub struct FederatedIdentityRow {
    /// User ID is used when fetching from database via query.
    #[allow(dead_code)]
    pub user_id: Uuid,
    pub identity_provider: String,
    pub federated_user_id: String,
    pub federated_user_name: Option<String>,
}

/// Database row for clients.
#[derive(Debug, Clone, FromRow)]
#[allow(clippy::struct_excessive_bools)]
pub struct ClientRow {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub protocol: String,
    pub secret: Option<String>,
    pub public_client: bool,
    pub bearer_only: bool,
    pub client_authenticator_type: String,
    pub consent_required: bool,
    pub not_before: i64,
    pub standard_flow_enabled: bool,
    pub implicit_flow_enabled: bool,
    pub direct_access_grants_enabled: bool,
    pub service_accounts_enabled: bool,
    pub root_url: Option<String>,
    pub base_url: Option<String>,
    pub admin_url: Option<String>,
    pub redirect_uris: sqlx::types::Json<Vec<String>>,
    pub web_origins: sqlx::types::Json<Vec<String>>,
    pub frontchannel_logout: bool,
    pub full_scope_allowed: bool,
    pub always_display_in_console: bool,
    pub attributes: sqlx::types::Json<serde_json::Value>,
    pub auth_flow_bindings: sqlx::types::Json<serde_json::Value>,
}

/// Database row for roles.
#[derive(Debug, Clone, FromRow)]
pub struct RoleRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
    pub client_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub composite_roles: sqlx::types::Json<Vec<Uuid>>,
    pub attributes: sqlx::types::Json<serde_json::Value>,
}

/// Database row for groups.
#[derive(Debug, Clone, FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub attributes: sqlx::types::Json<serde_json::Value>,
    pub realm_roles: sqlx::types::Json<Vec<Uuid>>,
    pub client_roles: sqlx::types::Json<serde_json::Value>,
}

/// Database row for credentials.
#[derive(Debug, Clone, FromRow)]
pub struct CredentialRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub realm_id: Uuid,
    pub credential_type: String,
    pub user_label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub secret_data: String,
    pub credential_data: String,
    pub priority: i32,
}
