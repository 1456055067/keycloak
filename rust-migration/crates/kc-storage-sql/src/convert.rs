//! Conversion between database entities and domain models.

use std::collections::{HashMap, HashSet};

use kc_model::{
    Client, Credential, CredentialType, FederatedIdentity, Group, Protocol, Realm, Role,
    SslRequired, User,
};
use uuid::Uuid;

use crate::entities::{
    ClientRow, CredentialRow, FederatedIdentityRow, GroupRow, RealmRow, RoleRow, UserRow,
};

/// Convert a `RealmRow` to a `Realm` domain model.
impl From<RealmRow> for Realm {
    fn from(row: RealmRow) -> Self {
        let ssl_required = match row.ssl_required.as_str() {
            "none" => SslRequired::None,
            "all" => SslRequired::All,
            _ => SslRequired::External,
        };

        let otp_policy = serde_json::from_value(row.otp_policy.0).unwrap_or_default();

        Self {
            id: row.id,
            name: row.name,
            display_name: row.display_name,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ssl_required,
            password_policy: row.password_policy,
            otp_policy,
            not_before: row.not_before,
            registration_allowed: row.registration_allowed,
            registration_email_as_username: row.registration_email_as_username,
            verify_email: row.verify_email,
            reset_password_allowed: row.reset_password_allowed,
            login_with_email_allowed: row.login_with_email_allowed,
            duplicate_emails_allowed: row.duplicate_emails_allowed,
            remember_me: row.remember_me,
            edit_username_allowed: row.edit_username_allowed,
            access_token_lifespan: row.access_token_lifespan,
            access_token_lifespan_implicit: row.access_token_lifespan_implicit,
            access_code_lifespan: row.access_code_lifespan,
            access_code_lifespan_user_action: row.access_code_lifespan_user_action,
            access_code_lifespan_login: row.access_code_lifespan_login,
            sso_session_idle_timeout: row.sso_session_idle_timeout,
            sso_session_max_lifespan: row.sso_session_max_lifespan,
            sso_session_idle_timeout_remember_me: row.sso_session_idle_timeout_remember_me,
            sso_session_max_lifespan_remember_me: row.sso_session_max_lifespan_remember_me,
            offline_session_idle_timeout: row.offline_session_idle_timeout,
            offline_session_max_lifespan: row.offline_session_max_lifespan,
            login_theme: row.login_theme,
            account_theme: row.account_theme,
            admin_theme: row.admin_theme,
            email_theme: row.email_theme,
            events_enabled: row.events_enabled,
            events_expiration: row.events_expiration,
            admin_events_enabled: row.admin_events_enabled,
            admin_events_details_enabled: row.admin_events_details_enabled,
            events_listeners: row.events_listeners.0.into_iter().collect(),
            enabled_event_types: row.enabled_event_types.0.into_iter().collect(),
            internationalization_enabled: row.internationalization_enabled,
            default_locale: row.default_locale,
            supported_locales: row.supported_locales.0.into_iter().collect(),
            browser_flow: row.browser_flow,
            registration_flow: row.registration_flow,
            direct_grant_flow: row.direct_grant_flow,
            reset_credentials_flow: row.reset_credentials_flow,
            client_authentication_flow: row.client_authentication_flow,
            default_role_id: row.default_role_id,
            default_groups: row.default_groups.0.into_iter().collect(),
            smtp_config: serde_json::from_value(row.smtp_config.0).unwrap_or_default(),
            attributes: serde_json::from_value(row.attributes.0).unwrap_or_default(),
        }
    }
}

/// Convert a `UserRow` to a `User` domain model.
pub fn user_from_row(row: UserRow, federated_identities: Vec<FederatedIdentityRow>) -> User {
    let identities = federated_identities
        .into_iter()
        .map(|fi| FederatedIdentity {
            identity_provider: fi.identity_provider,
            user_id: fi.federated_user_id,
            user_name: fi.federated_user_name,
        })
        .collect();

    User {
        id: row.id,
        realm_id: row.realm_id,
        username: row.username,
        enabled: row.enabled,
        first_name: row.first_name,
        last_name: row.last_name,
        email: row.email,
        email_verified: row.email_verified,
        created_at: row.created_at,
        updated_at: row.updated_at,
        not_before: row.not_before,
        federation_link: row.federation_link,
        service_account_client_link: row.service_account_client_link,
        required_actions: row.required_actions.0,
        attributes: serde_json::from_value(row.attributes.0).unwrap_or_default(),
        federated_identities: identities,
    }
}

/// Convert a `ClientRow` to a `Client` domain model.
impl From<ClientRow> for Client {
    fn from(row: ClientRow) -> Self {
        let protocol = match row.protocol.as_str() {
            "saml" => Protocol::Saml,
            _ => Protocol::OpenidConnect,
        };

        Self {
            id: row.id,
            realm_id: row.realm_id,
            client_id: row.client_id,
            name: row.name,
            description: row.description,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            protocol,
            secret: row.secret,
            public_client: row.public_client,
            bearer_only: row.bearer_only,
            client_authenticator_type: row.client_authenticator_type,
            consent_required: row.consent_required,
            not_before: row.not_before,
            standard_flow_enabled: row.standard_flow_enabled,
            implicit_flow_enabled: row.implicit_flow_enabled,
            direct_access_grants_enabled: row.direct_access_grants_enabled,
            service_accounts_enabled: row.service_accounts_enabled,
            root_url: row.root_url,
            base_url: row.base_url,
            admin_url: row.admin_url,
            redirect_uris: row.redirect_uris.0.into_iter().collect(),
            web_origins: row.web_origins.0.into_iter().collect(),
            frontchannel_logout: row.frontchannel_logout,
            full_scope_allowed: row.full_scope_allowed,
            always_display_in_console: row.always_display_in_console,
            attributes: serde_json::from_value(row.attributes.0).unwrap_or_default(),
            auth_flow_bindings: serde_json::from_value(row.auth_flow_bindings.0)
                .unwrap_or_default(),
        }
    }
}

/// Convert a `RoleRow` to a `Role` domain model.
impl From<RoleRow> for Role {
    fn from(row: RoleRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            realm_id: row.realm_id,
            client_id: row.client_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            composite_roles: row.composite_roles.0,
            attributes: serde_json::from_value(row.attributes.0).unwrap_or_default(),
        }
    }
}

/// Convert a `GroupRow` to a `Group` domain model.
impl From<GroupRow> for Group {
    fn from(row: GroupRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            realm_id: row.realm_id,
            parent_id: row.parent_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            attributes: serde_json::from_value(row.attributes.0).unwrap_or_default(),
            realm_roles: row.realm_roles.0,
            client_roles: serde_json::from_value(row.client_roles.0).unwrap_or_default(),
        }
    }
}

/// Convert a `CredentialRow` to a `Credential` domain model.
impl From<CredentialRow> for Credential {
    fn from(row: CredentialRow) -> Self {
        let credential_type = match row.credential_type.as_str() {
            "otp" => CredentialType::Totp,
            "hotp" => CredentialType::Hotp,
            "webauthn" => CredentialType::Webauthn,
            "webauthn-passwordless" => CredentialType::WebauthnPasswordless,
            "recovery-authn-codes" => CredentialType::RecoveryCodes,
            // "password" and any unknown type default to Password
            _ => CredentialType::Password,
        };

        Self {
            id: row.id,
            user_id: row.user_id,
            realm_id: row.realm_id,
            credential_type,
            user_label: row.user_label,
            created_at: row.created_at,
            secret_data: row.secret_data,
            credential_data: row.credential_data,
            priority: row.priority,
        }
    }
}

// === Helpers for converting domain models to database values ===

/// Get SSL required as a database string.
pub const fn ssl_required_to_string(ssl: SslRequired) -> &'static str {
    match ssl {
        SslRequired::None => "none",
        SslRequired::External => "external",
        SslRequired::All => "all",
    }
}

/// Get protocol as a database string.
pub const fn protocol_to_string(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::OpenidConnect => "openid-connect",
        Protocol::Saml => "saml",
    }
}

/// Convert `HashSet` to a sorted Vec for consistent JSON serialization.
pub fn hashset_to_vec<T: Ord + Clone>(set: &HashSet<T>) -> Vec<T> {
    let mut vec: Vec<T> = set.iter().cloned().collect();
    vec.sort();
    vec
}

/// Convert `HashMap` with `Vec` values to JSON value.
pub fn attributes_to_json(attrs: &HashMap<String, Vec<String>>) -> serde_json::Value {
    serde_json::to_value(attrs)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()))
}

/// Convert `HashMap<String, String>` to JSON value.
pub fn string_map_to_json(map: &HashMap<String, String>) -> serde_json::Value {
    serde_json::to_value(map)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()))
}

/// Convert `HashMap<String, Uuid>` to JSON value.
pub fn uuid_map_to_json(map: &HashMap<String, Uuid>) -> serde_json::Value {
    serde_json::to_value(map)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()))
}

/// Convert `HashMap<Uuid, Vec<Uuid>>` to JSON value.
pub fn client_roles_to_json(map: &HashMap<Uuid, Vec<Uuid>>) -> serde_json::Value {
    serde_json::to_value(map)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()))
}
