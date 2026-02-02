//! Realm DTOs for the Admin API.

use chrono::Utc;
use kc_model::{OtpPolicy, Realm, SslRequired};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create a new realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRealmRequest {
    /// Realm name (unique identifier).
    pub realm: String,
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    // Security settings
    /// SSL requirement level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_required: Option<SslRequired>,
    /// Password policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<String>,

    // Registration settings
    /// Allow user self-registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_allowed: Option<bool>,
    /// Require email verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_email: Option<bool>,
    /// Allow password reset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_password_allowed: Option<bool>,

    // Login settings
    /// Allow login with email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_with_email_allowed: Option<bool>,
    /// Allow duplicate emails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_emails_allowed: Option<bool>,
    /// Enable "Remember Me" checkbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,

    // Token lifespans
    /// Access token lifespan in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifespan: Option<i32>,
    /// SSO session idle timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso_session_idle_timeout: Option<i32>,
    /// SSO session max lifespan in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso_session_max_lifespan: Option<i32>,
}

fn default_enabled() -> bool {
    true
}

impl CreateRealmRequest {
    /// Converts this request to a domain `Realm` model.
    #[must_use]
    pub fn into_realm(self) -> Realm {
        let mut realm = Realm::new(self.realm);
        realm.display_name = self.display_name;
        realm.enabled = self.enabled;

        if let Some(ssl) = self.ssl_required {
            realm.ssl_required = ssl;
        }
        realm.password_policy = self.password_policy;

        if let Some(v) = self.registration_allowed {
            realm.registration_allowed = v;
        }
        if let Some(v) = self.verify_email {
            realm.verify_email = v;
        }
        if let Some(v) = self.reset_password_allowed {
            realm.reset_password_allowed = v;
        }

        if let Some(v) = self.login_with_email_allowed {
            realm.login_with_email_allowed = v;
        }
        if let Some(v) = self.duplicate_emails_allowed {
            realm.duplicate_emails_allowed = v;
        }
        if let Some(v) = self.remember_me {
            realm.remember_me = v;
        }

        if let Some(v) = self.access_token_lifespan {
            realm.access_token_lifespan = v;
        }
        if let Some(v) = self.sso_session_idle_timeout {
            realm.sso_session_idle_timeout = v;
        }
        if let Some(v) = self.sso_session_max_lifespan {
            realm.sso_session_max_lifespan = v;
        }

        realm
    }
}

/// Request to update a realm.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRealmRequest {
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    // Security settings
    /// SSL requirement level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_required: Option<SslRequired>,
    /// Password policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<String>,

    // Registration settings
    /// Allow user self-registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_allowed: Option<bool>,
    /// Require email verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_email: Option<bool>,
    /// Allow password reset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_password_allowed: Option<bool>,

    // Login settings
    /// Allow login with email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_with_email_allowed: Option<bool>,
    /// Allow duplicate emails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_emails_allowed: Option<bool>,
    /// Enable "Remember Me" checkbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,

    // Token lifespans
    /// Access token lifespan in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifespan: Option<i32>,
    /// SSO session idle timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso_session_idle_timeout: Option<i32>,
    /// SSO session max lifespan in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso_session_max_lifespan: Option<i32>,
}

impl UpdateRealmRequest {
    /// Applies this update to an existing realm.
    pub fn apply_to(&self, realm: &mut Realm) {
        if let Some(ref v) = self.display_name {
            realm.display_name = Some(v.clone());
        }
        if let Some(v) = self.enabled {
            realm.enabled = v;
        }
        if let Some(v) = self.ssl_required {
            realm.ssl_required = v;
        }
        if let Some(ref v) = self.password_policy {
            realm.password_policy = Some(v.clone());
        }
        if let Some(v) = self.registration_allowed {
            realm.registration_allowed = v;
        }
        if let Some(v) = self.verify_email {
            realm.verify_email = v;
        }
        if let Some(v) = self.reset_password_allowed {
            realm.reset_password_allowed = v;
        }
        if let Some(v) = self.login_with_email_allowed {
            realm.login_with_email_allowed = v;
        }
        if let Some(v) = self.duplicate_emails_allowed {
            realm.duplicate_emails_allowed = v;
        }
        if let Some(v) = self.remember_me {
            realm.remember_me = v;
        }
        if let Some(v) = self.access_token_lifespan {
            realm.access_token_lifespan = v;
        }
        if let Some(v) = self.sso_session_idle_timeout {
            realm.sso_session_idle_timeout = v;
        }
        if let Some(v) = self.sso_session_max_lifespan {
            realm.sso_session_max_lifespan = v;
        }
        realm.updated_at = Utc::now();
    }
}

/// Full realm representation for API responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmRepresentation {
    /// Unique identifier.
    pub id: Uuid,
    /// Realm name.
    pub realm: String,
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    pub enabled: bool,

    // Timestamps
    /// When the realm was created.
    pub created_timestamp: i64,

    // Security settings
    /// SSL requirement level.
    pub ssl_required: SslRequired,
    /// Password policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<String>,
    /// OTP policy.
    pub otp_policy: OtpPolicy,

    // Registration settings
    /// Allow user self-registration.
    pub registration_allowed: bool,
    /// Use email as username during registration.
    pub registration_email_as_username: bool,
    /// Require email verification.
    pub verify_email: bool,
    /// Allow password reset.
    pub reset_password_allowed: bool,

    // Login settings
    /// Allow login with email.
    pub login_with_email_allowed: bool,
    /// Allow duplicate emails.
    pub duplicate_emails_allowed: bool,
    /// Enable "Remember Me" checkbox.
    pub remember_me: bool,
    /// Allow users to edit their username.
    pub edit_username_allowed: bool,

    // Token lifespans
    /// Access token lifespan in seconds.
    pub access_token_lifespan: i32,
    /// Access token lifespan for implicit flow in seconds.
    pub access_token_lifespan_for_implicit_flow: i32,
    /// Authorization code lifespan in seconds.
    pub access_code_lifespan: i32,
    /// User action code lifespan in seconds.
    pub access_code_lifespan_user_action: i32,
    /// Login flow code lifespan in seconds.
    pub access_code_lifespan_login: i32,

    // Session lifespans
    /// SSO session idle timeout in seconds.
    pub sso_session_idle_timeout: i32,
    /// SSO session max lifespan in seconds.
    pub sso_session_max_lifespan: i32,
    /// Offline session idle timeout in seconds.
    pub offline_session_idle_timeout: i32,
    /// Offline session max lifespan in seconds.
    pub offline_session_max_lifespan: i32,

    // Events
    /// Enable event logging.
    pub events_enabled: bool,
    /// Enable admin event logging.
    pub admin_events_enabled: bool,

    // Internationalization
    /// Enable internationalization.
    pub internationalization_enabled: bool,
    /// Default locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_locale: Option<String>,
}

impl From<Realm> for RealmRepresentation {
    fn from(realm: Realm) -> Self {
        Self {
            id: realm.id,
            realm: realm.name,
            display_name: realm.display_name,
            enabled: realm.enabled,
            created_timestamp: realm.created_at.timestamp_millis(),
            ssl_required: realm.ssl_required,
            password_policy: realm.password_policy,
            otp_policy: realm.otp_policy,
            registration_allowed: realm.registration_allowed,
            registration_email_as_username: realm.registration_email_as_username,
            verify_email: realm.verify_email,
            reset_password_allowed: realm.reset_password_allowed,
            login_with_email_allowed: realm.login_with_email_allowed,
            duplicate_emails_allowed: realm.duplicate_emails_allowed,
            remember_me: realm.remember_me,
            edit_username_allowed: realm.edit_username_allowed,
            access_token_lifespan: realm.access_token_lifespan,
            access_token_lifespan_for_implicit_flow: realm.access_token_lifespan_implicit,
            access_code_lifespan: realm.access_code_lifespan,
            access_code_lifespan_user_action: realm.access_code_lifespan_user_action,
            access_code_lifespan_login: realm.access_code_lifespan_login,
            sso_session_idle_timeout: realm.sso_session_idle_timeout,
            sso_session_max_lifespan: realm.sso_session_max_lifespan,
            offline_session_idle_timeout: realm.offline_session_idle_timeout,
            offline_session_max_lifespan: realm.offline_session_max_lifespan,
            events_enabled: realm.events_enabled,
            admin_events_enabled: realm.admin_events_enabled,
            internationalization_enabled: realm.internationalization_enabled,
            default_locale: realm.default_locale,
        }
    }
}

/// Summary realm representation for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmSummary {
    /// Unique identifier.
    pub id: Uuid,
    /// Realm name.
    pub realm: String,
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    pub enabled: bool,
}

impl From<Realm> for RealmSummary {
    fn from(realm: Realm) -> Self {
        Self {
            id: realm.id,
            realm: realm.name,
            display_name: realm.display_name,
            enabled: realm.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_realm_request_defaults() {
        let json = r#"{"realm": "test"}"#;
        let req: CreateRealmRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.realm, "test");
        assert!(req.enabled);
    }

    #[test]
    fn create_realm_request_to_realm() {
        let req = CreateRealmRequest {
            realm: "test-realm".to_string(),
            display_name: Some("Test Realm".to_string()),
            enabled: true,
            ssl_required: Some(SslRequired::All),
            password_policy: None,
            registration_allowed: Some(true),
            verify_email: Some(true),
            reset_password_allowed: None,
            login_with_email_allowed: None,
            duplicate_emails_allowed: None,
            remember_me: None,
            access_token_lifespan: Some(600),
            sso_session_idle_timeout: None,
            sso_session_max_lifespan: None,
        };

        let realm = req.into_realm();
        assert_eq!(realm.name, "test-realm");
        assert_eq!(realm.display_name, Some("Test Realm".to_string()));
        assert!(realm.enabled);
        assert_eq!(realm.ssl_required, SslRequired::All);
        assert!(realm.registration_allowed);
        assert!(realm.verify_email);
        assert_eq!(realm.access_token_lifespan, 600);
    }

    #[test]
    fn update_realm_request_applies() {
        let mut realm = Realm::new("test");
        realm.enabled = true;

        let update = UpdateRealmRequest {
            enabled: Some(false),
            display_name: Some("Updated".to_string()),
            ..Default::default()
        };

        update.apply_to(&mut realm);
        assert!(!realm.enabled);
        assert_eq!(realm.display_name, Some("Updated".to_string()));
    }

    #[test]
    fn realm_representation_from_realm() {
        let realm = Realm::new("test-realm")
            .with_display_name("Test Realm")
            .with_registration_allowed(true);

        let repr = RealmRepresentation::from(realm);
        assert_eq!(repr.realm, "test-realm");
        assert_eq!(repr.display_name, Some("Test Realm".to_string()));
        assert!(repr.registration_allowed);
    }
}
