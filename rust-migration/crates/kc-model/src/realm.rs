//! Realm domain model.
//!
//! A realm is the top-level container for all Keycloak entities.
//! Each realm is isolated and manages its own users, clients, and roles.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SSL requirement level for a realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SslRequired {
    /// No SSL required.
    None,
    /// SSL required for external requests only.
    #[default]
    External,
    /// SSL required for all requests.
    All,
}

/// OTP (One-Time Password) policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpPolicy {
    /// OTP type: TOTP or HOTP.
    pub otp_type: OtpType,
    /// Hash algorithm for OTP generation.
    pub algorithm: OtpAlgorithm,
    /// Number of digits in the OTP.
    pub digits: u8,
    /// Time period for TOTP (seconds).
    pub period: u32,
    /// Initial counter for HOTP.
    pub initial_counter: u32,
    /// Look-ahead window for validation.
    pub look_ahead_window: u32,
}

impl Default for OtpPolicy {
    fn default() -> Self {
        Self {
            otp_type: OtpType::Totp,
            algorithm: OtpAlgorithm::HmacSha1,
            digits: 6,
            period: 30,
            initial_counter: 0,
            look_ahead_window: 1,
        }
    }
}

/// OTP type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    /// Time-based OTP.
    #[default]
    Totp,
    /// HMAC-based OTP.
    Hotp,
}

/// OTP hash algorithm.
///
/// Note: `HmacSha1` is allowed for OTP compatibility despite CNSA 2.0,
/// as OTP secrets are short-lived and the algorithm is required by RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    /// HMAC-SHA1 (RFC 6238 default).
    #[default]
    HmacSha1,
    /// HMAC-SHA256.
    HmacSha256,
    /// HMAC-SHA512.
    HmacSha512,
}

/// A Keycloak realm.
///
/// Realms are the top-level organizational unit in Keycloak.
/// They provide complete isolation between different sets of users,
/// clients, and authentication configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Domain model naturally has many boolean flags
pub struct Realm {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// Unique realm name.
    pub name: String,
    /// Display name for UI.
    pub display_name: Option<String>,
    /// Whether the realm is enabled.
    pub enabled: bool,

    // === Timestamps ===
    /// When the realm was created.
    pub created_at: DateTime<Utc>,
    /// When the realm was last updated.
    pub updated_at: DateTime<Utc>,

    // === Security Settings ===
    /// SSL requirement level.
    pub ssl_required: SslRequired,
    /// Password policy (e.g., "length(8) and digits(1)").
    pub password_policy: Option<String>,
    /// OTP policy configuration.
    pub otp_policy: OtpPolicy,
    /// Token not-before timestamp (invalidate tokens issued before this).
    pub not_before: i64,

    // === Registration Settings ===
    /// Allow user self-registration.
    pub registration_allowed: bool,
    /// Use email as username during registration.
    pub registration_email_as_username: bool,
    /// Require email verification.
    pub verify_email: bool,
    /// Allow password reset.
    pub reset_password_allowed: bool,

    // === Login Settings ===
    /// Allow login with email address.
    pub login_with_email_allowed: bool,
    /// Allow duplicate email addresses.
    pub duplicate_emails_allowed: bool,
    /// Enable "Remember Me" checkbox.
    pub remember_me: bool,
    /// Allow users to edit their username.
    pub edit_username_allowed: bool,

    // === Token Lifespans (seconds) ===
    /// Access token lifespan.
    pub access_token_lifespan: i32,
    /// Access token lifespan for implicit flow.
    pub access_token_lifespan_implicit: i32,
    /// Authorization code lifespan.
    pub access_code_lifespan: i32,
    /// User action code lifespan.
    pub access_code_lifespan_user_action: i32,
    /// Login flow code lifespan.
    pub access_code_lifespan_login: i32,

    // === Session Lifespans (seconds) ===
    /// SSO session idle timeout.
    pub sso_session_idle_timeout: i32,
    /// SSO session max lifespan.
    pub sso_session_max_lifespan: i32,
    /// SSO session idle timeout with "Remember Me".
    pub sso_session_idle_timeout_remember_me: i32,
    /// SSO session max lifespan with "Remember Me".
    pub sso_session_max_lifespan_remember_me: i32,
    /// Offline session idle timeout.
    pub offline_session_idle_timeout: i32,
    /// Offline session max lifespan.
    pub offline_session_max_lifespan: i32,

    // === Themes ===
    /// Login page theme.
    pub login_theme: Option<String>,
    /// Account management theme.
    pub account_theme: Option<String>,
    /// Admin console theme.
    pub admin_theme: Option<String>,
    /// Email theme.
    pub email_theme: Option<String>,

    // === Events ===
    /// Enable event logging.
    pub events_enabled: bool,
    /// Event expiration time (seconds).
    pub events_expiration: i64,
    /// Enable admin event logging.
    pub admin_events_enabled: bool,
    /// Include details in admin events.
    pub admin_events_details_enabled: bool,
    /// Event listener types.
    pub events_listeners: HashSet<String>,
    /// Enabled event types.
    pub enabled_event_types: HashSet<String>,

    // === Internationalization ===
    /// Enable internationalization.
    pub internationalization_enabled: bool,
    /// Default locale.
    pub default_locale: Option<String>,
    /// Supported locales.
    pub supported_locales: HashSet<String>,

    // === Authentication Flows ===
    /// Browser authentication flow ID.
    pub browser_flow: Option<Uuid>,
    /// Registration flow ID.
    pub registration_flow: Option<Uuid>,
    /// Direct grant (Resource Owner Password) flow ID.
    pub direct_grant_flow: Option<Uuid>,
    /// Reset credentials flow ID.
    pub reset_credentials_flow: Option<Uuid>,
    /// Client authentication flow ID.
    pub client_authentication_flow: Option<Uuid>,

    // === Default Assignments ===
    /// Default role ID assigned to new users.
    pub default_role_id: Option<Uuid>,
    /// Default group IDs assigned to new users.
    pub default_groups: HashSet<Uuid>,

    // === SMTP Configuration ===
    /// SMTP server configuration.
    pub smtp_config: HashMap<String, String>,

    // === Custom Attributes ===
    /// Custom realm attributes.
    pub attributes: HashMap<String, String>,
}

impl Realm {
    /// Creates a new realm with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            display_name: None,
            enabled: true,
            created_at: now,
            updated_at: now,
            ssl_required: SslRequired::default(),
            password_policy: None,
            otp_policy: OtpPolicy::default(),
            not_before: 0,
            registration_allowed: false,
            registration_email_as_username: false,
            verify_email: false,
            reset_password_allowed: true,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            remember_me: false,
            edit_username_allowed: false,
            access_token_lifespan: 300,            // 5 minutes
            access_token_lifespan_implicit: 900,   // 15 minutes
            access_code_lifespan: 60,              // 1 minute
            access_code_lifespan_user_action: 300, // 5 minutes
            access_code_lifespan_login: 1800,      // 30 minutes
            sso_session_idle_timeout: 1800,        // 30 minutes
            sso_session_max_lifespan: 36000,       // 10 hours
            sso_session_idle_timeout_remember_me: 0,
            sso_session_max_lifespan_remember_me: 0,
            offline_session_idle_timeout: 2_592_000, // 30 days
            offline_session_max_lifespan: 5_184_000, // 60 days
            login_theme: None,
            account_theme: None,
            admin_theme: None,
            email_theme: None,
            events_enabled: false,
            events_expiration: 0,
            admin_events_enabled: false,
            admin_events_details_enabled: false,
            events_listeners: HashSet::new(),
            enabled_event_types: HashSet::new(),
            internationalization_enabled: false,
            default_locale: None,
            supported_locales: HashSet::new(),
            browser_flow: None,
            registration_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            client_authentication_flow: None,
            default_role_id: None,
            default_groups: HashSet::new(),
            smtp_config: HashMap::new(),
            attributes: HashMap::new(),
        }
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets whether registration is allowed.
    #[must_use]
    pub const fn with_registration_allowed(mut self, allowed: bool) -> Self {
        self.registration_allowed = allowed;
        self
    }

    /// Sets the SSL requirement.
    #[must_use]
    pub const fn with_ssl_required(mut self, ssl: SslRequired) -> Self {
        self.ssl_required = ssl;
        self
    }

    /// Checks if the realm is the master realm.
    #[must_use]
    pub fn is_master(&self) -> bool {
        self.name == "master"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_realm_has_defaults() {
        let realm = Realm::new("test");

        assert_eq!(realm.name, "test");
        assert!(realm.enabled);
        assert!(!realm.registration_allowed);
        assert_eq!(realm.ssl_required, SslRequired::External);
        assert_eq!(realm.access_token_lifespan, 300);
    }

    #[test]
    fn master_realm_detected() {
        let master = Realm::new("master");
        let other = Realm::new("other");

        assert!(master.is_master());
        assert!(!other.is_master());
    }

    #[test]
    fn builder_pattern_works() {
        let realm = Realm::new("myrealm")
            .with_display_name("My Realm")
            .with_registration_allowed(true)
            .with_ssl_required(SslRequired::All);

        assert_eq!(realm.display_name, Some("My Realm".to_string()));
        assert!(realm.registration_allowed);
        assert_eq!(realm.ssl_required, SslRequired::All);
    }
}
