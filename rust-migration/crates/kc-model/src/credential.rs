//! Credential domain model.
//!
//! Credentials represent authentication factors for users,
//! such as passwords, OTP secrets, and `WebAuthn` credentials.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Credential type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// Password credential.
    Password,
    /// TOTP (Time-based One-Time Password) credential.
    Totp,
    /// HOTP (HMAC-based One-Time Password) credential.
    Hotp,
    /// `WebAuthn` credential.
    Webauthn,
    /// `WebAuthn` passwordless credential.
    WebauthnPasswordless,
    /// Recovery codes.
    RecoveryCodes,
}

impl CredentialType {
    /// Returns the string representation used in storage.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "otp",
            Self::Hotp => "hotp",
            Self::Webauthn => "webauthn",
            Self::WebauthnPasswordless => "webauthn-passwordless",
            Self::RecoveryCodes => "recovery-authn-codes",
        }
    }
}

/// A user credential.
///
/// Credentials are authentication factors that can be used to verify
/// a user's identity. Each user can have multiple credentials of
/// different types.
///
/// ## Security Note
///
/// The `secret_data` and `credential_data` fields contain sensitive
/// information and should be handled with care. Password hashes use
/// Argon2id per NIST SP 800-63B recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// User this credential belongs to.
    pub user_id: Uuid,
    /// Realm this credential belongs to.
    pub realm_id: Uuid,

    // === Type ===
    /// Credential type.
    pub credential_type: CredentialType,
    /// User-defined label (e.g., "My Yubikey").
    pub user_label: Option<String>,

    // === Timestamps ===
    /// When the credential was created.
    pub created_at: DateTime<Utc>,

    // === Credential Data ===
    /// Secret data (e.g., password hash, OTP secret).
    /// This field is encrypted at rest.
    pub secret_data: String,
    /// Additional credential metadata (e.g., hash algorithm, counter).
    pub credential_data: String,

    // === Priority ===
    /// Priority for ordering credentials of the same type.
    pub priority: i32,
}

impl Credential {
    /// Creates a new credential.
    #[must_use]
    pub fn new(
        user_id: Uuid,
        realm_id: Uuid,
        credential_type: CredentialType,
        secret_data: impl Into<String>,
        credential_data: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            user_id,
            realm_id,
            credential_type,
            user_label: None,
            created_at: Utc::now(),
            secret_data: secret_data.into(),
            credential_data: credential_data.into(),
            priority: 0,
        }
    }

    /// Creates a password credential.
    ///
    /// Note: The `secret_data` should contain the Argon2id hash,
    /// not the plaintext password.
    #[must_use]
    pub fn new_password(
        user_id: Uuid,
        realm_id: Uuid,
        secret_data: impl Into<String>,
        credential_data: impl Into<String>,
    ) -> Self {
        Self::new(
            user_id,
            realm_id,
            CredentialType::Password,
            secret_data,
            credential_data,
        )
    }

    /// Creates a TOTP credential.
    #[must_use]
    pub fn new_totp(
        user_id: Uuid,
        realm_id: Uuid,
        secret_data: impl Into<String>,
        credential_data: impl Into<String>,
    ) -> Self {
        Self::new(
            user_id,
            realm_id,
            CredentialType::Totp,
            secret_data,
            credential_data,
        )
    }

    /// Sets the user label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.user_label = Some(label.into());
        self
    }

    /// Sets the priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Checks if this is a password credential.
    #[must_use]
    pub const fn is_password(&self) -> bool {
        matches!(self.credential_type, CredentialType::Password)
    }

    /// Checks if this is an OTP credential (TOTP or HOTP).
    #[must_use]
    pub const fn is_otp(&self) -> bool {
        matches!(
            self.credential_type,
            CredentialType::Totp | CredentialType::Hotp
        )
    }

    /// Checks if this is a `WebAuthn` credential.
    #[must_use]
    pub const fn is_webauthn(&self) -> bool {
        matches!(
            self.credential_type,
            CredentialType::Webauthn | CredentialType::WebauthnPasswordless
        )
    }
}

/// Password credential data structure.
///
/// This is stored in the `credential_data` field for password credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCredentialData {
    /// Hash algorithm used.
    pub algorithm: String,
    /// Number of hash iterations (if applicable).
    pub hash_iterations: Option<i32>,
    /// Additional algorithm-specific parameters.
    #[serde(default)]
    pub additional_parameters: std::collections::HashMap<String, String>,
}

impl PasswordCredentialData {
    /// Creates credential data for Argon2id.
    #[must_use]
    pub fn argon2id() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            hash_iterations: None,
            additional_parameters: std::collections::HashMap::new(),
        }
    }
}

/// Password secret data structure.
///
/// This is stored in the `secret_data` field for password credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordSecretData {
    /// The password hash.
    pub value: String,
    /// Salt used for hashing (if stored separately).
    pub salt: Option<String>,
}

/// OTP credential data structure.
///
/// This is stored in the `credential_data` field for OTP credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpCredentialData {
    /// Number of digits in the OTP.
    pub digits: u8,
    /// Counter value (for HOTP).
    pub counter: Option<i64>,
    /// Time period in seconds (for TOTP).
    pub period: Option<i32>,
    /// Hash algorithm (`HmacSHA1`, `HmacSHA256`, `HmacSHA512`).
    pub algorithm: String,
    /// Sub-type (totp or hotp).
    pub sub_type: String,
}

impl OtpCredentialData {
    /// Creates credential data for TOTP with default settings.
    #[must_use]
    pub fn totp_default() -> Self {
        Self {
            digits: 6,
            counter: None,
            period: Some(30),
            algorithm: "HmacSHA1".to_string(),
            sub_type: "totp".to_string(),
        }
    }

    /// Creates credential data for HOTP with default settings.
    #[must_use]
    pub fn hotp_default() -> Self {
        Self {
            digits: 6,
            counter: Some(0),
            period: None,
            algorithm: "HmacSHA1".to_string(),
            sub_type: "hotp".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_credential_creation() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();

        let cred = Credential::new_password(
            user_id,
            realm_id,
            r#"{"value":"$argon2id$..."}"#,
            r#"{"algorithm":"argon2id"}"#,
        );

        assert!(cred.is_password());
        assert!(!cred.is_otp());
        assert_eq!(cred.credential_type, CredentialType::Password);
    }

    #[test]
    fn totp_credential_creation() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();

        let cred = Credential::new_totp(
            user_id,
            realm_id,
            r#"{"value":"BASE32SECRET"}"#,
            r#"{"digits":6,"period":30}"#,
        )
        .with_label("My Authenticator");

        assert!(cred.is_otp());
        assert!(!cred.is_password());
        assert_eq!(cred.user_label, Some("My Authenticator".to_string()));
    }

    #[test]
    fn credential_type_strings() {
        assert_eq!(CredentialType::Password.as_str(), "password");
        assert_eq!(CredentialType::Totp.as_str(), "otp");
        assert_eq!(CredentialType::Webauthn.as_str(), "webauthn");
    }

    #[test]
    fn password_credential_data_serialization() {
        let data = PasswordCredentialData::argon2id();
        let json = serde_json::to_string(&data).unwrap();

        assert!(json.contains("argon2id"));
    }

    #[test]
    fn otp_credential_data_defaults() {
        let totp = OtpCredentialData::totp_default();
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.period, Some(30));
        assert!(totp.counter.is_none());

        let hotp = OtpCredentialData::hotp_default();
        assert_eq!(hotp.counter, Some(0));
        assert!(hotp.period.is_none());
    }
}
