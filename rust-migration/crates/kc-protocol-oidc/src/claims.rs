//! JWT claim types for OIDC tokens.
//!
//! Implements token claims as defined in:
//! - RFC 7519 (JSON Web Token)
//! - `OpenID` Connect Core 1.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Access token claims.
///
/// These claims are included in OAuth 2.0 access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    // === Standard JWT Claims (RFC 7519) ===
    /// Issuer - URL of the authorization server.
    pub iss: String,

    /// Subject - unique identifier for the user.
    pub sub: String,

    /// Audience - intended recipient(s) of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration time (Unix timestamp).
    pub exp: i64,

    /// Issued at time (Unix timestamp).
    pub iat: i64,

    /// Not before time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// JWT ID - unique identifier for the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    // === OIDC Standard Claims ===
    /// Authentication time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    /// Authorized party - client ID that requested the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    /// Scope - space-separated list of scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    // === Keycloak-specific Claims ===
    /// Token type (usually "Bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Realm access (realm-level roles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess>,

    /// Resource access (client-level roles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_access: Option<HashMap<String, ResourceAccess>>,

    /// Preferred username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verified flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Given (first) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Family (last) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Full name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Additional claims (for protocol mappers).
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl AccessTokenClaims {
    /// Creates new access token claims.
    #[must_use]
    pub fn new(issuer: String, subject: String, expires_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            iss: issuer,
            sub: subject,
            aud: None,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            nbf: None,
            jti: Some(Uuid::now_v7().to_string()),
            auth_time: None,
            azp: None,
            sid: None,
            scope: None,
            typ: Some("Bearer".to_string()),
            realm_access: None,
            resource_access: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            given_name: None,
            family_name: None,
            name: None,
            additional: HashMap::new(),
        }
    }

    /// Sets the audience.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<Audience>) -> Self {
        self.aud = Some(audience.into());
        self
    }

    /// Sets the authorized party (client ID).
    #[must_use]
    pub fn with_azp(mut self, client_id: impl Into<String>) -> Self {
        self.azp = Some(client_id.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.sid = Some(session_id.into());
        self
    }

    /// Sets the scope.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Sets the authentication time.
    #[must_use]
    pub const fn with_auth_time(mut self, auth_time: i64) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    /// Sets realm access (roles).
    #[must_use]
    pub fn with_realm_access(mut self, roles: Vec<String>) -> Self {
        self.realm_access = Some(RealmAccess { roles });
        self
    }

    /// Adds a custom claim.
    #[must_use]
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.additional.insert(key.into(), value);
        self
    }

    /// Checks if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.exp
    }

    /// Checks if the token is not yet valid.
    #[must_use]
    pub fn is_not_yet_valid(&self) -> bool {
        self.nbf.is_some_and(|nbf| Utc::now().timestamp() < nbf)
    }
}

/// ID token claims.
///
/// These claims are included in `OpenID` Connect ID tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    // === Required Claims ===
    /// Issuer - URL of the authorization server.
    pub iss: String,

    /// Subject - unique identifier for the user.
    pub sub: String,

    /// Audience - client ID that requested the token.
    pub aud: Audience,

    /// Expiration time (Unix timestamp).
    pub exp: i64,

    /// Issued at time (Unix timestamp).
    pub iat: i64,

    // === Conditionally Required Claims ===
    /// Authentication time (required if `max_age` was requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    /// Nonce (required if provided in request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,

    /// Authentication methods references.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,

    /// Authorized party.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    // === Hash Claims (for hybrid flows) ===
    /// Access token hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,

    /// Code hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,

    // === Session Claims ===
    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    // === Profile Claims ===
    /// Full name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Given (first) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Family (last) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Middle name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Nickname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// Preferred username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    /// Profile URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Website URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// Gender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    /// Birthdate (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,

    /// Timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    /// Locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Last updated time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    // === Email Claims ===
    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verified flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    // === Phone Claims ===
    /// Phone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    /// Phone number verified flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    // === Address Claim ===
    /// Structured address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,

    /// Additional claims.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl IdTokenClaims {
    /// Creates new ID token claims.
    #[must_use]
    pub fn new(
        issuer: String,
        subject: String,
        audience: impl Into<Audience>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            iss: issuer,
            sub: subject,
            aud: audience.into(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            sid: None,
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            updated_at: None,
            email: None,
            email_verified: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            additional: HashMap::new(),
        }
    }

    /// Sets the nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the authentication time.
    #[must_use]
    pub const fn with_auth_time(mut self, auth_time: i64) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    /// Sets the access token hash.
    #[must_use]
    pub fn with_at_hash(mut self, at_hash: impl Into<String>) -> Self {
        self.at_hash = Some(at_hash.into());
        self
    }

    /// Sets the code hash.
    #[must_use]
    pub fn with_c_hash(mut self, c_hash: impl Into<String>) -> Self {
        self.c_hash = Some(c_hash.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.sid = Some(session_id.into());
        self
    }

    /// Sets the authorized party.
    #[must_use]
    pub fn with_azp(mut self, azp: impl Into<String>) -> Self {
        self.azp = Some(azp.into());
        self
    }
}

/// Refresh token claims.
///
/// These claims are included in refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Issuer.
    pub iss: String,

    /// Subject.
    pub sub: String,

    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration time (Unix timestamp).
    pub exp: i64,

    /// Issued at time (Unix timestamp).
    pub iat: i64,

    /// JWT ID.
    pub jti: String,

    /// Token type.
    pub typ: String,

    /// Authorized party (client ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    /// Scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Nonce (preserved from original auth request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl RefreshTokenClaims {
    /// Creates new refresh token claims.
    #[must_use]
    pub fn new(issuer: String, subject: String, expires_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            iss: issuer,
            sub: subject,
            aud: None,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::now_v7().to_string(),
            typ: "Refresh".to_string(),
            azp: None,
            sid: None,
            scope: None,
            nonce: None,
        }
    }

    /// Sets the authorized party (client ID).
    #[must_use]
    pub fn with_azp(mut self, client_id: impl Into<String>) -> Self {
        self.azp = Some(client_id.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.sid = Some(session_id.into());
        self
    }

    /// Sets the scope.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Sets the nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Checks if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.exp
    }
}

/// JWT audience claim (can be single string or array).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience.
    Single(String),
    /// Multiple audiences.
    Multiple(Vec<String>),
}

impl Audience {
    /// Checks if the audience contains a specific value.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::Single(s) => s == value,
            Self::Multiple(v) => v.iter().any(|s| s == value),
        }
    }

    /// Returns the audiences as a vector.
    #[must_use]
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => vec![s.as_str()],
            Self::Multiple(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

impl From<String> for Audience {
    fn from(s: String) -> Self {
        Self::Single(s)
    }
}

impl From<&str> for Audience {
    fn from(s: &str) -> Self {
        Self::Single(s.to_string())
    }
}

impl From<Vec<String>> for Audience {
    fn from(v: Vec<String>) -> Self {
        match v.len() {
            1 => Self::Single(v.into_iter().next().expect("length checked")),
            _ => Self::Multiple(v),
        }
    }
}

/// Realm access (roles) claim.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealmAccess {
    /// List of realm-level roles.
    pub roles: Vec<String>,
}

/// Resource (client) access claim.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceAccess {
    /// List of client-level roles.
    pub roles: Vec<String>,
}

/// OIDC address claim structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressClaim {
    /// Full mailing address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Street address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,

    /// City or locality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,

    /// State, province, or region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Postal code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    /// Country.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn access_token_claims_serialization() {
        let claims = AccessTokenClaims::new(
            "https://auth.example.com".to_string(),
            "user123".to_string(),
            Utc::now() + Duration::hours(1),
        )
        .with_azp("my-client")
        .with_scope("openid profile email");

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"https://auth.example.com\""));
        assert!(json.contains("\"sub\":\"user123\""));
        assert!(json.contains("\"azp\":\"my-client\""));
    }

    #[test]
    fn id_token_claims_serialization() {
        let claims = IdTokenClaims::new(
            "https://auth.example.com".to_string(),
            "user123".to_string(),
            "my-client",
            Utc::now() + Duration::hours(1),
        )
        .with_nonce("abc123");

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"nonce\":\"abc123\""));
    }

    #[test]
    fn audience_contains() {
        let single = Audience::Single("client1".to_string());
        assert!(single.contains("client1"));
        assert!(!single.contains("client2"));

        let multiple = Audience::Multiple(vec!["client1".to_string(), "client2".to_string()]);
        assert!(multiple.contains("client1"));
        assert!(multiple.contains("client2"));
        assert!(!multiple.contains("client3"));
    }

    #[test]
    fn token_expiration_check() {
        let expired = AccessTokenClaims::new(
            "https://auth.example.com".to_string(),
            "user123".to_string(),
            Utc::now() - Duration::hours(1),
        );
        assert!(expired.is_expired());

        let valid = AccessTokenClaims::new(
            "https://auth.example.com".to_string(),
            "user123".to_string(),
            Utc::now() + Duration::hours(1),
        );
        assert!(!valid.is_expired());
    }
}
