//! Common OIDC types and definitions.
//!
//! Implements types from OAuth 2.0 and `OpenID` Connect specifications.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

/// OAuth 2.0 grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Authorization code grant (RFC 6749 Section 4.1).
    #[serde(rename = "authorization_code")]
    AuthorizationCode,

    /// Client credentials grant (RFC 6749 Section 4.4).
    #[serde(rename = "client_credentials")]
    ClientCredentials,

    /// Resource owner password credentials grant (RFC 6749 Section 4.3).
    /// Note: This grant type is deprecated and should be avoided.
    #[serde(rename = "password")]
    Password,

    /// Refresh token grant (RFC 6749 Section 6).
    #[serde(rename = "refresh_token")]
    RefreshToken,

    /// Device authorization grant (RFC 8628).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,

    /// Token exchange grant (RFC 8693).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
}

impl fmt::Display for GrantType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::Password => "password",
            Self::RefreshToken => "refresh_token",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
        };
        write!(f, "{s}")
    }
}

impl FromStr for GrantType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "client_credentials" => Ok(Self::ClientCredentials),
            "password" => Ok(Self::Password),
            "refresh_token" => Ok(Self::RefreshToken),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(Self::DeviceCode),
            "urn:ietf:params:oauth:grant-type:token-exchange" => Ok(Self::TokenExchange),
            _ => Err(format!("unknown grant type: {s}")),
        }
    }
}

/// OAuth 2.0 response types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    /// Authorization code response.
    #[serde(rename = "code")]
    Code,

    /// Implicit grant - access token.
    #[serde(rename = "token")]
    Token,

    /// `OpenID` Connect - ID token.
    #[serde(rename = "id_token")]
    IdToken,

    /// None (for logout).
    #[serde(rename = "none")]
    None,
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Code => "code",
            Self::Token => "token",
            Self::IdToken => "id_token",
            Self::None => "none",
        };
        write!(f, "{s}")
    }
}

impl FromStr for ResponseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(Self::Code),
            "token" => Ok(Self::Token),
            "id_token" => Ok(Self::IdToken),
            "none" => Ok(Self::None),
            _ => Err(format!("unknown response type: {s}")),
        }
    }
}

/// Combined response types (for hybrid flows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseTypes(pub HashSet<ResponseType>);

impl ResponseTypes {
    /// Creates a new response types set.
    #[must_use]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Checks if this is a code flow.
    #[must_use]
    pub fn is_code_flow(&self) -> bool {
        self.0.contains(&ResponseType::Code) && self.0.len() == 1
    }

    /// Checks if this is an implicit flow.
    #[must_use]
    pub fn is_implicit_flow(&self) -> bool {
        !self.0.contains(&ResponseType::Code)
            && (self.0.contains(&ResponseType::Token) || self.0.contains(&ResponseType::IdToken))
    }

    /// Checks if this is a hybrid flow.
    #[must_use]
    pub fn is_hybrid_flow(&self) -> bool {
        self.0.contains(&ResponseType::Code)
            && (self.0.contains(&ResponseType::Token) || self.0.contains(&ResponseType::IdToken))
    }
}

impl Default for ResponseTypes {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for ResponseTypes {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut types = HashSet::new();
        for part in s.split_whitespace() {
            types.insert(ResponseType::from_str(part)?);
        }
        Ok(Self(types))
    }
}

/// OAuth 2.0 response modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Query string parameters (default for code).
    #[serde(rename = "query")]
    #[default]
    Query,

    /// Fragment parameters (default for implicit).
    #[serde(rename = "fragment")]
    Fragment,

    /// Form POST.
    #[serde(rename = "form_post")]
    FormPost,
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        };
        write!(f, "{s}")
    }
}

/// OIDC display modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Display {
    /// Full user agent page.
    #[serde(rename = "page")]
    #[default]
    Page,

    /// Popup window.
    #[serde(rename = "popup")]
    Popup,

    /// Touch-optimized dialog.
    #[serde(rename = "touch")]
    Touch,

    /// Feature phone display.
    #[serde(rename = "wap")]
    Wap,
}

/// OIDC prompt values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    /// No UI should be displayed.
    #[serde(rename = "none")]
    None,

    /// Force re-authentication.
    #[serde(rename = "login")]
    Login,

    /// Force consent screen.
    #[serde(rename = "consent")]
    Consent,

    /// Force account selection.
    #[serde(rename = "select_account")]
    SelectAccount,
}

/// Token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum TokenType {
    /// Bearer token (RFC 6750).
    #[serde(rename = "Bearer")]
    #[default]
    Bearer,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer => write!(f, "Bearer"),
        }
    }
}

/// Subject type for `OpenID` Connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    /// Public subject identifier (same for all clients).
    #[serde(rename = "public")]
    #[default]
    Public,

    /// Pairwise subject identifier (different per client).
    #[serde(rename = "pairwise")]
    Pairwise,
}

/// PKCE code challenge methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CodeChallengeMethod {
    /// Plain code verifier.
    #[serde(rename = "plain")]
    Plain,

    /// SHA-256 hash of code verifier.
    #[serde(rename = "S256")]
    #[default]
    S256,
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::S256 => write!(f, "S256"),
        }
    }
}

impl FromStr for CodeChallengeMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(Self::Plain),
            "S256" => Ok(Self::S256),
            _ => Err(format!("unknown code challenge method: {s}")),
        }
    }
}

/// Standard OIDC scopes.
pub mod scopes {
    /// `OpenID` Connect scope (required for OIDC).
    pub const OPENID: &str = "openid";
    /// Profile scope (name, `family_name`, etc.).
    pub const PROFILE: &str = "profile";
    /// Email scope.
    pub const EMAIL: &str = "email";
    /// Address scope.
    pub const ADDRESS: &str = "address";
    /// Phone scope.
    pub const PHONE: &str = "phone";
    /// Offline access scope (for refresh tokens).
    pub const OFFLINE_ACCESS: &str = "offline_access";
}

/// Standard OIDC claim names.
pub mod claims {
    // Standard claims
    /// Subject identifier.
    pub const SUB: &str = "sub";
    /// Issuer identifier.
    pub const ISS: &str = "iss";
    /// Audience.
    pub const AUD: &str = "aud";
    /// Expiration time.
    pub const EXP: &str = "exp";
    /// Issued at time.
    pub const IAT: &str = "iat";
    /// Authentication time.
    pub const AUTH_TIME: &str = "auth_time";
    /// Nonce.
    pub const NONCE: &str = "nonce";
    /// Access token hash.
    pub const AT_HASH: &str = "at_hash";
    /// Code hash.
    pub const C_HASH: &str = "c_hash";
    /// Authentication context class reference.
    pub const ACR: &str = "acr";
    /// Authentication methods references.
    pub const AMR: &str = "amr";
    /// Authorized party.
    pub const AZP: &str = "azp";

    // Profile claims
    /// Full name.
    pub const NAME: &str = "name";
    /// Given name.
    pub const GIVEN_NAME: &str = "given_name";
    /// Family name.
    pub const FAMILY_NAME: &str = "family_name";
    /// Middle name.
    pub const MIDDLE_NAME: &str = "middle_name";
    /// Nickname.
    pub const NICKNAME: &str = "nickname";
    /// Preferred username.
    pub const PREFERRED_USERNAME: &str = "preferred_username";
    /// Profile URL.
    pub const PROFILE: &str = "profile";
    /// Picture URL.
    pub const PICTURE: &str = "picture";
    /// Website.
    pub const WEBSITE: &str = "website";
    /// Gender.
    pub const GENDER: &str = "gender";
    /// Birthdate.
    pub const BIRTHDATE: &str = "birthdate";
    /// Timezone.
    pub const ZONEINFO: &str = "zoneinfo";
    /// Locale.
    pub const LOCALE: &str = "locale";
    /// Last updated time.
    pub const UPDATED_AT: &str = "updated_at";

    // Email claims
    /// Email address.
    pub const EMAIL: &str = "email";
    /// Email verified.
    pub const EMAIL_VERIFIED: &str = "email_verified";

    // Phone claims
    /// Phone number.
    pub const PHONE_NUMBER: &str = "phone_number";
    /// Phone number verified.
    pub const PHONE_NUMBER_VERIFIED: &str = "phone_number_verified";

    // Address claim
    /// Address (structured).
    pub const ADDRESS: &str = "address";

    // Custom Keycloak claims
    /// Realm access (roles).
    pub const REALM_ACCESS: &str = "realm_access";
    /// Resource access (client roles).
    pub const RESOURCE_ACCESS: &str = "resource_access";
    /// Session ID.
    pub const SID: &str = "sid";
    /// Session state.
    pub const SESSION_STATE: &str = "session_state";
    /// Scope.
    pub const SCOPE: &str = "scope";
    /// Token type.
    pub const TYP: &str = "typ";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_type_from_str() {
        assert_eq!(
            GrantType::from_str("authorization_code").unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            GrantType::from_str("client_credentials").unwrap(),
            GrantType::ClientCredentials
        );
        assert!(GrantType::from_str("invalid").is_err());
    }

    #[test]
    fn response_types_flow_detection() {
        let code_only: ResponseTypes = "code".parse().unwrap();
        assert!(code_only.is_code_flow());
        assert!(!code_only.is_implicit_flow());
        assert!(!code_only.is_hybrid_flow());

        let implicit: ResponseTypes = "token id_token".parse().unwrap();
        assert!(!implicit.is_code_flow());
        assert!(implicit.is_implicit_flow());
        assert!(!implicit.is_hybrid_flow());

        let hybrid: ResponseTypes = "code id_token".parse().unwrap();
        assert!(!hybrid.is_code_flow());
        assert!(!hybrid.is_implicit_flow());
        assert!(hybrid.is_hybrid_flow());
    }
}
