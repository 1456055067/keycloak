//! Client domain model.
//!
//! Clients represent applications that can request authentication
//! and authorization from Keycloak (OAuth 2.0 / OIDC clients).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol type for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// `OpenID` Connect protocol.
    #[default]
    OpenidConnect,
    /// SAML 2.0 protocol.
    Saml,
}

/// Client type based on OAuth 2.0 client types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// Confidential client (can keep secrets).
    #[default]
    Confidential,
    /// Public client (cannot keep secrets, e.g., SPAs, mobile apps).
    Public,
    /// Bearer-only client (only validates tokens, no login).
    BearerOnly,
}

/// A Keycloak client (OAuth 2.0 / OIDC application).
///
/// Clients represent applications that integrate with Keycloak for
/// authentication and authorization. They can be confidential (server-side)
/// or public (browser/mobile).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Domain model naturally has many boolean flags
pub struct Client {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// Realm this client belongs to.
    pub realm_id: Uuid,
    /// Unique client identifier (OAuth `client_id`).
    pub client_id: String,
    /// Display name.
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Whether the client is enabled.
    pub enabled: bool,

    // === Timestamps ===
    /// When the client was created.
    pub created_at: DateTime<Utc>,
    /// When the client was last updated.
    pub updated_at: DateTime<Utc>,

    // === Protocol ===
    /// Protocol type (OIDC or SAML).
    pub protocol: Protocol,

    // === Client Type ===
    /// Client secret (for confidential clients).
    pub secret: Option<String>,
    /// Whether this is a public client.
    pub public_client: bool,
    /// Whether this is bearer-only (no login, just token validation).
    pub bearer_only: bool,

    // === Authentication Settings ===
    /// Client authenticator type (e.g., "client-secret", "client-jwt").
    pub client_authenticator_type: String,
    /// Require user consent for scopes.
    pub consent_required: bool,
    /// Token not-before timestamp.
    pub not_before: i64,

    // === OAuth Flows ===
    /// Enable Authorization Code flow.
    pub standard_flow_enabled: bool,
    /// Enable Implicit flow (not recommended).
    pub implicit_flow_enabled: bool,
    /// Enable Direct Access Grants (Resource Owner Password).
    pub direct_access_grants_enabled: bool,
    /// Enable Service Account (Client Credentials flow).
    pub service_accounts_enabled: bool,

    // === URLs ===
    /// Root URL for relative redirects.
    pub root_url: Option<String>,
    /// Base URL for the client.
    pub base_url: Option<String>,
    /// Admin URL for backchannel operations.
    pub admin_url: Option<String>,
    /// Allowed redirect URIs.
    pub redirect_uris: HashSet<String>,
    /// Allowed web origins (CORS).
    pub web_origins: HashSet<String>,

    // === Logout ===
    /// Use front-channel logout.
    pub frontchannel_logout: bool,

    // === Scope ===
    /// Allow full scope (all realm roles).
    pub full_scope_allowed: bool,

    // === Admin Console ===
    /// Always show in admin console.
    pub always_display_in_console: bool,

    // === Custom Attributes ===
    /// Custom client attributes.
    pub attributes: HashMap<String, String>,

    // === Authentication Flow Bindings ===
    /// Custom authentication flow bindings.
    pub auth_flow_bindings: HashMap<String, Uuid>,
}

impl Client {
    /// Creates a new client with the given client ID.
    #[must_use]
    pub fn new(realm_id: Uuid, client_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            realm_id,
            client_id: client_id.into(),
            name: None,
            description: None,
            enabled: true,
            created_at: now,
            updated_at: now,
            protocol: Protocol::default(),
            secret: None,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: "client-secret".to_string(),
            consent_required: false,
            not_before: 0,
            standard_flow_enabled: true,
            implicit_flow_enabled: false,
            direct_access_grants_enabled: false,
            service_accounts_enabled: false,
            root_url: None,
            base_url: None,
            admin_url: None,
            redirect_uris: HashSet::new(),
            web_origins: HashSet::new(),
            frontchannel_logout: false,
            full_scope_allowed: true,
            always_display_in_console: false,
            attributes: HashMap::new(),
            auth_flow_bindings: HashMap::new(),
        }
    }

    /// Creates a public client.
    #[must_use]
    pub fn new_public(realm_id: Uuid, client_id: impl Into<String>) -> Self {
        let mut client = Self::new(realm_id, client_id);
        client.public_client = true;
        client.secret = None;
        client
    }

    /// Creates a confidential client with a secret.
    #[must_use]
    pub fn new_confidential(
        realm_id: Uuid,
        client_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        let mut client = Self::new(realm_id, client_id);
        client.public_client = false;
        client.secret = Some(secret.into());
        client
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds a redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.insert(uri.into());
        self
    }

    /// Adds a web origin.
    #[must_use]
    pub fn with_web_origin(mut self, origin: impl Into<String>) -> Self {
        self.web_origins.insert(origin.into());
        self
    }

    /// Enables service account (Client Credentials flow).
    #[must_use]
    pub const fn with_service_account(mut self) -> Self {
        self.service_accounts_enabled = true;
        self
    }

    /// Enables direct access grants (Resource Owner Password).
    #[must_use]
    pub const fn with_direct_access_grants(mut self) -> Self {
        self.direct_access_grants_enabled = true;
        self
    }

    /// Gets the client type.
    #[must_use]
    pub const fn client_type(&self) -> ClientType {
        if self.bearer_only {
            ClientType::BearerOnly
        } else if self.public_client {
            ClientType::Public
        } else {
            ClientType::Confidential
        }
    }

    /// Checks if the redirect URI is valid for this client.
    #[must_use]
    pub fn is_valid_redirect_uri(&self, uri: &str) -> bool {
        // Exact match
        if self.redirect_uris.contains(uri) {
            return true;
        }

        // Wildcard match (ends with /*)
        for pattern in &self.redirect_uris {
            if let Some(prefix) = pattern.strip_suffix("/*")
                && uri.starts_with(prefix)
            {
                return true;
            }
        }

        false
    }

    /// Checks if the origin is allowed for CORS.
    #[must_use]
    pub fn is_valid_origin(&self, origin: &str) -> bool {
        // Wildcard allows all
        if self.web_origins.contains("*") {
            return true;
        }

        // Check if origin matches any configured origin
        self.web_origins.contains(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_has_defaults() {
        let realm_id = Uuid::now_v7();
        let client = Client::new(realm_id, "my-app");

        assert_eq!(client.client_id, "my-app");
        assert!(client.enabled);
        assert!(client.standard_flow_enabled);
        assert!(!client.public_client);
        assert_eq!(client.protocol, Protocol::OpenidConnect);
    }

    #[test]
    fn public_client_creation() {
        let realm_id = Uuid::now_v7();
        let client = Client::new_public(realm_id, "spa-app");

        assert!(client.public_client);
        assert!(client.secret.is_none());
        assert_eq!(client.client_type(), ClientType::Public);
    }

    #[test]
    fn confidential_client_creation() {
        let realm_id = Uuid::now_v7();
        let client = Client::new_confidential(realm_id, "backend", "secret123");

        assert!(!client.public_client);
        assert_eq!(client.secret, Some("secret123".to_string()));
        assert_eq!(client.client_type(), ClientType::Confidential);
    }

    #[test]
    fn redirect_uri_validation() {
        let realm_id = Uuid::now_v7();
        let client = Client::new(realm_id, "app")
            .with_redirect_uri("https://example.com/callback")
            .with_redirect_uri("https://example.com/app/*");

        assert!(client.is_valid_redirect_uri("https://example.com/callback"));
        assert!(client.is_valid_redirect_uri("https://example.com/app/page"));
        assert!(client.is_valid_redirect_uri("https://example.com/app/deep/path"));
        assert!(!client.is_valid_redirect_uri("https://evil.com/callback"));
    }

    #[test]
    fn origin_validation() {
        let realm_id = Uuid::now_v7();
        let client = Client::new(realm_id, "app").with_web_origin("https://example.com");

        assert!(client.is_valid_origin("https://example.com"));
        assert!(!client.is_valid_origin("https://other.com"));

        // Wildcard client
        let wildcard_client = Client::new(realm_id, "app2").with_web_origin("*");
        assert!(wildcard_client.is_valid_origin("https://anything.com"));
    }
}
