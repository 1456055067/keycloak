//! Client DTOs for the Admin API.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use kc_model::{Client, Protocol};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create a new client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateClientRequest {
    /// Client identifier (OAuth client_id).
    pub client_id: String,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the client is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    // Client type
    /// Whether this is a public client.
    #[serde(default)]
    pub public_client: bool,
    /// Whether this is bearer-only.
    #[serde(default)]
    pub bearer_only: bool,
    /// Client secret (for confidential clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    // OAuth flows
    /// Enable Authorization Code flow.
    #[serde(default = "default_true")]
    pub standard_flow_enabled: bool,
    /// Enable Implicit flow.
    #[serde(default)]
    pub implicit_flow_enabled: bool,
    /// Enable Direct Access Grants.
    #[serde(default)]
    pub direct_access_grants_enabled: bool,
    /// Enable Service Account.
    #[serde(default)]
    pub service_accounts_enabled: bool,

    // URLs
    /// Root URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_url: Option<String>,
    /// Base URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Admin URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_url: Option<String>,
    /// Allowed redirect URIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// Allowed web origins (CORS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web_origins: Vec<String>,

    // Other settings
    /// Require user consent.
    #[serde(default)]
    pub consent_required: bool,
    /// Allow full scope.
    #[serde(default = "default_true")]
    pub full_scope_allowed: bool,
    /// Protocol (openid-connect or saml).
    #[serde(default)]
    pub protocol: Option<Protocol>,
    /// Custom attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl CreateClientRequest {
    /// Converts this request to a domain `Client` model.
    #[must_use]
    pub fn into_client(self, realm_id: Uuid) -> Client {
        let mut client = Client::new(realm_id, self.client_id);
        client.name = self.name;
        client.description = self.description;
        client.enabled = self.enabled;
        client.public_client = self.public_client;
        client.bearer_only = self.bearer_only;
        client.secret = self.secret;
        client.standard_flow_enabled = self.standard_flow_enabled;
        client.implicit_flow_enabled = self.implicit_flow_enabled;
        client.direct_access_grants_enabled = self.direct_access_grants_enabled;
        client.service_accounts_enabled = self.service_accounts_enabled;
        client.root_url = self.root_url;
        client.base_url = self.base_url;
        client.admin_url = self.admin_url;
        client.redirect_uris = self.redirect_uris.into_iter().collect();
        client.web_origins = self.web_origins.into_iter().collect();
        client.consent_required = self.consent_required;
        client.full_scope_allowed = self.full_scope_allowed;
        if let Some(protocol) = self.protocol {
            client.protocol = protocol;
        }
        client.attributes = self.attributes;
        client
    }
}

/// Request to update a client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClientRequest {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the client is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    // Client type
    /// Whether this is a public client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_client: Option<bool>,
    /// Whether this is bearer-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_only: Option<bool>,

    // OAuth flows
    /// Enable Authorization Code flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_flow_enabled: Option<bool>,
    /// Enable Implicit flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implicit_flow_enabled: Option<bool>,
    /// Enable Direct Access Grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_access_grants_enabled: Option<bool>,
    /// Enable Service Account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_accounts_enabled: Option<bool>,

    // URLs
    /// Root URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_url: Option<String>,
    /// Base URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Admin URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_url: Option<String>,
    /// Allowed redirect URIs (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed web origins (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_origins: Option<Vec<String>>,

    // Other settings
    /// Require user consent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_required: Option<bool>,
    /// Allow full scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_scope_allowed: Option<bool>,
    /// Custom attributes (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

impl UpdateClientRequest {
    /// Applies this update to an existing client.
    pub fn apply_to(&self, client: &mut Client) {
        if let Some(ref v) = self.name {
            client.name = Some(v.clone());
        }
        if let Some(ref v) = self.description {
            client.description = Some(v.clone());
        }
        if let Some(v) = self.enabled {
            client.enabled = v;
        }
        if let Some(v) = self.public_client {
            client.public_client = v;
        }
        if let Some(v) = self.bearer_only {
            client.bearer_only = v;
        }
        if let Some(v) = self.standard_flow_enabled {
            client.standard_flow_enabled = v;
        }
        if let Some(v) = self.implicit_flow_enabled {
            client.implicit_flow_enabled = v;
        }
        if let Some(v) = self.direct_access_grants_enabled {
            client.direct_access_grants_enabled = v;
        }
        if let Some(v) = self.service_accounts_enabled {
            client.service_accounts_enabled = v;
        }
        if let Some(ref v) = self.root_url {
            client.root_url = Some(v.clone());
        }
        if let Some(ref v) = self.base_url {
            client.base_url = Some(v.clone());
        }
        if let Some(ref v) = self.admin_url {
            client.admin_url = Some(v.clone());
        }
        if let Some(ref v) = self.redirect_uris {
            client.redirect_uris = v.iter().cloned().collect();
        }
        if let Some(ref v) = self.web_origins {
            client.web_origins = v.iter().cloned().collect();
        }
        if let Some(v) = self.consent_required {
            client.consent_required = v;
        }
        if let Some(v) = self.full_scope_allowed {
            client.full_scope_allowed = v;
        }
        if let Some(ref v) = self.attributes {
            client.attributes = v.clone();
        }
        client.updated_at = Utc::now();
    }
}

/// Full client representation for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRepresentation {
    /// Internal unique identifier.
    pub id: Uuid,
    /// Client identifier (OAuth client_id).
    pub client_id: String,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the client is enabled.
    pub enabled: bool,

    // Timestamps
    /// When the client was created.
    pub created_timestamp: i64,

    // Client type
    /// Whether this is a public client.
    pub public_client: bool,
    /// Whether this is bearer-only.
    pub bearer_only: bool,
    /// Client authenticator type.
    pub client_authenticator_type: String,

    // Protocol
    /// Protocol (openid-connect or saml).
    pub protocol: Protocol,

    // OAuth flows
    /// Authorization Code flow enabled.
    pub standard_flow_enabled: bool,
    /// Implicit flow enabled.
    pub implicit_flow_enabled: bool,
    /// Direct Access Grants enabled.
    pub direct_access_grants_enabled: bool,
    /// Service Account enabled.
    pub service_accounts_enabled: bool,

    // URLs
    /// Root URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_url: Option<String>,
    /// Base URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Admin URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_url: Option<String>,
    /// Allowed redirect URIs.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub redirect_uris: HashSet<String>,
    /// Allowed web origins.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub web_origins: HashSet<String>,

    // Other settings
    /// Require user consent.
    pub consent_required: bool,
    /// Allow full scope.
    pub full_scope_allowed: bool,
    /// Use front-channel logout.
    pub frontchannel_logout: bool,

    // Custom attributes
    /// Custom attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

impl From<Client> for ClientRepresentation {
    fn from(client: Client) -> Self {
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            enabled: client.enabled,
            created_timestamp: client.created_at.timestamp_millis(),
            public_client: client.public_client,
            bearer_only: client.bearer_only,
            client_authenticator_type: client.client_authenticator_type,
            protocol: client.protocol,
            standard_flow_enabled: client.standard_flow_enabled,
            implicit_flow_enabled: client.implicit_flow_enabled,
            direct_access_grants_enabled: client.direct_access_grants_enabled,
            service_accounts_enabled: client.service_accounts_enabled,
            root_url: client.root_url,
            base_url: client.base_url,
            admin_url: client.admin_url,
            redirect_uris: client.redirect_uris,
            web_origins: client.web_origins,
            consent_required: client.consent_required,
            full_scope_allowed: client.full_scope_allowed,
            frontchannel_logout: client.frontchannel_logout,
            attributes: client.attributes,
        }
    }
}

/// Summary client representation for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSummary {
    /// Internal unique identifier.
    pub id: Uuid,
    /// Client identifier (OAuth client_id).
    pub client_id: String,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the client is enabled.
    pub enabled: bool,
    /// Whether this is a public client.
    pub public_client: bool,
    /// Protocol type.
    pub protocol: Protocol,
}

impl From<Client> for ClientSummary {
    fn from(client: Client) -> Self {
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            enabled: client.enabled,
            public_client: client.public_client,
            protocol: client.protocol,
        }
    }
}

/// Query parameters for client search.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSearchParams {
    /// Search string (matches client_id, name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Filter by client_id prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Filter by enabled status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Filter by public client status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_client: Option<bool>,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// Starting offset for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<usize>,
}

impl ClientSearchParams {
    /// Converts to storage search criteria.
    #[must_use]
    pub fn into_criteria(self) -> kc_storage::client::ClientSearchCriteria {
        let mut criteria = kc_storage::client::ClientSearchCriteria::new();
        if let Some(s) = self.search {
            criteria = criteria.search(s);
        }
        if let Some(c) = self.client_id {
            criteria = criteria.client_id(c);
        }
        if let Some(e) = self.enabled {
            criteria = criteria.enabled(e);
        }
        if let Some(p) = self.public_client {
            criteria = criteria.public_client(p);
        }
        if let Some(m) = self.max {
            criteria = criteria.max_results(m);
        }
        if let Some(f) = self.first {
            criteria = criteria.offset(f);
        }
        criteria
    }
}

/// Response for client secret operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSecretResponse {
    /// The client secret value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_client_request_defaults() {
        let json = r#"{"clientId": "my-app"}"#;
        let req: CreateClientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.client_id, "my-app");
        assert!(req.enabled);
        assert!(req.standard_flow_enabled);
        assert!(!req.public_client);
    }

    #[test]
    fn create_client_request_to_client() {
        let realm_id = Uuid::now_v7();
        let req = CreateClientRequest {
            client_id: "spa-app".to_string(),
            name: Some("SPA Application".to_string()),
            description: None,
            enabled: true,
            public_client: true,
            bearer_only: false,
            secret: None,
            standard_flow_enabled: true,
            implicit_flow_enabled: false,
            direct_access_grants_enabled: false,
            service_accounts_enabled: false,
            root_url: Some("https://example.com".to_string()),
            base_url: None,
            admin_url: None,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            web_origins: vec!["https://example.com".to_string()],
            consent_required: false,
            full_scope_allowed: true,
            protocol: None,
            attributes: HashMap::new(),
        };

        let client = req.into_client(realm_id);
        assert_eq!(client.client_id, "spa-app");
        assert_eq!(client.name, Some("SPA Application".to_string()));
        assert!(client.public_client);
        assert!(client.redirect_uris.contains("https://example.com/callback"));
    }

    #[test]
    fn update_client_request_applies() {
        let realm_id = Uuid::now_v7();
        let mut client = Client::new(realm_id, "my-app");

        let update = UpdateClientRequest {
            enabled: Some(false),
            name: Some("Updated Name".to_string()),
            service_accounts_enabled: Some(true),
            ..Default::default()
        };

        update.apply_to(&mut client);
        assert!(!client.enabled);
        assert_eq!(client.name, Some("Updated Name".to_string()));
        assert!(client.service_accounts_enabled);
    }

    #[test]
    fn client_representation_from_client() {
        let realm_id = Uuid::now_v7();
        let client = Client::new(realm_id, "test-client")
            .with_name("Test Client")
            .with_redirect_uri("https://example.com/callback");

        let repr = ClientRepresentation::from(client);
        assert_eq!(repr.client_id, "test-client");
        assert_eq!(repr.name, Some("Test Client".to_string()));
        assert!(repr.redirect_uris.contains("https://example.com/callback"));
    }
}
