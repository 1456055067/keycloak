//! SAML AuthnRequest types.
//!
//! Authentication request message sent by a service provider to an identity provider.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{AuthnContextClass, NameIdPolicy, SamlBinding};

/// SAML Authentication Request.
///
/// An authentication request message sent from a service provider to an
/// identity provider requesting authentication of a principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnRequest {
    /// Unique identifier for this request.
    pub id: String,

    /// Version of the SAML protocol (always "2.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Timestamp when this request was issued.
    pub issue_instant: DateTime<Utc>,

    /// The entity ID of the service provider issuing the request.
    pub issuer: String,

    /// The URL where the response should be sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_service_url: Option<String>,

    /// Index into the SP's assertion consumer service list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_service_index: Option<u32>,

    /// The URL where the request originated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// Binding to use for the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_binding: Option<String>,

    /// Name ID policy constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_id_policy: Option<NameIdPolicy>,

    /// Requested authentication context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_authn_context: Option<RequestedAuthnContext>,

    /// Whether the IdP must authenticate the user directly.
    #[serde(default)]
    pub force_authn: bool,

    /// Whether the IdP must not interact with the user.
    #[serde(default)]
    pub is_passive: bool,

    /// Index into the SP's attribute consuming service list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_consuming_service_index: Option<u32>,

    /// A human-readable name for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,

    /// Consent obtained for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,

    /// SAML extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,

    /// The RelayState parameter (not part of SAML but commonly used).
    #[serde(skip)]
    pub relay_state: Option<String>,
}

fn default_version() -> String {
    "2.0".to_string()
}

impl AuthnRequest {
    /// Creates a new authentication request.
    #[must_use]
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            assertion_consumer_service_url: None,
            assertion_consumer_service_index: None,
            destination: None,
            protocol_binding: None,
            name_id_policy: None,
            requested_authn_context: None,
            force_authn: false,
            is_passive: false,
            attribute_consuming_service_index: None,
            provider_name: None,
            consent: None,
            extensions: None,
            relay_state: None,
        }
    }

    /// Creates a new authentication request with a custom ID.
    #[must_use]
    pub fn with_id(id: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::new(issuer)
        }
    }

    /// Sets the assertion consumer service URL.
    #[must_use]
    pub fn with_acs_url(mut self, url: impl Into<String>) -> Self {
        self.assertion_consumer_service_url = Some(url.into());
        self
    }

    /// Sets the destination URL.
    #[must_use]
    pub fn with_destination(mut self, url: impl Into<String>) -> Self {
        self.destination = Some(url.into());
        self
    }

    /// Sets the protocol binding for the response.
    #[must_use]
    pub fn with_binding(mut self, binding: SamlBinding) -> Self {
        self.protocol_binding = Some(binding.uri().to_string());
        self
    }

    /// Sets the name ID policy.
    #[must_use]
    pub fn with_name_id_policy(mut self, policy: NameIdPolicy) -> Self {
        self.name_id_policy = Some(policy);
        self
    }

    /// Sets the requested authentication context.
    #[must_use]
    pub fn with_authn_context(mut self, context: RequestedAuthnContext) -> Self {
        self.requested_authn_context = Some(context);
        self
    }

    /// Sets force authentication.
    #[must_use]
    pub const fn force_authn(mut self, force: bool) -> Self {
        self.force_authn = force;
        self
    }

    /// Sets passive authentication.
    #[must_use]
    pub const fn is_passive(mut self, passive: bool) -> Self {
        self.is_passive = passive;
        self
    }

    /// Sets the provider name.
    #[must_use]
    pub fn with_provider_name(mut self, name: impl Into<String>) -> Self {
        self.provider_name = Some(name.into());
        self
    }

    /// Sets the relay state.
    #[must_use]
    pub fn with_relay_state(mut self, state: impl Into<String>) -> Self {
        self.relay_state = Some(state.into());
        self
    }

    /// Returns the parsed protocol binding.
    #[must_use]
    pub fn parsed_binding(&self) -> Option<SamlBinding> {
        self.protocol_binding.as_deref().and_then(SamlBinding::from_uri)
    }

    /// Validates the basic structure of this request.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("ID is required".to_string());
        }
        if self.version != "2.0" {
            return Err(format!("Unsupported SAML version: {}", self.version));
        }
        if self.issuer.is_empty() {
            return Err("Issuer is required".to_string());
        }
        Ok(())
    }
}

/// Requested authentication context.
///
/// Specifies the authentication context requirements for the request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestedAuthnContext {
    /// Comparison method for the authentication context.
    #[serde(default)]
    pub comparison: AuthnContextComparison,

    /// List of acceptable authentication context class references.
    #[serde(default)]
    pub authn_context_class_refs: Vec<String>,

    /// List of acceptable authentication context declaration references.
    #[serde(default)]
    pub authn_context_decl_refs: Vec<String>,
}

impl RequestedAuthnContext {
    /// Creates a new requested authentication context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            comparison: AuthnContextComparison::Exact,
            authn_context_class_refs: Vec::new(),
            authn_context_decl_refs: Vec::new(),
        }
    }

    /// Creates a context requiring exact match of a class reference.
    #[must_use]
    pub fn exact(class: AuthnContextClass) -> Self {
        Self {
            comparison: AuthnContextComparison::Exact,
            authn_context_class_refs: vec![class.uri().to_string()],
            authn_context_decl_refs: Vec::new(),
        }
    }

    /// Adds a class reference.
    #[must_use]
    pub fn with_class_ref(mut self, class: AuthnContextClass) -> Self {
        self.authn_context_class_refs.push(class.uri().to_string());
        self
    }

    /// Sets the comparison method.
    #[must_use]
    pub const fn with_comparison(mut self, comparison: AuthnContextComparison) -> Self {
        self.comparison = comparison;
        self
    }
}

/// Authentication context comparison methods.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthnContextComparison {
    /// Exact match required.
    #[default]
    Exact,
    /// Match must be at least as strong.
    Minimum,
    /// Match must be at most as strong.
    Maximum,
    /// Any of the listed contexts acceptable.
    Better,
}

impl AuthnContextComparison {
    /// Returns the string value for this comparison.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Minimum => "minimum",
            Self::Maximum => "maximum",
            Self::Better => "better",
        }
    }
}

/// SAML extensions container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Extensions {
    /// Raw extension content.
    #[serde(default)]
    pub content: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authn_request_creation() {
        let request = AuthnRequest::new("https://sp.example.com")
            .with_acs_url("https://sp.example.com/acs")
            .with_destination("https://idp.example.com/sso")
            .with_binding(SamlBinding::HttpPost)
            .force_authn(true);

        assert!(!request.id.is_empty());
        assert_eq!(request.version, "2.0");
        assert_eq!(request.issuer, "https://sp.example.com");
        assert_eq!(
            request.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert!(request.force_authn);
        assert_eq!(request.parsed_binding(), Some(SamlBinding::HttpPost));
    }

    #[test]
    fn authn_request_validation() {
        let request = AuthnRequest::new("https://sp.example.com");
        assert!(request.validate().is_ok());

        let mut invalid = request.clone();
        invalid.id = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = request.clone();
        invalid.issuer = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = request;
        invalid.version = "1.1".to_string();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn requested_authn_context() {
        let context = RequestedAuthnContext::exact(AuthnContextClass::PasswordProtectedTransport)
            .with_comparison(AuthnContextComparison::Minimum);

        assert_eq!(context.comparison, AuthnContextComparison::Minimum);
        assert_eq!(context.authn_context_class_refs.len(), 1);
    }
}
