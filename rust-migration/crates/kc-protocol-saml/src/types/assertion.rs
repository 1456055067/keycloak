//! SAML Assertion types.
//!
//! Assertions contain statements about a subject made by an issuer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{AuthnContextClass, NameId};

/// SAML Assertion.
///
/// A package of information that supplies one or more statements made
/// by a SAML authority (the issuer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    /// Unique identifier for this assertion.
    pub id: String,

    /// Version of the SAML protocol (always "2.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Timestamp when this assertion was issued.
    pub issue_instant: DateTime<Utc>,

    /// The entity ID of the identity provider that issued this assertion.
    pub issuer: String,

    /// The subject of this assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,

    /// Conditions that must be evaluated for the assertion to be valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,

    /// Authentication statement describing how the subject authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authn_statement: Option<AuthnStatement>,

    /// Attribute statement containing attributes about the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_statement: Option<AttributeStatement>,

    /// Whether this assertion has been signed.
    #[serde(skip)]
    pub signed: bool,
}

fn default_version() -> String {
    "2.0".to_string()
}

impl Assertion {
    /// Creates a new assertion.
    #[must_use]
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            subject: None,
            conditions: None,
            authn_statement: None,
            attribute_statement: None,
            signed: false,
        }
    }

    /// Creates a new assertion with a custom ID.
    #[must_use]
    pub fn with_id(id: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::new(issuer)
        }
    }

    /// Sets the subject.
    #[must_use]
    pub fn with_subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Sets the conditions.
    #[must_use]
    pub fn with_conditions(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// Sets the authentication statement.
    #[must_use]
    pub fn with_authn_statement(mut self, statement: AuthnStatement) -> Self {
        self.authn_statement = Some(statement);
        self
    }

    /// Sets the attribute statement.
    #[must_use]
    pub fn with_attribute_statement(mut self, statement: AttributeStatement) -> Self {
        self.attribute_statement = Some(statement);
        self
    }

    /// Validates the assertion conditions.
    ///
    /// Returns `Ok(())` if the assertion is valid, or an error message if not.
    pub fn validate(&self, audience: &str, now: DateTime<Utc>) -> Result<(), String> {
        // Check version
        if self.version != "2.0" {
            return Err(format!("Unsupported SAML version: {}", self.version));
        }

        // Check conditions if present
        if let Some(ref conditions) = self.conditions {
            // Check time constraints
            if let Some(not_before) = conditions.not_before {
                if now < not_before {
                    return Err("Assertion not yet valid".to_string());
                }
            }
            if let Some(not_on_or_after) = conditions.not_on_or_after {
                if now >= not_on_or_after {
                    return Err("Assertion has expired".to_string());
                }
            }

            // Check audience restriction
            if !conditions.audience_restrictions.is_empty() {
                let valid_audience = conditions
                    .audience_restrictions
                    .iter()
                    .any(|ar| ar.audiences.iter().any(|a| a == audience));
                if !valid_audience {
                    return Err(format!("Invalid audience: expected {audience}"));
                }
            }
        }

        Ok(())
    }
}

/// Subject of an assertion.
///
/// Identifies the principal that is the subject of all statements in the assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// The name identifier for the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_id: Option<NameId>,

    /// Subject confirmation data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_confirmations: Vec<SubjectConfirmation>,
}

impl Subject {
    /// Creates a new subject with a name ID.
    #[must_use]
    pub fn new(name_id: NameId) -> Self {
        Self {
            name_id: Some(name_id),
            subject_confirmations: Vec::new(),
        }
    }

    /// Adds a subject confirmation.
    #[must_use]
    pub fn with_confirmation(mut self, confirmation: SubjectConfirmation) -> Self {
        self.subject_confirmations.push(confirmation);
        self
    }
}

/// Subject confirmation.
///
/// Information that allows the assertion consumer to confirm the subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectConfirmation {
    /// The confirmation method.
    pub method: String,

    /// Additional confirmation data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

impl SubjectConfirmation {
    /// Bearer confirmation method URI.
    pub const BEARER: &'static str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    /// Holder of key confirmation method URI.
    pub const HOLDER_OF_KEY: &'static str = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

    /// Sender vouches confirmation method URI.
    pub const SENDER_VOUCHES: &'static str = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

    /// Creates a bearer confirmation.
    #[must_use]
    pub fn bearer() -> Self {
        Self {
            method: Self::BEARER.to_string(),
            subject_confirmation_data: None,
        }
    }

    /// Sets the confirmation data.
    #[must_use]
    pub fn with_data(mut self, data: SubjectConfirmationData) -> Self {
        self.subject_confirmation_data = Some(data);
        self
    }
}

/// Subject confirmation data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectConfirmationData {
    /// The request ID that this assertion responds to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_response_to: Option<String>,

    /// Time after which the subject can no longer be confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_on_or_after: Option<DateTime<Utc>>,

    /// Time before which the subject cannot be confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,

    /// The location to which the assertion can be presented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// IP address of the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl SubjectConfirmationData {
    /// Creates new subject confirmation data for a request.
    #[must_use]
    pub fn for_request(request_id: impl Into<String>, recipient: impl Into<String>) -> Self {
        Self {
            in_response_to: Some(request_id.into()),
            recipient: Some(recipient.into()),
            not_on_or_after: Some(Utc::now() + chrono::Duration::minutes(5)),
            not_before: None,
            address: None,
        }
    }
}

/// Conditions for assertion validity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    /// Time before which the assertion is not valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,

    /// Time at or after which the assertion is not valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_on_or_after: Option<DateTime<Utc>>,

    /// Audience restrictions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience_restrictions: Vec<AudienceRestriction>,

    /// One-time use condition.
    #[serde(default)]
    pub one_time_use: bool,

    /// Proxy restriction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_restriction: Option<ProxyRestriction>,
}

impl Conditions {
    /// Creates new conditions with default validity period.
    #[must_use]
    pub fn with_validity(validity_minutes: i64) -> Self {
        let now = Utc::now();
        Self {
            not_before: Some(now),
            not_on_or_after: Some(now + chrono::Duration::minutes(validity_minutes)),
            audience_restrictions: Vec::new(),
            one_time_use: false,
            proxy_restriction: None,
        }
    }

    /// Adds an audience restriction.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience_restrictions.push(AudienceRestriction {
            audiences: vec![audience.into()],
        });
        self
    }

    /// Sets the one-time use flag.
    #[must_use]
    pub const fn one_time_use(mut self) -> Self {
        self.one_time_use = true;
        self
    }
}

/// Audience restriction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AudienceRestriction {
    /// List of valid audiences.
    pub audiences: Vec<String>,
}

/// Proxy restriction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyRestriction {
    /// Maximum number of proxies allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,

    /// List of allowed proxy audiences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
}

/// Authentication statement.
///
/// Describes the act of authentication performed by the subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnStatement {
    /// The time of authentication.
    pub authn_instant: DateTime<Utc>,

    /// The session index (for session management).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_index: Option<String>,

    /// Time at which the session ends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_not_on_or_after: Option<DateTime<Utc>>,

    /// The authentication context.
    pub authn_context: AuthnContext,

    /// The subject locality information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_locality: Option<SubjectLocality>,
}

impl AuthnStatement {
    /// Creates a new authentication statement.
    #[must_use]
    pub fn new(context_class: AuthnContextClass) -> Self {
        Self {
            authn_instant: Utc::now(),
            session_index: Some(format!("_session{}", uuid::Uuid::new_v4())),
            session_not_on_or_after: None,
            authn_context: AuthnContext::class_ref(context_class),
            subject_locality: None,
        }
    }

    /// Sets the session timeout.
    #[must_use]
    pub fn with_session_timeout(mut self, timeout_minutes: i64) -> Self {
        self.session_not_on_or_after =
            Some(Utc::now() + chrono::Duration::minutes(timeout_minutes));
        self
    }

    /// Sets the subject locality.
    #[must_use]
    pub fn with_locality(mut self, address: impl Into<String>) -> Self {
        self.subject_locality = Some(SubjectLocality {
            address: Some(address.into()),
            dns_name: None,
        });
        self
    }
}

/// Authentication context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnContext {
    /// Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authn_context_class_ref: Option<String>,

    /// Authentication context declaration reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authn_context_decl_ref: Option<String>,

    /// Authenticating authorities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticating_authorities: Vec<String>,
}

impl AuthnContext {
    /// Creates an authentication context with a class reference.
    #[must_use]
    pub fn class_ref(class: AuthnContextClass) -> Self {
        Self {
            authn_context_class_ref: Some(class.uri().to_string()),
            authn_context_decl_ref: None,
            authenticating_authorities: Vec::new(),
        }
    }
}

/// Subject locality information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectLocality {
    /// IP address of the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// DNS name of the system from which the subject authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
}

/// Attribute statement.
///
/// Contains attributes about the subject.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeStatement {
    /// List of attributes.
    pub attributes: Vec<Attribute>,
}

impl AttributeStatement {
    /// Creates a new empty attribute statement.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    /// Adds an attribute.
    #[must_use]
    pub fn with_attribute(mut self, attr: Attribute) -> Self {
        self.attributes.push(attr);
        self
    }

    /// Creates an attribute statement from a map.
    #[must_use]
    pub fn from_map(attrs: HashMap<String, Vec<String>>) -> Self {
        let attributes = attrs
            .into_iter()
            .map(|(name, values)| Attribute {
                name,
                name_format: None,
                friendly_name: None,
                values,
            })
            .collect();
        Self { attributes }
    }
}

/// SAML Attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    /// The attribute name (typically a URI).
    pub name: String,

    /// The format of the attribute name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,

    /// A human-readable name for the attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,

    /// The attribute values.
    pub values: Vec<String>,
}

impl Attribute {
    /// URI name format.
    pub const NAME_FORMAT_URI: &'static str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

    /// Basic name format.
    pub const NAME_FORMAT_BASIC: &'static str =
        "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    /// Unspecified name format.
    pub const NAME_FORMAT_UNSPECIFIED: &'static str =
        "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

    /// Creates a new attribute with a single value.
    #[must_use]
    pub fn single(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            name_format: None,
            friendly_name: None,
            values: vec![value.into()],
        }
    }

    /// Creates a new attribute with multiple values.
    #[must_use]
    pub fn multi(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            name: name.into(),
            name_format: None,
            friendly_name: None,
            values,
        }
    }

    /// Sets the friendly name.
    #[must_use]
    pub fn with_friendly_name(mut self, name: impl Into<String>) -> Self {
        self.friendly_name = Some(name.into());
        self
    }

    /// Sets the name format.
    #[must_use]
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.name_format = Some(format.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_creation() {
        let assertion = Assertion::new("https://idp.example.com")
            .with_subject(Subject::new(NameId::email("user@example.com")))
            .with_conditions(Conditions::with_validity(5).with_audience("https://sp.example.com"))
            .with_authn_statement(AuthnStatement::new(
                AuthnContextClass::PasswordProtectedTransport,
            ));

        assert!(!assertion.id.is_empty());
        assert_eq!(assertion.issuer, "https://idp.example.com");
        assert!(assertion.subject.is_some());
        assert!(assertion.conditions.is_some());
        assert!(assertion.authn_statement.is_some());
    }

    #[test]
    fn assertion_validation() {
        // Create the assertion first, then capture time for validation
        // Use a time slightly in the future to avoid timing issues
        let assertion = Assertion::new("https://idp.example.com").with_conditions(
            Conditions::with_validity(5).with_audience("https://sp.example.com"),
        );

        // Use the assertion's not_before time as the validation time
        let validation_time = assertion
            .conditions
            .as_ref()
            .and_then(|c| c.not_before)
            .unwrap_or_else(Utc::now);

        assert!(assertion.validate("https://sp.example.com", validation_time).is_ok());
        assert!(assertion.validate("https://other.example.com", validation_time).is_err());
    }

    #[test]
    fn attribute_statement() {
        let stmt = AttributeStatement::new()
            .with_attribute(
                Attribute::single("email", "user@example.com").with_friendly_name("Email"),
            )
            .with_attribute(Attribute::multi(
                "roles",
                vec!["admin".to_string(), "user".to_string()],
            ));

        assert_eq!(stmt.attributes.len(), 2);
        assert_eq!(stmt.attributes[0].values[0], "user@example.com");
        assert_eq!(stmt.attributes[1].values.len(), 2);
    }
}
