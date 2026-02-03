//! SAML Name ID types.
//!
//! Name identifiers are used to identify subjects in SAML assertions.

use serde::{Deserialize, Serialize};

use super::NameIdFormat;

/// SAML Name ID.
///
/// Represents the identifier of a subject in a SAML assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameId {
    /// The actual identifier value.
    pub value: String,

    /// The format of the name identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// The security or administrative domain that qualifies the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_qualifier: Option<String>,

    /// The service provider's entity ID that qualifies the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_name_qualifier: Option<String>,

    /// A provider identifier for the SP that was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_provided_id: Option<String>,
}

impl NameId {
    /// Creates a new name ID with the given value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Creates a new email name ID.
    #[must_use]
    pub fn email(email: impl Into<String>) -> Self {
        Self {
            value: email.into(),
            format: Some(NameIdFormat::Email.uri().to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Creates a new persistent name ID.
    #[must_use]
    pub fn persistent(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            format: Some(NameIdFormat::Persistent.uri().to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Creates a new transient name ID.
    #[must_use]
    pub fn transient(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            format: Some(NameIdFormat::Transient.uri().to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Sets the format for this name ID.
    #[must_use]
    pub fn with_format(mut self, format: NameIdFormat) -> Self {
        self.format = Some(format.uri().to_string());
        self
    }

    /// Sets the name qualifier.
    #[must_use]
    pub fn with_name_qualifier(mut self, qualifier: impl Into<String>) -> Self {
        self.name_qualifier = Some(qualifier.into());
        self
    }

    /// Sets the SP name qualifier.
    #[must_use]
    pub fn with_sp_name_qualifier(mut self, qualifier: impl Into<String>) -> Self {
        self.sp_name_qualifier = Some(qualifier.into());
        self
    }

    /// Returns the parsed name ID format.
    #[must_use]
    pub fn parsed_format(&self) -> NameIdFormat {
        self.format
            .as_deref()
            .and_then(NameIdFormat::from_uri)
            .unwrap_or_default()
    }
}

/// Name ID policy for authentication requests.
///
/// Specifies constraints on the name identifier to be returned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameIdPolicy {
    /// The requested name ID format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// The SP name qualifier for the name ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_name_qualifier: Option<String>,

    /// Whether a new identifier should be created for this request.
    #[serde(default)]
    pub allow_create: bool,
}

impl NameIdPolicy {
    /// Creates a new name ID policy with no constraints.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            format: None,
            sp_name_qualifier: None,
            allow_create: false,
        }
    }

    /// Creates a policy requesting a specific format.
    #[must_use]
    pub fn with_format(format: NameIdFormat) -> Self {
        Self {
            format: Some(format.uri().to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        }
    }

    /// Sets whether new identifiers can be created.
    #[must_use]
    pub const fn allow_create(mut self, allow: bool) -> Self {
        self.allow_create = allow;
        self
    }

    /// Returns the parsed name ID format.
    #[must_use]
    pub fn parsed_format(&self) -> Option<NameIdFormat> {
        self.format.as_deref().and_then(NameIdFormat::from_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_id_email() {
        let name_id = NameId::email("user@example.com");
        assert_eq!(name_id.value, "user@example.com");
        assert_eq!(name_id.parsed_format(), NameIdFormat::Email);
    }

    #[test]
    fn name_id_persistent() {
        let name_id = NameId::persistent("abc123");
        assert_eq!(name_id.value, "abc123");
        assert_eq!(name_id.parsed_format(), NameIdFormat::Persistent);
    }

    #[test]
    fn name_id_with_qualifiers() {
        let name_id = NameId::new("user")
            .with_format(NameIdFormat::Persistent)
            .with_name_qualifier("idp.example.com")
            .with_sp_name_qualifier("sp.example.com");

        assert_eq!(name_id.name_qualifier.as_deref(), Some("idp.example.com"));
        assert_eq!(name_id.sp_name_qualifier.as_deref(), Some("sp.example.com"));
    }

    #[test]
    fn name_id_policy_format() {
        let policy = NameIdPolicy::with_format(NameIdFormat::Email).allow_create(true);
        assert_eq!(policy.parsed_format(), Some(NameIdFormat::Email));
        assert!(policy.allow_create);
    }
}
