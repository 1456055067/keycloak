//! SAML Response types.
//!
//! Response messages sent by an identity provider to a service provider.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Assertion, Status};

/// SAML Response.
///
/// A response message sent from an identity provider to a service provider
/// containing authentication results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Unique identifier for this response.
    pub id: String,

    /// Version of the SAML protocol (always "2.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Timestamp when this response was issued.
    pub issue_instant: DateTime<Utc>,

    /// The entity ID of the identity provider that issued this response.
    pub issuer: String,

    /// The ID of the request this response is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_response_to: Option<String>,

    /// The URL where this response was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// The consent obtained for this response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,

    /// The status of the response.
    pub status: Status,

    /// The assertions in this response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<Assertion>,

    /// Encrypted assertions in this response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_assertions: Vec<EncryptedAssertion>,

    /// Whether this response has been signed.
    #[serde(skip)]
    pub signed: bool,
}

fn default_version() -> String {
    "2.0".to_string()
}

impl Response {
    /// Creates a new success response.
    #[must_use]
    pub fn success(issuer: impl Into<String>) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            in_response_to: None,
            destination: None,
            consent: None,
            status: Status::success(),
            assertions: Vec::new(),
            encrypted_assertions: Vec::new(),
            signed: false,
        }
    }

    /// Creates a new error response.
    #[must_use]
    pub fn error(issuer: impl Into<String>, status: Status) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            in_response_to: None,
            destination: None,
            consent: None,
            status,
            assertions: Vec::new(),
            encrypted_assertions: Vec::new(),
            signed: false,
        }
    }

    /// Sets the request ID this response is for.
    #[must_use]
    pub fn in_response_to(mut self, request_id: impl Into<String>) -> Self {
        self.in_response_to = Some(request_id.into());
        self
    }

    /// Sets the destination URL.
    #[must_use]
    pub fn with_destination(mut self, url: impl Into<String>) -> Self {
        self.destination = Some(url.into());
        self
    }

    /// Adds an assertion to this response.
    #[must_use]
    pub fn with_assertion(mut self, assertion: Assertion) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Adds an encrypted assertion to this response.
    #[must_use]
    pub fn with_encrypted_assertion(mut self, assertion: EncryptedAssertion) -> Self {
        self.encrypted_assertions.push(assertion);
        self
    }

    /// Returns true if this response indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Validates the basic structure of this response.
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

    /// Gets the first assertion if present.
    #[must_use]
    pub fn first_assertion(&self) -> Option<&Assertion> {
        self.assertions.first()
    }
}

/// Encrypted assertion placeholder.
///
/// Contains the encrypted XML data for an assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAssertion {
    /// The encrypted data.
    pub encrypted_data: EncryptedData,
}

/// Encrypted data structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encryption algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_method: Option<String>,

    /// Key info for decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<KeyInfo>,

    /// The cipher data.
    pub cipher_data: CipherData,
}

/// Key information for encryption/decryption.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Encrypted key data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<EncryptedKey>,

    /// Key name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
}

/// Encrypted key data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// The encryption algorithm used for the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_method: Option<String>,

    /// The cipher data containing the encrypted key.
    pub cipher_data: CipherData,
}

/// Cipher data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherData {
    /// The cipher value (base64 encoded).
    pub cipher_value: String,
}

/// Builder for creating SAML responses with assertions.
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    /// Creates a new response builder.
    #[must_use]
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            response: Response::success(issuer),
        }
    }

    /// Sets the request ID this response is for.
    #[must_use]
    pub fn in_response_to(mut self, request_id: impl Into<String>) -> Self {
        self.response.in_response_to = Some(request_id.into());
        self
    }

    /// Sets the destination URL.
    #[must_use]
    pub fn destination(mut self, url: impl Into<String>) -> Self {
        self.response.destination = Some(url.into());
        self
    }

    /// Sets the status.
    #[must_use]
    pub fn status(mut self, status: Status) -> Self {
        self.response.status = status;
        self
    }

    /// Adds an assertion.
    #[must_use]
    pub fn assertion(mut self, assertion: Assertion) -> Self {
        self.response.assertions.push(assertion);
        self
    }

    /// Builds the response.
    #[must_use]
    pub fn build(self) -> Response {
        self.response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_success() {
        let response = Response::success("https://idp.example.com")
            .in_response_to("_req123")
            .with_destination("https://sp.example.com/acs");

        assert!(response.is_success());
        assert!(!response.id.is_empty());
        assert_eq!(response.in_response_to.as_deref(), Some("_req123"));
        assert!(response.validate().is_ok());
    }

    #[test]
    fn response_error() {
        let response = Response::error(
            "https://idp.example.com",
            Status::authn_failed("Invalid credentials"),
        );

        assert!(!response.is_success());
        assert!(response.assertions.is_empty());
    }

    #[test]
    fn response_builder() {
        let response = ResponseBuilder::new("https://idp.example.com")
            .in_response_to("_req123")
            .destination("https://sp.example.com/acs")
            .assertion(Assertion::new("https://idp.example.com"))
            .build();

        assert!(response.is_success());
        assert_eq!(response.assertions.len(), 1);
    }

    #[test]
    fn response_validation() {
        let response = Response::success("https://idp.example.com");
        assert!(response.validate().is_ok());

        let mut invalid = response.clone();
        invalid.id = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = response;
        invalid.version = "1.1".to_string();
        assert!(invalid.validate().is_err());
    }
}
