//! SAML Status types.
//!
//! Status information returned in SAML protocol responses.

use serde::{Deserialize, Serialize};

use super::status_codes;

/// SAML protocol status.
///
/// Contains the status code and optional message for a SAML response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The status code.
    pub status_code: StatusCode,

    /// Optional status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,

    /// Optional detailed status information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
}

impl Status {
    /// Creates a success status.
    #[must_use]
    pub fn success() -> Self {
        Self {
            status_code: StatusCode::success(),
            status_message: None,
            status_detail: None,
        }
    }

    /// Creates a requester error status.
    #[must_use]
    pub fn requester_error(message: impl Into<String>) -> Self {
        Self {
            status_code: StatusCode::requester(),
            status_message: Some(message.into()),
            status_detail: None,
        }
    }

    /// Creates a responder error status.
    #[must_use]
    pub fn responder_error(message: impl Into<String>) -> Self {
        Self {
            status_code: StatusCode::responder(),
            status_message: Some(message.into()),
            status_detail: None,
        }
    }

    /// Creates an authentication failed status.
    #[must_use]
    pub fn authn_failed(message: impl Into<String>) -> Self {
        Self {
            status_code: StatusCode::authn_failed(),
            status_message: Some(message.into()),
            status_detail: None,
        }
    }

    /// Returns true if this status indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status_code.value == status_codes::SUCCESS
    }

    /// Sets the status message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.status_message = Some(message.into());
        self
    }

    /// Sets the status detail.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.status_detail = Some(detail.into());
        self
    }
}

impl Default for Status {
    fn default() -> Self {
        Self::success()
    }
}

/// SAML status code.
///
/// Status codes can be nested, with a top-level code and optional sub-code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCode {
    /// The status code URI value.
    pub value: String,

    /// Optional nested status code providing more detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<Box<StatusCode>>,
}

impl StatusCode {
    /// Creates a new status code with the given value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            status_code: None,
        }
    }

    /// Creates a success status code.
    #[must_use]
    pub fn success() -> Self {
        Self::new(status_codes::SUCCESS)
    }

    /// Creates a requester error status code.
    #[must_use]
    pub fn requester() -> Self {
        Self::new(status_codes::REQUESTER)
    }

    /// Creates a responder error status code.
    #[must_use]
    pub fn responder() -> Self {
        Self::new(status_codes::RESPONDER)
    }

    /// Creates a version mismatch status code.
    #[must_use]
    pub fn version_mismatch() -> Self {
        Self::new(status_codes::VERSION_MISMATCH)
    }

    /// Creates an authentication failed status code.
    #[must_use]
    pub fn authn_failed() -> Self {
        Self {
            value: status_codes::REQUESTER.to_string(),
            status_code: Some(Box::new(Self::new(
                "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            ))),
        }
    }

    /// Adds a sub-status code.
    #[must_use]
    pub fn with_sub_status(mut self, sub: StatusCode) -> Self {
        self.status_code = Some(Box::new(sub));
        self
    }

    /// Returns true if this is a success status code.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.value == status_codes::SUCCESS
    }

    /// Returns the sub-status code value if present.
    #[must_use]
    pub fn sub_status_value(&self) -> Option<&str> {
        self.status_code.as_ref().map(|s| s.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_success() {
        let status = Status::success();
        assert!(status.is_success());
        assert!(status.status_message.is_none());
    }

    #[test]
    fn status_error() {
        let status = Status::requester_error("Invalid request");
        assert!(!status.is_success());
        assert_eq!(status.status_message.as_deref(), Some("Invalid request"));
    }

    #[test]
    fn status_authn_failed() {
        let status = Status::authn_failed("Wrong password");
        assert!(!status.is_success());
        assert_eq!(
            status.status_code.sub_status_value(),
            Some("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
        );
    }

    #[test]
    fn status_code_with_sub() {
        let code =
            StatusCode::requester().with_sub_status(StatusCode::new("custom:status:SubCode"));
        assert!(!code.is_success());
        assert_eq!(code.sub_status_value(), Some("custom:status:SubCode"));
    }
}
