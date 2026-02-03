//! SAML Logout types.
//!
//! Single Logout (SLO) request and response messages.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{NameId, Status};

/// SAML Logout Request.
///
/// A request to terminate an existing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// Unique identifier for this request.
    pub id: String,

    /// Version of the SAML protocol (always "2.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Timestamp when this request was issued.
    pub issue_instant: DateTime<Utc>,

    /// The entity ID of the requester.
    pub issuer: String,

    /// The URL where this request was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// The consent obtained for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,

    /// The name identifier of the principal to log out.
    pub name_id: NameId,

    /// Session indexes to terminate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_indexes: Vec<String>,

    /// Reason for the logout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Time after which the request is no longer valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_on_or_after: Option<DateTime<Utc>>,

    /// The RelayState parameter (not part of SAML but commonly used).
    #[serde(skip)]
    pub relay_state: Option<String>,
}

fn default_version() -> String {
    "2.0".to_string()
}

impl LogoutRequest {
    /// User logout reason.
    pub const REASON_USER: &'static str = "urn:oasis:names:tc:SAML:2.0:logout:user";

    /// Admin logout reason.
    pub const REASON_ADMIN: &'static str = "urn:oasis:names:tc:SAML:2.0:logout:admin";

    /// Creates a new logout request.
    #[must_use]
    pub fn new(issuer: impl Into<String>, name_id: NameId) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            destination: None,
            consent: None,
            name_id,
            session_indexes: Vec::new(),
            reason: None,
            not_on_or_after: None,
            relay_state: None,
        }
    }

    /// Sets the destination URL.
    #[must_use]
    pub fn with_destination(mut self, url: impl Into<String>) -> Self {
        self.destination = Some(url.into());
        self
    }

    /// Adds a session index to terminate.
    #[must_use]
    pub fn with_session_index(mut self, index: impl Into<String>) -> Self {
        self.session_indexes.push(index.into());
        self
    }

    /// Sets the logout reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the relay state.
    #[must_use]
    pub fn with_relay_state(mut self, state: impl Into<String>) -> Self {
        self.relay_state = Some(state.into());
        self
    }

    /// Sets the validity period.
    #[must_use]
    pub fn valid_for(mut self, minutes: i64) -> Self {
        self.not_on_or_after = Some(Utc::now() + chrono::Duration::minutes(minutes));
        self
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
        if self.name_id.value.is_empty() {
            return Err("NameID is required".to_string());
        }
        Ok(())
    }

    /// Checks if the request has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.not_on_or_after
            .is_some_and(|not_after| Utc::now() >= not_after)
    }
}

/// SAML Logout Response.
///
/// A response to a logout request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Unique identifier for this response.
    pub id: String,

    /// Version of the SAML protocol (always "2.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Timestamp when this response was issued.
    pub issue_instant: DateTime<Utc>,

    /// The entity ID of the responder.
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

    /// The RelayState parameter (not part of SAML but commonly used).
    #[serde(skip)]
    pub relay_state: Option<String>,
}

impl LogoutResponse {
    /// Creates a new success logout response.
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
            relay_state: None,
        }
    }

    /// Creates a new error logout response.
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
            relay_state: None,
        }
    }

    /// Creates a partial logout response.
    #[must_use]
    pub fn partial_logout(issuer: impl Into<String>) -> Self {
        Self {
            id: format!("_id{}", uuid::Uuid::new_v4()),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            in_response_to: None,
            destination: None,
            consent: None,
            status: Status {
                status_code: super::StatusCode::success().with_sub_status(super::StatusCode::new(
                    "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
                )),
                status_message: Some("Some sessions could not be terminated".to_string()),
                status_detail: None,
            },
            relay_state: None,
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

    /// Sets the relay state.
    #[must_use]
    pub fn with_relay_state(mut self, state: impl Into<String>) -> Self {
        self.relay_state = Some(state.into());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_request_creation() {
        let request =
            LogoutRequest::new("https://sp.example.com", NameId::email("user@example.com"))
                .with_destination("https://idp.example.com/slo")
                .with_session_index("_session123")
                .with_reason(LogoutRequest::REASON_USER)
                .valid_for(5);

        assert!(!request.id.is_empty());
        assert_eq!(request.issuer, "https://sp.example.com");
        assert_eq!(request.name_id.value, "user@example.com");
        assert_eq!(request.session_indexes.len(), 1);
        assert!(request.validate().is_ok());
        assert!(!request.is_expired());
    }

    #[test]
    fn logout_response_success() {
        let response = LogoutResponse::success("https://idp.example.com")
            .in_response_to("_req123")
            .with_destination("https://sp.example.com/slo");

        assert!(response.is_success());
        assert_eq!(response.in_response_to.as_deref(), Some("_req123"));
        assert!(response.validate().is_ok());
    }

    #[test]
    fn logout_response_partial() {
        let response = LogoutResponse::partial_logout("https://idp.example.com");

        // Partial logout is technically a success with a sub-status
        assert!(response.is_success());
        assert!(response.status.status_message.is_some());
    }
}
