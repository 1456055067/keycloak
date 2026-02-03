//! SAML error types.
//!
//! Provides error types for SAML operations including parsing, validation,
//! signature verification, and protocol errors.

use thiserror::Error;

/// Result type for SAML operations.
pub type SamlResult<T> = Result<T, SamlError>;

/// SAML protocol errors.
#[derive(Debug, Error)]
pub enum SamlError {
    /// Invalid SAML request format or content.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Invalid SAML response format or content.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// XML parsing error.
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    /// XML signature validation failed.
    #[error("signature validation failed: {0}")]
    SignatureInvalid(String),

    /// XML signature creation failed.
    #[error("signature creation failed: {0}")]
    SignatureCreation(String),

    /// Missing required element or attribute.
    #[error("missing required element: {0}")]
    MissingElement(String),

    /// Invalid assertion.
    #[error("invalid assertion: {0}")]
    InvalidAssertion(String),

    /// Assertion conditions not met.
    #[error("assertion conditions not met: {0}")]
    ConditionsNotMet(String),

    /// Assertion expired.
    #[error("assertion expired")]
    AssertionExpired,

    /// Assertion not yet valid.
    #[error("assertion not yet valid")]
    AssertionNotYetValid,

    /// Invalid audience.
    #[error("invalid audience: expected {expected}, got {actual}")]
    InvalidAudience {
        /// The expected audience URI.
        expected: String,
        /// The actual audience URI.
        actual: String,
    },

    /// Invalid issuer.
    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer {
        /// The expected issuer.
        expected: String,
        /// The actual issuer.
        actual: String,
    },

    /// Invalid destination.
    #[error("invalid destination: expected {expected}, got {actual}")]
    InvalidDestination {
        /// The expected destination URL.
        expected: String,
        /// The actual destination URL.
        actual: String,
    },

    /// Unknown or unsupported binding.
    #[error("unsupported binding: {0}")]
    UnsupportedBinding(String),

    /// Unknown or unsupported name ID format.
    #[error("unsupported name ID format: {0}")]
    UnsupportedNameIdFormat(String),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// Deflate decompression error.
    #[error("deflate error: {0}")]
    Deflate(String),

    /// Unknown service provider.
    #[error("unknown service provider: {0}")]
    UnknownServiceProvider(String),

    /// Unknown identity provider.
    #[error("unknown identity provider: {0}")]
    UnknownIdentityProvider(String),

    /// Realm not found.
    #[error("realm not found: {0}")]
    RealmNotFound(String),

    /// User not found.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Session not found or expired.
    #[error("session not found or expired")]
    SessionNotFound,

    /// Authentication failed.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization failed.
    #[error("authorization failed: {0}")]
    AuthorizationFailed(String),

    /// Cryptographic operation error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Storage operation error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl SamlError {
    /// Returns the SAML status code for this error.
    ///
    /// Maps errors to appropriate SAML status codes as defined in the SAML 2.0 spec.
    #[must_use]
    pub fn status_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::MissingElement(_) => {
                "urn:oasis:names:tc:SAML:2.0:status:Requester"
            }
            Self::InvalidAssertion(_)
            | Self::ConditionsNotMet(_)
            | Self::AssertionExpired
            | Self::AssertionNotYetValid => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::InvalidAudience { .. }
            | Self::InvalidIssuer { .. }
            | Self::InvalidDestination { .. } => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::SignatureInvalid(_) => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::AuthenticationFailed(_) => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            Self::AuthorizationFailed(_) => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            Self::UnknownServiceProvider(_) | Self::UnknownIdentityProvider(_) => {
                "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
            }
            Self::UnsupportedBinding(_) | Self::UnsupportedNameIdFormat(_) => {
                "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
            }
            _ => "urn:oasis:names:tc:SAML:2.0:status:Responder",
        }
    }

    /// Returns a sub-status code if applicable.
    #[must_use]
    pub fn sub_status_code(&self) -> Option<&'static str> {
        match self {
            Self::AuthenticationFailed(_) => {
                Some("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
            }
            Self::InvalidAudience { .. } => {
                Some("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue")
            }
            _ => None,
        }
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_)
            | Self::MissingElement(_)
            | Self::Base64Decode(_)
            | Self::Deflate(_)
            | Self::XmlParse(_) => 400,
            Self::SignatureInvalid(_) | Self::AuthenticationFailed(_) => 401,
            Self::AuthorizationFailed(_) => 403,
            Self::RealmNotFound(_)
            | Self::UserNotFound(_)
            | Self::UnknownServiceProvider(_)
            | Self::UnknownIdentityProvider(_)
            | Self::SessionNotFound => 404,
            _ => 500,
        }
    }
}

impl From<quick_xml::Error> for SamlError {
    fn from(err: quick_xml::Error) -> Self {
        Self::XmlParse(err.to_string())
    }
}

impl From<quick_xml::DeError> for SamlError {
    fn from(err: quick_xml::DeError) -> Self {
        Self::XmlParse(err.to_string())
    }
}

impl From<base64::DecodeError> for SamlError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64Decode(err.to_string())
    }
}

impl From<std::io::Error> for SamlError {
    fn from(err: std::io::Error) -> Self {
        Self::Deflate(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_codes() {
        let err = SamlError::InvalidRequest("test".to_string());
        assert_eq!(err.status_code(), "urn:oasis:names:tc:SAML:2.0:status:Requester");
        assert_eq!(err.http_status(), 400);

        let err = SamlError::AuthenticationFailed("test".to_string());
        assert_eq!(err.status_code(), "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
        assert_eq!(err.http_status(), 401);

        let err = SamlError::Internal("test".to_string());
        assert_eq!(err.status_code(), "urn:oasis:names:tc:SAML:2.0:status:Responder");
        assert_eq!(err.http_status(), 500);
    }
}
