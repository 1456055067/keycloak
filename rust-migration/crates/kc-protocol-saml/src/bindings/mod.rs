//! SAML bindings implementation.
//!
//! This module implements the SAML 2.0 bindings for message transport:
//!
//! - **HTTP-POST Binding** - Messages are base64-encoded and sent in HTML forms
//! - **HTTP-Redirect Binding** - Messages are deflated, base64-encoded, and URL-encoded
//!
//! # Usage
//!
//! ```rust,ignore
//! use kc_protocol_saml::bindings::{HttpPostBinding, HttpRedirectBinding};
//!
//! // Encode a SAML request for POST binding
//! let html = HttpPostBinding::encode_request(&request_xml, "https://idp.example.com/sso", Some("relay_state"));
//!
//! // Encode a SAML request for Redirect binding
//! let url = HttpRedirectBinding::encode_request(&request_xml, "https://idp.example.com/sso", Some("relay_state"))?;
//! ```

mod post;
mod redirect;

pub use post::*;
pub use redirect::*;


/// SAML message type for binding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlMessageType {
    /// AuthnRequest message.
    Request,
    /// Response message.
    Response,
}

impl SamlMessageType {
    /// Returns the form parameter name for this message type.
    #[must_use]
    pub const fn form_param(&self) -> &'static str {
        match self {
            Self::Request => "SAMLRequest",
            Self::Response => "SAMLResponse",
        }
    }
}

/// Decoded SAML binding message.
#[derive(Debug, Clone)]
pub struct DecodedMessage {
    /// The decoded XML message.
    pub xml: String,
    /// The message type (request or response).
    pub message_type: SamlMessageType,
    /// The RelayState if present.
    pub relay_state: Option<String>,
    /// The signature (for redirect binding).
    pub signature: Option<String>,
    /// The signature algorithm (for redirect binding).
    pub sig_alg: Option<String>,
}
