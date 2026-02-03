//! HTTP-POST Binding implementation.
//!
//! Implements the SAML 2.0 HTTP-POST binding for sending SAML messages
//! via HTML form POST.

use base64::Engine;

use crate::error::{SamlError, SamlResult};

use super::{DecodedMessage, SamlMessageType};

/// HTTP-POST binding encoder/decoder.
pub struct HttpPostBinding;

impl HttpPostBinding {
    /// Encodes a SAML request for HTTP-POST binding.
    ///
    /// Returns an HTML form that will auto-submit to the destination.
    #[must_use]
    pub fn encode_request(xml: &str, destination: &str, relay_state: Option<&str>) -> String {
        Self::encode(xml, destination, relay_state, SamlMessageType::Request)
    }

    /// Encodes a SAML response for HTTP-POST binding.
    ///
    /// Returns an HTML form that will auto-submit to the destination.
    #[must_use]
    pub fn encode_response(xml: &str, destination: &str, relay_state: Option<&str>) -> String {
        Self::encode(xml, destination, relay_state, SamlMessageType::Response)
    }

    /// Encodes a SAML message for HTTP-POST binding.
    fn encode(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
        message_type: SamlMessageType,
    ) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(xml);
        let param_name = message_type.form_param();

        let relay_state_input = relay_state
            .map(|rs| {
                format!(
                    r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                    html_escape(rs)
                )
            })
            .unwrap_or_default();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML POST Binding</title>
</head>
<body onload="document.forms[0].submit()">
    <noscript>
        <p>JavaScript is disabled. Click the button below to continue.</p>
    </noscript>
    <form method="post" action="{}">
        <input type="hidden" name="{}" value="{}"/>
        {}
        <noscript>
            <input type="submit" value="Continue"/>
        </noscript>
    </form>
</body>
</html>"#,
            html_escape(destination),
            param_name,
            encoded,
            relay_state_input
        )
    }

    /// Decodes a SAML message from HTTP-POST form data.
    ///
    /// # Arguments
    ///
    /// * `saml_request` - The SAMLRequest parameter value (if present)
    /// * `saml_response` - The SAMLResponse parameter value (if present)
    /// * `relay_state` - The RelayState parameter value (if present)
    pub fn decode(
        saml_request: Option<&str>,
        saml_response: Option<&str>,
        relay_state: Option<&str>,
    ) -> SamlResult<DecodedMessage> {
        let (encoded, message_type) = if let Some(req) = saml_request {
            (req, SamlMessageType::Request)
        } else if let Some(resp) = saml_response {
            (resp, SamlMessageType::Response)
        } else {
            return Err(SamlError::InvalidRequest(
                "No SAMLRequest or SAMLResponse parameter".to_string(),
            ));
        };

        // Base64 decode
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| SamlError::Base64Decode(e.to_string()))?;

        // Convert to string
        let xml = String::from_utf8(decoded)
            .map_err(|e| SamlError::InvalidRequest(format!("Invalid UTF-8 in message: {e}")))?;

        Ok(DecodedMessage {
            xml,
            message_type,
            relay_state: relay_state.map(String::from),
            signature: None,
            sig_alg: None,
        })
    }

    /// Creates a simple form for displaying to users who need to click submit.
    ///
    /// Unlike `encode_*` methods, this creates a form with a visible submit button
    /// and no auto-submit JavaScript.
    #[must_use]
    pub fn create_manual_form(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
        message_type: SamlMessageType,
        button_text: &str,
    ) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(xml);
        let param_name = message_type.form_param();

        let relay_state_input = relay_state
            .map(|rs| {
                format!(
                    r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                    html_escape(rs)
                )
            })
            .unwrap_or_default();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML Authentication</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
        button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; }}
    </style>
</head>
<body>
    <form method="post" action="{}">
        <input type="hidden" name="{}" value="{}"/>
        {}
        <button type="submit">{}</button>
    </form>
</body>
</html>"#,
            html_escape(destination),
            param_name,
            encoded,
            relay_state_input,
            html_escape(button_text)
        )
    }
}

/// Escapes HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_request() {
        let xml = r#"<samlp:AuthnRequest>test</samlp:AuthnRequest>"#;
        let html = HttpPostBinding::encode_request(xml, "https://idp.example.com", Some("state123"));

        // Verify HTML structure
        assert!(html.contains("SAMLRequest"));
        assert!(html.contains("RelayState"));
        assert!(html.contains("https://idp.example.com"));

        // Extract the encoded value
        let start = html.find("name=\"SAMLRequest\" value=\"").unwrap() + 26;
        let end = html[start..].find('"').unwrap();
        let encoded = &html[start..start + end];

        // Decode and verify
        let decoded = HttpPostBinding::decode(Some(encoded), None, Some("state123")).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.message_type, SamlMessageType::Request);
        assert_eq!(decoded.relay_state.as_deref(), Some("state123"));
    }

    #[test]
    fn encode_and_decode_response() {
        let xml = r#"<samlp:Response>test</samlp:Response>"#;
        let html = HttpPostBinding::encode_response(xml, "https://sp.example.com", None);

        assert!(html.contains("SAMLResponse"));

        // Extract the encoded value
        let start = html.find("name=\"SAMLResponse\" value=\"").unwrap() + 27;
        let end = html[start..].find('"').unwrap();
        let encoded = &html[start..start + end];

        let decoded = HttpPostBinding::decode(None, Some(encoded), None).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.message_type, SamlMessageType::Response);
    }

    #[test]
    fn decode_missing_message() {
        let result = HttpPostBinding::decode(None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn html_escape_special_chars() {
        let input = r#"<script>alert("xss")</script>"#;
        let escaped = html_escape(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
    }
}
