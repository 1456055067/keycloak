//! HTTP-Redirect Binding implementation.
//!
//! Implements the SAML 2.0 HTTP-Redirect binding for sending SAML messages
//! via URL query parameters with DEFLATE compression.

use base64::Engine;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{Read, Write};

use crate::error::{SamlError, SamlResult};

use super::{DecodedMessage, SamlMessageType};

/// HTTP-Redirect binding encoder/decoder.
pub struct HttpRedirectBinding;

impl HttpRedirectBinding {
    /// Encodes a SAML request for HTTP-Redirect binding.
    ///
    /// Returns a URL with the encoded message in query parameters.
    pub fn encode_request(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
    ) -> SamlResult<String> {
        Self::encode(xml, destination, relay_state, SamlMessageType::Request)
    }

    /// Encodes a SAML response for HTTP-Redirect binding.
    ///
    /// Returns a URL with the encoded message in query parameters.
    pub fn encode_response(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
    ) -> SamlResult<String> {
        Self::encode(xml, destination, relay_state, SamlMessageType::Response)
    }

    /// Encodes a SAML message for HTTP-Redirect binding.
    fn encode(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
        message_type: SamlMessageType,
    ) -> SamlResult<String> {
        // DEFLATE compress
        let compressed = deflate_compress(xml.as_bytes())?;

        // Base64 encode
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        // URL encode
        let url_encoded = urlencoding::encode(&encoded);

        // Build URL
        let param_name = message_type.form_param();
        let separator = if destination.contains('?') { '&' } else { '?' };

        let mut url = format!("{}{}{}={}", destination, separator, param_name, url_encoded);

        if let Some(rs) = relay_state {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
        }

        Ok(url)
    }

    /// Encodes a signed SAML request for HTTP-Redirect binding.
    ///
    /// The signature is over the query string parameters, not embedded in the XML.
    pub fn encode_signed_request(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
        sig_alg: &str,
        signature: &str,
    ) -> SamlResult<String> {
        let mut url = Self::encode_request(xml, destination, relay_state)?;

        url.push_str(&format!("&SigAlg={}", urlencoding::encode(sig_alg)));
        url.push_str(&format!("&Signature={}", urlencoding::encode(signature)));

        Ok(url)
    }

    /// Encodes a signed SAML response for HTTP-Redirect binding.
    pub fn encode_signed_response(
        xml: &str,
        destination: &str,
        relay_state: Option<&str>,
        sig_alg: &str,
        signature: &str,
    ) -> SamlResult<String> {
        let mut url = Self::encode_response(xml, destination, relay_state)?;

        url.push_str(&format!("&SigAlg={}", urlencoding::encode(sig_alg)));
        url.push_str(&format!("&Signature={}", urlencoding::encode(signature)));

        Ok(url)
    }

    /// Decodes a SAML message from HTTP-Redirect query parameters.
    ///
    /// # Arguments
    ///
    /// * `saml_request` - The SAMLRequest parameter value (if present)
    /// * `saml_response` - The SAMLResponse parameter value (if present)
    /// * `relay_state` - The RelayState parameter value (if present)
    /// * `signature` - The Signature parameter value (if present)
    /// * `sig_alg` - The SigAlg parameter value (if present)
    pub fn decode(
        saml_request: Option<&str>,
        saml_response: Option<&str>,
        relay_state: Option<&str>,
        signature: Option<&str>,
        sig_alg: Option<&str>,
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

        // URL decode (may already be done by the web framework)
        let url_decoded = urlencoding::decode(encoded)
            .map_err(|e| SamlError::InvalidRequest(format!("URL decode error: {e}")))?;

        // Base64 decode
        let b64_decoded = base64::engine::general_purpose::STANDARD
            .decode(url_decoded.as_ref())
            .map_err(|e| SamlError::Base64Decode(e.to_string()))?;

        // DEFLATE decompress
        let xml_bytes = deflate_decompress(&b64_decoded)?;

        // Convert to string
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| SamlError::InvalidRequest(format!("Invalid UTF-8 in message: {e}")))?;

        Ok(DecodedMessage {
            xml,
            message_type,
            relay_state: relay_state.map(String::from),
            signature: signature.map(String::from),
            sig_alg: sig_alg.map(String::from),
        })
    }

    /// Decodes a message from a full URL.
    pub fn decode_url(url: &str) -> SamlResult<DecodedMessage> {
        let parsed = url::Url::parse(url)
            .map_err(|e| SamlError::InvalidRequest(format!("Invalid URL: {e}")))?;

        let mut saml_request = None;
        let mut saml_response = None;
        let mut relay_state = None;
        let mut signature = None;
        let mut sig_alg = None;

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "SAMLRequest" => saml_request = Some(value.to_string()),
                "SAMLResponse" => saml_response = Some(value.to_string()),
                "RelayState" => relay_state = Some(value.to_string()),
                "Signature" => signature = Some(value.to_string()),
                "SigAlg" => sig_alg = Some(value.to_string()),
                _ => {}
            }
        }

        Self::decode(
            saml_request.as_deref(),
            saml_response.as_deref(),
            relay_state.as_deref(),
            signature.as_deref(),
            sig_alg.as_deref(),
        )
    }

    /// Extracts the query string for signature verification.
    ///
    /// Returns the portion of the query string that should be signed/verified,
    /// which includes SAMLRequest/SAMLResponse, RelayState (if present), and SigAlg.
    pub fn extract_signed_query(url: &str) -> SamlResult<String> {
        let parsed = url::Url::parse(url)
            .map_err(|e| SamlError::InvalidRequest(format!("Invalid URL: {e}")))?;

        let mut parts = Vec::new();

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "SAMLRequest" | "SAMLResponse" | "RelayState" | "SigAlg" => {
                    parts.push(format!("{}={}", key, urlencoding::encode(&value)));
                }
                _ => {}
            }
        }

        if parts.is_empty() {
            return Err(SamlError::InvalidRequest(
                "No SAML parameters found".to_string(),
            ));
        }

        Ok(parts.join("&"))
    }
}

/// Compresses data using DEFLATE (raw, no zlib header).
fn deflate_compress(data: &[u8]) -> SamlResult<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| SamlError::Deflate(format!("Compression error: {e}")))?;
    encoder
        .finish()
        .map_err(|e| SamlError::Deflate(format!("Compression finish error: {e}")))
}

/// Decompresses DEFLATE data.
fn deflate_decompress(data: &[u8]) -> SamlResult<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| SamlError::Deflate(format!("Decompression error: {e}")))?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_request() {
        let xml = r#"<samlp:AuthnRequest>test content here</samlp:AuthnRequest>"#;
        let url =
            HttpRedirectBinding::encode_request(xml, "https://idp.example.com/sso", Some("state123"))
                .unwrap();

        assert!(url.starts_with("https://idp.example.com/sso?"));
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState=state123"));

        let decoded = HttpRedirectBinding::decode_url(&url).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.message_type, SamlMessageType::Request);
        assert_eq!(decoded.relay_state.as_deref(), Some("state123"));
    }

    #[test]
    fn encode_and_decode_response() {
        let xml = r#"<samlp:Response>test response</samlp:Response>"#;
        let url =
            HttpRedirectBinding::encode_response(xml, "https://sp.example.com/acs", None).unwrap();

        assert!(url.contains("SAMLResponse="));

        let decoded = HttpRedirectBinding::decode_url(&url).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.message_type, SamlMessageType::Response);
    }

    #[test]
    fn deflate_roundtrip() {
        let original = b"Test data for compression";
        let compressed = deflate_compress(original).unwrap();
        let decompressed = deflate_decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn extract_signed_query() {
        let url = "https://idp.example.com/sso?SAMLRequest=abc&RelayState=xyz&SigAlg=rsa-sha256&Signature=sig";
        let query = HttpRedirectBinding::extract_signed_query(url).unwrap();

        assert!(query.contains("SAMLRequest="));
        assert!(query.contains("RelayState="));
        assert!(query.contains("SigAlg="));
        assert!(!query.contains("Signature="));
    }

    #[test]
    fn url_with_existing_query() {
        let xml = "<Test/>";
        let url = HttpRedirectBinding::encode_request(
            xml,
            "https://idp.example.com/sso?existing=param",
            None,
        )
        .unwrap();

        // Should use & not ? since URL already has query params
        assert!(url.contains("?existing=param&SAMLRequest="));
    }
}
