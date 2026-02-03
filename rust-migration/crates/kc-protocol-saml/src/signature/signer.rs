//! XML Signature creation.
//!
//! Provides functionality for signing SAML documents using XML-DSig.

use base64::Engine;

use crate::error::{SamlError, SamlResult};

use super::{SignatureAlgorithm, SignatureConfig};

/// XML document signer.
///
/// Signs SAML documents using the configured private key.
pub struct XmlSigner {
    /// The private key in DER format.
    private_key_der: Vec<u8>,
    /// The X.509 certificate in DER format (optional).
    certificate_der: Option<Vec<u8>>,
    /// Signature configuration.
    config: SignatureConfig,
}

impl XmlSigner {
    /// Creates a new signer with an RSA private key.
    ///
    /// # Arguments
    ///
    /// * `private_key_der` - The private key in DER format
    /// * `certificate_der` - Optional X.509 certificate in DER format
    pub fn new(private_key_der: Vec<u8>, certificate_der: Option<Vec<u8>>) -> Self {
        Self {
            private_key_der,
            certificate_der,
            config: SignatureConfig::default(),
        }
    }

    /// Creates a new signer from PEM-encoded key and certificate.
    pub fn from_pem(private_key_pem: &str, certificate_pem: Option<&str>) -> SamlResult<Self> {
        let private_key_der = pem_to_der(private_key_pem, "PRIVATE KEY")
            .or_else(|| pem_to_der(private_key_pem, "RSA PRIVATE KEY"))
            .ok_or_else(|| SamlError::Crypto("Invalid private key PEM".to_string()))?;

        let certificate_der = certificate_pem
            .and_then(|pem| pem_to_der(pem, "CERTIFICATE"));

        Ok(Self::new(private_key_der, certificate_der))
    }

    /// Sets the signature configuration.
    #[must_use]
    pub fn with_config(mut self, config: SignatureConfig) -> Self {
        self.config = config;
        self
    }

    /// Signs an XML document.
    ///
    /// # Arguments
    ///
    /// * `xml` - The XML document to sign
    /// * `reference_id` - The ID of the element to sign (without the '#' prefix)
    ///
    /// # Returns
    ///
    /// The signed XML document with the `<ds:Signature>` element inserted.
    pub fn sign(&self, xml: &str, reference_id: &str) -> SamlResult<String> {
        // Find the element to sign and where to insert the signature
        let (element_start, insert_position) = find_element_and_insert_position(xml, reference_id)?;

        // Canonicalize the element for digest calculation
        let canonical_element = canonicalize_element(xml, element_start)?;

        // Calculate the digest
        let digest = calculate_digest(&canonical_element, self.config.algorithm)?;
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(&digest);

        // Build the SignedInfo element
        let signed_info = build_signed_info(
            reference_id,
            &digest_b64,
            self.config.algorithm,
            self.config.canonicalization,
        );

        // Canonicalize SignedInfo for signing
        let canonical_signed_info = canonicalize_signed_info(&signed_info)?;

        // Sign the canonical SignedInfo
        let signature_value = self.sign_data(canonical_signed_info.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_value);

        // Build the complete Signature element
        let signature_element = build_signature_element(
            &signed_info,
            &signature_b64,
            self.certificate_der.as_deref(),
            &self.config,
        );

        // Insert the signature into the document
        let signed_xml = insert_signature(xml, insert_position, &signature_element);

        Ok(signed_xml)
    }

    /// Signs raw data using the configured algorithm.
    fn sign_data(&self, data: &[u8]) -> SamlResult<Vec<u8>> {
        // Currently only RSA is implemented
        if !self.config.algorithm.is_rsa() {
            return Err(SamlError::SignatureCreation(
                "ECDSA signing not yet implemented".to_string(),
            ));
        }

        // Map SAML signature algorithm to kc-crypto legacy algorithm
        let legacy_alg = match self.config.algorithm {
            SignatureAlgorithm::RsaSha256 => kc_crypto::LegacyRsaAlgorithm::Rs256,
            SignatureAlgorithm::RsaSha384 => kc_crypto::LegacyRsaAlgorithm::Rs384,
            SignatureAlgorithm::RsaSha512 => kc_crypto::LegacyRsaAlgorithm::Rs512,
            _ => {
                return Err(SamlError::SignatureCreation(format!(
                    "Unsupported signature algorithm: {:?}",
                    self.config.algorithm
                )));
            }
        };

        kc_crypto::rsa_sign_legacy(&self.private_key_der, data, legacy_alg)
            .map_err(|e| SamlError::SignatureCreation(format!("RSA signing failed: {e}")))
    }

    /// Creates a detached signature for HTTP-Redirect binding.
    ///
    /// This creates a signature over the query string parameters rather than
    /// embedding the signature in the XML.
    pub fn sign_redirect_binding(
        &self,
        saml_message: &str,
        relay_state: Option<&str>,
        is_request: bool,
    ) -> SamlResult<String> {
        // Build the string to sign
        let param_name = if is_request {
            "SAMLRequest"
        } else {
            "SAMLResponse"
        };

        let mut to_sign = format!(
            "{}={}",
            param_name,
            urlencoding::encode(saml_message)
        );

        if let Some(rs) = relay_state {
            to_sign.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
        }

        to_sign.push_str(&format!(
            "&SigAlg={}",
            urlencoding::encode(self.config.algorithm.uri())
        ));

        // Sign the string
        let signature = self.sign_data(to_sign.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        Ok(signature_b64)
    }
}

/// Extracts DER data from a PEM string.
fn pem_to_der(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {}-----", label);
    let end = format!("-----END {}-----", label);

    let start = pem.find(&begin)? + begin.len();
    let end_pos = pem.find(&end)?;

    let b64_data: String = pem[start..end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD.decode(&b64_data).ok()
}

/// Finds the element to sign and determines where to insert the signature.
fn find_element_and_insert_position(xml: &str, reference_id: &str) -> SamlResult<(usize, usize)> {
    // Look for the element with the given ID
    let id_pattern = format!("ID=\"{}\"", reference_id);
    let alt_pattern = format!("Id=\"{}\"", reference_id);

    let element_start = xml
        .find(&id_pattern)
        .or_else(|| xml.find(&alt_pattern))
        .ok_or_else(|| {
            SamlError::SignatureCreation(format!("Element with ID '{}' not found", reference_id))
        })?;

    // Find the start of the element (go back to find '<')
    let mut tag_start = element_start;
    while tag_start > 0 && xml.as_bytes()[tag_start - 1] != b'<' {
        tag_start -= 1;
    }
    if tag_start > 0 {
        tag_start -= 1;
    }

    // Find the end of the opening tag to insert signature after
    let tag_end = xml[element_start..]
        .find('>')
        .map(|pos| element_start + pos + 1)
        .ok_or_else(|| SamlError::SignatureCreation("Malformed XML element".to_string()))?;

    // For SAML, signature should be inserted after Issuer element if present
    let insert_pos = find_issuer_end(xml, tag_end).unwrap_or(tag_end);

    Ok((tag_start, insert_pos))
}

/// Finds the end of the Issuer element after the given position.
fn find_issuer_end(xml: &str, after: usize) -> Option<usize> {
    let search_area = &xml[after..];

    // Look for </saml:Issuer> or </Issuer>
    for pattern in &["</saml:Issuer>", "</Issuer>", "</saml2:Issuer>"] {
        if let Some(pos) = search_area.find(pattern) {
            return Some(after + pos + pattern.len());
        }
    }
    None
}

/// Canonicalizes an XML element.
fn canonicalize_element(xml: &str, start: usize) -> SamlResult<String> {
    // Find the element's closing tag
    let element = extract_element(xml, start)?;

    // For now, use a simple canonicalization (normalize whitespace)
    // A full implementation would use proper C14N
    Ok(normalize_xml_whitespace(&element))
}

/// Extracts a complete XML element starting at the given position.
fn extract_element(xml: &str, start: usize) -> SamlResult<String> {
    let xml_bytes = xml.as_bytes();

    // Find the tag name (including any namespace prefix)
    let mut tag_end = start + 1;
    while tag_end < xml.len() && xml_bytes[tag_end] != b' ' && xml_bytes[tag_end] != b'>' {
        tag_end += 1;
    }

    let full_tag_name = &xml[start + 1..tag_end];

    // Try to find closing tag with full name first (e.g., </samlp:Response>)
    let close_pattern_full = format!("</{}>", full_tag_name);
    if let Some(close_pos) = xml[start..].find(&close_pattern_full) {
        let end_pos = start + close_pos + close_pattern_full.len();
        return Ok(xml[start..end_pos].to_string());
    }

    // Also try without the trailing >
    let close_pattern_full2 = format!("</{}", full_tag_name);
    if let Some(close_pos) = xml[start..].find(&close_pattern_full2) {
        // Find the end of the closing tag
        if let Some(end_offset) = xml[start + close_pos..].find('>') {
            let end_pos = start + close_pos + end_offset + 1;
            return Ok(xml[start..end_pos].to_string());
        }
    }

    // If no namespace, try just the local name
    let tag_name = full_tag_name.split(':').last().unwrap_or(full_tag_name);
    let close_pattern = format!("</{}", tag_name);
    let close_pos = xml[start..]
        .find(&close_pattern)
        .ok_or_else(|| {
            SamlError::SignatureCreation(format!(
                "Unclosed XML element '{}' (searched for '{}')",
                full_tag_name, close_pattern
            ))
        })?;

    // Find the end of the closing tag
    let end_pos = xml[start + close_pos..]
        .find('>')
        .map(|pos| start + close_pos + pos + 1)
        .ok_or_else(|| SamlError::SignatureCreation("Malformed closing tag".to_string()))?;

    Ok(xml[start..end_pos].to_string())
}

/// Normalizes XML whitespace (simplified canonicalization).
fn normalize_xml_whitespace(xml: &str) -> String {
    // This is a simplified version - a full implementation would use proper C14N
    xml.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Calculates the digest of data using the specified algorithm.
fn calculate_digest(data: &str, algorithm: SignatureAlgorithm) -> SamlResult<Vec<u8>> {
    let digest = match algorithm {
        SignatureAlgorithm::RsaSha256 | SignatureAlgorithm::EcdsaSha256 => {
            kc_crypto::sha256(data.as_bytes())
        }
        SignatureAlgorithm::RsaSha384 | SignatureAlgorithm::EcdsaSha384 => {
            kc_crypto::sha384(data.as_bytes())
        }
        SignatureAlgorithm::RsaSha512 | SignatureAlgorithm::EcdsaSha512 => {
            kc_crypto::sha512(data.as_bytes())
        }
        SignatureAlgorithm::RsaSha1 => {
            // SHA-1 is deprecated but still needed for compatibility
            return Err(SamlError::SignatureCreation(
                "SHA-1 not implemented (deprecated)".to_string(),
            ));
        }
    };

    Ok(digest)
}

/// Builds the SignedInfo element.
fn build_signed_info(
    reference_id: &str,
    digest_b64: &str,
    algorithm: SignatureAlgorithm,
    canonicalization: super::CanonicalizationAlgorithm,
) -> String {
    format!(
        r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:CanonicalizationMethod Algorithm="{}"/>
<ds:SignatureMethod Algorithm="{}"/>
<ds:Reference URI="#{}">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="{}"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="{}"/>
<ds:DigestValue>{}</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>"##,
        canonicalization.uri(),
        algorithm.uri(),
        reference_id,
        canonicalization.uri(),
        algorithm.digest_uri(),
        digest_b64
    )
}

/// Canonicalizes the SignedInfo element for signing.
fn canonicalize_signed_info(signed_info: &str) -> SamlResult<String> {
    // Simplified - a full implementation would use proper C14N
    Ok(normalize_xml_whitespace(signed_info))
}

/// Builds the complete Signature element.
fn build_signature_element(
    signed_info: &str,
    signature_value: &str,
    certificate_der: Option<&[u8]>,
    config: &SignatureConfig,
) -> String {
    let mut signature = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
{}
<ds:SignatureValue>{}</ds:SignatureValue>"#,
        signed_info, signature_value
    );

    if config.include_certificate {
        if let Some(cert) = certificate_der {
            let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert);
            signature.push_str(&format!(
                r#"
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>{}</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>"#,
                cert_b64
            ));
        }
    }

    signature.push_str("\n</ds:Signature>");
    signature
}

/// Inserts the signature into the XML document.
fn insert_signature(xml: &str, position: usize, signature: &str) -> String {
    format!("{}{}{}", &xml[..position], signature, &xml[position..])
}

#[cfg(test)]

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_to_der_extraction() {
        let pem = "-----BEGIN CERTIFICATE-----\nTUIJ\n-----END CERTIFICATE-----";
        let der = pem_to_der(pem, "CERTIFICATE");
        assert!(der.is_some());
    }

    #[test]
    fn test_normalize_whitespace() {
        let input = "  <element>   content   </element>  ";
        let output = normalize_xml_whitespace(input);
        assert_eq!(output, "<element> content </element>");
    }
}
