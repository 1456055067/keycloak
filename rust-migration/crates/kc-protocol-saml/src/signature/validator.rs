//! XML Signature validation.
//!
//! Provides functionality for validating signatures on SAML documents.

use base64::Engine;

use crate::error::{SamlError, SamlResult};

use super::{CanonicalizationAlgorithm, SignatureAlgorithm, XmlSignature};

/// XML signature validator.
///
/// Validates signatures on SAML documents using configured trusted certificates.
pub struct XmlSignatureValidator {
    /// Trusted certificates for signature validation (DER format).
    trusted_certificates: Vec<Vec<u8>>,
    /// Whether to allow SHA-1 signatures (deprecated but sometimes needed).
    allow_sha1: bool,
}

impl XmlSignatureValidator {
    /// Creates a new validator with the given trusted certificates.
    pub fn new(trusted_certificates: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_certificates,
            allow_sha1: false,
        }
    }

    /// Creates a validator from PEM-encoded certificates.
    pub fn from_pem(certificates_pem: &[&str]) -> SamlResult<Self> {
        let mut certs = Vec::new();
        for pem in certificates_pem {
            let der = pem_to_der(pem, "CERTIFICATE").ok_or_else(|| {
                SamlError::Crypto("Invalid certificate PEM".to_string())
            })?;
            certs.push(der);
        }
        Ok(Self::new(certs))
    }

    /// Allows SHA-1 based signatures (not recommended).
    #[must_use]
    pub const fn allow_sha1(mut self, allow: bool) -> Self {
        self.allow_sha1 = allow;
        self
    }

    /// Validates an XML signature.
    ///
    /// # Arguments
    ///
    /// * `xml` - The signed XML document
    ///
    /// # Returns
    ///
    /// Returns `Ok(XmlSignature)` if the signature is valid, or an error if not.
    pub fn validate(&self, xml: &str) -> SamlResult<XmlSignature> {
        // Extract the signature element
        let signature = extract_signature(xml)?;

        // Check if the algorithm is allowed
        if signature.algorithm.is_deprecated() && !self.allow_sha1 {
            return Err(SamlError::SignatureInvalid(
                "SHA-1 signatures are not allowed".to_string(),
            ));
        }

        // Find the certificate to use for validation
        let cert = self.find_certificate(&signature)?;

        // Verify the digest
        self.verify_digest(xml, &signature)?;

        // Verify the signature
        self.verify_signature(&signature, &cert)?;

        Ok(signature)
    }

    /// Validates a detached signature for HTTP-Redirect binding.
    pub fn validate_redirect_binding(
        &self,
        signed_query: &str,
        signature_b64: &str,
        sig_alg: &str,
    ) -> SamlResult<()> {
        let algorithm = SignatureAlgorithm::from_uri(sig_alg).ok_or_else(|| {
            SamlError::SignatureInvalid(format!("Unknown signature algorithm: {sig_alg}"))
        })?;

        if algorithm.is_deprecated() && !self.allow_sha1 {
            return Err(SamlError::SignatureInvalid(
                "SHA-1 signatures are not allowed".to_string(),
            ));
        }

        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| SamlError::SignatureInvalid(format!("Invalid signature encoding: {e}")))?;

        // Try each trusted certificate
        for cert_der in &self.trusted_certificates {
            if self
                .verify_signature_with_cert(signed_query.as_bytes(), &signature, cert_der, algorithm)
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(SamlError::SignatureInvalid(
            "Signature verification failed with all trusted certificates".to_string(),
        ))
    }

    /// Finds a certificate for validation.
    fn find_certificate(&self, signature: &XmlSignature) -> SamlResult<Vec<u8>> {
        // If the signature contains a certificate, try to match it
        if let Some(ref cert_b64) = signature.x509_certificate {
            let cert_der = base64::engine::general_purpose::STANDARD
                .decode(cert_b64)
                .map_err(|e| {
                    SamlError::SignatureInvalid(format!("Invalid certificate encoding: {e}"))
                })?;

            // Check if this certificate is trusted
            if self.trusted_certificates.iter().any(|tc| tc == &cert_der) {
                return Ok(cert_der);
            }

            // If we have no trusted certs configured, use the embedded one
            // (for testing or when certificate validation is done elsewhere)
            if self.trusted_certificates.is_empty() {
                return Ok(cert_der);
            }
        }

        // Return the first trusted certificate if available
        self.trusted_certificates
            .first()
            .cloned()
            .ok_or_else(|| SamlError::SignatureInvalid("No certificate available".to_string()))
    }

    /// Verifies the digest value in the signature.
    fn verify_digest(&self, xml: &str, signature: &XmlSignature) -> SamlResult<()> {
        // Extract the referenced element
        let reference_id = signature
            .reference_uri
            .strip_prefix('#')
            .unwrap_or(&signature.reference_uri);

        let element = extract_referenced_element(xml, reference_id)?;

        // Remove the Signature element from the content for digest calculation
        let element_without_sig = remove_signature_element(&element);

        // Canonicalize and calculate digest
        let canonical = canonicalize(&element_without_sig)?;
        let calculated_digest = calculate_digest(&canonical, signature.algorithm)?;
        let calculated_b64 = base64::engine::general_purpose::STANDARD.encode(&calculated_digest);

        // Compare with the signature's digest value
        if calculated_b64 != signature.digest_value {
            return Err(SamlError::SignatureInvalid(
                "Digest value mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// Verifies the signature value.
    fn verify_signature(&self, signature: &XmlSignature, cert_der: &[u8]) -> SamlResult<()> {
        // Build the SignedInfo element for verification
        let signed_info = rebuild_signed_info(signature);
        let canonical_signed_info = canonicalize(&signed_info)?;

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signature.signature_value)
            .map_err(|e| SamlError::SignatureInvalid(format!("Invalid signature encoding: {e}")))?;

        self.verify_signature_with_cert(
            canonical_signed_info.as_bytes(),
            &signature_bytes,
            cert_der,
            signature.algorithm,
        )
    }

    /// Verifies a signature using a certificate.
    fn verify_signature_with_cert(
        &self,
        data: &[u8],
        signature: &[u8],
        cert_der: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> SamlResult<()> {
        // Extract public key from certificate
        let public_key = extract_public_key_from_cert(cert_der)?;

        // Map SAML signature algorithm to kc-crypto legacy algorithm
        let legacy_alg = match algorithm {
            SignatureAlgorithm::RsaSha256 => kc_crypto::LegacyRsaAlgorithm::Rs256,
            SignatureAlgorithm::RsaSha384 => kc_crypto::LegacyRsaAlgorithm::Rs384,
            SignatureAlgorithm::RsaSha512 => kc_crypto::LegacyRsaAlgorithm::Rs512,
            SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512 => {
                return Err(SamlError::SignatureInvalid(
                    "ECDSA signature verification not yet implemented".to_string(),
                ));
            }
            SignatureAlgorithm::RsaSha1 => {
                return Err(SamlError::SignatureInvalid(
                    "SHA-1 signature verification not supported".to_string(),
                ));
            }
        };

        let valid = kc_crypto::rsa_verify_legacy(&public_key, data, signature, legacy_alg)
            .map_err(|e| SamlError::SignatureInvalid(format!("Signature verification error: {e}")))?;

        if valid {
            Ok(())
        } else {
            Err(SamlError::SignatureInvalid("Signature verification failed".to_string()))
        }
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

/// Extracts signature information from an XML document.
fn extract_signature(xml: &str) -> SamlResult<XmlSignature> {
    // Find the Signature element
    let _sig_start = xml
        .find("<ds:Signature")
        .or_else(|| xml.find("<Signature"))
        .ok_or_else(|| SamlError::SignatureInvalid("No Signature element found".to_string()))?;

    // Extract algorithm from SignatureMethod
    let algorithm = extract_attribute(xml, "SignatureMethod", "Algorithm")
        .and_then(|uri| SignatureAlgorithm::from_uri(&uri))
        .ok_or_else(|| SamlError::SignatureInvalid("Invalid signature algorithm".to_string()))?;

    // Extract canonicalization from CanonicalizationMethod
    let canonicalization = extract_attribute(xml, "CanonicalizationMethod", "Algorithm")
        .and_then(|uri| CanonicalizationAlgorithm::from_uri(&uri))
        .unwrap_or_default();

    // Extract reference URI
    let reference_uri = extract_attribute(xml, "Reference", "URI")
        .ok_or_else(|| SamlError::SignatureInvalid("No Reference URI found".to_string()))?;

    // Extract DigestValue
    let digest_value = extract_element_content(xml, "DigestValue")
        .ok_or_else(|| SamlError::SignatureInvalid("No DigestValue found".to_string()))?;

    // Extract SignatureValue
    let signature_value = extract_element_content(xml, "SignatureValue")
        .ok_or_else(|| SamlError::SignatureInvalid("No SignatureValue found".to_string()))?;

    // Extract X509Certificate if present
    let x509_certificate = extract_element_content(xml, "X509Certificate");

    Ok(XmlSignature {
        algorithm,
        canonicalization,
        reference_uri,
        digest_value: digest_value.chars().filter(|c| !c.is_whitespace()).collect(),
        signature_value: signature_value.chars().filter(|c| !c.is_whitespace()).collect(),
        x509_certificate: x509_certificate.map(|s| s.chars().filter(|c| !c.is_whitespace()).collect()),
    })
}

/// Extracts an attribute value from an XML element.
fn extract_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    // Find element with or without namespace prefix
    let patterns = [
        format!("<{}",element),
        format!("<ds:{}", element),
    ];

    for pattern in &patterns {
        if let Some(pos) = xml.find(pattern) {
            let end = xml[pos..].find('>')?;
            let element_str = &xml[pos..pos + end];

            let attr_pattern = format!("{}=\"", attribute);
            if let Some(attr_start) = element_str.find(&attr_pattern) {
                let value_start = attr_start + attr_pattern.len();
                let value_end = element_str[value_start..].find('"')?;
                return Some(element_str[value_start..value_start + value_end].to_string());
            }
        }
    }
    None
}

/// Extracts the text content of an XML element.
fn extract_element_content(xml: &str, element: &str) -> Option<String> {
    // Try with and without namespace prefix
    let patterns = [
        (format!("<{}>", element), format!("</{}>", element)),
        (format!("<ds:{}>", element), format!("</ds:{}>", element)),
    ];

    for (open, close) in &patterns {
        if let Some(start) = xml.find(open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(close) {
                return Some(xml[content_start..content_start + end].to_string());
            }
        }
    }
    None
}

/// Extracts the referenced element from the document.
fn extract_referenced_element(xml: &str, reference_id: &str) -> SamlResult<String> {
    let id_pattern = format!("ID=\"{}\"", reference_id);
    let alt_pattern = format!("Id=\"{}\"", reference_id);

    let pos = xml
        .find(&id_pattern)
        .or_else(|| xml.find(&alt_pattern))
        .ok_or_else(|| {
            SamlError::SignatureInvalid(format!(
                "Referenced element '{}' not found",
                reference_id
            ))
        })?;

    // Find the start of the element
    let mut start = pos;
    while start > 0 && xml.as_bytes()[start - 1] != b'<' {
        start -= 1;
    }
    if start > 0 {
        start -= 1;
    }

    // Find the element name
    let mut name_end = start + 1;
    while name_end < xml.len()
        && xml.as_bytes()[name_end] != b' '
        && xml.as_bytes()[name_end] != b'>'
    {
        name_end += 1;
    }
    let tag_name = &xml[start + 1..name_end];
    let close_tag = format!("</{}>", tag_name.split(':').last().unwrap_or(tag_name));

    // Find the closing tag
    let close_pos = xml[start..].find(&close_tag).ok_or_else(|| {
        SamlError::SignatureInvalid("Referenced element is not properly closed".to_string())
    })?;

    Ok(xml[start..start + close_pos + close_tag.len()].to_string())
}

/// Removes the Signature element from XML content.
fn remove_signature_element(xml: &str) -> String {
    // Find and remove <ds:Signature>...</ds:Signature> or <Signature>...</Signature>
    let patterns = [
        ("<ds:Signature", "</ds:Signature>"),
        ("<Signature", "</Signature>"),
    ];

    let mut result = xml.to_string();
    for (open, close) in &patterns {
        if let Some(start) = result.find(open) {
            if let Some(end_offset) = result[start..].find(close) {
                let end = start + end_offset + close.len();
                result = format!("{}{}", &result[..start], &result[end..]);
                break;
            }
        }
    }
    result
}

/// Canonicalizes XML content.
fn canonicalize(xml: &str) -> SamlResult<String> {
    // Simplified canonicalization - a full implementation would use proper C14N
    Ok(xml.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Calculates the digest of data.
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
            return Err(SamlError::SignatureInvalid(
                "SHA-1 not implemented".to_string(),
            ));
        }
    };

    Ok(digest)
}

/// Rebuilds the SignedInfo element for verification.
fn rebuild_signed_info(signature: &XmlSignature) -> String {
    format!(
        r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:CanonicalizationMethod Algorithm="{}"/>
<ds:SignatureMethod Algorithm="{}"/>
<ds:Reference URI="{}">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="{}"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="{}"/>
<ds:DigestValue>{}</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>"#,
        signature.canonicalization.uri(),
        signature.algorithm.uri(),
        signature.reference_uri,
        signature.canonicalization.uri(),
        signature.algorithm.digest_uri(),
        signature.digest_value
    )
}

/// Extracts the public key from an X.509 certificate.
fn extract_public_key_from_cert(cert_der: &[u8]) -> SamlResult<Vec<u8>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| SamlError::Crypto(format!("Failed to parse certificate: {e}")))?;

    // Get the SubjectPublicKeyInfo as raw DER bytes
    let spki = cert.public_key().raw;
    Ok(spki.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_attribute_from_xml() {
        let xml = r##"<ds:Reference URI="#_123"></ds:Reference>"##;
        let uri = extract_attribute(xml, "Reference", "URI");
        assert_eq!(uri.as_deref(), Some("#_123"));
    }

    #[test]
    fn extract_element_content_from_xml() {
        let xml = "<ds:DigestValue>abc123</ds:DigestValue>";
        let content = extract_element_content(xml, "DigestValue");
        assert_eq!(content.as_deref(), Some("abc123"));
    }

    #[test]
    fn remove_signature() {
        let xml = "<Root><ds:Signature>sig</ds:Signature><Data>content</Data></Root>";
        let without_sig = remove_signature_element(xml);
        assert!(!without_sig.contains("Signature"));
        assert!(without_sig.contains("<Data>content</Data>"));
    }
}
