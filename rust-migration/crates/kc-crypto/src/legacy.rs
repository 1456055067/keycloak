//! Legacy cryptographic operations for protocol compatibility.
//!
//! **WARNING**: The algorithms in this module do NOT comply with CNSA 2.0.
//! They are provided solely for backward compatibility with legacy protocols
//! like SAML 2.0 that require SHA-256 based signatures.
//!
//! ## When to use these algorithms
//!
//! - SAML 2.0 interoperability with existing IdPs/SPs
//! - Legacy system integration that cannot be upgraded
//!
//! ## When NOT to use these algorithms
//!
//! - New deployments should use CNSA 2.0 compliant algorithms
//! - Internal services should use RS384/RS512/ES384/ES512

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{self, RsaKeyPair},
};

use crate::signature::SignatureError;

/// Legacy RSA signature algorithms (NOT CNSA 2.0 compliant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRsaAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256 (NOT CNSA 2.0 compliant).
    Rs256,
    /// RSA PKCS#1 v1.5 with SHA-384 (CNSA 2.0 compliant).
    Rs384,
    /// RSA PKCS#1 v1.5 with SHA-512 (CNSA 2.0 compliant).
    Rs512,
}

impl LegacyRsaAlgorithm {
    /// Returns the JWA algorithm name.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
        }
    }

    /// Returns the XML-DSig algorithm URI.
    #[must_use]
    pub const fn xml_dsig_uri(self) -> &'static str {
        match self {
            Self::Rs256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Rs384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::Rs512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        }
    }

    /// Returns true if this algorithm is CNSA 2.0 compliant.
    #[must_use]
    pub const fn is_cnsa_compliant(self) -> bool {
        !matches!(self, Self::Rs256)
    }
}

/// Signs data using RSA with legacy algorithm support.
///
/// **WARNING**: This function supports SHA-256 for legacy compatibility.
/// Prefer using `RsaSigningKey` from the `keys` module for CNSA 2.0 compliance.
///
/// # Arguments
///
/// * `key_der` - RSA private key in DER format (PKCS#1 or PKCS#8)
/// * `data` - Data to sign
/// * `algorithm` - Signature algorithm
///
/// # Errors
///
/// Returns an error if signing fails.
pub fn rsa_sign_legacy(
    key_der: &[u8],
    data: &[u8],
    algorithm: LegacyRsaAlgorithm,
) -> Result<Vec<u8>, SignatureError> {
    let key_pair = RsaKeyPair::from_der(key_der)
        .or_else(|_| RsaKeyPair::from_pkcs8(key_der))
        .map_err(|e| SignatureError::InvalidKey(format!("Invalid RSA key: {e}")))?;

    let rng = SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public_modulus_len()];

    let padding = match algorithm {
        LegacyRsaAlgorithm::Rs256 => &signature::RSA_PKCS1_SHA256,
        LegacyRsaAlgorithm::Rs384 => &signature::RSA_PKCS1_SHA384,
        LegacyRsaAlgorithm::Rs512 => &signature::RSA_PKCS1_SHA512,
    };

    key_pair
        .sign(padding, &rng, data, &mut signature)
        .map_err(|e| SignatureError::Signing(format!("RSA signing failed: {e}")))?;

    Ok(signature)
}

/// Verifies an RSA signature with legacy algorithm support.
///
/// **WARNING**: This function supports SHA-256 for legacy compatibility.
///
/// # Arguments
///
/// * `public_key_der` - RSA public key in DER format (`SubjectPublicKeyInfo`)
/// * `data` - Original data that was signed
/// * `signature` - Signature to verify
/// * `algorithm` - Signature algorithm
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn rsa_verify_legacy(
    public_key_der: &[u8],
    data: &[u8],
    sig: &[u8],
    algorithm: LegacyRsaAlgorithm,
) -> Result<bool, SignatureError> {
    use aws_lc_rs::signature::{
        UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
    };

    let verification_alg: &dyn signature::VerificationAlgorithm = match algorithm {
        LegacyRsaAlgorithm::Rs256 => &RSA_PKCS1_2048_8192_SHA256,
        LegacyRsaAlgorithm::Rs384 => &RSA_PKCS1_2048_8192_SHA384,
        LegacyRsaAlgorithm::Rs512 => &RSA_PKCS1_2048_8192_SHA512,
    };

    let public_key = UnparsedPublicKey::new(verification_alg, public_key_der);

    match public_key.verify(data, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_algorithm_properties() {
        assert!(!LegacyRsaAlgorithm::Rs256.is_cnsa_compliant());
        assert!(LegacyRsaAlgorithm::Rs384.is_cnsa_compliant());
        assert!(LegacyRsaAlgorithm::Rs512.is_cnsa_compliant());
    }

    #[test]
    fn legacy_algorithm_uris() {
        assert!(LegacyRsaAlgorithm::Rs256.xml_dsig_uri().contains("sha256"));
        assert!(LegacyRsaAlgorithm::Rs384.xml_dsig_uri().contains("sha384"));
    }
}
