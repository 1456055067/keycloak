//! XML Signature support for SAML.
//!
//! This module provides XML Digital Signature (XML-DSig) support for
//! signing and validating SAML messages and assertions.
//!
//! # Signing Algorithms
//!
//! The following signature algorithms are supported:
//! - RSA-SHA256 (recommended)
//! - RSA-SHA384
//! - RSA-SHA512
//! - ECDSA-SHA256
//! - ECDSA-SHA384
//! - ECDSA-SHA512
//!
//! Legacy SHA-1 algorithms are supported for compatibility but not recommended.

mod signer;
mod validator;

pub use signer::*;
pub use validator::*;

use crate::types::{canonicalization_algorithms, digest_algorithms, signature_algorithms};

/// Signature algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256 (recommended).
    #[default]
    RsaSha256,
    /// RSA with SHA-384.
    RsaSha384,
    /// RSA with SHA-512.
    RsaSha512,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
    /// Legacy RSA with SHA-1 (not recommended).
    RsaSha1,
}

impl SignatureAlgorithm {
    /// Returns the URI for this signature algorithm.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::RsaSha256 => signature_algorithms::RSA_SHA256,
            Self::RsaSha384 => signature_algorithms::RSA_SHA384,
            Self::RsaSha512 => signature_algorithms::RSA_SHA512,
            Self::EcdsaSha256 => signature_algorithms::ECDSA_SHA256,
            Self::EcdsaSha384 => signature_algorithms::ECDSA_SHA384,
            Self::EcdsaSha512 => signature_algorithms::ECDSA_SHA512,
            Self::RsaSha1 => signature_algorithms::RSA_SHA1,
        }
    }

    /// Returns the corresponding digest algorithm URI.
    #[must_use]
    pub const fn digest_uri(&self) -> &'static str {
        match self {
            Self::RsaSha256 | Self::EcdsaSha256 => digest_algorithms::SHA256,
            Self::RsaSha384 | Self::EcdsaSha384 => digest_algorithms::SHA384,
            Self::RsaSha512 | Self::EcdsaSha512 => digest_algorithms::SHA512,
            Self::RsaSha1 => digest_algorithms::SHA1,
        }
    }

    /// Parses a signature algorithm from its URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            signature_algorithms::RSA_SHA256 => Some(Self::RsaSha256),
            signature_algorithms::RSA_SHA384 => Some(Self::RsaSha384),
            signature_algorithms::RSA_SHA512 => Some(Self::RsaSha512),
            signature_algorithms::ECDSA_SHA256 => Some(Self::EcdsaSha256),
            signature_algorithms::ECDSA_SHA384 => Some(Self::EcdsaSha384),
            signature_algorithms::ECDSA_SHA512 => Some(Self::EcdsaSha512),
            signature_algorithms::RSA_SHA1 => Some(Self::RsaSha1),
            _ => None,
        }
    }

    /// Returns true if this algorithm uses RSA.
    #[must_use]
    pub const fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512 | Self::RsaSha1
        )
    }

    /// Returns true if this algorithm uses ECDSA.
    #[must_use]
    pub const fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512
        )
    }

    /// Returns true if this algorithm uses a deprecated hash (SHA-1).
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, Self::RsaSha1)
    }
}

/// Canonicalization algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanonicalizationAlgorithm {
    /// Exclusive C14N without comments (recommended).
    #[default]
    ExclusiveC14N,
    /// Exclusive C14N with comments.
    ExclusiveC14NWithComments,
    /// C14N without comments.
    C14N,
    /// C14N with comments.
    C14NWithComments,
}

impl CanonicalizationAlgorithm {
    /// Returns the URI for this canonicalization algorithm.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::ExclusiveC14N => canonicalization_algorithms::EXCLUSIVE_C14N,
            Self::ExclusiveC14NWithComments => {
                canonicalization_algorithms::EXCLUSIVE_C14N_WITH_COMMENTS
            }
            Self::C14N => canonicalization_algorithms::C14N,
            Self::C14NWithComments => canonicalization_algorithms::C14N_WITH_COMMENTS,
        }
    }

    /// Parses a canonicalization algorithm from its URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            canonicalization_algorithms::EXCLUSIVE_C14N => Some(Self::ExclusiveC14N),
            canonicalization_algorithms::EXCLUSIVE_C14N_WITH_COMMENTS => {
                Some(Self::ExclusiveC14NWithComments)
            }
            canonicalization_algorithms::C14N => Some(Self::C14N),
            canonicalization_algorithms::C14N_WITH_COMMENTS => Some(Self::C14NWithComments),
            _ => None,
        }
    }
}

/// XML Signature structure.
///
/// Represents the `<ds:Signature>` element in signed SAML documents.
#[derive(Debug, Clone)]
pub struct XmlSignature {
    /// The signature algorithm used.
    pub algorithm: SignatureAlgorithm,
    /// The canonicalization algorithm used.
    pub canonicalization: CanonicalizationAlgorithm,
    /// The reference URI (typically the ID of the signed element).
    pub reference_uri: String,
    /// The digest value (base64 encoded).
    pub digest_value: String,
    /// The signature value (base64 encoded).
    pub signature_value: String,
    /// Optional X.509 certificate (base64 encoded, DER format).
    pub x509_certificate: Option<String>,
}

/// Configuration for signature creation.
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// The signature algorithm to use.
    pub algorithm: SignatureAlgorithm,
    /// The canonicalization algorithm to use.
    pub canonicalization: CanonicalizationAlgorithm,
    /// Whether to include the X.509 certificate in the signature.
    pub include_certificate: bool,
    /// Whether to include the public key value in the signature.
    pub include_key_value: bool,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            algorithm: SignatureAlgorithm::RsaSha256,
            canonicalization: CanonicalizationAlgorithm::ExclusiveC14N,
            include_certificate: true,
            include_key_value: false,
        }
    }
}

impl SignatureConfig {
    /// Creates a new signature configuration with the given algorithm.
    #[must_use]
    pub const fn with_algorithm(algorithm: SignatureAlgorithm) -> Self {
        Self {
            algorithm,
            canonicalization: CanonicalizationAlgorithm::ExclusiveC14N,
            include_certificate: true,
            include_key_value: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_algorithm_uri_roundtrip() {
        for alg in [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::EcdsaSha256,
        ] {
            let uri = alg.uri();
            let parsed = SignatureAlgorithm::from_uri(uri);
            assert_eq!(parsed, Some(alg));
        }
    }

    #[test]
    fn signature_algorithm_properties() {
        assert!(SignatureAlgorithm::RsaSha256.is_rsa());
        assert!(!SignatureAlgorithm::RsaSha256.is_ecdsa());
        assert!(!SignatureAlgorithm::RsaSha256.is_deprecated());

        assert!(!SignatureAlgorithm::EcdsaSha256.is_rsa());
        assert!(SignatureAlgorithm::EcdsaSha256.is_ecdsa());

        assert!(SignatureAlgorithm::RsaSha1.is_deprecated());
    }

    #[test]
    fn canonicalization_algorithm_uri_roundtrip() {
        for alg in [
            CanonicalizationAlgorithm::ExclusiveC14N,
            CanonicalizationAlgorithm::C14N,
        ] {
            let uri = alg.uri();
            let parsed = CanonicalizationAlgorithm::from_uri(uri);
            assert_eq!(parsed, Some(alg));
        }
    }

    #[test]
    fn signature_config_default() {
        let config = SignatureConfig::default();
        assert_eq!(config.algorithm, SignatureAlgorithm::RsaSha256);
        assert!(config.include_certificate);
    }
}
