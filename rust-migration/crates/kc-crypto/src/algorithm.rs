//! Cryptographic algorithm definitions.
//!
//! ## CNSA 2.0 Compliance
//!
//! Only CNSA 2.0 approved algorithms are available:
//! - Hash: SHA-384, SHA-512 (NO SHA-256)
//! - ECDSA: P-384, P-521 (NO P-256)
//! - RSA: Minimum 3072 bits

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for algorithm operations.
#[derive(Debug, Error)]
pub enum AlgorithmError {
    /// Algorithm is not CNSA 2.0 compliant.
    #[error("algorithm '{0}' is not CNSA 2.0 compliant")]
    NotCnsaCompliant(String),

    /// Unknown algorithm.
    #[error("unknown algorithm: {0}")]
    Unknown(String),

    /// Key size too small.
    #[error("key size {0} bits is below CNSA 2.0 minimum of {1} bits")]
    KeySizeTooSmall(u32, u32),
}

/// CNSA 2.0 compliant hash algorithms.
///
/// ## CNSA 2.0
///
/// SHA-256 is **forbidden**. Minimum hash is SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-384 (CNSA 2.0 minimum).
    #[serde(rename = "SHA384")]
    Sha384,

    /// SHA-512.
    #[serde(rename = "SHA512")]
    Sha512,
}

impl HashAlgorithm {
    /// Returns the output length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Returns the algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

/// CNSA 2.0 compliant signature algorithms.
///
/// ## CNSA 2.0
///
/// - ES256, RS256, PS256, HS256 are **forbidden**
/// - Only P-384 and P-521 curves are permitted
/// - RSA keys must be at least 3072 bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    // ECDSA with P-384 curve and SHA-384 hash
    /// ECDSA using P-384 curve and SHA-384 hash.
    #[serde(rename = "ES384")]
    Es384,

    /// ECDSA using P-521 curve and SHA-512 hash.
    #[serde(rename = "ES512")]
    Es512,

    // RSA PKCS#1 v1.5 signatures
    /// RSA PKCS#1 v1.5 with SHA-384.
    #[serde(rename = "RS384")]
    Rs384,

    /// RSA PKCS#1 v1.5 with SHA-512.
    #[serde(rename = "RS512")]
    Rs512,

    // RSA-PSS signatures
    /// RSA-PSS with SHA-384.
    #[serde(rename = "PS384")]
    Ps384,

    /// RSA-PSS with SHA-512.
    #[serde(rename = "PS512")]
    Ps512,
}

impl SignatureAlgorithm {
    /// Returns the JWA algorithm name.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
        }
    }

    /// Returns the hash algorithm used by this signature algorithm.
    #[must_use]
    pub const fn hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::Es384 | Self::Rs384 | Self::Ps384 => HashAlgorithm::Sha384,
            Self::Es512 | Self::Rs512 | Self::Ps512 => HashAlgorithm::Sha512,
        }
    }

    /// Returns whether this is an ECDSA algorithm.
    #[must_use]
    pub const fn is_ecdsa(self) -> bool {
        matches!(self, Self::Es384 | Self::Es512)
    }

    /// Returns whether this is an RSA algorithm.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(self, Self::Rs384 | Self::Rs512 | Self::Ps384 | Self::Ps512)
    }

    /// Parses a JWA algorithm name.
    ///
    /// ## Errors
    ///
    /// Returns an error if the algorithm is not CNSA 2.0 compliant or unknown.
    pub fn from_jwa(name: &str) -> Result<Self, AlgorithmError> {
        match name {
            "ES384" => Ok(Self::Es384),
            "ES512" => Ok(Self::Es512),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),

            // CNSA 2.0: These algorithms are explicitly forbidden
            "ES256" | "RS256" | "PS256" | "HS256" => {
                Err(AlgorithmError::NotCnsaCompliant(name.to_string()))
            }

            _ => Err(AlgorithmError::Unknown(name.to_string())),
        }
    }

    /// Validates that an RSA key size meets CNSA 2.0 requirements.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key size is below 3072 bits.
    pub const fn validate_rsa_key_size(bits: u32) -> Result<(), AlgorithmError> {
        const CNSA_MIN_RSA_BITS: u32 = 3072;

        if bits < CNSA_MIN_RSA_BITS {
            return Err(AlgorithmError::KeySizeTooSmall(bits, CNSA_MIN_RSA_BITS));
        }
        Ok(())
    }
}

/// CNSA 2.0 compliant elliptic curves.
///
/// ## CNSA 2.0
///
/// P-256 is **forbidden**. Only P-384 and P-521 are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EllipticCurve {
    /// NIST P-384 curve (secp384r1).
    #[serde(rename = "P-384")]
    P384,

    /// NIST P-521 curve (secp521r1).
    #[serde(rename = "P-521")]
    P521,
}

impl EllipticCurve {
    /// Returns the curve name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    /// Returns the key size in bits.
    #[must_use]
    pub const fn key_size_bits(self) -> u32 {
        match self {
            Self::P384 => 384,
            Self::P521 => 521,
        }
    }

    /// Parses a curve name.
    ///
    /// ## Errors
    ///
    /// Returns an error if the curve is not CNSA 2.0 compliant or unknown.
    pub fn from_name(name: &str) -> Result<Self, AlgorithmError> {
        match name {
            "P-384" | "secp384r1" => Ok(Self::P384),
            "P-521" | "secp521r1" => Ok(Self::P521),

            // CNSA 2.0: P-256 is explicitly forbidden
            "P-256" | "secp256r1" | "prime256v1" => {
                Err(AlgorithmError::NotCnsaCompliant(name.to_string()))
            }

            _ => Err(AlgorithmError::Unknown(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_is_rejected() {
        let result = SignatureAlgorithm::from_jwa("ES256");
        assert!(matches!(result, Err(AlgorithmError::NotCnsaCompliant(_))));
    }

    #[test]
    fn rs256_is_rejected() {
        let result = SignatureAlgorithm::from_jwa("RS256");
        assert!(matches!(result, Err(AlgorithmError::NotCnsaCompliant(_))));
    }

    #[test]
    fn ps256_is_rejected() {
        let result = SignatureAlgorithm::from_jwa("PS256");
        assert!(matches!(result, Err(AlgorithmError::NotCnsaCompliant(_))));
    }

    #[test]
    fn hs256_is_rejected() {
        let result = SignatureAlgorithm::from_jwa("HS256");
        assert!(matches!(result, Err(AlgorithmError::NotCnsaCompliant(_))));
    }

    #[test]
    fn es384_is_accepted() {
        let result = SignatureAlgorithm::from_jwa("ES384");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SignatureAlgorithm::Es384);
    }

    #[test]
    fn p256_curve_is_rejected() {
        let result = EllipticCurve::from_name("P-256");
        assert!(matches!(result, Err(AlgorithmError::NotCnsaCompliant(_))));
    }

    #[test]
    fn p384_curve_is_accepted() {
        let result = EllipticCurve::from_name("P-384");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EllipticCurve::P384);
    }

    #[test]
    fn rsa_2048_is_rejected() {
        let result = SignatureAlgorithm::validate_rsa_key_size(2048);
        assert!(matches!(
            result,
            Err(AlgorithmError::KeySizeTooSmall(2048, 3072))
        ));
    }

    #[test]
    fn rsa_3072_is_accepted() {
        let result = SignatureAlgorithm::validate_rsa_key_size(3072);
        assert!(result.is_ok());
    }

    #[test]
    fn rsa_4096_is_accepted() {
        let result = SignatureAlgorithm::validate_rsa_key_size(4096);
        assert!(result.is_ok());
    }
}
