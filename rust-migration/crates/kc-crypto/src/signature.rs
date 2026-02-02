//! Digital signature operations.
//!
//! ## CNSA 2.0 Compliance
//!
//! - Only P-384 and P-521 curves for ECDSA
//! - Only SHA-384 and SHA-512 for hashing
//! - RSA keys must be at least 3072 bits

use thiserror::Error;

use crate::algorithm::SignatureAlgorithm;

/// Error type for signature operations.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Signing failed.
    #[error("signing failed: {0}")]
    Signing(String),

    /// Verification failed.
    #[error("signature verification failed")]
    Verification,

    /// Invalid key format.
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// Algorithm not supported.
    #[error("algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
}

/// Trait for signature providers.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
pub trait SignatureProvider: Send + Sync {
    /// Signs the given data.
    ///
    /// ## Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignatureError>;

    /// Verifies a signature.
    ///
    /// ## Errors
    ///
    /// Returns an error if verification fails.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignatureError>;

    /// Returns the signature algorithm.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// Trait for key management.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Management)
pub trait KeyProvider: Send + Sync {
    /// Returns the key ID.
    fn key_id(&self) -> &str;

    /// Returns the algorithm.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Returns the public key in JWK format.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key cannot be serialized.
    fn public_key_jwk(&self) -> Result<serde_json::Value, SignatureError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_error_verification_is_generic() {
        let error = SignatureError::Verification;
        // Don't leak information about why verification failed
        assert_eq!(error.to_string(), "signature verification failed");
    }
}
