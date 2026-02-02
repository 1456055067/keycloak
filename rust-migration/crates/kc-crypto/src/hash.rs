//! Hash and HMAC functions for Keycloak Rust.
//!
//! ## CNSA 2.0 Compliance
//!
//! SHA-256 is **forbidden** for primary hashing. Minimum hash is SHA-384.
//!
//! Note: SHA-1 and SHA-256 HMAC functions are provided ONLY for OTP
//! verification compatibility (RFC 6238 TOTP and RFC 4226 HOTP).
//! These should NOT be used for new cryptographic operations.

use crate::algorithm::HashAlgorithm;
use aws_lc_rs::{digest, hmac};

/// Computes a hash of the input data.
///
/// ## CNSA 2.0
///
/// Only SHA-384 and SHA-512 are permitted.
#[must_use]
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    let alg = match algorithm {
        HashAlgorithm::Sha384 => &digest::SHA384,
        HashAlgorithm::Sha512 => &digest::SHA512,
    };

    digest::digest(alg, data).as_ref().to_vec()
}

/// Computes a SHA-384 hash of the input data.
///
/// ## CNSA 2.0
///
/// This is the minimum acceptable hash algorithm.
#[must_use]
pub fn sha384(data: &[u8]) -> Vec<u8> {
    hash(HashAlgorithm::Sha384, data)
}

/// Computes a SHA-512 hash of the input data.
#[must_use]
pub fn sha512(data: &[u8]) -> Vec<u8> {
    hash(HashAlgorithm::Sha512, data)
}

// =============================================================================
// HMAC Functions for OTP Compatibility
// =============================================================================
//
// These HMAC functions are provided ONLY for OTP (TOTP/HOTP) compatibility.
// RFC 6238 and RFC 4226 specify SHA-1 and SHA-256 as valid algorithms.
// For new cryptographic operations, use SHA-384 or SHA-512.

/// Computes HMAC-SHA-1 for OTP compatibility only.
///
/// # Warning
///
/// SHA-1 is deprecated for general cryptographic use. This function
/// exists solely for TOTP/HOTP compatibility per RFC 6238/RFC 4226.
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    hmac::sign(&signing_key, data).as_ref().to_vec()
}

/// Computes HMAC-SHA-256 for OTP compatibility only.
///
/// # Warning
///
/// SHA-256 does not meet CNSA 2.0 requirements. This function
/// exists solely for TOTP/HOTP compatibility per RFC 6238.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&signing_key, data).as_ref().to_vec()
}

/// Computes HMAC-SHA-384 (CNSA 2.0 compliant).
#[must_use]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA384, key);
    hmac::sign(&signing_key, data).as_ref().to_vec()
}

/// Computes HMAC-SHA-512 (CNSA 2.0 compliant).
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA512, key);
    hmac::sign(&signing_key, data).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha384_produces_correct_length() {
        let result = sha384(b"test");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn sha512_produces_correct_length() {
        let result = sha512(b"test");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn sha384_is_deterministic() {
        let a = sha384(b"hello world");
        let b = sha384(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let a = sha384(b"hello");
        let b = sha384(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_sha1_produces_correct_length() {
        let result = hmac_sha1(b"key", b"data");
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn hmac_sha256_produces_correct_length() {
        let result = hmac_sha256(b"key", b"data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn hmac_sha384_produces_correct_length() {
        let result = hmac_sha384(b"key", b"data");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn hmac_sha512_produces_correct_length() {
        let result = hmac_sha512(b"key", b"data");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn hmac_is_deterministic() {
        let a = hmac_sha256(b"key", b"hello world");
        let b = hmac_sha256(b"key", b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_hmacs() {
        let a = hmac_sha256(b"key1", b"data");
        let b = hmac_sha256(b"key2", b"data");
        assert_ne!(a, b);
    }
}
