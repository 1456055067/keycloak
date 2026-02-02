//! Hash functions for Keycloak Rust.
//!
//! ## CNSA 2.0 Compliance
//!
//! SHA-256 is **forbidden**. Minimum hash is SHA-384.

use crate::algorithm::HashAlgorithm;
use aws_lc_rs::digest;

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
}
