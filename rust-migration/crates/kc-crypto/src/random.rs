//! Cryptographically secure random number generation.
//!
//! This module provides secure random generation for:
//! - Authorization codes (OAuth 2.0/OIDC)
//! - Session IDs
//! - Token identifiers
//! - Nonce values
//!
//! All functions use cryptographically secure random number generators
//! suitable for security-sensitive operations.

use rand::distr::{Alphanumeric, SampleString};
use rand::{Rng, SeedableRng};

/// Generates a cryptographically secure random byte array.
///
/// Uses the thread-local random number generator which is cryptographically
/// secure by default.
///
/// # Arguments
///
/// * `len` - Number of random bytes to generate
///
/// # Returns
///
/// A vector containing `len` cryptographically secure random bytes.
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Generates a cryptographically secure random string.
///
/// The string contains alphanumeric characters (a-z, A-Z, 0-9) and is
/// suitable for authorization codes, session IDs, and other tokens.
///
/// # Arguments
///
/// * `len` - Length of the string to generate
///
/// # Returns
///
/// A string of `len` alphanumeric characters.
#[must_use]
pub fn random_alphanumeric(len: usize) -> String {
    let mut rng = rand::rng();
    Alphanumeric.sample_string(&mut rng, len)
}

/// Generates a secure random authorization code.
///
/// Creates a 32-character alphanumeric code suitable for OAuth 2.0
/// authorization code flow.
///
/// # Security
///
/// The code has approximately 190 bits of entropy (log2(62^32)),
/// exceeding the minimum 128 bits recommended by RFC 6749.
#[must_use]
pub fn generate_auth_code() -> String {
    random_alphanumeric(32)
}

/// Generates a secure random token identifier.
///
/// Creates a 24-character alphanumeric identifier suitable for
/// token JTI (JWT ID) claims.
#[must_use]
pub fn generate_token_id() -> String {
    random_alphanumeric(24)
}

/// Generates a secure random session identifier.
///
/// Creates a 32-character alphanumeric identifier for session tracking.
#[must_use]
pub fn generate_session_id() -> String {
    random_alphanumeric(32)
}

/// Generates a secure random client secret.
///
/// Creates a 32-character alphanumeric secret suitable for OAuth 2.0
/// confidential clients.
///
/// # Security
///
/// The secret has approximately 190 bits of entropy (log2(62^32)),
/// providing strong security for client authentication.
#[must_use]
pub fn generate_client_secret() -> String {
    random_alphanumeric(32)
}

/// Generates a URL-safe base64-encoded random string.
///
/// Suitable for use in URLs without encoding issues.
///
/// # Arguments
///
/// * `byte_len` - Number of random bytes (output will be ~4/3 this length)
#[must_use]
pub fn random_base64url(byte_len: usize) -> String {
    let bytes = random_bytes(byte_len);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Generates a cryptographically secure random number in a range.
///
/// # Arguments
///
/// * `min` - Minimum value (inclusive)
/// * `max` - Maximum value (exclusive)
///
/// # Panics
///
/// Panics if `min >= max`.
#[must_use]
pub fn random_range(min: u64, max: u64) -> u64 {
    assert!(min < max, "min must be less than max");
    let mut rng = rand::rng();
    rng.random_range(min..max)
}

/// Generates a deterministic random value from a seed (for testing only).
///
/// # Warning
///
/// This function is NOT cryptographically secure and should only be used
/// for testing purposes. For production code, use the other functions
/// in this module.
///
/// # Arguments
///
/// * `seed` - A 32-byte seed value
/// * `len` - Number of random bytes to generate
#[must_use]
pub fn seeded_random(seed: [u8; 32], len: usize) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn random_bytes_produces_correct_length() {
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(32).len(), 32);
        assert_eq!(random_bytes(64).len(), 64);
    }

    #[test]
    fn random_bytes_produces_different_values() {
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_ne!(a, b);
    }

    #[test]
    fn random_alphanumeric_produces_correct_length() {
        assert_eq!(random_alphanumeric(16).len(), 16);
        assert_eq!(random_alphanumeric(32).len(), 32);
        assert_eq!(random_alphanumeric(64).len(), 64);
    }

    #[test]
    fn random_alphanumeric_only_contains_valid_chars() {
        let s = random_alphanumeric(1000);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_auth_code_format() {
        let code = generate_auth_code();
        assert_eq!(code.len(), 32);
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_auth_code_uniqueness() {
        let codes: HashSet<String> = (0..1000).map(|_| generate_auth_code()).collect();
        // All 1000 codes should be unique
        assert_eq!(codes.len(), 1000);
    }

    #[test]
    fn generate_token_id_format() {
        let id = generate_token_id();
        assert_eq!(id.len(), 24);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_session_id_format() {
        let id = generate_session_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_client_secret_format() {
        let secret = generate_client_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_client_secret_uniqueness() {
        let secrets: HashSet<String> = (0..1000).map(|_| generate_client_secret()).collect();
        // All 1000 secrets should be unique
        assert_eq!(secrets.len(), 1000);
    }

    #[test]
    fn random_base64url_no_special_chars() {
        let s = random_base64url(32);
        // URL-safe base64 only contains alphanumeric, dash, and underscore
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn random_range_within_bounds() {
        for _ in 0..1000 {
            let val = random_range(10, 100);
            assert!(val >= 10);
            assert!(val < 100);
        }
    }

    #[test]
    #[should_panic(expected = "min must be less than max")]
    fn random_range_panics_on_invalid_range() {
        let _ = random_range(100, 10);
    }

    #[test]
    fn seeded_random_is_deterministic() {
        let seed = [42u8; 32];
        let a = seeded_random(seed, 32);
        let b = seeded_random(seed, 32);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_values() {
        let a = seeded_random([1u8; 32], 32);
        let b = seeded_random([2u8; 32], 32);
        assert_ne!(a, b);
    }
}
