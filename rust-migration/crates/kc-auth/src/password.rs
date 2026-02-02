//! Password hashing and verification using Argon2id.
//!
//! Implements NIST SP 800-63B password recommendations:
//! - Argon2id for memory-hard hashing
//! - Secure random salt generation
//! - Constant-time comparison

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::{AuthError, AuthResult};

/// Password hashing configuration.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Memory cost in KiB.
    pub memory_cost: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism factor.
    pub parallelism: u32,
    /// Output hash length.
    pub hash_length: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        // OWASP recommended settings for Argon2id
        Self {
            memory_cost: 19 * 1024, // 19 MiB
            time_cost: 2,
            parallelism: 1,
            hash_length: 32,
        }
    }
}

impl PasswordPolicy {
    /// Creates a new password policy with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the memory cost in KiB.
    #[must_use]
    pub const fn memory_cost(mut self, kib: u32) -> Self {
        self.memory_cost = kib;
        self
    }

    /// Sets the time cost (iterations).
    #[must_use]
    pub const fn time_cost(mut self, iterations: u32) -> Self {
        self.time_cost = iterations;
        self
    }

    /// Sets the parallelism factor.
    #[must_use]
    pub const fn parallelism(mut self, p: u32) -> Self {
        self.parallelism = p;
        self
    }

    /// Builds the Argon2 parameters.
    #[allow(clippy::missing_const_for_fn)] // Params::new is not const
    fn build_params(&self) -> Result<Params, argon2::Error> {
        Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(self.hash_length as usize),
        )
    }
}

/// Password hasher using Argon2id.
pub struct PasswordHasherService {
    policy: PasswordPolicy,
}

impl PasswordHasherService {
    /// Creates a new password hasher with the given policy.
    #[must_use]
    pub const fn new(policy: PasswordPolicy) -> Self {
        Self { policy }
    }

    /// Creates a new password hasher with default policy.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PasswordPolicy::default())
    }

    /// Hashes a password.
    ///
    /// Returns the PHC-formatted hash string.
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails.
    pub fn hash(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);

        let params = self
            .policy
            .build_params()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(hash.to_string())
    }

    /// Verifies a password against a hash.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidCredentials` if verification fails.
    pub fn verify(&self, password: &str, hash: &str) -> AuthResult<()> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| AuthError::Internal(e.to_string()))?;

        // Argon2::default() can verify any Argon2 variant
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)
    }

    /// Checks if a hash needs to be re-hashed due to policy changes.
    ///
    /// Returns `true` if the hash was created with different parameters.
    #[must_use]
    pub fn needs_rehash(&self, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return true;
        };

        // Check algorithm
        if parsed.algorithm != argon2::ARGON2ID_IDENT {
            return true;
        }

        // Check parameters if present - params is a field, not a method
        let params = &parsed.params;
        let m_cost = params.get_decimal("m").unwrap_or(0);
        let t_cost = params.get_decimal("t").unwrap_or(0);
        let p_cost = params.get_decimal("p").unwrap_or(0);

        if m_cost != self.policy.memory_cost
            || t_cost != self.policy.time_cost
            || p_cost != self.policy.parallelism
        {
            return true;
        }

        false
    }
}

impl Default for PasswordHasherService {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let hasher = PasswordHasherService::with_defaults();
        let password = "correct horse battery staple";

        let hash = hasher.hash(password).unwrap();

        // Hash should be PHC formatted
        assert!(hash.starts_with("$argon2id$"));

        // Correct password should verify
        assert!(hasher.verify(password, &hash).is_ok());

        // Wrong password should not verify
        assert!(hasher.verify("wrong password", &hash).is_err());
    }

    #[test]
    fn different_passwords_produce_different_hashes() {
        let hasher = PasswordHasherService::with_defaults();

        let hash1 = hasher.hash("password1").unwrap();
        let hash2 = hasher.hash("password2").unwrap();
        let hash3 = hasher.hash("password1").unwrap();

        // Different passwords produce different hashes
        assert_ne!(hash1, hash2);

        // Same password produces different hashes (different salts)
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn needs_rehash_detects_old_params() {
        // Create hasher with specific params
        let hasher = PasswordHasherService::new(PasswordPolicy {
            memory_cost: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            hash_length: 32,
        });

        let hash = hasher.hash("password").unwrap();

        // Same params should not need rehash
        assert!(!hasher.needs_rehash(&hash));

        // Different params should need rehash
        let different_hasher = PasswordHasherService::new(PasswordPolicy {
            memory_cost: 32 * 1024,
            time_cost: 3,
            parallelism: 1,
            hash_length: 32,
        });

        assert!(different_hasher.needs_rehash(&hash));
    }

    #[test]
    fn custom_policy() {
        let policy = PasswordPolicy::new()
            .memory_cost(32 * 1024)
            .time_cost(3)
            .parallelism(2);

        let hasher = PasswordHasherService::new(policy);
        let hash = hasher.hash("password").unwrap();

        assert!(hasher.verify("password", &hash).is_ok());
    }
}
