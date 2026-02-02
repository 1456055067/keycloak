//! One-Time Password (OTP) verification.
//!
//! Supports TOTP (time-based) and HOTP (counter-based) algorithms
//! per RFC 6238 and RFC 4226.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AuthError, AuthResult};

/// OTP algorithm type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    /// HMAC-SHA1 (default, widely supported).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl OtpAlgorithm {
    /// Returns the algorithm name for display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// TOTP configuration.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Number of digits in the OTP.
    pub digits: u8,
    /// Time period in seconds.
    pub period: u32,
    /// Hash algorithm.
    pub algorithm: OtpAlgorithm,
    /// Number of periods to check before/after current.
    pub look_around: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha1,
            look_around: 1,
        }
    }
}

impl TotpConfig {
    /// Creates a new TOTP configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the number of digits.
    #[must_use]
    pub const fn digits(mut self, digits: u8) -> Self {
        self.digits = digits;
        self
    }

    /// Sets the time period in seconds.
    #[must_use]
    pub const fn period(mut self, period: u32) -> Self {
        self.period = period;
        self
    }

    /// Sets the hash algorithm.
    #[must_use]
    pub const fn algorithm(mut self, algorithm: OtpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the look-around window.
    #[must_use]
    pub const fn look_around(mut self, periods: u32) -> Self {
        self.look_around = periods;
        self
    }
}

/// HOTP configuration.
#[derive(Debug, Clone)]
pub struct HotpConfig {
    /// Number of digits in the OTP.
    pub digits: u8,
    /// Hash algorithm.
    pub algorithm: OtpAlgorithm,
    /// Look-ahead window for counter.
    pub look_ahead: u32,
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            algorithm: OtpAlgorithm::Sha1,
            look_ahead: 10,
        }
    }
}

impl HotpConfig {
    /// Creates a new HOTP configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the number of digits.
    #[must_use]
    pub const fn digits(mut self, digits: u8) -> Self {
        self.digits = digits;
        self
    }

    /// Sets the hash algorithm.
    #[must_use]
    pub const fn algorithm(mut self, algorithm: OtpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the look-ahead window.
    #[must_use]
    pub const fn look_ahead(mut self, count: u32) -> Self {
        self.look_ahead = count;
        self
    }
}

/// OTP verifier.
pub struct OtpVerifier;

impl OtpVerifier {
    /// Verifies a TOTP code.
    ///
    /// # Arguments
    ///
    /// * `secret` - The base32-encoded secret
    /// * `code` - The OTP code to verify
    /// * `config` - TOTP configuration
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidOtp` if verification fails.
    pub fn verify_totp(secret: &[u8], code: &str, config: &TotpConfig) -> AuthResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let current_counter = now.as_secs() / u64::from(config.period);

        // Check current and surrounding periods
        for offset in 0..=config.look_around {
            // Check current + offset
            if Self::check_hotp(
                secret,
                current_counter.saturating_add(u64::from(offset)),
                code,
                config.digits,
                config.algorithm,
            ) {
                return Ok(());
            }

            // Check current - offset (if offset > 0)
            if offset > 0
                && Self::check_hotp(
                    secret,
                    current_counter.saturating_sub(u64::from(offset)),
                    code,
                    config.digits,
                    config.algorithm,
                )
            {
                return Ok(());
            }
        }

        Err(AuthError::InvalidOtp)
    }

    /// Verifies an HOTP code.
    ///
    /// Returns the new counter value if successful.
    ///
    /// # Arguments
    ///
    /// * `secret` - The base32-encoded secret
    /// * `counter` - The current counter value
    /// * `code` - The OTP code to verify
    /// * `config` - HOTP configuration
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidOtp` if verification fails.
    pub fn verify_hotp(
        secret: &[u8],
        counter: u64,
        code: &str,
        config: &HotpConfig,
    ) -> AuthResult<u64> {
        for offset in 0..=config.look_ahead {
            let check_counter = counter.saturating_add(u64::from(offset));
            if Self::check_hotp(secret, check_counter, code, config.digits, config.algorithm) {
                // Return the next counter value
                return Ok(check_counter + 1);
            }
        }

        Err(AuthError::InvalidOtp)
    }

    /// Generates a TOTP code for the current time.
    ///
    /// # Errors
    ///
    /// Returns an error if time cannot be determined.
    pub fn generate_totp(secret: &[u8], config: &TotpConfig) -> AuthResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let counter = now.as_secs() / u64::from(config.period);
        Ok(Self::generate_hotp(secret, counter, config.digits, config.algorithm))
    }

    /// Generates an HOTP code for a counter.
    #[must_use]
    pub fn generate_hotp(secret: &[u8], counter: u64, digits: u8, algorithm: OtpAlgorithm) -> String {
        let hmac = Self::compute_hmac(secret, counter, algorithm);
        let code = Self::truncate(&hmac, digits);
        format!("{:0width$}", code, width = digits as usize)
    }

    fn check_hotp(
        secret: &[u8],
        counter: u64,
        code: &str,
        digits: u8,
        algorithm: OtpAlgorithm,
    ) -> bool {
        let expected = Self::generate_hotp(secret, counter, digits, algorithm);
        constant_time_eq(code.as_bytes(), expected.as_bytes())
    }

    fn compute_hmac(secret: &[u8], counter: u64, algorithm: OtpAlgorithm) -> Vec<u8> {
        use kc_crypto::{hmac_sha1, hmac_sha256, hmac_sha512};

        let counter_bytes = counter.to_be_bytes();

        match algorithm {
            OtpAlgorithm::Sha1 => hmac_sha1(secret, &counter_bytes),
            OtpAlgorithm::Sha256 => hmac_sha256(secret, &counter_bytes),
            OtpAlgorithm::Sha512 => hmac_sha512(secret, &counter_bytes),
        }
    }

    fn truncate(hmac: &[u8], digits: u8) -> u32 {
        let offset = (hmac.last().unwrap_or(&0) & 0x0f) as usize;
        let code = u32::from_be_bytes([
            hmac.get(offset).copied().unwrap_or(0) & 0x7f,
            hmac.get(offset + 1).copied().unwrap_or(0),
            hmac.get(offset + 2).copied().unwrap_or(0),
            hmac.get(offset + 3).copied().unwrap_or(0),
        ]);
        code % 10_u32.pow(u32::from(digits))
    }
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_config_defaults() {
        let config = TotpConfig::default();
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn hotp_config_defaults() {
        let config = HotpConfig::default();
        assert_eq!(config.digits, 6);
        assert_eq!(config.look_ahead, 10);
    }

    #[test]
    fn generate_hotp_produces_correct_length() {
        let secret = b"test secret key";

        let code = OtpVerifier::generate_hotp(secret, 0, 6, OtpAlgorithm::Sha256);
        assert_eq!(code.len(), 6);

        let code = OtpVerifier::generate_hotp(secret, 0, 8, OtpAlgorithm::Sha256);
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn hotp_verification() {
        let secret = b"test secret key";
        let config = HotpConfig::default();

        // Generate a code for counter 5
        let code = OtpVerifier::generate_hotp(secret, 5, config.digits, config.algorithm);

        // Verify starting from counter 5 should succeed
        let result = OtpVerifier::verify_hotp(secret, 5, &code, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 6); // Next counter

        // Verify starting from counter 0 should succeed (within look-ahead)
        let result = OtpVerifier::verify_hotp(secret, 0, &code, &config);
        assert!(result.is_ok());

        // Wrong code should fail
        let result = OtpVerifier::verify_hotp(secret, 5, "000000", &config);
        assert!(result.is_err());
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
