//! Cryptographic key management and signing operations.
//!
//! This module provides RSA and ECDSA key pair management using aws-lc-rs.
//!
//! ## Supported Algorithms
//!
//! ### RSA
//! - RS384 (RSA PKCS#1 v1.5 with SHA-384)
//! - RS512 (RSA PKCS#1 v1.5 with SHA-512)
//! - PS384 (RSA-PSS with SHA-384)
//! - PS512 (RSA-PSS with SHA-512)
//!
//! ### ECDSA
//! - ES384 (ECDSA with P-384 and SHA-384)
//! - ES512 (ECDSA with P-521 and SHA-512)
//!
//! ## CNSA 2.0 Compliance
//!
//! By default, only CNSA 2.0 compliant algorithms are provided.
//! SHA-256 based algorithms (ES256, RS256, PS256) are not available
//! unless the `legacy-sha256` feature is enabled.

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        self, EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
        ECDSA_P521_SHA512_ASN1_SIGNING,
    },
};
use base64::Engine;

use crate::algorithm::SignatureAlgorithm;
use crate::signature::SignatureError;

/// RSA key pair for signing and verification.
///
/// Supports PKCS#1 v1.5 and PSS padding schemes.
pub struct RsaSigningKey {
    key_pair: RsaKeyPair,
    key_id: String,
    algorithm: SignatureAlgorithm,
}

impl RsaSigningKey {
    /// Creates a new RSA signing key from PKCS#8 DER-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `pkcs8_der` - The PKCS#8 DER-encoded private key
    /// * `algorithm` - The signature algorithm (must be RSA-based)
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or algorithm is not RSA-based.
    pub fn from_pkcs8(pkcs8_der: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, SignatureError> {
        if !algorithm.is_rsa() {
            return Err(SignatureError::UnsupportedAlgorithm(format!(
                "{algorithm:?} is not an RSA algorithm"
            )));
        }

        let key_pair = RsaKeyPair::from_pkcs8(pkcs8_der)
            .map_err(|e| SignatureError::InvalidKey(format!("Invalid RSA PKCS#8 key: {e}")))?;

        // Validate key size (CNSA 2.0 requires >= 3072 bits)
        let key_bits = key_pair.public_modulus_len() * 8;
        #[allow(clippy::cast_possible_truncation)]
        SignatureAlgorithm::validate_rsa_key_size(key_bits as u32)
            .map_err(|e| SignatureError::InvalidKey(e.to_string()))?;

        // Generate key ID from public key hash
        let key_id = generate_key_id(key_pair.public_key().as_ref());

        Ok(Self {
            key_pair,
            key_id,
            algorithm,
        })
    }

    /// Creates a new RSA signing key from DER-encoded private key (traditional format).
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded RSA private key (`RSAPrivateKey` format)
    /// * `algorithm` - The signature algorithm (must be RSA-based)
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or algorithm is not RSA-based.
    pub fn from_der(der: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, SignatureError> {
        if !algorithm.is_rsa() {
            return Err(SignatureError::UnsupportedAlgorithm(format!(
                "{algorithm:?} is not an RSA algorithm"
            )));
        }

        let key_pair = RsaKeyPair::from_der(der)
            .map_err(|e| SignatureError::InvalidKey(format!("Invalid RSA DER key: {e}")))?;

        // Validate key size (CNSA 2.0 requires >= 3072 bits)
        let key_bits = key_pair.public_modulus_len() * 8;
        #[allow(clippy::cast_possible_truncation)]
        SignatureAlgorithm::validate_rsa_key_size(key_bits as u32)
            .map_err(|e| SignatureError::InvalidKey(e.to_string()))?;

        // Generate key ID from public key hash
        let key_id = generate_key_id(key_pair.public_key().as_ref());

        Ok(Self {
            key_pair,
            key_id,
            algorithm,
        })
    }

    /// Returns the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Signs the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; self.key_pair.public_modulus_len()];

        let padding = match self.algorithm {
            SignatureAlgorithm::Rs384 => &signature::RSA_PKCS1_SHA384,
            SignatureAlgorithm::Rs512 => &signature::RSA_PKCS1_SHA512,
            SignatureAlgorithm::Ps384 => &signature::RSA_PSS_SHA384,
            SignatureAlgorithm::Ps512 => &signature::RSA_PSS_SHA512,
            _ => {
                return Err(SignatureError::UnsupportedAlgorithm(format!(
                    "{:?} not supported for RSA signing",
                    self.algorithm
                )));
            }
        };

        self.key_pair
            .sign(padding, &rng, data, &mut signature)
            .map_err(|e| SignatureError::Signing(format!("RSA signing failed: {e}")))?;

        Ok(signature)
    }

    /// Returns the public key in JWK format.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be serialized.
    pub fn public_key_jwk(&self) -> Result<serde_json::Value, SignatureError> {
        let public_key = self.key_pair.public_key();
        let (n, e) = extract_rsa_components(public_key.as_ref())?;

        Ok(serde_json::json!({
            "kty": "RSA",
            "kid": self.key_id,
            "use": "sig",
            "alg": self.algorithm.jwa_name(),
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e),
        }))
    }
}

/// ECDSA key pair for signing and verification.
///
/// Supports P-384 and P-521 curves only (CNSA 2.0 compliant).
pub struct EcdsaSigningKey {
    key_pair: EcdsaKeyPair,
    key_id: String,
    algorithm: SignatureAlgorithm,
}

impl EcdsaSigningKey {
    /// Creates a new ECDSA signing key from PKCS#8 DER-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `pkcs8_der` - The PKCS#8 DER-encoded private key
    /// * `algorithm` - The signature algorithm (must be ECDSA-based)
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or algorithm is not ECDSA-based.
    pub fn from_pkcs8(pkcs8_der: &[u8], algorithm: SignatureAlgorithm) -> Result<Self, SignatureError> {
        if !algorithm.is_ecdsa() {
            return Err(SignatureError::UnsupportedAlgorithm(format!(
                "{algorithm:?} is not an ECDSA algorithm"
            )));
        }

        let signing_alg = match algorithm {
            SignatureAlgorithm::Es384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            SignatureAlgorithm::Es512 => &ECDSA_P521_SHA512_ASN1_SIGNING,
            _ => {
                return Err(SignatureError::UnsupportedAlgorithm(format!(
                    "{algorithm:?} not supported"
                )));
            }
        };

        let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, pkcs8_der)
            .map_err(|e| SignatureError::InvalidKey(format!("Invalid ECDSA PKCS#8 key: {e}")))?;

        // Generate key ID from public key hash
        let key_id = generate_key_id(key_pair.public_key().as_ref());

        Ok(Self {
            key_pair,
            key_id,
            algorithm,
        })
    }

    /// Returns the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Signs the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let rng = SystemRandom::new();

        let signature = self
            .key_pair
            .sign(&rng, data)
            .map_err(|e| SignatureError::Signing(format!("ECDSA signing failed: {e}")))?;

        Ok(signature.as_ref().to_vec())
    }

    /// Returns the public key in JWK format.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be serialized.
    pub fn public_key_jwk(&self) -> Result<serde_json::Value, SignatureError> {
        let public_key = self.key_pair.public_key();
        let (x, y, crv) = extract_ec_components(public_key.as_ref(), self.algorithm)?;

        Ok(serde_json::json!({
            "kty": "EC",
            "kid": self.key_id,
            "use": "sig",
            "alg": self.algorithm.jwa_name(),
            "crv": crv,
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y),
        }))
    }
}

/// Generates a key ID from the public key bytes.
fn generate_key_id(public_key: &[u8]) -> String {
    let hash = crate::sha256(public_key);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash[..8])
}

/// Extracts RSA modulus (n) and exponent (e) from a `SubjectPublicKeyInfo`.
fn extract_rsa_components(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignatureError> {
    // SubjectPublicKeyInfo is ASN.1 DER encoded
    // We need to parse it to extract n and e
    // The structure is:
    // SEQUENCE {
    //   SEQUENCE { OID, NULL }
    //   BIT STRING (containing RSAPublicKey)
    // }
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }

    // For simplicity, we'll look for the inner RSAPublicKey sequence
    // This is a simplified parser - a full implementation would use proper ASN.1

    // Skip the outer SEQUENCE and algorithm SEQUENCE
    let mut pos = 0;

    // Skip outer SEQUENCE tag and length
    if spki.get(pos) != Some(&0x30) {
        return Err(SignatureError::InvalidKey("Invalid SPKI: expected SEQUENCE".to_string()));
    }
    pos += 1;
    pos = skip_length(spki, pos)?;

    // Skip algorithm SEQUENCE
    if spki.get(pos) != Some(&0x30) {
        return Err(SignatureError::InvalidKey("Invalid SPKI: expected algorithm SEQUENCE".to_string()));
    }
    pos += 1;
    let alg_len = read_length(spki, pos)?;
    pos = skip_length(spki, pos)?;
    pos += alg_len;

    // BIT STRING containing the key
    if spki.get(pos) != Some(&0x03) {
        return Err(SignatureError::InvalidKey("Invalid SPKI: expected BIT STRING".to_string()));
    }
    pos += 1;
    pos = skip_length(spki, pos)?;

    // Skip unused bits byte
    pos += 1;

    // Now we're at the RSAPublicKey SEQUENCE
    if spki.get(pos) != Some(&0x30) {
        return Err(SignatureError::InvalidKey("Invalid RSAPublicKey: expected SEQUENCE".to_string()));
    }
    pos += 1;
    pos = skip_length(spki, pos)?;

    // Read modulus (n)
    if spki.get(pos) != Some(&0x02) {
        return Err(SignatureError::InvalidKey("Invalid RSAPublicKey: expected INTEGER for n".to_string()));
    }
    pos += 1;
    let n_len = read_length(spki, pos)?;
    pos = skip_length(spki, pos)?;
    let mut n = spki[pos..pos + n_len].to_vec();
    // Remove leading zero if present (ASN.1 INTEGER padding)
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    pos += n_len;

    // Read exponent (e)
    if spki.get(pos) != Some(&0x02) {
        return Err(SignatureError::InvalidKey("Invalid RSAPublicKey: expected INTEGER for e".to_string()));
    }
    pos += 1;
    let e_len = read_length(spki, pos)?;
    pos = skip_length(spki, pos)?;
    let mut e = spki[pos..pos + e_len].to_vec();
    // Remove leading zero if present
    if !e.is_empty() && e[0] == 0 {
        e.remove(0);
    }

    Ok((n, e))
}

/// Extracts EC x and y coordinates from a `SubjectPublicKeyInfo`.
fn extract_ec_components(
    spki: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>, &'static str), SignatureError> {
    // EC public key is a point in uncompressed form: 0x04 || x || y
    // The sizes depend on the curve

    let (coord_size, crv) = match algorithm {
        SignatureAlgorithm::Es384 => (48, "P-384"),
        SignatureAlgorithm::Es512 => (66, "P-521"),
        _ => return Err(SignatureError::UnsupportedAlgorithm(format!("{algorithm:?}"))),
    };

    // Find the uncompressed point marker (0x04)
    let point_start = spki
        .iter()
        .position(|&b| b == 0x04)
        .ok_or_else(|| SignatureError::InvalidKey("EC point marker not found".to_string()))?;

    let expected_len = 1 + coord_size * 2;
    if spki.len() < point_start + expected_len {
        return Err(SignatureError::InvalidKey("EC public key too short".to_string()));
    }

    let x = spki[point_start + 1..point_start + 1 + coord_size].to_vec();
    let y = spki[point_start + 1 + coord_size..point_start + 1 + coord_size * 2].to_vec();

    Ok((x, y, crv))
}

/// Reads an ASN.1 length field and returns the length value.
fn read_length(data: &[u8], pos: usize) -> Result<usize, SignatureError> {
    let first = *data.get(pos).ok_or_else(|| SignatureError::InvalidKey("Unexpected end of data".to_string()))?;

    if first < 0x80 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 {
            return Err(SignatureError::InvalidKey("Length too large".to_string()));
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            let byte = *data.get(pos + 1 + i).ok_or_else(|| SignatureError::InvalidKey("Unexpected end of length".to_string()))?;
            len = (len << 8) | (byte as usize);
        }
        Ok(len)
    }
}

/// Skips an ASN.1 length field and returns the new position.
fn skip_length(data: &[u8], pos: usize) -> Result<usize, SignatureError> {
    let first = *data.get(pos).ok_or_else(|| SignatureError::InvalidKey("Unexpected end of data".to_string()))?;

    if first < 0x80 {
        Ok(pos + 1)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        Ok(pos + 1 + num_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_id_generation() {
        let data = b"test public key data";
        let key_id = generate_key_id(data);
        assert!(!key_id.is_empty());
        // Key ID should be consistent for same input
        assert_eq!(key_id, generate_key_id(data));
    }

    #[test]
    fn ecdsa_algorithm_validation() {
        // ECDSA key should not accept RSA algorithm
        let result = EcdsaSigningKey::from_pkcs8(&[], SignatureAlgorithm::Rs384);
        assert!(result.is_err());
    }

    #[test]
    fn rsa_algorithm_validation() {
        // RSA key should not accept ECDSA algorithm
        let result = RsaSigningKey::from_pkcs8(&[], SignatureAlgorithm::Es384);
        assert!(result.is_err());
    }
}
