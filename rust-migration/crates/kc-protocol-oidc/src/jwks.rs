//! JSON Web Key Set (JWKS) types.
//!
//! Implements JWKS as defined in:
//! - [RFC 7517](https://tools.ietf.org/html/rfc7517) (JSON Web Key)
//! - [RFC 7518](https://tools.ietf.org/html/rfc7518) (JSON Web Algorithms)

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kc_crypto::SignatureAlgorithm;
use serde::{Deserialize, Serialize};

/// Converts a `SignatureAlgorithm` to its JWA string representation.
const fn algorithm_to_jwa(alg: SignatureAlgorithm) -> &'static str {
    match alg {
        SignatureAlgorithm::Es384 => "ES384",
        SignatureAlgorithm::Es512 => "ES512",
        SignatureAlgorithm::Rs384 => "RS384",
        SignatureAlgorithm::Rs512 => "RS512",
        SignatureAlgorithm::Ps384 => "PS384",
        SignatureAlgorithm::Ps512 => "PS512",
    }
}

/// JSON Web Key Set.
///
/// A set of JSON Web Keys, returned by the JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    /// Array of JSON Web Keys.
    pub keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    /// Creates a new empty JWKS.
    #[must_use]
    pub const fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Creates a JWKS with the given keys.
    #[must_use]
    pub const fn with_keys(keys: Vec<JsonWebKey>) -> Self {
        Self { keys }
    }

    /// Adds a key to the set.
    pub fn add_key(&mut self, key: JsonWebKey) {
        self.keys.push(key);
    }

    /// Finds a key by its ID.
    #[must_use]
    pub fn find_key(&self, kid: &str) -> Option<&JsonWebKey> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Finds keys by algorithm.
    #[must_use]
    pub fn find_keys_by_alg(&self, alg: &str) -> Vec<&JsonWebKey> {
        self.keys
            .iter()
            .filter(|k| k.alg.as_deref() == Some(alg))
            .collect()
    }

    /// Finds keys suitable for signing.
    #[must_use]
    pub fn signing_keys(&self) -> Vec<&JsonWebKey> {
        self.keys
            .iter()
            .filter(|k| k.key_use.as_deref() == Some("sig") || k.key_use.is_none())
            .collect()
    }
}

impl Default for JsonWebKeySet {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON Web Key.
///
/// Represents a cryptographic key in JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type (e.g., "RSA", "EC").
    pub kty: KeyType,

    /// Public key use ("sig" for signature, "enc" for encryption).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Key operations (sign, verify, encrypt, decrypt, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// Algorithm intended for use with the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    // === RSA Key Parameters ===
    /// RSA modulus (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    /// RSA exponent (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // === EC Key Parameters ===
    /// EC curve name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<EcCurve>,

    /// EC x coordinate (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// EC y coordinate (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl JsonWebKey {
    /// Creates a new RSA public key.
    #[must_use]
    pub fn rsa_public(
        kid: impl Into<String>,
        algorithm: SignatureAlgorithm,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Self {
        Self {
            kty: KeyType::Rsa,
            key_use: Some("sig".to_string()),
            key_ops: None,
            alg: Some(algorithm_to_jwa(algorithm).to_string()),
            kid: Some(kid.into()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            n: Some(URL_SAFE_NO_PAD.encode(modulus)),
            e: Some(URL_SAFE_NO_PAD.encode(exponent)),
            crv: None,
            x: None,
            y: None,
        }
    }

    /// Creates a new EC public key.
    #[must_use]
    pub fn ec_public(
        kid: impl Into<String>,
        algorithm: SignatureAlgorithm,
        curve: EcCurve,
        x: &[u8],
        y: &[u8],
    ) -> Self {
        Self {
            kty: KeyType::Ec,
            key_use: Some("sig".to_string()),
            key_ops: None,
            alg: Some(algorithm_to_jwa(algorithm).to_string()),
            kid: Some(kid.into()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            n: None,
            e: None,
            crv: Some(curve),
            x: Some(URL_SAFE_NO_PAD.encode(x)),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
        }
    }

    /// Checks if this is an RSA key.
    #[must_use]
    pub const fn is_rsa(&self) -> bool {
        matches!(self.kty, KeyType::Rsa)
    }

    /// Checks if this is an EC key.
    #[must_use]
    pub const fn is_ec(&self) -> bool {
        matches!(self.kty, KeyType::Ec)
    }

    /// Checks if this key is for signing.
    #[must_use]
    pub fn is_signing_key(&self) -> bool {
        self.key_use.as_deref() == Some("sig") || self.key_use.is_none()
    }

    /// Checks if this key is for encryption.
    #[must_use]
    pub fn is_encryption_key(&self) -> bool {
        self.key_use.as_deref() == Some("enc")
    }

    /// Returns the key ID if present.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Returns the algorithm if present.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.alg.as_deref()
    }
}

/// Key type for JWK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA key.
    #[serde(rename = "RSA")]
    Rsa,

    /// Elliptic Curve key.
    #[serde(rename = "EC")]
    Ec,

    /// Octet sequence (symmetric key).
    #[serde(rename = "oct")]
    Oct,

    /// Octet Key Pair (Ed25519, X25519).
    #[serde(rename = "OKP")]
    Okp,
}

/// Elliptic curve names for JWK.
///
/// Note: Only P-384 and P-521 are CNSA 2.0 compliant.
/// P-256 is included only for parsing external keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcCurve {
    /// NIST P-256 curve (NOT CNSA 2.0 compliant - DO NOT USE for new keys).
    #[serde(rename = "P-256")]
    P256,

    /// NIST P-384 curve (CNSA 2.0 compliant).
    #[serde(rename = "P-384")]
    P384,

    /// NIST P-521 curve (CNSA 2.0 compliant).
    #[serde(rename = "P-521")]
    P521,
}

impl EcCurve {
    /// Checks if this curve is CNSA 2.0 compliant.
    #[must_use]
    pub const fn is_cnsa_compliant(&self) -> bool {
        matches!(self, Self::P384 | Self::P521)
    }

    /// Returns the curve name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    /// Returns the expected coordinate length in bytes.
    #[must_use]
    pub const fn coordinate_length(&self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

/// Builder for constructing JWKS from signing keys.
#[derive(Debug, Default)]
pub struct JwksBuilder {
    keys: Vec<JsonWebKey>,
}

impl JwksBuilder {
    /// Creates a new JWKS builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an RSA key to the JWKS.
    #[must_use]
    pub fn add_rsa_key(
        mut self,
        kid: impl Into<String>,
        algorithm: SignatureAlgorithm,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Self {
        self.keys
            .push(JsonWebKey::rsa_public(kid, algorithm, modulus, exponent));
        self
    }

    /// Adds an EC key to the JWKS.
    #[must_use]
    pub fn add_ec_key(
        mut self,
        kid: impl Into<String>,
        algorithm: SignatureAlgorithm,
        curve: EcCurve,
        x: &[u8],
        y: &[u8],
    ) -> Self {
        self.keys
            .push(JsonWebKey::ec_public(kid, algorithm, curve, x, y));
        self
    }

    /// Builds the JWKS.
    #[must_use]
    pub fn build(self) -> JsonWebKeySet {
        JsonWebKeySet { keys: self.keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_new() {
        let jwks = JsonWebKeySet::new();
        assert!(jwks.keys.is_empty());
    }

    #[test]
    fn jwks_find_key() {
        let mut jwks = JsonWebKeySet::new();
        let key = JsonWebKey::ec_public(
            "key1",
            SignatureAlgorithm::Es384,
            EcCurve::P384,
            &[0; 48],
            &[0; 48],
        );
        jwks.add_key(key);

        assert!(jwks.find_key("key1").is_some());
        assert!(jwks.find_key("key2").is_none());
    }

    #[test]
    fn ec_curve_cnsa_compliance() {
        assert!(!EcCurve::P256.is_cnsa_compliant());
        assert!(EcCurve::P384.is_cnsa_compliant());
        assert!(EcCurve::P521.is_cnsa_compliant());
    }

    #[test]
    fn jwk_rsa_key() {
        let modulus = vec![0u8; 256]; // Simplified for test
        let exponent = vec![1, 0, 1]; // 65537

        let key = JsonWebKey::rsa_public("rsa-key-1", SignatureAlgorithm::Rs384, &modulus, &exponent);

        assert!(key.is_rsa());
        assert!(!key.is_ec());
        assert!(key.is_signing_key());
        assert_eq!(key.key_id(), Some("rsa-key-1"));
        assert_eq!(key.algorithm(), Some("RS384"));
    }

    #[test]
    fn jwk_ec_key() {
        let x = vec![0u8; 48];
        let y = vec![0u8; 48];

        let key = JsonWebKey::ec_public("ec-key-1", SignatureAlgorithm::Es384, EcCurve::P384, &x, &y);

        assert!(!key.is_rsa());
        assert!(key.is_ec());
        assert!(key.is_signing_key());
        assert_eq!(key.key_id(), Some("ec-key-1"));
        assert_eq!(key.algorithm(), Some("ES384"));
        assert_eq!(key.crv, Some(EcCurve::P384));
    }

    #[test]
    fn jwks_builder() {
        let jwks = JwksBuilder::new()
            .add_ec_key("ec1", SignatureAlgorithm::Es384, EcCurve::P384, &[0; 48], &[0; 48])
            .add_rsa_key("rsa1", SignatureAlgorithm::Rs384, &[0; 256], &[1, 0, 1])
            .build();

        assert_eq!(jwks.keys.len(), 2);
        assert!(jwks.find_key("ec1").is_some());
        assert!(jwks.find_key("rsa1").is_some());
    }

    #[test]
    fn jwks_serialization() {
        let jwks = JwksBuilder::new()
            .add_ec_key("key1", SignatureAlgorithm::Es384, EcCurve::P384, &[1; 48], &[2; 48])
            .build();

        let json = serde_json::to_string(&jwks).unwrap();
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(json.contains("\"crv\":\"P-384\""));
        assert!(json.contains("\"alg\":\"ES384\""));

        // Roundtrip
        let parsed: JsonWebKeySet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].kid, Some("key1".to_string()));
    }
}
