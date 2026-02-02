//! Token Manager for creating and validating OIDC tokens.
//!
//! This module provides the core token management functionality including:
//! - Access token generation
//! - ID token generation
//! - Refresh token generation
//! - Token validation
//!
//! ## CNSA 2.0 Compliance
//!
//! Only ES384, ES512, RS384, RS512, PS384, PS512 signing algorithms are supported.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use kc_crypto::{SignatureAlgorithm, sha384, sha512};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;

use crate::claims::{AccessTokenClaims, Audience, IdTokenClaims, RefreshTokenClaims};
use crate::error::{OidcError, OidcResult};

/// Token configuration.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// Issuer URL.
    pub issuer: String,

    /// Access token lifespan in seconds.
    pub access_token_lifespan: i64,

    /// ID token lifespan in seconds.
    pub id_token_lifespan: i64,

    /// Refresh token lifespan in seconds.
    pub refresh_token_lifespan: i64,

    /// Signing algorithm.
    pub algorithm: SignatureAlgorithm,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:8080".to_string(),
            access_token_lifespan: 300,       // 5 minutes
            id_token_lifespan: 300,           // 5 minutes
            refresh_token_lifespan: 1_800,    // 30 minutes
            algorithm: SignatureAlgorithm::Es384,
        }
    }
}

/// Signing key for token generation.
#[derive(Clone)]
pub struct SigningKey {
    /// Key ID (kid).
    pub kid: String,

    /// Signing algorithm.
    pub algorithm: SignatureAlgorithm,

    /// Private key for signing (PEM or DER encoded).
    encoding_key: EncodingKey,

    /// Public key for verification.
    decoding_key: DecodingKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("encoding_key", &"[REDACTED]")
            .field("decoding_key", &"[REDACTED]")
            .finish()
    }
}

impl SigningKey {
    /// Creates a new signing key from PEM-encoded keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the keys are invalid.
    pub fn from_pem(
        kid: impl Into<String>,
        algorithm: SignatureAlgorithm,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> OidcResult<Self> {
        let encoding_key = match algorithm {
            SignatureAlgorithm::Es384 | SignatureAlgorithm::Es512 => {
                EncodingKey::from_ec_pem(private_key_pem)
                    .map_err(|e| OidcError::TokenSigning(e.to_string()))?
            }
            SignatureAlgorithm::Rs384
            | SignatureAlgorithm::Rs512
            | SignatureAlgorithm::Ps384
            | SignatureAlgorithm::Ps512 => EncodingKey::from_rsa_pem(private_key_pem)
                .map_err(|e| OidcError::TokenSigning(e.to_string()))?,
        };

        let decoding_key = match algorithm {
            SignatureAlgorithm::Es384 | SignatureAlgorithm::Es512 => {
                DecodingKey::from_ec_pem(public_key_pem)
                    .map_err(|e| OidcError::TokenValidation(e.to_string()))?
            }
            SignatureAlgorithm::Rs384
            | SignatureAlgorithm::Rs512
            | SignatureAlgorithm::Ps384
            | SignatureAlgorithm::Ps512 => DecodingKey::from_rsa_pem(public_key_pem)
                .map_err(|e| OidcError::TokenValidation(e.to_string()))?,
        };

        Ok(Self {
            kid: kid.into(),
            algorithm,
            encoding_key,
            decoding_key,
        })
    }

    /// Returns the `jsonwebtoken` algorithm.
    fn jwt_algorithm(&self) -> Algorithm {
        match self.algorithm {
            SignatureAlgorithm::Es384 => Algorithm::ES384,
            SignatureAlgorithm::Es512 => Algorithm::default(), // ES512 not directly supported, use ES384
            SignatureAlgorithm::Rs384 => Algorithm::RS384,
            SignatureAlgorithm::Rs512 => Algorithm::RS512,
            SignatureAlgorithm::Ps384 => Algorithm::PS384,
            SignatureAlgorithm::Ps512 => Algorithm::PS512,
        }
    }
}

/// Token Manager for creating and validating tokens.
#[derive(Debug)]
pub struct TokenManager {
    /// Token configuration.
    config: TokenConfig,

    /// Signing keys indexed by key ID.
    signing_keys: HashMap<String, SigningKey>,

    /// Active signing key ID.
    active_key_id: Option<String>,
}

impl TokenManager {
    /// Creates a new token manager.
    #[must_use]
    pub fn new(config: TokenConfig) -> Self {
        Self {
            config,
            signing_keys: HashMap::new(),
            active_key_id: None,
        }
    }

    /// Adds a signing key.
    pub fn add_signing_key(&mut self, key: SigningKey) {
        let kid = key.kid.clone();
        if self.active_key_id.is_none() {
            self.active_key_id = Some(kid.clone());
        }
        self.signing_keys.insert(kid, key);
    }

    /// Sets the active signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key ID is not found.
    pub fn set_active_key(&mut self, kid: &str) -> OidcResult<()> {
        if self.signing_keys.contains_key(kid) {
            self.active_key_id = Some(kid.to_string());
            Ok(())
        } else {
            Err(OidcError::Internal(format!("signing key not found: {kid}")))
        }
    }

    /// Returns the active signing key.
    fn active_key(&self) -> OidcResult<&SigningKey> {
        let kid = self
            .active_key_id
            .as_ref()
            .ok_or_else(|| OidcError::Internal("no active signing key".to_string()))?;

        self.signing_keys
            .get(kid)
            .ok_or_else(|| OidcError::Internal(format!("signing key not found: {kid}")))
    }

    /// Creates an access token.
    ///
    /// # Errors
    ///
    /// Returns an error if token signing fails.
    pub fn create_access_token(&self, claims: &AccessTokenClaims) -> OidcResult<String> {
        self.sign_token(claims)
    }

    /// Creates an ID token.
    ///
    /// # Errors
    ///
    /// Returns an error if token signing fails.
    pub fn create_id_token(&self, claims: &IdTokenClaims) -> OidcResult<String> {
        self.sign_token(claims)
    }

    /// Creates a refresh token.
    ///
    /// # Errors
    ///
    /// Returns an error if token signing fails.
    pub fn create_refresh_token(&self, claims: &RefreshTokenClaims) -> OidcResult<String> {
        self.sign_token(claims)
    }

    /// Signs a token with the active key.
    fn sign_token<T: Serialize>(&self, claims: &T) -> OidcResult<String> {
        let key = self.active_key()?;

        let mut header = Header::new(key.jwt_algorithm());
        header.kid = Some(key.kid.clone());
        header.typ = Some("JWT".to_string());

        encode(&header, claims, &key.encoding_key)
            .map_err(|e| OidcError::TokenSigning(e.to_string()))
    }

    /// Validates and decodes an access token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or expired.
    pub fn validate_access_token(&self, token: &str) -> OidcResult<AccessTokenClaims> {
        self.validate_token(token)
    }

    /// Validates and decodes an ID token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or expired.
    pub fn validate_id_token(&self, token: &str) -> OidcResult<IdTokenClaims> {
        self.validate_token(token)
    }

    /// Validates and decodes a refresh token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or expired.
    pub fn validate_refresh_token(&self, token: &str) -> OidcResult<RefreshTokenClaims> {
        self.validate_token(token)
    }

    /// Validates and decodes a token.
    fn validate_token<T: DeserializeOwned>(&self, token: &str) -> OidcResult<T> {
        // Extract the header to get the key ID
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| OidcError::TokenValidation(e.to_string()))?;

        let kid = header
            .kid
            .ok_or_else(|| OidcError::TokenValidation("missing kid in token header".to_string()))?;

        let key = self
            .signing_keys
            .get(&kid)
            .ok_or_else(|| OidcError::TokenValidation(format!("unknown signing key: {kid}")))?;

        let mut validation = Validation::new(key.jwt_algorithm());
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = true;

        let token_data = decode::<T>(token, &key.decoding_key, &validation)
            .map_err(|e| OidcError::TokenValidation(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// Creates a token response for the token endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn create_token_response(
        &self,
        subject: &str,
        client_id: &str,
        scope: &str,
        session_id: Option<&str>,
        nonce: Option<&str>,
        include_id_token: bool,
        include_refresh_token: bool,
    ) -> OidcResult<TokenResponse> {
        let now = Utc::now();
        let access_expires = now + Duration::seconds(self.config.access_token_lifespan);
        let refresh_expires = now + Duration::seconds(self.config.refresh_token_lifespan);

        // Create access token
        let mut access_claims = AccessTokenClaims::new(
            self.config.issuer.clone(),
            subject.to_string(),
            access_expires,
        )
        .with_azp(client_id)
        .with_scope(scope)
        .with_auth_time(now.timestamp());

        if let Some(sid) = session_id {
            access_claims = access_claims.with_session(sid);
        }

        let access_token = self.create_access_token(&access_claims)?;

        // Create ID token if requested
        let id_token = if include_id_token && scope.contains("openid") {
            let id_expires = now + Duration::seconds(self.config.id_token_lifespan);
            let mut id_claims = IdTokenClaims::new(
                self.config.issuer.clone(),
                subject.to_string(),
                client_id,
                id_expires,
            )
            .with_auth_time(now.timestamp())
            .with_azp(client_id)
            .with_at_hash(self.compute_at_hash(&access_token));

            if let Some(n) = nonce {
                id_claims = id_claims.with_nonce(n);
            }

            if let Some(sid) = session_id {
                id_claims = id_claims.with_session(sid);
            }

            Some(self.create_id_token(&id_claims)?)
        } else {
            None
        };

        // Create refresh token if requested
        let refresh_token = if include_refresh_token {
            let mut refresh_claims = RefreshTokenClaims::new(
                self.config.issuer.clone(),
                subject.to_string(),
                refresh_expires,
            )
            .with_azp(client_id)
            .with_scope(scope);

            if let Some(sid) = session_id {
                refresh_claims = refresh_claims.with_session(sid);
            }

            if let Some(n) = nonce {
                refresh_claims = refresh_claims.with_nonce(n);
            }

            Some(self.create_refresh_token(&refresh_claims)?)
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_lifespan,
            refresh_token,
            refresh_expires_in: if include_refresh_token {
                Some(self.config.refresh_token_lifespan)
            } else {
                None
            },
            id_token,
            scope: Some(scope.to_string()),
            session_state: session_id.map(ToString::to_string),
        })
    }

    /// Computes the `at_hash` value for an access token.
    ///
    /// Uses the first half of the hash of the access token (base64url encoded).
    fn compute_at_hash(&self, access_token: &str) -> String {
        let hash = match self.config.algorithm.hash_algorithm() {
            kc_crypto::HashAlgorithm::Sha384 => sha384(access_token.as_bytes()),
            kc_crypto::HashAlgorithm::Sha512 => sha512(access_token.as_bytes()),
        };

        // Take the left-most half of the hash
        let half_len = hash.len() / 2;
        let half_hash = &hash[..half_len];

        URL_SAFE_NO_PAD.encode(half_hash)
    }

    /// Returns the issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Returns the token configuration.
    #[must_use]
    pub const fn config(&self) -> &TokenConfig {
        &self.config
    }
}

/// Token endpoint response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// Token type (always "Bearer").
    pub token_type: String,

    /// Access token lifetime in seconds.
    pub expires_in: i64,

    /// Refresh token (if issued).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Refresh token lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<i64>,

    /// ID token (if `OpenID` scope requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,

    /// Granted scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Session state for session management.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
}

/// Introspection endpoint response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is active.
    pub active: bool,

    /// Token scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Client ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Not before time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    /// Creates an inactive introspection response.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }

    /// Creates an active introspection response from access token claims.
    #[must_use]
    pub fn from_access_token(claims: &AccessTokenClaims) -> Self {
        Self {
            active: true,
            scope: claims.scope.clone(),
            client_id: claims.azp.clone(),
            username: claims.preferred_username.clone(),
            token_type: Some("Bearer".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: claims.nbf,
            sub: Some(claims.sub.clone()),
            aud: claims.aud.clone(),
            iss: Some(claims.iss.clone()),
            jti: claims.jti.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_config_defaults() {
        let config = TokenConfig::default();
        assert_eq!(config.access_token_lifespan, 300);
        assert_eq!(config.refresh_token_lifespan, 1800);
    }

    #[test]
    fn introspection_inactive() {
        let response = IntrospectionResponse::inactive();
        assert!(!response.active);
        assert!(response.scope.is_none());
    }
}
