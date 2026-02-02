//! Storage-backed OIDC provider implementation.
//!
//! This module provides a concrete implementation of the OIDC [`RealmProvider`]
//! trait that connects to the storage layer for persistent data.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use kc_protocol_oidc::provider::StorageRealmProvider;
//! use kc_storage_sql::{create_pool, PoolConfig, PgRealmProvider, PgClientProvider};
//!
//! let pool = create_pool(&config).await?;
//! let realm_storage = PgRealmProvider::new(pool.clone());
//! let client_storage = PgClientProvider::new(pool.clone());
//!
//! let provider = StorageRealmProvider::new(
//!     realm_storage,
//!     client_storage,
//!     "https://auth.example.com".to_string(),
//! );
//! ```

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use kc_model::{Client, Realm};
use kc_storage::{ClientProvider, RealmProvider as StorageRealmProvider};

use crate::discovery::{ProviderMetadata, ProviderMetadataBuilder};
use crate::endpoints::RealmProvider as OidcRealmProvider;
use crate::error::{OidcError, OidcResult};
use crate::jwks::{EcCurve, JsonWebKey, JsonWebKeySet, KeyType};
use crate::token::{SigningKey, TokenConfig, TokenManager};

/// Configuration for the storage-backed provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Base URL for the identity provider (e.g., `https://auth.example.com`).
    pub base_url: String,

    /// Default access token lifespan in seconds.
    pub access_token_lifespan: i64,

    /// Default ID token lifespan in seconds.
    pub id_token_lifespan: i64,

    /// Default refresh token lifespan in seconds.
    pub refresh_token_lifespan: i64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".to_string(),
            access_token_lifespan: 300,      // 5 minutes
            id_token_lifespan: 300,          // 5 minutes
            refresh_token_lifespan: 1_800,   // 30 minutes
        }
    }
}

impl ProviderConfig {
    /// Creates a new provider configuration.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Default::default()
        }
    }

    /// Gets the issuer URL for a realm.
    #[must_use]
    pub fn issuer(&self, realm: &str) -> String {
        format!("{}/realms/{}", self.base_url, realm)
    }
}

/// Storage-backed OIDC realm provider.
///
/// This provider implements the OIDC [`RealmProvider`](OidcRealmProvider) trait
/// using the storage layer for persistent data access.
pub struct OidcStorageProvider<R, C>
where
    R: StorageRealmProvider + Send + Sync,
    C: ClientProvider + Send + Sync,
{
    /// Realm storage provider.
    realm_storage: Arc<R>,

    /// Client storage provider.
    client_storage: Arc<C>,

    /// Provider configuration.
    config: ProviderConfig,

    /// Cached token managers by realm name.
    /// TODO: Add proper caching with TTL
    token_managers: tokio::sync::RwLock<HashMap<String, Arc<TokenManager>>>,

    /// Signing keys by realm (for JWKS).
    /// TODO: Load from storage/HSM
    signing_keys: tokio::sync::RwLock<HashMap<String, Vec<SigningKeyInfo>>>,
}

/// Information about a signing key.
#[derive(Clone)]
struct SigningKeyInfo {
    /// Key ID.
    kid: String,
    /// Algorithm.
    algorithm: kc_crypto::SignatureAlgorithm,
    /// Private key PEM.
    private_key_pem: Vec<u8>,
    /// Public key PEM.
    public_key_pem: Vec<u8>,
    /// EC curve (for EC keys).
    curve: Option<EcCurve>,
    /// RSA modulus (for RSA keys, base64url).
    n: Option<String>,
    /// RSA exponent (for RSA keys, base64url).
    e: Option<String>,
    /// EC x coordinate (for EC keys, base64url).
    x: Option<String>,
    /// EC y coordinate (for EC keys, base64url).
    y: Option<String>,
}

impl<R, C> OidcStorageProvider<R, C>
where
    R: StorageRealmProvider + Send + Sync,
    C: ClientProvider + Send + Sync,
{
    /// Creates a new storage-backed provider.
    pub fn new(realm_storage: R, client_storage: C, config: ProviderConfig) -> Self {
        Self {
            realm_storage: Arc::new(realm_storage),
            client_storage: Arc::new(client_storage),
            config,
            token_managers: tokio::sync::RwLock::new(HashMap::new()),
            signing_keys: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Creates a provider from Arc references (for sharing).
    pub fn from_arc(realm_storage: Arc<R>, client_storage: Arc<C>, config: ProviderConfig) -> Self {
        Self {
            realm_storage,
            client_storage,
            config,
            token_managers: tokio::sync::RwLock::new(HashMap::new()),
            signing_keys: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Gets the realm storage provider.
    pub fn realm_storage(&self) -> &R {
        &self.realm_storage
    }

    /// Gets the client storage provider.
    pub fn client_storage(&self) -> &C {
        &self.client_storage
    }

    /// Gets a realm by name.
    pub async fn get_realm(&self, realm_name: &str) -> OidcResult<Option<Realm>> {
        self.realm_storage
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::Internal(format!("failed to get realm: {e}")))
    }

    /// Gets a client by `client_id` in a realm.
    pub async fn get_client(&self, realm_name: &str, client_id: &str) -> OidcResult<Option<Client>> {
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;

        self.client_storage
            .get_by_client_id(realm.id, client_id)
            .await
            .map_err(|e| OidcError::Internal(format!("failed to get client: {e}")))
    }

    /// Validates client credentials.
    pub async fn validate_client_secret(
        &self,
        realm_name: &str,
        client_id: &str,
        secret: &str,
    ) -> OidcResult<bool> {
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;

        self.client_storage
            .validate_secret(realm.id, client_id, secret)
            .await
            .map_err(|e| OidcError::Internal(format!("failed to validate client secret: {e}")))
    }

    /// Registers signing keys for a realm.
    ///
    /// This should be called during initialization to set up the realm's signing keys.
    pub async fn register_signing_key(
        &self,
        realm_name: &str,
        kid: impl Into<String>,
        algorithm: kc_crypto::SignatureAlgorithm,
        private_key_pem: Vec<u8>,
        public_key_pem: Vec<u8>,
    ) -> OidcResult<()> {
        let kid = kid.into();

        // Parse key components based on algorithm
        let (curve, n, e, x, y) = parse_key_components(&public_key_pem, algorithm);

        let key_info = SigningKeyInfo {
            kid,
            algorithm,
            private_key_pem,
            public_key_pem,
            curve,
            n,
            e,
            x,
            y,
        };

        // Add the key
        self.signing_keys
            .write()
            .await
            .entry(realm_name.to_string())
            .or_default()
            .push(key_info);

        // Invalidate cached token manager for this realm
        self.token_managers.write().await.remove(realm_name);

        Ok(())
    }

    /// Gets or creates a token manager for a realm.
    async fn get_or_create_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>> {
        // Check cache first
        if let Some(manager) = self.token_managers.read().await.get(realm_name) {
            return Ok(Arc::clone(manager));
        }

        // Create new token manager
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;

        let issuer = self.config.issuer(realm_name);

        let token_config = TokenConfig {
            issuer,
            access_token_lifespan: i64::from(realm.access_token_lifespan),
            id_token_lifespan: i64::from(realm.access_token_lifespan), // Same as access token by default
            // Use SSO session idle timeout as refresh token lifespan
            refresh_token_lifespan: i64::from(realm.sso_session_idle_timeout),
            algorithm: kc_crypto::SignatureAlgorithm::Es384, // Default, should come from realm config
        };

        let mut token_manager = TokenManager::new(token_config);

        // Add signing keys - clone the keys we need while holding the read lock
        let realm_keys: Vec<SigningKeyInfo> = self
            .signing_keys
            .read()
            .await
            .get(realm_name)
            .cloned()
            .unwrap_or_default();

        for key_info in &realm_keys {
            let signing_key = SigningKey::from_pem(
                &key_info.kid,
                key_info.algorithm,
                &key_info.private_key_pem,
                &key_info.public_key_pem,
            )?;
            token_manager.add_signing_key(signing_key);
        }

        let manager = Arc::new(token_manager);

        // Cache it
        self.token_managers
            .write()
            .await
            .insert(realm_name.to_string(), Arc::clone(&manager));

        Ok(manager)
    }

    /// Builds JWKS from signing keys.
    async fn build_jwks(&self, realm_name: &str) -> OidcResult<JsonWebKeySet> {
        let jwk_keys = self
            .signing_keys
            .read()
            .await
            .get(realm_name)
            .map_or_else(Vec::new, |realm_keys| {
                realm_keys.iter().map(build_jwk_from_key_info).collect()
            });

        Ok(JsonWebKeySet { keys: jwk_keys })
    }
}

#[async_trait]
impl<R, C> OidcRealmProvider for OidcStorageProvider<R, C>
where
    R: StorageRealmProvider + Send + Sync + 'static,
    C: ClientProvider + Send + Sync + 'static,
{
    async fn realm_exists(&self, realm_name: &str) -> OidcResult<bool> {
        self.realm_storage
            .exists_by_name(realm_name)
            .await
            .map_err(|e| OidcError::Internal(format!("failed to check realm existence: {e}")))
    }

    async fn get_realm_id(&self, realm_name: &str) -> OidcResult<Uuid> {
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;
        Ok(realm.id)
    }

    fn get_issuer(&self, realm_name: &str) -> String {
        self.config.issuer(realm_name)
    }

    async fn get_provider_metadata(&self, realm_name: &str) -> OidcResult<ProviderMetadata> {
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;

        if !realm.enabled {
            return Err(OidcError::InvalidRequest(format!(
                "realm '{realm_name}' is disabled"
            )));
        }

        // ProviderMetadataBuilder takes base_url and realm_name, then builds all URLs
        let metadata = ProviderMetadataBuilder::new(&self.config.base_url, realm_name).build();

        Ok(metadata)
    }

    async fn get_jwks(&self, realm_name: &str) -> OidcResult<JsonWebKeySet> {
        // Verify realm exists and is enabled
        let realm = self
            .get_realm(realm_name)
            .await?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{realm_name}' not found")))?;

        if !realm.enabled {
            return Err(OidcError::InvalidRequest(format!(
                "realm '{realm_name}' is disabled"
            )));
        }

        self.build_jwks(realm_name).await
    }

    async fn get_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>> {
        self.get_or_create_token_manager(realm_name).await
    }
}

/// Key components extracted from a public key.
type KeyComponents = (
    Option<EcCurve>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Parses public key components for JWKS.
///
/// Returns (curve, n, e, x, y) where:
/// - curve: EC curve name (for EC keys)
/// - n, e: RSA modulus and exponent (for RSA keys)
/// - x, y: EC coordinates (for EC keys)
const fn parse_key_components(
    _public_key_pem: &[u8],
    algorithm: kc_crypto::SignatureAlgorithm,
) -> KeyComponents {
    // TODO: Actually parse the PEM to extract key components
    // For now, return placeholder values based on algorithm type
    match algorithm {
        kc_crypto::SignatureAlgorithm::Es384 => (Some(EcCurve::P384), None, None, None, None),
        kc_crypto::SignatureAlgorithm::Es512 => (Some(EcCurve::P521), None, None, None, None),
        kc_crypto::SignatureAlgorithm::Rs384
        | kc_crypto::SignatureAlgorithm::Rs512
        | kc_crypto::SignatureAlgorithm::Ps384
        | kc_crypto::SignatureAlgorithm::Ps512 => (None, None, None, None, None),
    }
}

/// Builds a JWK from key info.
fn build_jwk_from_key_info(key_info: &SigningKeyInfo) -> JsonWebKey {
    let (kty, alg) = match key_info.algorithm {
        kc_crypto::SignatureAlgorithm::Es384 => (KeyType::Ec, "ES384"),
        kc_crypto::SignatureAlgorithm::Es512 => (KeyType::Ec, "ES512"),
        kc_crypto::SignatureAlgorithm::Rs384 => (KeyType::Rsa, "RS384"),
        kc_crypto::SignatureAlgorithm::Rs512 => (KeyType::Rsa, "RS512"),
        kc_crypto::SignatureAlgorithm::Ps384 => (KeyType::Rsa, "PS384"),
        kc_crypto::SignatureAlgorithm::Ps512 => (KeyType::Rsa, "PS512"),
    };

    JsonWebKey {
        kty,
        key_use: Some("sig".to_string()),
        key_ops: None,
        alg: Some(alg.to_string()),
        kid: Some(key_info.kid.clone()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
        n: key_info.n.clone(),
        e: key_info.e.clone(),
        crv: key_info.curve,
        x: key_info.x.clone(),
        y: key_info.y.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_config_issuer() {
        let config = ProviderConfig::new("https://auth.example.com");
        assert_eq!(
            config.issuer("master"),
            "https://auth.example.com/realms/master"
        );
    }

    #[test]
    fn provider_config_default() {
        let config = ProviderConfig::default();
        assert_eq!(config.access_token_lifespan, 300);
        assert_eq!(config.refresh_token_lifespan, 1_800);
    }
}
