//! Storage provider implementations for the server.
//!
//! This module provides concrete implementations of the various provider traits
//! used throughout the system, backed by PostgreSQL storage.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use kc_auth::password::PasswordHasherService;
use kc_protocol_oidc::discovery::{ProviderMetadata, ProviderMetadataBuilder};
use kc_protocol_oidc::endpoints::grants::{
    AuthCodeStore, AuthenticatedClient, AuthenticatedUser, ClientAuthenticator, StoredAuthCode,
    UserAuthenticator,
};
use kc_protocol_oidc::endpoints::RealmProvider;
use kc_protocol_oidc::error::{OidcError, OidcResult};
use kc_protocol_oidc::jwks::JsonWebKeySet;
use kc_protocol_oidc::token::{SigningKey, TokenConfig, TokenManager};
use kc_session::auth_session::AuthenticationSession;
use kc_session::client_session::ClientSession;
use kc_session::error::SessionResult;
use kc_session::user_session::UserSession;
use kc_session::SessionProvider;
use kc_protocol_saml::endpoints::{
    AcsEndpoint, SamlRealmError, SamlRealmProvider, SamlUser, ServiceProviderConfig, SessionInfo,
    SigningConfig, SlsEndpoint,
};
use kc_protocol_saml::signature::SignatureConfig as SamlSignatureConfig;
use kc_storage::{ClientProvider, CredentialProvider, RealmProvider as StorageRealmProvider, UserProvider};
use kc_storage_sql::providers::{
    PgClientProvider, PgCredentialProvider, PgRealmProvider, PgUserProvider,
};
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

// Test EC P-384 keys for development (DO NOT USE IN PRODUCTION)
// These should be loaded from secure storage in production
const DEV_PRIVATE_KEY_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCJcUzYqb6R3F1QvX2oMmC+1WQijzNjz3kqhMF7ZhQPZBz8PHXiVQzS
NqvJT4Y+2XigBwYFK4EEACKhZANiAAQGzwS5QCkqK3QgjCM0x/SmXR5G3E1HVMen
Dh88cSVYCl0Y8OMUNYJyUWCJlKwZrZGMH2+Y0x0QJKlTBBZqsPLnqhKQYZvCZXXp
vKPd8VZKGrQPZRLKDlqCQB3Qz6PGXL0=
-----END EC PRIVATE KEY-----"#;

const DEV_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBs8EuUApKit0IIwjNMf0pl0eRtxNR1TH
pw4fPHElWApdGPDjFDWCclFgiZSsGa2RjB9vmNMdECSpUwQWarDy56oSkGGbwmV1
6byj3fFWShq0D2USyg5agkAd0M+jxly9
-----END PUBLIC KEY-----"#;

// Development self-signed certificate for SAML (DO NOT USE IN PRODUCTION)
// This is a minimal DER-encoded X.509 v3 certificate for testing purposes
// CN=keycloak-dev, O=Keycloak Development
// Generated using a 2048-bit RSA key for compatibility (SAML often uses 2048-bit)
const DEV_SAML_CERTIFICATE_DER: &[u8] = include_bytes!("dev_saml_cert.der");
const DEV_SAML_PRIVATE_KEY_DER: &[u8] = include_bytes!("dev_saml_key.der");

/// Aggregate storage providers backed by PostgreSQL.
#[derive(Clone)]
pub struct StorageProviders {
    /// Realm provider.
    pub realm: Arc<PgRealmProvider>,

    /// User provider.
    pub user: Arc<PgUserProvider>,

    /// Client provider.
    pub client: Arc<PgClientProvider>,

    /// Credential provider.
    pub credential: Arc<PgCredentialProvider>,

    /// In-memory session provider.
    pub session: Arc<InMemorySessionProvider>,

    /// In-memory auth code store.
    pub auth_codes: Arc<InMemoryAuthCodeStore>,

    /// Password hasher service.
    password_hasher: Arc<PasswordHasherService>,

    /// Base URL for the server.
    base_url: Arc<RwLock<String>>,

    /// Token managers per realm (cached).
    token_managers: Arc<RwLock<HashMap<String, Arc<TokenManager>>>>,
}

impl StorageProviders {
    /// Creates new storage providers with the given database pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            realm: Arc::new(PgRealmProvider::new(pool.clone())),
            user: Arc::new(PgUserProvider::new(pool.clone())),
            client: Arc::new(PgClientProvider::new(pool.clone())),
            credential: Arc::new(PgCredentialProvider::new(pool)),
            session: Arc::new(InMemorySessionProvider::new()),
            auth_codes: Arc::new(InMemoryAuthCodeStore::new()),
            password_hasher: Arc::new(PasswordHasherService::with_defaults()),
            base_url: Arc::new(RwLock::new("http://localhost:8080".to_string())),
            token_managers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Sets the base URL.
    pub async fn set_base_url(&self, url: &str) {
        *self.base_url.write().await = url.to_string();
    }

    /// Gets the base URL.
    pub async fn base_url(&self) -> String {
        self.base_url.read().await.clone()
    }

    /// Gets or creates a token manager for a realm.
    async fn get_or_create_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>> {
        // Check cache first
        {
            let managers = self.token_managers.read().await;
            if let Some(manager) = managers.get(realm_name) {
                return Ok(manager.clone());
            }
        }

        // Create new token manager
        let base_url = self.base_url.read().await.clone();
        let issuer = format!("{}/realms/{}", base_url, realm_name);

        let token_config = TokenConfig {
            issuer,
            access_token_lifespan: 300,      // 5 minutes
            id_token_lifespan: 300,          // 5 minutes
            refresh_token_lifespan: 1800,    // 30 minutes
            algorithm: kc_crypto::SignatureAlgorithm::Es384,
        };

        let mut token_manager = TokenManager::new(token_config);

        // Add the development signing key
        // In production, keys should be loaded from secure storage
        let signing_key = SigningKey::from_pem(
            format!("dev-key-{}", realm_name),
            kc_crypto::SignatureAlgorithm::Es384,
            DEV_PRIVATE_KEY_PEM.as_bytes(),
            DEV_PUBLIC_KEY_PEM.as_bytes(),
        )
        .map_err(|e| OidcError::ServerError(format!("failed to load signing key: {e}")))?;

        token_manager.add_signing_key(signing_key);

        let manager = Arc::new(token_manager);

        // Cache it
        {
            let mut managers = self.token_managers.write().await;
            managers.insert(realm_name.to_string(), manager.clone());
        }

        Ok(manager)
    }
}

#[async_trait]
impl RealmProvider for StorageProviders {
    async fn realm_exists(&self, realm_name: &str) -> OidcResult<bool> {
        self.realm
            .get_by_name(realm_name)
            .await
            .map(|r| r.is_some())
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))
    }

    async fn get_realm_id(&self, realm_name: &str) -> OidcResult<Uuid> {
        self.realm
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .map(|r| r.id)
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{}' not found", realm_name)))
    }

    fn get_issuer(&self, realm_name: &str) -> String {
        // Note: This is sync, so we can't access the async lock.
        // For now, use a default. The actual base_url should be set at startup.
        format!("http://localhost:8080/realms/{}", realm_name)
    }

    async fn get_provider_metadata(&self, realm_name: &str) -> OidcResult<ProviderMetadata> {
        let base_url = self.base_url.read().await.clone();

        // The builder takes base_url and realm, then builds all standard OIDC URLs
        Ok(ProviderMetadataBuilder::new(&base_url, realm_name).build())
    }

    async fn get_jwks(&self, _realm_name: &str) -> OidcResult<JsonWebKeySet> {
        // For now, return an empty JWKS
        // In production, this should return the realm's public keys
        // The TokenManager would need a method to export public keys as JWKs
        Ok(JsonWebKeySet { keys: vec![] })
    }

    async fn get_token_manager(&self, realm_name: &str) -> OidcResult<Arc<TokenManager>> {
        self.get_or_create_token_manager(realm_name).await
    }
}

#[async_trait]
impl ClientAuthenticator for StorageProviders {
    async fn authenticate(
        &self,
        realm_name: &str,
        client_id: &str,
        client_secret: Option<&str>,
        _client_assertion: Option<&str>,
        _client_assertion_type: Option<&str>,
    ) -> OidcResult<AuthenticatedClient> {
        // Get realm ID
        let realm = self
            .realm
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{}' not found", realm_name)))?;

        // Get client by client_id
        let client = self
            .client
            .get_by_client_id(realm.id, client_id)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .ok_or_else(|| OidcError::InvalidClient("client not found".to_string()))?;

        // Check if client is enabled
        if !client.enabled {
            return Err(OidcError::InvalidClient("client is disabled".to_string()));
        }

        // Check if public client
        let is_public = client.public_client;

        // Validate credentials for confidential clients
        if !is_public {
            let secret = client_secret.ok_or_else(|| {
                OidcError::InvalidClient("client_secret required for confidential client".to_string())
            })?;

            // Get client secret from storage
            let stored_secret = client.secret.as_deref().ok_or_else(|| {
                OidcError::ServerError("client has no secret configured".to_string())
            })?;

            // Compare secrets (timing-safe comparison would be better)
            if secret != stored_secret {
                return Err(OidcError::InvalidClient("invalid client credentials".to_string()));
            }
        }

        Ok(AuthenticatedClient {
            id: client.id,
            client_id: client.client_id,
            is_public,
            service_account_enabled: client.service_accounts_enabled,
            // For now, no service account user ID - would need to be looked up
            service_account_user_id: None,
            direct_access_grants_enabled: client.direct_access_grants_enabled,
            realm_id: realm.id,
        })
    }
}

#[async_trait]
impl UserAuthenticator for StorageProviders {
    async fn authenticate(
        &self,
        realm_name: &str,
        username: &str,
        password: &str,
    ) -> OidcResult<AuthenticatedUser> {
        // Get realm ID
        let realm = self
            .realm
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .ok_or_else(|| OidcError::InvalidRequest(format!("realm '{}' not found", realm_name)))?;

        // Get user by username
        let user = self
            .user
            .get_by_username(realm.id, username)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .ok_or_else(|| OidcError::InvalidGrant("invalid username or password".to_string()))?;

        // Check if user is enabled
        if !user.enabled {
            return Err(OidcError::InvalidGrant("user is disabled".to_string()));
        }

        // Get user's password credential using the correct API
        let password_cred = self
            .credential
            .get_password(realm.id, user.id)
            .await
            .map_err(|e| OidcError::ServerError(format!("storage error: {e}")))?
            .ok_or_else(|| OidcError::InvalidGrant("invalid username or password".to_string()))?;

        // Validate password - secret_data contains the hash
        let stored_hash = &password_cred.secret_data;

        // Use the password hasher service to verify
        self.password_hasher
            .verify(password, stored_hash)
            .map_err(|_| OidcError::InvalidGrant("invalid username or password".to_string()))?;

        Ok(AuthenticatedUser {
            id: user.id,
            username: user.username,
            email: user.email,
            enabled: user.enabled,
        })
    }
}

// ============================================================================
// In-Memory Session Provider
// ============================================================================

/// In-memory session provider for development and testing.
///
/// For production with multiple instances, use a distributed store (Redis).
pub struct InMemorySessionProvider {
    user_sessions: RwLock<HashMap<(Uuid, Uuid), UserSession>>,
    client_sessions: RwLock<HashMap<(Uuid, Uuid), ClientSession>>,
    auth_sessions: RwLock<HashMap<(Uuid, Uuid), AuthenticationSession>>,
    offline_sessions: RwLock<HashMap<(Uuid, Uuid), UserSession>>,
}

impl InMemorySessionProvider {
    /// Creates a new in-memory session provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_sessions: RwLock::new(HashMap::new()),
            client_sessions: RwLock::new(HashMap::new()),
            auth_sessions: RwLock::new(HashMap::new()),
            offline_sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionProvider for InMemorySessionProvider {
    async fn create_user_session(&self, session: &UserSession) -> SessionResult<()> {
        self.user_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn get_user_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<UserSession>> {
        Ok(self
            .user_sessions
            .read()
            .await
            .get(&(realm_id, session_id))
            .cloned())
    }

    async fn update_user_session(&self, session: &UserSession) -> SessionResult<()> {
        self.user_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn remove_user_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()> {
        self.user_sessions
            .write()
            .await
            .remove(&(realm_id, session_id));
        Ok(())
    }

    async fn get_user_sessions_by_user(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
    ) -> SessionResult<Vec<UserSession>> {
        Ok(self
            .user_sessions
            .read()
            .await
            .values()
            .filter(|s| s.realm_id == realm_id && s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn get_user_sessions_by_client(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
        max_results: Option<usize>,
        offset: Option<usize>,
    ) -> SessionResult<Vec<UserSession>> {
        // Get client sessions for this client
        let client_sessions: Vec<_> = self
            .client_sessions
            .read()
            .await
            .values()
            .filter(|cs| cs.realm_id == realm_id && cs.client_id == client_id)
            .cloned()
            .collect();

        // Get corresponding user sessions
        let user_sessions = self.user_sessions.read().await;
        let mut sessions: Vec<_> = client_sessions
            .iter()
            .filter_map(|cs| user_sessions.get(&(realm_id, cs.user_session_id)).cloned())
            .collect();

        // Apply pagination
        let offset = offset.unwrap_or(0);
        let max = max_results.unwrap_or(usize::MAX);
        sessions = sessions.into_iter().skip(offset).take(max).collect();

        Ok(sessions)
    }

    async fn count_user_sessions(&self, realm_id: Uuid, user_id: Uuid) -> SessionResult<u64> {
        let count = self
            .user_sessions
            .read()
            .await
            .values()
            .filter(|s| s.realm_id == realm_id && s.user_id == user_id)
            .count();
        Ok(count as u64)
    }

    async fn remove_user_sessions(&self, realm_id: Uuid, user_id: Uuid) -> SessionResult<()> {
        self.user_sessions
            .write()
            .await
            .retain(|_, s| !(s.realm_id == realm_id && s.user_id == user_id));
        Ok(())
    }

    async fn remove_all_sessions(&self, realm_id: Uuid) -> SessionResult<()> {
        self.user_sessions
            .write()
            .await
            .retain(|_, s| s.realm_id != realm_id);
        self.client_sessions
            .write()
            .await
            .retain(|_, s| s.realm_id != realm_id);
        Ok(())
    }

    async fn create_client_session(&self, session: &ClientSession) -> SessionResult<()> {
        self.client_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn get_client_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<ClientSession>> {
        Ok(self
            .client_sessions
            .read()
            .await
            .get(&(realm_id, session_id))
            .cloned())
    }

    async fn get_client_sessions(
        &self,
        realm_id: Uuid,
        user_session_id: Uuid,
    ) -> SessionResult<Vec<ClientSession>> {
        Ok(self
            .client_sessions
            .read()
            .await
            .values()
            .filter(|s| s.realm_id == realm_id && s.user_session_id == user_session_id)
            .cloned()
            .collect())
    }

    async fn update_client_session(&self, session: &ClientSession) -> SessionResult<()> {
        self.client_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn remove_client_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()> {
        self.client_sessions
            .write()
            .await
            .remove(&(realm_id, session_id));
        Ok(())
    }

    async fn create_auth_session(&self, session: &AuthenticationSession) -> SessionResult<()> {
        self.auth_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn get_auth_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<AuthenticationSession>> {
        Ok(self
            .auth_sessions
            .read()
            .await
            .get(&(realm_id, session_id))
            .cloned())
    }

    async fn update_auth_session(&self, session: &AuthenticationSession) -> SessionResult<()> {
        self.auth_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn remove_auth_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()> {
        self.auth_sessions
            .write()
            .await
            .remove(&(realm_id, session_id));
        Ok(())
    }

    async fn create_offline_session(&self, session: &UserSession) -> SessionResult<()> {
        self.offline_sessions
            .write()
            .await
            .insert((session.realm_id, session.id), session.clone());
        Ok(())
    }

    async fn get_offline_session(
        &self,
        realm_id: Uuid,
        session_id: Uuid,
    ) -> SessionResult<Option<UserSession>> {
        Ok(self
            .offline_sessions
            .read()
            .await
            .get(&(realm_id, session_id))
            .cloned())
    }

    async fn get_offline_sessions_by_user(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
    ) -> SessionResult<Vec<UserSession>> {
        Ok(self
            .offline_sessions
            .read()
            .await
            .values()
            .filter(|s| s.realm_id == realm_id && s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn remove_offline_session(&self, realm_id: Uuid, session_id: Uuid) -> SessionResult<()> {
        self.offline_sessions
            .write()
            .await
            .remove(&(realm_id, session_id));
        Ok(())
    }

    async fn remove_expired_sessions(&self, _realm_id: Uuid) -> SessionResult<u64> {
        // For a real implementation, would check session timestamps
        Ok(0)
    }
}

// ============================================================================
// In-Memory Auth Code Store
// ============================================================================

/// In-memory authorization code store.
pub struct InMemoryAuthCodeStore {
    codes: RwLock<HashMap<String, StoredAuthCode>>,
}

impl InMemoryAuthCodeStore {
    /// Creates a new in-memory auth code store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            codes: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAuthCodeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthCodeStore for InMemoryAuthCodeStore {
    async fn store_code(&self, code: &StoredAuthCode) -> OidcResult<()> {
        self.codes
            .write()
            .await
            .insert(code.code_hash.clone(), code.clone());
        Ok(())
    }

    async fn get_code(&self, code_hash: &str) -> OidcResult<Option<StoredAuthCode>> {
        Ok(self.codes.read().await.get(code_hash).cloned())
    }

    async fn mark_code_used(&self, code_hash: &str) -> OidcResult<()> {
        if let Some(code) = self.codes.write().await.get_mut(code_hash) {
            code.used = true;
        }
        Ok(())
    }

    async fn remove_code(&self, code_hash: &str) -> OidcResult<()> {
        self.codes.write().await.remove(code_hash);
        Ok(())
    }

    async fn remove_expired_codes(&self) -> OidcResult<u64> {
        let mut codes = self.codes.write().await;
        let now = Utc::now();
        let initial_len = codes.len();
        codes.retain(|_, code| code.expires_at > now);
        Ok((initial_len - codes.len()) as u64)
    }
}

// ============================================================================
// SAML Realm Provider Implementation
// ============================================================================

#[async_trait]
impl SamlRealmProvider for StorageProviders {
    async fn realm_exists(&self, realm: &str) -> Result<bool, SamlRealmError> {
        self.realm
            .get_by_name(realm)
            .await
            .map(|r| r.is_some())
            .map_err(|e| SamlRealmError::Storage(e.to_string()))
    }

    async fn get_idp_entity_id(&self, realm: &str) -> Result<String, SamlRealmError> {
        let base_url = self.base_url.read().await.clone();
        Ok(format!("{}/realms/{}", base_url, realm))
    }

    async fn get_sso_url(&self, realm: &str) -> Result<String, SamlRealmError> {
        let base_url = self.base_url.read().await.clone();
        Ok(format!("{}/realms/{}/protocol/saml", base_url, realm))
    }

    async fn get_sls_url(&self, realm: &str) -> Result<String, SamlRealmError> {
        let base_url = self.base_url.read().await.clone();
        Ok(format!("{}/realms/{}/protocol/saml/logout", base_url, realm))
    }

    async fn get_signing_config(&self, _realm: &str) -> Result<SigningConfig, SamlRealmError> {
        // For development, use the embedded RSA key and certificate
        // In production, this should load realm-specific signing keys
        Ok(SigningConfig {
            private_key_der: DEV_SAML_PRIVATE_KEY_DER.to_vec(),
            certificate_der: DEV_SAML_CERTIFICATE_DER.to_vec(),
            config: SamlSignatureConfig::default(),
        })
    }

    async fn get_service_provider(
        &self,
        realm: &str,
        entity_id: &str,
    ) -> Result<Option<ServiceProviderConfig>, SamlRealmError> {
        // Look up the realm first
        let realm_model = self
            .realm
            .get_by_name(realm)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?
            .ok_or_else(|| SamlRealmError::RealmNotFound(realm.to_string()))?;

        // In a real implementation, we would look up SAML clients by entity_id
        // For now, try to find a client with matching client_id
        let client = self
            .client
            .get_by_client_id(realm_model.id, entity_id)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        match client {
            Some(c) => {
                // Build service provider config from client
                // Note: Real implementation would have SAML-specific fields
                let base_redirect = c.base_url.as_deref().unwrap_or("");

                Ok(Some(ServiceProviderConfig {
                    entity_id: c.client_id.clone(),
                    name: c.name.clone(),
                    acs_urls: vec![AcsEndpoint {
                        url: if base_redirect.is_empty() {
                            format!("{}/saml/acs", entity_id)
                        } else {
                            format!("{}/saml/acs", base_redirect)
                        },
                        binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
                        index: 0,
                        is_default: true,
                    }],
                    sls_urls: vec![SlsEndpoint {
                        url: if base_redirect.is_empty() {
                            format!("{}/saml/sls", entity_id)
                        } else {
                            format!("{}/saml/sls", base_redirect)
                        },
                        binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
                    }],
                    sign_assertions: true,
                    sign_responses: true,
                    encrypt_assertions: false,
                    encryption_certificate: None,
                    name_id_format: Some(
                        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".to_string(),
                    ),
                    enabled: c.enabled,
                    // Signature validation settings
                    // By default, don't require signed AuthnRequests for flexibility
                    require_authn_request_signed: false,
                    signing_certificate: None, // Would be populated from client settings
                    allow_sha1: false, // Don't allow deprecated SHA-1 by default
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_user(&self, realm: &str, user_id: &str) -> Result<Option<SamlUser>, SamlRealmError> {
        // Parse user_id as UUID
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|_| SamlRealmError::UserNotFound(user_id.to_string()))?;

        // Get realm
        let realm_model = self
            .realm
            .get_by_name(realm)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?
            .ok_or_else(|| SamlRealmError::RealmNotFound(realm.to_string()))?;

        // Get user
        let user = self
            .user
            .get_by_id(realm_model.id, user_uuid)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        Ok(user.map(|u| SamlUser {
            id: u.id.to_string(),
            username: u.username,
            email: u.email,
            first_name: u.first_name,
            last_name: u.last_name,
            enabled: u.enabled,
        }))
    }

    async fn get_user_attributes(
        &self,
        realm: &str,
        user_id: &str,
        _sp_entity_id: &str,
    ) -> Result<Vec<(String, Vec<String>)>, SamlRealmError> {
        // Get user first
        let user = self
            .get_user(realm, user_id)
            .await?
            .ok_or_else(|| SamlRealmError::UserNotFound(user_id.to_string()))?;

        // Build basic attributes from user properties
        let mut attributes = Vec::new();

        if let Some(email) = &user.email {
            attributes.push(("email".to_string(), vec![email.clone()]));
        }
        if let Some(first_name) = &user.first_name {
            attributes.push(("firstName".to_string(), vec![first_name.clone()]));
        }
        if let Some(last_name) = &user.last_name {
            attributes.push(("lastName".to_string(), vec![last_name.clone()]));
        }

        // In a real implementation, would also include:
        // - Custom user attributes
        // - Group memberships
        // - Role assignments
        // - Protocol mapper results

        Ok(attributes)
    }

    async fn terminate_session(
        &self,
        realm: &str,
        name_id: &str,
        session_index: Option<&str>,
    ) -> Result<u64, SamlRealmError> {
        // Get the realm to find its ID
        let realm_model = self
            .realm
            .get_by_name(realm)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?
            .ok_or_else(|| SamlRealmError::RealmNotFound(realm.to_string()))?;

        // Try to find user by username first (common NameID format)
        let user = self
            .user
            .get_by_username(realm_model.id, name_id)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        let user_id = match user {
            Some(u) => u.id,
            None => {
                // NameID might be a persistent ID (UUID) or other format
                // Try parsing as UUID
                match Uuid::parse_str(name_id) {
                    Ok(id) => id,
                    Err(_) => {
                        tracing::debug!(
                            "Could not find user for NameID '{}' in realm '{}'",
                            name_id,
                            realm
                        );
                        return Ok(0);
                    }
                }
            }
        };

        // Get sessions for this user
        let sessions = self
            .session
            .get_user_sessions_by_user(realm_model.id, user_id)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        if sessions.is_empty() {
            tracing::debug!(
                "No sessions found for user '{}' in realm '{}'",
                user_id,
                realm
            );
            return Ok(0);
        }

        let mut terminated = 0u64;

        for session in &sessions {
            // If session_index is specified, only terminate matching sessions
            if let Some(idx) = session_index {
                // The session ID is used as the session index
                if session.id.to_string() != idx {
                    continue;
                }
            }

            // Terminate the session
            if self
                .session
                .remove_user_session(realm_model.id, session.id)
                .await
                .is_ok()
            {
                terminated += 1;
                tracing::info!(
                    "Terminated session '{}' for NameID '{}' in realm '{}'",
                    session.id,
                    name_id,
                    realm
                );
            }
        }

        Ok(terminated)
    }

    async fn find_sessions_by_name_id(
        &self,
        realm: &str,
        name_id: &str,
    ) -> Result<Vec<SessionInfo>, SamlRealmError> {
        // Get the realm to find its ID
        let realm_model = self
            .realm
            .get_by_name(realm)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?
            .ok_or_else(|| SamlRealmError::RealmNotFound(realm.to_string()))?;

        // Try to find user by username first
        let user = self
            .user
            .get_by_username(realm_model.id, name_id)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        let user_id = match user {
            Some(u) => u.id,
            None => {
                // Try parsing NameID as UUID
                match Uuid::parse_str(name_id) {
                    Ok(id) => id,
                    Err(_) => return Ok(Vec::new()),
                }
            }
        };

        // Get sessions for this user
        let sessions = self
            .session
            .get_user_sessions_by_user(realm_model.id, user_id)
            .await
            .map_err(|e| SamlRealmError::Storage(e.to_string()))?;

        let result: Vec<SessionInfo> = sessions
            .into_iter()
            .map(|s| SessionInfo {
                session_id: s.id.to_string(),
                user_id: s.user_id.to_string(),
                session_index: Some(s.id.to_string()),
                client_sessions: Vec::new(), // Would need to query client sessions separately
            })
            .collect();

        Ok(result)
    }
}
