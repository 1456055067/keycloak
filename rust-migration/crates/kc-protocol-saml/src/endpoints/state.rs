//! SAML endpoint state management.

use std::sync::Arc;

use crate::signature::{SignatureConfig, XmlSigner};

/// SAML endpoint state.
///
/// Contains the configuration and services needed by SAML endpoints.
#[derive(Clone)]
pub struct SamlState<R>
where
    R: SamlRealmProvider,
{
    /// Realm provider for looking up realm configuration.
    pub realm_provider: Arc<R>,
}

impl<R: SamlRealmProvider> SamlState<R> {
    /// Creates a new SAML state.
    pub fn new(realm_provider: Arc<R>) -> Self {
        Self { realm_provider }
    }
}

/// Provider for SAML realm configuration.
#[async_trait::async_trait]
pub trait SamlRealmProvider: Send + Sync + 'static {
    /// Checks if a realm exists.
    async fn realm_exists(&self, realm: &str) -> Result<bool, SamlRealmError>;

    /// Gets the IdP entity ID for a realm.
    async fn get_idp_entity_id(&self, realm: &str) -> Result<String, SamlRealmError>;

    /// Gets the IdP SSO URL for a realm.
    async fn get_sso_url(&self, realm: &str) -> Result<String, SamlRealmError>;

    /// Gets the IdP SLS URL for a realm.
    async fn get_sls_url(&self, realm: &str) -> Result<String, SamlRealmError>;

    /// Gets the signing configuration for a realm.
    async fn get_signing_config(&self, realm: &str) -> Result<SigningConfig, SamlRealmError>;

    /// Gets a service provider by entity ID.
    async fn get_service_provider(
        &self,
        realm: &str,
        entity_id: &str,
    ) -> Result<Option<ServiceProviderConfig>, SamlRealmError>;

    /// Gets a user by ID.
    async fn get_user(&self, realm: &str, user_id: &str) -> Result<Option<SamlUser>, SamlRealmError>;

    /// Gets user attributes for SAML assertion.
    async fn get_user_attributes(
        &self,
        realm: &str,
        user_id: &str,
        sp_entity_id: &str,
    ) -> Result<Vec<(String, Vec<String>)>, SamlRealmError>;
}

/// Error type for realm provider operations.
#[derive(Debug, thiserror::Error)]
pub enum SamlRealmError {
    /// Realm not found.
    #[error("realm not found: {0}")]
    RealmNotFound(String),

    /// Service provider not found.
    #[error("service provider not found: {0}")]
    ServiceProviderNotFound(String),

    /// User not found.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Signing configuration for a realm.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Private key in DER format.
    pub private_key_der: Vec<u8>,
    /// Certificate in DER format.
    pub certificate_der: Vec<u8>,
    /// Signature algorithm configuration.
    pub config: SignatureConfig,
}

impl SigningConfig {
    /// Creates an `XmlSigner` from this configuration.
    #[must_use]
    pub fn create_signer(&self) -> XmlSigner {
        XmlSigner::new(
            self.private_key_der.clone(),
            Some(self.certificate_der.clone()),
        )
        .with_config(self.config.clone())
    }
}

/// Service provider configuration.
#[derive(Debug, Clone)]
pub struct ServiceProviderConfig {
    /// Entity ID of the service provider.
    pub entity_id: String,

    /// Display name.
    pub name: Option<String>,

    /// Assertion Consumer Service URLs.
    pub acs_urls: Vec<AcsEndpoint>,

    /// Single Logout Service URLs.
    pub sls_urls: Vec<SlsEndpoint>,

    /// Whether to sign assertions.
    pub sign_assertions: bool,

    /// Whether to sign responses.
    pub sign_responses: bool,

    /// Whether to encrypt assertions.
    pub encrypt_assertions: bool,

    /// Encryption certificate (if encrypting).
    pub encryption_certificate: Option<Vec<u8>>,

    /// Name ID format to use.
    pub name_id_format: Option<String>,

    /// Whether this SP is enabled.
    pub enabled: bool,
}

/// Assertion Consumer Service endpoint.
#[derive(Debug, Clone)]
pub struct AcsEndpoint {
    /// The URL.
    pub url: String,
    /// The binding (POST or Redirect).
    pub binding: String,
    /// Index for this endpoint.
    pub index: u32,
    /// Whether this is the default endpoint.
    pub is_default: bool,
}

/// Single Logout Service endpoint.
#[derive(Debug, Clone)]
pub struct SlsEndpoint {
    /// The URL.
    pub url: String,
    /// The binding (POST or Redirect).
    pub binding: String,
}

/// SAML user data.
#[derive(Debug, Clone)]
pub struct SamlUser {
    /// User ID.
    pub id: String,
    /// Username.
    pub username: String,
    /// Email address.
    pub email: Option<String>,
    /// First name.
    pub first_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Whether the user is enabled.
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_realm_error_display() {
        let err = SamlRealmError::RealmNotFound("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
