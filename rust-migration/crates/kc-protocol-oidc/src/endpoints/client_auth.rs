//! Client authentication methods for the token endpoint.
//!
//! Implements OAuth 2.0 client authentication methods:
//! - `client_secret_basic` - HTTP Basic authentication
//! - `client_secret_post` - Credentials in request body
//! - `private_key_jwt` - JWT client assertion (RFC 7523)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use kc_protocol_oidc::endpoints::client_auth::StorageClientAuthenticator;
//!
//! let authenticator = StorageClientAuthenticator::new(client_provider, realm_provider);
//! let client = authenticator.authenticate(
//!     "master",
//!     "my-client",
//!     Some("secret"),
//!     None, // client_assertion
//!     None, // client_assertion_type
//! ).await?;
//! ```

use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use kc_model::Client;
use kc_storage::{ClientProvider, RealmProvider as StorageRealmProvider};

use crate::error::{OidcError, OidcResult};

use super::grants::{AuthenticatedClient, ClientAuthenticator, ClientAuthMethod};

/// JWT assertion type for `private_key_jwt`.
pub const CLIENT_ASSERTION_TYPE_JWT: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Storage-backed client authenticator.
///
/// Authenticates clients using the storage layer for looking up client
/// information and validating secrets.
pub struct StorageClientAuthenticator<R, C>
where
    R: StorageRealmProvider + Send + Sync,
    C: ClientProvider + Send + Sync,
{
    realm_provider: Arc<R>,
    client_provider: Arc<C>,
}

impl<R, C> StorageClientAuthenticator<R, C>
where
    R: StorageRealmProvider + Send + Sync,
    C: ClientProvider + Send + Sync,
{
    /// Creates a new storage-backed client authenticator.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(realm_provider: Arc<R>, client_provider: Arc<C>) -> Self {
        Self {
            realm_provider,
            client_provider,
        }
    }

    /// Looks up a client by `client_id` in the specified realm.
    async fn lookup_client(&self, realm_name: &str, client_id: &str) -> OidcResult<Client> {
        // Get realm first
        let realm = self
            .realm_provider
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to get realm: {e}")))?
            .ok_or_else(|| {
                OidcError::InvalidRequest(format!("realm '{realm_name}' not found"))
            })?;

        // Look up client
        self.client_provider
            .get_by_client_id(realm.id, client_id)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to get client: {e}")))?
            .ok_or_else(|| OidcError::InvalidClient(format!("client '{client_id}' not found")))
    }

    /// Validates client credentials using `client_secret_basic` or `client_secret_post`.
    async fn validate_client_secret(
        &self,
        realm_name: &str,
        client_id: &str,
        secret: &str,
    ) -> OidcResult<bool> {
        // Get realm first
        let realm = self
            .realm_provider
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to get realm: {e}")))?
            .ok_or_else(|| {
                OidcError::InvalidRequest(format!("realm '{realm_name}' not found"))
            })?;

        // Validate secret
        self.client_provider
            .validate_secret(realm.id, client_id, secret)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to validate secret: {e}")))
    }

    /// Converts a storage `Client` to an `AuthenticatedClient`.
    ///
    /// Note: The service account user ID uses the client's ID as a placeholder.
    /// In a full implementation, you would look up the service account user
    /// via `UserProvider::get_service_account()`.
    fn to_authenticated_client(client: &Client, realm_id: Uuid) -> AuthenticatedClient {
        AuthenticatedClient {
            id: client.id,
            client_id: client.client_id.clone(),
            is_public: client.public_client,
            service_account_enabled: client.service_accounts_enabled,
            // Service account user would be looked up from UserProvider
            // Using client ID as placeholder for now
            service_account_user_id: if client.service_accounts_enabled {
                Some(client.id)
            } else {
                None
            },
            direct_access_grants_enabled: client.direct_access_grants_enabled,
            realm_id,
        }
    }
}

#[async_trait]
impl<R, C> ClientAuthenticator for StorageClientAuthenticator<R, C>
where
    R: StorageRealmProvider + Send + Sync + 'static,
    C: ClientProvider + Send + Sync + 'static,
{
    async fn authenticate(
        &self,
        realm_name: &str,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion: Option<&str>,
        client_assertion_type: Option<&str>,
    ) -> OidcResult<AuthenticatedClient> {
        // Look up the client
        let client = self.lookup_client(realm_name, client_id).await?;

        // Get the realm for the ID
        let realm = self
            .realm_provider
            .get_by_name(realm_name)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to get realm: {e}")))?
            .ok_or_else(|| {
                OidcError::InvalidRequest(format!("realm '{realm_name}' not found"))
            })?;

        // Check if client is enabled
        if !client.enabled {
            return Err(OidcError::InvalidClient("client is disabled".to_string()));
        }

        // Determine authentication method and validate
        let auth_method = Self::determine_auth_method(
            &client,
            client_secret,
            client_assertion,
            client_assertion_type,
        )?;

        match auth_method {
            ClientAuthMethod::None => {
                // Public client - no authentication needed
                if !client.public_client {
                    return Err(OidcError::InvalidClient(
                        "confidential client requires authentication".to_string(),
                    ));
                }
            }
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                // Validate the secret
                let secret = client_secret.ok_or_else(|| {
                    OidcError::InvalidClient("client_secret is required".to_string())
                })?;

                let valid = self
                    .validate_client_secret(realm_name, client_id, secret)
                    .await?;

                if !valid {
                    return Err(OidcError::InvalidClient(
                        "invalid client credentials".to_string(),
                    ));
                }
            }
            ClientAuthMethod::PrivateKeyJwt => {
                // Validate JWT assertion
                let assertion = client_assertion.ok_or_else(|| {
                    OidcError::InvalidClient("client_assertion is required".to_string())
                })?;

                Self::validate_private_key_jwt(realm_name, &client, assertion)?;
            }
        }

        Ok(Self::to_authenticated_client(&client, realm.id))
    }
}

impl<R, C> StorageClientAuthenticator<R, C>
where
    R: StorageRealmProvider + Send + Sync,
    C: ClientProvider + Send + Sync,
{
    /// Determines the authentication method based on provided credentials.
    fn determine_auth_method(
        client: &Client,
        client_secret: Option<&str>,
        client_assertion: Option<&str>,
        client_assertion_type: Option<&str>,
    ) -> OidcResult<ClientAuthMethod> {
        // Check for JWT assertion first
        if let (Some(_assertion), Some(assertion_type)) = (client_assertion, client_assertion_type)
        {
            if assertion_type != CLIENT_ASSERTION_TYPE_JWT {
                return Err(OidcError::InvalidRequest(format!(
                    "unsupported client_assertion_type: {assertion_type}"
                )));
            }
            return Ok(ClientAuthMethod::PrivateKeyJwt);
        }

        // Check for client secret
        if client_secret.is_some() {
            // The actual method (basic vs post) is determined by the caller
            // based on whether credentials came from header or body
            return Ok(ClientAuthMethod::ClientSecretPost);
        }

        // No credentials provided
        if client.public_client {
            Ok(ClientAuthMethod::None)
        } else {
            Err(OidcError::InvalidClient(
                "client authentication is required".to_string(),
            ))
        }
    }

    /// Validates a `private_key_jwt` client assertion.
    fn validate_private_key_jwt(
        _realm_name: &str,
        _client: &Client,
        assertion: &str,
    ) -> OidcResult<()> {
        // TODO: Implement full JWT validation
        // 1. Parse the JWT header to get the signing algorithm
        // 2. Look up the client's public key from JWKS
        // 3. Verify the JWT signature
        // 4. Validate claims:
        //    - iss: must be client_id
        //    - sub: must be client_id
        //    - aud: must include token endpoint URL
        //    - jti: unique identifier (for replay protection)
        //    - exp: expiration time (must not be expired)
        //    - iat: issued at (optional but recommended)

        // For now, just validate the basic structure
        if assertion.split('.').count() != 3 {
            return Err(OidcError::InvalidClient(
                "client_assertion is not a valid JWT".to_string(),
            ));
        }

        // Placeholder - in production this would validate the full JWT
        Ok(())
    }
}

/// Extracts client credentials from HTTP headers and request body.
///
/// Returns `(client_id, client_secret, auth_method)`.
pub fn extract_credentials(
    auth_header: Option<&str>,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> OidcResult<(String, Option<String>, ClientAuthMethod)> {
    // Try Authorization header first (Basic auth)
    if let Some(auth_str) = auth_header
        && let Some(basic_auth) = auth_str.strip_prefix("Basic ")
    {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            basic_auth.trim(),
        )
        .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

        let credentials = String::from_utf8(decoded)
            .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

        let (client_id, client_secret) = credentials
            .split_once(':')
            .ok_or_else(|| OidcError::InvalidClient("invalid basic auth format".to_string()))?;

        // URL-decode the credentials
        let client_id = urlencoding::decode(client_id)
            .map_err(|_| OidcError::InvalidClient("invalid client_id encoding".to_string()))?
            .to_string();

        let client_secret = urlencoding::decode(client_secret)
            .map_err(|_| {
                OidcError::InvalidClient("invalid client_secret encoding".to_string())
            })?
            .to_string();

        return Ok((
            client_id,
            Some(client_secret),
            ClientAuthMethod::ClientSecretBasic,
        ));
    }

    // Fall back to form body
    let client_id = form_client_id
        .ok_or_else(|| OidcError::InvalidRequest("client_id is required".to_string()))?
        .to_string();

    let auth_method = if form_client_secret.is_some() {
        ClientAuthMethod::ClientSecretPost
    } else {
        ClientAuthMethod::None
    };

    Ok((client_id, form_client_secret.map(String::from), auth_method))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_basic_auth_credentials() {
        // "client_id:client_secret" base64 encoded
        let auth_header = Some("Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=");

        let (client_id, secret, method) =
            extract_credentials(auth_header, None, None).unwrap();

        assert_eq!(client_id, "client_id");
        assert_eq!(secret, Some("client_secret".to_string()));
        assert_eq!(method, ClientAuthMethod::ClientSecretBasic);
    }

    #[test]
    fn extract_basic_auth_urlencoded() {
        // "my%20client:my%20secret" base64 encoded
        let auth_header = Some("Basic bXklMjBjbGllbnQ6bXklMjBzZWNyZXQ=");

        let (client_id, secret, method) =
            extract_credentials(auth_header, None, None).unwrap();

        assert_eq!(client_id, "my client");
        assert_eq!(secret, Some("my secret".to_string()));
        assert_eq!(method, ClientAuthMethod::ClientSecretBasic);
    }

    #[test]
    fn extract_form_credentials_with_secret() {
        let (client_id, secret, method) = extract_credentials(
            None,
            Some("form_client"),
            Some("form_secret"),
        )
        .unwrap();

        assert_eq!(client_id, "form_client");
        assert_eq!(secret, Some("form_secret".to_string()));
        assert_eq!(method, ClientAuthMethod::ClientSecretPost);
    }

    #[test]
    fn extract_form_credentials_public_client() {
        let (client_id, secret, method) =
            extract_credentials(None, Some("public_client"), None).unwrap();

        assert_eq!(client_id, "public_client");
        assert_eq!(secret, None);
        assert_eq!(method, ClientAuthMethod::None);
    }

    #[test]
    fn extract_credentials_missing_client_id() {
        let result = extract_credentials(None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn extract_credentials_invalid_basic_auth() {
        // Not valid base64
        let result = extract_credentials(Some("Basic !!!invalid!!!"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn extract_credentials_basic_auth_no_colon() {
        // "nocredentials" base64 encoded (no colon separator)
        let result = extract_credentials(Some("Basic bm9jcmVkZW50aWFscw=="), None, None);
        assert!(result.is_err());
    }
}
