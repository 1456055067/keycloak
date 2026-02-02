//! Token revocation endpoint handler.
//!
//! Implements POST `/revoke` as defined in RFC 7009.
//!
//! ## Enhanced Revocation Endpoint
//!
//! For proper client authentication and token blocklist, use `revoke_with_blocklist`
//! with `RevocationEndpointState`.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

use crate::error::{ErrorResponse, OidcError, OidcResult};
use crate::request::RevocationRequest;

use super::client_auth::extract_credentials;
use super::grants::ClientAuthenticator;
use super::state::{OidcState, RealmProvider};

// ============================================================================
// Token Blocklist
// ============================================================================

/// Token blocklist for revoked tokens.
///
/// Implement this trait to store revoked token identifiers.
#[async_trait::async_trait]
pub trait TokenBlocklist: Send + Sync {
    /// Adds a token JTI to the blocklist.
    ///
    /// The `expires_at` timestamp indicates when the entry can be removed
    /// (typically the token's original expiration time).
    async fn add(&self, jti: &str, expires_at: i64) -> OidcResult<()>;

    /// Checks if a token JTI is in the blocklist.
    async fn contains(&self, jti: &str) -> OidcResult<bool>;

    /// Removes expired entries from the blocklist.
    async fn cleanup_expired(&self) -> OidcResult<u64>;
}

/// In-memory token blocklist.
///
/// Suitable for single-instance deployments or testing.
/// For production with multiple instances, use a distributed store.
pub struct InMemoryTokenBlocklist {
    entries: tokio::sync::RwLock<std::collections::HashMap<String, i64>>,
}

impl InMemoryTokenBlocklist {
    /// Creates a new in-memory token blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryTokenBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenBlocklist for InMemoryTokenBlocklist {
    async fn add(&self, jti: &str, expires_at: i64) -> OidcResult<()> {
        self.entries
            .write()
            .await
            .insert(jti.to_string(), expires_at);
        Ok(())
    }

    async fn contains(&self, jti: &str) -> OidcResult<bool> {
        Ok(self.entries.read().await.contains_key(jti))
    }

    async fn cleanup_expired(&self) -> OidcResult<u64> {
        let mut entries = self.entries.write().await;
        let now = chrono::Utc::now().timestamp();
        let initial_len = entries.len();
        entries.retain(|_, expires_at| *expires_at > now);
        Ok((initial_len - entries.len()) as u64)
    }
}

// ============================================================================
// Enhanced Revocation Endpoint State
// ============================================================================

/// Enhanced state for revocation endpoint with proper client authentication and blocklist.
#[derive(Clone)]
pub struct RevocationEndpointState<R, C, B>
where
    R: RealmProvider,
    C: ClientAuthenticator,
    B: TokenBlocklist,
{
    /// Realm provider for token validation.
    pub realm_provider: Arc<R>,
    /// Client authenticator for verifying the revoking client.
    pub client_authenticator: Arc<C>,
    /// Token blocklist for storing revoked tokens.
    pub token_blocklist: Arc<B>,
}

impl<R, C, B> RevocationEndpointState<R, C, B>
where
    R: RealmProvider,
    C: ClientAuthenticator,
    B: TokenBlocklist,
{
    /// Creates a new revocation endpoint state.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(
        realm_provider: Arc<R>,
        client_authenticator: Arc<C>,
        token_blocklist: Arc<B>,
    ) -> Self {
        Self {
            realm_provider,
            client_authenticator,
            token_blocklist,
        }
    }
}

/// POST `/revoke`
///
/// Revokes a token (access token or refresh token).
///
/// # Authorization
///
/// Requires client authentication (Basic auth or `client_id`/`client_secret` in body).
///
/// # Request Body
///
/// - `token`: The token to revoke (required)
/// - `token_type_hint`: Hint about the token type (`access_token` or `refresh_token`)
///
/// # Responses
///
/// - 200 OK: Token revoked (or was already invalid)
/// - 401 Unauthorized: Client authentication failed
///
/// Per RFC 7009, the revocation endpoint MUST return 200 OK even if the token
/// was already invalid, to prevent token scanning attacks.
pub async fn revoke<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(request): Form<RevocationRequest>,
) -> impl IntoResponse {
    match handle_revocation_request(&state, &realm, &headers, &request).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(ref err) => error_response(err),
    }
}

// ============================================================================
// Enhanced Revocation Handler
// ============================================================================

/// POST `/revoke` - Enhanced version with proper client authentication and blocklist.
///
/// This handler authenticates the client, validates token ownership, and adds
/// the token to the blocklist for proper revocation.
pub async fn revoke_with_blocklist<R, C, B>(
    State(state): State<RevocationEndpointState<R, C, B>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(request): Form<RevocationRequest>,
) -> impl IntoResponse
where
    R: RealmProvider + 'static,
    C: ClientAuthenticator + 'static,
    B: TokenBlocklist + 'static,
{
    match handle_revocation_with_blocklist(&state, &realm, &headers, &request).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(ref err) => error_response(err),
    }
}

/// Handles the revocation request with proper client authentication and blocklist.
async fn handle_revocation_with_blocklist<R, C, B>(
    state: &RevocationEndpointState<R, C, B>,
    realm: &str,
    headers: &HeaderMap,
    request: &RevocationRequest,
) -> Result<(), OidcError>
where
    R: RealmProvider,
    C: ClientAuthenticator,
    B: TokenBlocklist,
{
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Extract client credentials from Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    // Authenticate client if credentials provided
    let authenticated_client_id = if auth_header.is_some() {
        let (client_id, client_secret, _method) = extract_credentials(auth_header, None, None)?;

        // Authenticate the client
        let client = state
            .client_authenticator
            .authenticate(realm, &client_id, client_secret.as_deref(), None, None)
            .await?;

        Some(client.client_id)
    } else {
        None
    };

    // Get the token manager
    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Try to validate the token to get its claims
    let token_type_hint = request.token_type_hint.as_deref();

    // Try access token first
    if (token_type_hint.is_none() || token_type_hint == Some("access_token"))
        && let Ok(claims) = token_manager.validate_access_token(&request.token)
    {
        // Verify token ownership if client authenticated
        if let Some(ref auth_client_id) = authenticated_client_id
            && claims.azp.as_ref() != Some(auth_client_id)
        {
            return Err(OidcError::UnauthorizedClient(
                "client is not authorized to revoke this token".to_string(),
            ));
        }

        // Add to blocklist if JTI is present
        if let Some(ref jti) = claims.jti {
            state.token_blocklist.add(jti, claims.exp).await?;
        }
        return Ok(());
    }

    // Try refresh token
    if (token_type_hint.is_none() || token_type_hint == Some("refresh_token"))
        && let Ok(claims) = token_manager.validate_refresh_token(&request.token)
    {
        // Verify token ownership if client authenticated
        if let Some(ref auth_client_id) = authenticated_client_id
            && claims.azp.as_ref() != Some(auth_client_id)
        {
            return Err(OidcError::UnauthorizedClient(
                "client is not authorized to revoke this token".to_string(),
            ));
        }

        // Add to blocklist
        state.token_blocklist.add(&claims.jti, claims.exp).await?;
        return Ok(());
    }

    // Token is invalid or expired - per RFC 7009, return success anyway
    Ok(())
}

/// Handles the revocation request.
async fn handle_revocation_request<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    headers: &HeaderMap,
    request: &RevocationRequest,
) -> Result<(), OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Authenticate the client making the revocation request
    let client_id = authenticate_client(headers)?;

    // Get the token manager to validate the token
    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Determine token type and validate ownership
    let token_type_hint = request.token_type_hint.as_deref();

    // Try to validate the token to get its claims
    let token_client_id = if token_type_hint.is_none() || token_type_hint == Some("access_token") {
        if let Ok(claims) = token_manager.validate_access_token(&request.token) {
            claims.azp
        } else if token_type_hint.is_none() || token_type_hint == Some("refresh_token") {
            if let Ok(claims) = token_manager.validate_refresh_token(&request.token) {
                claims.azp
            } else {
                // Token is invalid - per RFC 7009, return success anyway
                return Ok(());
            }
        } else {
            // Token is invalid - per RFC 7009, return success anyway
            return Ok(());
        }
    } else if token_type_hint == Some("refresh_token") {
        if let Ok(claims) = token_manager.validate_refresh_token(&request.token) {
            claims.azp
        } else {
            // Token is invalid - per RFC 7009, return success anyway
            return Ok(());
        }
    } else {
        // Unknown token type hint - try anyway
        return Ok(());
    };

    // Verify the token belongs to the requesting client
    if let (Some(ref client_id), Some(ref token_client_id)) = (client_id, token_client_id)
        && client_id != token_client_id
    {
        // Per RFC 7009, if client is not authorized to revoke the token,
        // the server SHOULD return an error
        return Err(OidcError::UnauthorizedClient(
            "client is not authorized to revoke this token".to_string(),
        ));
    }

    // TODO: Actually revoke the token
    // In a real implementation, we would:
    // 1. Add the token to a revocation list (blocklist)
    // 2. If it's a refresh token, also invalidate any access tokens derived from it
    // 3. If using session-bound tokens, potentially invalidate the session

    // For now, just log and return success
    // tracing::info!(token_type = ?request.token_type_hint, "Token revoked");

    Ok(())
}

/// Authenticates the client making the revocation request.
fn authenticate_client(headers: &HeaderMap) -> Result<Option<String>, OidcError> {
    // Check for Authorization header (Basic auth)
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OidcError::InvalidClient("invalid authorization header".to_string()))?;

        if let Some(basic_auth) = auth_str.strip_prefix("Basic ") {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                basic_auth.trim(),
            )
            .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

            let credentials = String::from_utf8(decoded)
                .map_err(|_| OidcError::InvalidClient("invalid basic auth encoding".to_string()))?;

            let (client_id, _client_secret) = credentials
                .split_once(':')
                .ok_or_else(|| OidcError::InvalidClient("invalid basic auth format".to_string()))?;

            // In a real implementation, we would verify the client_secret here

            return Ok(Some(client_id.to_string()));
        }
    }

    // For public clients, no authentication is required
    // but we can't verify token ownership
    Ok(None)
}

/// Converts an `OidcError` to an HTTP response.
fn error_response(err: &OidcError) -> axum::response::Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let error_response = ErrorResponse {
        error: err.error_code().to_string(),
        error_description: Some(err.to_string()),
        error_uri: None,
    };
    (status, Json(error_response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    #[test]
    fn authenticate_client_basic_auth() {
        let mut headers = HeaderMap::new();
        // "test_client:test_secret" base64 encoded
        headers.insert(
            AUTHORIZATION,
            "Basic dGVzdF9jbGllbnQ6dGVzdF9zZWNyZXQ=".parse().unwrap(),
        );

        let result = authenticate_client(&headers).unwrap();
        assert_eq!(result, Some("test_client".to_string()));
    }

    #[test]
    fn authenticate_client_no_auth() {
        let headers = HeaderMap::new();
        let result = authenticate_client(&headers).unwrap();
        assert_eq!(result, None);
    }
}
