//! Grant handlers for the token endpoint.
//!
//! This module implements the OAuth 2.0 grant types:
//! - `authorization_code`: Exchange auth code for tokens
//! - `client_credentials`: Client authenticates directly for service-to-service
//! - `refresh_token`: Exchange refresh token for new tokens
//! - `password`: Direct username/password (deprecated but supported)
//!
//! ## Architecture
//!
//! Each grant type is implemented as a separate handler that:
//! 1. Validates grant-specific parameters
//! 2. Authenticates the client (when required)
//! 3. Validates/authenticates the user (when applicable)
//! 4. Creates or updates sessions
//! 5. Issues tokens
//!
//! ## PKCE Support
//!
//! PKCE (Proof Key for Code Exchange) is supported for the authorization code
//! flow with S256 (recommended) and plain methods.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use kc_session::{ClientSession, SessionProvider, UserSession};

use crate::error::{OidcError, OidcResult};
use crate::request::TokenRequest;
use crate::token::{TokenManager, TokenResponse};
use crate::types::CodeChallengeMethod;

// ============================================================================
// Authorization Code Store
// ============================================================================

/// Stored authorization code data.
///
/// This represents the authorization code issued during the authorization flow,
/// stored until it's exchanged for tokens at the token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthCode {
    /// The authorization code value (hashed for security).
    pub code_hash: String,

    /// Realm name this code belongs to.
    pub realm_name: String,

    /// Client ID that requested the code.
    pub client_id: String,

    /// Client internal UUID.
    pub client_uuid: Uuid,

    /// Subject (user) ID.
    pub user_id: Uuid,

    /// Redirect URI used in the request.
    pub redirect_uri: String,

    /// Granted scopes (space-separated).
    pub scope: String,

    /// Nonce from the authorization request (for OIDC).
    pub nonce: Option<String>,

    /// PKCE code challenge.
    pub code_challenge: Option<String>,

    /// PKCE code challenge method.
    pub code_challenge_method: Option<CodeChallengeMethod>,

    /// User session ID (for session binding).
    pub user_session_id: Option<Uuid>,

    /// Client session ID.
    pub client_session_id: Option<Uuid>,

    /// When the code was created.
    pub created_at: DateTime<Utc>,

    /// When the code expires.
    pub expires_at: DateTime<Utc>,

    /// Whether this code has been used (single-use).
    pub used: bool,
}

/// Parameters for creating a new authorization code.
pub struct AuthCodeParams {
    /// The raw authorization code value.
    pub code: String,
    /// Realm name.
    pub realm_name: String,
    /// OAuth `client_id`.
    pub client_id: String,
    /// Client internal UUID.
    pub client_uuid: Uuid,
    /// User ID.
    pub user_id: Uuid,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Granted scopes.
    pub scope: String,
    /// TTL in seconds.
    pub ttl_seconds: i64,
}

impl StoredAuthCode {
    /// Creates a new stored authorization code from parameters.
    #[must_use]
    pub fn new(params: AuthCodeParams) -> Self {
        let now = Utc::now();
        Self {
            code_hash: hash_code(&params.code),
            realm_name: params.realm_name,
            client_id: params.client_id,
            client_uuid: params.client_uuid,
            user_id: params.user_id,
            redirect_uri: params.redirect_uri,
            scope: params.scope,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user_session_id: None,
            client_session_id: None,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(params.ttl_seconds),
            used: false,
        }
    }

    /// Sets the nonce.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: drops Option<String>
    pub fn with_nonce(mut self, nonce: Option<String>) -> Self {
        self.nonce = nonce;
        self
    }

    /// Sets PKCE parameters.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: drops Option<String>
    pub fn with_pkce(
        mut self,
        challenge: Option<String>,
        method: Option<CodeChallengeMethod>,
    ) -> Self {
        self.code_challenge = challenge;
        self.code_challenge_method = method;
        self
    }

    /// Sets session IDs.
    #[must_use]
    pub const fn with_session(
        mut self,
        user_session_id: Option<Uuid>,
        client_session_id: Option<Uuid>,
    ) -> Self {
        self.user_session_id = user_session_id;
        self.client_session_id = client_session_id;
        self
    }

    /// Checks if the code has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Verifies the code value.
    #[must_use]
    pub fn verify_code(&self, code: &str) -> bool {
        hash_code(code) == self.code_hash
    }
}

/// Hashes an authorization code for secure storage.
fn hash_code(code: &str) -> String {
    let hash = kc_crypto::sha256(code.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
}

/// Provider for storing and retrieving authorization codes.
#[async_trait]
pub trait AuthCodeStore: Send + Sync {
    /// Stores an authorization code.
    async fn store_code(&self, code: &StoredAuthCode) -> OidcResult<()>;

    /// Retrieves an authorization code by its hash.
    async fn get_code(&self, code_hash: &str) -> OidcResult<Option<StoredAuthCode>>;

    /// Marks a code as used (to prevent reuse).
    async fn mark_code_used(&self, code_hash: &str) -> OidcResult<()>;

    /// Removes an authorization code.
    async fn remove_code(&self, code_hash: &str) -> OidcResult<()>;

    /// Removes all expired codes (cleanup).
    async fn remove_expired_codes(&self) -> OidcResult<u64>;
}

// ============================================================================
// PKCE Validation
// ============================================================================

/// PKCE verifier for authorization code flow.
pub struct PkceVerifier;

impl PkceVerifier {
    /// Verifies the PKCE `code_verifier` against the stored `code_challenge`.
    ///
    /// Returns `Ok(())` if verification succeeds, `Err` otherwise.
    pub fn verify(
        code_verifier: &str,
        code_challenge: &str,
        method: CodeChallengeMethod,
    ) -> OidcResult<()> {
        // Validate code_verifier format (43-128 characters, unreserved chars only)
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            return Err(OidcError::InvalidGrant(
                "code_verifier must be between 43 and 128 characters".to_string(),
            ));
        }

        if !code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(OidcError::InvalidGrant(
                "code_verifier contains invalid characters".to_string(),
            ));
        }

        let computed_challenge = match method {
            CodeChallengeMethod::Plain => code_verifier.to_string(),
            CodeChallengeMethod::S256 => {
                let hash = kc_crypto::sha256(code_verifier.as_bytes());
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
            }
        };

        if computed_challenge != code_challenge {
            return Err(OidcError::InvalidGrant("PKCE verification failed".to_string()));
        }

        Ok(())
    }
}

// ============================================================================
// Client Authentication
// ============================================================================

/// Authenticated client information.
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Internal client UUID.
    pub id: Uuid,

    /// OAuth `client_id`.
    pub client_id: String,

    /// Whether this is a public client (no secret).
    pub is_public: bool,

    /// Whether the client is a service account (can use `client_credentials`).
    pub service_account_enabled: bool,

    /// Service account user ID (if enabled).
    pub service_account_user_id: Option<Uuid>,

    /// Whether direct access grants (password) are enabled.
    pub direct_access_grants_enabled: bool,

    /// Realm ID.
    pub realm_id: Uuid,
}

/// Methods for authenticating clients at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// `client_secret_basic` - HTTP Basic auth with `client_id:client_secret`.
    ClientSecretBasic,

    /// `client_secret_post` - `client_id` and `client_secret` in request body.
    ClientSecretPost,

    /// `private_key_jwt` - JWT signed with client's private key.
    PrivateKeyJwt,

    /// No authentication (public client).
    None,
}

/// Client authenticator trait.
#[async_trait]
pub trait ClientAuthenticator: Send + Sync {
    /// Authenticates a client and returns client information.
    ///
    /// # Arguments
    ///
    /// * `realm_name` - The realm name
    /// * `client_id` - OAuth `client_id`
    /// * `client_secret` - Client secret (for confidential clients)
    /// * `client_assertion` - JWT assertion (for `private_key_jwt`)
    /// * `client_assertion_type` - Type of assertion
    async fn authenticate(
        &self,
        realm_name: &str,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion: Option<&str>,
        client_assertion_type: Option<&str>,
    ) -> OidcResult<AuthenticatedClient>;

    /// Validates that a client can use a specific grant type.
    fn validate_grant_type(
        &self,
        client: &AuthenticatedClient,
        grant_type: &str,
    ) -> OidcResult<()> {
        match grant_type {
            "client_credentials" => {
                if !client.service_account_enabled {
                    return Err(OidcError::UnauthorizedClient(
                        "client_credentials grant not enabled for this client".to_string(),
                    ));
                }
            }
            "password" => {
                if !client.direct_access_grants_enabled {
                    return Err(OidcError::UnauthorizedClient(
                        "password grant not enabled for this client".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// ============================================================================
// User Authentication (for password grant)
// ============================================================================

/// Authenticated user information.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// User UUID.
    pub id: Uuid,

    /// Username.
    pub username: String,

    /// Email (if available).
    pub email: Option<String>,

    /// Whether the user is enabled.
    pub enabled: bool,
}

/// User authenticator trait for password grant.
#[async_trait]
pub trait UserAuthenticator: Send + Sync {
    /// Authenticates a user with username and password.
    async fn authenticate(
        &self,
        realm_name: &str,
        username: &str,
        password: &str,
    ) -> OidcResult<AuthenticatedUser>;
}

// ============================================================================
// Grant Context
// ============================================================================

/// Context passed to grant handlers.
///
/// The context includes all resources needed to process a token request,
/// including session management for maintaining SSO state.
pub struct GrantContext<'a, S: SessionProvider> {
    /// Realm name.
    pub realm_name: &'a str,

    /// Realm ID.
    pub realm_id: Uuid,

    /// Token request.
    pub request: &'a TokenRequest,

    /// Token manager for creating tokens.
    pub token_manager: Arc<TokenManager>,

    /// Authenticated client.
    pub client: AuthenticatedClient,

    /// Session provider for managing user and client sessions.
    pub session_provider: Arc<S>,

    /// Client IP address (for session binding).
    pub client_ip: Option<String>,

    /// User agent (for session tracking).
    pub user_agent: Option<String>,
}

impl<'a, S: SessionProvider> GrantContext<'a, S> {
    /// Creates a new grant context.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(
        realm_name: &'a str,
        realm_id: Uuid,
        request: &'a TokenRequest,
        token_manager: Arc<TokenManager>,
        client: AuthenticatedClient,
        session_provider: Arc<S>,
    ) -> Self {
        Self {
            realm_name,
            realm_id,
            request,
            token_manager,
            client,
            session_provider,
            client_ip: None,
            user_agent: None,
        }
    }

    /// Sets the client IP address.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: drops Option<String>
    pub fn with_client_ip(mut self, ip: Option<String>) -> Self {
        self.client_ip = ip;
        self
    }

    /// Sets the user agent.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: drops Option<String>
    pub fn with_user_agent(mut self, ua: Option<String>) -> Self {
        self.user_agent = ua;
        self
    }
}

// ============================================================================
// Grant Handlers
// ============================================================================

/// Result of a successful grant.
pub struct GrantResult {
    /// The token response to return.
    pub token_response: TokenResponse,

    /// User session (if created/updated).
    pub user_session: Option<UserSession>,

    /// Client session (if created/updated).
    pub client_session: Option<ClientSession>,
}

impl GrantResult {
    /// Returns the user session ID if a session was created.
    #[must_use]
    pub fn user_session_id(&self) -> Option<Uuid> {
        self.user_session.as_ref().map(|s| s.id)
    }

    /// Returns the client session ID if a session was created.
    #[must_use]
    pub fn client_session_id(&self) -> Option<Uuid> {
        self.client_session.as_ref().map(|s| s.id)
    }
}

/// Handler for `authorization_code` grant.
pub struct AuthorizationCodeGrant<C: AuthCodeStore> {
    code_store: Arc<C>,
}

impl<C: AuthCodeStore> AuthorizationCodeGrant<C> {
    /// Creates a new authorization code grant handler.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(code_store: Arc<C>) -> Self {
        Self { code_store }
    }

    /// Handles the authorization code grant.
    ///
    /// This method validates the authorization code, verifies PKCE if used,
    /// retrieves or creates sessions, and issues tokens.
    pub async fn handle<S: SessionProvider + 'static>(
        &self,
        ctx: &GrantContext<'_, S>,
    ) -> OidcResult<GrantResult> {
        // Extract required parameters
        let code = ctx
            .request
            .code
            .as_ref()
            .ok_or_else(|| OidcError::InvalidRequest("code is required".to_string()))?;

        let redirect_uri = ctx
            .request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| OidcError::InvalidRequest("redirect_uri is required".to_string()))?;

        // Look up the authorization code
        let code_hash = hash_code(code);
        let stored_code = self
            .code_store
            .get_code(&code_hash)
            .await?
            .ok_or_else(|| OidcError::InvalidGrant("invalid authorization code".to_string()))?;

        // Validate the code
        Self::validate_code(&stored_code, ctx, redirect_uri)?;

        // Verify PKCE if code_challenge was used
        if let Some(ref challenge) = stored_code.code_challenge {
            let verifier = ctx
                .request
                .code_verifier
                .as_ref()
                .ok_or_else(|| OidcError::InvalidGrant("code_verifier is required".to_string()))?;

            let method = stored_code
                .code_challenge_method
                .unwrap_or(CodeChallengeMethod::S256);

            PkceVerifier::verify(verifier, challenge, method)?;
        }

        // Mark the code as used (single-use)
        self.code_store.mark_code_used(&code_hash).await?;

        // Retrieve the user session if it exists
        let user_session = if let Some(session_id) = stored_code.user_session_id {
            ctx.session_provider
                .get_user_session(ctx.realm_id, session_id)
                .await
                .map_err(|e| OidcError::ServerError(format!("failed to get session: {e}")))?
        } else {
            None
        };

        // Update session activity if found
        if let Some(ref session) = user_session {
            let mut updated = session.clone();
            updated.touch();
            ctx.session_provider
                .update_user_session(&updated)
                .await
                .map_err(|e| OidcError::ServerError(format!("failed to update session: {e}")))?;
        }

        // Retrieve or create client session
        let client_session = if let Some(session_id) = stored_code.client_session_id {
            ctx.session_provider
                .get_client_session(ctx.realm_id, session_id)
                .await
                .map_err(|e| OidcError::ServerError(format!("failed to get client session: {e}")))?
        } else if let Some(ref user_sess) = user_session {
            // Create a new client session
            let mut client_sess = ClientSession::new(
                user_sess.id,
                ctx.client.id,
                ctx.realm_id,
                "openid-connect",
            );
            client_sess.add_scopes(stored_code.scope.split_whitespace());
            if let Some(ref uri) = ctx.request.redirect_uri {
                client_sess.redirect_uri = Some(uri.clone());
            }
            ctx.session_provider
                .create_client_session(&client_sess)
                .await
                .map_err(|e| {
                    OidcError::ServerError(format!("failed to create client session: {e}"))
                })?;
            Some(client_sess)
        } else {
            None
        };

        // Create tokens
        let token_response = ctx
            .token_manager
            .create_token_response(
                &stored_code.user_id.to_string(),
                &ctx.client.client_id,
                &stored_code.scope,
                user_session.as_ref().map(|s| s.id.to_string()).as_deref(),
                stored_code.nonce.as_deref(),
                true, // include ID token
                true, // include refresh token
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create tokens: {e}")))?;

        Ok(GrantResult {
            token_response,
            user_session,
            client_session,
        })
    }

    /// Validates the stored authorization code.
    fn validate_code<S: SessionProvider>(
        code: &StoredAuthCode,
        ctx: &GrantContext<'_, S>,
        redirect_uri: &str,
    ) -> OidcResult<()> {
        // Check if code has expired
        if code.is_expired() {
            return Err(OidcError::InvalidGrant(
                "authorization code has expired".to_string(),
            ));
        }

        // Check if code has been used
        if code.used {
            // Code reuse is a potential attack - consider revoking all tokens
            return Err(OidcError::InvalidGrant(
                "authorization code has already been used".to_string(),
            ));
        }

        // Verify client_id matches
        if code.client_id != ctx.client.client_id {
            return Err(OidcError::InvalidGrant(
                "authorization code was not issued to this client".to_string(),
            ));
        }

        // Verify realm matches
        if code.realm_name != ctx.realm_name {
            return Err(OidcError::InvalidGrant(
                "authorization code was issued for a different realm".to_string(),
            ));
        }

        // Verify redirect_uri matches exactly
        if code.redirect_uri != redirect_uri {
            return Err(OidcError::InvalidGrant(
                "redirect_uri does not match the authorization request".to_string(),
            ));
        }

        Ok(())
    }
}

/// Handler for `client_credentials` grant.
pub struct ClientCredentialsGrant;

impl ClientCredentialsGrant {
    /// Handles the client credentials grant.
    ///
    /// For `client_credentials`, no user session is created because this is
    /// a service-to-service authentication. The subject is the service account
    /// user associated with the client.
    pub fn handle<S: SessionProvider>(
        &self,
        ctx: &GrantContext<'_, S>,
    ) -> OidcResult<GrantResult> {
        // Validate client can use this grant type
        if !ctx.client.service_account_enabled {
            return Err(OidcError::UnauthorizedClient(
                "client_credentials grant not enabled".to_string(),
            ));
        }

        // Get service account user ID
        let service_account_id = ctx.client.service_account_user_id.ok_or_else(|| {
            OidcError::ServerError("service account not configured for client".to_string())
        })?;

        // Determine scope
        let scope = ctx.request.scope.as_deref().unwrap_or("openid");

        // Create tokens (no ID token, no refresh token typically)
        // Client credentials don't create user sessions - it's service-to-service
        let token_response = ctx
            .token_manager
            .create_token_response(
                &service_account_id.to_string(),
                &ctx.client.client_id,
                scope,
                None,   // no user session
                None,   // no nonce
                false,  // no ID token for client_credentials
                false,  // typically no refresh token
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create tokens: {e}")))?;

        Ok(GrantResult {
            token_response,
            user_session: None,
            client_session: None,
        })
    }
}

/// Handler for `refresh_token` grant.
pub struct RefreshTokenGrant;

/// Session timeout configuration for refresh token validation.
pub struct SessionTimeouts {
    /// Idle timeout in seconds.
    pub idle_timeout: i64,
    /// Maximum session lifespan in seconds.
    pub max_lifespan: i64,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            idle_timeout: 1800,    // 30 minutes
            max_lifespan: 36000,   // 10 hours
        }
    }
}

impl RefreshTokenGrant {
    /// Handles the refresh token grant.
    ///
    /// This method validates the refresh token, checks session validity,
    /// updates session activity, and issues new tokens with refresh token rotation.
    pub async fn handle<S: SessionProvider + 'static>(
        &self,
        ctx: &GrantContext<'_, S>,
        timeouts: &SessionTimeouts,
    ) -> OidcResult<GrantResult> {
        let refresh_token = ctx
            .request
            .refresh_token
            .as_ref()
            .ok_or_else(|| OidcError::InvalidRequest("refresh_token is required".to_string()))?;

        // Validate the refresh token
        let claims = ctx
            .token_manager
            .validate_refresh_token(refresh_token)
            .map_err(|e| OidcError::InvalidGrant(format!("invalid refresh token: {e}")))?;

        // Verify the client_id matches
        if claims.azp.as_deref() != Some(&ctx.client.client_id) {
            return Err(OidcError::InvalidGrant(
                "refresh token was not issued to this client".to_string(),
            ));
        }

        // Check if the session is still valid
        let user_session = if let Some(ref sid) = claims.sid {
            let session_id = Uuid::parse_str(sid)
                .map_err(|_| OidcError::InvalidGrant("invalid session ID in token".to_string()))?;

            let session = ctx
                .session_provider
                .get_user_session(ctx.realm_id, session_id)
                .await
                .map_err(|e| OidcError::ServerError(format!("failed to get session: {e}")))?
                .ok_or_else(|| {
                    OidcError::InvalidGrant("session no longer exists".to_string())
                })?;

            // Check if session is active
            if !session.is_active() {
                return Err(OidcError::InvalidGrant("session has been logged out".to_string()));
            }

            // Check if session has expired
            if session.is_expired(timeouts.idle_timeout, timeouts.max_lifespan) {
                return Err(OidcError::InvalidGrant("session has expired".to_string()));
            }

            // Update session activity
            let mut updated = session.clone();
            updated.touch();
            ctx.session_provider
                .update_user_session(&updated)
                .await
                .map_err(|e| OidcError::ServerError(format!("failed to update session: {e}")))?;

            Some(updated)
        } else {
            None
        };

        // Determine if scope should be reduced
        let original_scope = claims.scope.as_deref().unwrap_or("openid");
        let requested_scope = ctx.request.scope.as_deref().unwrap_or(original_scope);

        // Validate requested scope is subset of original scope
        let original_scopes: std::collections::HashSet<&str> =
            original_scope.split_whitespace().collect();
        let requested_scopes: std::collections::HashSet<&str> =
            requested_scope.split_whitespace().collect();

        if !requested_scopes.is_subset(&original_scopes) {
            return Err(OidcError::InvalidScope(
                "requested scope exceeds original grant".to_string(),
            ));
        }

        // Issue new tokens
        let token_response = ctx
            .token_manager
            .create_token_response(
                &claims.sub,
                &ctx.client.client_id,
                requested_scope,
                user_session.as_ref().map(|s| s.id.to_string()).as_deref(),
                claims.nonce.as_deref(),
                true, // include ID token
                true, // include new refresh token (refresh token rotation)
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create tokens: {e}")))?;

        Ok(GrantResult {
            token_response,
            user_session,
            client_session: None,
        })
    }
}

/// Handler for password grant (deprecated but supported).
///
/// **Note**: The password grant is deprecated in OAuth 2.1 and should only
/// be used for trusted first-party applications. Consider using authorization
/// code flow with PKCE instead.
pub struct PasswordGrant<U: UserAuthenticator> {
    user_authenticator: Arc<U>,
}

impl<U: UserAuthenticator> PasswordGrant<U> {
    /// Creates a new password grant handler.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(user_authenticator: Arc<U>) -> Self {
        Self { user_authenticator }
    }

    /// Handles the password grant.
    ///
    /// This method authenticates the user, creates a new SSO session and
    /// client session, then issues tokens.
    pub async fn handle<S: SessionProvider + 'static>(
        &self,
        ctx: &GrantContext<'_, S>,
    ) -> OidcResult<GrantResult> {
        // Validate client can use this grant type
        if !ctx.client.direct_access_grants_enabled {
            return Err(OidcError::UnauthorizedClient(
                "password grant not enabled for this client".to_string(),
            ));
        }

        let username = ctx
            .request
            .username
            .as_ref()
            .ok_or_else(|| OidcError::InvalidRequest("username is required".to_string()))?;

        let password = ctx
            .request
            .password
            .as_ref()
            .ok_or_else(|| OidcError::InvalidRequest("password is required".to_string()))?;

        // Authenticate user
        let user = self
            .user_authenticator
            .authenticate(ctx.realm_name, username, password)
            .await?;

        // Check user is enabled
        if !user.enabled {
            return Err(OidcError::InvalidGrant("user is disabled".to_string()));
        }

        // Determine scope
        let scope = ctx.request.scope.as_deref().unwrap_or("openid");

        // Create user session (SSO session)
        let mut user_session = UserSession::new(ctx.realm_id, user.id);
        user_session.auth_method = Some("password".to_string());
        if let Some(ref ip) = ctx.client_ip {
            user_session.ip_address = Some(ip.clone());
        }
        if let Some(ref ua) = ctx.user_agent {
            user_session.user_agent = Some(ua.clone());
        }
        // Store which client initiated the login
        user_session.set_note(
            kc_session::user_session::notes::AUTH_CLIENT_ID,
            &ctx.client.client_id,
        );

        ctx.session_provider
            .create_user_session(&user_session)
            .await
            .map_err(|e| OidcError::ServerError(format!("failed to create session: {e}")))?;

        // Create client session
        let mut client_session = ClientSession::new(
            user_session.id,
            ctx.client.id,
            ctx.realm_id,
            "openid-connect",
        );
        client_session.add_scopes(scope.split_whitespace());

        ctx.session_provider
            .create_client_session(&client_session)
            .await
            .map_err(|e| {
                OidcError::ServerError(format!("failed to create client session: {e}"))
            })?;

        // Create tokens with session ID
        let token_response = ctx
            .token_manager
            .create_token_response(
                &user.id.to_string(),
                &ctx.client.client_id,
                scope,
                Some(&user_session.id.to_string()),
                None, // no nonce for password grant
                true, // include ID token
                true, // include refresh token
            )
            .map_err(|e| OidcError::ServerError(format!("failed to create tokens: {e}")))?;

        Ok(GrantResult {
            token_response,
            user_session: Some(user_session),
            client_session: Some(client_session),
        })
    }
}

// ============================================================================
// In-Memory AuthCode Store (for testing/development)
// ============================================================================

/// In-memory authorization code store.
///
/// This is suitable for single-instance deployments or testing.
/// For production with multiple instances, use a distributed store (Redis, etc.).
pub struct InMemoryAuthCodeStore {
    codes: tokio::sync::RwLock<std::collections::HashMap<String, StoredAuthCode>>,
}

impl InMemoryAuthCodeStore {
    /// Creates a new in-memory auth code store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            codes: tokio::sync::RwLock::new(std::collections::HashMap::new()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_verification() {
        // Test vectors from RFC 7636
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(PkceVerifier::verify(code_verifier, code_challenge, CodeChallengeMethod::S256).is_ok());
    }

    #[test]
    fn pkce_plain_verification() {
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        assert!(
            PkceVerifier::verify(code_verifier, code_verifier, CodeChallengeMethod::Plain).is_ok()
        );
    }

    #[test]
    fn pkce_verification_fails_on_mismatch() {
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "wrong-challenge-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        assert!(
            PkceVerifier::verify(code_verifier, wrong_challenge, CodeChallengeMethod::S256).is_err()
        );
    }

    #[test]
    fn pkce_verifier_too_short() {
        let short_verifier = "tooshort";
        let challenge = "test";

        assert!(PkceVerifier::verify(short_verifier, challenge, CodeChallengeMethod::Plain).is_err());
    }

    #[test]
    fn hash_code_produces_consistent_output() {
        let code = "test-authorization-code";
        let hash1 = hash_code(code);
        let hash2 = hash_code(code);

        assert_eq!(hash1, hash2);
        assert!(!hash1.contains('+')); // URL-safe encoding
        assert!(!hash1.contains('/')); // URL-safe encoding
    }

    fn test_auth_code_params(code: &str, ttl_seconds: i64) -> AuthCodeParams {
        AuthCodeParams {
            code: code.to_string(),
            realm_name: "master".to_string(),
            client_id: "test-client".to_string(),
            client_uuid: Uuid::nil(),
            user_id: Uuid::nil(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid".to_string(),
            ttl_seconds,
        }
    }

    #[test]
    fn stored_auth_code_expiration() {
        let code = StoredAuthCode::new(test_auth_code_params("test-code", -1));
        assert!(code.is_expired());

        let valid_code = StoredAuthCode::new(test_auth_code_params("test-code", 600));
        assert!(!valid_code.is_expired());
    }

    #[tokio::test]
    async fn in_memory_store_basic_operations() {
        let store = InMemoryAuthCodeStore::new();

        let code = StoredAuthCode::new(test_auth_code_params("test-code", 600));

        // Store
        store.store_code(&code).await.unwrap();

        // Retrieve
        let retrieved = store.get_code(&code.code_hash).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().client_id, "test-client");

        // Mark used
        store.mark_code_used(&code.code_hash).await.unwrap();
        let used = store.get_code(&code.code_hash).await.unwrap().unwrap();
        assert!(used.used);

        // Remove
        store.remove_code(&code.code_hash).await.unwrap();
        assert!(store.get_code(&code.code_hash).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn in_memory_store_cleanup_expired() {
        let store = InMemoryAuthCodeStore::new();

        // Add expired code
        let expired = StoredAuthCode::new(test_auth_code_params("expired-code", -1));
        store.store_code(&expired).await.unwrap();

        // Add valid code
        let valid = StoredAuthCode::new(test_auth_code_params("valid-code", 600));
        store.store_code(&valid).await.unwrap();

        // Cleanup
        let removed = store.remove_expired_codes().await.unwrap();
        assert_eq!(removed, 1);

        // Valid code should still be there
        assert!(store.get_code(&valid.code_hash).await.unwrap().is_some());
        // Expired code should be gone
        assert!(store.get_code(&expired.code_hash).await.unwrap().is_none());
    }
}
