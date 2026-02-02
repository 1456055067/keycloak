//! `UserInfo` endpoint handler.
//!
//! Implements GET/POST `/userinfo` for returning user claims.
//!
//! ## Enhanced UserInfo Endpoint
//!
//! For full user data retrieval, use the enhanced handlers with `UserInfoEndpointState`:
//! - `userinfo_get_with_provider` / `userinfo_post_with_provider`
//!
//! These handlers look up actual user data from storage based on the access token.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{ErrorResponse, OidcError};

use super::state::{OidcState, RealmProvider};

// ============================================================================
// UserInfo Provider Trait
// ============================================================================

/// User data for building UserInfo response.
///
/// This is a simplified view of the user suitable for the userinfo endpoint,
/// containing only OIDC standard claims and custom attributes.
#[derive(Debug, Clone, Default)]
pub struct UserInfoData {
    /// Subject identifier (user ID).
    pub sub: String,

    // === Profile scope ===
    /// Full name.
    pub name: Option<String>,
    /// Given name (first name).
    pub given_name: Option<String>,
    /// Family name (last name).
    pub family_name: Option<String>,
    /// Middle name.
    pub middle_name: Option<String>,
    /// Nickname.
    pub nickname: Option<String>,
    /// Preferred username.
    pub preferred_username: Option<String>,
    /// Profile URL.
    pub profile: Option<String>,
    /// Picture URL.
    pub picture: Option<String>,
    /// Website URL.
    pub website: Option<String>,
    /// Gender.
    pub gender: Option<String>,
    /// Birthdate (YYYY-MM-DD).
    pub birthdate: Option<String>,
    /// Timezone (zoneinfo).
    pub zoneinfo: Option<String>,
    /// Locale.
    pub locale: Option<String>,
    /// Last updated timestamp (Unix seconds).
    pub updated_at: Option<i64>,

    // === Email scope ===
    /// Email address.
    pub email: Option<String>,
    /// Whether email is verified.
    pub email_verified: Option<bool>,

    // === Phone scope ===
    /// Phone number.
    pub phone_number: Option<String>,
    /// Whether phone is verified.
    pub phone_number_verified: Option<bool>,

    // === Address scope ===
    /// Address claim.
    pub address: Option<AddressClaim>,

    // === Custom attributes ===
    /// Custom claims from user attributes.
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// Provider trait for retrieving user information.
///
/// Implement this trait to provide user data from your storage layer.
#[async_trait::async_trait]
pub trait UserInfoProvider: Send + Sync {
    /// Retrieves user information by user ID.
    ///
    /// Returns `None` if the user is not found.
    async fn get_user_info(
        &self,
        realm_name: &str,
        user_id: Uuid,
    ) -> Result<Option<UserInfoData>, OidcError>;

    /// Retrieves user information with scope filtering.
    ///
    /// Only includes claims allowed by the granted scopes.
    /// Default implementation calls `get_user_info` and filters.
    async fn get_user_info_for_scopes(
        &self,
        realm_name: &str,
        user_id: Uuid,
        scopes: &[&str],
    ) -> Result<Option<UserInfoData>, OidcError> {
        let user_data = self.get_user_info(realm_name, user_id).await?;

        Ok(user_data.map(|mut data| {
            // Filter claims based on scopes
            if !scopes.contains(&"profile") {
                data.name = None;
                data.given_name = None;
                data.family_name = None;
                data.middle_name = None;
                data.nickname = None;
                data.preferred_username = None;
                data.profile = None;
                data.picture = None;
                data.website = None;
                data.gender = None;
                data.birthdate = None;
                data.zoneinfo = None;
                data.locale = None;
                data.updated_at = None;
            }

            if !scopes.contains(&"email") {
                data.email = None;
                data.email_verified = None;
            }

            if !scopes.contains(&"phone") {
                data.phone_number = None;
                data.phone_number_verified = None;
            }

            if !scopes.contains(&"address") {
                data.address = None;
            }

            data
        }))
    }
}

/// Enhanced state for UserInfo endpoint with user data provider.
#[derive(Clone)]
pub struct UserInfoEndpointState<R, U>
where
    R: RealmProvider,
    U: UserInfoProvider,
{
    /// Realm provider for token validation.
    pub realm_provider: Arc<R>,
    /// User info provider for retrieving user data.
    pub user_info_provider: Arc<U>,
}

impl<R, U> UserInfoEndpointState<R, U>
where
    R: RealmProvider,
    U: UserInfoProvider,
{
    /// Creates a new UserInfo endpoint state.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: moves Arc
    pub fn new(realm_provider: Arc<R>, user_info_provider: Arc<U>) -> Self {
        Self {
            realm_provider,
            user_info_provider,
        }
    }
}

/// `UserInfo` response.
///
/// Contains user claims based on the granted scopes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserInfoResponse {
    /// Subject identifier.
    pub sub: String,

    // === Profile scope claims ===
    /// Full name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Given name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Family name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Middle name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Nickname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// Preferred username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    /// Profile URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Website URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// Gender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    /// Birthdate (YYYY-MM-DD format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,

    /// Timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    /// Locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Last updated timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    // === Email scope claims ===
    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Whether email is verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    // === Phone scope claims ===
    /// Phone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    /// Whether phone number is verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    // === Address scope claims ===
    /// Address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,

    // === Custom claims ===
    /// Additional custom claims.
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// Address claim structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressClaim {
    /// Formatted address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Street address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,

    /// Locality (city).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,

    /// Region (state/province).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Postal code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    /// Country.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// GET `/userinfo`
///
/// Returns user claims for the authenticated user.
///
/// # Authorization
///
/// Requires a valid access token in the Authorization header:
/// - `Authorization: Bearer <access_token>`
///
/// # Responses
///
/// - 200 OK: `UserInfo` JSON
/// - 401 Unauthorized: Invalid or missing token
/// - 403 Forbidden: Insufficient scope
pub async fn userinfo_get<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match handle_userinfo_request(&state, &realm, &headers).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// POST `/userinfo`
///
/// Same as GET but accepts access token in form body.
pub async fn userinfo_post<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // For POST, token can also come from form body, but we simplify to headers only
    match handle_userinfo_request(&state, &realm, &headers).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

// ============================================================================
// Enhanced UserInfo Handlers (with user data provider)
// ============================================================================

/// GET `/userinfo` - Enhanced version with actual user data retrieval.
///
/// This handler retrieves user claims from the storage layer based on
/// the validated access token.
pub async fn userinfo_get_with_provider<R, U>(
    State(state): State<UserInfoEndpointState<R, U>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse
where
    R: RealmProvider + 'static,
    U: UserInfoProvider + 'static,
{
    match handle_userinfo_with_provider(&state, &realm, &headers).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// POST `/userinfo` - Enhanced version with actual user data retrieval.
pub async fn userinfo_post_with_provider<R, U>(
    State(state): State<UserInfoEndpointState<R, U>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse
where
    R: RealmProvider + 'static,
    U: UserInfoProvider + 'static,
{
    match handle_userinfo_with_provider(&state, &realm, &headers).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// Handles the UserInfo request with actual user data retrieval.
async fn handle_userinfo_with_provider<R, U>(
    state: &UserInfoEndpointState<R, U>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<UserInfoResponse, OidcError>
where
    R: RealmProvider,
    U: UserInfoProvider,
{
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Extract and validate access token
    let access_token = extract_bearer_token(headers)?;

    // Validate the access token
    let token_manager = state.realm_provider.get_token_manager(realm).await?;
    let claims = token_manager
        .validate_access_token(&access_token)
        .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

    // Check for openid scope
    let scope = claims.scope.as_deref().unwrap_or("");
    if !scope.contains("openid") {
        return Err(OidcError::InsufficientScope(
            "openid scope is required for userinfo endpoint".to_string(),
        ));
    }

    // Parse the user ID from the subject claim
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| OidcError::InvalidToken("invalid subject in token".to_string()))?;

    // Parse scopes into a list
    let scopes: Vec<&str> = scope.split_whitespace().collect();

    // Retrieve user data from storage
    let user_data = state
        .user_info_provider
        .get_user_info_for_scopes(realm, user_id, &scopes)
        .await?
        .ok_or_else(|| OidcError::InvalidToken("user not found".to_string()))?;

    // Build the response
    Ok(build_userinfo_response(user_data))
}

/// Builds a UserInfoResponse from UserInfoData.
fn build_userinfo_response(data: UserInfoData) -> UserInfoResponse {
    UserInfoResponse {
        sub: data.sub,
        name: data.name,
        given_name: data.given_name,
        family_name: data.family_name,
        middle_name: data.middle_name,
        nickname: data.nickname,
        preferred_username: data.preferred_username,
        profile: data.profile,
        picture: data.picture,
        website: data.website,
        gender: data.gender,
        birthdate: data.birthdate,
        zoneinfo: data.zoneinfo,
        locale: data.locale,
        updated_at: data.updated_at,
        email: data.email,
        email_verified: data.email_verified,
        phone_number: data.phone_number,
        phone_number_verified: data.phone_number_verified,
        address: data.address,
        custom_claims: data.custom_claims,
    }
}

/// Handles the `UserInfo` request.
async fn handle_userinfo_request<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<UserInfoResponse, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Extract and validate access token
    let access_token = extract_bearer_token(headers)?;

    // Validate the access token
    let token_manager = state.realm_provider.get_token_manager(realm).await?;
    let claims = token_manager
        .validate_access_token(&access_token)
        .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

    // Check for openid scope
    let scope = claims.scope.as_deref().unwrap_or("");
    if !scope.contains("openid") {
        return Err(OidcError::InsufficientScope(
            "openid scope is required for userinfo endpoint".to_string(),
        ));
    }

    // Build the `UserInfo` response based on granted scopes
    // TODO: Fetch actual user data from storage
    let mut response = UserInfoResponse {
        sub: claims.sub.clone(),
        ..Default::default()
    };

    // Add claims based on scope
    // In a real implementation, these would come from the user's stored attributes
    if scope.contains("profile") {
        response.preferred_username.clone_from(&claims.preferred_username);
        // Additional profile claims would be fetched from storage
    }

    if scope.contains("email") {
        response.email.clone_from(&claims.email);
        response.email_verified = claims.email_verified;
    }

    // phone and address scopes would similarly fetch from storage

    Ok(response)
}

/// Extracts the Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, OidcError> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| OidcError::InvalidToken("missing authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| OidcError::InvalidToken("invalid authorization header".to_string()))?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .ok_or_else(|| OidcError::InvalidToken("expected Bearer token".to_string()))?;

    if token.is_empty() {
        return Err(OidcError::InvalidToken("empty token".to_string()));
    }

    Ok(token.to_string())
}

/// Converts an `OidcError` to an HTTP response.
fn error_response(err: &OidcError) -> axum::response::Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // For `UserInfo` endpoint, return WWW-Authenticate header on 401
    if status == StatusCode::UNAUTHORIZED {
        let error_response = ErrorResponse {
            error: err.error_code().to_string(),
            error_description: Some(err.to_string()),
            error_uri: None,
        };
        return (
            status,
            [(
                "WWW-Authenticate",
                format!(
                    "Bearer realm=\"userinfo\", error=\"{}\", error_description=\"{}\"",
                    err.error_code(),
                    err.to_string().replace('"', "'")
                ),
            )],
            Json(error_response),
        )
            .into_response();
    }

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

    #[test]
    fn extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test_token_123".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "test_token_123");
    }

    #[test]
    fn extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn extract_bearer_token_not_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dGVzdDp0ZXN0".parse().unwrap());

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn userinfo_response_serialization() {
        let response = UserInfoResponse {
            sub: "user123".to_string(),
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            ..Default::default()
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"sub\":\"user123\""));
        assert!(json.contains("\"email\":\"user@example.com\""));
        assert!(json.contains("\"email_verified\":true"));
        // Ensure None fields are not serialized
        assert!(!json.contains("name"));
    }
}
