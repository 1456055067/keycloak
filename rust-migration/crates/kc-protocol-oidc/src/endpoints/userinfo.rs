//! `UserInfo` endpoint handler.
//!
//! Implements GET/POST `/userinfo` for returning user claims.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{ErrorResponse, OidcError};

use super::state::{OidcState, RealmProvider};

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
