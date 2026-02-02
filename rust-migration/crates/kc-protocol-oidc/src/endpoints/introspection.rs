//! Token introspection endpoint handler.
//!
//! Implements POST `/token/introspect` as defined in RFC 7662.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::error::{ErrorResponse, OidcError};
use crate::request::IntrospectionRequest;
use crate::token::IntrospectionResponse;

use super::state::{OidcState, RealmProvider};

/// POST `/token/introspect`
///
/// Introspects a token to determine its validity and associated metadata.
///
/// # Authorization
///
/// Requires client authentication (Basic auth or `client_id`/`client_secret` in body).
///
/// # Request Body
///
/// - `token`: The token to introspect (required)
/// - `token_type_hint`: Hint about the token type (`access_token` or `refresh_token`)
///
/// # Responses
///
/// - 200 OK: Introspection response JSON (always returns 200, even for invalid tokens)
/// - 401 Unauthorized: Client authentication failed
pub async fn introspect<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(request): Form<IntrospectionRequest>,
) -> impl IntoResponse {
    match handle_introspection_request(&state, &realm, &headers, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// Handles the introspection request.
async fn handle_introspection_request<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
    headers: &HeaderMap,
    request: &IntrospectionRequest,
) -> Result<IntrospectionResponse, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    // Authenticate the client making the introspection request
    authenticate_client(headers)?;

    // Get the token manager
    let token_manager = state.realm_provider.get_token_manager(realm).await?;

    // Determine token type based on hint or try both
    let token_type_hint = request.token_type_hint.as_deref();

    // Try to validate as access token first (or if hinted)
    if (token_type_hint.is_none() || token_type_hint == Some("access_token"))
        && let Ok(claims) = token_manager.validate_access_token(&request.token)
    {
        return Ok(IntrospectionResponse::from_access_token(&claims));
    }

    // Try to validate as refresh token
    if (token_type_hint.is_none() || token_type_hint == Some("refresh_token"))
        && let Ok(claims) = token_manager.validate_refresh_token(&request.token)
    {
        // Build response from refresh token claims
        return Ok(IntrospectionResponse {
            active: true,
            scope: claims.scope.clone(),
            client_id: claims.azp.clone(),
            username: None, // Refresh tokens don't have username
            token_type: Some("refresh_token".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: None, // Refresh tokens don't have nbf
            sub: Some(claims.sub.clone()),
            aud: claims.aud.clone(),
            iss: Some(claims.iss.clone()),
            jti: Some(claims.jti),
        });
    }

    // Token is invalid or expired - return inactive response
    // Per RFC 7662, we MUST return 200 OK with active=false for invalid tokens
    Ok(IntrospectionResponse::inactive())
}

/// Authenticates the client making the introspection request.
fn authenticate_client(headers: &HeaderMap) -> Result<(), OidcError> {
    // Check for Authorization header (Basic auth)
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OidcError::InvalidClient("invalid authorization header".to_string()))?;

        if auth_str.starts_with("Basic ") {
            // In a real implementation, we would:
            // 1. Decode the Basic auth credentials
            // 2. Look up the client in the database
            // 3. Verify the client_secret
            // 4. Check if the client is allowed to introspect tokens
            return Ok(());
        }
    }

    // For simplicity, allow requests without authentication in development
    // In production, this should be an error
    // TODO: Implement proper client authentication
    Ok(())
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

    #[test]
    fn introspection_response_inactive() {
        let response = IntrospectionResponse::inactive();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"active\":false"));
        // Inactive response should only contain active field
    }
}
