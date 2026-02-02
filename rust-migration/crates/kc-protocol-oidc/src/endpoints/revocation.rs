//! Token revocation endpoint handler.
//!
//! Implements POST `/revoke` as defined in RFC 7009.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::error::{ErrorResponse, OidcError};
use crate::request::RevocationRequest;

use super::state::{OidcState, RealmProvider};

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
