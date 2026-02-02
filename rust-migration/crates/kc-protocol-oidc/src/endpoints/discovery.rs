//! Discovery endpoint handlers.
//!
//! Implements:
//! - GET `/.well-known/openid-configuration` - `OpenID` Provider Metadata
//! - GET `/certs` - JSON Web Key Set

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::discovery::ProviderMetadata;
use crate::error::{ErrorResponse, OidcError};
use crate::jwks::JsonWebKeySet;

use super::state::{OidcState, RealmProvider};

/// GET `/.well-known/openid-configuration`
///
/// Returns the `OpenID` Provider Metadata for the realm.
///
/// # Responses
///
/// - 200 OK: Provider metadata JSON
/// - 404 Not Found: Realm does not exist
/// - 500 Internal Server Error: Server error
pub async fn well_known<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    match get_provider_metadata(&state, &realm).await {
        Ok(metadata) => (StatusCode::OK, Json(metadata)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// GET `/certs`
///
/// Returns the JSON Web Key Set for the realm.
///
/// # Responses
///
/// - 200 OK: JWKS JSON
/// - 404 Not Found: Realm does not exist
/// - 500 Internal Server Error: Server error
pub async fn jwks<R: RealmProvider>(
    State(state): State<OidcState<R>>,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    match get_jwks(&state, &realm).await {
        Ok(jwks) => (StatusCode::OK, Json(jwks)).into_response(),
        Err(ref err) => error_response(err),
    }
}

/// Gets provider metadata for a realm.
async fn get_provider_metadata<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
) -> Result<ProviderMetadata, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    state.realm_provider.get_provider_metadata(realm).await
}

/// Gets JWKS for a realm.
async fn get_jwks<R: RealmProvider>(
    state: &OidcState<R>,
    realm: &str,
) -> Result<JsonWebKeySet, OidcError> {
    // Check if realm exists
    if !state.realm_provider.realm_exists(realm).await? {
        return Err(OidcError::InvalidRequest(format!(
            "realm '{realm}' does not exist"
        )));
    }

    state.realm_provider.get_jwks(realm).await
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

    // Tests would require mocking the RealmProvider trait
    // which is better done in integration tests

    #[test]
    fn error_response_status_codes() {
        let err = OidcError::InvalidRequest("test".to_string());
        assert_eq!(err.http_status(), 400);

        let err = OidcError::InvalidClient("test".to_string());
        assert_eq!(err.http_status(), 401);

        let err = OidcError::ServerError("test".to_string());
        assert_eq!(err.http_status(), 500);
    }
}
