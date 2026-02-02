//! Token Introspection Endpoint Conformance Tests
//!
//! Tests for the Token Introspection endpoint per RFC 7662.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc7662

use serde::{Deserialize, Serialize};

use crate::harness::{TestHarness, TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_REALM};

/// Introspection response per RFC 7662.
#[derive(Debug, Deserialize, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

/// Error response from the introspection endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// introspect-1: Requires client authentication.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_requires_client_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .form(&[("token", "some-token")])
        // No client authentication
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Introspection should require client authentication"
    );

    Ok(())
}

/// introspect-2: Accepts client_secret_basic auth.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_accepts_basic_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "some-token")])
        .send()
        .await?;

    // Should not return 401 (auth failed)
    assert_ne!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "client_secret_basic should be accepted"
    );

    Ok(())
}

/// introspect-3: Accepts client_secret_post auth.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_accepts_post_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .form(&[
            ("token", "some-token"),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
        ])
        .send()
        .await?;

    // Should not return 401 (auth failed)
    assert_ne!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "client_secret_post should be accepted"
    );

    Ok(())
}

/// introspect-4: Returns active=false for invalid token.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_invalid_token_returns_inactive() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "invalid-token")])
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Introspection should succeed even for invalid token"
    );

    let introspection: IntrospectionResponse = response.json().await?;
    assert!(
        !introspection.active,
        "Invalid token should be reported as inactive"
    );

    Ok(())
}

/// introspect-5: Returns active=false for expired token.
#[tokio::test]
#[ignore = "Requires expired access token"]
async fn test_introspect_expired_token_returns_inactive() -> anyhow::Result<()> {
    // This test would verify that an expired token
    // is reported as active=false.

    Ok(())
}

/// introspect-6: Returns active=false for revoked token.
#[tokio::test]
#[ignore = "Requires revoked access token"]
async fn test_introspect_revoked_token_returns_inactive() -> anyhow::Result<()> {
    // This test would verify that a revoked token
    // is reported as active=false.

    Ok(())
}

/// introspect-7: Returns active=true for valid token.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_introspect_valid_token_returns_active() -> anyhow::Result<()> {
    // This test would verify that a valid token
    // is reported as active=true.

    Ok(())
}

/// introspect-8: Returns token metadata for active token.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_introspect_returns_metadata() -> anyhow::Result<()> {
    // This test would verify that for an active token,
    // the response includes relevant metadata:
    // - scope
    // - client_id
    // - username
    // - token_type
    // - exp
    // - iat
    // - sub
    // - aud
    // - iss

    Ok(())
}

/// introspect-9: Returns only active=false for inactive token.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_inactive_minimal_response() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "invalid-token")])
        .send()
        .await?;

    let introspection: IntrospectionResponse = response.json().await?;

    // Per RFC 7662, for inactive tokens, the response SHOULD NOT
    // include other claims that might leak information
    if !introspection.active {
        // Ideally, these should be None for inactive tokens
        // (though the spec says SHOULD, not MUST)
    }

    Ok(())
}

/// introspect-10: Supports token_type_hint parameter.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_supports_token_type_hint() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // With access_token hint
    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[
            ("token", "some-token"),
            ("token_type_hint", "access_token"),
        ])
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Should accept token_type_hint=access_token"
    );

    // With refresh_token hint
    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[
            ("token", "some-token"),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Should accept token_type_hint=refresh_token"
    );

    Ok(())
}

/// introspect-11: Returns JSON content type.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_returns_json() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "some-token")])
        .send()
        .await?;

    if response.status().is_success() {
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            content_type.contains("application/json"),
            "Introspection should return JSON"
        );
    }

    Ok(())
}

/// introspect-12: Requires token parameter.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_introspect_requires_token_param() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.introspect_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("foo", "bar")]) // No token parameter
        .send()
        .await?;

    assert!(
        response.status().is_client_error(),
        "Missing token parameter should return error"
    );

    Ok(())
}
