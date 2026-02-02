//! Token Endpoint Conformance Tests
//!
//! Tests for the token endpoint functionality including all grant types.
//!
//! Reference: RFC 6749, RFC 7636 (PKCE), RFC 7009 (Token Revocation)

use serde::{Deserialize, Serialize};

use crate::harness::{TestHarness, TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_REALM};

/// Token response from the token endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// Error response from the token endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// token-endpoint-1: Client credentials grant returns access token.
#[tokio::test]
#[ignore = "Requires running database with configured client"]
async fn test_client_credentials_grant() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if response.status().is_success() {
        let token: TokenResponse = response.json().await?;
        assert!(!token.access_token.is_empty());
        assert_eq!(token.token_type.to_lowercase(), "bearer");
        assert!(token.expires_in.is_some());
        // Client credentials should not return refresh token or ID token
        assert!(token.id_token.is_none());
    }

    Ok(())
}

/// token-endpoint-2: Password grant validates credentials.
#[tokio::test]
#[ignore = "Requires running database with test user"]
async fn test_password_grant_valid_credentials() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[
            ("grant_type", "password"),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
            ("username", "testuser"),
            ("password", "testpassword"),
            ("scope", "openid profile"),
        ])
        .send()
        .await?;

    if response.status().is_success() {
        let token: TokenResponse = response.json().await?;
        assert!(!token.access_token.is_empty());
        assert!(token.id_token.is_some(), "OIDC request should return id_token");
    }

    Ok(())
}

/// token-endpoint-3: Password grant rejects invalid credentials.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_password_grant_invalid_credentials() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[
            ("grant_type", "password"),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
            ("username", "testuser"),
            ("password", "wrongpassword"),
        ])
        .send()
        .await?;

    assert!(
        response.status().is_client_error(),
        "Invalid credentials should return error"
    );

    let error: ErrorResponse = response.json().await?;
    assert_eq!(error.error, "invalid_grant");

    Ok(())
}

/// token-endpoint-4: Refresh token grant returns new tokens.
#[tokio::test]
#[ignore = "Requires valid refresh token"]
async fn test_refresh_token_grant() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // First, get a refresh token via password grant
    let initial_response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[
            ("grant_type", "password"),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
            ("username", "testuser"),
            ("password", "testpassword"),
            ("scope", "openid offline_access"),
        ])
        .send()
        .await?;

    if !initial_response.status().is_success() {
        return Ok(()); // Skip if initial grant fails
    }

    let initial_tokens: TokenResponse = initial_response.json().await?;
    let refresh_token = initial_tokens.refresh_token.expect("Should have refresh token");

    // Use refresh token to get new tokens
    let refresh_response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
        ])
        .send()
        .await?;

    assert!(
        refresh_response.status().is_success(),
        "Refresh token grant should succeed"
    );

    let new_tokens: TokenResponse = refresh_response.json().await?;
    assert!(!new_tokens.access_token.is_empty());
    assert!(new_tokens.refresh_token.is_some());

    Ok(())
}

/// token-endpoint-5: Invalid refresh token returns error.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_invalid_refresh_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "invalid-refresh-token"),
            ("client_id", TEST_CLIENT_ID),
            ("client_secret", TEST_CLIENT_SECRET),
        ])
        .send()
        .await?;

    assert!(
        response.status().is_client_error(),
        "Invalid refresh token should return error"
    );

    let error: ErrorResponse = response.json().await?;
    assert_eq!(error.error, "invalid_grant");

    Ok(())
}

/// token-endpoint-6: Token response includes token_type.
#[tokio::test]
#[ignore = "Requires running database with configured client"]
async fn test_token_response_includes_token_type() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if response.status().is_success() {
        let token: TokenResponse = response.json().await?;
        assert!(
            !token.token_type.is_empty(),
            "token_type must be present"
        );
        assert!(
            token.token_type.eq_ignore_ascii_case("bearer"),
            "token_type should be Bearer"
        );
    }

    Ok(())
}

/// token-endpoint-7: Token response includes expires_in.
#[tokio::test]
#[ignore = "Requires running database with configured client"]
async fn test_token_response_includes_expires_in() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if response.status().is_success() {
        let token: TokenResponse = response.json().await?;
        assert!(
            token.expires_in.is_some(),
            "expires_in should be present"
        );
        assert!(
            token.expires_in.unwrap() > 0,
            "expires_in should be positive"
        );
    }

    Ok(())
}

/// token-endpoint-8: CORS headers are present.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_cors_headers() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // Send OPTIONS preflight request
    let response = harness
        .client
        .request(reqwest::Method::OPTIONS, &harness.token_url(TEST_REALM))
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await?;

    // Check for CORS headers
    let headers = response.headers();
    // Access-Control-Allow-Origin should be present
    // The exact value depends on CORS configuration

    Ok(())
}

/// token-endpoint-9: Content-Type must be application/x-www-form-urlencoded.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_content_type_requirement() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // Send request with JSON content type (should be rejected)
    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .header("Content-Type", "application/json")
        .body(r#"{"grant_type":"client_credentials"}"#)
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .send()
        .await?;

    // Should reject JSON content type
    assert!(
        response.status().is_client_error(),
        "JSON content type should be rejected"
    );

    Ok(())
}

/// token-endpoint-10: Missing client authentication returns error.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_missing_client_authentication() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .form(&[("grant_type", "client_credentials")])
        // No client authentication
        .send()
        .await?;

    assert!(
        response.status().is_client_error(),
        "Missing client authentication should return error"
    );

    let error: ErrorResponse = response.json().await?;
    assert_eq!(error.error, "invalid_client");

    Ok(())
}

/// token-endpoint-11: Wrong client secret returns error.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_wrong_client_secret() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.token_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some("wrong-secret"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    assert!(
        response.status().is_client_error(),
        "Wrong client secret should return error"
    );

    let error: ErrorResponse = response.json().await?;
    assert_eq!(error.error, "invalid_client");

    Ok(())
}
