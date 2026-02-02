//! Token Revocation Endpoint Conformance Tests
//!
//! Tests for the Token Revocation endpoint per RFC 7009.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc7009

use crate::harness::{TestHarness, TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_REALM};

/// revoke-1: Requires client authentication.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_requires_client_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
        .form(&[("token", "some-token")])
        // No client authentication
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Revocation should require client authentication"
    );

    Ok(())
}

/// revoke-2: Accepts client_secret_basic auth.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_accepts_basic_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
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

/// revoke-3: Accepts client_secret_post auth.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_accepts_post_auth() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
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

/// revoke-4: Returns 200 OK for successful revocation.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_revoke_returns_200_on_success() -> anyhow::Result<()> {
    // This test would verify that revoking a valid token returns 200 OK.

    Ok(())
}

/// revoke-5: Returns 200 OK even for invalid token.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_returns_200_for_invalid_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "invalid-token")])
        .send()
        .await?;

    // Per RFC 7009: "The authorization server responds with HTTP status
    // code 200 if the token has been revoked successfully or if the
    // client submitted an invalid token."
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Revocation should return 200 even for invalid token"
    );

    Ok(())
}

/// revoke-6: Revoked access token becomes invalid.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_revoked_access_token_becomes_invalid() -> anyhow::Result<()> {
    // This test would:
    // 1. Obtain an access token
    // 2. Verify it works (e.g., call UserInfo)
    // 3. Revoke the token
    // 4. Verify the token no longer works

    Ok(())
}

/// revoke-7: Revoked refresh token becomes invalid.
#[tokio::test]
#[ignore = "Requires valid refresh token"]
async fn test_revoked_refresh_token_becomes_invalid() -> anyhow::Result<()> {
    // This test would:
    // 1. Obtain a refresh token
    // 2. Revoke the refresh token
    // 3. Verify that using it for refresh returns an error

    Ok(())
}

/// revoke-8: Revoking refresh token may revoke associated access tokens.
#[tokio::test]
#[ignore = "Requires valid token pair"]
async fn test_revoke_refresh_may_revoke_access() -> anyhow::Result<()> {
    // This test would verify behavior when revoking a refresh token:
    // - The refresh token becomes invalid
    // - Associated access tokens may also be invalidated (implementation choice)

    Ok(())
}

/// revoke-9: Supports token_type_hint parameter.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_supports_token_type_hint() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // With access_token hint
    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[
            ("token", "some-token"),
            ("token_type_hint", "access_token"),
        ])
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Should accept token_type_hint=access_token"
    );

    // With refresh_token hint
    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[
            ("token", "some-token"),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Should accept token_type_hint=refresh_token"
    );

    Ok(())
}

/// revoke-10: Requires token parameter.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_requires_token_param() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
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

/// revoke-11: Client can only revoke its own tokens.
#[tokio::test]
#[ignore = "Requires tokens from different clients"]
async fn test_revoke_only_own_tokens() -> anyhow::Result<()> {
    // This test would verify that a client cannot revoke tokens
    // issued to a different client.
    //
    // The expected behavior is:
    // - Either reject with an error (more informative but may leak info)
    // - Or return 200 but not actually revoke (per RFC 7009 security considerations)

    Ok(())
}

/// revoke-12: No response body on success.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_revoke_empty_response_body() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .post(&harness.revoke_url(TEST_REALM))
        .basic_auth(TEST_CLIENT_ID, Some(TEST_CLIENT_SECRET))
        .form(&[("token", "some-token")])
        .send()
        .await?;

    if response.status().is_success() {
        let body = response.text().await?;
        // Body should be empty or minimal
        assert!(
            body.is_empty() || body.trim().is_empty(),
            "Successful revocation should have empty response body"
        );
    }

    Ok(())
}
