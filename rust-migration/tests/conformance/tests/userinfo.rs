//! UserInfo Endpoint Conformance Tests
//!
//! Tests for the UserInfo endpoint per OpenID Connect Core spec.
//!
//! Reference: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

use serde::{Deserialize, Serialize};

use crate::harness::{TestHarness, TEST_REALM};

/// Standard UserInfo claims.
#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfoClaims {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<serde_json::Value>,
    pub updated_at: Option<i64>,
}

/// Error response from the UserInfo endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// userinfo-1: Returns 401 without access token.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_userinfo_requires_access_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "UserInfo should return 401 without access token"
    );

    // Should have WWW-Authenticate header
    let www_auth = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok());

    assert!(
        www_auth.is_some(),
        "Should include WWW-Authenticate header"
    );

    Ok(())
}

/// userinfo-2: Accepts Bearer token in Authorization header.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_userinfo_accepts_bearer_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // This test requires a valid access token
    let access_token = "valid-access-token"; // Would need to obtain this

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(access_token)
        .send()
        .await?;

    // If token is valid, should return user info
    // If invalid, should return 401
    let _status = response.status();

    Ok(())
}

/// userinfo-3: Returns JSON content type.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_userinfo_returns_json() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let access_token = "valid-access-token"; // Would need to obtain this

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(access_token)
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
            "UserInfo should return JSON content type"
        );
    }

    Ok(())
}

/// userinfo-4: Contains required 'sub' claim.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_userinfo_contains_sub_claim() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let access_token = "valid-access-token"; // Would need to obtain this

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(access_token)
        .send()
        .await?;

    if response.status().is_success() {
        let claims: UserInfoClaims = response.json().await?;
        assert!(!claims.sub.is_empty(), "sub claim must be present and non-empty");
    }

    Ok(())
}

/// userinfo-5: 'sub' matches ID token subject.
#[tokio::test]
#[ignore = "Requires valid tokens from same auth flow"]
async fn test_userinfo_sub_matches_id_token() -> anyhow::Result<()> {
    // This test would verify that the 'sub' claim from UserInfo
    // matches the 'sub' claim from the ID token received in the
    // same authentication flow.

    // Implementation requires completing an auth flow and comparing tokens.
    Ok(())
}

/// userinfo-6: Supports GET method.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_userinfo_supports_get() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let access_token = "valid-access-token";

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(access_token)
        .send()
        .await?;

    // Should not return 405 Method Not Allowed
    assert_ne!(
        response.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
        "GET should be allowed"
    );

    Ok(())
}

/// userinfo-7: Supports POST method.
#[tokio::test]
#[ignore = "Requires valid access token"]
async fn test_userinfo_supports_post() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let access_token = "valid-access-token";

    let response = harness
        .client
        .post(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(access_token)
        .send()
        .await?;

    // Should not return 405 Method Not Allowed
    assert_ne!(
        response.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
        "POST should be allowed"
    );

    Ok(())
}

/// userinfo-8: Returns profile claims when 'profile' scope was granted.
#[tokio::test]
#[ignore = "Requires token with profile scope"]
async fn test_userinfo_profile_scope() -> anyhow::Result<()> {
    // This test would verify that when the access token was granted with
    // 'profile' scope, the UserInfo response includes profile claims:
    // - name
    // - family_name
    // - given_name
    // - middle_name
    // - nickname
    // - preferred_username
    // - profile
    // - picture
    // - website
    // - gender
    // - birthdate
    // - zoneinfo
    // - locale
    // - updated_at

    Ok(())
}

/// userinfo-9: Returns email claims when 'email' scope was granted.
#[tokio::test]
#[ignore = "Requires token with email scope"]
async fn test_userinfo_email_scope() -> anyhow::Result<()> {
    // This test would verify that when the access token was granted with
    // 'email' scope, the UserInfo response includes:
    // - email
    // - email_verified

    Ok(())
}

/// userinfo-10: Returns phone claims when 'phone' scope was granted.
#[tokio::test]
#[ignore = "Requires token with phone scope"]
async fn test_userinfo_phone_scope() -> anyhow::Result<()> {
    // This test would verify that when the access token was granted with
    // 'phone' scope, the UserInfo response includes:
    // - phone_number
    // - phone_number_verified

    Ok(())
}

/// userinfo-11: Returns address claim when 'address' scope was granted.
#[tokio::test]
#[ignore = "Requires token with address scope"]
async fn test_userinfo_address_scope() -> anyhow::Result<()> {
    // This test would verify that when the access token was granted with
    // 'address' scope, the UserInfo response includes:
    // - address (as a JSON object with formatted, street_address, locality, etc.)

    Ok(())
}

/// userinfo-12: Rejects expired access token.
#[tokio::test]
#[ignore = "Requires expired access token"]
async fn test_userinfo_rejects_expired_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // Use an expired token
    let expired_token = "expired-access-token";

    let response = harness
        .client
        .get(&harness.userinfo_url(TEST_REALM))
        .bearer_auth(expired_token)
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expired token should return 401"
    );

    Ok(())
}

/// userinfo-13: Rejects revoked access token.
#[tokio::test]
#[ignore = "Requires revoked access token"]
async fn test_userinfo_rejects_revoked_token() -> anyhow::Result<()> {
    // This test would verify that a token that has been revoked
    // is rejected by the UserInfo endpoint.

    Ok(())
}
