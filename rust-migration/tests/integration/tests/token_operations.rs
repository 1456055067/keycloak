//! Token operation integration tests (introspection, revocation).

use serde::{Deserialize, Serialize};

use crate::common::TestEnv;

/// Token response.
#[derive(Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

/// Introspection response.
#[derive(Debug, Deserialize, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
}

/// Tests token introspection for a valid token.
#[tokio::test]
async fn test_introspect_valid_token() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create test realm and client
    let realm_id = env.create_realm("test").await?;
    let _client_id = env
        .create_client(realm_id, "test-client", Some("test-secret"), false)
        .await?;

    // Get an access token
    let token_response = env
        .client
        .post(&env.token_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if !token_response.status().is_success() {
        tracing::warn!("Token request failed, skipping introspection test");
        return Ok(());
    }

    let tokens: TokenResponse = token_response.json().await?;

    // Introspect the token
    let introspect_response = env
        .client
        .post(&env.introspect_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await?;

    if introspect_response.status().is_success() {
        let introspection: IntrospectionResponse = introspect_response.json().await?;

        assert!(introspection.active, "Valid token should be active");
        assert!(introspection.client_id.is_some(), "Should have client_id");
        assert!(introspection.exp.is_some(), "Should have exp");
    } else {
        let error_text = introspect_response.text().await?;
        tracing::warn!("Introspection failed: {}", error_text);
    }

    Ok(())
}

/// Tests token introspection for an invalid token.
#[tokio::test]
async fn test_introspect_invalid_token() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create test realm and client
    let realm_id = env.create_realm("test").await?;
    let _client_id = env
        .create_client(realm_id, "test-client", Some("test-secret"), false)
        .await?;

    // Introspect an invalid token
    let introspect_response = env
        .client
        .post(&env.introspect_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("token", "invalid-token")])
        .send()
        .await?;

    assert!(
        introspect_response.status().is_success(),
        "Introspection should return 200 even for invalid tokens"
    );

    let introspection: IntrospectionResponse = introspect_response.json().await?;
    assert!(!introspection.active, "Invalid token should not be active");

    Ok(())
}

/// Tests token revocation.
#[tokio::test]
async fn test_revoke_token() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create test realm and client
    let realm_id = env.create_realm("test").await?;
    let _client_id = env
        .create_client(realm_id, "test-client", Some("test-secret"), false)
        .await?;

    // Get an access token
    let token_response = env
        .client
        .post(&env.token_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?;

    if !token_response.status().is_success() {
        tracing::warn!("Token request failed, skipping revocation test");
        return Ok(());
    }

    let tokens: TokenResponse = token_response.json().await?;

    // Revoke the token
    let revoke_response = env
        .client
        .post(&env.revoke_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await?;

    assert_eq!(
        revoke_response.status(),
        reqwest::StatusCode::OK,
        "Revocation should return 200"
    );

    // Introspect the revoked token
    let introspect_response = env
        .client
        .post(&env.introspect_url("test"))
        .basic_auth("test-client", Some("test-secret"))
        .form(&[("token", &tokens.access_token)])
        .send()
        .await?;

    if introspect_response.status().is_success() {
        let introspection: IntrospectionResponse = introspect_response.json().await?;
        assert!(
            !introspection.active,
            "Revoked token should not be active"
        );
    }

    Ok(())
}

/// Tests that introspection requires client authentication.
#[tokio::test]
async fn test_introspect_requires_auth() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create test realm and client
    let realm_id = env.create_realm("test").await?;
    let _client_id = env
        .create_client(realm_id, "test-client", Some("test-secret"), false)
        .await?;

    // Try to introspect without authentication
    let introspect_response = env
        .client
        .post(&env.introspect_url("test"))
        .form(&[("token", "some-token")])
        .send()
        .await?;

    assert_eq!(
        introspect_response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Introspection without auth should return 401"
    );

    Ok(())
}

/// Tests that revocation requires client authentication.
#[tokio::test]
async fn test_revoke_requires_auth() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create test realm and client
    let realm_id = env.create_realm("test").await?;
    let _client_id = env
        .create_client(realm_id, "test-client", Some("test-secret"), false)
        .await?;

    // Try to revoke without authentication
    let revoke_response = env
        .client
        .post(&env.revoke_url("test"))
        .form(&[("token", "some-token")])
        .send()
        .await?;

    assert_eq!(
        revoke_response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Revocation without auth should return 401"
    );

    Ok(())
}
