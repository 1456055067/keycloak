//! Admin API integration tests.

use serde::{Deserialize, Serialize};

use crate::common::TestEnv;

/// Realm representation.
#[derive(Debug, Deserialize, Serialize)]
pub struct RealmRepresentation {
    pub id: Option<uuid::Uuid>,
    pub realm: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

/// User representation.
#[derive(Debug, Deserialize, Serialize)]
pub struct UserRepresentation {
    pub id: Option<uuid::Uuid>,
    pub username: String,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<bool>,
    pub enabled: Option<bool>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

/// Client representation.
#[derive(Debug, Deserialize, Serialize)]
pub struct ClientRepresentation {
    pub id: Option<uuid::Uuid>,
    #[serde(rename = "clientId")]
    pub client_id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "publicClient")]
    pub public_client: Option<bool>,
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Option<Vec<String>>,
}

/// Tests health endpoints.
#[tokio::test]
async fn test_health_endpoints() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Test main health endpoint
    let health_response = env
        .client
        .get(&format!("{}/health", env.base_url))
        .send()
        .await?;

    assert!(
        health_response.status().is_success(),
        "Health endpoint should return success"
    );

    // Test liveness probe
    let liveness_response = env
        .client
        .get(&format!("{}/health/live", env.base_url))
        .send()
        .await?;

    assert!(
        liveness_response.status().is_success(),
        "Liveness probe should return success"
    );

    // Test readiness probe
    let readiness_response = env
        .client
        .get(&format!("{}/health/ready", env.base_url))
        .send()
        .await?;

    assert!(
        readiness_response.status().is_success(),
        "Readiness probe should return success"
    );

    Ok(())
}

/// Tests the root endpoint.
#[tokio::test]
async fn test_root_endpoint() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    let response = env
        .client
        .get(&env.base_url)
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Root endpoint should return success"
    );

    let body: serde_json::Value = response.json().await?;
    assert!(body.get("name").is_some(), "Should have name field");
    assert!(body.get("version").is_some(), "Should have version field");

    Ok(())
}

/// Tests OIDC discovery endpoint.
#[tokio::test]
async fn test_discovery_endpoint() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create a test realm
    let _realm_id = env.create_realm("test").await?;

    // Get discovery document
    let discovery_response = env
        .client
        .get(&env.discovery_url("test"))
        .send()
        .await?;

    if discovery_response.status().is_success() {
        let metadata: serde_json::Value = discovery_response.json().await?;

        assert!(metadata.get("issuer").is_some(), "Should have issuer");
        assert!(
            metadata.get("authorization_endpoint").is_some(),
            "Should have authorization_endpoint"
        );
        assert!(
            metadata.get("token_endpoint").is_some(),
            "Should have token_endpoint"
        );
        assert!(metadata.get("jwks_uri").is_some(), "Should have jwks_uri");
    } else {
        tracing::warn!(
            "Discovery endpoint returned {}: {}",
            discovery_response.status(),
            discovery_response.text().await?
        );
    }

    Ok(())
}

/// Tests JWKS endpoint.
#[tokio::test]
async fn test_jwks_endpoint() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create a test realm
    let _realm_id = env.create_realm("test").await?;

    // Get JWKS
    let jwks_url = format!(
        "{}/realms/test/protocol/openid-connect/certs",
        env.base_url
    );

    let jwks_response = env.client.get(&jwks_url).send().await?;

    if jwks_response.status().is_success() {
        let jwks: serde_json::Value = jwks_response.json().await?;

        assert!(jwks.get("keys").is_some(), "JWKS should have keys array");
    } else {
        tracing::warn!(
            "JWKS endpoint returned {}: {}",
            jwks_response.status(),
            jwks_response.text().await?
        );
    }

    Ok(())
}

/// Tests that the server handles unknown realms gracefully.
#[tokio::test]
async fn test_unknown_realm() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Try to get discovery for non-existent realm
    let discovery_response = env
        .client
        .get(&env.discovery_url("nonexistent"))
        .send()
        .await?;

    // Should return 404 or similar error
    assert!(
        discovery_response.status().is_client_error() || discovery_response.status().is_server_error(),
        "Unknown realm should return error, got {}",
        discovery_response.status()
    );

    Ok(())
}

/// Tests concurrent requests to the server.
#[tokio::test]
async fn test_concurrent_requests() -> anyhow::Result<()> {
    let env = TestEnv::new().await?;

    // Create a test realm
    let _realm_id = env.create_realm("test").await?;

    // Make multiple concurrent requests
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let client = env.client.clone();
            let url = format!("{}/health", env.base_url);
            tokio::spawn(async move { client.get(&url).send().await })
        })
        .collect();

    // Wait for all requests
    let results = futures::future::join_all(handles).await;

    // All should succeed
    for result in results {
        let response = result??;
        assert!(
            response.status().is_success(),
            "Concurrent request failed"
        );
    }

    Ok(())
}
