//! Config OP (Discovery) Conformance Tests
//!
//! Tests for OpenID Provider Configuration (Discovery).
//! These tests validate that the discovery endpoint returns
//! proper OIDC Provider Metadata.
//!
//! Reference: https://openid.net/specs/openid-connect-discovery-1_0.html

use serde::{Deserialize, Serialize};

use crate::harness::{TestHarness, TEST_REALM};

/// OpenID Provider Metadata as defined in the OIDC Discovery spec.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub acr_values_supported: Option<Vec<String>>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub display_values_supported: Option<Vec<String>>,
    pub claim_types_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<String>>,
    pub service_documentation: Option<String>,
    pub claims_locales_supported: Option<Vec<String>>,
    pub ui_locales_supported: Option<Vec<String>>,
    pub claims_parameter_supported: Option<bool>,
    pub request_parameter_supported: Option<bool>,
    pub request_uri_parameter_supported: Option<bool>,
    pub require_request_uri_registration: Option<bool>,
    pub op_policy_uri: Option<String>,
    pub op_tos_uri: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint: Option<String>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// oidc-provider-config-1: Discovery endpoint returns valid JSON.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_discovery_returns_valid_json() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Discovery endpoint should return success"
    );

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("application/json"),
        "Content-Type should be application/json"
    );

    // Verify it parses as valid provider metadata
    let metadata: ProviderMetadata = response.json().await?;
    assert!(!metadata.issuer.is_empty(), "issuer must be present");

    Ok(())
}

/// oidc-provider-config-2: Issuer matches the discovery URL.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_issuer_matches_discovery_url() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let discovery_url = harness.discovery_url(TEST_REALM);
    let response = harness.client.get(&discovery_url).send().await?;
    let metadata: ProviderMetadata = response.json().await?;

    // The issuer should be the discovery URL without the well-known suffix
    let expected_issuer = discovery_url
        .strip_suffix("/.well-known/openid-configuration")
        .unwrap();

    assert_eq!(
        metadata.issuer, expected_issuer,
        "Issuer must match the discovery URL base"
    );

    Ok(())
}

/// oidc-provider-config-3: Required endpoints are present.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_required_endpoints_present() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    // Required fields per OIDC Core spec
    assert!(
        !metadata.authorization_endpoint.is_empty(),
        "authorization_endpoint required"
    );
    assert!(
        !metadata.token_endpoint.is_empty(),
        "token_endpoint required"
    );
    assert!(!metadata.jwks_uri.is_empty(), "jwks_uri required");
    assert!(
        !metadata.response_types_supported.is_empty(),
        "response_types_supported required"
    );
    assert!(
        !metadata.subject_types_supported.is_empty(),
        "subject_types_supported required"
    );
    assert!(
        !metadata.id_token_signing_alg_values_supported.is_empty(),
        "id_token_signing_alg_values_supported required"
    );

    Ok(())
}

/// oidc-provider-config-4: Response types include "code".
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_code_response_type_supported() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    assert!(
        metadata.response_types_supported.contains(&"code".to_string()),
        "response_types_supported must include 'code' for Basic OP"
    );

    Ok(())
}

/// oidc-provider-config-5: Subject types include "public".
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_public_subject_type_supported() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    assert!(
        metadata.subject_types_supported.contains(&"public".to_string()),
        "subject_types_supported must include 'public'"
    );

    Ok(())
}

/// oidc-provider-config-6: ID token signing algorithms are secure.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_secure_id_token_signing_algorithms() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    // Per CNSA 2.0 compliance, we should support ES384, ES512, PS384, PS512, RS384, RS512
    // And NOT support ES256, RS256, PS256
    let weak_algs = ["ES256", "RS256", "PS256", "HS256", "HS384", "HS512", "none"];

    for alg in &weak_algs {
        assert!(
            !metadata
                .id_token_signing_alg_values_supported
                .contains(&alg.to_string()),
            "Should not support weak algorithm: {}",
            alg
        );
    }

    // Should support at least one CNSA 2.0 compliant algorithm
    let strong_algs = ["ES384", "ES512", "PS384", "PS512", "RS384", "RS512"];
    let has_strong_alg = strong_algs.iter().any(|alg| {
        metadata
            .id_token_signing_alg_values_supported
            .contains(&alg.to_string())
    });

    assert!(has_strong_alg, "Must support at least one CNSA 2.0 compliant signing algorithm");

    Ok(())
}

/// oidc-provider-config-7: PKCE support is advertised.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_pkce_support_advertised() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    // code_challenge_methods_supported should include S256
    if let Some(methods) = &metadata.code_challenge_methods_supported {
        assert!(
            methods.contains(&"S256".to_string()),
            "code_challenge_methods_supported should include S256"
        );
    }

    Ok(())
}

/// oidc-provider-config-8: Grant types supported are valid.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_grant_types_supported() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    if let Some(grant_types) = &metadata.grant_types_supported {
        // Should support authorization_code
        assert!(
            grant_types.contains(&"authorization_code".to_string()),
            "grant_types_supported should include authorization_code"
        );

        // Should support refresh_token
        assert!(
            grant_types.contains(&"refresh_token".to_string()),
            "grant_types_supported should include refresh_token"
        );
    }

    Ok(())
}

/// oidc-provider-config-9: Token endpoint auth methods are secure.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_token_auth_methods_supported() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    if let Some(methods) = &metadata.token_endpoint_auth_methods_supported {
        // Should support at least client_secret_basic or client_secret_post
        let has_basic_auth = methods.contains(&"client_secret_basic".to_string())
            || methods.contains(&"client_secret_post".to_string());

        assert!(
            has_basic_auth,
            "Should support client_secret_basic or client_secret_post"
        );
    }

    Ok(())
}

/// oidc-provider-config-10: JWKS endpoint is accessible.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_jwks_endpoint_accessible() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    // First get the JWKS URI from discovery
    let response = harness
        .client
        .get(&harness.discovery_url(TEST_REALM))
        .send()
        .await?;
    let metadata: ProviderMetadata = response.json().await?;

    // Then verify the JWKS endpoint is accessible
    let jwks_response = harness.client.get(&metadata.jwks_uri).send().await?;

    assert!(
        jwks_response.status().is_success(),
        "JWKS endpoint should be accessible"
    );

    let jwks: serde_json::Value = jwks_response.json().await?;
    assert!(
        jwks.get("keys").is_some(),
        "JWKS response must contain 'keys' array"
    );

    Ok(())
}
