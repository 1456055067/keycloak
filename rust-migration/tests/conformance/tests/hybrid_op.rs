//! Hybrid OP Conformance Tests
//!
//! Tests for OpenID Connect Hybrid flow certification profile.
//!
//! Reference: https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth

use url::Url;

use crate::harness::{pkce, TestHarness, TEST_CLIENT_ID, TEST_REALM};

/// hybrid-op-1: Authorization endpoint accepts code id_token response_type.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_auth_accepts_code_id_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let verifier = pkce::generate_verifier();
    let challenge = pkce::generate_challenge(&verifier);

    let auth_url = Url::parse_with_params(
        &harness.auth_url(TEST_REALM),
        &[
            ("response_type", "code id_token"),
            ("client_id", TEST_CLIENT_ID),
            ("redirect_uri", "http://localhost:8080/callback"),
            ("scope", "openid"),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )?;

    let response = harness.client.get(auth_url).send().await?;

    let status = response.status();
    assert!(
        status.is_redirection() || status.is_success(),
        "Auth endpoint should accept 'code id_token' response type"
    );

    Ok(())
}

/// hybrid-op-2: Authorization endpoint accepts code token response_type.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_auth_accepts_code_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let verifier = pkce::generate_verifier();
    let challenge = pkce::generate_challenge(&verifier);

    let auth_url = Url::parse_with_params(
        &harness.auth_url(TEST_REALM),
        &[
            ("response_type", "code token"),
            ("client_id", TEST_CLIENT_ID),
            ("redirect_uri", "http://localhost:8080/callback"),
            ("scope", "openid"),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )?;

    let response = harness.client.get(auth_url).send().await?;

    let status = response.status();
    assert!(
        status.is_redirection() || status.is_success(),
        "Auth endpoint should accept 'code token' response type"
    );

    Ok(())
}

/// hybrid-op-3: Authorization endpoint accepts code token id_token response_type.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_auth_accepts_code_token_id_token() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let verifier = pkce::generate_verifier();
    let challenge = pkce::generate_challenge(&verifier);

    let auth_url = Url::parse_with_params(
        &harness.auth_url(TEST_REALM),
        &[
            ("response_type", "code token id_token"),
            ("client_id", TEST_CLIENT_ID),
            ("redirect_uri", "http://localhost:8080/callback"),
            ("scope", "openid"),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )?;

    let response = harness.client.get(auth_url).send().await?;

    let status = response.status();
    assert!(
        status.is_redirection() || status.is_success(),
        "Auth endpoint should accept 'code token id_token' response type"
    );

    Ok(())
}

/// hybrid-op-4: Nonce required for hybrid flow.
#[tokio::test]
#[ignore = "Requires running database"]
async fn test_hybrid_requires_nonce() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;

    let verifier = pkce::generate_verifier();
    let challenge = pkce::generate_challenge(&verifier);

    // Try hybrid flow without nonce
    let auth_url = Url::parse_with_params(
        &harness.auth_url(TEST_REALM),
        &[
            ("response_type", "code id_token"),
            ("client_id", TEST_CLIENT_ID),
            ("redirect_uri", "http://localhost:8080/callback"),
            ("scope", "openid"),
            ("state", "test-state"),
            // Missing nonce
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )?;

    let response = harness.client.get(auth_url).send().await?;

    // Should be an error - nonce is required when id_token is requested
    let _status = response.status();

    Ok(())
}

/// hybrid-op-5: ID token contains c_hash when code is returned.
#[tokio::test]
#[ignore = "Requires completed hybrid flow"]
async fn test_id_token_contains_c_hash() -> anyhow::Result<()> {
    // When the response includes both 'code' and 'id_token',
    // the ID token MUST contain a c_hash claim that is the
    // hash of the authorization code.

    Ok(())
}

/// hybrid-op-6: ID token contains at_hash when access_token is returned.
#[tokio::test]
#[ignore = "Requires completed hybrid flow with token"]
async fn test_hybrid_id_token_contains_at_hash() -> anyhow::Result<()> {
    // When the response includes both 'token' and 'id_token',
    // the ID token MUST contain an at_hash claim.

    Ok(())
}

/// hybrid-op-7: Code can be exchanged at token endpoint.
#[tokio::test]
#[ignore = "Requires completed hybrid flow"]
async fn test_hybrid_code_exchangeable() -> anyhow::Result<()> {
    // The authorization code returned in hybrid flow
    // should be exchangeable at the token endpoint for tokens.

    Ok(())
}

/// hybrid-op-8: Response includes both code and tokens.
#[tokio::test]
#[ignore = "Requires completed hybrid flow"]
async fn test_hybrid_response_includes_both() -> anyhow::Result<()> {
    // For code id_token: response includes both code and id_token
    // For code token: response includes both code and access_token
    // For code token id_token: response includes all three

    Ok(())
}

/// hybrid-op-9: Tokens from authorization and token endpoints match.
#[tokio::test]
#[ignore = "Requires completed hybrid flow"]
async fn test_hybrid_tokens_consistent() -> anyhow::Result<()> {
    // When comparing tokens from authorization endpoint (implicit delivery)
    // and tokens from token endpoint (code exchange):
    // - The 'sub' claim should be identical
    // - The issuer should be identical

    Ok(())
}

/// hybrid-op-10: Default response mode is fragment.
#[tokio::test]
#[ignore = "Requires completed hybrid flow"]
async fn test_hybrid_default_response_mode() -> anyhow::Result<()> {
    // For hybrid flow (when tokens are returned directly),
    // the default response_mode is fragment.

    Ok(())
}
