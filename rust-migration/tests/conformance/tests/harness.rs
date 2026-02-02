//! Test harness for OIDC conformance testing.
//!
//! This module provides utilities for setting up and running
//! the Keycloak server in a test environment.

use std::net::TcpListener;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::oneshot;
use tokio::time::sleep;

use kc_server::{Server, ServerConfig};

/// Test harness that manages a running server instance.
pub struct TestHarness {
    /// Base URL of the running server.
    pub base_url: String,
    /// HTTP client configured for testing.
    pub client: Client,
    /// Shutdown signal sender.
    _shutdown_tx: oneshot::Sender<()>,
}

impl TestHarness {
    /// Creates a new test harness with a running server.
    ///
    /// The server is started on a random available port.
    pub async fn new() -> anyhow::Result<Self> {
        // Find an available port
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener); // Release the port for the server

        let base_url = format!("http://127.0.0.1:{port}");

        // Create server config
        let mut config = ServerConfig::for_testing(&test_database_url());
        config.host = "127.0.0.1".to_string();
        config.port = port;
        config.base_url = base_url.clone();

        // Create shutdown channel
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start server in background
        let server = Server::new(config).await?;
        tokio::spawn(async move {
            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                        tracing::error!("Server error: {}", e);
                    }
                }
                _ = shutdown_rx => {
                    tracing::info!("Server shutdown requested");
                }
            }
        });

        // Wait for server to be ready
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .cookie_store(true)
            .build()?;

        wait_for_server(&client, &base_url).await?;

        Ok(Self {
            base_url,
            client,
            _shutdown_tx,
        })
    }

    /// Returns the discovery endpoint URL for a realm.
    pub fn discovery_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/.well-known/openid-configuration",
            self.base_url, realm
        )
    }

    /// Returns the authorization endpoint URL for a realm.
    pub fn auth_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/auth",
            self.base_url, realm
        )
    }

    /// Returns the token endpoint URL for a realm.
    pub fn token_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.base_url, realm
        )
    }

    /// Returns the userinfo endpoint URL for a realm.
    pub fn userinfo_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/userinfo",
            self.base_url, realm
        )
    }

    /// Returns the JWKS endpoint URL for a realm.
    pub fn jwks_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/certs",
            self.base_url, realm
        )
    }

    /// Returns the introspection endpoint URL for a realm.
    pub fn introspect_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token/introspect",
            self.base_url, realm
        )
    }

    /// Returns the revocation endpoint URL for a realm.
    pub fn revoke_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/revoke",
            self.base_url, realm
        )
    }
}

/// Returns the test database URL.
fn test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:postgres@localhost:5432/keycloak_test".to_string()
    })
}

/// Waits for the server to be ready.
async fn wait_for_server(client: &Client, base_url: &str) -> anyhow::Result<()> {
    let health_url = format!("{base_url}/health");
    let max_attempts = 30;

    for attempt in 1..=max_attempts {
        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Server ready after {} attempts", attempt);
                return Ok(());
            }
            Ok(response) => {
                tracing::debug!(
                    "Server not ready (status {}), attempt {}/{}",
                    response.status(),
                    attempt,
                    max_attempts
                );
            }
            Err(e) => {
                tracing::debug!(
                    "Server not ready ({}), attempt {}/{}",
                    e,
                    attempt,
                    max_attempts
                );
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Server did not become ready in time")
}

/// Standard test realm name.
pub const TEST_REALM: &str = "test";

/// Standard test client ID.
pub const TEST_CLIENT_ID: &str = "test-client";

/// Standard test client secret.
pub const TEST_CLIENT_SECRET: &str = "test-secret";

/// Standard test user.
pub const TEST_USERNAME: &str = "testuser";
pub const TEST_PASSWORD: &str = "testpassword";

/// PKCE challenge for tests.
pub mod pkce {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};

    /// Generates a PKCE code verifier.
    pub fn generate_verifier() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::rng().random();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generates a PKCE code challenge from a verifier.
    pub fn generate_challenge(verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        URL_SAFE_NO_PAD.encode(hash)
    }
}

/// JWT decoding utilities for tests.
pub mod jwt {
    use serde::de::DeserializeOwned;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    /// Decodes a JWT payload without verification (for testing only).
    pub fn decode_payload_unverified<T: DeserializeOwned>(token: &str) -> anyhow::Result<T> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format");
        }

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let payload: T = serde_json::from_slice(&payload_bytes)?;
        Ok(payload)
    }

    /// Extracts the header from a JWT without verification.
    pub fn decode_header_unverified(token: &str) -> anyhow::Result<serde_json::Value> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format");
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
        Ok(header)
    }
}
