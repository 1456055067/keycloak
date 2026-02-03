//! Command implementations.

pub mod client;
pub mod config;
pub mod crypto;
pub mod export;
pub mod group;
pub mod import;
pub mod realm;
pub mod role;
pub mod status;
pub mod user;

pub use config::run_config;
pub use crypto::run_crypto;
pub use export::run_export;
pub use import::run_import;
pub use realm::run_realm;
pub use status::run_status;
pub use user::run_user;
pub use client::run_client;
pub use role::run_role;
pub use group::run_group;

use crate::CliConfig;

/// API client for making requests to the Keycloak server.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    /// Creates a new API client.
    pub fn new(config: &CliConfig, server_override: Option<&str>) -> crate::CliResult<Self> {
        let base_url = server_override
            .map(|s| s.to_string())
            .unwrap_or_else(|| config.server_url.clone());

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self { client, base_url })
    }

    /// Makes a GET request.
    pub async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> crate::CliResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.get(&url).send().await?;
        handle_response(response).await
    }

    /// Makes a POST request.
    pub async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> crate::CliResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.post(&url).json(body).send().await?;
        handle_response(response).await
    }

    /// Makes a POST request without response body.
    pub async fn post_no_response<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> crate::CliResult<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.post(&url).json(body).send().await?;
        handle_empty_response(response).await
    }

    /// Makes a PUT request.
    pub async fn put<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> crate::CliResult<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.put(&url).json(body).send().await?;
        handle_empty_response(response).await
    }

    /// Makes a DELETE request.
    pub async fn delete(&self, path: &str) -> crate::CliResult<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.delete(&url).send().await?;
        handle_empty_response(response).await
    }

    /// Gets the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// Handles a response with a body.
async fn handle_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> crate::CliResult<T> {
    let status = response.status();

    if status.is_success() {
        response.json().await.map_err(crate::CliError::Http)
    } else {
        let message = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Err(crate::CliError::Api {
            status: status.as_u16(),
            message,
        })
    }
}

/// Handles a response without a body.
async fn handle_empty_response(response: reqwest::Response) -> crate::CliResult<()> {
    let status = response.status();

    if status.is_success() {
        Ok(())
    } else {
        let message = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Err(crate::CliError::Api {
            status: status.as_u16(),
            message,
        })
    }
}
