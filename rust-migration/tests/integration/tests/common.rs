//! Common test utilities and fixtures.

use std::net::TcpListener;
use std::time::Duration;

use reqwest::Client;
use sqlx::PgPool;
use testcontainers::{
    runners::AsyncRunner,
    ContainerAsync, ImageExt,
};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::oneshot;
use tokio::time::sleep;

use kc_server::{Server, ServerConfig};

/// Test environment that manages containers and server.
pub struct TestEnv {
    /// PostgreSQL container.
    _postgres: ContainerAsync<Postgres>,
    /// Database connection pool.
    pub pool: PgPool,
    /// Base URL of the running server.
    pub base_url: String,
    /// HTTP client for testing.
    pub client: Client,
    /// Server shutdown signal.
    _shutdown_tx: oneshot::Sender<()>,
}

impl TestEnv {
    /// Creates a new test environment with ephemeral containers.
    pub async fn new() -> anyhow::Result<Self> {
        // Initialize tracing for tests
        let _ = tracing_subscriber::fmt()
            .with_env_filter("kc_server=debug,sqlx=warn")
            .try_init();

        // Start PostgreSQL container
        let postgres = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;

        let pg_port = postgres.get_host_port_ipv4(5432).await?;
        let database_url = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg_port
        );

        // Connect to database
        let pool = PgPool::connect(&database_url).await?;

        // Run migrations
        sqlx::migrate!("../../migrations").run(&pool).await?;

        // Find available port for server
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let server_port = listener.local_addr()?.port();
        drop(listener);

        let base_url = format!("http://127.0.0.1:{}", server_port);

        // Create server config
        let mut config = ServerConfig::for_testing(&database_url);
        config.host = "127.0.0.1".to_string();
        config.port = server_port;
        config.base_url = base_url.clone();

        // Create shutdown channel
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start server
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

        // Wait for server
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .cookie_store(true)
            .build()?;

        wait_for_server(&client, &base_url).await?;

        Ok(Self {
            _postgres: postgres,
            pool,
            base_url,
            client,
            _shutdown_tx,
        })
    }

    /// Creates a test realm in the database.
    pub async fn create_realm(&self, name: &str) -> anyhow::Result<uuid::Uuid> {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO realms (id, name, display_name, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, true, NOW(), NOW())
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(name)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Creates a test client in the database.
    pub async fn create_client(
        &self,
        realm_id: uuid::Uuid,
        client_id: &str,
        secret: Option<&str>,
        public: bool,
    ) -> anyhow::Result<uuid::Uuid> {
        let id = uuid::Uuid::new_v4();
        let redirect_uris = serde_json::json!(["http://localhost:8080/callback"]);
        let web_origins = serde_json::json!(["http://localhost:8080"]);
        sqlx::query(
            r#"
            INSERT INTO clients (
                id, realm_id, client_id, name, secret, public_client, enabled,
                redirect_uris, web_origins, protocol, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, 'openid-connect', NOW(), NOW())
            "#,
        )
        .bind(id)
        .bind(realm_id)
        .bind(client_id)
        .bind(client_id)
        .bind(secret)
        .bind(public)
        .bind(&redirect_uris)
        .bind(&web_origins)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Creates a test user in the database.
    pub async fn create_user(
        &self,
        realm_id: uuid::Uuid,
        username: &str,
        email: &str,
        password: &str,
    ) -> anyhow::Result<uuid::Uuid> {
        let user_id = uuid::Uuid::new_v4();

        // Create user
        sqlx::query(
            r#"
            INSERT INTO users (
                id, realm_id, username, email, email_verified, enabled,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, true, true, NOW(), NOW())
            "#,
        )
        .bind(user_id)
        .bind(realm_id)
        .bind(username)
        .bind(email)
        .execute(&self.pool)
        .await?;

        // Hash password
        let password_hash = kc_auth::password::PasswordHasherService::with_defaults()
            .hash(password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {:?}", e))?;

        // Create password credential
        let cred_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, user_id, realm_id, credential_type, secret_data,
                credential_data, priority, created_at
            )
            VALUES ($1, $2, $3, 'password', $4, '{}', 0, NOW())
            "#,
        )
        .bind(cred_id)
        .bind(user_id)
        .bind(realm_id)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        Ok(user_id)
    }

    /// Returns the discovery URL for a realm.
    pub fn discovery_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/.well-known/openid-configuration",
            self.base_url, realm
        )
    }

    /// Returns the token URL for a realm.
    pub fn token_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.base_url, realm
        )
    }

    /// Returns the userinfo URL for a realm.
    pub fn userinfo_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/userinfo",
            self.base_url, realm
        )
    }

    /// Returns the introspect URL for a realm.
    pub fn introspect_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token/introspect",
            self.base_url, realm
        )
    }

    /// Returns the revoke URL for a realm.
    pub fn revoke_url(&self, realm: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/revoke",
            self.base_url, realm
        )
    }
}

/// Waits for the server to be ready.
async fn wait_for_server(client: &Client, base_url: &str) -> anyhow::Result<()> {
    let health_url = format!("{}/health", base_url);
    let max_attempts = 50;

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
