//! Client storage provider trait.

use async_trait::async_trait;
use kc_model::Client;
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for client storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait ClientProvider: Send + Sync {
    /// Creates a new client.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::Duplicate` if a client with the same `client_id` exists.
    async fn create(&self, client: &Client) -> StorageResult<()>;

    /// Updates an existing client.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the client doesn't exist.
    async fn update(&self, client: &Client) -> StorageResult<()>;

    /// Deletes a client by ID.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the client doesn't exist.
    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()>;

    /// Gets a client by internal ID.
    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Client>>;

    /// Gets a client by `client_id` (OAuth client identifier).
    async fn get_by_client_id(
        &self,
        realm_id: Uuid,
        client_id: &str,
    ) -> StorageResult<Option<Client>>;

    /// Searches for clients matching criteria.
    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &ClientSearchCriteria,
    ) -> StorageResult<Vec<Client>>;

    /// Counts clients in a realm.
    async fn count(&self, realm_id: Uuid) -> StorageResult<u64>;

    /// Gets all clients in a realm.
    async fn list(&self, realm_id: Uuid) -> StorageResult<Vec<Client>>;

    /// Validates a client secret.
    ///
    /// Returns true if the secret matches.
    async fn validate_secret(
        &self,
        realm_id: Uuid,
        client_id: &str,
        secret: &str,
    ) -> StorageResult<bool>;

    /// Regenerates a client secret.
    ///
    /// Returns the new secret.
    async fn regenerate_secret(&self, realm_id: Uuid, id: Uuid) -> StorageResult<String>;
}

/// Search criteria for clients.
#[derive(Debug, Default, Clone)]
pub struct ClientSearchCriteria {
    /// Search string (matches `client_id`, name).
    pub search: Option<String>,
    /// Filter by `client_id` (prefix match).
    pub client_id: Option<String>,
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Filter by public client status.
    pub public_client: Option<bool>,
    /// Filter by protocol.
    pub protocol: Option<String>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl ClientSearchCriteria {
    /// Creates a new search criteria.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            search: None,
            client_id: None,
            enabled: None,
            public_client: None,
            protocol: None,
            max_results: None,
            offset: None,
        }
    }

    /// Sets the search string.
    #[must_use]
    pub fn search(mut self, search: impl Into<String>) -> Self {
        self.search = Some(search.into());
        self
    }

    /// Filters by `client_id` prefix.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Filters by enabled status.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// Filters by public client status.
    #[must_use]
    pub const fn public_client(mut self, public_client: bool) -> Self {
        self.public_client = Some(public_client);
        self
    }

    /// Sets maximum results.
    #[must_use]
    pub const fn max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }

    /// Sets offset for pagination.
    #[must_use]
    pub const fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}
