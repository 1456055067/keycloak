//! Realm storage provider trait.

use async_trait::async_trait;
use kc_model::Realm;
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for realm storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait RealmProvider: Send + Sync {
    /// Creates a new realm.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::Duplicate` if a realm with the same name exists.
    async fn create(&self, realm: &Realm) -> StorageResult<()>;

    /// Updates an existing realm.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the realm doesn't exist.
    async fn update(&self, realm: &Realm) -> StorageResult<()>;

    /// Deletes a realm by ID.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the realm doesn't exist.
    async fn delete(&self, id: Uuid) -> StorageResult<()>;

    /// Gets a realm by ID.
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<Realm>>;

    /// Gets a realm by name.
    async fn get_by_name(&self, name: &str) -> StorageResult<Option<Realm>>;

    /// Lists all realms.
    async fn list(&self) -> StorageResult<Vec<Realm>>;

    /// Lists realm names only (for efficiency).
    async fn list_names(&self) -> StorageResult<Vec<String>>;

    /// Counts all realms.
    async fn count(&self) -> StorageResult<u64>;

    /// Checks if a realm exists by name.
    async fn exists_by_name(&self, name: &str) -> StorageResult<bool> {
        Ok(self.get_by_name(name).await?.is_some())
    }
}

/// Search criteria for realms.
#[derive(Debug, Default, Clone)]
pub struct RealmSearchCriteria {
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl RealmSearchCriteria {
    /// Creates a new search criteria.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            enabled: None,
            max_results: None,
            offset: None,
        }
    }

    /// Filters by enabled status.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
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
