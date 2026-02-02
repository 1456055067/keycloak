//! Group storage provider trait.

use async_trait::async_trait;
use kc_model::Group;
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for group storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait GroupProvider: Send + Sync {
    /// Creates a new group.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::Duplicate` if a group with the same name
    /// exists at the same level (same parent or top-level).
    async fn create(&self, group: &Group) -> StorageResult<()>;

    /// Updates an existing group.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the group doesn't exist.
    async fn update(&self, group: &Group) -> StorageResult<()>;

    /// Deletes a group by ID.
    ///
    /// Note: This should also handle cascading deletion of child groups.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the group doesn't exist.
    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()>;

    /// Gets a group by ID.
    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Group>>;

    /// Gets a group by path (e.g., "/parent/child/grandchild").
    async fn get_by_path(&self, realm_id: Uuid, path: &str) -> StorageResult<Option<Group>>;

    /// Lists top-level groups in a realm.
    async fn list_top_level(&self, realm_id: Uuid) -> StorageResult<Vec<Group>>;

    /// Lists child groups of a parent group.
    async fn list_children(&self, realm_id: Uuid, parent_id: Uuid) -> StorageResult<Vec<Group>>;

    /// Searches for groups matching criteria.
    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &GroupSearchCriteria,
    ) -> StorageResult<Vec<Group>>;

    /// Counts groups in a realm.
    async fn count(&self, realm_id: Uuid) -> StorageResult<u64>;

    /// Gets the full path of a group.
    async fn get_path(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<String>;

    /// Moves a group to a new parent (or top-level if parent is None).
    async fn move_group(
        &self,
        realm_id: Uuid,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> StorageResult<()>;

    /// Gets members of a group.
    async fn get_members(
        &self,
        realm_id: Uuid,
        group_id: Uuid,
        max_results: Option<usize>,
        offset: Option<usize>,
    ) -> StorageResult<Vec<Uuid>>;

    /// Counts members in a group.
    async fn count_members(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<u64>;
}

/// Search criteria for groups.
#[derive(Debug, Default, Clone)]
pub struct GroupSearchCriteria {
    /// Search string (matches group name).
    pub search: Option<String>,
    /// Filter by exact name.
    pub name: Option<String>,
    /// Filter to top-level groups only.
    pub top_level_only: bool,
    /// Filter by parent group ID.
    pub parent_id: Option<Uuid>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl GroupSearchCriteria {
    /// Creates a new search criteria.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            search: None,
            name: None,
            top_level_only: false,
            parent_id: None,
            max_results: None,
            offset: None,
        }
    }

    /// Creates criteria for top-level groups only.
    #[must_use]
    pub const fn top_level() -> Self {
        Self {
            search: None,
            name: None,
            top_level_only: true,
            parent_id: None,
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

    /// Filters by exact name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Filters by parent group.
    #[must_use]
    pub const fn parent(mut self, parent_id: Uuid) -> Self {
        self.parent_id = Some(parent_id);
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
