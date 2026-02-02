//! Role storage provider trait.

use async_trait::async_trait;
use kc_model::Role;
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for role storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait RoleProvider: Send + Sync {
    /// Creates a new role.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::Duplicate` if a role with the same name exists
    /// in the same scope (realm or client).
    async fn create(&self, role: &Role) -> StorageResult<()>;

    /// Updates an existing role.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the role doesn't exist.
    async fn update(&self, role: &Role) -> StorageResult<()>;

    /// Deletes a role by ID.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the role doesn't exist.
    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()>;

    /// Gets a role by ID.
    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Role>>;

    /// Gets a realm role by name.
    async fn get_realm_role_by_name(
        &self,
        realm_id: Uuid,
        name: &str,
    ) -> StorageResult<Option<Role>>;

    /// Gets a client role by name.
    async fn get_client_role_by_name(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
        name: &str,
    ) -> StorageResult<Option<Role>>;

    /// Lists all realm roles.
    async fn list_realm_roles(&self, realm_id: Uuid) -> StorageResult<Vec<Role>>;

    /// Lists all client roles for a client.
    async fn list_client_roles(&self, realm_id: Uuid, client_id: Uuid) -> StorageResult<Vec<Role>>;

    /// Searches for roles matching criteria.
    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &RoleSearchCriteria,
    ) -> StorageResult<Vec<Role>>;

    /// Gets composite roles (roles included in a composite role).
    async fn get_composites(&self, realm_id: Uuid, role_id: Uuid) -> StorageResult<Vec<Role>>;

    /// Adds a role to a composite role.
    async fn add_composite(
        &self,
        realm_id: Uuid,
        composite_id: Uuid,
        role_id: Uuid,
    ) -> StorageResult<()>;

    /// Removes a role from a composite role.
    async fn remove_composite(
        &self,
        realm_id: Uuid,
        composite_id: Uuid,
        role_id: Uuid,
    ) -> StorageResult<()>;
}

/// Search criteria for roles.
#[derive(Debug, Default, Clone)]
pub struct RoleSearchCriteria {
    /// Search string (matches role name).
    pub search: Option<String>,
    /// Filter by client ID (None for realm roles only).
    pub client_id: Option<Uuid>,
    /// Include realm roles in results.
    pub include_realm_roles: bool,
    /// Include client roles in results.
    pub include_client_roles: bool,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl RoleSearchCriteria {
    /// Creates a new search criteria (includes both realm and client roles).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            search: None,
            client_id: None,
            include_realm_roles: true,
            include_client_roles: true,
            max_results: None,
            offset: None,
        }
    }

    /// Creates criteria for realm roles only.
    #[must_use]
    pub const fn realm_roles_only() -> Self {
        Self {
            search: None,
            client_id: None,
            include_realm_roles: true,
            include_client_roles: false,
            max_results: None,
            offset: None,
        }
    }

    /// Creates criteria for client roles only.
    #[must_use]
    pub const fn client_roles_only(client_id: Uuid) -> Self {
        Self {
            search: None,
            client_id: Some(client_id),
            include_realm_roles: false,
            include_client_roles: true,
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
