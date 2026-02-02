//! User storage provider trait.

use async_trait::async_trait;
use kc_model::User;
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for user storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait UserProvider: Send + Sync {
    /// Creates a new user.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::Duplicate` if a user with the same username exists.
    async fn create(&self, user: &User) -> StorageResult<()>;

    /// Updates an existing user.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the user doesn't exist.
    async fn update(&self, user: &User) -> StorageResult<()>;

    /// Deletes a user by ID.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the user doesn't exist.
    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()>;

    /// Gets a user by ID.
    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<User>>;

    /// Gets a user by username.
    async fn get_by_username(&self, realm_id: Uuid, username: &str) -> StorageResult<Option<User>>;

    /// Gets a user by email.
    async fn get_by_email(&self, realm_id: Uuid, email: &str) -> StorageResult<Option<User>>;

    /// Searches for users matching criteria.
    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &UserSearchCriteria,
    ) -> StorageResult<Vec<User>>;

    /// Counts users matching criteria.
    async fn count(&self, realm_id: Uuid, criteria: &UserSearchCriteria) -> StorageResult<u64>;

    /// Gets users by role.
    async fn get_by_role(&self, realm_id: Uuid, role_id: Uuid) -> StorageResult<Vec<User>>;

    /// Gets users by group.
    async fn get_by_group(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<Vec<User>>;

    /// Gets the service account user for a client.
    async fn get_service_account(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
    ) -> StorageResult<Option<User>>;

    /// Adds a user to a group.
    async fn add_to_group(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> StorageResult<()>;

    /// Removes a user from a group.
    async fn remove_from_group(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> StorageResult<()>;

    /// Gets the groups a user belongs to.
    async fn get_groups(&self, realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Uuid>>;

    /// Grants a role to a user.
    async fn grant_role(&self, realm_id: Uuid, user_id: Uuid, role_id: Uuid) -> StorageResult<()>;

    /// Revokes a role from a user.
    async fn revoke_role(&self, realm_id: Uuid, user_id: Uuid, role_id: Uuid) -> StorageResult<()>;

    /// Gets the roles granted to a user (direct grants only).
    async fn get_roles(&self, realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Uuid>>;

    /// Checks if a user has a specific role (direct or inherited).
    async fn has_role(&self, realm_id: Uuid, user_id: Uuid, role_id: Uuid) -> StorageResult<bool>;
}

/// Search criteria for users.
#[derive(Debug, Default, Clone)]
pub struct UserSearchCriteria {
    /// Search string (matches username, email, first name, last name).
    pub search: Option<String>,
    /// Filter by username (exact match).
    pub username: Option<String>,
    /// Filter by email (exact match).
    pub email: Option<String>,
    /// Filter by first name (prefix match).
    pub first_name: Option<String>,
    /// Filter by last name (prefix match).
    pub last_name: Option<String>,
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Filter by email verified status.
    pub email_verified: Option<bool>,
    /// Filter by federation link.
    pub federation_link: Option<String>,
    /// Filter by identity provider.
    pub identity_provider: Option<String>,
    /// Filter by attribute (name, value).
    pub attribute: Option<(String, String)>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl UserSearchCriteria {
    /// Creates a new search criteria.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            search: None,
            username: None,
            email: None,
            first_name: None,
            last_name: None,
            enabled: None,
            email_verified: None,
            federation_link: None,
            identity_provider: None,
            attribute: None,
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

    /// Filters by username.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Filters by email.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
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
