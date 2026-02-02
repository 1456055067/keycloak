//! Credential storage provider trait.

use async_trait::async_trait;
use kc_model::{Credential, CredentialType};
use uuid::Uuid;

use crate::error::StorageResult;

/// Provider for credential storage operations.
///
/// Implementations must be thread-safe and support concurrent access.
///
/// ## Security Note
///
/// Credential data (passwords, OTP secrets) should be encrypted at rest.
/// Implementations must ensure sensitive data is never logged.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Creates a new credential.
    async fn create(&self, credential: &Credential) -> StorageResult<()>;

    /// Updates an existing credential.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the credential doesn't exist.
    async fn update(&self, credential: &Credential) -> StorageResult<()>;

    /// Deletes a credential by ID.
    ///
    /// ## Errors
    ///
    /// Returns `StorageError::NotFound` if the credential doesn't exist.
    async fn delete(&self, realm_id: Uuid, user_id: Uuid, id: Uuid) -> StorageResult<()>;

    /// Gets a credential by ID.
    async fn get_by_id(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> StorageResult<Option<Credential>>;

    /// Lists all credentials for a user.
    async fn list_by_user(&self, realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Credential>>;

    /// Lists credentials of a specific type for a user.
    async fn list_by_type(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
    ) -> StorageResult<Vec<Credential>>;

    /// Gets the password credential for a user (if any).
    async fn get_password(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
    ) -> StorageResult<Option<Credential>> {
        let credentials = self
            .list_by_type(realm_id, user_id, CredentialType::Password)
            .await?;
        Ok(credentials.into_iter().next())
    }

    /// Checks if a user has a credential of the specified type.
    async fn has_credential_type(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
    ) -> StorageResult<bool> {
        let count = self
            .list_by_type(realm_id, user_id, credential_type)
            .await?
            .len();
        Ok(count > 0)
    }

    /// Deletes all credentials of a specific type for a user.
    async fn delete_by_type(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
    ) -> StorageResult<()>;

    /// Updates the priority/order of credentials.
    async fn update_priority(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_ids: &[Uuid],
    ) -> StorageResult<()>;

    /// Updates the label of a credential.
    async fn update_label(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_id: Uuid,
        label: Option<&str>,
    ) -> StorageResult<()>;
}
