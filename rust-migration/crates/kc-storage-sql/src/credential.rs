//! `PostgreSQL` implementation of the credential storage provider.

use async_trait::async_trait;
use kc_model::{Credential, CredentialType};
use kc_storage::CredentialProvider;
use kc_storage::error::StorageResult;
use sqlx::PgPool;
use uuid::Uuid;

use crate::entities::CredentialRow;
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` credential storage provider.
pub struct PgCredentialProvider {
    pool: PgPool,
}

impl PgCredentialProvider {
    /// Creates a new `PostgreSQL` credential provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialProvider for PgCredentialProvider {
    async fn create(&self, credential: &Credential) -> StorageResult<()> {
        sqlx::query(
            r"INSERT INTO credentials (
                id, user_id, realm_id, credential_type, user_label,
                created_at, secret_data, credential_data, priority
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(credential.id)
        .bind(credential.user_id)
        .bind(credential.realm_id)
        .bind(credential.credential_type.as_str())
        .bind(&credential.user_label)
        .bind(credential.created_at)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
        .bind(credential.priority)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn update(&self, credential: &Credential) -> StorageResult<()> {
        let result = sqlx::query(
            r"UPDATE credentials SET
                user_label = $2, secret_data = $3, credential_data = $4, priority = $5
            WHERE id = $1 AND user_id = $6 AND realm_id = $7",
        )
        .bind(credential.id)
        .bind(&credential.user_label)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
        .bind(credential.priority)
        .bind(credential.user_id)
        .bind(credential.realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Credential", credential.id));
        }

        Ok(())
    }

    async fn delete(&self, realm_id: Uuid, user_id: Uuid, id: Uuid) -> StorageResult<()> {
        let result =
            sqlx::query("DELETE FROM credentials WHERE id = $1 AND user_id = $2 AND realm_id = $3")
                .bind(id)
                .bind(user_id)
                .bind(realm_id)
                .execute(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Credential", id));
        }

        Ok(())
    }

    async fn get_by_id(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> StorageResult<Option<Credential>> {
        let row: Option<CredentialRow> = sqlx::query_as(
            "SELECT * FROM credentials WHERE id = $1 AND user_id = $2 AND realm_id = $3",
        )
        .bind(id)
        .bind(user_id)
        .bind(realm_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(row.map(Credential::from))
    }

    async fn list_by_user(&self, realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Credential>> {
        let rows: Vec<CredentialRow> = sqlx::query_as(
            "SELECT * FROM credentials WHERE realm_id = $1 AND user_id = $2 ORDER BY priority, created_at",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Credential::from).collect())
    }

    async fn list_by_type(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
    ) -> StorageResult<Vec<Credential>> {
        let rows: Vec<CredentialRow> = sqlx::query_as(
            r"SELECT * FROM credentials
            WHERE realm_id = $1 AND user_id = $2 AND credential_type = $3
            ORDER BY priority, created_at",
        )
        .bind(realm_id)
        .bind(user_id)
        .bind(credential_type.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Credential::from).collect())
    }

    async fn delete_by_type(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
    ) -> StorageResult<()> {
        sqlx::query(
            "DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = $3",
        )
        .bind(realm_id)
        .bind(user_id)
        .bind(credential_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    async fn update_priority(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_ids: &[Uuid],
    ) -> StorageResult<()> {
        // Update priority based on position in the array
        for (priority, id) in credential_ids.iter().enumerate() {
            sqlx::query(
                "UPDATE credentials SET priority = $1 WHERE id = $2 AND user_id = $3 AND realm_id = $4",
            )
            .bind(priority as i32)
            .bind(id)
            .bind(user_id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;
        }

        Ok(())
    }

    async fn update_label(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        credential_id: Uuid,
        label: Option<&str>,
    ) -> StorageResult<()> {
        let result = sqlx::query(
            "UPDATE credentials SET user_label = $1 WHERE id = $2 AND user_id = $3 AND realm_id = $4",
        )
        .bind(label)
        .bind(credential_id)
        .bind(user_id)
        .bind(realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Credential", credential_id));
        }

        Ok(())
    }
}
