//! `PostgreSQL` implementation of the user storage provider.

use async_trait::async_trait;
use kc_model::User;
use kc_storage::UserProvider;
use kc_storage::error::StorageResult;
use kc_storage::user::UserSearchCriteria;
use sqlx::PgPool;
use uuid::Uuid;

use crate::convert::{attributes_to_json, user_from_row};
use crate::entities::{FederatedIdentityRow, UserRow};
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` user storage provider.
pub struct PgUserProvider {
    pool: PgPool,
}

impl PgUserProvider {
    /// Creates a new `PostgreSQL` user provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch federated identities for a user.
    async fn fetch_federated_identities(
        &self,
        user_id: Uuid,
    ) -> StorageResult<Vec<FederatedIdentityRow>> {
        let rows: Vec<FederatedIdentityRow> =
            sqlx::query_as("SELECT * FROM federated_identities WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(rows)
    }

    /// Save federated identities for a user.
    async fn save_federated_identities(&self, user: &User) -> StorageResult<()> {
        // Delete existing identities
        sqlx::query("DELETE FROM federated_identities WHERE user_id = $1")
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        // Insert new identities
        for fi in &user.federated_identities {
            sqlx::query(
                r"INSERT INTO federated_identities (user_id, identity_provider, federated_user_id, federated_user_name)
                VALUES ($1, $2, $3, $4)",
            )
            .bind(user.id)
            .bind(&fi.identity_provider)
            .bind(&fi.user_id)
            .bind(&fi.user_name)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;
        }

        Ok(())
    }
}

#[async_trait]
impl UserProvider for PgUserProvider {
    async fn create(&self, user: &User) -> StorageResult<()> {
        let required_actions: Vec<String> = user.required_actions.clone();
        let attributes = attributes_to_json(&user.attributes);

        sqlx::query(
            r"INSERT INTO users (
                id, realm_id, username, enabled, first_name, last_name,
                email, email_verified, created_at, updated_at, not_before,
                federation_link, service_account_client_link,
                required_actions, attributes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(user.id)
        .bind(user.realm_id)
        .bind(&user.username)
        .bind(user.enabled)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.not_before)
        .bind(&user.federation_link)
        .bind(user.service_account_client_link)
        .bind(sqlx::types::Json(&required_actions))
        .bind(sqlx::types::Json(&attributes))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        // Save federated identities
        self.save_federated_identities(user).await?;

        Ok(())
    }

    async fn update(&self, user: &User) -> StorageResult<()> {
        let required_actions: Vec<String> = user.required_actions.clone();
        let attributes = attributes_to_json(&user.attributes);

        let result = sqlx::query(
            r"UPDATE users SET
                username = $2, enabled = $3, first_name = $4, last_name = $5,
                email = $6, email_verified = $7, updated_at = $8, not_before = $9,
                federation_link = $10, service_account_client_link = $11,
                required_actions = $12, attributes = $13
            WHERE id = $1 AND realm_id = $14",
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(user.enabled)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(user.updated_at)
        .bind(user.not_before)
        .bind(&user.federation_link)
        .bind(user.service_account_client_link)
        .bind(sqlx::types::Json(&required_actions))
        .bind(sqlx::types::Json(&attributes))
        .bind(user.realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("User", user.id));
        }

        // Update federated identities
        self.save_federated_identities(user).await?;

        Ok(())
    }

    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()> {
        // Federated identities will be deleted by cascade
        let result = sqlx::query("DELETE FROM users WHERE id = $1 AND realm_id = $2")
            .bind(id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("User", id));
        }

        Ok(())
    }

    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE id = $1 AND realm_id = $2")
                .bind(id)
                .bind(realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        match row {
            Some(r) => {
                let identities = self.fetch_federated_identities(r.id).await?;
                Ok(Some(user_from_row(r, identities)))
            }
            None => Ok(None),
        }
    }

    async fn get_by_username(&self, realm_id: Uuid, username: &str) -> StorageResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND username = $2")
                .bind(realm_id)
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        match row {
            Some(r) => {
                let identities = self.fetch_federated_identities(r.id).await?;
                Ok(Some(user_from_row(r, identities)))
            }
            None => Ok(None),
        }
    }

    async fn get_by_email(&self, realm_id: Uuid, email: &str) -> StorageResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND email = $2")
                .bind(realm_id)
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        match row {
            Some(r) => {
                let identities = self.fetch_federated_identities(r.id).await?;
                Ok(Some(user_from_row(r, identities)))
            }
            None => Ok(None),
        }
    }

    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &UserSearchCriteria,
    ) -> StorageResult<Vec<User>> {
        // Build dynamic query based on criteria
        #[allow(clippy::cast_possible_wrap)]
        let limit = criteria.max_results.unwrap_or(100) as i64;
        #[allow(clippy::cast_possible_wrap)]
        let offset = criteria.offset.unwrap_or(0) as i64;

        let rows: Vec<UserRow> = if let Some(search) = &criteria.search {
            let pattern = format!("%{search}%");
            sqlx::query_as(
                r"SELECT * FROM users WHERE realm_id = $1
                AND (username ILIKE $2 OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)
                ORDER BY username LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(&pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else if let Some(username) = &criteria.username {
            sqlx::query_as(
                "SELECT * FROM users WHERE realm_id = $1 AND username = $2 LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(username)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else if let Some(email) = &criteria.email {
            sqlx::query_as(
                "SELECT * FROM users WHERE realm_id = $1 AND email = $2 LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(email)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as(
                "SELECT * FROM users WHERE realm_id = $1 ORDER BY username LIMIT $2 OFFSET $3",
            )
            .bind(realm_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(from_sqlx_error)?;

        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            let identities = self.fetch_federated_identities(row.id).await?;
            users.push(user_from_row(row, identities));
        }

        Ok(users)
    }

    async fn count(&self, realm_id: Uuid, _criteria: &UserSearchCriteria) -> StorageResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE realm_id = $1")
            .bind(realm_id)
            .fetch_one(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }

    async fn get_by_role(&self, realm_id: Uuid, role_id: Uuid) -> StorageResult<Vec<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            r"SELECT u.* FROM users u
            JOIN user_role_mappings urm ON u.id = urm.user_id
            WHERE u.realm_id = $1 AND urm.role_id = $2
            ORDER BY u.username",
        )
        .bind(realm_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            let identities = self.fetch_federated_identities(row.id).await?;
            users.push(user_from_row(row, identities));
        }

        Ok(users)
    }

    async fn get_by_group(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<Vec<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            r"SELECT u.* FROM users u
            JOIN user_group_memberships ugm ON u.id = ugm.user_id
            WHERE u.realm_id = $1 AND ugm.group_id = $2
            ORDER BY u.username",
        )
        .bind(realm_id)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            let identities = self.fetch_federated_identities(row.id).await?;
            users.push(user_from_row(row, identities));
        }

        Ok(users)
    }

    async fn get_service_account(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
    ) -> StorageResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT * FROM users WHERE realm_id = $1 AND service_account_client_link = $2",
        )
        .bind(realm_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        match row {
            Some(r) => {
                let identities = self.fetch_federated_identities(r.id).await?;
                Ok(Some(user_from_row(r, identities)))
            }
            None => Ok(None),
        }
    }

    async fn add_to_group(
        &self,
        _realm_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> StorageResult<()> {
        sqlx::query("INSERT INTO user_group_memberships (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(user_id)
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn remove_from_group(
        &self,
        _realm_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> StorageResult<()> {
        sqlx::query("DELETE FROM user_group_memberships WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn get_groups(&self, _realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> =
            sqlx::query_as("SELECT group_id FROM user_group_memberships WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn grant_role(&self, _realm_id: Uuid, user_id: Uuid, role_id: Uuid) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO user_role_mappings (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn revoke_role(
        &self,
        _realm_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> StorageResult<()> {
        sqlx::query("DELETE FROM user_role_mappings WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn get_roles(&self, _realm_id: Uuid, user_id: Uuid) -> StorageResult<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> =
            sqlx::query_as("SELECT role_id FROM user_role_mappings WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn has_role(&self, _realm_id: Uuid, user_id: Uuid, role_id: Uuid) -> StorageResult<bool> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_role_mappings WHERE user_id = $1 AND role_id = $2",
        )
        .bind(user_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(count > 0)
    }
}
