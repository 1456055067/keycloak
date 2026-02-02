//! `PostgreSQL` implementation of the role storage provider.

use async_trait::async_trait;
use kc_model::Role;
use kc_storage::RoleProvider;
use kc_storage::error::StorageResult;
use kc_storage::role::RoleSearchCriteria;
use sqlx::PgPool;
use uuid::Uuid;

use crate::convert::attributes_to_json;
use crate::entities::RoleRow;
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` role storage provider.
pub struct PgRoleProvider {
    pool: PgPool,
}

impl PgRoleProvider {
    /// Creates a new `PostgreSQL` role provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleProvider for PgRoleProvider {
    async fn create(&self, role: &Role) -> StorageResult<()> {
        let composite_roles: Vec<Uuid> = role.composite_roles.clone();
        let attributes = attributes_to_json(&role.attributes);

        sqlx::query(
            r"INSERT INTO roles (
                id, name, description, realm_id, client_id,
                created_at, updated_at, composite_roles, attributes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(role.id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(role.realm_id)
        .bind(role.client_id)
        .bind(role.created_at)
        .bind(role.updated_at)
        .bind(sqlx::types::Json(&composite_roles))
        .bind(sqlx::types::Json(&attributes))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn update(&self, role: &Role) -> StorageResult<()> {
        let composite_roles: Vec<Uuid> = role.composite_roles.clone();
        let attributes = attributes_to_json(&role.attributes);

        let result = sqlx::query(
            r"UPDATE roles SET
                name = $2, description = $3, updated_at = $4,
                composite_roles = $5, attributes = $6
            WHERE id = $1 AND realm_id = $7",
        )
        .bind(role.id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(role.updated_at)
        .bind(sqlx::types::Json(&composite_roles))
        .bind(sqlx::types::Json(&attributes))
        .bind(role.realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Role", role.id));
        }

        Ok(())
    }

    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM roles WHERE id = $1 AND realm_id = $2")
            .bind(id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Role", id));
        }

        Ok(())
    }

    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Role>> {
        let row: Option<RoleRow> =
            sqlx::query_as("SELECT * FROM roles WHERE id = $1 AND realm_id = $2")
                .bind(id)
                .bind(realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(row.map(Role::from))
    }

    async fn get_realm_role_by_name(
        &self,
        realm_id: Uuid,
        name: &str,
    ) -> StorageResult<Option<Role>> {
        let row: Option<RoleRow> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id IS NULL AND name = $2",
        )
        .bind(realm_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(row.map(Role::from))
    }

    async fn get_client_role_by_name(
        &self,
        realm_id: Uuid,
        client_id: Uuid,
        name: &str,
    ) -> StorageResult<Option<Role>> {
        let row: Option<RoleRow> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 AND name = $3",
        )
        .bind(realm_id)
        .bind(client_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(row.map(Role::from))
    }

    async fn list_realm_roles(&self, realm_id: Uuid) -> StorageResult<Vec<Role>> {
        let rows: Vec<RoleRow> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id IS NULL ORDER BY name",
        )
        .bind(realm_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Role::from).collect())
    }

    async fn list_client_roles(&self, realm_id: Uuid, client_id: Uuid) -> StorageResult<Vec<Role>> {
        let rows: Vec<RoleRow> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 ORDER BY name",
        )
        .bind(realm_id)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Role::from).collect())
    }

    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &RoleSearchCriteria,
    ) -> StorageResult<Vec<Role>> {
        #[allow(clippy::cast_possible_wrap)]
        let limit = criteria.max_results.unwrap_or(100) as i64;
        #[allow(clippy::cast_possible_wrap)]
        let offset = criteria.offset.unwrap_or(0) as i64;

        let rows: Vec<RoleRow> = if let Some(search) = &criteria.search {
            let pattern = format!("%{search}%");
            if criteria.include_realm_roles && criteria.include_client_roles {
                sqlx::query_as(
                    "SELECT * FROM roles WHERE realm_id = $1 AND name ILIKE $2 ORDER BY name LIMIT $3 OFFSET $4",
                )
                .bind(realm_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            } else if criteria.include_realm_roles {
                sqlx::query_as(
                    "SELECT * FROM roles WHERE realm_id = $1 AND client_id IS NULL AND name ILIKE $2 ORDER BY name LIMIT $3 OFFSET $4",
                )
                .bind(realm_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            } else if let Some(client_id) = criteria.client_id {
                sqlx::query_as(
                    "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 AND name ILIKE $3 ORDER BY name LIMIT $4 OFFSET $5",
                )
                .bind(realm_id)
                .bind(client_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            } else {
                sqlx::query_as(
                    "SELECT * FROM roles WHERE realm_id = $1 AND client_id IS NOT NULL AND name ILIKE $2 ORDER BY name LIMIT $3 OFFSET $4",
                )
                .bind(realm_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            }
        } else {
            sqlx::query_as(
                "SELECT * FROM roles WHERE realm_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
            )
            .bind(realm_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Role::from).collect())
    }

    async fn get_composites(&self, realm_id: Uuid, role_id: Uuid) -> StorageResult<Vec<Role>> {
        // First get the role to find its composite_roles
        let role = self.get_by_id(realm_id, role_id).await?;

        match role {
            Some(r) if !r.composite_roles.is_empty() => {
                let mut roles = Vec::new();
                for id in r.composite_roles {
                    if let Some(composite) = self.get_by_id(realm_id, id).await? {
                        roles.push(composite);
                    }
                }
                Ok(roles)
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn add_composite(
        &self,
        realm_id: Uuid,
        composite_id: Uuid,
        role_id: Uuid,
    ) -> StorageResult<()> {
        // Get the composite role (the role that will contain others)
        let role = self.get_by_id(realm_id, composite_id).await?;
        let mut role = role.ok_or_else(|| not_found("Role", composite_id))?;

        // Add role_id to composite if not already present
        if !role.composite_roles.contains(&role_id) {
            role.composite_roles.push(role_id);
            self.update(&role).await?;
        }

        Ok(())
    }

    async fn remove_composite(
        &self,
        realm_id: Uuid,
        composite_id: Uuid,
        role_id: Uuid,
    ) -> StorageResult<()> {
        // Get the composite role
        let role = self.get_by_id(realm_id, composite_id).await?;
        let mut role = role.ok_or_else(|| not_found("Role", composite_id))?;

        // Remove role_id from composite
        role.composite_roles.retain(|id| *id != role_id);
        self.update(&role).await?;

        Ok(())
    }
}
