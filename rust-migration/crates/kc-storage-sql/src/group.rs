//! `PostgreSQL` implementation of the group storage provider.

use async_trait::async_trait;
use kc_model::Group;
use kc_storage::GroupProvider;
use kc_storage::error::StorageResult;
use kc_storage::group::GroupSearchCriteria;
use sqlx::PgPool;
use uuid::Uuid;

use crate::convert::{attributes_to_json, client_roles_to_json};
use crate::entities::GroupRow;
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` group storage provider.
pub struct PgGroupProvider {
    pool: PgPool,
}

impl PgGroupProvider {
    /// Creates a new `PostgreSQL` group provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Build the full path for a group by traversing parents.
    async fn build_path(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<String> {
        let mut path_parts = Vec::new();
        let mut current_id = Some(group_id);

        while let Some(id) = current_id {
            let group = self.get_by_id(realm_id, id).await?;
            match group {
                Some(g) => {
                    path_parts.push(g.name);
                    current_id = g.parent_id;
                }
                None => break,
            }
        }

        path_parts.reverse();
        Ok(format!("/{}", path_parts.join("/")))
    }
}

#[async_trait]
impl GroupProvider for PgGroupProvider {
    async fn create(&self, group: &Group) -> StorageResult<()> {
        let realm_roles: Vec<Uuid> = group.realm_roles.clone();
        let client_roles = client_roles_to_json(&group.client_roles);
        let attributes = attributes_to_json(&group.attributes);

        sqlx::query(
            r"INSERT INTO groups (
                id, name, description, realm_id, parent_id,
                created_at, updated_at, attributes, realm_roles, client_roles
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(group.id)
        .bind(&group.name)
        .bind(&group.description)
        .bind(group.realm_id)
        .bind(group.parent_id)
        .bind(group.created_at)
        .bind(group.updated_at)
        .bind(sqlx::types::Json(&attributes))
        .bind(sqlx::types::Json(&realm_roles))
        .bind(sqlx::types::Json(&client_roles))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn update(&self, group: &Group) -> StorageResult<()> {
        let realm_roles: Vec<Uuid> = group.realm_roles.clone();
        let client_roles = client_roles_to_json(&group.client_roles);
        let attributes = attributes_to_json(&group.attributes);

        let result = sqlx::query(
            r"UPDATE groups SET
                name = $2, description = $3, parent_id = $4, updated_at = $5,
                attributes = $6, realm_roles = $7, client_roles = $8
            WHERE id = $1 AND realm_id = $9",
        )
        .bind(group.id)
        .bind(&group.name)
        .bind(&group.description)
        .bind(group.parent_id)
        .bind(group.updated_at)
        .bind(sqlx::types::Json(&attributes))
        .bind(sqlx::types::Json(&realm_roles))
        .bind(sqlx::types::Json(&client_roles))
        .bind(group.realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Group", group.id));
        }

        Ok(())
    }

    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM groups WHERE id = $1 AND realm_id = $2")
            .bind(id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Group", id));
        }

        Ok(())
    }

    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Group>> {
        let row: Option<GroupRow> =
            sqlx::query_as("SELECT * FROM groups WHERE id = $1 AND realm_id = $2")
                .bind(id)
                .bind(realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(row.map(Group::from))
    }

    async fn get_by_path(&self, realm_id: Uuid, path: &str) -> StorageResult<Option<Group>> {
        // Parse path and navigate through groups
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
            return Ok(None);
        }

        let mut current_parent: Option<Uuid> = None;
        let mut current_group: Option<Group> = None;

        for part in parts {
            let row: Option<GroupRow> = match current_parent {
                Some(pid) => {
                    sqlx::query_as(
                        "SELECT * FROM groups WHERE realm_id = $1 AND parent_id = $2 AND name = $3",
                    )
                    .bind(realm_id)
                    .bind(pid)
                    .bind(part)
                    .fetch_optional(&self.pool)
                    .await
                }
                None => sqlx::query_as(
                    "SELECT * FROM groups WHERE realm_id = $1 AND parent_id IS NULL AND name = $2",
                )
                .bind(realm_id)
                .bind(part)
                .fetch_optional(&self.pool)
                .await,
            }
            .map_err(from_sqlx_error)?;

            match row {
                Some(r) => {
                    current_parent = Some(r.id);
                    current_group = Some(Group::from(r));
                }
                None => return Ok(None),
            }
        }

        Ok(current_group)
    }

    async fn list_top_level(&self, realm_id: Uuid) -> StorageResult<Vec<Group>> {
        let rows: Vec<GroupRow> = sqlx::query_as(
            "SELECT * FROM groups WHERE realm_id = $1 AND parent_id IS NULL ORDER BY name",
        )
        .bind(realm_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Group::from).collect())
    }

    async fn list_children(&self, realm_id: Uuid, parent_id: Uuid) -> StorageResult<Vec<Group>> {
        let rows: Vec<GroupRow> = sqlx::query_as(
            "SELECT * FROM groups WHERE realm_id = $1 AND parent_id = $2 ORDER BY name",
        )
        .bind(realm_id)
        .bind(parent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Group::from).collect())
    }

    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &GroupSearchCriteria,
    ) -> StorageResult<Vec<Group>> {
        #[allow(clippy::cast_possible_wrap)]
        let limit = criteria.max_results.unwrap_or(100) as i64;
        #[allow(clippy::cast_possible_wrap)]
        let offset = criteria.offset.unwrap_or(0) as i64;

        let rows: Vec<GroupRow> = if let Some(search) = &criteria.search {
            let pattern = format!("%{search}%");
            if criteria.top_level_only {
                sqlx::query_as(
                    r"SELECT * FROM groups WHERE realm_id = $1 AND parent_id IS NULL AND name ILIKE $2
                    ORDER BY name LIMIT $3 OFFSET $4",
                )
                .bind(realm_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            } else if let Some(parent_id) = criteria.parent_id {
                sqlx::query_as(
                    r"SELECT * FROM groups WHERE realm_id = $1 AND parent_id = $2 AND name ILIKE $3
                    ORDER BY name LIMIT $4 OFFSET $5",
                )
                .bind(realm_id)
                .bind(parent_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            } else {
                sqlx::query_as(
                    r"SELECT * FROM groups WHERE realm_id = $1 AND name ILIKE $2
                    ORDER BY name LIMIT $3 OFFSET $4",
                )
                .bind(realm_id)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
            }
        } else if let Some(name) = &criteria.name {
            sqlx::query_as(
                "SELECT * FROM groups WHERE realm_id = $1 AND name = $2 LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(name)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as(
                "SELECT * FROM groups WHERE realm_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
            )
            .bind(realm_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Group::from).collect())
    }

    async fn count(&self, realm_id: Uuid) -> StorageResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups WHERE realm_id = $1")
            .bind(realm_id)
            .fetch_one(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }

    async fn get_path(&self, realm_id: Uuid, group_id: Uuid) -> StorageResult<String> {
        self.build_path(realm_id, group_id).await
    }

    async fn move_group(
        &self,
        realm_id: Uuid,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> StorageResult<()> {
        let result =
            sqlx::query("UPDATE groups SET parent_id = $1 WHERE id = $2 AND realm_id = $3")
                .bind(new_parent_id)
                .bind(group_id)
                .bind(realm_id)
                .execute(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Group", group_id));
        }

        Ok(())
    }

    async fn get_members(
        &self,
        _realm_id: Uuid,
        group_id: Uuid,
        max_results: Option<usize>,
        offset: Option<usize>,
    ) -> StorageResult<Vec<Uuid>> {
        #[allow(clippy::cast_possible_wrap)]
        let limit = max_results.unwrap_or(100) as i64;
        #[allow(clippy::cast_possible_wrap)]
        let off = offset.unwrap_or(0) as i64;

        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT user_id FROM user_group_memberships WHERE group_id = $1 LIMIT $2 OFFSET $3",
        )
        .bind(group_id)
        .bind(limit)
        .bind(off)
        .fetch_all(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn count_members(&self, _realm_id: Uuid, group_id: Uuid) -> StorageResult<u64> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM user_group_memberships WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }
}
