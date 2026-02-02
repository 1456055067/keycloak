//! `PostgreSQL` implementation of the client storage provider.

use async_trait::async_trait;
use kc_model::Client;
use kc_storage::ClientProvider;
use kc_storage::client::ClientSearchCriteria;
use kc_storage::error::StorageResult;
use sqlx::PgPool;
use uuid::Uuid;

use crate::convert::{hashset_to_vec, protocol_to_string, string_map_to_json, uuid_map_to_json};
use crate::entities::ClientRow;
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` client storage provider.
pub struct PgClientProvider {
    pool: PgPool,
}

impl PgClientProvider {
    /// Creates a new `PostgreSQL` client provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ClientProvider for PgClientProvider {
    async fn create(&self, client: &Client) -> StorageResult<()> {
        let redirect_uris: Vec<String> = hashset_to_vec(&client.redirect_uris);
        let web_origins: Vec<String> = hashset_to_vec(&client.web_origins);
        let attributes = string_map_to_json(&client.attributes);
        let auth_flow_bindings = uuid_map_to_json(&client.auth_flow_bindings);

        sqlx::query(
            r"INSERT INTO clients (
                id, realm_id, client_id, name, description, enabled,
                created_at, updated_at, protocol, secret, public_client, bearer_only,
                client_authenticator_type, consent_required, not_before,
                standard_flow_enabled, implicit_flow_enabled,
                direct_access_grants_enabled, service_accounts_enabled,
                root_url, base_url, admin_url, redirect_uris, web_origins,
                frontchannel_logout, full_scope_allowed, always_display_in_console,
                attributes, auth_flow_bindings
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25, $26, $27, $28, $29
            )",
        )
        .bind(client.id)
        .bind(client.realm_id)
        .bind(&client.client_id)
        .bind(&client.name)
        .bind(&client.description)
        .bind(client.enabled)
        .bind(client.created_at)
        .bind(client.updated_at)
        .bind(protocol_to_string(client.protocol))
        .bind(&client.secret)
        .bind(client.public_client)
        .bind(client.bearer_only)
        .bind(&client.client_authenticator_type)
        .bind(client.consent_required)
        .bind(client.not_before)
        .bind(client.standard_flow_enabled)
        .bind(client.implicit_flow_enabled)
        .bind(client.direct_access_grants_enabled)
        .bind(client.service_accounts_enabled)
        .bind(&client.root_url)
        .bind(&client.base_url)
        .bind(&client.admin_url)
        .bind(sqlx::types::Json(&redirect_uris))
        .bind(sqlx::types::Json(&web_origins))
        .bind(client.frontchannel_logout)
        .bind(client.full_scope_allowed)
        .bind(client.always_display_in_console)
        .bind(sqlx::types::Json(&attributes))
        .bind(sqlx::types::Json(&auth_flow_bindings))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn update(&self, client: &Client) -> StorageResult<()> {
        let redirect_uris: Vec<String> = hashset_to_vec(&client.redirect_uris);
        let web_origins: Vec<String> = hashset_to_vec(&client.web_origins);
        let attributes = string_map_to_json(&client.attributes);
        let auth_flow_bindings = uuid_map_to_json(&client.auth_flow_bindings);

        let result = sqlx::query(
            r"UPDATE clients SET
                client_id = $2, name = $3, description = $4, enabled = $5,
                updated_at = $6, protocol = $7, secret = $8, public_client = $9, bearer_only = $10,
                client_authenticator_type = $11, consent_required = $12, not_before = $13,
                standard_flow_enabled = $14, implicit_flow_enabled = $15,
                direct_access_grants_enabled = $16, service_accounts_enabled = $17,
                root_url = $18, base_url = $19, admin_url = $20, redirect_uris = $21, web_origins = $22,
                frontchannel_logout = $23, full_scope_allowed = $24, always_display_in_console = $25,
                attributes = $26, auth_flow_bindings = $27
            WHERE id = $1 AND realm_id = $28",
        )
        .bind(client.id)
        .bind(&client.client_id)
        .bind(&client.name)
        .bind(&client.description)
        .bind(client.enabled)
        .bind(client.updated_at)
        .bind(protocol_to_string(client.protocol))
        .bind(&client.secret)
        .bind(client.public_client)
        .bind(client.bearer_only)
        .bind(&client.client_authenticator_type)
        .bind(client.consent_required)
        .bind(client.not_before)
        .bind(client.standard_flow_enabled)
        .bind(client.implicit_flow_enabled)
        .bind(client.direct_access_grants_enabled)
        .bind(client.service_accounts_enabled)
        .bind(&client.root_url)
        .bind(&client.base_url)
        .bind(&client.admin_url)
        .bind(sqlx::types::Json(&redirect_uris))
        .bind(sqlx::types::Json(&web_origins))
        .bind(client.frontchannel_logout)
        .bind(client.full_scope_allowed)
        .bind(client.always_display_in_console)
        .bind(sqlx::types::Json(&attributes))
        .bind(sqlx::types::Json(&auth_flow_bindings))
        .bind(client.realm_id)
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Client", client.id));
        }

        Ok(())
    }

    async fn delete(&self, realm_id: Uuid, id: Uuid) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM clients WHERE id = $1 AND realm_id = $2")
            .bind(id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Client", id));
        }

        Ok(())
    }

    async fn get_by_id(&self, realm_id: Uuid, id: Uuid) -> StorageResult<Option<Client>> {
        let row: Option<ClientRow> =
            sqlx::query_as("SELECT * FROM clients WHERE id = $1 AND realm_id = $2")
                .bind(id)
                .bind(realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(row.map(Client::from))
    }

    async fn get_by_client_id(
        &self,
        realm_id: Uuid,
        client_id: &str,
    ) -> StorageResult<Option<Client>> {
        let row: Option<ClientRow> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND client_id = $2")
                .bind(realm_id)
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(row.map(Client::from))
    }

    async fn search(
        &self,
        realm_id: Uuid,
        criteria: &ClientSearchCriteria,
    ) -> StorageResult<Vec<Client>> {
        #[allow(clippy::cast_possible_wrap)]
        let limit = criteria.max_results.unwrap_or(100) as i64;
        #[allow(clippy::cast_possible_wrap)]
        let offset = criteria.offset.unwrap_or(0) as i64;

        let rows: Vec<ClientRow> = if let Some(search) = &criteria.search {
            let pattern = format!("%{search}%");
            sqlx::query_as(
                r"SELECT * FROM clients WHERE realm_id = $1
                AND (client_id ILIKE $2 OR name ILIKE $2)
                ORDER BY client_id LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(&pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else if let Some(client_id) = &criteria.client_id {
            let pattern = format!("{client_id}%");
            sqlx::query_as(
                "SELECT * FROM clients WHERE realm_id = $1 AND client_id LIKE $2 LIMIT $3 OFFSET $4",
            )
            .bind(realm_id)
            .bind(&pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as(
                "SELECT * FROM clients WHERE realm_id = $1 ORDER BY client_id LIMIT $2 OFFSET $3",
            )
            .bind(realm_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Client::from).collect())
    }

    async fn count(&self, realm_id: Uuid) -> StorageResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients WHERE realm_id = $1")
            .bind(realm_id)
            .fetch_one(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }

    async fn list(&self, realm_id: Uuid) -> StorageResult<Vec<Client>> {
        let rows: Vec<ClientRow> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 ORDER BY client_id")
                .bind(realm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Client::from).collect())
    }

    async fn validate_secret(
        &self,
        realm_id: Uuid,
        client_id: &str,
        secret: &str,
    ) -> StorageResult<bool> {
        let row: Option<ClientRow> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND client_id = $2")
                .bind(realm_id)
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(from_sqlx_error)?;

        match row {
            Some(client) => Ok(client.secret.as_deref() == Some(secret)),
            None => Ok(false),
        }
    }

    async fn regenerate_secret(&self, realm_id: Uuid, id: Uuid) -> StorageResult<String> {
        let new_secret = uuid::Uuid::now_v7().to_string();

        let result = sqlx::query("UPDATE clients SET secret = $1 WHERE id = $2 AND realm_id = $3")
            .bind(&new_secret)
            .bind(id)
            .bind(realm_id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Client", id));
        }

        Ok(new_secret)
    }
}
