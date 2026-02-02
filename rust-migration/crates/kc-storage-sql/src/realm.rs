//! `PostgreSQL` implementation of the realm storage provider.

use async_trait::async_trait;
use kc_model::Realm;
use kc_storage::RealmProvider;
use kc_storage::error::StorageResult;
use sqlx::PgPool;
use uuid::Uuid;

use crate::convert::{hashset_to_vec, ssl_required_to_string, string_map_to_json};
use crate::entities::RealmRow;
use crate::error::{from_sqlx_error, not_found};

/// `PostgreSQL` realm storage provider.
pub struct PgRealmProvider {
    pool: PgPool,
}

impl PgRealmProvider {
    /// Creates a new `PostgreSQL` realm provider.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RealmProvider for PgRealmProvider {
    async fn create(&self, realm: &Realm) -> StorageResult<()> {
        let otp_policy = serde_json::to_value(&realm.otp_policy)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()));
        let events_listeners: Vec<String> = hashset_to_vec(&realm.events_listeners);
        let enabled_event_types: Vec<String> = hashset_to_vec(&realm.enabled_event_types);
        let supported_locales: Vec<String> = hashset_to_vec(&realm.supported_locales);
        let default_groups: Vec<Uuid> = hashset_to_vec(&realm.default_groups);
        let smtp_config = string_map_to_json(&realm.smtp_config);
        let attributes = string_map_to_json(&realm.attributes);

        sqlx::query(
            r"INSERT INTO realms (
                id, name, display_name, enabled, created_at, updated_at,
                ssl_required, password_policy, otp_policy, not_before,
                registration_allowed, registration_email_as_username, verify_email,
                reset_password_allowed, login_with_email_allowed, duplicate_emails_allowed,
                remember_me, edit_username_allowed,
                access_token_lifespan, access_token_lifespan_implicit,
                access_code_lifespan, access_code_lifespan_user_action, access_code_lifespan_login,
                sso_session_idle_timeout, sso_session_max_lifespan,
                sso_session_idle_timeout_remember_me, sso_session_max_lifespan_remember_me,
                offline_session_idle_timeout, offline_session_max_lifespan,
                login_theme, account_theme, admin_theme, email_theme,
                events_enabled, events_expiration, admin_events_enabled, admin_events_details_enabled,
                events_listeners, enabled_event_types,
                internationalization_enabled, default_locale, supported_locales,
                browser_flow, registration_flow, direct_grant_flow,
                reset_credentials_flow, client_authentication_flow,
                default_role_id, default_groups, smtp_config, attributes
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
                $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
                $41, $42, $43, $44, $45, $46, $47, $48, $49, $50
            )",
        )
        .bind(realm.id)
        .bind(&realm.name)
        .bind(&realm.display_name)
        .bind(realm.enabled)
        .bind(realm.created_at)
        .bind(realm.updated_at)
        .bind(ssl_required_to_string(realm.ssl_required))
        .bind(&realm.password_policy)
        .bind(sqlx::types::Json(&otp_policy))
        .bind(realm.not_before)
        .bind(realm.registration_allowed)
        .bind(realm.registration_email_as_username)
        .bind(realm.verify_email)
        .bind(realm.reset_password_allowed)
        .bind(realm.login_with_email_allowed)
        .bind(realm.duplicate_emails_allowed)
        .bind(realm.remember_me)
        .bind(realm.edit_username_allowed)
        .bind(realm.access_token_lifespan)
        .bind(realm.access_token_lifespan_implicit)
        .bind(realm.access_code_lifespan)
        .bind(realm.access_code_lifespan_user_action)
        .bind(realm.access_code_lifespan_login)
        .bind(realm.sso_session_idle_timeout)
        .bind(realm.sso_session_max_lifespan)
        .bind(realm.sso_session_idle_timeout_remember_me)
        .bind(realm.sso_session_max_lifespan_remember_me)
        .bind(realm.offline_session_idle_timeout)
        .bind(realm.offline_session_max_lifespan)
        .bind(&realm.login_theme)
        .bind(&realm.account_theme)
        .bind(&realm.admin_theme)
        .bind(&realm.email_theme)
        .bind(realm.events_enabled)
        .bind(realm.events_expiration)
        .bind(realm.admin_events_enabled)
        .bind(realm.admin_events_details_enabled)
        .bind(sqlx::types::Json(&events_listeners))
        .bind(sqlx::types::Json(&enabled_event_types))
        .bind(realm.internationalization_enabled)
        .bind(&realm.default_locale)
        .bind(sqlx::types::Json(&supported_locales))
        .bind(realm.browser_flow)
        .bind(realm.registration_flow)
        .bind(realm.direct_grant_flow)
        .bind(realm.reset_credentials_flow)
        .bind(realm.client_authentication_flow)
        .bind(realm.default_role_id)
        .bind(sqlx::types::Json(&default_groups))
        .bind(sqlx::types::Json(&smtp_config))
        .bind(sqlx::types::Json(&attributes))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        Ok(())
    }

    async fn update(&self, realm: &Realm) -> StorageResult<()> {
        let otp_policy = serde_json::to_value(&realm.otp_policy)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::default()));
        let events_listeners: Vec<String> = hashset_to_vec(&realm.events_listeners);
        let enabled_event_types: Vec<String> = hashset_to_vec(&realm.enabled_event_types);
        let supported_locales: Vec<String> = hashset_to_vec(&realm.supported_locales);
        let default_groups: Vec<Uuid> = hashset_to_vec(&realm.default_groups);
        let smtp_config = string_map_to_json(&realm.smtp_config);
        let attributes = string_map_to_json(&realm.attributes);

        let result = sqlx::query(
            r"UPDATE realms SET
                name = $2, display_name = $3, enabled = $4, updated_at = $5,
                ssl_required = $6, password_policy = $7, otp_policy = $8, not_before = $9,
                registration_allowed = $10, registration_email_as_username = $11, verify_email = $12,
                reset_password_allowed = $13, login_with_email_allowed = $14, duplicate_emails_allowed = $15,
                remember_me = $16, edit_username_allowed = $17,
                access_token_lifespan = $18, access_token_lifespan_implicit = $19,
                access_code_lifespan = $20, access_code_lifespan_user_action = $21, access_code_lifespan_login = $22,
                sso_session_idle_timeout = $23, sso_session_max_lifespan = $24,
                sso_session_idle_timeout_remember_me = $25, sso_session_max_lifespan_remember_me = $26,
                offline_session_idle_timeout = $27, offline_session_max_lifespan = $28,
                login_theme = $29, account_theme = $30, admin_theme = $31, email_theme = $32,
                events_enabled = $33, events_expiration = $34, admin_events_enabled = $35, admin_events_details_enabled = $36,
                events_listeners = $37, enabled_event_types = $38,
                internationalization_enabled = $39, default_locale = $40, supported_locales = $41,
                browser_flow = $42, registration_flow = $43, direct_grant_flow = $44,
                reset_credentials_flow = $45, client_authentication_flow = $46,
                default_role_id = $47, default_groups = $48, smtp_config = $49, attributes = $50
            WHERE id = $1",
        )
        .bind(realm.id)
        .bind(&realm.name)
        .bind(&realm.display_name)
        .bind(realm.enabled)
        .bind(realm.updated_at)
        .bind(ssl_required_to_string(realm.ssl_required))
        .bind(&realm.password_policy)
        .bind(sqlx::types::Json(&otp_policy))
        .bind(realm.not_before)
        .bind(realm.registration_allowed)
        .bind(realm.registration_email_as_username)
        .bind(realm.verify_email)
        .bind(realm.reset_password_allowed)
        .bind(realm.login_with_email_allowed)
        .bind(realm.duplicate_emails_allowed)
        .bind(realm.remember_me)
        .bind(realm.edit_username_allowed)
        .bind(realm.access_token_lifespan)
        .bind(realm.access_token_lifespan_implicit)
        .bind(realm.access_code_lifespan)
        .bind(realm.access_code_lifespan_user_action)
        .bind(realm.access_code_lifespan_login)
        .bind(realm.sso_session_idle_timeout)
        .bind(realm.sso_session_max_lifespan)
        .bind(realm.sso_session_idle_timeout_remember_me)
        .bind(realm.sso_session_max_lifespan_remember_me)
        .bind(realm.offline_session_idle_timeout)
        .bind(realm.offline_session_max_lifespan)
        .bind(&realm.login_theme)
        .bind(&realm.account_theme)
        .bind(&realm.admin_theme)
        .bind(&realm.email_theme)
        .bind(realm.events_enabled)
        .bind(realm.events_expiration)
        .bind(realm.admin_events_enabled)
        .bind(realm.admin_events_details_enabled)
        .bind(sqlx::types::Json(&events_listeners))
        .bind(sqlx::types::Json(&enabled_event_types))
        .bind(realm.internationalization_enabled)
        .bind(&realm.default_locale)
        .bind(sqlx::types::Json(&supported_locales))
        .bind(realm.browser_flow)
        .bind(realm.registration_flow)
        .bind(realm.direct_grant_flow)
        .bind(realm.reset_credentials_flow)
        .bind(realm.client_authentication_flow)
        .bind(realm.default_role_id)
        .bind(sqlx::types::Json(&default_groups))
        .bind(sqlx::types::Json(&smtp_config))
        .bind(sqlx::types::Json(&attributes))
        .execute(&self.pool)
        .await
        .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Realm", realm.id));
        }

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM realms WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(not_found("Realm", id));
        }

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<Realm>> {
        let row: Option<RealmRow> = sqlx::query_as("SELECT * FROM realms WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(row.map(Realm::from))
    }

    async fn get_by_name(&self, name: &str) -> StorageResult<Option<Realm>> {
        let row: Option<RealmRow> = sqlx::query_as("SELECT * FROM realms WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(row.map(Realm::from))
    }

    async fn list(&self) -> StorageResult<Vec<Realm>> {
        let rows: Vec<RealmRow> = sqlx::query_as("SELECT * FROM realms ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(Realm::from).collect())
    }

    async fn list_names(&self) -> StorageResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT name FROM realms ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    async fn count(&self) -> StorageResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM realms")
            .fetch_one(&self.pool)
            .await
            .map_err(from_sqlx_error)?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }
}
