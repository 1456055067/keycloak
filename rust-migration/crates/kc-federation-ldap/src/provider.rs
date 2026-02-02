//! LDAP storage provider implementation.
//!
//! ## Security Requirements
//!
//! - All connections use LDAPS (TLS from connection start)
//! - STARTTLS is NOT supported
//! - Plain LDAP is NOT supported
//! - Passwords are never logged

use std::sync::Arc;

use chrono::{DateTime, Utc};
use kc_federation::config::{EditMode, FederationConfig};
use kc_federation::error::FederationResult;
use kc_federation::provider::{CredentialValidator, UserStorageProvider};
use kc_federation::sync::{ImportSynchronization, SyncError, SyncResult};
use kc_model::User;
use uuid::Uuid;

use crate::config::LdapConfig;
use crate::connection::LdapConnectionPool;
use crate::error::LdapResult;
use crate::mapper::LdapUserAttributeMapper;
use crate::search::LdapSearcher;

/// LDAP storage provider.
///
/// Provides user federation with LDAP directories.
///
/// ## Security
///
/// This provider enforces LDAPS-only connections. Any attempt to use
/// plain LDAP or STARTTLS will be rejected.
pub struct LdapStorageProvider {
    /// Provider ID.
    id: Uuid,

    /// Federation configuration.
    federation_config: FederationConfig,

    /// LDAP-specific configuration.
    ldap_config: Arc<LdapConfig>,

    /// Connection pool.
    pool: LdapConnectionPool,

    /// Attribute mapper.
    mapper: LdapUserAttributeMapper,
}

impl LdapStorageProvider {
    /// Creates a new LDAP storage provider.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The connection URL does not use LDAPS
    /// - Configuration validation fails
    pub fn new(
        id: Uuid,
        realm_id: Uuid,
        name: String,
        ldap_config: LdapConfig,
    ) -> LdapResult<Self> {
        // Validate configuration (includes LDAPS check)
        ldap_config.validate()?;

        // Create federation config from LDAP config
        let federation_config = FederationConfig::builder()
            .id(id)
            .realm_id(realm_id)
            .provider_type("ldap")
            .name(name)
            .edit_mode(EditMode::ReadOnly) // Default to read-only for LDAP
            .build();

        let mapper = LdapUserAttributeMapper::new(ldap_config.clone());
        let pool = LdapConnectionPool::new(ldap_config.clone());

        Ok(Self {
            id,
            federation_config,
            ldap_config: Arc::new(ldap_config),
            pool,
            mapper,
        })
    }

    /// Returns the provider ID.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the LDAP configuration.
    #[must_use]
    pub fn ldap_config(&self) -> &LdapConfig {
        &self.ldap_config
    }

    /// Returns the attribute mapper.
    #[must_use]
    pub const fn mapper(&self) -> &LdapUserAttributeMapper {
        &self.mapper
    }

    /// Gets the DN for a username.
    async fn get_user_dn(&self, username: &str) -> LdapResult<Option<String>> {
        let mut conn = self.pool.get().await?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);
        searcher.get_user_dn(username).await
    }
}

impl UserStorageProvider for LdapStorageProvider {
    fn config(&self) -> &FederationConfig {
        &self.federation_config
    }

    fn provider_type(&self) -> &'static str {
        "ldap"
    }

    async fn validate_config(&self) -> FederationResult<()> {
        self.ldap_config.validate().map_err(Into::into)
    }

    async fn test_connection(&self) -> FederationResult<()> {
        self.pool.test_connection().await.map_err(Into::into)
    }

    async fn get_user_by_external_id(
        &self,
        realm_id: Uuid,
        external_id: &str,
    ) -> FederationResult<Option<User>> {
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        let entry = searcher
            .find_user_by_external_id(external_id)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        Ok(entry.map(|e| self.mapper.map_to_user(realm_id, &e, &self.id.to_string())))
    }

    async fn get_user_by_username(
        &self,
        realm_id: Uuid,
        username: &str,
    ) -> FederationResult<Option<User>> {
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        let entry = searcher
            .find_user_by_username(username)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        Ok(entry.map(|e| self.mapper.map_to_user(realm_id, &e, &self.id.to_string())))
    }

    async fn get_user_by_email(
        &self,
        realm_id: Uuid,
        email: &str,
    ) -> FederationResult<Option<User>> {
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        let entry = searcher
            .find_user_by_email(email)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        Ok(entry.map(|e| self.mapper.map_to_user(realm_id, &e, &self.id.to_string())))
    }

    async fn search_users(
        &self,
        realm_id: Uuid,
        query: &str,
        first: usize,
        max: usize,
    ) -> FederationResult<Vec<User>> {
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        // Build search filter for query
        let username_attr = self.ldap_config.username_attribute.as_str();
        let email_attr = &self.ldap_config.email_attribute;
        let first_name_attr = &self.ldap_config.first_name_attribute;
        let last_name_attr = &self.ldap_config.last_name_attribute;

        let query_filter = format!(
            "(|({username_attr}=*{query}*)({email_attr}=*{query}*)({first_name_attr}=*{query}*)({last_name_attr}=*{query}*))"
        );

        let base_filter = self.ldap_config.user_search_filter();
        let filter = format!("(&{base_filter}{query_filter})");

        let entries = searcher
            .search_users(&filter, first, max)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        let users = entries
            .into_iter()
            .map(|e| self.mapper.map_to_user(realm_id, &e, &self.id.to_string()))
            .collect();

        Ok(users)
    }

    async fn count_users(
        &self,
        _realm_id: Uuid,
        query: Option<&str>,
    ) -> FederationResult<usize> {
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        let filter = query.map(|q| {
            let username_attr = self.ldap_config.username_attribute.as_str();
            format!("({username_attr}=*{q}*)")
        });

        searcher
            .count_users(filter.as_deref())
            .await
            .map_err(Into::into)
    }
}

impl CredentialValidator for LdapStorageProvider {
    /// Validates a password by performing an LDAP bind.
    ///
    /// ## Security
    ///
    /// - The password is NEVER logged
    /// - Connection uses LDAPS (encrypted from start)
    /// - The connection is discarded after use (not returned to pool)
    async fn validate_password(
        &self,
        _realm_id: Uuid,
        username: &str,
        password: &str,
    ) -> FederationResult<bool> {
        // Get user DN
        let user_dn = match self.get_user_dn(username).await.map_err(Into::<kc_federation::FederationError>::into)? {
            Some(dn) => dn,
            None => return Ok(false),
        };

        // Get a connection for authentication
        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;

        // Attempt bind with user credentials
        let result = conn
            .authenticate_user(&user_dn, password)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        // Discard connection (it's now bound as the user)
        conn.discard().await;

        Ok(result)
    }

    fn supports_password_validation(&self) -> bool {
        true
    }
}

impl ImportSynchronization for LdapStorageProvider {
    async fn sync_full(&self, realm_id: Uuid) -> FederationResult<SyncResult> {
        let started_at = Utc::now();
        let mut result = SyncResult::new(started_at);

        let mut conn = self.pool.get().await.map_err(Into::<kc_federation::FederationError>::into)?;
        let mut searcher = LdapSearcher::new(&mut conn, &self.ldap_config);

        // Search all users
        let filter = self.ldap_config.user_search_filter();
        let entries = searcher
            .search_users(&filter, 0, self.ldap_config.max_results)
            .await
            .map_err(Into::<kc_federation::FederationError>::into)?;

        for entry in entries {
            let external_id = match entry.external_id(&self.ldap_config.uuid_attribute) {
                Some(id) => id,
                None => {
                    result.record_failure(SyncError::new(
                        entry.dn.clone(),
                        "Missing external ID attribute",
                    ));
                    continue;
                }
            };

            // Map to user (in a real implementation, we'd check if user exists
            // and create/update accordingly)
            let _user = self.mapper.map_to_user(realm_id, &entry, &self.id.to_string());

            // For now, just count as added
            // In a real implementation, this would interact with UserProvider
            result.record_added();

            tracing::debug!(
                external_id = %external_id,
                dn = %entry.dn,
                "Synced user from LDAP"
            );
        }

        Ok(result.complete())
    }

    async fn sync_changed(
        &self,
        realm_id: Uuid,
        _last_sync: DateTime<Utc>,
    ) -> FederationResult<SyncResult> {
        // Changed sync requires LDAP server support for modifyTimestamp
        // For simplicity, delegate to full sync
        self.sync_full(realm_id).await
    }

    fn supports_changed_sync(&self) -> bool {
        // Could be enabled for LDAP servers that support modifyTimestamp
        false
    }

    async fn last_sync_time(&self, _realm_id: Uuid) -> FederationResult<Option<DateTime<Utc>>> {
        // Would need to be stored in database
        Ok(None)
    }

    async fn remove_orphans(&self, _realm_id: Uuid) -> FederationResult<usize> {
        // Would need to compare LDAP users with local storage
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_creation_requires_ldaps() {
        let ldap_config = LdapConfig::builder()
            .connection_url("ldap://ldap.example.com:389") // NOT LDAPS
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build();

        // Should fail because it's not LDAPS
        assert!(ldap_config.is_err());
    }

    #[test]
    fn provider_accepts_ldaps() {
        let ldap_config = LdapConfig::builder()
            .connection_url("ldaps://ldap.example.com:636")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .build();

        assert!(ldap_config.is_ok());

        let config = ldap_config.unwrap();
        let provider = LdapStorageProvider::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "Test LDAP".to_string(),
            config,
        );

        assert!(provider.is_ok());
    }
}
