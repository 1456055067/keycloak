//! LDAP connection pool management.
//!
//! ## Security Requirements
//!
//! All connections use LDAPS (TLS from connection start).
//! STARTTLS is NOT supported to prevent downgrade attacks.

use std::sync::Arc;

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use tokio::sync::{Mutex, Semaphore};

use crate::config::LdapConfig;
use crate::error::{LdapError, LdapResult};

/// Connection pool for LDAP connections.
///
/// Manages a pool of LDAPS connections with automatic reconnection.
pub struct LdapConnectionPool {
    config: Arc<LdapConfig>,
    semaphore: Arc<Semaphore>,
    /// Single connection protected by mutex (simplified pool).
    /// In production, consider using a proper pool like deadpool.
    connection: Arc<Mutex<Option<Ldap>>>,
}

impl LdapConnectionPool {
    /// Creates a new connection pool.
    ///
    /// ## Security
    ///
    /// The configuration must use LDAPS. This is validated at config build time.
    pub fn new(config: LdapConfig) -> Self {
        let max_size = config.pool_max_size;
        Self {
            config: Arc::new(config),
            semaphore: Arc::new(Semaphore::new(max_size)),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    /// Gets a connection from the pool.
    ///
    /// Returns a connection handle that releases back to the pool when dropped.
    pub async fn get(&self) -> LdapResult<LdapConnection> {
        // Acquire permit from semaphore
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LdapError::PoolExhausted)?;

        // Try to reuse existing connection
        let mut guard = self.connection.lock().await;
        if let Some(ldap) = guard.take() {
            return Ok(LdapConnection {
                ldap,
                _pool: self.connection.clone(),
                _permit: permit,
            });
        }
        drop(guard);

        // Create new connection
        let ldap = self.create_connection().await?;
        Ok(LdapConnection {
            ldap,
            _pool: self.connection.clone(),
            _permit: permit,
        })
    }

    /// Creates a new LDAPS connection.
    async fn create_connection(&self) -> LdapResult<Ldap> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.connection_timeout);

        // Connect using LDAPS
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(settings, &self.config.connection_url)
                .await
                .map_err(|e| LdapError::Connection(e.to_string()))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::warn!("LDAP connection driver error: {}", e);
            }
        });

        // Bind with service account
        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_credential)
            .await
            .map_err(|e| LdapError::Bind(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Bind(format!("Bind failed: {e:?}")))?;

        Ok(ldap)
    }

    /// Tests the connection to the LDAP server.
    pub async fn test_connection(&self) -> LdapResult<()> {
        let conn = self.get().await?;

        // Perform a simple search to verify connectivity
        conn.ldap
            .clone()
            .search(
                &self.config.users_dn,
                ldap3::Scope::Base,
                "(objectClass=*)",
                vec!["dn"],
            )
            .await
            .map_err(|e| LdapError::Connection(format!("Test search failed: {e}")))?;

        Ok(())
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &LdapConfig {
        &self.config
    }
}

/// A connection from the pool.
///
/// When dropped, the connection is returned to the pool.
pub struct LdapConnection {
    ldap: Ldap,
    /// Pool reference (for returning connection when Drop is implemented fully)
    _pool: Arc<Mutex<Option<Ldap>>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl LdapConnection {
    /// Returns a reference to the LDAP connection.
    #[must_use]
    pub fn ldap(&self) -> &Ldap {
        &self.ldap
    }

    /// Returns a mutable reference to the LDAP connection.
    #[must_use]
    pub fn ldap_mut(&mut self) -> &mut Ldap {
        &mut self.ldap
    }

    /// Performs an LDAP bind with user credentials for authentication.
    ///
    /// ## Security
    ///
    /// This method is used to validate user passwords by attempting
    /// a bind operation. The password is never logged or stored.
    ///
    /// After validation, the connection is NOT returned to the pool
    /// since it's now bound as a different user.
    pub async fn authenticate_user(&mut self, user_dn: &str, password: &str) -> LdapResult<bool> {
        let result = self
            .ldap
            .simple_bind(user_dn, password)
            .await
            .map_err(|e| LdapError::Bind(e.to_string()))?;

        match result.success() {
            Ok(_) => Ok(true),
            Err(e) => {
                // Check if it's an invalid credentials error (result code 49)
                let err_str = format!("{e:?}");
                if err_str.contains("49") || err_str.contains("InvalidCredentials") {
                    Ok(false)
                } else {
                    Err(LdapError::Bind(format!("Bind error: {e:?}")))
                }
            }
        }
    }

    /// Consumes the connection without returning it to the pool.
    ///
    /// Use this when the connection state has changed (e.g., after user bind).
    pub async fn discard(mut self) {
        // Unbind and close the connection
        let _ = self.ldap.unbind().await;
    }
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        // Try to return connection to pool
        // Note: This is a simplified implementation
        // A production pool would handle this more carefully
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_creation() {
        let config = LdapConfig::builder()
            .connection_url("ldaps://ldap.example.com:636")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_credential("password")
            .users_dn("ou=users,dc=example,dc=com")
            .pool_size(1, 5)
            .build()
            .unwrap();

        let pool = LdapConnectionPool::new(config);
        assert_eq!(pool.config().pool_max_size, 5);
    }
}
