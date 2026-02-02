//! Synchronization support for federation providers.
//!
//! Provides traits and types for bulk import and periodic synchronization
//! of users from external identity stores.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::FederationResult;

// ============================================================================
// Sync Mode
// ============================================================================

/// Synchronization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncMode {
    /// Full sync - import all users from external store.
    Full,

    /// Changed sync - import only users changed since last sync.
    Changed,
}

// ============================================================================
// Sync Results
// ============================================================================

/// Result of a synchronization operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Number of users added.
    pub added: usize,

    /// Number of users updated.
    pub updated: usize,

    /// Number of users removed.
    pub removed: usize,

    /// Number of users that failed to sync.
    pub failed: usize,

    /// When the sync started.
    pub started_at: DateTime<Utc>,

    /// When the sync completed.
    pub completed_at: DateTime<Utc>,

    /// Status message.
    pub status: String,

    /// Errors encountered (if any).
    pub errors: Vec<SyncError>,
}

impl SyncResult {
    /// Creates a new sync result.
    #[must_use]
    pub fn new(started_at: DateTime<Utc>) -> Self {
        Self {
            added: 0,
            updated: 0,
            removed: 0,
            failed: 0,
            started_at,
            completed_at: Utc::now(),
            status: String::new(),
            errors: Vec::new(),
        }
    }

    /// Marks the sync as complete.
    #[must_use]
    pub fn complete(mut self) -> Self {
        self.completed_at = Utc::now();
        self.status = format!(
            "Sync completed: {} added, {} updated, {} removed, {} failed",
            self.added, self.updated, self.removed, self.failed
        );
        self
    }

    /// Records a user addition.
    pub fn record_added(&mut self) {
        self.added += 1;
    }

    /// Records a user update.
    pub fn record_updated(&mut self) {
        self.updated += 1;
    }

    /// Records a user removal.
    pub fn record_removed(&mut self) {
        self.removed += 1;
    }

    /// Records a sync failure.
    pub fn record_failure(&mut self, error: SyncError) {
        self.failed += 1;
        self.errors.push(error);
    }

    /// Returns the total number of users processed.
    #[must_use]
    pub fn total(&self) -> usize {
        self.added + self.updated + self.removed + self.failed
    }

    /// Returns true if the sync had any errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Error encountered during sync for a specific user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncError {
    /// External user ID.
    pub external_id: String,

    /// Username (if available).
    pub username: Option<String>,

    /// Error message.
    pub message: String,
}

impl SyncError {
    /// Creates a new sync error.
    #[must_use]
    pub fn new(external_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            external_id: external_id.into(),
            username: None,
            message: message.into(),
        }
    }

    /// Sets the username.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
}

/// Result of a full sync operation.
pub type FullSyncResult = SyncResult;

/// Result of a changed-only sync operation.
pub type ChangedSyncResult = SyncResult;

// ============================================================================
// Import Synchronization Trait
// ============================================================================

/// Trait for providers that support bulk import/sync.
///
/// This trait extends the base UserStorageProvider with synchronization
/// capabilities for bulk importing users from external stores.
#[allow(async_fn_in_trait)]
pub trait ImportSynchronization: Send + Sync {
    /// Performs a full synchronization.
    ///
    /// Imports all users from the external store, creating new users
    /// and updating existing ones.
    async fn sync_full(&self, realm_id: Uuid) -> FederationResult<FullSyncResult>;

    /// Performs a changed-only synchronization.
    ///
    /// Imports only users that have changed since the last sync.
    /// Uses the provider's change tracking mechanism (e.g., LDAP modifyTimestamp).
    async fn sync_changed(
        &self,
        realm_id: Uuid,
        last_sync: DateTime<Utc>,
    ) -> FederationResult<ChangedSyncResult>;

    /// Returns true if the provider supports changed-only sync.
    fn supports_changed_sync(&self) -> bool {
        false
    }

    /// Returns the timestamp of the last successful sync.
    async fn last_sync_time(&self, realm_id: Uuid) -> FederationResult<Option<DateTime<Utc>>>;

    /// Removes users that no longer exist in the external store.
    ///
    /// Called during full sync to clean up orphaned users.
    async fn remove_orphans(&self, realm_id: Uuid) -> FederationResult<usize>;
}

// ============================================================================
// Sync Scheduler
// ============================================================================

/// Configuration for periodic synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncScheduleConfig {
    /// Provider ID.
    pub provider_id: Uuid,

    /// Whether periodic full sync is enabled.
    pub full_sync_enabled: bool,

    /// Full sync period in seconds.
    pub full_sync_period_secs: u64,

    /// Whether periodic changed sync is enabled.
    pub changed_sync_enabled: bool,

    /// Changed sync period in seconds.
    pub changed_sync_period_secs: u64,
}

impl Default for SyncScheduleConfig {
    fn default() -> Self {
        Self {
            provider_id: Uuid::nil(),
            full_sync_enabled: false,
            full_sync_period_secs: 86400, // 1 day
            changed_sync_enabled: false,
            changed_sync_period_secs: 3600, // 1 hour
        }
    }
}

impl SyncScheduleConfig {
    /// Creates a new sync schedule config.
    #[must_use]
    pub const fn new(provider_id: Uuid) -> Self {
        Self {
            provider_id,
            full_sync_enabled: false,
            full_sync_period_secs: 86400,
            changed_sync_enabled: false,
            changed_sync_period_secs: 3600,
        }
    }

    /// Enables full sync with the given period.
    #[must_use]
    pub const fn with_full_sync(mut self, period_secs: u64) -> Self {
        self.full_sync_enabled = true;
        self.full_sync_period_secs = period_secs;
        self
    }

    /// Enables changed sync with the given period.
    #[must_use]
    pub const fn with_changed_sync(mut self, period_secs: u64) -> Self {
        self.changed_sync_enabled = true;
        self.changed_sync_period_secs = period_secs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_result_tracking() {
        let mut result = SyncResult::new(Utc::now());

        result.record_added();
        result.record_added();
        result.record_updated();
        result.record_failure(SyncError::new("ext-123", "Invalid email"));

        assert_eq!(result.added, 2);
        assert_eq!(result.updated, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.total(), 4);
        assert!(result.has_errors());
    }

    #[test]
    fn sync_schedule_config() {
        let provider_id = Uuid::now_v7();
        let config = SyncScheduleConfig::new(provider_id)
            .with_full_sync(43200) // 12 hours
            .with_changed_sync(1800); // 30 minutes

        assert!(config.full_sync_enabled);
        assert_eq!(config.full_sync_period_secs, 43200);
        assert!(config.changed_sync_enabled);
        assert_eq!(config.changed_sync_period_secs, 1800);
    }
}
