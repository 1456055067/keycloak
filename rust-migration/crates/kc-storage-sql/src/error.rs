//! SQL storage error types.

use kc_storage::StorageError;
use sqlx::Error as SqlxError;
use uuid::Uuid;

/// Converts a `SQLx` error to a storage error.
#[allow(clippy::needless_pass_by_value)]
pub fn from_sqlx_error(err: SqlxError) -> StorageError {
    match err {
        SqlxError::RowNotFound => {
            // Generic internal error - callers should handle specific not-found cases
            StorageError::Internal("Row not found".to_string())
        }
        SqlxError::Database(db_err) => {
            // Check for unique constraint violation (PostgreSQL error code 23505)
            if db_err.code().is_some_and(|c| c == "23505") {
                StorageError::Internal(format!("Duplicate entry: {}", db_err.message()))
            } else if db_err.code().is_some_and(|c| c == "23503") {
                // Foreign key violation
                StorageError::Internal(format!("Reference violation: {}", db_err.message()))
            } else {
                StorageError::Query(db_err.to_string())
            }
        }
        SqlxError::PoolTimedOut => StorageError::Connection("Connection pool timeout".to_string()),
        SqlxError::PoolClosed => StorageError::Connection("Connection pool closed".to_string()),
        _ => StorageError::Internal(err.to_string()),
    }
}

/// Creates a not found error for the given entity type and ID.
pub const fn not_found(entity_type: &'static str, id: Uuid) -> StorageError {
    StorageError::not_found(entity_type, id)
}

/// Creates a not found by name error for the given entity type and name.
#[allow(dead_code)]
pub fn not_found_by_name(entity_type: &'static str, name: impl Into<String>) -> StorageError {
    StorageError::not_found_by_name(entity_type, name)
}

/// Creates a duplicate error for the given entity.
#[allow(dead_code)]
pub fn duplicate(
    entity_type: &'static str,
    field: &'static str,
    value: impl Into<String>,
) -> StorageError {
    StorageError::duplicate(entity_type, field, value)
}
