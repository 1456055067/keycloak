//! Storage error types.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Entity not found.
    #[error("Entity not found: {entity_type} with id {id}")]
    NotFound {
        /// Type of entity (e.g., "User", "Realm").
        entity_type: &'static str,
        /// Entity ID.
        id: Uuid,
    },

    /// Entity not found by name.
    #[error("Entity not found: {entity_type} with name '{name}'")]
    NotFoundByName {
        /// Type of entity.
        entity_type: &'static str,
        /// Entity name.
        name: String,
    },

    /// Duplicate entity (unique constraint violation).
    #[error("Duplicate {entity_type}: {field} '{value}' already exists")]
    Duplicate {
        /// Type of entity.
        entity_type: &'static str,
        /// Field that caused the conflict.
        field: &'static str,
        /// Conflicting value.
        value: String,
    },

    /// Invalid data.
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Database connection error.
    #[error("Database connection error: {0}")]
    Connection(String),

    /// Database query error.
    #[error("Database query error: {0}")]
    Query(String),

    /// Transaction error.
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal error.
    #[error("Internal storage error: {0}")]
    Internal(String),
}

impl StorageError {
    /// Creates a not found error for an entity.
    #[must_use]
    pub const fn not_found(entity_type: &'static str, id: Uuid) -> Self {
        Self::NotFound { entity_type, id }
    }

    /// Creates a not found by name error.
    #[must_use]
    pub fn not_found_by_name(entity_type: &'static str, name: impl Into<String>) -> Self {
        Self::NotFoundByName {
            entity_type,
            name: name.into(),
        }
    }

    /// Creates a duplicate error.
    #[must_use]
    pub fn duplicate(
        entity_type: &'static str,
        field: &'static str,
        value: impl Into<String>,
    ) -> Self {
        Self::Duplicate {
            entity_type,
            field,
            value: value.into(),
        }
    }

    /// Checks if this is a not found error.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. } | Self::NotFoundByName { .. })
    }

    /// Checks if this is a duplicate error.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate { .. })
    }
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_error() {
        let id = Uuid::now_v7();
        let err = StorageError::not_found("User", id);

        assert!(err.is_not_found());
        assert!(!err.is_duplicate());
        assert!(err.to_string().contains("User"));
    }

    #[test]
    fn duplicate_error() {
        let err = StorageError::duplicate("User", "username", "john");

        assert!(err.is_duplicate());
        assert!(!err.is_not_found());
        assert!(err.to_string().contains("john"));
    }
}
