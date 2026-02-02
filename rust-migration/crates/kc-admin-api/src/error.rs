//! Admin API error types.
//!
//! Provides structured error handling for the Admin REST API,
//! mapping internal errors to appropriate HTTP responses.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur in the Admin API.
#[derive(Debug, Error)]
pub enum AdminError {
    /// Resource not found.
    #[error("{entity_type} not found: {id}")]
    NotFound {
        /// Type of entity (e.g., "Realm", "User").
        entity_type: &'static str,
        /// Resource identifier.
        id: String,
    },

    /// Duplicate resource (unique constraint violation).
    #[error("{entity_type} already exists: {field} '{value}'")]
    Conflict {
        /// Type of entity.
        entity_type: &'static str,
        /// Field that caused the conflict.
        field: &'static str,
        /// Conflicting value.
        value: String,
    },

    /// Invalid request data.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication required.
    #[error("Authentication required")]
    Unauthorized,

    /// Insufficient permissions.
    #[error("Access denied: {0}")]
    Forbidden(String),

    /// Storage layer error.
    #[error("Storage error: {0}")]
    Storage(#[from] kc_storage::StorageError),

    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AdminError {
    /// Creates a not found error.
    #[must_use]
    pub fn not_found(entity_type: &'static str, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity_type,
            id: id.into(),
        }
    }

    /// Creates a not found error for a UUID.
    #[must_use]
    pub fn not_found_id(entity_type: &'static str, id: Uuid) -> Self {
        Self::NotFound {
            entity_type,
            id: id.to_string(),
        }
    }

    /// Creates a conflict error.
    #[must_use]
    pub fn conflict(
        entity_type: &'static str,
        field: &'static str,
        value: impl Into<String>,
    ) -> Self {
        Self::Conflict {
            entity_type,
            field,
            value: value.into(),
        }
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Storage(err) => match err {
                kc_storage::StorageError::NotFound { .. }
                | kc_storage::StorageError::NotFoundByName { .. } => StatusCode::NOT_FOUND,
                kc_storage::StorageError::Duplicate { .. } => StatusCode::CONFLICT,
                kc_storage::StorageError::InvalidData(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the error code for API responses.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::Conflict { .. } => "conflict",
            Self::BadRequest(_) => "bad_request",
            Self::Validation(_) => "validation_error",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::Storage(_) => "storage_error",
            Self::Internal(_) => "internal_error",
        }
    }
}

/// API error response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code for programmatic handling.
    pub error: String,
    /// Human-readable error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// Additional error details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            error: self.error_code().to_string(),
            error_description: Some(self.to_string()),
            details: None,
        };
        (status, Json(body)).into_response()
    }
}

/// Result type for Admin API operations.
pub type AdminResult<T> = Result<T, AdminError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_error() {
        let err = AdminError::not_found("Realm", "test-realm");
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(err.error_code(), "not_found");
        assert!(err.to_string().contains("Realm"));
        assert!(err.to_string().contains("test-realm"));
    }

    #[test]
    fn conflict_error() {
        let err = AdminError::conflict("User", "username", "john");
        assert_eq!(err.status_code(), StatusCode::CONFLICT);
        assert_eq!(err.error_code(), "conflict");
    }

    #[test]
    fn storage_error_mapping() {
        let storage_err =
            kc_storage::StorageError::not_found("User", Uuid::nil());
        let admin_err = AdminError::from(storage_err);
        assert_eq!(admin_err.status_code(), StatusCode::NOT_FOUND);
    }
}
