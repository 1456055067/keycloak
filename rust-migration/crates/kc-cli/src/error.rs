//! CLI error types.

use thiserror::Error;

/// CLI error type.
#[derive(Debug, Error)]
pub enum CliError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// Authentication error.
    #[error("authentication error: {0}")]
    Auth(String),

    /// API error.
    #[error("API error: {status} - {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
    },

    /// Resource not found.
    #[error("{resource_type} not found: {id}")]
    NotFound {
        /// Type of resource.
        resource_type: String,
        /// Resource identifier.
        id: String,
    },

    /// Resource already exists.
    #[error("{resource_type} already exists: {id}")]
    AlreadyExists {
        /// Type of resource.
        resource_type: String,
        /// Resource identifier.
        id: String,
    },

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation cancelled.
    #[error("operation cancelled")]
    Cancelled,
}

/// CLI result type.
pub type CliResult<T> = Result<T, CliError>;
