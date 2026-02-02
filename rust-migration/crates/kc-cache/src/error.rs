//! Cache error types.

use std::fmt;

/// Cache operation errors.
#[derive(Debug)]
pub enum CacheError {
    /// Connection to cache backend failed.
    Connection(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Key not found in cache.
    NotFound,
    /// Cache operation timed out.
    Timeout,
    /// Invalid cache configuration.
    Configuration(String),
    /// Internal cache error.
    Internal(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "cache connection error: {msg}"),
            Self::Serialization(msg) => write!(f, "cache serialization error: {msg}"),
            Self::NotFound => write!(f, "key not found in cache"),
            Self::Timeout => write!(f, "cache operation timed out"),
            Self::Configuration(msg) => write!(f, "cache configuration error: {msg}"),
            Self::Internal(msg) => write!(f, "internal cache error: {msg}"),
        }
    }
}

impl std::error::Error for CacheError {}

/// Result type for cache operations.
pub type CacheResult<T> = Result<T, CacheError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = CacheError::NotFound;
        assert_eq!(err.to_string(), "key not found in cache");

        let err = CacheError::Connection("refused".to_string());
        assert!(err.to_string().contains("refused"));
    }
}
