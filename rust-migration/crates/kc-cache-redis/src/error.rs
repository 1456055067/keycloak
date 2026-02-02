//! Redis cache error conversion.

use kc_cache::CacheError;

/// Converts a `fred` Redis error to a `CacheError`.
#[allow(clippy::needless_pass_by_value)]
pub fn from_redis_error(err: fred::error::Error) -> CacheError {
    match err.kind() {
        fred::error::ErrorKind::IO | fred::error::ErrorKind::Timeout => {
            CacheError::Connection(err.to_string())
        }
        fred::error::ErrorKind::Config => CacheError::Configuration(err.to_string()),
        _ => CacheError::Internal(err.to_string()),
    }
}

/// Converts a serialization error to a `CacheError`.
#[allow(clippy::needless_pass_by_value)]
pub fn from_serde_error(err: serde_json::Error) -> CacheError {
    CacheError::Serialization(err.to_string())
}
