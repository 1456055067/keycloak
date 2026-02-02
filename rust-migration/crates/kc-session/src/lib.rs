//! # kc-session
//!
//! Session management for Keycloak Rust.
//!
//! This crate handles user sessions (SSO sessions) and client sessions
//! (per-client authentication state within a user session).
//!
//! ## Session Types
//!
//! - [`UserSession`] - Represents an authenticated user's SSO session
//! - [`ClientSession`] - Represents authentication state with a specific client
//! - [`AuthenticationSession`] - Temporary session during authentication flow
//!
//! ## Session Lifecycle
//!
//! 1. User initiates authentication → `AuthenticationSession` created
//! 2. Authentication succeeds → `UserSession` created
//! 3. User accesses client → `ClientSession` created within `UserSession`
//! 4. Session expires or user logs out → Sessions invalidated

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod auth_session;
pub mod client_session;
pub mod error;
pub mod provider;
pub mod user_session;

pub use auth_session::AuthenticationSession;
pub use client_session::ClientSession;
pub use error::SessionError;
pub use provider::SessionProvider;
pub use user_session::{SessionState, UserSession};
