//! # kc-auth
//!
//! Authentication engine for Keycloak Rust.
//!
//! This crate implements authentication flows, credential management,
//! and authenticator plugins.
//!
//! ## Features
//!
//! - Type-safe authentication flow state machine
//! - Argon2id password hashing (NIST SP 800-63B compliant)
//! - TOTP/HOTP one-time password verification
//! - Pluggable authenticator architecture
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management
//! - AC-7: Unsuccessful Logon Attempts
//!
//! ## Example
//!
//! ```ignore
//! use kc_auth::{FlowContext, PasswordHasherService};
//! use uuid::Uuid;
//!
//! // Password hashing
//! let hasher = PasswordHasherService::with_defaults();
//! let hash = hasher.hash("password123")?;
//! hasher.verify("password123", &hash)?;
//!
//! // Authentication flow
//! let flow = FlowContext::new(realm_id, client_id);
//! let flow = flow.start_identification();
//! let flow = flow.user_identified(user_id);
//! let result = flow.authenticated(vec![]);
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod authenticator;
pub mod error;
pub mod flow;
pub mod otp;
pub mod password;

pub use authenticator::{AuthContext, Authenticator, AuthenticatorFactory, AuthenticatorResult};
pub use error::{AuthError, AuthResult};
pub use flow::{states, AuthenticatedResult, FlowContext, RequiredActionResult};
pub use otp::{HotpConfig, OtpAlgorithm, OtpVerifier, TotpConfig};
pub use password::{PasswordHasherService, PasswordPolicy};
