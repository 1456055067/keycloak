//! SAML 2.0 types and data structures.
//!
//! This module contains all the core SAML types used for authentication,
//! including requests, responses, assertions, and related structures.

mod assertion;
mod authn_request;
mod constants;
mod logout;
mod name_id;
mod response;
mod status;

pub use assertion::*;
pub use authn_request::*;
pub use constants::*;
pub use logout::*;
pub use name_id::*;
pub use response::*;
pub use status::*;
