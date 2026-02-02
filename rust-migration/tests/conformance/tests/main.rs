//! OIDC Conformance Test Suite
//!
//! This test suite validates the OIDC implementation against the
//! OpenID Foundation Conformance Test Suite requirements.
//!
//! ## Test Profiles
//!
//! The tests are organized according to the OIDC certification profiles:
//! - Basic OP (Authorization Code flow)
//! - Implicit OP
//! - Hybrid OP
//! - Config OP (Discovery)
//! - Dynamic OP (Dynamic Client Registration)
//!
//! ## Running Tests
//!
//! Run all conformance tests:
//! ```bash
//! cargo test -p oidc-conformance-tests
//! ```
//!
//! Run specific profile tests:
//! ```bash
//! cargo test -p oidc-conformance-tests basic_op
//! cargo test -p oidc-conformance-tests config_op
//! ```

mod harness;
mod basic_op;
mod config_op;
mod hybrid_op;
mod implicit_op;
mod token_endpoint;
mod userinfo;
mod introspection;
mod revocation;
