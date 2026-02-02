//! # kc-protocol-oidc
//!
//! `OpenID` Connect protocol implementation for Keycloak Rust.
//!
//! This crate implements the OIDC specification including:
//! - Authorization endpoint
//! - Token endpoint
//! - `UserInfo` endpoint
//! - JWKS endpoint
//! - Token introspection and revocation
//!
//! ## CNSA 2.0 Compliance
//!
//! Only ES384, ES512, RS384, RS512, PS384, PS512 signing algorithms are supported.
//! ES256, RS256, PS256 are explicitly forbidden.
//!
//! ## Modules
//!
//! - [`claims`] - JWT claim types for access, ID, and refresh tokens
//! - [`discovery`] - `OpenID` Provider Metadata for `.well-known` endpoint
//! - [`endpoints`] - Axum HTTP handlers for OIDC endpoints
//! - [`error`] - OIDC error types following RFC 6749
//! - [`jwks`] - JSON Web Key Set types for `/certs` endpoint
//! - [`provider`] - Storage-backed OIDC provider implementation
//! - [`request`] - Request types for OIDC endpoints
//! - [`token`] - Token manager for creating and validating tokens
//! - [`types`] - Common OIDC types (grant types, response modes, etc.)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

pub mod claims;
pub mod discovery;
pub mod endpoints;
pub mod error;
pub mod jwks;
pub mod mapper;
pub mod provider;
pub mod request;
pub mod token;
pub mod types;

// Re-export commonly used types
pub use claims::{AccessTokenClaims, IdTokenClaims, RefreshTokenClaims};
pub use discovery::{ProviderMetadata, ProviderMetadataBuilder};
pub use error::{ErrorResponse, OidcError, OidcResult};
pub use jwks::{EcCurve, JsonWebKey, JsonWebKeySet, JwksBuilder, KeyType};
pub use request::{
    AuthorizationRequest, DeviceAuthorizationRequest, DeviceTokenRequest, EndSessionRequest,
    IntrospectionRequest, RevocationRequest, TokenRequest, UserInfoRequest,
};
pub use token::{IntrospectionResponse, TokenConfig, TokenManager, TokenResponse};
pub use types::{
    CodeChallengeMethod, Display, GrantType, Prompt, ResponseMode, ResponseType, ResponseTypes,
    SubjectType, TokenType,
};
pub use provider::{OidcStorageProvider, ProviderConfig};
pub use mapper::{
    AccessTokenMapper, ClientInfo, ClaimValueType, ConfigProperty, ConfigPropertyType,
    IdTokenMapper, IntrospectionMapper, MapperConfig, MapperContext, ProtocolMapper,
    ProtocolMapperRegistry, SessionInfo, UserInfo, UserInfoMapper,
    TokenType as MapperTokenType,
    // Built-in mappers
    AudienceMapper, ClientRoleMapper, GroupMembershipMapper, HardcodedClaimMapper,
    RealmRoleMapper, UserAttributeMapper, UserPropertyMapper,
};

// Re-export grant handler types
pub use endpoints::{
    AuthCodeParams, AuthCodeStore, AuthenticatedClient, AuthenticatedUser, AuthorizationCodeGrant,
    ClientAuthMethod, ClientAuthenticator, ClientCredentialsGrant, GrantContext, GrantResult,
    InMemoryAuthCodeStore, PasswordGrant, PkceVerifier, RefreshTokenGrant, SessionTimeouts,
    StoredAuthCode, UserAuthenticator,
    // Client authentication
    extract_credentials, StorageClientAuthenticator, CLIENT_ASSERTION_TYPE_JWT,
    // State types
    OidcState, RealmProvider, TokenEndpointState,
    // Token endpoint handlers
    token, token_with_sessions,
};
