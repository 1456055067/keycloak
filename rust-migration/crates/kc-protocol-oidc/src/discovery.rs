//! `OpenID` Connect Discovery 1.0 implementation.
//!
//! Implements the `OpenID` Provider Metadata as defined in:
//! - [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
//! - [RFC 8414](https://tools.ietf.org/html/rfc8414) (OAuth 2.0 Authorization Server Metadata)

use serde::{Deserialize, Serialize};

use crate::types::{CodeChallengeMethod, Display, GrantType, ResponseMode, SubjectType};

/// `OpenID` Provider Metadata.
///
/// This is returned by the `.well-known/openid-configuration` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    // === Required Fields ===
    /// URL of the authorization server's issuer identifier.
    pub issuer: String,

    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,

    /// URL of the token endpoint.
    pub token_endpoint: String,

    /// URL of the JSON Web Key Set document.
    pub jwks_uri: String,

    /// List of supported response types.
    pub response_types_supported: Vec<String>,

    /// List of supported subject types.
    pub subject_types_supported: Vec<SubjectType>,

    /// List of supported signing algorithms for ID tokens.
    pub id_token_signing_alg_values_supported: Vec<String>,

    // === Recommended Fields ===
    /// URL of the `UserInfo` endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// URL of the dynamic client registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// List of supported scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// List of supported response modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<ResponseMode>>,

    /// List of supported grant types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    /// List of supported ACR values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,

    // === Token Endpoint Auth ===
    /// List of supported client authentication methods for token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// List of supported signing algorithms for token endpoint auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    // === Display and Prompt ===
    /// List of supported display values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<Display>>,

    /// List of supported claim types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_types_supported: Option<Vec<String>>,

    /// List of supported claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    // === Service Documentation ===
    /// URL of the service documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Languages supported for claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,

    /// Languages supported for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// Whether claims parameter is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,

    /// Whether request parameter is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,

    /// Whether `request_uri` parameter is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,

    /// Whether `request_uri` values must be pre-registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,

    /// URL of the OP policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// URL of the OP terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    // === Additional Endpoints ===
    /// URL of the token revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// Supported auth methods for revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// URL of the token introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// Supported auth methods for introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// URL of the end session (logout) endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,

    // === PKCE ===
    /// Supported code challenge methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<CodeChallengeMethod>>,

    // === Signing Algorithms ===
    /// Supported signing algorithms for `UserInfo` responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// Supported encryption algorithms for `UserInfo` responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,

    /// Supported encryption encoding for `UserInfo` responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,

    /// Supported signing algorithms for request objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// Supported encryption algorithms for request objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    /// Supported encryption encoding for request objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    // === Device Authorization (RFC 8628) ===
    /// URL of the device authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    // === Backchannel Logout ===
    /// Whether backchannel logout is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_supported: Option<bool>,

    /// Whether backchannel logout session is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_supported: Option<bool>,

    // === Frontchannel Logout ===
    /// Whether frontchannel logout is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_supported: Option<bool>,

    /// Whether frontchannel logout session is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_supported: Option<bool>,

    // === Pushed Authorization Requests (RFC 9126) ===
    /// URL of the pushed authorization request endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// Whether PAR is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    // === mTLS (RFC 8705) ===
    /// mTLS endpoint aliases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,

    /// Whether TLS client certificate bound access tokens are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
}

/// mTLS endpoint aliases for certificate-bound tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsEndpointAliases {
    /// mTLS token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// mTLS revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// mTLS introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// mTLS device authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    /// mTLS registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// mTLS `UserInfo` endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// mTLS pushed authorization request endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
}

/// Returns CNSA 2.0 compliant signing algorithms.
fn cnsa_signing_algorithms() -> Vec<String> {
    vec![
        "ES384".to_string(),
        "ES512".to_string(),
        "RS384".to_string(),
        "RS512".to_string(),
        "PS384".to_string(),
        "PS512".to_string(),
    ]
}

/// Returns supported OIDC claims.
fn supported_claims() -> Vec<String> {
    vec![
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
        "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
        "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
        "updated_at", "email", "email_verified", "phone_number", "phone_number_verified", "address",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns supported client auth methods.
fn client_auth_methods() -> Vec<String> {
    vec![
        "client_secret_basic".to_string(),
        "client_secret_post".to_string(),
        "private_key_jwt".to_string(),
    ]
}

/// Builder for creating `ProviderMetadata`.
#[derive(Debug, Clone)]
pub struct ProviderMetadataBuilder {
    issuer: String,
    realm: String,
}

impl ProviderMetadataBuilder {
    /// Creates a new builder with the issuer URL and realm name.
    #[must_use]
    pub fn new(issuer: impl Into<String>, realm: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            realm: realm.into(),
        }
    }

    /// Builds the provider metadata with default CNSA 2.0 compliant settings.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn build(&self) -> ProviderMetadata {
        let base_url = format!("{}/realms/{}", self.issuer, self.realm);
        let protocol_url = format!("{base_url}/protocol/openid-connect");

        ProviderMetadata {
            issuer: base_url,
            authorization_endpoint: format!("{protocol_url}/auth"),
            token_endpoint: format!("{protocol_url}/token"),
            jwks_uri: format!("{protocol_url}/certs"),
            response_types_supported: vec![
                "code".to_string(), "id_token".to_string(), "code id_token".to_string(),
                "code token".to_string(), "code id_token token".to_string(), "id_token token".to_string(),
            ],
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            id_token_signing_alg_values_supported: cnsa_signing_algorithms(),
            userinfo_endpoint: Some(format!("{protocol_url}/userinfo")),
            registration_endpoint: None,
            scopes_supported: Some(vec![
                "openid".to_string(), "profile".to_string(), "email".to_string(),
                "address".to_string(), "phone".to_string(), "offline_access".to_string(),
            ]),
            response_modes_supported: Some(vec![ResponseMode::Query, ResponseMode::Fragment, ResponseMode::FormPost]),
            grant_types_supported: Some(vec![
                GrantType::AuthorizationCode.to_string(), GrantType::ClientCredentials.to_string(),
                GrantType::RefreshToken.to_string(), GrantType::Password.to_string(),
                GrantType::DeviceCode.to_string(), GrantType::TokenExchange.to_string(),
            ]),
            acr_values_supported: None,
            token_endpoint_auth_methods_supported: Some({
                let mut methods = client_auth_methods();
                methods.push("client_secret_jwt".to_string());
                methods
            }),
            token_endpoint_auth_signing_alg_values_supported: Some(cnsa_signing_algorithms()),
            display_values_supported: Some(vec![Display::Page, Display::Popup, Display::Touch, Display::Wap]),
            claim_types_supported: Some(vec!["normal".to_string()]),
            claims_supported: Some(supported_claims()),
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: Some(true),
            request_parameter_supported: Some(true),
            request_uri_parameter_supported: Some(true),
            require_request_uri_registration: Some(false),
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: Some(format!("{protocol_url}/revoke")),
            revocation_endpoint_auth_methods_supported: Some(client_auth_methods()),
            introspection_endpoint: Some(format!("{protocol_url}/token/introspect")),
            introspection_endpoint_auth_methods_supported: Some(client_auth_methods()),
            end_session_endpoint: Some(format!("{protocol_url}/logout")),
            code_challenge_methods_supported: Some(vec![CodeChallengeMethod::S256, CodeChallengeMethod::Plain]),
            userinfo_signing_alg_values_supported: Some(cnsa_signing_algorithms()),
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: Some({
                let mut algs = cnsa_signing_algorithms();
                algs.push("none".to_string());
                algs
            }),
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            device_authorization_endpoint: Some(format!("{protocol_url}/auth/device")),
            backchannel_logout_supported: Some(true),
            backchannel_logout_session_supported: Some(true),
            frontchannel_logout_supported: Some(true),
            frontchannel_logout_session_supported: Some(true),
            pushed_authorization_request_endpoint: Some(format!("{protocol_url}/ext/par/request")),
            require_pushed_authorization_requests: Some(false),
            mtls_endpoint_aliases: None,
            tls_client_certificate_bound_access_tokens: Some(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_metadata_builder() {
        let metadata = ProviderMetadataBuilder::new("https://auth.example.com", "master").build();

        assert_eq!(
            metadata.issuer,
            "https://auth.example.com/realms/master"
        );
        assert_eq!(
            metadata.authorization_endpoint,
            "https://auth.example.com/realms/master/protocol/openid-connect/auth"
        );
        assert_eq!(
            metadata.token_endpoint,
            "https://auth.example.com/realms/master/protocol/openid-connect/token"
        );
        assert_eq!(
            metadata.jwks_uri,
            "https://auth.example.com/realms/master/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn cnsa_compliant_algorithms() {
        let metadata = ProviderMetadataBuilder::new("https://auth.example.com", "test").build();

        // Verify no ES256, RS256, PS256
        for alg in &metadata.id_token_signing_alg_values_supported {
            assert!(!alg.contains("256"), "ES256/RS256/PS256 should not be supported");
        }

        // Verify CNSA 2.0 algorithms are present
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"ES384".to_string()));
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"ES512".to_string()));
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"RS384".to_string()));
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"RS512".to_string()));
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"PS384".to_string()));
        assert!(metadata.id_token_signing_alg_values_supported.contains(&"PS512".to_string()));
    }

    #[test]
    fn serialization_roundtrip() {
        let metadata = ProviderMetadataBuilder::new("https://auth.example.com", "test").build();
        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: ProviderMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.issuer, parsed.issuer);
        assert_eq!(metadata.token_endpoint, parsed.token_endpoint);
    }
}
