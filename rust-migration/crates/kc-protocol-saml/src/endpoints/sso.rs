//! Single Sign-On endpoint.
//!
//! Handles SAML AuthnRequest messages and generates responses.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    Form,
};
use serde::Deserialize;

use crate::bindings::{HttpPostBinding, HttpRedirectBinding};
use crate::error::SamlError;
use crate::signature::XmlSignatureValidator;
use crate::types::{
    Assertion, AuthnContextClass, AuthnStatement, Conditions, NameId,
    ResponseBuilder, Subject, SubjectConfirmation, SubjectConfirmationData,
};
use crate::types::Response as SamlResponse;

use super::state::{SamlRealmProvider, SamlState};

/// Action to take after processing an SSO request.
///
/// This enum allows the SSO endpoint to communicate to the caller
/// what action should be taken - either show a login page or
/// generate a SAML response.
#[derive(Debug)]
pub enum SsoAction {
    /// Show a login page to the user.
    ShowLoginPage {
        /// The realm name.
        realm: String,
        /// The parsed authentication request.
        request: ParsedAuthnRequest,
        /// Optional relay state.
        relay_state: Option<String>,
    },
    /// Return a SAML response (user already authenticated).
    SendResponse {
        /// The SAML response XML.
        response_xml: String,
        /// The ACS URL to post to.
        acs_url: String,
        /// Optional relay state.
        relay_state: Option<String>,
    },
}

/// Query parameters for SSO redirect binding.
#[derive(Debug, Deserialize)]
pub struct SsoRedirectParams {
    /// The SAML request (deflated, base64, URL-encoded).
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,

    /// Relay state.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,

    /// Signature (if signed).
    #[serde(rename = "Signature")]
    pub signature: Option<String>,

    /// Signature algorithm.
    #[serde(rename = "SigAlg")]
    pub sig_alg: Option<String>,
}

/// Form data for SSO POST binding.
#[derive(Debug, Deserialize)]
pub struct SsoPostForm {
    /// The SAML request (base64-encoded).
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,

    /// Relay state.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// GET handler for SSO endpoint (HTTP-Redirect binding).
pub async fn sso_redirect<R: SamlRealmProvider>(
    State(state): State<SamlState<R>>,
    Path(realm): Path<String>,
    Query(params): Query<SsoRedirectParams>,
) -> impl IntoResponse {
    match handle_sso_redirect(&state, &realm, params).await {
        Ok(response) => response.into_response(),
        Err(e) => error_response(&e).into_response(),
    }
}

/// POST handler for SSO endpoint (HTTP-POST binding).
pub async fn sso_post<R: SamlRealmProvider>(
    State(state): State<SamlState<R>>,
    Path(realm): Path<String>,
    Form(form): Form<SsoPostForm>,
) -> impl IntoResponse {
    match handle_sso_post(&state, &realm, form).await {
        Ok(response) => response.into_response(),
        Err(e) => error_response(&e).into_response(),
    }
}

/// Processes an SSO redirect binding request and returns the action to take.
///
/// This function parses and validates the SAML AuthnRequest but does not
/// authenticate the user. The caller is responsible for showing a login page
/// or generating a SAML response.
pub async fn process_sso_redirect<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    params: &SsoRedirectParams,
) -> Result<SsoAction, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    let saml_request = params
        .saml_request
        .as_ref()
        .ok_or_else(|| SamlError::InvalidRequest("SAMLRequest parameter required".to_string()))?;

    // Decode the request
    let decoded = HttpRedirectBinding::decode(
        Some(saml_request),
        None,
        params.relay_state.as_deref(),
        params.signature.as_deref(),
        params.sig_alg.as_deref(),
    )?;

    // Parse and validate the AuthnRequest
    let authn_request = parse_authn_request(&decoded.xml)?;

    // Validate signature if present or required
    validate_authn_request_signature(
        state,
        realm,
        &authn_request,
        params.signature.as_deref(),
        params.sig_alg.as_deref(),
        saml_request,
        params.relay_state.as_deref(),
    )
    .await?;

    // Return action to show login page
    Ok(SsoAction::ShowLoginPage {
        realm: realm.to_string(),
        request: authn_request,
        relay_state: decoded.relay_state,
    })
}

/// Processes an SSO POST binding request and returns the action to take.
///
/// This function parses and validates the SAML AuthnRequest but does not
/// authenticate the user. The caller is responsible for showing a login page
/// or generating a SAML response.
pub async fn process_sso_post<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    form: &SsoPostForm,
) -> Result<SsoAction, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    let saml_request = form
        .saml_request
        .as_ref()
        .ok_or_else(|| SamlError::InvalidRequest("SAMLRequest parameter required".to_string()))?;

    // Decode the request
    let decoded = HttpPostBinding::decode(Some(saml_request), None, form.relay_state.as_deref())?;

    // Parse and validate the AuthnRequest
    let authn_request = parse_authn_request(&decoded.xml)?;

    // Validate embedded signature for POST binding if present or required
    validate_authn_request_signature_post(state, realm, &authn_request, &decoded.xml).await?;

    // Return action to show login page
    Ok(SsoAction::ShowLoginPage {
        realm: realm.to_string(),
        request: authn_request,
        relay_state: decoded.relay_state,
    })
}

/// Handles SSO via HTTP-Redirect binding.
async fn handle_sso_redirect<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    params: SsoRedirectParams,
) -> Result<Html<String>, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    let saml_request = params
        .saml_request
        .ok_or_else(|| SamlError::InvalidRequest("SAMLRequest parameter required".to_string()))?;

    // Decode the request
    let decoded = HttpRedirectBinding::decode(
        Some(&saml_request),
        None,
        params.relay_state.as_deref(),
        params.signature.as_deref(),
        params.sig_alg.as_deref(),
    )?;

    // TODO: Validate signature if present

    // Parse and validate the AuthnRequest
    let authn_request = parse_authn_request(&decoded.xml)?;

    // TODO: Actually authenticate the user
    // For now, we'll return a login page or generate a response

    // Generate success response (placeholder - would normally require authentication)
    let response = generate_success_response(
        state,
        realm,
        &authn_request,
        "placeholder-user-id",
    )
    .await?;

    // Encode response for POST binding to ACS
    let acs_url = authn_request
        .assertion_consumer_service_url
        .ok_or_else(|| {
            SamlError::InvalidRequest("No ACS URL in request".to_string())
        })?;

    let html = HttpPostBinding::encode_response(&response, &acs_url, decoded.relay_state.as_deref());

    Ok(Html(html))
}

/// Handles SSO via HTTP-POST binding.
async fn handle_sso_post<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    form: SsoPostForm,
) -> Result<Html<String>, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    let saml_request = form
        .saml_request
        .ok_or_else(|| SamlError::InvalidRequest("SAMLRequest parameter required".to_string()))?;

    // Decode the request
    let decoded = HttpPostBinding::decode(Some(&saml_request), None, form.relay_state.as_deref())?;

    // Parse and validate the AuthnRequest
    let authn_request = parse_authn_request(&decoded.xml)?;

    // TODO: Actually authenticate the user

    // Generate success response (placeholder)
    let response = generate_success_response(
        state,
        realm,
        &authn_request,
        "placeholder-user-id",
    )
    .await?;

    // Encode response for POST binding to ACS
    let acs_url = authn_request
        .assertion_consumer_service_url
        .ok_or_else(|| {
            SamlError::InvalidRequest("No ACS URL in request".to_string())
        })?;

    let html = HttpPostBinding::encode_response(&response, &acs_url, decoded.relay_state.as_deref());

    Ok(Html(html))
}

/// Parsed authentication request.
///
/// This struct contains the parsed information from a SAML AuthnRequest
/// and can be used to determine how to authenticate the user.
#[derive(Debug, Clone)]
pub struct ParsedAuthnRequest {
    /// The unique identifier of the request.
    pub id: String,
    /// The issuer (SP entity ID).
    pub issuer: String,
    /// The Assertion Consumer Service URL where the response should be sent.
    pub assertion_consumer_service_url: Option<String>,
    /// The requested NameID format.
    pub name_id_policy_format: Option<String>,
    /// Whether to force re-authentication.
    pub force_authn: bool,
    /// Whether the IdP should not interact with the user.
    pub is_passive: bool,
}

/// Validates the AuthnRequest signature for HTTP-Redirect binding.
///
/// For redirect binding, the signature is detached and computed over the
/// query string parameters.
async fn validate_authn_request_signature<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    authn_request: &ParsedAuthnRequest,
    signature: Option<&str>,
    sig_alg: Option<&str>,
    saml_request: &str,
    relay_state: Option<&str>,
) -> Result<(), SamlError> {
    // Look up the SP configuration
    let sp_config = state
        .realm_provider
        .get_service_provider(realm, &authn_request.issuer)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get SP config: {e}")))?;

    // If SP is not registered, we might allow the request for testing
    // In production, you may want to reject unregistered SPs
    let Some(sp) = sp_config else {
        tracing::debug!("SP '{}' not registered, skipping signature validation", authn_request.issuer);
        return Ok(());
    };

    // Check if SP requires signed requests
    if sp.require_authn_request_signed {
        // Signature is required
        let signature = signature.ok_or_else(|| {
            SamlError::SignatureInvalid("SP requires signed AuthnRequest but no signature provided".to_string())
        })?;
        let sig_alg = sig_alg.ok_or_else(|| {
            SamlError::SignatureInvalid("Signature algorithm not specified".to_string())
        })?;

        // Get the SP's signing certificate
        let cert_der = sp.signing_certificate.as_ref().ok_or_else(|| {
            SamlError::SignatureInvalid("SP requires signed requests but no certificate configured".to_string())
        })?;

        // Build the signed query string for validation
        // For redirect binding, the signature is computed over: SAMLRequest=value&RelayState=value&SigAlg=value
        let mut signed_query = format!("SAMLRequest={}", urlencoding::encode(saml_request));
        if let Some(rs) = relay_state {
            signed_query.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
        }
        signed_query.push_str(&format!("&SigAlg={}", urlencoding::encode(sig_alg)));

        // Create validator and validate
        let validator = XmlSignatureValidator::new(vec![cert_der.clone()])
            .allow_sha1(sp.allow_sha1);

        validator
            .validate_redirect_binding(&signed_query, signature, sig_alg)
            .map_err(|e| {
                tracing::warn!("AuthnRequest signature validation failed: {}", e);
                SamlError::SignatureInvalid(format!("AuthnRequest signature invalid: {e}"))
            })?;

        tracing::debug!("AuthnRequest signature validated successfully");
    } else if signature.is_some() {
        // Signature provided but not required - validate it anyway for security
        if let (Some(sig), Some(alg), Some(cert_der)) = (signature, sig_alg, sp.signing_certificate.as_ref()) {
            let mut signed_query = format!("SAMLRequest={}", urlencoding::encode(saml_request));
            if let Some(rs) = relay_state {
                signed_query.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
            }
            signed_query.push_str(&format!("&SigAlg={}", urlencoding::encode(alg)));

            let validator = XmlSignatureValidator::new(vec![cert_der.clone()])
                .allow_sha1(sp.allow_sha1);

            if let Err(e) = validator.validate_redirect_binding(&signed_query, sig, alg) {
                tracing::warn!("Optional AuthnRequest signature validation failed: {}", e);
                // Don't fail - signature was optional
            } else {
                tracing::debug!("Optional AuthnRequest signature validated successfully");
            }
        }
    }

    Ok(())
}

/// Validates the AuthnRequest signature for HTTP-POST binding.
///
/// For POST binding, the signature is embedded in the XML document.
async fn validate_authn_request_signature_post<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    authn_request: &ParsedAuthnRequest,
    xml: &str,
) -> Result<(), SamlError> {
    // Look up the SP configuration
    let sp_config = state
        .realm_provider
        .get_service_provider(realm, &authn_request.issuer)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get SP config: {e}")))?;

    // If SP is not registered, we might allow the request for testing
    let Some(sp) = sp_config else {
        tracing::debug!("SP '{}' not registered, skipping signature validation", authn_request.issuer);
        return Ok(());
    };

    // Check if XML contains a signature
    let has_signature = xml.contains("<ds:Signature") || xml.contains("<Signature");

    if sp.require_authn_request_signed {
        if !has_signature {
            return Err(SamlError::SignatureInvalid(
                "SP requires signed AuthnRequest but no signature found in request".to_string(),
            ));
        }

        // Get the SP's signing certificate
        let cert_der = sp.signing_certificate.as_ref().ok_or_else(|| {
            SamlError::SignatureInvalid("SP requires signed requests but no certificate configured".to_string())
        })?;

        // Create validator and validate the embedded signature
        let validator = XmlSignatureValidator::new(vec![cert_der.clone()])
            .allow_sha1(sp.allow_sha1);

        validator.validate(xml).map_err(|e| {
            tracing::warn!("AuthnRequest embedded signature validation failed: {}", e);
            SamlError::SignatureInvalid(format!("AuthnRequest signature invalid: {e}"))
        })?;

        tracing::debug!("AuthnRequest embedded signature validated successfully");
    } else if has_signature {
        // Signature present but not required - validate it anyway if we have a certificate
        if let Some(cert_der) = sp.signing_certificate.as_ref() {
            let validator = XmlSignatureValidator::new(vec![cert_der.clone()])
                .allow_sha1(sp.allow_sha1);

            if let Err(e) = validator.validate(xml) {
                tracing::warn!("Optional AuthnRequest embedded signature validation failed: {}", e);
                // Don't fail - signature was optional
            } else {
                tracing::debug!("Optional AuthnRequest embedded signature validated successfully");
            }
        }
    }

    Ok(())
}

/// Parses an AuthnRequest from XML.
fn parse_authn_request(xml: &str) -> Result<ParsedAuthnRequest, SamlError> {
    // Simplified XML parsing - a full implementation would use quick-xml properly

    let id = extract_attribute(xml, "AuthnRequest", "ID")
        .ok_or_else(|| SamlError::MissingElement("AuthnRequest ID".to_string()))?;

    let issuer = extract_element_content(xml, "Issuer")
        .ok_or_else(|| SamlError::MissingElement("Issuer".to_string()))?;

    let acs_url = extract_attribute(xml, "AuthnRequest", "AssertionConsumerServiceURL");

    let force_authn = extract_attribute(xml, "AuthnRequest", "ForceAuthn")
        .map(|v| v == "true")
        .unwrap_or(false);

    let is_passive = extract_attribute(xml, "AuthnRequest", "IsPassive")
        .map(|v| v == "true")
        .unwrap_or(false);

    let name_id_format = extract_attribute(xml, "NameIDPolicy", "Format");

    Ok(ParsedAuthnRequest {
        id,
        issuer,
        assertion_consumer_service_url: acs_url,
        name_id_policy_format: name_id_format,
        force_authn,
        is_passive,
    })
}

/// Extracts an attribute from an XML element.
fn extract_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let patterns = [format!("<{}", element), format!("<samlp:{}", element)];

    for pattern in &patterns {
        if let Some(pos) = xml.find(pattern) {
            let end = xml[pos..].find('>')?;
            let element_str = &xml[pos..pos + end];

            let attr_pattern = format!("{}=\"", attribute);
            if let Some(attr_start) = element_str.find(&attr_pattern) {
                let value_start = attr_start + attr_pattern.len();
                let value_end = element_str[value_start..].find('"')?;
                return Some(element_str[value_start..value_start + value_end].to_string());
            }
        }
    }
    None
}

/// Extracts element content from XML.
fn extract_element_content(xml: &str, element: &str) -> Option<String> {
    let patterns = [
        (format!("<{}>", element), format!("</{}>", element)),
        (
            format!("<saml:{}>", element),
            format!("</saml:{}>", element),
        ),
    ];

    for (open, close) in &patterns {
        if let Some(start) = xml.find(open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(close) {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
        }
    }
    None
}

/// Generates a success SAML response.
async fn generate_success_response<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    request: &ParsedAuthnRequest,
    user_id: &str,
) -> Result<String, SamlError> {
    let idp_entity_id = state
        .realm_provider
        .get_idp_entity_id(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get IdP entity ID: {e}")))?;

    // Get user info
    let user = state
        .realm_provider
        .get_user(realm, user_id)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get user: {e}")))?
        .ok_or_else(|| SamlError::UserNotFound(user_id.to_string()))?;

    // Determine name ID format
    let name_id = match request.name_id_policy_format.as_deref() {
        Some(fmt) if fmt.contains("emailAddress") => {
            NameId::email(user.email.as_deref().unwrap_or(&user.username))
        }
        Some(fmt) if fmt.contains("persistent") => NameId::persistent(&user.id),
        Some(fmt) if fmt.contains("transient") => {
            NameId::transient(format!("_transient_{}", uuid::Uuid::new_v4()))
        }
        _ => NameId::new(&user.username),
    };

    // Build assertion
    let acs_url = request.assertion_consumer_service_url.as_deref().unwrap_or("");

    let assertion = Assertion::new(&idp_entity_id)
        .with_subject(
            Subject::new(name_id).with_confirmation(
                SubjectConfirmation::bearer().with_data(
                    SubjectConfirmationData::for_request(&request.id, acs_url),
                ),
            ),
        )
        .with_conditions(
            Conditions::with_validity(5)
                .with_audience(&request.issuer),
        )
        .with_authn_statement(
            AuthnStatement::new(AuthnContextClass::PasswordProtectedTransport)
                .with_session_timeout(480),
        );

    // Build response
    let response = ResponseBuilder::new(&idp_entity_id)
        .in_response_to(&request.id)
        .destination(acs_url)
        .assertion(assertion)
        .build();

    // Serialize to XML
    let xml = serialize_response(&response)?;

    // TODO: Sign the response

    Ok(xml)
}

/// Serializes a SAML response to XML.
fn serialize_response(response: &SamlResponse) -> Result<String, SamlError> {
    // Simplified XML generation - a full implementation would use quick-xml
    let assertion_xml = if let Some(ref assertion) = response.assertions.first() {
        format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" IssueInstant="{}" Version="2.0">
<saml:Issuer>{}</saml:Issuer>
</saml:Assertion>"#,
            assertion.id,
            assertion.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
            assertion.issuer
        )
    } else {
        String::new()
    };

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{}" InResponseTo="{}" IssueInstant="{}" Version="2.0" Destination="{}">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{}</saml:Issuer>
<samlp:Status>
<samlp:StatusCode Value="{}"/>
</samlp:Status>
{}
</samlp:Response>"#,
        response.id,
        response.in_response_to.as_deref().unwrap_or(""),
        response.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
        response.destination.as_deref().unwrap_or(""),
        response.issuer,
        response.status.status_code.value,
        assertion_xml
    );

    Ok(xml)
}

/// Creates an error response.
fn error_response(err: &SamlError) -> (StatusCode, Html<String>) {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>SAML Error</title></head>
<body>
<h1>SAML Error</h1>
<p>{}</p>
</body>
</html>"#,
        err
    );
    (status, Html(html))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authn_request_basic() {
        let xml = r#"<samlp:AuthnRequest ID="_123" AssertionConsumerServiceURL="https://sp.example.com/acs" ForceAuthn="true">
            <saml:Issuer>https://sp.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;

        let parsed = parse_authn_request(xml).unwrap();
        assert_eq!(parsed.id, "_123");
        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(
            parsed.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert!(parsed.force_authn);
    }
}
