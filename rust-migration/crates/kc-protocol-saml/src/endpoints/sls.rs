//! Single Logout Service endpoint.
//!
//! Handles SAML LogoutRequest and LogoutResponse messages.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;

use crate::bindings::{HttpPostBinding, HttpRedirectBinding};
use crate::error::SamlError;
use crate::types::LogoutResponse;

use super::state::{SamlRealmProvider, SamlState};

/// Query parameters for SLS redirect binding.
#[derive(Debug, Deserialize)]
pub struct SlsRedirectParams {
    /// The SAML request (deflated, base64, URL-encoded).
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,

    /// The SAML response (deflated, base64, URL-encoded).
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,

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

/// Form data for SLS POST binding.
#[derive(Debug, Deserialize)]
pub struct SlsPostForm {
    /// The SAML request (base64-encoded).
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,

    /// The SAML response (base64-encoded).
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,

    /// Relay state.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// GET handler for SLS endpoint (HTTP-Redirect binding).
pub async fn sls_redirect<R: SamlRealmProvider>(
    State(state): State<SamlState<R>>,
    Path(realm): Path<String>,
    Query(params): Query<SlsRedirectParams>,
) -> impl IntoResponse {
    match handle_sls_redirect(&state, &realm, params).await {
        Ok(response) => response.into_response(),
        Err(e) => error_response(&e).into_response(),
    }
}

/// POST handler for SLS endpoint (HTTP-POST binding).
pub async fn sls_post<R: SamlRealmProvider>(
    State(state): State<SamlState<R>>,
    Path(realm): Path<String>,
    Form(form): Form<SlsPostForm>,
) -> impl IntoResponse {
    match handle_sls_post(&state, &realm, form).await {
        Ok(response) => response.into_response(),
        Err(e) => error_response(&e).into_response(),
    }
}

/// Handles SLS via HTTP-Redirect binding.
async fn handle_sls_redirect<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    params: SlsRedirectParams,
) -> Result<SlsRedirectResponse, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    // Determine if this is a request or response
    if let Some(saml_request) = params.saml_request {
        // Handle logout request
        let decoded = HttpRedirectBinding::decode(
            Some(&saml_request),
            None,
            params.relay_state.as_deref(),
            params.signature.as_deref(),
            params.sig_alg.as_deref(),
        )?;

        let logout_request = parse_logout_request(&decoded.xml)?;

        // TODO: Validate signature

        // Terminate the user's session
        let terminated = state
            .realm_provider
            .terminate_session(
                realm,
                &logout_request.name_id,
                logout_request.session_index.as_deref(),
            )
            .await
            .map_err(|e| SamlError::Internal(format!("Failed to terminate session: {e}")))?;

        tracing::info!(
            "SAML logout for '{}' in realm '{}': terminated {} sessions",
            logout_request.name_id,
            realm,
            terminated
        );

        // Generate logout response
        let response = generate_logout_response(state, realm, &logout_request).await?;

        // Find the response URL
        let response_url = get_sp_sls_url(state, realm, &logout_request.issuer).await?;

        // Encode response for redirect binding
        let redirect_url = HttpRedirectBinding::encode_response(
            &response,
            &response_url,
            decoded.relay_state.as_deref(),
        )?;

        Ok(SlsRedirectResponse::Redirect(redirect_url))
    } else if let Some(saml_response) = params.saml_response {
        // Handle logout response
        let _decoded = HttpRedirectBinding::decode(
            None,
            Some(&saml_response),
            params.relay_state.as_deref(),
            params.signature.as_deref(),
            params.sig_alg.as_deref(),
        )?;

        // TODO: Validate the response

        // Return success page
        Ok(SlsRedirectResponse::Html(logout_complete_page()))
    } else {
        Err(SamlError::InvalidRequest(
            "No SAMLRequest or SAMLResponse parameter".to_string(),
        ))
    }
}

/// Handles SLS via HTTP-POST binding.
async fn handle_sls_post<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    form: SlsPostForm,
) -> Result<Html<String>, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    // Determine if this is a request or response
    if let Some(saml_request) = form.saml_request {
        // Handle logout request
        let decoded = HttpPostBinding::decode(Some(&saml_request), None, form.relay_state.as_deref())?;

        let logout_request = parse_logout_request(&decoded.xml)?;

        // Terminate the user's session
        let terminated = state
            .realm_provider
            .terminate_session(
                realm,
                &logout_request.name_id,
                logout_request.session_index.as_deref(),
            )
            .await
            .map_err(|e| SamlError::Internal(format!("Failed to terminate session: {e}")))?;

        tracing::info!(
            "SAML logout (POST) for '{}' in realm '{}': terminated {} sessions",
            logout_request.name_id,
            realm,
            terminated
        );

        // Generate logout response
        let response = generate_logout_response(state, realm, &logout_request).await?;

        // Find the response URL
        let response_url = get_sp_sls_url(state, realm, &logout_request.issuer).await?;

        // Encode response for POST binding
        let html = HttpPostBinding::encode_response(&response, &response_url, decoded.relay_state.as_deref());

        Ok(Html(html))
    } else if let Some(saml_response) = form.saml_response {
        // Handle logout response
        let _decoded = HttpPostBinding::decode(None, Some(&saml_response), form.relay_state.as_deref())?;

        // TODO: Validate the response

        // Return success page
        Ok(Html(logout_complete_page()))
    } else {
        Err(SamlError::InvalidRequest(
            "No SAMLRequest or SAMLResponse parameter".to_string(),
        ))
    }
}

/// Response type for SLS redirect handling.
enum SlsRedirectResponse {
    Redirect(String),
    Html(String),
}

impl IntoResponse for SlsRedirectResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Redirect(url) => Redirect::temporary(&url).into_response(),
            Self::Html(html) => Html(html).into_response(),
        }
    }
}

/// Parsed logout request (simplified).
#[derive(Debug)]
#[allow(dead_code)]
struct ParsedLogoutRequest {
    id: String,
    issuer: String,
    name_id: String,
    session_index: Option<String>,
}

/// Parses a LogoutRequest from XML.
fn parse_logout_request(xml: &str) -> Result<ParsedLogoutRequest, SamlError> {
    let id = extract_attribute(xml, "LogoutRequest", "ID")
        .ok_or_else(|| SamlError::MissingElement("LogoutRequest ID".to_string()))?;

    let issuer = extract_element_content(xml, "Issuer")
        .ok_or_else(|| SamlError::MissingElement("Issuer".to_string()))?;

    let name_id = extract_element_content(xml, "NameID")
        .ok_or_else(|| SamlError::MissingElement("NameID".to_string()))?;

    let session_index = extract_element_content(xml, "SessionIndex");

    Ok(ParsedLogoutRequest {
        id,
        issuer,
        name_id,
        session_index,
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
        (
            format!("<samlp:{}>", element),
            format!("</samlp:{}>", element),
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

/// Generates a SAML logout response.
async fn generate_logout_response<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    request: &ParsedLogoutRequest,
) -> Result<String, SamlError> {
    let idp_entity_id = state
        .realm_provider
        .get_idp_entity_id(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get IdP entity ID: {e}")))?;

    let response = LogoutResponse::success(&idp_entity_id).in_response_to(&request.id);

    // Serialize to XML
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{}" InResponseTo="{}" IssueInstant="{}" Version="2.0">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{}</saml:Issuer>
<samlp:Status>
<samlp:StatusCode Value="{}"/>
</samlp:Status>
</samlp:LogoutResponse>"#,
        response.id,
        response.in_response_to.as_deref().unwrap_or(""),
        response.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
        response.issuer,
        response.status.status_code.value
    );

    Ok(xml)
}

/// Gets the SLS URL for a service provider.
async fn get_sp_sls_url<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
    sp_entity_id: &str,
) -> Result<String, SamlError> {
    let sp = state
        .realm_provider
        .get_service_provider(realm, sp_entity_id)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get SP: {e}")))?
        .ok_or_else(|| SamlError::UnknownServiceProvider(sp_entity_id.to_string()))?;

    sp.sls_urls
        .first()
        .map(|e| e.url.clone())
        .ok_or_else(|| {
            SamlError::InvalidRequest(format!("SP {} has no SLS URL configured", sp_entity_id))
        })
}

/// Generates a logout complete HTML page.
fn logout_complete_page() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Logout Complete</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; }
    </style>
</head>
<body>
    <h1>Logout Complete</h1>
    <p>You have been successfully logged out.</p>
</body>
</html>"#
        .to_string()
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
    fn parse_logout_request_basic() {
        let xml = r#"<samlp:LogoutRequest ID="_logout123">
            <saml:Issuer>https://sp.example.com</saml:Issuer>
            <saml:NameID>user@example.com</saml:NameID>
            <samlp:SessionIndex>_session456</samlp:SessionIndex>
        </samlp:LogoutRequest>"#;

        let parsed = parse_logout_request(xml).unwrap();
        assert_eq!(parsed.id, "_logout123");
        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(parsed.name_id, "user@example.com");
        assert_eq!(parsed.session_index.as_deref(), Some("_session456"));
    }
}
