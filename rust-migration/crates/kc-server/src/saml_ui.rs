//! SAML Login/Logout UI handlers.
//!
//! This module provides the HTML UI for SAML authentication flows.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;

use kc_protocol_oidc::endpoints::UserAuthenticator;
use kc_protocol_saml::bindings::HttpPostBinding;
use kc_protocol_saml::endpoints::SamlRealmProvider;
use kc_protocol_saml::types::{
    Assertion, AuthnContextClass, AuthnStatement, Conditions, NameId, ResponseBuilder, Subject,
    SubjectConfirmation, SubjectConfirmationData,
};

use crate::state::AppState;

/// SAML Login page template.
#[derive(Template)]
#[template(path = "saml_login.html")]
pub struct SamlLoginTemplate {
    /// Realm name.
    pub realm_name: String,
    /// Service provider name.
    pub sp_name: Option<String>,
    /// SAML request ID.
    pub saml_request_id: String,
    /// Service provider entity ID.
    pub sp_entity_id: String,
    /// Assertion Consumer Service URL.
    pub acs_url: String,
    /// Relay state.
    pub relay_state: Option<String>,
    /// Requested NameID format.
    pub name_id_format: Option<String>,
    /// Force authentication flag.
    pub force_authn: bool,
    /// Form action URL.
    pub action_url: String,
    /// Error message to display.
    pub error: Option<String>,
}

/// Form data for SAML login submission.
#[derive(Debug, Deserialize)]
pub struct SamlLoginForm {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// SAML request ID.
    pub saml_request_id: String,
    /// Service provider entity ID.
    pub sp_entity_id: String,
    /// Assertion Consumer Service URL.
    pub acs_url: String,
    /// Relay state.
    pub relay_state: Option<String>,
    /// Requested NameID format.
    pub name_id_format: Option<String>,
    /// Force authentication flag.
    #[serde(default)]
    pub force_authn: bool,
}

/// Shows the SAML login page.
pub fn show_saml_login(
    realm: &str,
    saml_request_id: &str,
    sp_entity_id: &str,
    sp_name: Option<&str>,
    acs_url: &str,
    relay_state: Option<&str>,
    name_id_format: Option<&str>,
    force_authn: bool,
    error: Option<&str>,
) -> Response {
    let template = SamlLoginTemplate {
        realm_name: realm.to_string(),
        sp_name: sp_name.map(String::from),
        saml_request_id: saml_request_id.to_string(),
        sp_entity_id: sp_entity_id.to_string(),
        acs_url: acs_url.to_string(),
        relay_state: relay_state.map(String::from),
        name_id_format: name_id_format.map(String::from),
        force_authn,
        action_url: format!("/realms/{}/protocol/saml/login", realm),
        error: error.map(String::from),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Handles SAML login form submission.
pub async fn saml_login_submit(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Form(form): Form<SamlLoginForm>,
) -> Response {
    let providers = &state.providers;

    // Authenticate user
    let user = match UserAuthenticator::authenticate(
        providers.as_ref(),
        &realm,
        &form.username,
        &form.password,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!("SAML authentication failed: {}", e);
            // Invalid credentials - show login page with error
            return show_saml_login(
                &realm,
                &form.saml_request_id,
                &form.sp_entity_id,
                None,
                &form.acs_url,
                form.relay_state.as_deref(),
                form.name_id_format.as_deref(),
                form.force_authn,
                Some("Invalid username or password"),
            );
        }
    };

    // Get IdP entity ID
    let base_url = state.config.base_url.clone();
    let idp_entity_id = format!("{}/realms/{}", base_url, realm);

    // Determine name ID format
    let name_id = match form.name_id_format.as_deref() {
        Some(fmt) if fmt.contains("emailAddress") => {
            NameId::email(user.email.as_deref().unwrap_or(&user.username))
        }
        Some(fmt) if fmt.contains("persistent") => NameId::persistent(&user.id.to_string()),
        Some(fmt) if fmt.contains("transient") => {
            NameId::transient(format!("_transient_{}", uuid::Uuid::new_v4()))
        }
        _ => NameId::new(&user.username),
    };

    // Build assertion
    let assertion = Assertion::new(&idp_entity_id)
        .with_subject(
            Subject::new(name_id).with_confirmation(
                SubjectConfirmation::bearer().with_data(
                    SubjectConfirmationData::for_request(&form.saml_request_id, &form.acs_url),
                ),
            ),
        )
        .with_conditions(Conditions::with_validity(5).with_audience(&form.sp_entity_id))
        .with_authn_statement(
            AuthnStatement::new(AuthnContextClass::PasswordProtectedTransport)
                .with_session_timeout(480),
        );

    // Build response
    let response = ResponseBuilder::new(&idp_entity_id)
        .in_response_to(&form.saml_request_id)
        .destination(&form.acs_url)
        .assertion(assertion)
        .build();

    // Serialize response to XML
    let response_xml = serialize_saml_response(&response);

    // Get signing config and sign the response
    let signed_xml = match providers.get_signing_config(&realm).await {
        Ok(signing_config) => {
            let signer = signing_config.create_signer();
            match signer.sign(&response_xml, &response.id) {
                Ok(signed) => signed,
                Err(e) => {
                    tracing::warn!("Failed to sign SAML response: {}, using unsigned", e);
                    response_xml
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to get signing config: {}, using unsigned response", e);
            response_xml
        }
    };

    // Encode and return POST binding form
    let html = HttpPostBinding::encode_response(
        &signed_xml,
        &form.acs_url,
        form.relay_state.as_deref(),
    );

    Html(html).into_response()
}

/// Serializes a SAML response to XML.
fn serialize_saml_response(response: &kc_protocol_saml::types::Response) -> String {
    let assertion_xml = if let Some(ref assertion) = response.assertions.first() {
        let subject_xml = if let Some(ref subject) = assertion.subject {
            let name_id_xml = if let Some(ref name_id) = subject.name_id {
                let format = name_id.format.as_deref().unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                format!(
                    r#"<saml:NameID Format="{}">{}</saml:NameID>"#,
                    format,
                    name_id.value
                )
            } else {
                String::new()
            };

            let confirmation_xml = if let Some(ref conf) = subject.subject_confirmations.first() {
                let data_xml = if let Some(ref data) = conf.subject_confirmation_data {
                    format!(
                        r#"<saml:SubjectConfirmationData InResponseTo="{}" Recipient="{}" NotOnOrAfter="{}"/>"#,
                        data.in_response_to.as_deref().unwrap_or(""),
                        data.recipient.as_deref().unwrap_or(""),
                        data.not_on_or_after.map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<saml:SubjectConfirmation Method="{}">
{}
</saml:SubjectConfirmation>"#,
                    conf.method,
                    data_xml
                )
            } else {
                String::new()
            };

            format!(
                r#"<saml:Subject>
{}
{}
</saml:Subject>"#,
                name_id_xml,
                confirmation_xml
            )
        } else {
            String::new()
        };

        let conditions_xml = if let Some(ref cond) = assertion.conditions {
            let audience_xml = cond
                .audience_restrictions
                .iter()
                .flat_map(|ar| ar.audiences.iter())
                .map(|a| format!("<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>", a))
                .collect::<Vec<_>>()
                .join("\n");

            let not_before = cond.not_before
                .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();
            let not_on_or_after = cond.not_on_or_after
                .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();

            format!(
                r#"<saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
{}
</saml:Conditions>"#,
                not_before,
                not_on_or_after,
                audience_xml
            )
        } else {
            String::new()
        };

        let authn_stmt_xml = if let Some(ref stmt) = assertion.authn_statement {
            let class_ref = stmt.authn_context.authn_context_class_ref.as_deref()
                .unwrap_or("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
            format!(
                r#"<saml:AuthnStatement AuthnInstant="{}">
<saml:AuthnContext>
<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>
</saml:AuthnContext>
</saml:AuthnStatement>"#,
                stmt.authn_instant.format("%Y-%m-%dT%H:%M:%SZ"),
                class_ref
            )
        } else {
            String::new()
        };

        format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" IssueInstant="{}" Version="2.0">
<saml:Issuer>{}</saml:Issuer>
{}
{}
{}
</saml:Assertion>"#,
            assertion.id,
            assertion.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
            assertion.issuer,
            subject_xml,
            conditions_xml,
            authn_stmt_xml
        )
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" InResponseTo="{}" IssueInstant="{}" Version="2.0" Destination="{}">
<saml:Issuer>{}</saml:Issuer>
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
    )
}

/// Error page for SAML.
pub fn saml_error_page(realm: &str, error: &str, description: Option<&str>) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SAML Error - {}</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
        .error {{ color: #d32f2f; }}
    </style>
</head>
<body>
    <h1>SAML Authentication Error</h1>
    <p class="error">{}</p>
    {}
</body>
</html>"#,
        realm,
        error,
        description
            .map(|d| format!("<p>{}</p>", d))
            .unwrap_or_default()
    );

    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
