//! Custom SAML endpoint handlers for kc-server.
//!
//! These handlers override the default kc-protocol-saml handlers to integrate
//! with the server's authentication flow.

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    Form,
};

use kc_protocol_saml::endpoints::{
    process_sso_post, process_sso_redirect, SamlState, SsoAction, SsoPostForm, SsoRedirectParams,
};
use kc_protocol_saml::error::SamlError;

use crate::providers::StorageProviders;
use crate::saml_ui::{saml_error_page, show_saml_login};

/// Custom SSO redirect handler that shows a login page.
pub async fn custom_sso_redirect(
    State(state): State<SamlState<StorageProviders>>,
    Path(realm): Path<String>,
    Query(params): Query<SsoRedirectParams>,
) -> Response {
    match process_sso_redirect(&state, &realm, &params).await {
        Ok(action) => handle_sso_action(action),
        Err(e) => error_response(&realm, &e),
    }
}

/// Custom SSO POST handler that shows a login page.
pub async fn custom_sso_post(
    State(state): State<SamlState<StorageProviders>>,
    Path(realm): Path<String>,
    Form(form): Form<SsoPostForm>,
) -> Response {
    match process_sso_post(&state, &realm, &form).await {
        Ok(action) => handle_sso_action(action),
        Err(e) => error_response(&realm, &e),
    }
}

/// Handles the SSO action returned by the protocol layer.
fn handle_sso_action(action: SsoAction) -> Response {
    match action {
        SsoAction::ShowLoginPage {
            realm,
            request,
            relay_state,
        } => {
            let acs_url = request.assertion_consumer_service_url.as_deref().unwrap_or("");
            show_saml_login(
                &realm,
                &request.id,
                &request.issuer,
                None, // SP name could be looked up from registered clients
                acs_url,
                relay_state.as_deref(),
                request.name_id_policy_format.as_deref(),
                request.force_authn,
                None,
            )
        }
        SsoAction::SendResponse {
            response_xml,
            acs_url,
            relay_state,
        } => {
            use axum::response::Html;
            use kc_protocol_saml::bindings::HttpPostBinding;

            let html = HttpPostBinding::encode_response(
                &response_xml,
                &acs_url,
                relay_state.as_deref(),
            );
            Html(html).into_response()
        }
    }
}

/// Creates an error response for SAML errors.
fn error_response(realm: &str, err: &SamlError) -> Response {
    let description = match err {
        SamlError::InvalidRequest(msg) => Some(msg.as_str()),
        SamlError::Internal(msg) => Some(msg.as_str()),
        _ => None,
    };
    saml_error_page(realm, &err.to_string(), description)
}
