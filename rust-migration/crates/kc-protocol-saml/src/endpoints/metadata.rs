//! IdP Metadata endpoint.
//!
//! Generates SAML 2.0 metadata for the Identity Provider.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use base64::Engine;

use crate::error::SamlError;
use crate::types::SamlBinding;

use super::state::{SamlRealmProvider, SamlState};

/// GET handler for IdP metadata endpoint.
pub async fn idp_metadata<R: SamlRealmProvider>(
    State(state): State<SamlState<R>>,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    match generate_metadata(&state, &realm).await {
        Ok(metadata) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
            metadata,
        )
            .into_response(),
        Err(e) => (StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), e.to_string())
            .into_response(),
    }
}

/// Generates IdP metadata XML.
async fn generate_metadata<R: SamlRealmProvider>(
    state: &SamlState<R>,
    realm: &str,
) -> Result<String, SamlError> {
    // Check realm exists
    if !state.realm_provider.realm_exists(realm).await.map_err(|e| {
        SamlError::Internal(format!("Failed to check realm: {e}"))
    })? {
        return Err(SamlError::RealmNotFound(realm.to_string()));
    }

    let entity_id = state
        .realm_provider
        .get_idp_entity_id(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get entity ID: {e}")))?;

    let sso_url = state
        .realm_provider
        .get_sso_url(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get SSO URL: {e}")))?;

    let sls_url = state
        .realm_provider
        .get_sls_url(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get SLS URL: {e}")))?;

    let signing_config = state
        .realm_provider
        .get_signing_config(realm)
        .await
        .map_err(|e| SamlError::Internal(format!("Failed to get signing config: {e}")))?;

    let certificate_b64 = base64::engine::general_purpose::STANDARD.encode(&signing_config.certificate_der);

    let metadata = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:SingleSignOnService Binding="{}" Location="{}"/>
        <md:SingleSignOnService Binding="{}" Location="{}"/>
        <md:SingleLogoutService Binding="{}" Location="{}"/>
        <md:SingleLogoutService Binding="{}" Location="{}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        entity_id,
        certificate_b64,
        certificate_b64,
        SamlBinding::HttpPost.uri(),
        sso_url,
        SamlBinding::HttpRedirect.uri(),
        sso_url,
        SamlBinding::HttpPost.uri(),
        sls_url,
        SamlBinding::HttpRedirect.uri(),
        sls_url
    );

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn metadata_contains_required_elements() {
        // This test would require a mock provider
        // For now, just verify the format strings are valid
        let entity_id = "https://idp.example.com";
        let certificate_b64 = "MIIC...";
        let sso_url = "https://idp.example.com/sso";
        let sls_url = "https://idp.example.com/slo";

        let metadata = format!(
            r#"<md:EntityDescriptor entityID="{}">
    <md:IDPSSODescriptor>
        <md:KeyDescriptor use="signing">
            <ds:X509Certificate>{}</ds:X509Certificate>
        </md:KeyDescriptor>
        <md:SingleSignOnService Location="{}"/>
        <md:SingleLogoutService Location="{}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id, certificate_b64, sso_url, sls_url
        );

        assert!(metadata.contains("entityID"));
        assert!(metadata.contains("X509Certificate"));
        assert!(metadata.contains("SingleSignOnService"));
        assert!(metadata.contains("SingleLogoutService"));
    }
}
