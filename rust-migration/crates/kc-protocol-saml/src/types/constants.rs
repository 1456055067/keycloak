//! SAML 2.0 constants and URIs.
//!
//! Contains namespace URIs, binding URIs, name ID formats, and other
//! constants defined in the SAML 2.0 specification.

/// SAML 2.0 namespace URI.
pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// SAML 2.0 protocol namespace URI.
pub const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// XML Digital Signature namespace URI.
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// XML Encryption namespace URI.
pub const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

/// XSI namespace URI.
pub const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// XS namespace URI.
pub const XS_NS: &str = "http://www.w3.org/2001/XMLSchema";

// ============================================================================
// Binding URIs
// ============================================================================

/// SAML binding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SamlBinding {
    /// HTTP POST binding.
    HttpPost,
    /// HTTP Redirect binding.
    HttpRedirect,
    /// HTTP Artifact binding.
    HttpArtifact,
    /// SOAP binding.
    Soap,
}

impl SamlBinding {
    /// Returns the URI for this binding.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Self::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Self::HttpArtifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            Self::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        }
    }

    /// Parses a binding from its URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Some(Self::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" => Some(Self::HttpRedirect),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" => Some(Self::HttpArtifact),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" => Some(Self::Soap),
            _ => None,
        }
    }
}

// ============================================================================
// Name ID Formats
// ============================================================================

/// SAML Name ID formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NameIdFormat {
    /// Unspecified name ID format.
    #[default]
    Unspecified,
    /// Email address format.
    Email,
    /// X.509 subject name format.
    X509SubjectName,
    /// Windows domain qualified name format.
    WindowsDomainQualifiedName,
    /// Kerberos principal name format.
    Kerberos,
    /// Entity identifier format.
    Entity,
    /// Persistent identifier format.
    Persistent,
    /// Transient identifier format.
    Transient,
}

impl NameIdFormat {
    /// Returns the URI for this name ID format.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            Self::Email => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::X509SubjectName => "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
            Self::WindowsDomainQualifiedName => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
            }
            Self::Kerberos => "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
            Self::Entity => "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        }
    }

    /// Parses a name ID format from its URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" => Some(Self::Unspecified),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => Some(Self::Email),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" => {
                Some(Self::X509SubjectName)
            }
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" => {
                Some(Self::WindowsDomainQualifiedName)
            }
            "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos" => Some(Self::Kerberos),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" => Some(Self::Entity),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => Some(Self::Persistent),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => Some(Self::Transient),
            _ => None,
        }
    }
}

// ============================================================================
// Authentication Context Classes
// ============================================================================

/// SAML authentication context class references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthnContextClass {
    /// Unspecified authentication context.
    #[default]
    Unspecified,
    /// Password-based authentication.
    Password,
    /// Password protected transport (TLS + password).
    PasswordProtectedTransport,
    /// X.509 certificate authentication.
    X509,
    /// TLS client authentication.
    TlsClient,
    /// Kerberos authentication.
    Kerberos,
    /// Previous session (SSO).
    PreviousSession,
}

impl AuthnContextClass {
    /// Returns the URI for this authentication context class.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            Self::Password => "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            Self::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            Self::X509 => "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
            Self::TlsClient => "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
            Self::Kerberos => "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            Self::PreviousSession => "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession",
        }
    }

    /// Parses an authentication context class from its URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" => Some(Self::Unspecified),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" => Some(Self::Password),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" => {
                Some(Self::PasswordProtectedTransport)
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:X509" => Some(Self::X509),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient" => Some(Self::TlsClient),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos" => Some(Self::Kerberos),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession" => Some(Self::PreviousSession),
            _ => None,
        }
    }
}

// ============================================================================
// Status Codes
// ============================================================================

/// Top-level SAML status codes.
pub mod status_codes {
    /// Success status code.
    pub const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

    /// Requester error status code.
    pub const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";

    /// Responder error status code.
    pub const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";

    /// Version mismatch status code.
    pub const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
}

/// Second-level SAML status codes.
pub mod sub_status_codes {
    /// Authentication failed.
    pub const AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

    /// Invalid attribute name or value.
    pub const INVALID_ATTR_NAME_OR_VALUE: &str =
        "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";

    /// Invalid name ID policy.
    pub const INVALID_NAMEID_POLICY: &str = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";

    /// No authn context.
    pub const NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";

    /// No available IDP.
    pub const NO_AVAILABLE_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";

    /// No passive.
    pub const NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

    /// No supported IDP.
    pub const NO_SUPPORTED_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";

    /// Partial logout.
    pub const PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

    /// Proxy count exceeded.
    pub const PROXY_COUNT_EXCEEDED: &str = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";

    /// Request denied.
    pub const REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";

    /// Request unsupported.
    pub const REQUEST_UNSUPPORTED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";

    /// Request version deprecated.
    pub const REQUEST_VERSION_DEPRECATED: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";

    /// Request version too high.
    pub const REQUEST_VERSION_TOO_HIGH: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";

    /// Request version too low.
    pub const REQUEST_VERSION_TOO_LOW: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";

    /// Resource not recognized.
    pub const RESOURCE_NOT_RECOGNIZED: &str =
        "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";

    /// Too many responses.
    pub const TOO_MANY_RESPONSES: &str = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";

    /// Unknown attribute profile.
    pub const UNKNOWN_ATTR_PROFILE: &str =
        "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";

    /// Unknown principal.
    pub const UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

    /// Unsupported binding.
    pub const UNSUPPORTED_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
}

// ============================================================================
// Signature Algorithms
// ============================================================================

/// XML signature algorithms.
pub mod signature_algorithms {
    /// RSA-SHA256 signature algorithm.
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// RSA-SHA384 signature algorithm.
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    /// RSA-SHA512 signature algorithm.
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /// ECDSA-SHA256 signature algorithm.
    pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// ECDSA-SHA384 signature algorithm.
    pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    /// ECDSA-SHA512 signature algorithm.
    pub const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// Legacy RSA-SHA1 signature algorithm (not recommended).
    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
}

/// Digest algorithms.
pub mod digest_algorithms {
    /// SHA-256 digest algorithm.
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// SHA-384 digest algorithm.
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /// SHA-512 digest algorithm.
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

    /// Legacy SHA-1 digest algorithm (not recommended).
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
}

/// Canonicalization algorithms.
pub mod canonicalization_algorithms {
    /// Exclusive C14N without comments.
    pub const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// Exclusive C14N with comments.
    pub const EXCLUSIVE_C14N_WITH_COMMENTS: &str =
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    /// C14N without comments.
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /// C14N with comments.
    pub const C14N_WITH_COMMENTS: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_uri_roundtrip() {
        for binding in [
            SamlBinding::HttpPost,
            SamlBinding::HttpRedirect,
            SamlBinding::HttpArtifact,
            SamlBinding::Soap,
        ] {
            let uri = binding.uri();
            let parsed = SamlBinding::from_uri(uri);
            assert_eq!(parsed, Some(binding));
        }
    }

    #[test]
    fn name_id_format_uri_roundtrip() {
        for format in [
            NameIdFormat::Unspecified,
            NameIdFormat::Email,
            NameIdFormat::Persistent,
            NameIdFormat::Transient,
        ] {
            let uri = format.uri();
            let parsed = NameIdFormat::from_uri(uri);
            assert_eq!(parsed, Some(format));
        }
    }

    #[test]
    fn authn_context_uri_roundtrip() {
        for ctx in [
            AuthnContextClass::Unspecified,
            AuthnContextClass::Password,
            AuthnContextClass::PasswordProtectedTransport,
        ] {
            let uri = ctx.uri();
            let parsed = AuthnContextClass::from_uri(uri);
            assert_eq!(parsed, Some(ctx));
        }
    }
}
