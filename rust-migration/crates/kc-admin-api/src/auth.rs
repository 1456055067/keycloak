//! Authentication and authorization middleware for Admin API.
//!
//! Provides Axum middleware layers for:
//! - Bearer token authentication
//! - Role-based access control (RBAC)
//! - Fine-grained permissions
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - AC-3: Access Enforcement
//! - AC-6: Least Privilege
//! - IA-2: Identification and Authentication

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AdminError;

// ============================================================================
// Permission Types
// ============================================================================

/// Admin API permissions following Keycloak's permission model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    // Realm permissions
    /// View realm settings.
    ViewRealm,
    /// Manage realm settings.
    ManageRealm,

    // User permissions
    /// View users in a realm.
    ViewUsers,
    /// Manage users (create, update, delete).
    ManageUsers,
    /// Impersonate users.
    ImpersonateUsers,

    // Client permissions
    /// View clients in a realm.
    ViewClients,
    /// Manage clients (create, update, delete).
    ManageClients,

    // Role permissions
    /// View roles in a realm.
    ViewRoles,
    /// Manage roles (create, update, delete, assign).
    ManageRoles,

    // Group permissions
    /// View groups in a realm.
    ViewGroups,
    /// Manage groups (create, update, delete).
    ManageGroups,

    // Identity provider permissions
    /// View identity providers.
    ViewIdentityProviders,
    /// Manage identity providers.
    ManageIdentityProviders,

    // Event permissions
    /// View events.
    ViewEvents,
    /// Manage events.
    ManageEvents,

    // Authorization permissions
    /// View authorization settings.
    ViewAuthorization,
    /// Manage authorization settings.
    ManageAuthorization,

    /// Full admin access (superuser).
    RealmAdmin,
}

impl Permission {
    /// Returns all permissions implied by this permission.
    ///
    /// For example, `ManageUsers` implies `ViewUsers`.
    #[must_use]
    pub fn implies(&self) -> Vec<Self> {
        match self {
            Self::RealmAdmin => vec![
                Self::ViewRealm,
                Self::ManageRealm,
                Self::ViewUsers,
                Self::ManageUsers,
                Self::ImpersonateUsers,
                Self::ViewClients,
                Self::ManageClients,
                Self::ViewRoles,
                Self::ManageRoles,
                Self::ViewGroups,
                Self::ManageGroups,
                Self::ViewIdentityProviders,
                Self::ManageIdentityProviders,
                Self::ViewEvents,
                Self::ManageEvents,
                Self::ViewAuthorization,
                Self::ManageAuthorization,
            ],
            Self::ManageRealm => vec![Self::ViewRealm],
            Self::ManageUsers => vec![Self::ViewUsers],
            Self::ManageClients => vec![Self::ViewClients],
            Self::ManageRoles => vec![Self::ViewRoles],
            Self::ManageGroups => vec![Self::ViewGroups],
            Self::ManageIdentityProviders => vec![Self::ViewIdentityProviders],
            Self::ManageEvents => vec![Self::ViewEvents],
            Self::ManageAuthorization => vec![Self::ViewAuthorization],
            _ => vec![],
        }
    }

    /// Maps a Keycloak role name to a permission.
    #[must_use]
    pub fn from_role_name(role: &str) -> Option<Self> {
        match role {
            "realm-admin" | "admin" => Some(Self::RealmAdmin),
            "view-realm" => Some(Self::ViewRealm),
            "manage-realm" => Some(Self::ManageRealm),
            "view-users" => Some(Self::ViewUsers),
            "manage-users" => Some(Self::ManageUsers),
            "impersonation" => Some(Self::ImpersonateUsers),
            "view-clients" => Some(Self::ViewClients),
            "manage-clients" => Some(Self::ManageClients),
            "view-roles" => Some(Self::ViewRoles),
            "manage-roles" => Some(Self::ManageRoles),
            "view-groups" => Some(Self::ViewGroups),
            "manage-groups" => Some(Self::ManageGroups),
            "view-identity-providers" => Some(Self::ViewIdentityProviders),
            "manage-identity-providers" => Some(Self::ManageIdentityProviders),
            "view-events" => Some(Self::ViewEvents),
            "manage-events" => Some(Self::ManageEvents),
            "view-authorization" => Some(Self::ViewAuthorization),
            "manage-authorization" => Some(Self::ManageAuthorization),
            _ => None,
        }
    }

    /// Returns the role name for this permission.
    #[must_use]
    pub const fn role_name(&self) -> &'static str {
        match self {
            Self::RealmAdmin => "realm-admin",
            Self::ViewRealm => "view-realm",
            Self::ManageRealm => "manage-realm",
            Self::ViewUsers => "view-users",
            Self::ManageUsers => "manage-users",
            Self::ImpersonateUsers => "impersonation",
            Self::ViewClients => "view-clients",
            Self::ManageClients => "manage-clients",
            Self::ViewRoles => "view-roles",
            Self::ManageRoles => "manage-roles",
            Self::ViewGroups => "view-groups",
            Self::ManageGroups => "manage-groups",
            Self::ViewIdentityProviders => "view-identity-providers",
            Self::ManageIdentityProviders => "manage-identity-providers",
            Self::ViewEvents => "view-events",
            Self::ManageEvents => "manage-events",
            Self::ViewAuthorization => "view-authorization",
            Self::ManageAuthorization => "manage-authorization",
        }
    }
}

// ============================================================================
// Authentication Context
// ============================================================================

/// Authenticated admin user context.
///
/// Extracted from the Bearer token and made available to handlers.
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// User ID from the token.
    pub user_id: Uuid,
    /// Username.
    pub username: String,
    /// Realm the user belongs to.
    pub realm: String,
    /// Realm being accessed (from URL path).
    pub target_realm: Option<String>,
    /// Permissions granted to this user.
    pub permissions: Vec<Permission>,
    /// Raw token (for forwarding to other services).
    pub token: String,
}

impl AdminAuth {
    /// Checks if the user has a specific permission.
    #[must_use]
    pub fn has_permission(&self, permission: Permission) -> bool {
        // Check direct permissions
        if self.permissions.contains(&permission) {
            return true;
        }

        // Check implied permissions
        for p in &self.permissions {
            if p.implies().contains(&permission) {
                return true;
            }
        }

        false
    }

    /// Checks if the user has any of the specified permissions.
    #[must_use]
    pub fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        permissions.iter().any(|p| self.has_permission(*p))
    }

    /// Checks if the user has all of the specified permissions.
    #[must_use]
    pub fn has_all_permissions(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.has_permission(*p))
    }

    /// Ensures the user has a specific permission, returning an error if not.
    ///
    /// # Errors
    ///
    /// Returns `AdminError::Forbidden` if the user lacks the permission.
    pub fn require_permission(&self, permission: Permission) -> Result<(), AdminError> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(AdminError::Forbidden(format!(
                "Missing required permission: {}",
                permission.role_name()
            )))
        }
    }

    /// Ensures the user has any of the specified permissions.
    ///
    /// # Errors
    ///
    /// Returns `AdminError::Forbidden` if the user lacks all permissions.
    pub fn require_any_permission(&self, permissions: &[Permission]) -> Result<(), AdminError> {
        if self.has_any_permission(permissions) {
            Ok(())
        } else {
            let names: Vec<_> = permissions.iter().map(Permission::role_name).collect();
            Err(AdminError::Forbidden(format!(
                "Missing required permission (one of): {}",
                names.join(", ")
            )))
        }
    }
}

// ============================================================================
// Token Validator Trait
// ============================================================================

/// Trait for validating admin access tokens.
///
/// Implementations should verify the token signature, expiration,
/// and extract user information and permissions.
#[allow(async_fn_in_trait)]
pub trait TokenValidator: Send + Sync {
    /// Validates a bearer token and extracts the admin auth context.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or the user
    /// lacks admin access.
    async fn validate(&self, token: &str, target_realm: Option<&str>) -> Result<AdminAuth, AdminError>;
}

/// Simple in-memory token validator for testing.
///
/// In production, use a proper JWT validator that checks signatures
/// against the realm's public keys.
#[derive(Debug, Clone)]
pub struct SimpleTokenValidator {
    /// Predefined valid tokens for testing.
    valid_tokens: std::collections::HashMap<String, AdminAuth>,
}

impl SimpleTokenValidator {
    /// Creates a new simple token validator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            valid_tokens: std::collections::HashMap::new(),
        }
    }

    /// Adds a valid token for testing.
    pub fn add_token(&mut self, token: impl Into<String>, auth: AdminAuth) {
        self.valid_tokens.insert(token.into(), auth);
    }
}

impl Default for SimpleTokenValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenValidator for SimpleTokenValidator {
    async fn validate(&self, token: &str, target_realm: Option<&str>) -> Result<AdminAuth, AdminError> {
        self.valid_tokens
            .get(token)
            .cloned()
            .map(|mut auth| {
                auth.target_realm = target_realm.map(String::from);
                auth
            })
            .ok_or(AdminError::Unauthorized)
    }
}

// ============================================================================
// Axum Middleware
// ============================================================================

/// Shared state for authentication middleware.
#[derive(Clone)]
pub struct AuthState<V: TokenValidator> {
    /// Token validator implementation.
    pub validator: Arc<V>,
}

impl<V: TokenValidator> AuthState<V> {
    /// Creates a new auth state with the given validator.
    pub fn new(validator: V) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }
}

/// Authentication middleware that validates bearer tokens.
///
/// Extracts the `Authorization: Bearer <token>` header, validates it,
/// and injects `AdminAuth` into the request extensions.
pub async fn auth_middleware<V: TokenValidator + 'static>(
    State(state): State<AuthState<V>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract bearer token from Authorization header
    let token = match extract_bearer_token(&request) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                "Missing or invalid Authorization header",
            )
                .into_response();
        }
    };

    // Extract target realm from path (e.g., /admin/realms/{realm}/...)
    let target_realm = extract_target_realm(request.uri().path());

    // Validate token
    match state.validator.validate(&token, target_realm.as_deref()).await {
        Ok(auth) => {
            // Insert auth context into request extensions
            request.extensions_mut().insert(auth);
            next.run(request).await
        }
        Err(e) => {
            let status = match &e {
                AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
                AdminError::Forbidden(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string()).into_response()
        }
    }
}

/// Extracts the bearer token from the request.
fn extract_bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get(AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from)
}

/// Extracts the target realm from the request path.
fn extract_target_realm(path: &str) -> Option<String> {
    // Match pattern: /admin/realms/{realm}/...
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() >= 4 && parts[1] == "admin" && parts[2] == "realms" {
        Some(parts[3].to_string())
    } else {
        None
    }
}

// ============================================================================
// Extractor Implementation
// ============================================================================

/// Axum extractor for `AdminAuth`.
///
/// Use this in handler functions to get the authenticated user context:
///
/// ```ignore
/// async fn handler(auth: AdminAuth) -> impl IntoResponse {
///     // auth.user_id, auth.permissions, etc.
/// }
/// ```
impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AdminAuth>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated"))
    }
}

// ============================================================================
// Permission Guard
// ============================================================================

/// Creates a permission-checking middleware layer.
///
/// Use this to protect routes that require specific permissions:
///
/// ```ignore
/// let router = Router::new()
///     .route("/users", get(list_users))
///     .layer(require_permission(Permission::ViewUsers));
/// ```
pub fn require_permission(
    permission: Permission,
) -> impl Fn(Request, Next) -> Pin<Box<dyn Future<Output = Response> + Send>> + Clone {
    move |request: Request, next: Next| {
        let permission = permission;
        Box::pin(async move {
            let auth = request.extensions().get::<AdminAuth>().cloned();

            match auth {
                Some(auth) if auth.has_permission(permission) => next.run(request).await,
                Some(_) => (
                    StatusCode::FORBIDDEN,
                    format!("Missing required permission: {}", permission.role_name()),
                )
                    .into_response(),
                None => (StatusCode::UNAUTHORIZED, "Not authenticated").into_response(),
            }
        })
    }
}

/// Creates a middleware layer requiring any of the specified permissions.
pub fn require_any_permission(
    permissions: Vec<Permission>,
) -> impl Fn(Request, Next) -> Pin<Box<dyn Future<Output = Response> + Send>> + Clone {
    move |request: Request, next: Next| {
        let permissions = permissions.clone();
        Box::pin(async move {
            let auth = request.extensions().get::<AdminAuth>().cloned();

            match auth {
                Some(auth) if auth.has_any_permission(&permissions) => next.run(request).await,
                Some(_) => {
                    let names: Vec<_> = permissions.iter().map(Permission::role_name).collect();
                    (
                        StatusCode::FORBIDDEN,
                        format!("Missing required permission (one of): {}", names.join(", ")),
                    )
                        .into_response()
                }
                None => (StatusCode::UNAUTHORIZED, "Not authenticated").into_response(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_implies() {
        assert!(Permission::RealmAdmin.implies().contains(&Permission::ViewUsers));
        assert!(Permission::ManageUsers.implies().contains(&Permission::ViewUsers));
        assert!(Permission::ViewUsers.implies().is_empty());
    }

    #[test]
    fn permission_from_role_name() {
        assert_eq!(
            Permission::from_role_name("realm-admin"),
            Some(Permission::RealmAdmin)
        );
        assert_eq!(
            Permission::from_role_name("view-users"),
            Some(Permission::ViewUsers)
        );
        assert_eq!(Permission::from_role_name("unknown"), None);
    }

    #[test]
    fn admin_auth_has_permission() {
        let auth = AdminAuth {
            user_id: Uuid::now_v7(),
            username: "admin".to_string(),
            realm: "master".to_string(),
            target_realm: Some("test".to_string()),
            permissions: vec![Permission::ManageUsers],
            token: "test-token".to_string(),
        };

        // Direct permission
        assert!(auth.has_permission(Permission::ManageUsers));

        // Implied permission
        assert!(auth.has_permission(Permission::ViewUsers));

        // Not granted
        assert!(!auth.has_permission(Permission::ManageClients));
    }

    #[test]
    fn admin_auth_realm_admin_has_all() {
        let auth = AdminAuth {
            user_id: Uuid::now_v7(),
            username: "admin".to_string(),
            realm: "master".to_string(),
            target_realm: None,
            permissions: vec![Permission::RealmAdmin],
            token: "test-token".to_string(),
        };

        assert!(auth.has_permission(Permission::ViewUsers));
        assert!(auth.has_permission(Permission::ManageUsers));
        assert!(auth.has_permission(Permission::ViewClients));
        assert!(auth.has_permission(Permission::ManageRoles));
    }

    #[test]
    fn extract_target_realm_works() {
        assert_eq!(
            extract_target_realm("/admin/realms/test/users"),
            Some("test".to_string())
        );
        assert_eq!(
            extract_target_realm("/admin/realms/my-realm/clients/123"),
            Some("my-realm".to_string())
        );
        assert_eq!(extract_target_realm("/admin/realms"), None);
        assert_eq!(extract_target_realm("/other/path"), None);
    }
}
