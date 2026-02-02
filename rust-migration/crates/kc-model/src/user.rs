//! User domain model.
//!
//! Users are the primary identity entities in Keycloak.
//! They belong to a realm and can have credentials, attributes,
//! role mappings, and group memberships.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user attribute (key-value pair).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAttribute {
    /// Attribute name.
    pub name: String,
    /// Attribute values (multi-valued attributes are common).
    pub values: Vec<String>,
}

impl UserAttribute {
    /// Creates a new single-valued attribute.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            values: vec![value.into()],
        }
    }

    /// Creates a new multi-valued attribute.
    #[must_use]
    pub fn multi(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            name: name.into(),
            values,
        }
    }

    /// Gets the first value, if any.
    #[must_use]
    pub fn first_value(&self) -> Option<&str> {
        self.values.first().map(String::as_str)
    }
}

/// A federated identity link (e.g., Google, GitHub login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedIdentity {
    /// Identity provider alias (e.g., "google", "github").
    pub identity_provider: String,
    /// User ID at the identity provider.
    pub user_id: String,
    /// Username at the identity provider.
    pub user_name: Option<String>,
}

impl FederatedIdentity {
    /// Creates a new federated identity.
    #[must_use]
    pub fn new(provider: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            identity_provider: provider.into(),
            user_id: user_id.into(),
            user_name: None,
        }
    }
}

/// A Keycloak user.
///
/// Users represent individual identities within a realm.
/// They can authenticate using credentials (passwords, OTP, etc.)
/// and may have roles and group memberships for authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    // === Identity ===
    /// Unique identifier.
    pub id: Uuid,
    /// Realm this user belongs to.
    pub realm_id: Uuid,
    /// Unique username within the realm.
    pub username: String,
    /// Whether the user account is enabled.
    pub enabled: bool,

    // === Profile ===
    /// User's first name.
    pub first_name: Option<String>,
    /// User's last name.
    pub last_name: Option<String>,
    /// User's email address.
    pub email: Option<String>,
    /// Whether the email has been verified.
    pub email_verified: bool,

    // === Timestamps ===
    /// When the user was created.
    pub created_at: DateTime<Utc>,
    /// When the user was last updated.
    pub updated_at: DateTime<Utc>,

    // === Security ===
    /// Token not-before timestamp (invalidate tokens issued before this).
    pub not_before: i64,

    // === Federation ===
    /// Link to external user federation provider.
    pub federation_link: Option<String>,
    /// Link to service account client (if this is a service account).
    pub service_account_client_link: Option<Uuid>,

    // === Required Actions ===
    /// Pending required actions (e.g., `UPDATE_PASSWORD`, `VERIFY_EMAIL`).
    pub required_actions: Vec<String>,

    // === Custom Attributes ===
    /// Custom user attributes.
    pub attributes: HashMap<String, Vec<String>>,

    // === Federated Identities ===
    /// Linked external identities (social logins, etc.).
    pub federated_identities: Vec<FederatedIdentity>,
}

impl User {
    /// Creates a new user with the given username.
    #[must_use]
    pub fn new(realm_id: Uuid, username: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            realm_id,
            username: username.into(),
            enabled: true,
            first_name: None,
            last_name: None,
            email: None,
            email_verified: false,
            created_at: now,
            updated_at: now,
            not_before: 0,
            federation_link: None,
            service_account_client_link: None,
            required_actions: Vec::new(),
            attributes: HashMap::new(),
            federated_identities: Vec::new(),
        }
    }

    /// Sets the user's email.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the user's first name.
    #[must_use]
    pub fn with_first_name(mut self, name: impl Into<String>) -> Self {
        self.first_name = Some(name.into());
        self
    }

    /// Sets the user's last name.
    #[must_use]
    pub fn with_last_name(mut self, name: impl Into<String>) -> Self {
        self.last_name = Some(name.into());
        self
    }

    /// Sets whether the user is enabled.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Adds a required action.
    #[must_use]
    pub fn with_required_action(mut self, action: impl Into<String>) -> Self {
        self.required_actions.push(action.into());
        self
    }

    /// Gets the user's full name.
    #[must_use]
    pub fn full_name(&self) -> Option<String> {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => None,
        }
    }

    /// Checks if this is a service account.
    #[must_use]
    pub const fn is_service_account(&self) -> bool {
        self.service_account_client_link.is_some()
    }

    /// Checks if this is a federated user.
    #[must_use]
    pub const fn is_federated(&self) -> bool {
        self.federation_link.is_some()
    }

    /// Checks if the user has a specific required action.
    #[must_use]
    pub fn has_required_action(&self, action: &str) -> bool {
        self.required_actions.iter().any(|a| a == action)
    }

    /// Gets an attribute value.
    #[must_use]
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }

    /// Gets the first value of an attribute.
    #[must_use]
    pub fn get_first_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Sets an attribute value.
    pub fn set_attribute(&mut self, name: impl Into<String>, values: Vec<String>) {
        self.attributes.insert(name.into(), values);
    }

    /// Adds a federated identity.
    pub fn add_federated_identity(&mut self, identity: FederatedIdentity) {
        self.federated_identities.push(identity);
    }

    /// Finds a federated identity by provider.
    #[must_use]
    pub fn get_federated_identity(&self, provider: &str) -> Option<&FederatedIdentity> {
        self.federated_identities
            .iter()
            .find(|fi| fi.identity_provider == provider)
    }
}

/// Common required action constants.
pub mod required_actions {
    /// User must update their password.
    pub const UPDATE_PASSWORD: &str = "UPDATE_PASSWORD";
    /// User must verify their email.
    pub const VERIFY_EMAIL: &str = "VERIFY_EMAIL";
    /// User must update their profile.
    pub const UPDATE_PROFILE: &str = "UPDATE_PROFILE";
    /// User must configure OTP.
    pub const CONFIGURE_TOTP: &str = "CONFIGURE_TOTP";
    /// User must accept terms and conditions.
    pub const TERMS_AND_CONDITIONS: &str = "TERMS_AND_CONDITIONS";
    /// User must configure `WebAuthn`.
    pub const WEBAUTHN_REGISTER: &str = "webauthn-register";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_user_has_defaults() {
        let realm_id = Uuid::now_v7();
        let user = User::new(realm_id, "testuser");

        assert_eq!(user.username, "testuser");
        assert_eq!(user.realm_id, realm_id);
        assert!(user.enabled);
        assert!(!user.email_verified);
        assert!(user.required_actions.is_empty());
    }

    #[test]
    fn builder_pattern_works() {
        let realm_id = Uuid::now_v7();
        let user = User::new(realm_id, "john")
            .with_email("john@example.com")
            .with_first_name("John")
            .with_last_name("Doe")
            .with_required_action(required_actions::VERIFY_EMAIL);

        assert_eq!(user.email, Some("john@example.com".to_string()));
        assert_eq!(user.full_name(), Some("John Doe".to_string()));
        assert!(user.has_required_action(required_actions::VERIFY_EMAIL));
    }

    #[test]
    fn full_name_handles_partial() {
        let realm_id = Uuid::now_v7();

        let user_both = User::new(realm_id, "u1")
            .with_first_name("John")
            .with_last_name("Doe");
        assert_eq!(user_both.full_name(), Some("John Doe".to_string()));

        let user_first = User::new(realm_id, "u2").with_first_name("John");
        assert_eq!(user_first.full_name(), Some("John".to_string()));

        let user_last = User::new(realm_id, "u3").with_last_name("Doe");
        assert_eq!(user_last.full_name(), Some("Doe".to_string()));

        let user_none = User::new(realm_id, "u4");
        assert_eq!(user_none.full_name(), None);
    }

    #[test]
    fn attributes_work() {
        let realm_id = Uuid::now_v7();
        let mut user = User::new(realm_id, "testuser");

        user.set_attribute("department", vec!["Engineering".to_string()]);
        user.set_attribute("roles", vec!["admin".to_string(), "developer".to_string()]);

        assert_eq!(user.get_first_attribute("department"), Some("Engineering"));
        assert_eq!(
            user.get_attribute("roles"),
            Some(&vec!["admin".to_string(), "developer".to_string()])
        );
        assert_eq!(user.get_attribute("missing"), None);
    }

    #[test]
    fn federated_identity_works() {
        let realm_id = Uuid::now_v7();
        let mut user = User::new(realm_id, "testuser");

        user.add_federated_identity(FederatedIdentity::new("google", "12345"));
        user.add_federated_identity(FederatedIdentity::new("github", "67890"));

        assert!(user.get_federated_identity("google").is_some());
        assert!(user.get_federated_identity("github").is_some());
        assert!(user.get_federated_identity("facebook").is_none());
    }
}
