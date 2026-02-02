//! User DTOs for the Admin API.

use std::collections::HashMap;

use chrono::Utc;
use kc_model::{FederatedIdentity, User};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create a new user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    /// Username (required, unique within realm).
    pub username: String,
    /// Whether the user is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// User's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email has been verified.
    #[serde(default)]
    pub email_verified: bool,
    /// User's first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// User's last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Custom user attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
    /// Required actions for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_actions: Vec<String>,
    /// Credentials to set for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialRequest>,
}

fn default_enabled() -> bool {
    true
}

impl CreateUserRequest {
    /// Converts this request to a domain `User` model.
    #[must_use]
    pub fn into_user(self, realm_id: Uuid) -> User {
        let mut user = User::new(realm_id, self.username);
        user.enabled = self.enabled;
        user.email = self.email;
        user.email_verified = self.email_verified;
        user.first_name = self.first_name;
        user.last_name = self.last_name;
        user.attributes = self.attributes;
        user.required_actions = self.required_actions;
        user
    }
}

/// Request to update a user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    /// Username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Whether the user is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// User's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// User's first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// User's last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Custom user attributes (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, Vec<String>>>,
    /// Required actions (replaces existing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_actions: Option<Vec<String>>,
}

impl UpdateUserRequest {
    /// Applies this update to an existing user.
    pub fn apply_to(&self, user: &mut User) {
        if let Some(ref v) = self.username {
            user.username = v.clone();
        }
        if let Some(v) = self.enabled {
            user.enabled = v;
        }
        if let Some(ref v) = self.email {
            user.email = Some(v.clone());
        }
        if let Some(v) = self.email_verified {
            user.email_verified = v;
        }
        if let Some(ref v) = self.first_name {
            user.first_name = Some(v.clone());
        }
        if let Some(ref v) = self.last_name {
            user.last_name = Some(v.clone());
        }
        if let Some(ref v) = self.attributes {
            user.attributes = v.clone();
        }
        if let Some(ref v) = self.required_actions {
            user.required_actions = v.clone();
        }
        user.updated_at = Utc::now();
    }
}

/// Credential request for setting user credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// Credential type (e.g., "password").
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Credential value.
    pub value: String,
    /// Whether the credential is temporary (requires change on next login).
    #[serde(default)]
    pub temporary: bool,
}

/// Full user representation for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRepresentation {
    /// Unique identifier.
    pub id: Uuid,
    /// Username.
    pub username: String,
    /// Whether the user is enabled.
    pub enabled: bool,
    /// User's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email has been verified.
    pub email_verified: bool,
    /// User's first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// User's last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// When the user was created (milliseconds since epoch).
    pub created_timestamp: i64,
    /// Custom user attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, Vec<String>>,
    /// Required actions for the user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_actions: Vec<String>,
    /// Federated identities linked to this user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federated_identities: Vec<FederatedIdentityRepresentation>,
    /// Whether this is a service account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account_client_id: Option<Uuid>,
}

impl From<User> for UserRepresentation {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            enabled: user.enabled,
            email: user.email,
            email_verified: user.email_verified,
            first_name: user.first_name,
            last_name: user.last_name,
            created_timestamp: user.created_at.timestamp_millis(),
            attributes: user.attributes,
            required_actions: user.required_actions,
            federated_identities: user
                .federated_identities
                .into_iter()
                .map(FederatedIdentityRepresentation::from)
                .collect(),
            service_account_client_id: user.service_account_client_link,
        }
    }
}

/// Federated identity representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIdentityRepresentation {
    /// Identity provider alias.
    pub identity_provider: String,
    /// User ID at the identity provider.
    pub user_id: String,
    /// Username at the identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

impl From<FederatedIdentity> for FederatedIdentityRepresentation {
    fn from(fi: FederatedIdentity) -> Self {
        Self {
            identity_provider: fi.identity_provider,
            user_id: fi.user_id,
            user_name: fi.user_name,
        }
    }
}

/// Query parameters for user search.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSearchParams {
    /// Search string (matches username, email, first name, last name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Filter by username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Filter by email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Filter by first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Filter by last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Filter by enabled status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Filter by email verified status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// Starting offset for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<usize>,
}

impl UserSearchParams {
    /// Converts to storage search criteria.
    #[must_use]
    pub fn into_criteria(self) -> kc_storage::user::UserSearchCriteria {
        let mut criteria = kc_storage::user::UserSearchCriteria::new();
        if let Some(s) = self.search {
            criteria = criteria.search(s);
        }
        if let Some(u) = self.username {
            criteria = criteria.username(u);
        }
        if let Some(e) = self.email {
            criteria = criteria.email(e);
        }
        if let Some(e) = self.enabled {
            criteria = criteria.enabled(e);
        }
        if let Some(m) = self.max {
            criteria = criteria.max_results(m);
        }
        if let Some(f) = self.first {
            criteria = criteria.offset(f);
        }
        // first_name, last_name, email_verified need to be handled separately
        // as they're not directly in the criteria builder
        criteria
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user_request_defaults() {
        let json = r#"{"username": "testuser"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "testuser");
        assert!(req.enabled);
        assert!(!req.email_verified);
    }

    #[test]
    fn create_user_request_to_user() {
        let realm_id = Uuid::now_v7();
        let req = CreateUserRequest {
            username: "john".to_string(),
            enabled: true,
            email: Some("john@example.com".to_string()),
            email_verified: true,
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            attributes: HashMap::new(),
            required_actions: vec!["UPDATE_PASSWORD".to_string()],
            credentials: vec![],
        };

        let user = req.into_user(realm_id);
        assert_eq!(user.username, "john");
        assert_eq!(user.realm_id, realm_id);
        assert!(user.enabled);
        assert_eq!(user.email, Some("john@example.com".to_string()));
        assert!(user.email_verified);
        assert!(user.has_required_action("UPDATE_PASSWORD"));
    }

    #[test]
    fn update_user_request_applies() {
        let realm_id = Uuid::now_v7();
        let mut user = User::new(realm_id, "john");

        let update = UpdateUserRequest {
            email: Some("new@example.com".to_string()),
            enabled: Some(false),
            ..Default::default()
        };

        update.apply_to(&mut user);
        assert_eq!(user.email, Some("new@example.com".to_string()));
        assert!(!user.enabled);
    }

    #[test]
    fn user_representation_from_user() {
        let realm_id = Uuid::now_v7();
        let user = User::new(realm_id, "john")
            .with_email("john@example.com")
            .with_first_name("John")
            .with_last_name("Doe");

        let repr = UserRepresentation::from(user);
        assert_eq!(repr.username, "john");
        assert_eq!(repr.email, Some("john@example.com".to_string()));
        assert_eq!(repr.first_name, Some("John".to_string()));
        assert_eq!(repr.last_name, Some("Doe".to_string()));
    }
}
