//! User storage provider traits.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - IA-2: Identification and Authentication (Organizational Users)
//! - IA-5: Authenticator Management
//!
//! These traits enable integration with external identity stores while
//! maintaining security requirements for authentication.

use kc_model::User;
use uuid::Uuid;

use crate::config::FederationConfig;
use crate::error::FederationResult;

// ============================================================================
// User Storage Provider
// ============================================================================

/// Trait for user storage federation providers.
///
/// This is the main trait that federation providers must implement.
/// It handles user lookup and management from external identity stores.
///
/// ## Implementation Notes
///
/// - Providers should be thread-safe (Send + Sync)
/// - All operations are async to support network I/O
/// - Providers may cache results according to their cache policy
#[allow(async_fn_in_trait)]
pub trait UserStorageProvider: Send + Sync {
    /// Returns the provider configuration.
    fn config(&self) -> &FederationConfig;

    /// Returns the provider type identifier.
    fn provider_type(&self) -> &'static str;

    /// Validates the provider configuration.
    ///
    /// Called when the provider is configured to ensure settings are valid.
    async fn validate_config(&self) -> FederationResult<()>;

    /// Tests the connection to the external store.
    ///
    /// Returns Ok(()) if the connection is successful.
    async fn test_connection(&self) -> FederationResult<()>;

    // === User Lookup ===

    /// Gets a user by their external ID.
    ///
    /// The external ID is the identifier used in the external store.
    async fn get_user_by_external_id(
        &self,
        realm_id: Uuid,
        external_id: &str,
    ) -> FederationResult<Option<User>>;

    /// Gets a user by username.
    async fn get_user_by_username(
        &self,
        realm_id: Uuid,
        username: &str,
    ) -> FederationResult<Option<User>>;

    /// Gets a user by email.
    async fn get_user_by_email(
        &self,
        realm_id: Uuid,
        email: &str,
    ) -> FederationResult<Option<User>>;

    /// Searches for users matching the given query.
    ///
    /// The query string matches against username, email, first name, and last name.
    async fn search_users(
        &self,
        realm_id: Uuid,
        query: &str,
        first: usize,
        max: usize,
    ) -> FederationResult<Vec<User>>;

    /// Counts users matching the given query.
    async fn count_users(&self, realm_id: Uuid, query: Option<&str>) -> FederationResult<usize>;

    // === User Management (if supported) ===

    /// Creates a user in the external store.
    ///
    /// Returns `FederationError::ReadOnly` if the provider is read-only.
    async fn create_user(&self, realm_id: Uuid, user: &User) -> FederationResult<()> {
        if self.config().edit_mode.is_read_only() {
            return Err(crate::error::FederationError::read_only("create user"));
        }
        self.do_create_user(realm_id, user).await
    }

    /// Internal method to create a user. Override this in implementations.
    async fn do_create_user(&self, _realm_id: Uuid, _user: &User) -> FederationResult<()> {
        Err(crate::error::FederationError::not_supported("create user"))
    }

    /// Updates a user in the external store.
    ///
    /// Returns `FederationError::ReadOnly` if the provider is read-only.
    async fn update_user(&self, realm_id: Uuid, user: &User) -> FederationResult<()> {
        if self.config().edit_mode.is_read_only() {
            return Err(crate::error::FederationError::read_only("update user"));
        }
        self.do_update_user(realm_id, user).await
    }

    /// Internal method to update a user. Override this in implementations.
    async fn do_update_user(&self, _realm_id: Uuid, _user: &User) -> FederationResult<()> {
        Err(crate::error::FederationError::not_supported("update user"))
    }

    /// Deletes a user from the external store.
    ///
    /// Returns `FederationError::ReadOnly` if the provider is read-only.
    async fn delete_user(&self, realm_id: Uuid, external_id: &str) -> FederationResult<()> {
        if self.config().edit_mode.is_read_only() {
            return Err(crate::error::FederationError::read_only("delete user"));
        }
        self.do_delete_user(realm_id, external_id).await
    }

    /// Internal method to delete a user. Override this in implementations.
    async fn do_delete_user(&self, _realm_id: Uuid, _external_id: &str) -> FederationResult<()> {
        Err(crate::error::FederationError::not_supported("delete user"))
    }

    /// Checks if the provider supports user creation.
    fn supports_user_creation(&self) -> bool {
        self.config().edit_mode.is_writable()
    }

    /// Checks if the provider supports user updates.
    fn supports_user_update(&self) -> bool {
        !self.config().edit_mode.is_read_only()
    }

    /// Closes the provider, releasing any resources.
    async fn close(&self) -> FederationResult<()> {
        Ok(())
    }
}

// ============================================================================
// Credential Validator
// ============================================================================

/// Trait for validating credentials against external systems.
///
/// This trait is used to delegate password validation to external stores
/// like LDAP (via LDAP bind) or Kerberos.
///
/// ## NIST 800-53 Rev5: IA-5
///
/// Credential validators must:
/// - Not log or store plaintext passwords
/// - Use secure connections (TLS required)
/// - Support proper error handling for audit trails
#[allow(async_fn_in_trait)]
pub trait CredentialValidator: Send + Sync {
    /// Validates a password credential.
    ///
    /// Returns true if the password is valid for the given user.
    ///
    /// ## Parameters
    ///
    /// - `realm_id`: The realm containing the user
    /// - `username`: The username to validate
    /// - `password`: The plaintext password (not logged or stored)
    ///
    /// ## Security
    ///
    /// The password parameter must never be logged. Implementations
    /// should use secure connections (LDAPS, not STARTTLS or plain LDAP).
    async fn validate_password(
        &self,
        realm_id: Uuid,
        username: &str,
        password: &str,
    ) -> FederationResult<bool>;

    /// Checks if the provider supports password validation.
    fn supports_password_validation(&self) -> bool {
        true
    }

    /// Updates a user's password in the external store.
    ///
    /// Returns `FederationError::NotSupported` if password updates are not supported.
    async fn update_password(
        &self,
        _realm_id: Uuid,
        _username: &str,
        _new_password: &str,
    ) -> FederationResult<()> {
        Err(crate::error::FederationError::not_supported(
            "password update",
        ))
    }

    /// Checks if the provider supports password updates.
    fn supports_password_update(&self) -> bool {
        false
    }
}

// ============================================================================
// Imported User Validation
// ============================================================================

/// Validates users imported from external stores.
///
/// This trait is called when a user is imported to ensure they meet
/// Keycloak's requirements and to apply any necessary transformations.
pub trait ImportedUserValidation: Send + Sync {
    /// Validates an imported user.
    ///
    /// Returns an error if the user cannot be imported.
    fn validate(&self, user: &User) -> FederationResult<()>;

    /// Transforms a user after import.
    ///
    /// This can be used to set default values, normalize data, etc.
    fn transform(&self, user: &mut User);
}

/// Default user validation that accepts all users.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultUserValidation;

impl ImportedUserValidation for DefaultUserValidation {
    fn validate(&self, user: &User) -> FederationResult<()> {
        // Ensure username is not empty
        if user.username.is_empty() {
            return Err(crate::error::FederationError::AttributeMapping(
                "username cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn transform(&self, _user: &mut User) {
        // No transformation by default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EditMode;

    // Mock provider for testing
    struct MockProvider {
        config: FederationConfig,
    }

    impl MockProvider {
        fn new(edit_mode: EditMode) -> Self {
            let config = FederationConfig::builder()
                .realm_id(Uuid::now_v7())
                .provider_type("mock")
                .name("Mock Provider")
                .edit_mode(edit_mode)
                .build();
            Self { config }
        }
    }

    impl UserStorageProvider for MockProvider {
        fn config(&self) -> &FederationConfig {
            &self.config
        }

        fn provider_type(&self) -> &'static str {
            "mock"
        }

        async fn validate_config(&self) -> FederationResult<()> {
            Ok(())
        }

        async fn test_connection(&self) -> FederationResult<()> {
            Ok(())
        }

        async fn get_user_by_external_id(
            &self,
            _realm_id: Uuid,
            _external_id: &str,
        ) -> FederationResult<Option<User>> {
            Ok(None)
        }

        async fn get_user_by_username(
            &self,
            _realm_id: Uuid,
            _username: &str,
        ) -> FederationResult<Option<User>> {
            Ok(None)
        }

        async fn get_user_by_email(
            &self,
            _realm_id: Uuid,
            _email: &str,
        ) -> FederationResult<Option<User>> {
            Ok(None)
        }

        async fn search_users(
            &self,
            _realm_id: Uuid,
            _query: &str,
            _first: usize,
            _max: usize,
        ) -> FederationResult<Vec<User>> {
            Ok(vec![])
        }

        async fn count_users(
            &self,
            _realm_id: Uuid,
            _query: Option<&str>,
        ) -> FederationResult<usize> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn read_only_provider_rejects_writes() {
        let provider = MockProvider::new(EditMode::ReadOnly);
        let realm_id = Uuid::now_v7();
        let user = User::new(realm_id, "test");

        let result = provider.create_user(realm_id, &user).await;
        assert!(result.is_err());

        if let Err(crate::error::FederationError::ReadOnly(op)) = result {
            assert_eq!(op, "create user");
        } else {
            panic!("Expected ReadOnly error");
        }
    }

    #[test]
    fn default_validation_rejects_empty_username() {
        let validation = DefaultUserValidation;
        let realm_id = Uuid::now_v7();

        let mut user = User::new(realm_id, "");
        let result = validation.validate(&user);
        assert!(result.is_err());

        user.username = "valid".to_string();
        let result = validation.validate(&user);
        assert!(result.is_ok());
    }
}
