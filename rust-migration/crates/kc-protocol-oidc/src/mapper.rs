//! Protocol Mapper SPI for customizing token claims.
//!
//! This module provides the Protocol Mapper framework for adding custom claims
//! to OIDC tokens (access tokens, ID tokens, userinfo responses).
//!
//! ## Design
//!
//! The mapper system follows the SPI (Service Provider Interface) pattern:
//! - [`ProtocolMapper`] trait defines the contract for mappers
//! - [`MapperConfig`] provides configuration for each mapper instance
//! - [`ProtocolMapperRegistry`] manages mapper registration and lookup
//! - Built-in mappers provide common functionality (user attributes, roles, etc.)
//!
//! ## Token Types
//!
//! Mappers can target different token types by implementing the corresponding traits:
//! - [`AccessTokenMapper`] - Transforms access tokens
//! - [`IdTokenMapper`] - Transforms ID tokens
//! - [`UserInfoMapper`] - Transforms userinfo responses
//! - [`IntrospectionMapper`] - Transforms introspection responses
//!
//! ## Example
//!
//! ```rust,ignore
//! use kc_protocol_oidc::mapper::{
//!     ProtocolMapper, MapperConfig, MapperContext,
//!     AccessTokenMapper, IdTokenMapper,
//! };
//!
//! struct CustomMapper;
//!
//! impl ProtocolMapper for CustomMapper {
//!     fn id(&self) -> &'static str { "custom-mapper" }
//!     fn display_name(&self) -> &'static str { "Custom Mapper" }
//!     fn category(&self) -> &'static str { "Token mapper" }
//!     fn config_properties(&self) -> Vec<ConfigProperty> { vec![] }
//! }
//!
//! impl AccessTokenMapper for CustomMapper {
//!     fn transform_access_token(
//!         &self,
//!         claims: &mut AccessTokenClaims,
//!         config: &MapperConfig,
//!         context: &MapperContext<'_>,
//!     ) -> Result<(), OidcError> {
//!         claims.additional.insert(
//!             "custom_claim".to_string(),
//!             serde_json::Value::String("custom_value".to_string()),
//!         );
//!         Ok(())
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::claims::{AccessTokenClaims, IdTokenClaims, RealmAccess, ResourceAccess};
use crate::error::OidcResult;

/// Token type that a mapper can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Access token.
    AccessToken,
    /// ID token.
    IdToken,
    /// `UserInfo` response.
    UserInfo,
    /// Token introspection response.
    Introspection,
    /// Lightweight access token (reduced claims for performance).
    LightweightAccessToken,
}

/// Claim value type for JSON serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimValueType {
    /// String value.
    #[default]
    String,
    /// Integer (long) value.
    Long,
    /// Integer value.
    Int,
    /// Boolean value.
    Boolean,
    /// JSON object or array.
    Json,
}

/// Configuration for a protocol mapper instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapperConfig {
    /// Unique identifier for this mapper instance.
    pub id: Uuid,

    /// Mapper name (user-defined).
    pub name: String,

    /// Protocol mapper type ID (e.g., `"oidc-usermodel-attribute-mapper"`).
    pub mapper_type: String,

    /// Protocol (always `"openid-connect"` for OIDC).
    pub protocol: String,

    /// Whether to consent to this mapper.
    #[serde(default)]
    pub consent_required: bool,

    /// Consent text shown to users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_text: Option<String>,

    /// Configuration key-value pairs.
    #[serde(default)]
    pub config: HashMap<String, String>,
}

impl MapperConfig {
    /// Creates a new mapper configuration.
    #[must_use]
    pub fn new(name: impl Into<String>, mapper_type: impl Into<String>) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            mapper_type: mapper_type.into(),
            protocol: "openid-connect".to_string(),
            consent_required: false,
            consent_text: None,
            config: HashMap::new(),
        }
    }

    /// Sets a configuration value.
    #[must_use]
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Gets a configuration value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(String::as_str)
    }

    /// Gets a configuration value as a boolean.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.config.get(key).and_then(|v| v.parse().ok())
    }

    /// Gets a configuration value, returning a default if not present.
    #[must_use]
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.config.get(key).map_or(default, String::as_str)
    }

    /// Checks if the mapper should be included in access tokens.
    #[must_use]
    pub fn include_in_access_token(&self) -> bool {
        self.get_bool("access.token.claim").unwrap_or(true)
    }

    /// Checks if the mapper should be included in ID tokens.
    #[must_use]
    pub fn include_in_id_token(&self) -> bool {
        self.get_bool("id.token.claim").unwrap_or(true)
    }

    /// Checks if the mapper should be included in userinfo responses.
    #[must_use]
    pub fn include_in_userinfo(&self) -> bool {
        self.get_bool("userinfo.token.claim").unwrap_or(true)
    }

    /// Checks if the mapper should be included in introspection responses.
    #[must_use]
    pub fn include_in_introspection(&self) -> bool {
        self.get_bool("introspection.token.claim").unwrap_or(true)
    }

    /// Gets the claim name to use in tokens.
    #[must_use]
    pub fn claim_name(&self) -> Option<&str> {
        self.get("claim.name")
    }

    /// Gets the JSON type for the claim value.
    #[must_use]
    pub fn json_type(&self) -> ClaimValueType {
        self.get("jsonType.label")
            .and_then(|v| match v.to_lowercase().as_str() {
                "string" => Some(ClaimValueType::String),
                "long" => Some(ClaimValueType::Long),
                "int" => Some(ClaimValueType::Int),
                "boolean" => Some(ClaimValueType::Boolean),
                "json" => Some(ClaimValueType::Json),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Checks if the claim is multivalued.
    #[must_use]
    pub fn is_multivalued(&self) -> bool {
        self.get_bool("multivalued").unwrap_or(false)
    }
}

/// Configuration property definition for mapper UIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigProperty {
    /// Property name (config key).
    pub name: String,

    /// Display label.
    pub label: String,

    /// Help text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_text: Option<String>,

    /// Property type.
    pub property_type: ConfigPropertyType,

    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,

    /// Whether the property is required.
    #[serde(default)]
    pub required: bool,

    /// Whether the property is secret (should be masked).
    #[serde(default)]
    pub secret: bool,

    /// Options for select/multiselect types.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub options: Vec<String>,
}

/// Configuration property type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfigPropertyType {
    /// Text input.
    String,
    /// Boolean checkbox.
    Boolean,
    /// Select dropdown.
    List,
    /// Multi-select.
    MultivaluedList,
    /// Script/code editor.
    Script,
    /// Text area.
    Text,
    /// File upload.
    File,
}

impl ConfigProperty {
    /// Creates a new string property.
    #[must_use]
    pub fn string(name: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            help_text: None,
            property_type: ConfigPropertyType::String,
            default_value: None,
            required: false,
            secret: false,
            options: vec![],
        }
    }

    /// Creates a new boolean property.
    #[must_use]
    pub fn boolean(name: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            help_text: None,
            property_type: ConfigPropertyType::Boolean,
            default_value: Some("false".to_string()),
            required: false,
            secret: false,
            options: vec![],
        }
    }

    /// Creates a new list (select) property.
    #[must_use]
    pub fn list(name: impl Into<String>, label: impl Into<String>, options: Vec<String>) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            help_text: None,
            property_type: ConfigPropertyType::List,
            default_value: None,
            required: false,
            secret: false,
            options,
        }
    }

    /// Sets the help text.
    #[must_use]
    pub fn with_help(mut self, help_text: impl Into<String>) -> Self {
        self.help_text = Some(help_text.into());
        self
    }

    /// Sets the default value.
    #[must_use]
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default_value = Some(default.into());
        self
    }

    /// Marks the property as required.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// Context provided to mappers during token transformation.
#[derive(Debug, Clone)]
pub struct MapperContext<'a> {
    /// User information.
    pub user: Option<&'a UserInfo>,

    /// User session information.
    pub session: Option<&'a SessionInfo>,

    /// Client information.
    pub client: Option<&'a ClientInfo>,

    /// Realm name.
    pub realm: &'a str,

    /// Requested scopes.
    pub scopes: &'a [String],
}

impl<'a> MapperContext<'a> {
    /// Creates a new mapper context.
    #[must_use]
    pub const fn new(realm: &'a str, scopes: &'a [String]) -> Self {
        Self {
            user: None,
            session: None,
            client: None,
            realm,
            scopes,
        }
    }

    /// Sets the user information.
    #[must_use]
    pub const fn with_user(mut self, user: &'a UserInfo) -> Self {
        self.user = Some(user);
        self
    }

    /// Sets the session information.
    #[must_use]
    pub const fn with_session(mut self, session: &'a SessionInfo) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the client information.
    #[must_use]
    pub const fn with_client(mut self, client: &'a ClientInfo) -> Self {
        self.client = Some(client);
        self
    }
}

/// User information for mappers.
#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    /// User ID.
    pub id: Uuid,

    /// Username.
    pub username: String,

    /// Email address.
    pub email: Option<String>,

    /// Whether email is verified.
    pub email_verified: bool,

    /// First name.
    pub first_name: Option<String>,

    /// Last name.
    pub last_name: Option<String>,

    /// User attributes.
    pub attributes: HashMap<String, Vec<String>>,

    /// Realm roles assigned to the user.
    pub realm_roles: Vec<String>,

    /// Client roles assigned to the user (`client_id` -> roles).
    pub client_roles: HashMap<String, Vec<String>>,

    /// Groups the user belongs to.
    pub groups: Vec<String>,
}

impl UserInfo {
    /// Gets a single attribute value.
    #[must_use]
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Gets all attribute values.
    #[must_use]
    pub fn get_attributes(&self, name: &str) -> Option<&[String]> {
        self.attributes.get(name).map(Vec::as_slice)
    }

    /// Gets the full name.
    #[must_use]
    pub fn full_name(&self) -> Option<String> {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => None,
        }
    }
}

/// Session information for mappers.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID.
    pub id: String,

    /// Authentication time (Unix timestamp).
    pub auth_time: i64,

    /// Session start time (Unix timestamp).
    pub started: i64,

    /// Authentication methods used.
    pub auth_methods: Vec<String>,

    /// Session notes (key-value pairs).
    pub notes: HashMap<String, String>,
}

/// Client information for mappers.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Client ID.
    pub id: Uuid,

    /// OAuth `client_id`.
    pub client_id: String,

    /// Client name.
    pub name: Option<String>,

    /// Whether the client is public.
    pub public_client: bool,

    /// Client attributes.
    pub attributes: HashMap<String, String>,
}

/// Core trait for protocol mappers.
///
/// Protocol mappers customize the claims included in OIDC tokens.
/// Each mapper has a unique ID, display information, and configuration properties.
pub trait ProtocolMapper: Send + Sync {
    /// Returns the unique identifier for this mapper type.
    ///
    /// This ID is used to reference the mapper in configurations.
    /// Example: `"oidc-usermodel-attribute-mapper"`
    fn id(&self) -> &'static str;

    /// Returns the display name for this mapper.
    ///
    /// Shown in admin UIs. Example: `"User Attribute"`
    fn display_name(&self) -> &'static str;

    /// Returns the category for this mapper.
    ///
    /// Used for grouping in admin UIs. Example: `"Token mapper"`
    fn category(&self) -> &'static str;

    /// Returns the configuration properties for this mapper.
    ///
    /// These define the configuration options available in admin UIs.
    fn config_properties(&self) -> Vec<ConfigProperty>;

    /// Returns the priority for this mapper.
    ///
    /// Lower values execute first. Default is 0.
    /// Role name mappers typically use negative priorities to run before other mappers.
    fn priority(&self) -> i32 {
        0
    }

    /// Validates the mapper configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    fn validate_config(&self, _config: &MapperConfig) -> OidcResult<()> {
        Ok(())
    }
}

/// Trait for mappers that transform access tokens.
pub trait AccessTokenMapper: ProtocolMapper {
    /// Transforms an access token by adding/modifying claims.
    ///
    /// # Errors
    ///
    /// Returns an error if the transformation fails.
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()>;
}

/// Trait for mappers that transform ID tokens.
pub trait IdTokenMapper: ProtocolMapper {
    /// Transforms an ID token by adding/modifying claims.
    ///
    /// # Errors
    ///
    /// Returns an error if the transformation fails.
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()>;
}

/// Trait for mappers that transform userinfo responses.
pub trait UserInfoMapper: ProtocolMapper {
    /// Transforms a userinfo response by adding/modifying claims.
    ///
    /// The userinfo response uses the same structure as access tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the transformation fails.
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()>;
}

/// Trait for mappers that transform introspection responses.
pub trait IntrospectionMapper: ProtocolMapper {
    /// Transforms an introspection response by adding/modifying claims.
    ///
    /// The introspection response uses the same structure as access tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the transformation fails.
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()>;
}

/// Registry for protocol mappers.
///
/// Manages registration and lookup of mapper implementations.
#[derive(Default)]
pub struct ProtocolMapperRegistry {
    /// Registered mappers by ID.
    mappers: HashMap<String, Arc<dyn ProtocolMapper>>,

    /// Access token mappers.
    access_token_mappers: HashMap<String, Arc<dyn AccessTokenMapper>>,

    /// ID token mappers.
    id_token_mappers: HashMap<String, Arc<dyn IdTokenMapper>>,

    /// `UserInfo` mappers.
    userinfo_mappers: HashMap<String, Arc<dyn UserInfoMapper>>,

    /// Introspection mappers.
    introspection_mappers: HashMap<String, Arc<dyn IntrospectionMapper>>,
}

impl ProtocolMapperRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry with built-in mappers registered.
    #[must_use]
    pub fn with_builtin_mappers() -> Self {
        let mut registry = Self::new();

        // Register built-in mappers
        registry.register_mapper(Arc::new(UserAttributeMapper));
        registry.register_mapper(Arc::new(UserPropertyMapper));
        registry.register_mapper(Arc::new(RealmRoleMapper));
        registry.register_mapper(Arc::new(ClientRoleMapper));
        registry.register_mapper(Arc::new(GroupMembershipMapper));
        registry.register_mapper(Arc::new(HardcodedClaimMapper));
        registry.register_mapper(Arc::new(AudienceMapper));

        registry
    }

    /// Registers a mapper that implements all token type traits.
    pub fn register_mapper<M>(&mut self, mapper: Arc<M>)
    where
        M: AccessTokenMapper + IdTokenMapper + UserInfoMapper + IntrospectionMapper + 'static,
    {
        let id = mapper.id().to_string();

        self.mappers.insert(id.clone(), mapper.clone() as Arc<dyn ProtocolMapper>);
        self.access_token_mappers.insert(id.clone(), mapper.clone() as Arc<dyn AccessTokenMapper>);
        self.id_token_mappers.insert(id.clone(), mapper.clone() as Arc<dyn IdTokenMapper>);
        self.userinfo_mappers.insert(id.clone(), mapper.clone() as Arc<dyn UserInfoMapper>);
        self.introspection_mappers.insert(id, mapper as Arc<dyn IntrospectionMapper>);
    }

    /// Registers an access token mapper only.
    pub fn register_access_token_mapper<M>(&mut self, mapper: Arc<M>)
    where
        M: AccessTokenMapper + 'static,
    {
        let id = mapper.id().to_string();
        self.mappers.insert(id.clone(), mapper.clone() as Arc<dyn ProtocolMapper>);
        self.access_token_mappers.insert(id, mapper);
    }

    /// Gets a mapper by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Arc<dyn ProtocolMapper>> {
        self.mappers.get(id)
    }

    /// Gets an access token mapper by ID.
    #[must_use]
    pub fn get_access_token_mapper(&self, id: &str) -> Option<&Arc<dyn AccessTokenMapper>> {
        self.access_token_mappers.get(id)
    }

    /// Gets an ID token mapper by ID.
    #[must_use]
    pub fn get_id_token_mapper(&self, id: &str) -> Option<&Arc<dyn IdTokenMapper>> {
        self.id_token_mappers.get(id)
    }

    /// Gets a userinfo mapper by ID.
    #[must_use]
    pub fn get_userinfo_mapper(&self, id: &str) -> Option<&Arc<dyn UserInfoMapper>> {
        self.userinfo_mappers.get(id)
    }

    /// Gets an introspection mapper by ID.
    #[must_use]
    pub fn get_introspection_mapper(&self, id: &str) -> Option<&Arc<dyn IntrospectionMapper>> {
        self.introspection_mappers.get(id)
    }

    /// Returns all registered mapper IDs.
    #[must_use]
    pub fn mapper_ids(&self) -> Vec<&str> {
        self.mappers.keys().map(String::as_str).collect()
    }

    /// Applies all configured mappers to access token claims.
    ///
    /// # Errors
    ///
    /// Returns an error if any mapper fails.
    pub fn apply_access_token_mappers(
        &self,
        claims: &mut AccessTokenClaims,
        mapper_configs: &[MapperConfig],
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Sort by priority
        let mut configs: Vec<_> = mapper_configs
            .iter()
            .filter(|c| c.include_in_access_token())
            .collect();

        configs.sort_by_key(|c| {
            self.get(&c.mapper_type)
                .map_or(0, |m| m.priority())
        });

        for config in configs {
            if let Some(mapper) = self.access_token_mappers.get(&config.mapper_type) {
                mapper.transform_access_token(claims, config, context)?;
            }
        }

        Ok(())
    }

    /// Applies all configured mappers to ID token claims.
    ///
    /// # Errors
    ///
    /// Returns an error if any mapper fails.
    pub fn apply_id_token_mappers(
        &self,
        claims: &mut IdTokenClaims,
        mapper_configs: &[MapperConfig],
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Sort by priority
        let mut configs: Vec<_> = mapper_configs
            .iter()
            .filter(|c| c.include_in_id_token())
            .collect();

        configs.sort_by_key(|c| {
            self.get(&c.mapper_type)
                .map_or(0, |m| m.priority())
        });

        for config in configs {
            if let Some(mapper) = self.id_token_mappers.get(&config.mapper_type) {
                mapper.transform_id_token(claims, config, context)?;
            }
        }

        Ok(())
    }

    /// Applies all configured mappers to userinfo response.
    ///
    /// # Errors
    ///
    /// Returns an error if any mapper fails.
    pub fn apply_userinfo_mappers(
        &self,
        claims: &mut AccessTokenClaims,
        mapper_configs: &[MapperConfig],
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Sort by priority
        let mut configs: Vec<_> = mapper_configs
            .iter()
            .filter(|c| c.include_in_userinfo())
            .collect();

        configs.sort_by_key(|c| {
            self.get(&c.mapper_type)
                .map_or(0, |m| m.priority())
        });

        for config in configs {
            if let Some(mapper) = self.userinfo_mappers.get(&config.mapper_type) {
                mapper.transform_userinfo(claims, config, context)?;
            }
        }

        Ok(())
    }

    /// Applies all configured mappers to introspection response.
    ///
    /// # Errors
    ///
    /// Returns an error if any mapper fails.
    pub fn apply_introspection_mappers(
        &self,
        claims: &mut AccessTokenClaims,
        mapper_configs: &[MapperConfig],
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Sort by priority
        let mut configs: Vec<_> = mapper_configs
            .iter()
            .filter(|c| c.include_in_introspection())
            .collect();

        configs.sort_by_key(|c| {
            self.get(&c.mapper_type)
                .map_or(0, |m| m.priority())
        });

        for config in configs {
            if let Some(mapper) = self.introspection_mappers.get(&config.mapper_type) {
                mapper.transform_introspection(claims, config, context)?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// Built-in Mappers
// ============================================================================

/// Maps a user attribute to a token claim.
#[derive(Debug, Clone, Copy)]
pub struct UserAttributeMapper;

impl ProtocolMapper for UserAttributeMapper {
    fn id(&self) -> &'static str {
        "oidc-usermodel-attribute-mapper"
    }

    fn display_name(&self) -> &'static str {
        "User Attribute"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("user.attribute", "User Attribute")
                .with_help("Name of the user attribute to map")
                .required(),
            ConfigProperty::string("claim.name", "Token Claim Name")
                .with_help("Name of the claim in the token")
                .required(),
            ConfigProperty::list(
                "jsonType.label",
                "Claim JSON Type",
                vec![
                    "String".to_string(),
                    "long".to_string(),
                    "int".to_string(),
                    "boolean".to_string(),
                    "JSON".to_string(),
                ],
            )
            .with_default("String"),
            ConfigProperty::boolean("multivalued", "Multivalued")
                .with_help("Include all attribute values as an array"),
            ConfigProperty::boolean("aggregate.attrs", "Aggregate attribute values")
                .with_help("Aggregate attribute values from groups"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("true"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl UserAttributeMapper {
    /// Gets the attribute value and maps it to a claim.
    fn map_attribute(
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> Option<serde_json::Value> {
        let user = context.user?;
        let attr_name = config.get("user.attribute")?;

        if config.is_multivalued() {
            let values = user.get_attributes(attr_name)?;
            Some(convert_to_json_value(values, config.json_type()))
        } else {
            let value = user.get_attribute(attr_name)?;
            Some(convert_single_value(value, config.json_type()))
        }
    }
}

impl AccessTokenMapper for UserAttributeMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_attribute(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl IdTokenMapper for UserAttributeMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_attribute(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl UserInfoMapper for UserAttributeMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_attribute(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl IntrospectionMapper for UserAttributeMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_attribute(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

/// Maps a user property (username, email, etc.) to a token claim.
#[derive(Debug, Clone, Copy)]
pub struct UserPropertyMapper;

impl ProtocolMapper for UserPropertyMapper {
    fn id(&self) -> &'static str {
        "oidc-usermodel-property-mapper"
    }

    fn display_name(&self) -> &'static str {
        "User Property"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::list(
                "user.attribute",
                "Property",
                vec![
                    "username".to_string(),
                    "email".to_string(),
                    "firstName".to_string(),
                    "lastName".to_string(),
                    "id".to_string(),
                ],
            )
            .required(),
            ConfigProperty::string("claim.name", "Token Claim Name").required(),
            ConfigProperty::list(
                "jsonType.label",
                "Claim JSON Type",
                vec!["String".to_string()],
            )
            .with_default("String"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("true"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl UserPropertyMapper {
    /// Gets the property value.
    fn get_property_value(context: &MapperContext<'_>, property: &str) -> Option<String> {
        let user = context.user?;
        match property {
            "username" => Some(user.username.clone()),
            "email" => user.email.clone(),
            "firstName" => user.first_name.clone(),
            "lastName" => user.last_name.clone(),
            "id" => Some(user.id.to_string()),
            _ => None,
        }
    }

    fn map_property(
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> Option<serde_json::Value> {
        let property = config.get("user.attribute")?;
        let value = Self::get_property_value(context, property)?;
        Some(serde_json::Value::String(value))
    }
}

impl AccessTokenMapper for UserPropertyMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_property(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl IdTokenMapper for UserPropertyMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_property(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl UserInfoMapper for UserPropertyMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_property(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl IntrospectionMapper for UserPropertyMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::map_property(config, context)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

/// Maps realm roles to a token claim.
#[derive(Debug, Clone, Copy)]
pub struct RealmRoleMapper;

impl ProtocolMapper for RealmRoleMapper {
    fn id(&self) -> &'static str {
        "oidc-usermodel-realm-role-mapper"
    }

    fn display_name(&self) -> &'static str {
        "User Realm Role"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn priority(&self) -> i32 {
        10 // Run after role name mappers
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("claim.name", "Token Claim Name")
                .with_default("realm_access.roles"),
            ConfigProperty::string("user.model.realmRoleMapping.rolePrefix", "Role Prefix")
                .with_help("Prefix to add to role names"),
            ConfigProperty::boolean("multivalued", "Multivalued")
                .with_default("true"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("false"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl RealmRoleMapper {
    /// Gets realm roles with optional prefix.
    fn get_roles(
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> Option<Vec<String>> {
        let user = context.user?;
        let prefix = config.get("user.model.realmRoleMapping.rolePrefix").unwrap_or("");

        let roles: Vec<String> = user
            .realm_roles
            .iter()
            .map(|r| {
                if prefix.is_empty() {
                    r.clone()
                } else {
                    format!("{prefix}{r}")
                }
            })
            .collect();

        if roles.is_empty() {
            None
        } else {
            Some(roles)
        }
    }
}

impl AccessTokenMapper for RealmRoleMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(roles) = Self::get_roles(config, context) {
            let claim_name = config.claim_name().unwrap_or("realm_access.roles");

            // Special handling for standard `realm_access.roles` claim
            if claim_name == "realm_access.roles" {
                let access = claims.realm_access.get_or_insert(RealmAccess { roles: vec![] });
                access.roles.extend(roles);
            } else {
                let value = serde_json::Value::Array(
                    roles.into_iter().map(serde_json::Value::String).collect(),
                );
                set_claim_nested(&mut claims.additional, claim_name, value);
            }
        }
        Ok(())
    }
}

impl IdTokenMapper for RealmRoleMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(roles) = Self::get_roles(config, context)
            && let Some(claim_name) = config.claim_name()
        {
            let value = serde_json::Value::Array(
                roles.into_iter().map(serde_json::Value::String).collect(),
            );
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl UserInfoMapper for RealmRoleMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

impl IntrospectionMapper for RealmRoleMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

/// Maps client roles to a token claim.
#[derive(Debug, Clone, Copy)]
pub struct ClientRoleMapper;

impl ProtocolMapper for ClientRoleMapper {
    fn id(&self) -> &'static str {
        "oidc-usermodel-client-role-mapper"
    }

    fn display_name(&self) -> &'static str {
        "User Client Role"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn priority(&self) -> i32 {
        10 // Run after role name mappers
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("usermodel.clientRoleMapping.clientId", "Client ID")
                .with_help("Client to map roles from (empty = current client)")
                .required(),
            ConfigProperty::string("claim.name", "Token Claim Name")
                .with_help("Use 'resource_access.${client_id}.roles' for standard format"),
            ConfigProperty::string("usermodel.clientRoleMapping.rolePrefix", "Role Prefix")
                .with_help("Prefix to add to role names"),
            ConfigProperty::boolean("multivalued", "Multivalued")
                .with_default("true"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("false"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl ClientRoleMapper {
    /// Gets client roles with optional prefix.
    fn get_roles(
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> Option<(String, Vec<String>)> {
        let user = context.user?;
        let client_id = config
            .get("usermodel.clientRoleMapping.clientId")
            .or_else(|| context.client.map(|c| c.client_id.as_str()))?;

        let roles = user.client_roles.get(client_id)?;
        if roles.is_empty() {
            return None;
        }

        let prefix = config.get("usermodel.clientRoleMapping.rolePrefix").unwrap_or("");
        let prefixed_roles: Vec<String> = roles
            .iter()
            .map(|r| {
                if prefix.is_empty() {
                    r.clone()
                } else {
                    format!("{prefix}{r}")
                }
            })
            .collect();

        Some((client_id.to_string(), prefixed_roles))
    }
}

impl AccessTokenMapper for ClientRoleMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some((client_id, roles)) = Self::get_roles(config, context) {
            let claim_name = config.claim_name();

            // Check for standard `resource_access.{client}.roles` format
            let is_standard = claim_name.is_none()
                || claim_name == Some(&format!("resource_access.{client_id}.roles"));

            if is_standard {
                let resource_access = claims
                    .resource_access
                    .get_or_insert_with(HashMap::new);
                let access = resource_access
                    .entry(client_id)
                    .or_insert(ResourceAccess { roles: vec![] });
                access.roles.extend(roles);
            } else if let Some(name) = claim_name {
                let value = serde_json::Value::Array(
                    roles.into_iter().map(serde_json::Value::String).collect(),
                );
                set_claim_nested(&mut claims.additional, name, value);
            }
        }
        Ok(())
    }
}

impl IdTokenMapper for ClientRoleMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some((_, roles)) = Self::get_roles(config, context)
            && let Some(claim_name) = config.claim_name()
        {
            let value = serde_json::Value::Array(
                roles.into_iter().map(serde_json::Value::String).collect(),
            );
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl UserInfoMapper for ClientRoleMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

impl IntrospectionMapper for ClientRoleMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

/// Maps group membership to a token claim.
#[derive(Debug, Clone, Copy)]
pub struct GroupMembershipMapper;

impl ProtocolMapper for GroupMembershipMapper {
    fn id(&self) -> &'static str {
        "oidc-group-membership-mapper"
    }

    fn display_name(&self) -> &'static str {
        "Group Membership"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("claim.name", "Token Claim Name")
                .with_default("groups")
                .required(),
            ConfigProperty::boolean("full.path", "Full group path")
                .with_help("Include full path (e.g., /parent/child) or just name")
                .with_default("true"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("true"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl GroupMembershipMapper {
    /// Gets group membership as a JSON array.
    fn get_groups(
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> Option<serde_json::Value> {
        let user = context.user?;
        if user.groups.is_empty() {
            return None;
        }

        let full_path = config.get_bool("full.path").unwrap_or(true);
        let groups: Vec<serde_json::Value> = user
            .groups
            .iter()
            .map(|g| {
                if full_path {
                    serde_json::Value::String(g.clone())
                } else {
                    // Extract just the group name from the path
                    let name = g.rsplit('/').next().unwrap_or(g);
                    serde_json::Value::String(name.to_string())
                }
            })
            .collect();

        Some(serde_json::Value::Array(groups))
    }
}

impl AccessTokenMapper for GroupMembershipMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(groups) = Self::get_groups(config, context) {
            let claim_name = config.claim_name().unwrap_or("groups");
            set_claim_nested(&mut claims.additional, claim_name, groups);
        }
        Ok(())
    }
}

impl IdTokenMapper for GroupMembershipMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(groups) = Self::get_groups(config, context) {
            let claim_name = config.claim_name().unwrap_or("groups");
            set_claim_nested(&mut claims.additional, claim_name, groups);
        }
        Ok(())
    }
}

impl UserInfoMapper for GroupMembershipMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

impl IntrospectionMapper for GroupMembershipMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

/// Adds a hardcoded claim to tokens.
#[derive(Debug, Clone, Copy)]
pub struct HardcodedClaimMapper;

impl ProtocolMapper for HardcodedClaimMapper {
    fn id(&self) -> &'static str {
        "oidc-hardcoded-claim-mapper"
    }

    fn display_name(&self) -> &'static str {
        "Hardcoded claim"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("claim.name", "Token Claim Name").required(),
            ConfigProperty::string("claim.value", "Claim value").required(),
            ConfigProperty::list(
                "jsonType.label",
                "Claim JSON Type",
                vec![
                    "String".to_string(),
                    "long".to_string(),
                    "int".to_string(),
                    "boolean".to_string(),
                    "JSON".to_string(),
                ],
            )
            .with_default("String"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("true"),
            ConfigProperty::boolean("userinfo.token.claim", "Add to userinfo")
                .with_default("true"),
            ConfigProperty::boolean("introspection.token.claim", "Add to introspection")
                .with_default("true"),
        ]
    }
}

impl HardcodedClaimMapper {
    /// Gets the hardcoded value.
    fn get_value(config: &MapperConfig) -> Option<serde_json::Value> {
        let value = config.get("claim.value")?;
        Some(convert_single_value(value, config.json_type()))
    }
}

impl AccessTokenMapper for HardcodedClaimMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::get_value(config)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl IdTokenMapper for HardcodedClaimMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        if let Some(claim_name) = config.claim_name()
            && let Some(value) = Self::get_value(config)
        {
            set_claim_nested(&mut claims.additional, claim_name, value);
        }
        Ok(())
    }
}

impl UserInfoMapper for HardcodedClaimMapper {
    fn transform_userinfo(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

impl IntrospectionMapper for HardcodedClaimMapper {
    fn transform_introspection(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        self.transform_access_token(claims, config, context)
    }
}

/// Adds an audience to tokens.
#[derive(Debug, Clone, Copy)]
pub struct AudienceMapper;

impl ProtocolMapper for AudienceMapper {
    fn id(&self) -> &'static str {
        "oidc-audience-mapper"
    }

    fn display_name(&self) -> &'static str {
        "Audience"
    }

    fn category(&self) -> &'static str {
        "Token mapper"
    }

    fn config_properties(&self) -> Vec<ConfigProperty> {
        vec![
            ConfigProperty::string("included.client.audience", "Included Client Audience")
                .with_help("Client ID to add to audience"),
            ConfigProperty::string("included.custom.audience", "Included Custom Audience")
                .with_help("Custom audience value to add"),
            ConfigProperty::boolean("access.token.claim", "Add to access token")
                .with_default("true"),
            ConfigProperty::boolean("id.token.claim", "Add to ID token")
                .with_default("false"),
        ]
    }
}

impl AudienceMapper {
    /// Gets the audience values to add.
    fn get_audiences(config: &MapperConfig) -> Vec<String> {
        let mut audiences = Vec::new();

        if let Some(client) = config.get("included.client.audience")
            && !client.is_empty()
        {
            audiences.push(client.to_string());
        }

        if let Some(custom) = config.get("included.custom.audience")
            && !custom.is_empty()
        {
            audiences.push(custom.to_string());
        }

        audiences
    }
}

impl AccessTokenMapper for AudienceMapper {
    fn transform_access_token(
        &self,
        claims: &mut AccessTokenClaims,
        config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        let new_audiences = Self::get_audiences(config);
        if new_audiences.is_empty() {
            return Ok(());
        }

        // Merge with existing audience
        let mut audiences: Vec<String> = claims
            .aud
            .as_ref()
            .map_or_else(Vec::new, |a| a.as_vec().iter().map(|s| (*s).to_string()).collect());

        for aud in new_audiences {
            if !audiences.contains(&aud) {
                audiences.push(aud);
            }
        }

        claims.aud = Some(crate::claims::Audience::from(audiences));
        Ok(())
    }
}

impl IdTokenMapper for AudienceMapper {
    fn transform_id_token(
        &self,
        claims: &mut IdTokenClaims,
        config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        let new_audiences = Self::get_audiences(config);
        if new_audiences.is_empty() {
            return Ok(());
        }

        // Merge with existing audience
        let mut audiences: Vec<String> = claims.aud.as_vec().iter().map(|s| (*s).to_string()).collect();

        for aud in new_audiences {
            if !audiences.contains(&aud) {
                audiences.push(aud);
            }
        }

        claims.aud = crate::claims::Audience::from(audiences);
        Ok(())
    }
}

impl UserInfoMapper for AudienceMapper {
    fn transform_userinfo(
        &self,
        _claims: &mut AccessTokenClaims,
        _config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Audience mapper doesn't apply to userinfo
        Ok(())
    }
}

impl IntrospectionMapper for AudienceMapper {
    fn transform_introspection(
        &self,
        _claims: &mut AccessTokenClaims,
        _config: &MapperConfig,
        _context: &MapperContext<'_>,
    ) -> OidcResult<()> {
        // Audience mapper doesn't apply to introspection
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a slice of strings to a JSON value based on the claim type.
fn convert_to_json_value(values: &[String], claim_type: ClaimValueType) -> serde_json::Value {
    let json_values: Vec<serde_json::Value> = values
        .iter()
        .map(|v| convert_single_value(v, claim_type))
        .collect();
    serde_json::Value::Array(json_values)
}

/// Converts a single string value to a JSON value based on the claim type.
fn convert_single_value(value: &str, claim_type: ClaimValueType) -> serde_json::Value {
    match claim_type {
        ClaimValueType::String => serde_json::Value::String(value.to_string()),
        ClaimValueType::Long | ClaimValueType::Int => value
            .parse::<i64>()
            .map_or_else(
                |_| serde_json::Value::String(value.to_string()),
                |n| serde_json::Value::Number(n.into()),
            ),
        ClaimValueType::Boolean => value
            .parse::<bool>()
            .map_or_else(
                |_| serde_json::Value::String(value.to_string()),
                serde_json::Value::Bool,
            ),
        ClaimValueType::Json => serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_string())),
    }
}

/// Sets a claim value, supporting nested paths (e.g., `"address.country"`).
fn set_claim_nested(
    claims: &mut HashMap<String, serde_json::Value>,
    path: &str,
    value: serde_json::Value,
) {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() == 1 {
        // Simple case: no nesting
        claims.insert(path.to_string(), value);
    } else {
        // Nested case: create intermediate objects
        // Get or create the first-level object
        let first_part = parts[0];
        let entry = claims
            .entry(first_part.to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        if let serde_json::Value::Object(obj) = entry {
            // Build the remaining path
            let remaining_path = parts[1..].join(".");
            let mut nested_claims: HashMap<String, serde_json::Value> =
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

            set_claim_nested(&mut nested_claims, &remaining_path, value);

            // Convert back
            *obj = nested_claims
                .into_iter()
                .collect::<serde_json::Map<String, serde_json::Value>>();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_config_creation() {
        let config = MapperConfig::new("email-mapper", "oidc-usermodel-attribute-mapper")
            .with_config("user.attribute", "email")
            .with_config("claim.name", "email")
            .with_config("access.token.claim", "true");

        assert_eq!(config.mapper_type, "oidc-usermodel-attribute-mapper");
        assert_eq!(config.get("user.attribute"), Some("email"));
        assert!(config.include_in_access_token());
    }

    #[test]
    fn mapper_config_booleans() {
        let config = MapperConfig::new("test", "test-mapper")
            .with_config("access.token.claim", "false")
            .with_config("multivalued", "true");

        assert!(!config.include_in_access_token());
        assert!(config.is_multivalued());
    }

    #[test]
    fn user_attribute_mapper_properties() {
        let mapper = UserAttributeMapper;
        assert_eq!(mapper.id(), "oidc-usermodel-attribute-mapper");
        assert_eq!(mapper.display_name(), "User Attribute");

        let props = mapper.config_properties();
        assert!(!props.is_empty());

        let user_attr_prop = props.iter().find(|p| p.name == "user.attribute");
        assert!(user_attr_prop.is_some());
        assert!(user_attr_prop.unwrap().required);
    }

    #[test]
    fn realm_role_mapper_priority() {
        let mapper = RealmRoleMapper;
        assert_eq!(mapper.priority(), 10);
    }

    #[test]
    fn registry_with_builtin_mappers() {
        let registry = ProtocolMapperRegistry::with_builtin_mappers();

        assert!(registry.get("oidc-usermodel-attribute-mapper").is_some());
        assert!(registry.get("oidc-usermodel-realm-role-mapper").is_some());
        assert!(registry.get("oidc-group-membership-mapper").is_some());
        assert!(registry.get("oidc-hardcoded-claim-mapper").is_some());
    }

    #[test]
    fn set_claim_nested_simple() {
        let mut claims = HashMap::new();
        set_claim_nested(&mut claims, "email", serde_json::Value::String("test@example.com".to_string()));

        assert_eq!(claims.get("email"), Some(&serde_json::Value::String("test@example.com".to_string())));
    }

    #[test]
    fn set_claim_nested_deep() {
        let mut claims = HashMap::new();
        set_claim_nested(&mut claims, "address.country", serde_json::Value::String("US".to_string()));

        let address = claims.get("address").unwrap();
        if let serde_json::Value::Object(obj) = address {
            assert_eq!(obj.get("country"), Some(&serde_json::Value::String("US".to_string())));
        } else {
            panic!("Expected object");
        }
    }

    #[test]
    fn convert_values() {
        assert_eq!(
            convert_single_value("test", ClaimValueType::String),
            serde_json::Value::String("test".to_string())
        );

        assert_eq!(
            convert_single_value("123", ClaimValueType::Long),
            serde_json::Value::Number(123.into())
        );

        assert_eq!(
            convert_single_value("true", ClaimValueType::Boolean),
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn user_info_full_name() {
        let mut user = UserInfo::default();
        user.first_name = Some("John".to_string());
        user.last_name = Some("Doe".to_string());

        assert_eq!(user.full_name(), Some("John Doe".to_string()));

        user.last_name = None;
        assert_eq!(user.full_name(), Some("John".to_string()));
    }

    #[test]
    fn user_attribute_mapper_transform() {
        let mapper = UserAttributeMapper;
        let config = MapperConfig::new("test", "oidc-usermodel-attribute-mapper")
            .with_config("user.attribute", "department")
            .with_config("claim.name", "dept")
            .with_config("access.token.claim", "true");

        let mut user = UserInfo::default();
        user.attributes.insert(
            "department".to_string(),
            vec!["Engineering".to_string()],
        );

        let scopes = vec!["openid".to_string()];
        let context = MapperContext::new("master", &scopes).with_user(&user);

        let mut claims = AccessTokenClaims::new(
            "https://auth.example.com".to_string(),
            "user123".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );

        mapper.transform_access_token(&mut claims, &config, &context).unwrap();

        assert_eq!(
            claims.additional.get("dept"),
            Some(&serde_json::Value::String("Engineering".to_string()))
        );
    }
}
