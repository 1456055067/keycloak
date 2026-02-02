# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure and workspace configuration
- ROADMAP.md with phased migration plan
- CONTRIBUTING.md with development standards and rules
- NIST 800-53 Rev5 control mapping documentation
- Cargo workspace with 16 crates (kc-core, kc-crypto, kc-spi, kc-model, etc.)
- kc-core: Configuration system, error types, and event logging with NIST AU-2/AU-3 compliance
- kc-crypto: CNSA 2.0 compliant cryptographic algorithms (ES384, ES512, PS384, PS512, RS384, RS512)
- kc-crypto: SHA-384 and SHA-512 hashing (SHA-256 forbidden per CNSA 2.0)
- kc-spi: Provider and ProviderFactory traits for extensibility
- kc-spi: SPI Registry for dynamic provider lookup
- kc-spi: KeycloakSession for request-scoped operations
- kc-model: Complete domain models (User, Realm, Client, Group, Role, Credential)
- kc-storage: Storage provider traits (RealmProvider, UserProvider, ClientProvider, RoleProvider, GroupProvider, CredentialProvider)
- kc-storage: Search criteria types for paginated queries
- kc-session: User session and client session management
- kc-session: Session state machine with proper lifecycle
- kc-cache: Cache abstraction traits (CacheProvider, CacheEntry)
- kc-cache-redis: Redis implementation using fred crate
- kc-auth: Authentication flow engine with type-safe state machine
- kc-auth: Built-in authenticators (UsernamePassword, OTP)
- kc-auth: Required actions framework
- kc-storage-sql: Complete PostgreSQL implementation with SQLx
- kc-storage-sql: All six provider implementations (realm, user, client, role, group, credential)
- kc-storage-sql: Connection pool management with configurable limits
- kc-storage-sql: Entity-to-model conversion utilities
- migrations: Initial PostgreSQL schema (20240101000000_initial_schema.sql)
- migrations: 25+ tables including realms, users, clients, roles, groups, credentials, sessions, events
- migrations: Proper foreign key constraints and indexes
- migrations: Automatic updated_at trigger function
- kc-protocol-oidc: OIDC error types following RFC 6749 (OidcError, ErrorResponse)
- kc-protocol-oidc: Common OIDC types (GrantType, ResponseType, ResponseMode, Prompt, etc.)
- kc-protocol-oidc: JWT claim types (AccessTokenClaims, IdTokenClaims, RefreshTokenClaims)
- kc-protocol-oidc: Token Manager for token creation and validation
- kc-protocol-oidc: Request types for all OIDC endpoints (Authorization, Token, Introspection, etc.)
- kc-protocol-oidc: PKCE support with CodeChallengeMethod (S256, plain)
- kc-protocol-oidc: Token exchange support (RFC 8693)
- kc-protocol-oidc: Device authorization flow types (RFC 8628)
- kc-protocol-oidc: OpenID Provider Metadata (ProviderMetadata, ProviderMetadataBuilder)
- kc-protocol-oidc: JSON Web Key Set types (JsonWebKey, JsonWebKeySet, JwksBuilder)
- kc-protocol-oidc: Axum HTTP endpoint handlers module
- kc-protocol-oidc: Discovery endpoint handler (GET /.well-known/openid-configuration)
- kc-protocol-oidc: JWKS endpoint handler (GET /certs)
- kc-protocol-oidc: Token endpoint handler (POST /token) with all grant types
- kc-protocol-oidc: UserInfo endpoint handler (GET/POST /userinfo)
- kc-protocol-oidc: Introspection endpoint handler (POST /token/introspect, RFC 7662)
- kc-protocol-oidc: Revocation endpoint handler (POST /revoke, RFC 7009)
- kc-protocol-oidc: RealmProvider trait for pluggable realm data access
- kc-protocol-oidc: OidcState for shared Axum state management
- kc-protocol-oidc: oidc_router() function for complete OIDC router configuration
- kc-protocol-oidc: Authorization endpoint handler (GET/POST /auth) with code, implicit, hybrid flows
- kc-protocol-oidc: AuthorizationCode and AuthorizationResponse types
- kc-protocol-oidc: PKCE validation (S256 and plain methods)
- kc-protocol-oidc: Response mode handling (query, fragment, form_post)
- kc-protocol-oidc: OidcStorageProvider - storage-backed RealmProvider implementation
- kc-protocol-oidc: ProviderConfig for configuring base URL and token lifespans
- kc-protocol-oidc: Integration with kc-storage for realm and client data access
- kc-protocol-oidc: Protocol Mappers SPI with built-in mappers (UserAttribute, UserProperty, RealmRole, ClientRole, GroupMembership, HardcodedClaim, Audience)
- kc-protocol-oidc: Enhanced authorization endpoint with session, client lookup, and code storage integration
- kc-protocol-oidc: ClientProvider trait for client lookup and redirect URI validation
- kc-protocol-oidc: Cryptographic random code generation (kc-crypto random module)
- kc-protocol-oidc: PKCE enforcement for public clients
- kc-protocol-oidc: Enhanced UserInfo endpoint with UserInfoProvider trait and scope-based claim filtering
- kc-protocol-oidc: Enhanced Introspection endpoint with ClientAuthenticator (RFC 7662)
- kc-protocol-oidc: Enhanced Revocation endpoint with TokenBlocklist trait (RFC 7009)
- kc-crypto: Random number generation module (generate_auth_code, random_bytes, random_alphanumeric, etc.)
- kc-admin-api: Admin REST API crate structure
- kc-admin-api: Error types with HTTP status code mapping (AdminError, ErrorResponse)
- kc-admin-api: DTO types for API requests/responses (CreateRealmRequest, RealmRepresentation, etc.)
- kc-admin-api: State management with storage provider integration (AdminState, UserState, RealmState)
- kc-admin-api: Realm CRUD endpoints (GET/POST /admin/realms, GET/PUT/DELETE /admin/realms/{realm})
- kc-admin-api: User CRUD endpoints (GET/POST /admin/realms/{realm}/users, GET/PUT/DELETE /admin/realms/{realm}/users/{id})
- kc-admin-api: User search with query parameters (search, username, email, enabled, pagination)
- kc-admin-api: Client CRUD endpoints (GET/POST /admin/realms/{realm}/clients, GET/PUT/DELETE /admin/realms/{realm}/clients/{id})
- kc-admin-api: Client secret management (GET/POST /admin/realms/{realm}/clients/{id}/client-secret)
- kc-admin-api: Client search with query parameters (search, clientId, enabled, publicClient, pagination)
- kc-admin-api: Role CRUD endpoints for realm roles (GET/POST /admin/realms/{realm}/roles, GET/PUT/DELETE /admin/realms/{realm}/roles/{role-name})
- kc-admin-api: Composite roles management (GET/POST/DELETE /admin/realms/{realm}/roles/{role-name}/composites)
- kc-admin-api: Client role CRUD endpoints (GET/POST /admin/realms/{realm}/clients/{id}/roles, GET/PUT/DELETE /admin/realms/{realm}/clients/{id}/roles/{role-name})
- kc-admin-api: Role search with query parameters (search, pagination)
- kc-admin-api: admin_router(), admin_client_router(), admin_role_router(), realm_router(), user_router(), client_router(), realm_role_router(), client_role_router() for modular router composition
- kc-admin-api: Group CRUD endpoints (GET/POST /admin/realms/{realm}/groups, GET/PUT/DELETE /admin/realms/{realm}/groups/{id})
- kc-admin-api: Group hierarchy endpoints (GET/POST /admin/realms/{realm}/groups/{id}/children)
- kc-admin-api: Group members endpoint (GET /admin/realms/{realm}/groups/{id}/members)
- kc-admin-api: Group count endpoint (GET /admin/realms/{realm}/groups/count)
- kc-admin-api: Group search with query parameters (search, exact, topLevelOnly, pagination)
- kc-admin-api: admin_group_router(), group_router() for modular group router composition
- kc-admin-api: Authentication/authorization middleware (auth_middleware, AdminAuth extractor)
- kc-admin-api: Permission-based access control (Permission enum, require_permission/require_any_permission)
- kc-admin-api: TokenValidator trait for pluggable token validation
- kc-admin-api: Event logging framework (AdminEventLogger trait, TracingEventLogger, InMemoryEventLogger)
- kc-admin-api: AdminEventBuilder for constructing audit events with admin context
- kc-admin-api: Convenience functions for logging admin operations (log_user_created, log_realm_deleted, etc.)
- kc-admin-api: Import/export module for JSON-based realm configuration
- kc-admin-api: RealmExport, UserExport, ClientExport, RoleExport types for full realm export
- kc-admin-api: ImportOptions, ExportOptions, ImportResult for controlling import/export behavior
- kc-protocol-oidc: apply_userinfo_mappers() and apply_introspection_mappers() registry methods
- kc-core: Additional admin event types (RoleCreated/Updated/Deleted, GroupCreated/Updated/Deleted, etc.)
- kc-crypto: generate_client_secret() for OAuth 2.0 confidential client secrets
- kc-federation: Federation framework for external identity stores
- kc-federation: UserStorageProvider trait for user lookup and management
- kc-federation: CredentialValidator trait for password validation delegation
- kc-federation: FederationMapper trait for attribute mapping between systems
- kc-federation: ImportSynchronization trait for bulk import/sync operations
- kc-federation: FederationConfig with EditMode (ReadOnly, Writable, Unsynced)
- kc-federation: AttributeMapper, GroupMapper, RoleMapper traits
- kc-federation: Built-in mappers (UserAttributeMapper, FullNameMapper)
- kc-federation: SyncResult, SyncError, SyncScheduleConfig for synchronization tracking
- kc-federation-ldap: LDAP user federation provider using ldap3 crate
- kc-federation-ldap: **LDAPS-only enforcement** (no STARTTLS, no plain LDAP for security)
- kc-federation-ldap: LdapStorageProvider implementing UserStorageProvider and CredentialValidator
- kc-federation-ldap: LdapConfig with vendor presets (ActiveDirectory, OpenLDAP, RHDS, Oracle, IBM)
- kc-federation-ldap: LdapConnectionPool for managed connection pooling
- kc-federation-ldap: LdapSearcher for user search operations with proper escaping
- kc-federation-ldap: LdapUserAttributeMapper for mapping LDAP attributes to Keycloak users
- kc-federation-ldap: LdapGroupMapper for extracting group membership from memberOf
- kc-federation-ldap: LdapRoleMapper for role assignments with prefix stripping
- kc-federation-ldap: Password validation via LDAPS bind (credentials never logged)
- kc-federation-ldap: Full and changed synchronization support
- kc-federation-ldap: Active Directory GUID binary format support
- GitHub Actions CI workflow (.github/workflows/ci.yml)
- Pre-commit hooks script (scripts/pre-commit)
- Cargo audit configuration (.cargo/audit.toml)

### Security

- Established security-first development guidelines
- Mandated cargo audit for all commits
- CNSA 2.0 compliance enforced: NO ES256, RS256, PS256, SHA-256, P-256 curves
- Minimum key sizes: RSA 3072-bit, EC P-384
- Ignored RUSTSEC-2023-0071 (rsa crate via unused sqlx-mysql transitive dependency)
- kc-federation-ldap: LDAPS-only enforcement (STARTTLS and plain LDAP rejected at configuration time)
- kc-federation-ldap: LDAP passwords never logged, connections discarded after auth bind

---

## Version History

[Unreleased]: https://github.com/org/keycloak-rs/compare/v0.1.0...HEAD
