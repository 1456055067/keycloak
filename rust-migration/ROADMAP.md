# Keycloak Rust Migration Plan

## Executive Summary

A phased migration to rewrite Keycloak (1M+ lines Java) in Rust.

### Key Decisions

- **Team**: 6+ developers (enables aggressive parallelization)
- **Initial Focus**: OIDC-only for v1.0 (SAML added post-launch)
- **Database**: Fresh schema optimized for Rust (no Java compatibility)

### Estimated Timeline: 10-14 months

Accelerated due to larger team, focused scope, and freedom to design optimal schema.

---

## Technology Stack

| Component    | Library                      | Notes                         |
| ------------ | ---------------------------- | ----------------------------- |
| HTTP Server  | Axum                         | Async, tower ecosystem        |
| Database     | SQLx + Diesel                | SQLx primary, Diesel optional |
| Caching      | Redis (fred crate)           | Replace Infinispan            |
| Crypto       | aws-lc-rs                    | FIPS-capable, audited         |
| LDAP         | ldap3                        | Async LDAP client             |
| JWT/OIDC     | jsonwebtoken, openidconnect  | Token handling                |
| Async        | Tokio                        | Industry standard             |

---

## Project Structure

```text
keycloak-rs/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── kc-core/                  # Config, utilities, error types
│   ├── kc-crypto/                # Crypto operations (aws-lc-rs)
│   ├── kc-spi/                   # SPI trait definitions
│   ├── kc-model/                 # Domain models (User, Realm, Client)
│   ├── kc-storage/               # Storage abstraction traits
│   ├── kc-storage-sql/           # SQLx implementation (fresh schema)
│   ├── kc-cache/                 # Cache abstraction
│   ├── kc-cache-redis/           # Redis implementation
│   ├── kc-session/               # Session management
│   ├── kc-auth/                  # Authentication engine
│   ├── kc-protocol-oidc/         # OIDC protocol
│   ├── kc-federation/            # Federation framework
│   ├── kc-federation-ldap/       # LDAP provider
│   ├── kc-admin-api/             # Admin REST API
│   ├── kc-server/                # Main Axum server
│   └── kc-cli/                   # CLI tools
├── migrations/                   # SQLx migrations
└── tests/
    ├── integration/
    └── conformance/              # OIDC conformance tests
```

---

## Phase 1: Core Infrastructure (4-6 weeks) ✅ COMPLETE

**Team allocation**: 2 developers

### Deliverables

- ✅ Configuration system (environment, files, CLI args)
- ✅ Cryptographic layer with aws-lc-rs (RSA, EC, HMAC signing)
- ✅ SPI framework using Rust traits
- ✅ Error handling architecture
- ✅ Logging and telemetry foundation (tracing crate)

### Key Traits to Define

```rust
// SPI pattern
pub trait Provider: Send + Sync + Any {}

pub trait ProviderFactory<P: Provider>: Send + Sync {
    fn id(&self) -> &'static str;
    async fn create(&self, session: &KeycloakSession) -> Result<P, SpiError>;
}

// Crypto
pub trait SignatureProvider: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}
```

### Java Files to Reference

- [ProviderFactory.java](server-spi/src/main/java/org/keycloak/provider/ProviderFactory.java)
- [KeycloakSession.java](server-spi/src/main/java/org/keycloak/models/KeycloakSession.java)
- [crypto/](core/src/main/java/org/keycloak/crypto/)

---

## Phase 2: Storage Layer (6-8 weeks) ✅ COMPLETE

**Team allocation**: 2 developers (parallel with Phase 1 after week 2)

### Deliverables

- ✅ Fresh database schema optimized for Rust
- ✅ Storage abstraction traits (UserProvider, RealmProvider, ClientProvider, RoleProvider, GroupProvider, CredentialProvider)
- ✅ SQLx implementation with compile-time query checking
- ✅ Redis cache layer (kc-cache-redis with fred crate)
- ✅ Database migrations with SQLx (25+ tables)

### Optimized Schema Design

```rust
// Clean Rust-native schema (not JPA-compatible)
#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct Realm {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub config: Json<RealmConfig>,  // JSONB for flexible config
    pub created_at: DateTime<Utc>,
}
```

### Key Advantages of Fresh Schema

- Use Postgres-native types (UUID, JSONB, TIMESTAMPTZ)
- Proper foreign key constraints
- Optimized indexes for common queries
- No legacy JPA naming conventions

### Java Files to Reference (for domain understanding)

- [UserEntity.java](model/jpa/src/main/java/org/keycloak/models/jpa/entities/UserEntity.java)
- [RealmEntity.java](model/jpa/src/main/java/org/keycloak/models/jpa/entities/RealmEntity.java)

---

## Phase 3: Authentication Engine (6-8 weeks) ✅ COMPLETE

**Team allocation**: 2 developers (parallel with Phase 2)

### Deliverables

- ✅ Type-safe authentication flow state machine
- ✅ Authenticator SPI (password, OTP, WebAuthn)
- ✅ Session management (user sessions, client sessions)
- ✅ Credential management (password hashing with Argon2id)
- ✅ Required actions framework

### Type-Safe State Machine

```rust
pub mod states {
    pub struct Initial;
    pub struct InProgress;
    pub struct Challenged;
    pub struct Success;
    pub struct Failure;
}

pub struct FlowContext<S> {
    session: Arc<KeycloakSession>,
    auth_session: AuthenticationSession,
    user: Option<Arc<User>>,
    _state: PhantomData<S>,
}

impl FlowContext<states::InProgress> {
    pub fn challenge(self, response: Response) -> FlowContext<states::Challenged>;
    pub fn success(self) -> FlowContext<states::Success>;
    pub fn failure(self, error: AuthFlowError) -> FlowContext<states::Failure>;
}
```

### Java Files to Reference

- [Authenticator.java](server-spi-private/src/main/java/org/keycloak/authentication/Authenticator.java)
- [AuthenticationFlowContext.java](server-spi-private/src/main/java/org/keycloak/authentication/AuthenticationFlowContext.java)
- [UserSessionModel.java](server-spi/src/main/java/org/keycloak/models/UserSessionModel.java)

---

## Phase 4: OIDC Protocol (8-10 weeks) ✅ COMPLETE

**Team allocation**: 3 developers

### Deliverables

- ✅ Authorization endpoint (code, implicit, hybrid flows)
- ✅ Token endpoint handler (authorization_code, client_credentials, refresh_token, password, device_code, token_exchange)
- ✅ UserInfo endpoint handler (GET/POST)
- ✅ Introspection endpoint handler (RFC 7662)
- ✅ Revocation endpoint handler (RFC 7009)
- ✅ Well-known configuration endpoint (OpenID Provider Metadata)
- ✅ JWKS endpoint (JSON Web Key Set)
- ✅ PKCE support (required for public clients)
- ✅ Token Manager (access, ID, refresh tokens)
- ✅ Discovery module (ProviderMetadata, ProviderMetadataBuilder)
- ✅ JWKS module (JsonWebKey, JsonWebKeySet, JwksBuilder, KeyType, EcCurve)
- ✅ Axum endpoints module with oidc_router() function
- ✅ RealmProvider trait for pluggable realm data access
- ✅ Protocol mappers SPI (built-in mappers, registry, userinfo/introspection mapper methods)

### Axum Router Structure

```rust
pub fn oidc_router() -> Router<AppState> {
    Router::new()
        .route("/realms/:realm/.well-known/openid-configuration", get(well_known))
        .route("/realms/:realm/protocol/openid-connect/certs", get(jwks))
        .route("/realms/:realm/protocol/openid-connect/auth", get(authorize).post(authorize))
        .route("/realms/:realm/protocol/openid-connect/token", post(token))
        .route("/realms/:realm/protocol/openid-connect/userinfo", get(userinfo).post(userinfo))
        .route("/realms/:realm/protocol/openid-connect/token/introspect", post(introspect))
        .route("/realms/:realm/protocol/openid-connect/revoke", post(revoke))
        .route("/realms/:realm/protocol/openid-connect/logout", get(logout).post(logout))
}
```

### Java Files to Reference

- [TokenManager.java](services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java)
- [AuthorizationEndpoint.java](services/src/main/java/org/keycloak/protocol/oidc/endpoints/AuthorizationEndpoint.java)
- [TokenEndpoint.java](services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenEndpoint.java)

### Testing

- OIDC Conformance Test Suite (mandatory before v1.0)
- All grant type flow tests
- Token validation and refresh tests

---

## Phase 5: Admin API (6-8 weeks) ✅ COMPLETE

**Team allocation**: 2 developers (parallel with Phase 4)

### Deliverables

- ✅ Admin API crate structure (error types, DTOs, state management)
- ✅ Realm CRUD endpoints (list, create, get, update, delete)
- ✅ User CRUD endpoints (list/search, create, get, update, delete)
- ✅ Client CRUD endpoints (list/search, create, get, update, delete, client-secret)
- ✅ Role CRUD endpoints (realm roles, client roles, composite roles)
- ✅ Group CRUD endpoints (list/search, create, get, update, delete, children, members)
- ✅ Permission/authorization system (middleware, RBAC, AdminAuth extractor)
- ✅ Event logging (AdminEventLogger trait, TracingEventLogger, NIST AU-2/AU-3 compliance)
- ✅ Import/export (JSON format for realms, users, clients, roles, groups)

### API Endpoints Implemented

```text
GET    /admin/realms              - List all realms
POST   /admin/realms              - Create realm
GET    /admin/realms/{realm}      - Get realm by name
PUT    /admin/realms/{realm}      - Update realm
DELETE /admin/realms/{realm}      - Delete realm

GET    /admin/realms/{realm}/users      - List/search users
POST   /admin/realms/{realm}/users      - Create user
GET    /admin/realms/{realm}/users/{id} - Get user by ID
PUT    /admin/realms/{realm}/users/{id} - Update user
DELETE /admin/realms/{realm}/users/{id} - Delete user

GET    /admin/realms/{realm}/clients                    - List/search clients
POST   /admin/realms/{realm}/clients                    - Create client
GET    /admin/realms/{realm}/clients/{id}               - Get client by ID
PUT    /admin/realms/{realm}/clients/{id}               - Update client
DELETE /admin/realms/{realm}/clients/{id}               - Delete client
GET    /admin/realms/{realm}/clients/{id}/client-secret - Get client secret
POST   /admin/realms/{realm}/clients/{id}/client-secret - Regenerate client secret

GET    /admin/realms/{realm}/roles                           - List realm roles
POST   /admin/realms/{realm}/roles                           - Create realm role
GET    /admin/realms/{realm}/roles/{role-name}               - Get realm role by name
PUT    /admin/realms/{realm}/roles/{role-name}               - Update realm role
DELETE /admin/realms/{realm}/roles/{role-name}               - Delete realm role
GET    /admin/realms/{realm}/roles/{role-name}/composites    - Get composite roles
POST   /admin/realms/{realm}/roles/{role-name}/composites    - Add composite roles
DELETE /admin/realms/{realm}/roles/{role-name}/composites    - Remove composite roles

GET    /admin/realms/{realm}/clients/{id}/roles              - List client roles
POST   /admin/realms/{realm}/clients/{id}/roles              - Create client role
GET    /admin/realms/{realm}/clients/{id}/roles/{role-name}  - Get client role
PUT    /admin/realms/{realm}/clients/{id}/roles/{role-name}  - Update client role
DELETE /admin/realms/{realm}/clients/{id}/roles/{role-name}  - Delete client role

GET    /admin/realms/{realm}/groups                  - List/search groups
POST   /admin/realms/{realm}/groups                  - Create top-level group
GET    /admin/realms/{realm}/groups/count            - Count groups in realm
GET    /admin/realms/{realm}/groups/{id}             - Get group by ID
PUT    /admin/realms/{realm}/groups/{id}             - Update group
DELETE /admin/realms/{realm}/groups/{id}             - Delete group
GET    /admin/realms/{realm}/groups/{id}/children    - Get child groups
POST   /admin/realms/{realm}/groups/{id}/children    - Create child group
GET    /admin/realms/{realm}/groups/{id}/members     - Get group members
```

### Java Files to Reference

- [services/resources/admin/](services/src/main/java/org/keycloak/services/resources/admin/)
- [rest/admin-v2/](rest/admin-v2/)

---

## Phase 6: LDAP Federation (4-6 weeks)

**Team allocation**: 1-2 developers (after Phase 2)

### Deliverables

- Federation framework (UserStorageProvider trait)
- LDAP provider using ldap3 crate
- Attribute mappers
- Group/role sync
- Password authentication delegation

### Implementation

```rust
pub struct LdapStorageProvider {
    config: LdapConfig,
    ldap_store: LdapIdentityStore,
}

impl LdapIdentityStore {
    pub async fn authenticate(&self, dn: &str, password: &str) -> Result<bool, LdapError> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.config.connection_url).await?;
        tokio::spawn(async move { conn.drive().await });

        match ldap.simple_bind(dn, password).await?.success() {
            Ok(_) => Ok(true),
            Err(_) => Ok(false)
        }
    }
}
```

### Java Files to Reference

- [LDAPStorageProvider.java](federation/ldap/src/main/java/org/keycloak/storage/ldap/LDAPStorageProvider.java)

---

## Phase 7: Integration and Polish (4-6 weeks)

**Team allocation**: Full team

### Deliverables

- Login/logout UI (basic Askama templates or SPA)
- Account management UI
- End-to-end testing
- Performance optimization
- Documentation
- Docker/Kubernetes deployment configs

---

## Post-v1.0: SAML Protocol (8-10 weeks)

### Deliverables

- AuthnRequest parsing and validation
- SAML Response/Assertion generation
- XML signature (signing and validation)
- POST and Redirect bindings
- Single Logout (SLO)

### Java Files to Reference

- [SamlProtocol.java](services/src/main/java/org/keycloak/protocol/saml/SamlProtocol.java)
- [saml-core/](saml-core/)

---

## Parallel Execution Timeline

```text
Month:    1    2    3    4    5    6    7    8    9   10   11   12
          |----|----|----|----|----|----|----|----|----|----|----|

Phase 1:  ████████                                    (Core: 2 devs)
Phase 2:    ████████████                              (Storage: 2 devs)
Phase 3:      ████████████                            (Auth: 2 devs)
Phase 4:            ████████████████                  (OIDC: 3 devs)
Phase 5:              ████████████                    (Admin: 2 devs)
Phase 6:                    ████████                  (LDAP: 2 devs)
Phase 7:                          ████████            (Polish: 6 devs)
                                          |
                                        v1.0
```

---

## Team Structure (6+ developers)

| Role              | Count | Phases              |
| ----------------- | ----- | ------------------- |
| Core/Crypto Lead  | 1     | 1, 3                |
| Storage Lead      | 1     | 2, 6                |
| Auth Lead         | 1     | 3, 4                |
| OIDC Lead         | 1     | 4                   |
| API Lead          | 1     | 5                   |
| DevOps/Testing    | 1     | All (CI/CD, infra)  |

---

## Verification Strategy

### Per-Phase Testing

- Unit tests with high coverage (>80%)
- Integration tests with testcontainers (PostgreSQL, Redis, OpenLDAP)
- OIDC Conformance Test Suite (Phase 4)
- API contract tests (Phase 5)

### End-to-End Verification

1. OIDC Conformance certification
2. Load testing (10k concurrent users)
3. Security audit of crypto implementations
4. Penetration testing before v1.0

---

## Risk Mitigation

| Risk                  | Mitigation                                |
| --------------------- | ----------------------------------------- |
| OIDC spec gaps        | Early conformance testing, weekly reviews |
| Crypto bugs           | Use audited aws-lc-rs, security audit     |
| LDAP compatibility    | Test against AD, OpenLDAP, 389DS          |
| Performance issues    | Benchmark early, profile continuously     |
| Scope creep           | Strict v1.0 feature freeze                |

---

## Success Criteria for v1.0

1. Pass OIDC Conformance Test Suite (Basic, Implicit, Hybrid profiles)
2. Support 10,000+ concurrent sessions
3. Sub-100ms token endpoint latency (p99)
4. Memory usage under 256MB idle
5. Admin API supports all CRUD operations
6. LDAP federation works with Active Directory and OpenLDAP
7. Docker and Kubernetes deployment guides complete

---

## Data Migration (for existing Keycloak users)

Since we're using a fresh schema, provide migration tooling:

1. **Export tool**: Read from Java Keycloak's database, export to JSON
2. **Import tool**: Read JSON, populate Rust Keycloak's database
3. **Validation**: Compare entity counts and spot-check data integrity

This allows users to migrate without running both systems simultaneously.
