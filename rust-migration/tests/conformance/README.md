# OIDC Conformance Testing

This directory contains the OIDC conformance test infrastructure for the Keycloak Rust implementation.

## Overview

The tests validate compliance with:
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)
- [Token Introspection (RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662)
- [Token Revocation (RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)

## Test Profiles

Tests are organized by OIDC certification profile:

| Profile | Description | Test File |
|---------|-------------|-----------|
| Config OP | Discovery endpoint validation | `config_op.rs` |
| Basic OP | Authorization Code flow | `basic_op.rs` |
| Implicit OP | Implicit flow | `implicit_op.rs` |
| Hybrid OP | Hybrid flows | `hybrid_op.rs` |
| Token Endpoint | All grant types | `token_endpoint.rs` |
| UserInfo | UserInfo endpoint | `userinfo.rs` |
| Introspection | Token introspection | `introspection.rs` |
| Revocation | Token revocation | `revocation.rs` |

## Running Unit Tests

The unit tests in this crate can run against a local Keycloak Rust server with a PostgreSQL database.

### Prerequisites

1. PostgreSQL database running:
   ```bash
   docker run -d --name postgres \
     -e POSTGRES_DB=keycloak_test \
     -e POSTGRES_USER=postgres \
     -e POSTGRES_PASSWORD=postgres \
     -p 5432:5432 \
     postgres:16-alpine
   ```

2. Run migrations:
   ```bash
   cd ../.. && sqlx migrate run
   ```

### Running Tests

```bash
# Run all conformance tests
cargo test -p oidc-conformance-tests

# Run specific profile tests
cargo test -p oidc-conformance-tests config_op
cargo test -p oidc-conformance-tests basic_op
cargo test -p oidc-conformance-tests token_endpoint

# Run tests with output
cargo test -p oidc-conformance-tests -- --nocapture
```

Note: Most tests are marked `#[ignore]` because they require a running database with test data. To run them:

```bash
# Run ignored tests
cargo test -p oidc-conformance-tests -- --ignored

# Run all tests including ignored
cargo test -p oidc-conformance-tests -- --include-ignored
```

## Official OIDC Conformance Suite

For official certification, we use the OpenID Foundation's Conformance Test Suite.

### Starting the Suite

```bash
docker-compose up -d
```

This starts:
- PostgreSQL for Keycloak Rust (port 5432)
- MongoDB for the conformance suite (port 27017)
- OIDC Conformance Suite UI (port 9999)

### Accessing the UI

Open http://localhost:9999 in your browser.

### Configuring a Test Plan

1. Start your Keycloak Rust server:
   ```bash
   DATABASE_URL=postgres://keycloak:keycloak@localhost:5432/keycloak \
   cargo run -p kc-server
   ```

2. In the conformance suite UI:
   - Click "Create a new test plan"
   - Select the certification profile (e.g., "OpenID Connect Core: Basic OP")
   - Configure the server details:
     - Discovery URL: `http://host.docker.internal:3000/realms/test/.well-known/openid-configuration`
     - Client ID: `conformance-test-client`
     - Client Secret: `<configured secret>`

3. Run the test plan and review results.

### Test Realm Setup

Before running conformance tests, create a test realm with:

1. A realm named "test"
2. A confidential client "conformance-test-client" with:
   - Valid redirect URIs for the conformance suite
   - All necessary grant types enabled
   - Client secret configured
3. A test user for authentication flows

## CNSA 2.0 Compliance

Our implementation enforces CNSA 2.0 cryptographic requirements:

### Allowed Algorithms
- **Signing**: ES384, ES512, PS384, PS512, RS384, RS512
- **Hashing**: SHA-384, SHA-512

### Forbidden Algorithms
- ES256, RS256, PS256 (P-256 curve, SHA-256)
- HS256, HS384, HS512 (HMAC - symmetric)
- none (unsigned tokens)

The conformance tests validate that:
1. Discovery advertises only CNSA 2.0 compliant algorithms
2. Tokens are signed with compliant algorithms
3. PKCE uses S256 (SHA-256 is allowed for PKCE challenge)

## Test Data Fixtures

The `fixtures/` directory (when created) will contain:
- `test-realm.json` - Realm configuration for import
- `test-clients.json` - Client configurations
- `test-users.json` - Test user accounts

## Troubleshooting

### Database Connection Issues
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check connection
psql postgres://postgres:postgres@localhost:5432/keycloak_test -c "SELECT 1"
```

### Conformance Suite Issues
```bash
# Check logs
docker-compose logs conformance-server

# Restart the suite
docker-compose restart conformance-server
```

### Network Issues with Docker
When running the Keycloak server on the host and conformance suite in Docker,
use `host.docker.internal` to access host services from within containers.

## Continuous Integration

The conformance tests are integrated into CI:

1. **Unit Tests**: Run on every PR (excluding `#[ignore]` tests)
2. **Integration Tests**: Run with testcontainers for database
3. **Conformance Suite**: Run nightly against the official suite

See `.github/workflows/conformance.yml` for CI configuration.
