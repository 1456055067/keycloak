# Quick Start Guide

This guide will help you get Keycloak Rust running in just a few minutes.

## Prerequisites

- Docker and Docker Compose (for containerized deployment)
- OR Rust 1.92+ and PostgreSQL 14+ (for local development)

## Option 1: Docker Compose (Recommended)

The fastest way to get started:

```bash
cd deploy/docker

# Start PostgreSQL and Keycloak
docker-compose up -d

# Check logs
docker-compose logs -f keycloak

# Stop everything
docker-compose down
```

Access Keycloak at http://localhost:8080

### Default Test Data

The Docker setup includes:
- **Realm**: `test`
- **Client**: `test-client` (confidential, secret: `test-secret`)
- **Client**: `test-public-client` (public)
- **User**: `testuser` / `testpassword`

## Option 2: Local Development

### 1. Start PostgreSQL

```bash
docker run -d --name postgres \
  -e POSTGRES_DB=keycloak \
  -e POSTGRES_USER=keycloak \
  -e POSTGRES_PASSWORD=keycloak \
  -p 5432:5432 \
  postgres:16-alpine
```

### 2. Run Migrations

```bash
# Install sqlx-cli if needed
cargo install sqlx-cli --no-default-features --features postgres

# Run migrations
DATABASE_URL=postgres://keycloak:keycloak@localhost:5432/keycloak sqlx migrate run
```

### 3. Start the Server

```bash
DATABASE_URL=postgres://keycloak:keycloak@localhost:5432/keycloak cargo run -p kc-server
```

## Verify Installation

### Health Check

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"healthy","version":"0.1.0"}
```

### Discovery Endpoint

```bash
curl http://localhost:8080/realms/test/.well-known/openid-configuration
```

## Your First Token

### 1. Client Credentials Flow

For service-to-service authentication:

```bash
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret"
```

### 2. Password Flow

For user authentication:

```bash
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret" \
  -d "username=testuser" \
  -d "password=testpassword" \
  -d "scope=openid profile email"
```

### 3. Authorization Code Flow with PKCE

For browser-based applications:

1. Generate PKCE codes:
```bash
# Generate verifier (43-128 characters)
VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')

# Generate challenge
CHALLENGE=$(echo -n $VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '+/' '-_')
```

2. Open in browser:
```
http://localhost:8080/realms/test/login?response_type=code&client_id=test-public-client&redirect_uri=http://localhost:8080/callback&scope=openid&code_challenge=$CHALLENGE&code_challenge_method=S256&state=random123
```

3. Exchange code for tokens:
```bash
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=test-public-client" \
  -d "code=<CODE_FROM_REDIRECT>" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "code_verifier=$VERIFIER"
```

## Token Operations

### Introspect Token

```bash
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token/introspect \
  -u test-client:test-secret \
  -d "token=<ACCESS_TOKEN>"
```

### Revoke Token

```bash
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/revoke \
  -u test-client:test-secret \
  -d "token=<ACCESS_TOKEN>"
```

### UserInfo

```bash
curl http://localhost:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | Required | PostgreSQL connection URL |
| `KC_HOST` | `0.0.0.0` | Bind address |
| `KC_PORT` | `8080` | HTTP port |
| `KC_BASE_URL` | Auto | External URL for generated links |
| `KC_ACCESS_TOKEN_LIFESPAN` | `300` | Access token TTL (seconds) |
| `KC_REFRESH_TOKEN_LIFESPAN` | `1800` | Refresh token TTL (seconds) |
| `RUST_LOG` | `info` | Log level |

See [Configuration Guide](./CONFIGURATION.md) for all options.

## Next Steps

- [Configuration Guide](./CONFIGURATION.md) - All configuration options
- [API Reference](./API.md) - Complete OIDC endpoint documentation
- [Deployment Guide](./DEPLOYMENT.md) - Production deployment
- [Security Guide](./SECURITY.md) - Security considerations
