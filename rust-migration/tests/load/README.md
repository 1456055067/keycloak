# Load Testing for Keycloak Rust

This directory contains load testing infrastructure for validating v1.0 performance criteria.

## v1.0 Performance Criteria

| Criteria | Target | Test |
|----------|--------|------|
| Concurrent sessions | 10,000+ | Session load test |
| Token endpoint p99 latency | < 100ms | Token endpoint benchmark |
| Memory usage (idle) | < 256MB | Server monitoring |

## Running Load Tests

### Prerequisites

1. Start the Keycloak Rust server:
   ```bash
   DATABASE_URL=postgres://keycloak:keycloak@localhost:5432/keycloak \
   cargo run -p kc-server
   ```

2. Create a test realm and client (via Admin API or SQL):
   ```sql
   INSERT INTO realms (id, name, enabled)
   VALUES (gen_random_uuid(), 'test', true);

   INSERT INTO clients (id, realm_id, client_id, secret, public_client, enabled)
   VALUES (gen_random_uuid(), <realm_id>, 'test-client', 'test-secret', false, true);
   ```

### Token Endpoint Benchmark

Test the token endpoint with client_credentials flow:

```bash
# 10,000 requests with 100 concurrent workers
cargo run -p kc-load-tests -- \
  --server http://localhost:3000 \
  --realm test \
  --client-id test-client \
  --client-secret test-secret \
  --workers 100 \
  --requests 10000 \
  --test-type token
```

### Discovery Endpoint Benchmark

Test the OIDC discovery endpoint:

```bash
cargo run -p kc-load-tests -- \
  --server http://localhost:3000 \
  --realm test \
  --workers 100 \
  --requests 10000 \
  --test-type discovery
```

### JWKS Endpoint Benchmark

Test the JWKS (certificates) endpoint:

```bash
cargo run -p kc-load-tests -- \
  --server http://localhost:3000 \
  --realm test \
  --workers 100 \
  --requests 10000 \
  --test-type jwks
```

## Interpreting Results

The load test outputs:
- **Total requests**: Number of requests completed
- **Success rate**: Percentage of successful responses
- **Latency percentiles**: p50, p90, p95, p99, max
- **Requests/second**: Throughput achieved

### v1.0 Criteria Check

The tool automatically checks:
1. **p99 latency < 100ms** - Token endpoint response time
2. **Reliability >= 99.9%** - Success rate under load

## Memory Profiling

To measure memory usage, use system tools:

```bash
# macOS
ps aux | grep kc-server

# Linux
cat /proc/<pid>/status | grep VmRSS

# Or use heaptrack for detailed analysis
heaptrack ./target/release/kc-server
```

## Stress Testing

For longer stress tests:

```bash
# 1 hour stress test
cargo run -p kc-load-tests --release -- \
  --server http://localhost:3000 \
  --realm test \
  --client-id test-client \
  --client-secret test-secret \
  --workers 500 \
  --requests 1000000 \
  --test-type token
```

## CI Integration

These tests can be run in CI with a PostgreSQL testcontainer:

```yaml
- name: Run load tests
  run: |
    cargo run -p kc-load-tests --release -- \
      --workers 50 \
      --requests 5000 \
      --test-type token
```
