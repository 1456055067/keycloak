# Deployment Guide

This guide covers deploying Keycloak Rust in production environments.

## Requirements

- PostgreSQL 14+ (primary database)
- Redis 7+ (optional, for distributed caching)
- Kubernetes 1.25+ or Docker 24+

## Docker Deployment

### Building the Image

```bash
# Build from source
docker build -t keycloak-rs:latest .

# Or use pre-built image
docker pull ghcr.io/keycloak/keycloak-rs:latest
```

### Running with Docker

```bash
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host:5432/keycloak \
  -e KC_BASE_URL=https://auth.example.com \
  -e RUST_LOG=info \
  keycloak-rs:latest
```

### Docker Compose

See [deploy/docker/docker-compose.yml](../deploy/docker/docker-compose.yml) for a complete example.

```bash
cd deploy/docker
docker-compose up -d
```

## Kubernetes Deployment

### Quick Start

```bash
# Apply all resources
kubectl apply -k deploy/kubernetes/

# Check status
kubectl -n keycloak get pods
kubectl -n keycloak get svc
```

### Customization

Edit `deploy/kubernetes/kustomization.yaml` to customize:

```yaml
images:
  - name: keycloak-rs
    newName: your-registry/keycloak-rs
    newTag: v1.0.0
```

### Secrets Management

**Important**: Never commit real secrets to git!

Create secrets manually:
```bash
kubectl -n keycloak create secret generic keycloak-secrets \
  --from-literal=DATABASE_URL='postgres://user:pass@host:5432/keycloak'
```

Or use external secrets operators:
- [External Secrets Operator](https://external-secrets.io/)
- [Sealed Secrets](https://sealed-secrets.netlify.app/)
- [Vault](https://www.vaultproject.io/)

### TLS Configuration

For production, always use TLS:

```yaml
# ingress.yaml
spec:
  tls:
    - hosts:
        - auth.example.com
      secretName: keycloak-tls
```

With cert-manager:
```yaml
annotations:
  cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

### Resource Limits

Recommended production settings:

```yaml
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

## Database Configuration

### Connection Pool

```bash
KC_DB_MIN_CONNECTIONS=5
KC_DB_MAX_CONNECTIONS=50
```

Guidelines:
- Min: Number of replicas + buffer
- Max: (Database max connections - admin connections) / number of replicas

### Connection String

```
DATABASE_URL=postgres://user:password@host:5432/database?sslmode=require
```

SSL modes:
- `disable` - No SSL (development only)
- `require` - SSL required, no certificate verification
- `verify-ca` - Verify server certificate CA
- `verify-full` - Verify server hostname matches certificate

### High Availability

For production, use:
- PostgreSQL with streaming replication
- PgBouncer for connection pooling
- Read replicas for read-heavy workloads

## Scaling

### Horizontal Scaling

The server is stateless and can be horizontally scaled:

```yaml
# deployment.yaml
spec:
  replicas: 3
```

Or use HPA:
```yaml
# hpa.yaml
spec:
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Session Considerations

By default, sessions are stored in memory. For multi-replica deployments:

1. **Sticky Sessions** (simplest): Configure your load balancer
2. **Redis Sessions** (recommended): Set `REDIS_URL` environment variable
3. **Database Sessions** (future): Coming in a future release

## Monitoring

### Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | General health with version |
| `/health/live` | Kubernetes liveness probe |
| `/health/ready` | Kubernetes readiness probe |

### Prometheus Metrics

Coming in a future release. For now, use:
- Database connection pool metrics (via PostgreSQL)
- HTTP metrics (via your ingress/load balancer)

### Logging

Configure log level:
```bash
RUST_LOG=info,kc_server=debug,kc_protocol_oidc=debug
```

Structured JSON logging:
```bash
RUST_LOG_FORMAT=json
```

## Security Checklist

- [ ] Use TLS for all external traffic
- [ ] Database SSL enabled (`sslmode=verify-full`)
- [ ] Secrets managed externally (not in environment)
- [ ] Network policies restricting pod communication
- [ ] Pod security policies/standards enforced
- [ ] Regular security updates
- [ ] Audit logging enabled

## Backup and Recovery

### Database Backup

```bash
# PostgreSQL dump
pg_dump -h host -U keycloak keycloak > backup.sql

# Restore
psql -h host -U keycloak keycloak < backup.sql
```

### Disaster Recovery

1. Regular database backups (daily minimum)
2. Test restore procedures quarterly
3. Multi-region deployment for critical workloads

## Troubleshooting

### Common Issues

**Connection refused to database**
```bash
# Check database is reachable
nc -zv db-host 5432

# Check credentials
psql $DATABASE_URL -c "SELECT 1"
```

**Pods not starting**
```bash
kubectl -n keycloak describe pod <pod-name>
kubectl -n keycloak logs <pod-name>
```

**High memory usage**
- Check connection pool settings
- Review request patterns for memory leaks
- Consider resource limits

### Debug Mode

```bash
RUST_LOG=debug,kc_server=trace
```

**Warning**: Debug logging includes sensitive information. Never use in production!
