# Keycloak Rust - Multi-stage Docker build
#
# Build: docker build -t keycloak-rs .
# Run:   docker run -p 8080:8080 -e DATABASE_URL=postgres://... keycloak-rs

# === Build Stage ===
FROM rust:1.83-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build dependencies (cache layer)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --package kc-server && \
    cp target/release/keycloak /tmp/keycloak

# === Runtime Stage ===
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r keycloak && useradd -r -g keycloak keycloak

WORKDIR /app

# Copy binary from builder
COPY --from=builder /tmp/keycloak /app/keycloak

# Copy templates
COPY crates/kc-server/templates /app/templates

# Set ownership
RUN chown -R keycloak:keycloak /app

# Switch to non-root user
USER keycloak

# Set environment defaults
ENV KC_HOST=0.0.0.0
ENV KC_PORT=8080
ENV RUST_LOG=info

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the server
ENTRYPOINT ["/app/keycloak"]
