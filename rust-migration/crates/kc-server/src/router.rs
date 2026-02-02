//! Router configuration.
//!
//! This module creates the main Axum router that combines all endpoints.

use axum::{
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use kc_protocol_oidc::endpoints::oidc_router;

use crate::providers::StorageProviders;
use crate::state::AppState;
use crate::ui;

/// Creates the main application router.
pub fn create_router(state: AppState) -> Router {
    // Create OIDC router with our providers
    let oidc = oidc_router::<StorageProviders>()
        .with_state(state.oidc_state());

    // Create health check routes
    let health = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(|| async { readiness_check().await }));

    // Create UI routes for login/logout
    let ui_routes = Router::new()
        .route("/realms/{realm}/login", get(ui::login_page).post(ui::login_submit))
        .route(
            "/realms/{realm}/protocol/openid-connect/logout",
            get(ui::logout_page).post(ui::logout_submit),
        )
        .with_state(state.clone());

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Combine all routes
    Router::new()
        .merge(oidc)
        .merge(health)
        .merge(ui_routes)
        .route("/", get(root))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Root endpoint handler.
async fn root() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "Keycloak Rust".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        documentation: "https://github.com/keycloak/keycloak-rs".to_string(),
    })
}

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

/// Server information response.
#[derive(Serialize)]
pub struct ServerInfo {
    name: String,
    version: String,
    documentation: String,
}

/// Basic health check.
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

/// Kubernetes liveness probe.
async fn liveness_check() -> StatusCode {
    StatusCode::OK
}

/// Kubernetes readiness probe.
async fn readiness_check() -> StatusCode {
    // In a real implementation, would check database connectivity
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0.status, "healthy");
    }
}
