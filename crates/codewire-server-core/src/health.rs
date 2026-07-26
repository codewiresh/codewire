//! Liveness and readiness endpoints.
//!
//! Mounted by [`crate::http::AppBuilder::with_health`].

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use sqlx::PgPool;

/// State the readiness probe needs to check.
#[derive(Clone, Default)]
pub struct HealthState {
    /// If set, `/readyz` pings the pool with `SELECT 1` and fails with
    /// 503 when the database is unreachable.
    pub pool: Option<PgPool>,
}

pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<HealthState>) -> impl IntoResponse {
    if let Some(pool) = &state.pool
        && sqlx::query("SELECT 1").execute(pool).await.is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "database unavailable").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}
