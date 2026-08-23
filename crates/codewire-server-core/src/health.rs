//! Liveness and readiness endpoints.
//!
//! Mounted by [`crate::http::AppBuilder::with_health`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use sqlx::PgPool;

type ReadinessFuture = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;

#[derive(Clone)]
pub(crate) struct ReadinessProbe {
    check: Arc<dyn Fn() -> ReadinessFuture + Send + Sync>,
}

impl ReadinessProbe {
    pub(crate) fn new<F, Fut>(check: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        Self {
            check: Arc::new(move || Box::pin(check())),
        }
    }

    async fn is_ready(&self) -> bool {
        (self.check)().await
    }
}

/// State the readiness probe needs to check.
#[derive(Clone, Default)]
pub struct HealthState {
    /// If set, `/readyz` pings the pool with `SELECT 1` and fails with
    /// 503 when the database is unreachable.
    pub pool: Option<PgPool>,
    pub(crate) readiness_probe: Option<ReadinessProbe>,
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
    if let Some(probe) = &state.readiness_probe
        && !probe.is_ready().await
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "dependency unavailable").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn readiness_probe_fails_closed_and_recovers() {
        let ready = Arc::new(AtomicBool::new(false));
        let state = HealthState {
            pool: None,
            readiness_probe: Some(ReadinessProbe::new({
                let ready = ready.clone();
                move || {
                    let ready = ready.clone();
                    async move { ready.load(Ordering::SeqCst) }
                }
            })),
        };
        let app = router(state);
        let response = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        ready.store(true, Ordering::SeqCst);
        let response = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
