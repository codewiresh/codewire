//! End-to-end smoke for `AppBuilder`: spin up the standard router on a
//! random port, hit `/healthz` and an unauthenticated user route, assert
//! the response shapes match what the SDKs expect. No external services
//! required (no Postgres / NATS) — `/readyz` skips the DB check when no
//! pool was supplied.

use std::net::SocketAddr;

use axum::Json;
use axum::Router;
use axum::routing::{get, post};
use codewire_server_core::{AppBuilder, AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

async fn forbidden() -> Result<&'static str, AppError> {
    Err(AppError::Forbidden)
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InviteRequest {
    email: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct InviteResponse {
    email: String,
    role: String,
}

async fn invite(
    ValidatedJson(req): ValidatedJson<InviteRequest>,
) -> Result<Json<InviteResponse>, AppError> {
    Ok(Json(InviteResponse {
        email: req.email,
        role: req.role,
    }))
}

#[tokio::test(flavor = "current_thread")]
async fn app_builder_serves_health_and_propagates_error_envelope() {
    let routes = Router::new()
        .route("/protected", get(forbidden))
        .route("/invite", post(invite));
    let app = AppBuilder::new("test-service")
        .with_health()
        .with_routes(routes)
        .into_router();

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The CI flake budget is tight; give the listener a beat to accept.
    let client = reqwest::Client::new();

    // /healthz — always 200 ok.
    let health = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert!(health.status().is_success());
    assert_eq!(health.text().await.unwrap(), "ok");

    // `/metrics` is an internal Service endpoint for Prometheus. It exposes
    // only the static service label and carries the Prometheus text type.
    let metrics = client
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics.status().is_success());
    assert!(
        metrics
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain; version=0.0.4")
    );
    assert!(
        metrics
            .text()
            .await
            .unwrap()
            .contains("codewire_control_plane_service_info{service=\"test-service\"} 1")
    );

    // /protected — handler returns AppError::Forbidden; envelope is the
    // wire shape the SDKs parse.
    let resp = client
        .get(format!("http://{addr}/protected"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], 403);
    assert_eq!(body["title"], "Forbidden");
    assert_eq!(body["detail"], "forbidden");
    assert_eq!(body["code"], "forbidden");

    // /invite — ValidatedJson rejects the missing role before the
    // handler runs, using the Rust-native 422 shape.
    let resp = client
        .post(format!("http://{addr}/invite"))
        .json(&serde_json::json!({ "email": "n@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], 422);
    assert_eq!(body["title"], "Unprocessable Entity");
    assert_eq!(body["detail"], "validation failed");
    assert_eq!(body["errors"][0]["path"], "/");
    assert!(
        body["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("role")
    );

    server.abort();
}
