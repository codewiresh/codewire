//! codewire#3258: no service answers CORS unless its deployment names the
//! exact browser origin, and an unlisted origin never gets
//! `Access-Control-Allow-Origin`.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;

use axum::Router;
use axum::routing::post;
use codewire_server_core::AppBuilder;

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), server)
}

fn app(origins: &[&'static str]) -> Router {
    AppBuilder::new("cors-test")
        .with_health()
        .with_routes(Router::new().route("/echo", post(|| async { "ok" })))
        .with_cors_allowed_origins(
            origins
                .iter()
                .map(|origin| http::HeaderValue::from_static(origin)),
        )
        .into_router()
}

async fn preflight(base: &str, origin: &str) -> reqwest::Response {
    reqwest::Client::new()
        .request(reqwest::Method::OPTIONS, format!("{base}/echo"))
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap()
}

async fn simple(base: &str, origin: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/echo"))
        .header("origin", origin)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn without_configured_origins_no_response_carries_cors_headers() {
    let (base, server) = serve(app(&[])).await;
    for response in [
        preflight(&base, "https://evil.example").await,
        simple(&base, "https://evil.example").await,
    ] {
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-methods")
                .is_none()
        );
    }
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn only_a_listed_origin_is_allowed() {
    let (base, server) = serve(app(&["https://app.example.com"])).await;

    let listed = preflight(&base, "https://app.example.com").await;
    assert_eq!(
        listed.headers().get("access-control-allow-origin").unwrap(),
        "https://app.example.com"
    );
    assert!(
        listed
            .headers()
            .get("access-control-allow-credentials")
            .is_none()
    );
    let listed = simple(&base, "https://app.example.com").await;
    assert_eq!(listed.status(), 200);
    assert_eq!(
        listed.headers().get("access-control-allow-origin").unwrap(),
        "https://app.example.com"
    );

    for origin in [
        "https://evil.example",
        "https://app.example.com.evil.example",
        "null",
    ] {
        assert!(
            preflight(&base, origin)
                .await
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "{origin}"
        );
        assert!(
            simple(&base, origin)
                .await
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "{origin}"
        );
    }
    server.abort();
}
