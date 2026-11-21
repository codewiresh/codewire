//! A preview visitor's trace context never reaches the API router's request
//! span, which continues the trace in a `traceparent`
//! (docs/CONFIGURATION.md, "Tracing"). The app is built as `main` builds it:
//! the standard middleware from `AppBuilder`, with the preview proxy mounted
//! outside it by `mount_outside`, so a request on a preview host is answered
//! before the span exists.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use super::browser_router_tests::state;
use super::preview::mount_outside;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

/// The headers of each request that got as far as the request span.
async fn seen_by_the_request_span(host: &str) -> Vec<HeaderMap> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let routes = Router::new().fallback(move |headers: HeaderMap| {
        recorded.lock().unwrap().push(headers);
        async { StatusCode::NO_CONTENT }
    });
    let app = mount_outside(
        codewire_server_core::AppBuilder::new("codewire-orchestration")
            .with_routes(routes)
            .into_router(),
        state().await,
    );
    let request = Request::post("/codewire.v1.EnvironmentService/ListEnvironments")
        .header(header::HOST, host)
        .header("traceparent", TRACEPARENT)
        .header("tracestate", "vendor=opaque")
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap();
    seen.lock().unwrap().clone()
}

#[tokio::test]
async fn a_preview_visitors_trace_context_never_reaches_the_request_span() {
    // The API's own host: the request span sees the caller's trace context.
    let api = seen_by_the_request_span("api.example.test").await;
    assert_eq!(api.len(), 1);
    assert_eq!(api[0]["traceparent"], TRACEPARENT);

    // A preview host: no request that reaches the span carries one.
    for host in ["web-abcde-org.preview.test", "not a preview.preview.test"] {
        let preview = seen_by_the_request_span(host).await;
        assert!(
            preview
                .iter()
                .all(|headers| !headers.contains_key("traceparent")
                    && !headers.contains_key("tracestate")),
            "{host}: {preview:?}"
        );
    }
}
