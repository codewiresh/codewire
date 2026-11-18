//! [`super::never_shared_cached`] marks every answer, whatever the handler
//! set and whatever the status.

use super::never_shared_cached;
use axum::Router;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Headers a handler or an upstream might add that let a shared cache
/// store or revalidate an answer.
fn cacheable_headers() -> [(header::HeaderName, &'static str); 3] {
    [
        (header::CACHE_CONTROL, "public, max-age=300"),
        (header::ETAG, "\"synthetic-etag\""),
        (header::LAST_MODIFIED, "Mon, 16 Nov 2026 12:00:00 GMT"),
    ]
}

fn app() -> Router {
    never_shared_cached(
        Router::new()
            .route(
                "/cacheable",
                get(|| async { (cacheable_headers(), "{}").into_response() }),
            )
            .route(
                "/fails",
                get(|| async {
                    (StatusCode::INTERNAL_SERVER_ERROR, cacheable_headers(), "{}").into_response()
                }),
            ),
    )
}

async fn get_response(path: &str) -> Response {
    app()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn assert_never_shared_cached(response: &Response) {
    let headers = response.headers();
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store, private"
    );
    assert!(headers.get(header::ETAG).is_none());
    assert!(headers.get(header::LAST_MODIFIED).is_none());
}

#[tokio::test]
async fn a_handlers_cache_headers_give_way() {
    let response = get_response("/cacheable").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_never_shared_cached(&response);
}

#[tokio::test]
async fn errors_and_the_404_fallback_are_never_shared_cached() {
    let failed = get_response("/fails").await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_never_shared_cached(&failed);

    let missing = get_response("/no-such-route").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_never_shared_cached(&missing);
}
