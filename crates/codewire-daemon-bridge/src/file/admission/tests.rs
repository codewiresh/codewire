//! The `WriteFiles` body budget, driven through an axum router whose inner
//! service reads the whole body, and bodies that record whether they were
//! polled.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use tokio::sync::{mpsc, watch};
use tower::ServiceExt as _;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_FILES: &str = proto::FILE_SERVICE_WRITE_FILES_SPEC.procedure;
const UPLOAD_FILE: &str = proto::FILE_SERVICE_UPLOAD_FILE_SPEC.procedure;
const MAX: usize = WRITE_FILES_MAX_MESSAGE_BYTES;
const PRINCIPAL: &str = "x-test-principal";

fn test_principal(request: &Request) -> Option<String> {
    request
        .headers()
        .get(PRINCIPAL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A router behind `budget` whose routes read the whole body, answering 200
/// once read and 400 when reading fails. `reached` counts the requests that
/// got past the budget. Like the Connect dispatcher, a route keeps the
/// request's extensions, and with them its untaken charge, until it answers;
/// no route takes the charge.
fn app(budget: &Arc<BodyBudget>, reached: &Arc<watch::Sender<usize>>) -> axum::Router {
    async fn read_all(
        State(reached): State<Arc<watch::Sender<usize>>>,
        request: Request,
    ) -> StatusCode {
        reached.send_modify(|count| *count += 1);
        let (parts, body) = request.into_parts();
        let status = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(_) => StatusCode::OK,
            Err(_) => StatusCode::BAD_REQUEST,
        };
        drop(parts);
        status
    }
    let inner = axum::Router::new()
        .route(WRITE_FILES, axum::routing::post(read_all))
        .route(UPLOAD_FILE, axum::routing::post(read_all))
        .with_state(Arc::clone(reached));
    with_budget(inner, Arc::clone(budget))
}

/// A body that sends only what the test gives it and records whether anyone
/// polled it.
struct Fed {
    body: Body,
    polled: Arc<AtomicBool>,
    feed: mpsc::Sender<Bytes>,
}

fn fed() -> Fed {
    let (feed, mut chunks) = mpsc::channel::<Bytes>(4);
    let polled = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&polled);
    let stream = futures::stream::poll_fn(move |cx| {
        seen.store(true, Ordering::SeqCst);
        chunks
            .poll_recv(cx)
            .map(|chunk| chunk.map(Ok::<_, Infallible>))
    });
    Fed {
        body: Body::from_stream(stream),
        polled,
        feed,
    }
}

fn request(path: &str, principal: Option<&str>, headers: &[(&str, String)], body: Body) -> Request {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/proto");
    if let Some(principal) = principal {
        request = request.header(PRINCIPAL, principal);
    }
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    request.body(body).expect("test request")
}

fn length(bytes: usize) -> (&'static str, String) {
    ("content-length", bytes.to_string())
}

async fn send(router: &axum::Router, request: Request) -> Response {
    tokio::time::timeout(TEST_TIMEOUT, router.clone().oneshot(request))
        .await
        .expect("the request was not answered")
        .expect("router is infallible")
}

/// Asserts `response` is the Connect unary `resource_exhausted` error with
/// `message`.
async fn assert_refused(response: Response, message: &str) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("error body");
    let body = String::from_utf8(body.to_vec()).expect("utf-8 error body");
    assert!(
        body.starts_with(r#"{"code":"resource_exhausted""#),
        "{body}"
    );
    assert!(body.contains(message), "{body}");
}

/// A maximum-size request from `principal` whose body never arrives, spawned
/// so it holds its charge; the returned feed keeps the body open.
fn hold(
    router: &axum::Router,
    principal: Option<&str>,
) -> (
    tokio::task::JoinHandle<Result<Response, Infallible>>,
    mpsc::Sender<Bytes>,
) {
    let body = fed();
    let call = router
        .clone()
        .oneshot(request(WRITE_FILES, principal, &[length(MAX)], body.body));
    (tokio::spawn(call), body.feed)
}

async fn wait_reached(reached: &Arc<watch::Sender<usize>>, count: usize) {
    let mut reached = reached.subscribe();
    tokio::time::timeout(TEST_TIMEOUT, reached.wait_for(|n| *n >= count))
        .await
        .expect("held requests did not reach the inner service")
        .expect("reached sender kept");
}

/// Cancels held calls and waits until each has stopped.
async fn stop<const N: usize>(calls: [tokio::task::JoinHandle<Result<Response, Infallible>>; N]) {
    for call in calls {
        call.abort();
        let stopped = tokio::time::timeout(TEST_TIMEOUT, call)
            .await
            .expect("held call did not stop");
        assert!(stopped.is_err_and(|error| error.is_cancelled()));
    }
}

fn held(budget: &BodyBudget) -> (usize, HashMap<Option<String>, usize>) {
    budget.held()
}

#[test]
fn a_request_is_charged_its_length_unless_compressed_or_unknown() {
    let charged = |headers: &[(&str, &str)]| {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        charge(&map)
    };
    assert_eq!(charged(&[("content-length", "5")]), 5);
    assert_eq!(charged(&[("content-length", &(MAX + 1).to_string())]), MAX);
    assert_eq!(charged(&[]), MAX);
    assert_eq!(charged(&[("content-length", "five")]), MAX);
    assert_eq!(
        charged(&[("content-length", "5"), ("content-length", "5")]),
        MAX
    );
    assert_eq!(
        charged(&[
            ("content-length", "5"),
            ("connect-content-encoding", "gzip")
        ]),
        MAX
    );
    assert_eq!(
        charged(&[("content-length", "5"), ("content-encoding", "br")]),
        MAX
    );
    assert_eq!(
        charged(&[("content-length", "5"), ("content-encoding", "Identity")]),
        5
    );
    assert_eq!(
        charged(&[
            ("content-length", "5"),
            ("connect-content-encoding", "identity")
        ]),
        5
    );
}

#[tokio::test]
async fn a_full_budget_refuses_a_request_before_reading_its_body() {
    let budget = Arc::new(BodyBudget::new(test_principal));
    let reached = Arc::new(watch::channel(0).0);
    let router = app(&budget, &reached);

    // Principal a holds two maximum-size calls whose bodies never arrive.
    let (first, _first_feed) = hold(&router, Some("a"));
    let (second, second_feed) = hold(&router, Some("a"));
    wait_reached(&reached, 2).await;
    assert_eq!(held(&budget).0, 2 * MAX);

    // b is within its share, but the budget lacks room for its largest.
    let over = fed();
    let response = send(
        &router,
        request(WRITE_FILES, Some("b"), &[length(MAX)], over.body),
    )
    .await;
    assert_refused(response, BUDGET_FULL).await;
    assert!(!over.polled.load(Ordering::SeqCst));

    // A compressed request and one of unknown length are charged the most.
    let gzip = fed();
    let response = send(
        &router,
        request(
            WRITE_FILES,
            Some("b"),
            &[length(10), ("connect-content-encoding", "gzip".to_owned())],
            gzip.body,
        ),
    )
    .await;
    assert_refused(response, BUDGET_FULL).await;
    assert!(!gzip.polled.load(Ordering::SeqCst));
    let unknown = fed();
    let response = send(&router, request(WRITE_FILES, Some("b"), &[], unknown.body)).await;
    assert_refused(response, BUDGET_FULL).await;
    assert!(!unknown.polled.load(Ordering::SeqCst));
    assert_eq!(*reached.borrow(), 2);

    // A small uncompressed request still fits.
    let response = send(
        &router,
        request(WRITE_FILES, Some("b"), &[length(5)], Body::from("hello")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Every other path passes through.
    let response = send(
        &router,
        request(UPLOAD_FILE, Some("b"), &[length(MAX)], Body::from("x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A caller that leaves before any handler took its charge gives it back
    // with the request.
    first.abort();
    let left = tokio::time::timeout(TEST_TIMEOUT, first)
        .await
        .expect("held call did not stop");
    assert!(left.is_err_and(|error| error.is_cancelled()));
    assert_eq!(held(&budget).0, MAX);

    // So does a call that completes.
    second_feed.send(Bytes::from_static(b"done")).await.unwrap();
    drop(second_feed);
    let done = tokio::time::timeout(TEST_TIMEOUT, second)
        .await
        .expect("held call did not finish")
        .expect("held call task")
        .expect("router is infallible");
    assert_eq!(done.status(), StatusCode::OK);
    assert_eq!(held(&budget), (0, HashMap::new()));
}

#[tokio::test]
async fn one_caller_holds_at_most_its_share() {
    let budget = Arc::new(BodyBudget::new(test_principal));
    let reached = Arc::new(watch::channel(0).0);
    let router = app(&budget, &reached);
    let (first, _first_feed) = hold(&router, Some("a"));
    let (second, _second_feed) = hold(&router, Some("a"));
    wait_reached(&reached, 2).await;

    // The budget has room for a small request, but a's share does not.
    let next = fed();
    let response = send(
        &router,
        request(WRITE_FILES, Some("a"), &[length(10)], next.body),
    )
    .await;
    assert_refused(response, SHARE_FULL).await;
    assert!(!next.polled.load(Ordering::SeqCst));

    let response = send(
        &router,
        request(WRITE_FILES, Some("b"), &[length(5)], Body::from("hello")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    stop([first, second]).await;
    assert_eq!(held(&budget), (0, HashMap::new()));
}

#[tokio::test]
async fn requests_that_name_no_caller_share_one_share() {
    let budget = Arc::new(BodyBudget::new(test_principal));
    let reached = Arc::new(watch::channel(0).0);
    let router = app(&budget, &reached);
    let (first, _first_feed) = hold(&router, None);
    let (second, _second_feed) = hold(&router, None);
    wait_reached(&reached, 2).await;

    let next = fed();
    let response = send(
        &router,
        request(WRITE_FILES, None, &[length(10)], next.body),
    )
    .await;
    assert_refused(response, SHARE_FULL).await;
    assert!(!next.polled.load(Ordering::SeqCst));
    stop([first, second]).await;
    assert_eq!(held(&budget), (0, HashMap::new()));
}

#[tokio::test]
async fn a_body_longer_than_it_declared_fails_the_call() {
    let budget = Arc::new(BodyBudget::new(test_principal));
    let reached = Arc::new(watch::channel(0).0);
    let router = app(&budget, &reached);
    let body = fed();
    body.feed
        .send(Bytes::from_static(b"sixteen bytes!!!"))
        .await
        .unwrap();
    let response = send(
        &router,
        request(WRITE_FILES, Some("a"), &[length(4)], body.body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(held(&budget), (0, HashMap::new()));
}

#[test]
fn a_body_charged_the_largest_message_is_left_to_the_dispatcher_limit() {
    assert_eq!(read_limit(4), 4);
    assert_eq!(
        read_limit(WRITE_FILES_MAX_MESSAGE_BYTES - 1),
        WRITE_FILES_MAX_MESSAGE_BYTES - 1
    );
    assert_eq!(
        read_limit(WRITE_FILES_MAX_MESSAGE_BYTES),
        WRITE_FILES_MAX_MESSAGE_BYTES + 1
    );
}
