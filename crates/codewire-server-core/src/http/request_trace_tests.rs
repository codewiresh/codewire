//! [`super::request_trace_layer`]: the request span ends when the response
//! starts, and tower-http's log lines keep their targets inside it.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::routing::get;
use http::{Request, StatusCode};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// An event: its target, its level and the name of the span it was written
/// in.
type Event = (String, tracing::Level, Option<&'static str>);

/// What a test's requests did: each span opened and closed, by name, and
/// each event.
#[derive(Clone, Default)]
struct Seen {
    opened: Arc<Mutex<Vec<&'static str>>>,
    closed: Arc<Mutex<Vec<&'static str>>>,
    events: Arc<Mutex<Vec<Event>>>,
}

impl<S> tracing_subscriber::Layer<S> for Seen
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.opened
            .lock()
            .unwrap()
            .push(attributes.metadata().name());
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let name = ctx.span(&id).expect("a closing span is known").name();
        self.closed.lock().unwrap().push(name);
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.events.lock().unwrap().push((
            event.metadata().target().to_owned(),
            *event.metadata().level(),
            ctx.event_span(event).map(|span| span.name()),
        ));
    }
}

/// A route whose response starts at once and whose body ends only when
/// `release` is notified, writing one event as it does.
fn held_open(release: Arc<tokio::sync::Notify>) -> Router {
    Router::new().route(
        "/stream",
        get(move || {
            let release = release.clone();
            async move {
                tracing::info!(target: "codewire_test", "setup");
                Body::from_stream(futures::stream::once(async move {
                    release.notified().await;
                    tracing::info!(target: "codewire_test", "relay");
                    Ok::<_, std::convert::Infallible>(Bytes::from_static(b"done"))
                }))
            }
        }),
    )
}

async fn get_stream(app: Router) -> axum::response::Response {
    let response = app
        .oneshot(Request::get("/stream").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
}

fn test_events(seen: &Seen) -> Vec<(String, Option<&'static str>)> {
    seen.events
        .lock()
        .unwrap()
        .iter()
        .filter(|(target, _, _)| target == "codewire_test")
        .map(|(_, _, span)| ("codewire_test".to_owned(), *span))
        .collect()
}

#[tokio::test]
async fn the_request_span_ends_when_the_response_starts() {
    let seen = Seen::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(seen.clone()));
    let release = Arc::new(tokio::sync::Notify::new());

    let response = get_stream(held_open(release.clone()).layer(super::request_trace_layer())).await;
    // The body is still open, and the span is already closed.
    assert_eq!(*seen.opened.lock().unwrap(), ["request"]);
    assert_eq!(*seen.closed.lock().unwrap(), ["request"]);

    release.notify_one();
    let body = axum::body::to_bytes(response.into_body(), 16)
        .await
        .unwrap();
    assert_eq!(&body[..], b"done");
    // The handler's line was written in the span; the body's in none.
    assert_eq!(
        test_events(&seen),
        [
            ("codewire_test".to_owned(), Some("request")),
            ("codewire_test".to_owned(), None)
        ]
    );
}

/// The control for the test above: tower-http's layer with the same span
/// keeps it open until the body ends, which is what the standard layer did.
#[tokio::test]
async fn tower_https_own_layer_holds_the_span_until_the_body_ends() {
    let seen = Seen::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(seen.clone()));
    let release = Arc::new(tokio::sync::Notify::new());

    let layer = tower_http::trace::TraceLayer::new_for_http().make_span_with(super::RequestSpan);
    let response = get_stream(held_open(release.clone()).layer(layer)).await;
    assert_eq!(*seen.opened.lock().unwrap(), ["request"]);
    assert_eq!(*seen.closed.lock().unwrap(), Vec::<&str>::new());

    release.notify_one();
    drop(
        axum::body::to_bytes(response.into_body(), 16)
            .await
            .unwrap(),
    );
    assert_eq!(*seen.closed.lock().unwrap(), ["request"]);
    assert_eq!(
        test_events(&seen),
        [
            ("codewire_test".to_owned(), Some("request")),
            ("codewire_test".to_owned(), Some("request"))
        ]
    );
}

/// A failed request still writes tower-http's `response failed` line at
/// `ERROR`, under its own target and inside the request span, so the line
/// carries the request's trace ids while export is on.
#[tokio::test]
async fn a_failed_request_keeps_its_error_line_inside_the_request_span() {
    let seen = Seen::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(seen.clone()));
    let app = Router::new()
        .route(
            "/fails",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .layer(super::request_trace_layer());

    let response = app
        .oneshot(Request::get("/fails").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let events = seen.events.lock().unwrap().clone();
    let targets: Vec<_> = events
        .iter()
        .map(|(target, level, span)| (target.as_str(), *level, *span))
        .collect();
    assert_eq!(
        targets,
        [
            (
                "tower_http::trace::on_request",
                tracing::Level::DEBUG,
                Some("request")
            ),
            (
                "tower_http::trace::on_response",
                tracing::Level::DEBUG,
                Some("request")
            ),
            (
                "tower_http::trace::on_failure",
                tracing::Level::ERROR,
                Some("request")
            ),
        ]
    );
}
