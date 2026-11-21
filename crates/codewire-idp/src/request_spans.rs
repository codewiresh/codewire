//! Puts the IdP's own routes inside the standard request span.
//!
//! `main` merges the IdP's routes into the router `AppBuilder` has already
//! built, and a router's middleware covers only the routes it had when the
//! middleware was added. Without this the health and metrics routes would
//! have the request span and no sign-in route would, so the IdP would export
//! no trace and a sign-in's trace would stop at the dashboard
//! (docs/CONFIGURATION.md, "Tracing").

use axum::Router;

/// Wraps `routes` so each request to one of them runs inside the standard
/// request span, which continues the caller's trace while trace export is on.
///
/// Apply it after the last `merge` into `routes`: a route merged in later is
/// not covered.
pub fn request_spans(routes: Router) -> Router {
    routes.layer(codewire_server_core::http::request_trace_layer())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request, http::StatusCode, routing::get};
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt as _;

    /// Each request span opened, as whether trace export would build it.
    #[derive(Clone, Default)]
    struct RequestSpans(Arc<Mutex<Vec<bool>>>);

    impl tracing::Subscriber for RequestSpans {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.is_span() && metadata.name() == "request"
        }
        fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let mut spans = self.0.lock().unwrap();
            spans.push(codewire_server_core::obs::exports_span(
                attributes.metadata(),
            ));
            tracing::span::Id::from_u64(spans.len() as u64)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn sign_in_stand_in() -> Router {
        Router::new().route("/api/auth/stand-in", get(|| async { "{}" }))
    }

    async fn call(app: Router) {
        let request = Request::builder()
            .uri("/api/auth/stand-in")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn each_request_to_a_wrapped_route_opens_one_exported_request_span() {
        let spans = RequestSpans::default();
        let _subscriber = tracing::subscriber::set_default(spans.clone());

        // The control: a route merged in beside routes that have the span,
        // as `main` mounted the IdP's routes before, opens none.
        let standard = request_spans(Router::new().route("/healthz", get(|| async { "ok" })));
        call(standard.merge(sign_in_stand_in())).await;
        assert_eq!(*spans.0.lock().unwrap(), Vec::<bool>::new());

        call(request_spans(sign_in_stand_in())).await;
        assert_eq!(*spans.0.lock().unwrap(), [true]);
    }
}
