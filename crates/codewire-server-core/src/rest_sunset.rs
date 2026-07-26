//! REST sunset observation and deprecation middleware.
//!
//! Every event emitted by this module has tracing target `rest_sunset`. The
//! normal service JSON subscriber therefore writes one structured event per
//! matched REST route, which can be queried without edge-controller access:
//!
//! ```text
//! kubectl logs deployment/<service> | jq 'select(.target == "rest_sunset")'
//! ```
//!
//! `matched_path` is Axum's route template rather than the raw request URI,
//! so a sunset observation aggregates by route without recording path
//! parameters. API-key telemetry contains only the existing eight-character
//! key prefix; it never records a raw credential.

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::Response;

use crate::auth::{AuthUser, api_key_prefix};

/// One REST route-prefix area that has entered its deprecation window.
///
/// Services introduce this middleware with an empty table. A later,
/// area-specific sunset WI adds a row only after its client-flip prerequisites
/// have shipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeprecatedArea {
    /// Prefix of the matched Axum route template covered by this area.
    pub route_prefix: &'static str,
    /// RFC 8594 `Sunset` header value for the area.
    pub sunset: &'static str,
    /// Documentation target for the RFC 8288 `Link` deprecation relation.
    pub link: &'static str,
}

impl DeprecatedArea {
    /// Creates a deprecation entry for a future area-specific sunset WI.
    pub const fn new(route_prefix: &'static str, sunset: &'static str, link: &'static str) -> Self {
        Self {
            route_prefix,
            sunset,
            link,
        }
    }
}

/// Immutable REST-sunset policy for one service router.
#[derive(Clone, Copy, Debug)]
pub struct RestSunsetConfig {
    deprecated_areas: &'static [DeprecatedArea],
}

impl RestSunsetConfig {
    /// Builds a service-local deprecation table.
    pub const fn new(deprecated_areas: &'static [DeprecatedArea]) -> Self {
        Self { deprecated_areas }
    }

    fn deprecated_area(self, matched_path: &str) -> Option<DeprecatedArea> {
        self.deprecated_areas
            .iter()
            .copied()
            .find(|area| matched_path.starts_with(area.route_prefix))
    }
}

/// Adds REST sunset observation to a router after route matching.
///
/// For authenticated route groups, add this layer before the auth layer so
/// it runs after authentication and can read the established request
/// principal. Public and raw-HTTP groups can use the same layer directly;
/// they emit `authenticated=false` unless their own route stack provides the
/// shared [`AuthUser`] extension.
pub fn observe<S>(router: Router<S>, config: RestSunsetConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(middleware::from_fn_with_state(config, observe_rest_request))
}

async fn observe_rest_request(
    State(config): State<RestSunsetConfig>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".to_owned());
    let user_agent = request
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let principal = RestSunsetPrincipal::from_request(&request);
    let deprecated_area = config.deprecated_area(&matched_path);

    let mut response = next.run(request).await;

    if let Some(area) = deprecated_area {
        apply_deprecation_headers(&mut response, area);
    }

    tracing::info!(
        target: "rest_sunset",
        method = %method,
        matched_path = %matched_path,
        status = response.status().as_u16(),
        user_agent = %user_agent,
        authenticated = principal.is_some(),
        user_id = principal.user_id.as_deref().unwrap_or(""),
        org_id = principal.org_id.as_deref().unwrap_or(""),
        api_key_prefix = principal.api_key_prefix.as_deref().unwrap_or(""),
        "REST sunset observation"
    );

    response
}

#[derive(Clone, Debug, Default)]
struct RestSunsetPrincipal {
    user_id: Option<String>,
    org_id: Option<String>,
    api_key_prefix: Option<String>,
}

impl RestSunsetPrincipal {
    fn from_request(request: &Request) -> Self {
        let Some(user) = request.extensions().get::<AuthUser>() else {
            return Self::default();
        };

        let api_key_prefix = user.via_api_key.then(|| {
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value
                        .strip_prefix("Bearer ")
                        .or_else(|| value.strip_prefix("bearer "))
                })
                .filter(|token| token.starts_with("cw_"))
                .map(api_key_prefix)
                .unwrap_or("")
                .to_owned()
        });

        Self {
            user_id: Some(user.user_id.clone()),
            org_id: user.org_id.clone(),
            api_key_prefix,
        }
    }

    fn is_some(&self) -> bool {
        self.user_id.is_some()
    }
}

fn apply_deprecation_headers(response: &mut Response, area: DeprecatedArea) {
    response
        .headers_mut()
        .insert("deprecation", HeaderValue::from_static("true"));

    if let Ok(sunset) = HeaderValue::from_str(area.sunset) {
        response.headers_mut().insert("sunset", sunset);
    } else {
        tracing::error!(target: "rest_sunset", route_prefix = area.route_prefix, "invalid configured Sunset header");
    }

    let link = format!("<{}>; rel=\"deprecation\"", area.link);
    if let Ok(link) = HeaderValue::from_str(&link) {
        response.headers_mut().insert("link", link);
    } else {
        tracing::error!(target: "rest_sunset", route_prefix = area.route_prefix, "invalid configured Link header");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, OnceLock};

    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    use super::*;

    #[derive(Clone, Default)]
    struct EventCapture(Arc<Mutex<Vec<CapturedEvent>>>);

    #[derive(Clone, Debug, Default)]
    struct CapturedEvent {
        target: String,
        fields: BTreeMap<String, String>,
    }

    struct EventHarness {
        capture: EventCapture,
        dispatch: tracing::Dispatch,
    }

    impl<S> Layer<S> for EventCapture
    where
        S: Subscriber,
    {
        fn register_callsite(
            &self,
            metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            if metadata.target() == "rest_sunset" {
                tracing::subscriber::Interest::always()
            } else {
                tracing::subscriber::Interest::never()
            }
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>, _context: Context<'_, S>) -> bool {
            metadata.target() == "rest_sunset"
        }

        fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
            if event.metadata().target() != "rest_sunset" {
                return;
            }
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.0
                .lock()
                .expect("event capture lock")
                .push(CapturedEvent {
                    target: event.metadata().target().to_owned(),
                    fields: visitor.0,
                });
        }
    }

    #[derive(Default)]
    struct FieldVisitor(BTreeMap<String, String>);

    impl Visit for FieldVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    fn event_harness() -> &'static EventHarness {
        static HARNESS: OnceLock<EventHarness> = OnceLock::new();

        HARNESS.get_or_init(|| {
            let capture = EventCapture::default();
            let dispatch =
                tracing::Dispatch::new(tracing_subscriber::registry().with(capture.clone()));
            tracing::dispatcher::set_global_default(dispatch.clone())
                .expect("install retained test event dispatcher");
            EventHarness { capture, dispatch }
        })
    }

    fn captured_rest_event(
        capture: &EventCapture,
        matched_path: &str,
        user_agent: &str,
    ) -> CapturedEvent {
        let event = {
            capture
                .0
                .lock()
                .expect("event capture lock")
                .iter()
                .find(|event| {
                    event.target == "rest_sunset"
                        && event.fields.get("matched_path").map(String::as_str)
                            == Some(matched_path)
                        && event.fields.get("user_agent").map(String::as_str) == Some(user_agent)
                })
                .cloned()
        };
        event.expect("rest_sunset event")
    }

    fn authenticated_router(config: RestSunsetConfig) -> Router {
        observe(
            Router::new().route(
                "/api/v1/organizations/{org_id}/widgets/{widget_id}",
                get(|| async { (StatusCode::CREATED, "unchanged response body") }),
            ),
            config,
        )
        .route_layer(middleware::from_fn(
            |mut request: Request, next: Next| async move {
                request.extensions_mut().insert(AuthUser {
                    user_id: "user-123".into(),
                    org_id: Some("org-456".into()),
                    is_admin: false,
                    via_api_key: true,
                });
                next.run(request).await
            },
        ))
    }

    #[test]
    fn emits_matched_route_authentication_and_principal_fields_without_secret_material() {
        let harness = event_harness();
        let response = tracing::dispatcher::with_default(&harness.dispatch, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    authenticated_router(RestSunsetConfig::new(&[]))
                        .oneshot(
                            HttpRequest::builder()
                                .method("GET")
                                .uri("/api/v1/organizations/org-456/widgets/widget-789")
                                .header("authorization", format!("Bearer cw_{}", "a".repeat(64)))
                                .header("user-agent", "codewire-test")
                                .body(Body::empty())
                                .expect("request"),
                        )
                        .await
                        .expect("response")
                })
        });

        assert_eq!(response.status(), StatusCode::CREATED);
        let event = captured_rest_event(
            &harness.capture,
            "/api/v1/organizations/{org_id}/widgets/{widget_id}",
            "codewire-test",
        );
        assert_eq!(event.fields["method"], "GET");
        assert_eq!(
            event.fields["matched_path"],
            "/api/v1/organizations/{org_id}/widgets/{widget_id}"
        );
        assert_eq!(event.fields["status"], "201");
        assert_eq!(event.fields["user_agent"], "codewire-test");
        assert_eq!(event.fields["authenticated"], "true");
        assert_eq!(event.fields["user_id"], "user-123");
        assert_eq!(event.fields["org_id"], "org-456");
        assert_eq!(event.fields["api_key_prefix"], "aaaaaaaa");
        assert!(
            !event
                .fields
                .values()
                .any(|value| value.contains(&"a".repeat(64))),
            "the raw API key must not appear in telemetry"
        );
    }

    #[test]
    fn adds_deprecation_headers_for_a_listed_area_without_changing_the_body() {
        const AREAS: &[DeprecatedArea] = &[DeprecatedArea::new(
            "/api/v1/organizations/",
            "Wed, 01 Jul 2026 00:00:00 GMT",
            "https://docs.codewire.sh/migrations/connect",
        )];
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                authenticated_router(RestSunsetConfig::new(AREAS))
                    .oneshot(
                        HttpRequest::builder()
                            .uri("/api/v1/organizations/org-456/widgets/widget-789")
                            .body(Body::empty())
                            .expect("request"),
                    )
                    .await
                    .expect("response")
            });

        assert_eq!(response.headers()["deprecation"], "true");
        assert_eq!(
            response.headers()["sunset"],
            "Wed, 01 Jul 2026 00:00:00 GMT"
        );
        assert_eq!(
            response.headers()["link"],
            "<https://docs.codewire.sh/migrations/connect>; rel=\"deprecation\""
        );
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("body")
            });
        assert_eq!(body, "unchanged response body");
    }

    #[test]
    fn emits_unauthenticated_event_without_principal_fields() {
        let harness = event_harness();
        tracing::dispatcher::with_default(&harness.dispatch, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    observe(
                        Router::new().route("/api/public", get(|| async { "public" })),
                        RestSunsetConfig::new(&[]),
                    )
                    .oneshot(
                        HttpRequest::builder()
                            .uri("/api/public")
                            .body(Body::empty())
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                });
        });

        let event = captured_rest_event(&harness.capture, "/api/public", "");
        assert_eq!(event.fields["authenticated"], "false");
        assert_eq!(event.fields["user_id"], "");
        assert_eq!(event.fields["org_id"], "");
        assert_eq!(event.fields["api_key_prefix"], "");
    }
}
