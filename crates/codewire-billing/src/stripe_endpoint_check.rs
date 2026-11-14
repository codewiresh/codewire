//! Billing checks its own Stripe webhook endpoint (#3263).
//!
//! At startup and then hourly, every replica lists the account's webhook
//! endpoints with billing's own Stripe key and checks the endpoint for
//! billing's public webhook URL: it exists exactly once, is enabled, is in
//! the key's mode, uses the API version of billing's Stripe SDK, and sends
//! every event type billing handles and nothing else, but for the delivery
//! check's sentinel event ([`DELIVERY_SENTINEL_EVENT`]).
//!
//! A failed check logs one ERROR line, sets
//! `codewire_billing_stripe_webhook_endpoint_healthy` to 0 and reports
//! `degraded` at billing's internal `/healthz/stripe-webhook-endpoint`, which
//! the ingress does not route. It never touches readiness or liveness: a
//! Stripe outage or a misconfigured endpoint must not take billing out of
//! service.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::Json;
use prometheus::{IntGauge, register_int_gauge};
use serde::Serialize;

use crate::checkout_sessions::FrontendOrigin;
use crate::stripe_client::{StripeHandle, WebhookEndpoint};
use crate::webhook::HANDLED_EVENT_TYPES;

const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The one event type billing does not handle that its endpoint may also
/// send: the delivery check touches a sentinel customer, and this event is
/// how Stripe answers ([`crate::stripe_delivery_check`], #3263). Billing
/// records it as an unhandled no-op.
pub const DELIVERY_SENTINEL_EVENT: &str = "customer.updated";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The endpoint matches billing.
    Ok,
    /// The endpoint is missing or does not match billing.
    Degraded,
    /// No check has completed: the first is pending or Stripe could not be
    /// reached.
    Unknown,
    /// Stripe is not configured, or `STRIPE_WEBHOOK_URL=off`.
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub status: Status,
    pub url: Option<String>,
    pub endpoint: Option<String>,
    pub failures: Vec<String>,
}

impl Report {
    fn new(status: Status, url: Option<&str>) -> Self {
        Self {
            status,
            url: url.map(str::to_owned),
            endpoint: None,
            failures: Vec::new(),
        }
    }
}

static LATEST: Mutex<Option<Report>> = Mutex::new(None);

fn healthy_gauge() -> &'static IntGauge {
    static HEALTHY: OnceLock<IntGauge> = OnceLock::new();
    HEALTHY.get_or_init(|| {
        register_int_gauge!(
            "codewire_billing_stripe_webhook_endpoint_healthy",
            "1 when the last completed check found billing's Stripe webhook endpoint matching billing, else 0"
        )
        .expect("register Stripe webhook endpoint gauge")
    })
}

fn publish(report: &Report) {
    *LATEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(report.clone());
}

/// The URL to check. Unset or empty means the frontend origin's
/// `/api/webhooks/stripe`; `off` disables the check, for a deployment that
/// receives events another way, such as `stripe listen` in development.
pub fn webhook_url(configured: Option<&str>, frontend: &FrontendOrigin) -> Option<String> {
    match configured.map(str::trim) {
        None | Some("") => Some(frontend.webhook_url()),
        Some("off") => None,
        Some(url) => Some(url.to_owned()),
    }
}

/// The endpoint matching `url`, and every way it differs from billing.
pub fn evaluate(
    endpoints: &[WebhookEndpoint],
    url: &str,
    livemode: bool,
    api_version: &str,
) -> (Option<String>, Vec<String>) {
    let matches: Vec<&WebhookEndpoint> = endpoints.iter().filter(|e| e.url == url).collect();
    let [endpoint] = matches.as_slice() else {
        return (
            None,
            vec![format!(
                "expected exactly one endpoint for the URL, found {}",
                matches.len()
            )],
        );
    };
    let mut failures = Vec::new();
    if endpoint.status != "enabled" {
        failures.push(format!(
            "endpoint status is {:?}, not \"enabled\"",
            endpoint.status
        ));
    }
    if endpoint.livemode != livemode {
        failures.push(format!(
            "endpoint livemode is {}, but billing's key is {}",
            endpoint.livemode,
            if livemode { "live" } else { "test" }
        ));
    }
    if endpoint.api_version.as_deref() != Some(api_version) {
        failures.push(format!(
            "endpoint api_version is {:?}, billing's Stripe SDK expects {api_version:?}",
            endpoint.api_version
        ));
    }
    let missing: Vec<&str> = HANDLED_EVENT_TYPES
        .into_iter()
        .filter(|event| !endpoint.enabled_events.iter().any(|e| e == event))
        .collect();
    if !missing.is_empty() {
        failures.push(format!(
            "endpoint is not subscribed to {}",
            missing.join(", ")
        ));
    }
    let mut unexpected: Vec<&str> = endpoint
        .enabled_events
        .iter()
        .map(String::as_str)
        .filter(|event| !HANDLED_EVENT_TYPES.contains(event) && *event != DELIVERY_SENTINEL_EVENT)
        .collect();
    unexpected.sort_unstable();
    if !unexpected.is_empty() {
        failures.push(format!(
            "endpoint is subscribed to unexpected {}",
            unexpected.join(", ")
        ));
    }
    (Some(endpoint.id.clone()), failures)
}

/// Runs one check, records it and returns the report.
pub async fn run_once(stripe: &StripeHandle, url: &str) -> Report {
    let report = match stripe.list_webhook_endpoints().await {
        Ok(endpoints) => {
            let api_version = stripe_shared::version::VERSION.as_str();
            let (endpoint, failures) = evaluate(&endpoints, url, stripe.is_live(), api_version);
            let status = if failures.is_empty() {
                healthy_gauge().set(1);
                Status::Ok
            } else {
                healthy_gauge().set(0);
                tracing::error!(
                    url,
                    endpoint = endpoint.as_deref().unwrap_or(""),
                    failures = %failures.join("; "),
                    "billing: Stripe webhook endpoint check failed"
                );
                Status::Degraded
            };
            Report {
                endpoint,
                failures,
                ..Report::new(status, Some(url))
            }
        }
        Err(error) => {
            // An unreachable Stripe says nothing about the endpoint, so the
            // last completed result stands in the metric.
            tracing::warn!(error = %error, "billing: Stripe webhook endpoint check could not list endpoints");
            Report::new(Status::Unknown, Some(url))
        }
    };
    publish(&report);
    report
}

/// Starts the check: once now, then hourly. `url` is [`webhook_url`]'s.
pub fn spawn(stripe: StripeHandle, url: Option<String>) {
    let url = match url {
        Some(url) if stripe.is_configured() => url,
        _ => {
            tracing::info!("billing: Stripe webhook endpoint check disabled");
            publish(&Report::new(Status::Disabled, url.as_deref()));
            return;
        }
    };
    publish(&Report::new(Status::Unknown, Some(&url)));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            run_once(&stripe, &url).await;
        }
    });
}

/// The latest report. Always 200: this is a report, not a probe.
pub async fn status() -> Json<Report> {
    let latest = LATEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    Json(latest.unwrap_or_else(|| Report::new(Status::Disabled, None)))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::Router;
    use axum::extract::RawQuery;
    use axum::routing::get;
    use stripe_shared::event::EventType;

    use super::*;

    const URL: &str = "https://codewire.sh/api/webhooks/stripe";
    const VERSION: &str = "2026-04-22.dahlia";

    fn endpoint(overrides: impl FnOnce(&mut WebhookEndpoint)) -> WebhookEndpoint {
        let mut endpoint = WebhookEndpoint {
            id: "we_synthetic".into(),
            url: URL.into(),
            status: "enabled".into(),
            livemode: true,
            api_version: Some(VERSION.into()),
            enabled_events: HANDLED_EVENT_TYPES.map(str::to_owned).to_vec(),
        };
        overrides(&mut endpoint);
        endpoint
    }

    fn failures(endpoints: &[WebhookEndpoint]) -> Vec<String> {
        evaluate(endpoints, URL, true, VERSION).1
    }

    fn assert_fails(endpoints: &[WebhookEndpoint], fragment: &str) {
        let failures = failures(endpoints);
        assert!(
            failures.iter().any(|f| f.contains(fragment)),
            "{fragment:?} not in {failures:?}"
        );
    }

    #[test]
    fn handled_event_types_are_stripe_event_types() {
        for name in HANDLED_EVENT_TYPES {
            let parsed = EventType::from_str(name).unwrap();
            assert!(!matches!(parsed, EventType::Unknown(_)), "{name}");
        }
    }

    #[test]
    fn matching_endpoint_passes() {
        let (endpoint_id, failures) = evaluate(&[endpoint(|_| {})], URL, true, VERSION);
        assert_eq!(endpoint_id.as_deref(), Some("we_synthetic"));
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn every_mismatch_is_reported() {
        assert_fails(
            &[endpoint(|e| {
                e.url = "https://other.test/api/webhooks/stripe".into()
            })],
            "found 0",
        );
        assert_fails(
            &[endpoint(|_| {}), endpoint(|e| e.id = "we_other".into())],
            "found 2",
        );
        assert_fails(
            &[endpoint(|e| e.status = "disabled".into())],
            "not \"enabled\"",
        );
        assert_fails(&[endpoint(|e| e.livemode = false)], "billing's key is live");
        assert_fails(
            &[endpoint(|e| {
                e.api_version = Some("2026-01-28.clover".into())
            })],
            "billing's Stripe SDK expects",
        );
        assert_fails(&[endpoint(|e| e.api_version = None)], "api_version is None");
        assert_fails(
            &[endpoint(|e| {
                e.enabled_events.retain(|event| event != "invoice.paid")
            })],
            "not subscribed to invoice.paid",
        );
        assert_fails(
            &[endpoint(|e| {
                e.enabled_events.push("charge.succeeded".into())
            })],
            "unexpected charge.succeeded",
        );
        assert_fails(
            &[endpoint(|e| e.enabled_events = vec!["*".into()])],
            "unexpected *",
        );
    }

    #[test]
    fn the_delivery_sentinel_event_is_the_one_extra_allowed() {
        let with_sentinel = endpoint(|e| e.enabled_events.push(DELIVERY_SENTINEL_EVENT.into()));
        assert!(failures(&[with_sentinel]).is_empty());
        assert!(!HANDLED_EVENT_TYPES.contains(&DELIVERY_SENTINEL_EVENT));
        // Anything else beside it is still unexpected.
        assert_fails(
            &[endpoint(|e| {
                e.enabled_events.push(DELIVERY_SENTINEL_EVENT.into());
                e.enabled_events.push("charge.succeeded".into());
            })],
            "unexpected charge.succeeded",
        );
    }

    #[test]
    fn the_sdk_api_version_is_the_one_billing_checks() {
        assert_eq!(stripe_shared::version::VERSION.as_str(), VERSION);
    }

    #[test]
    fn webhook_url_defaults_to_the_frontend_origin_and_can_be_disabled() {
        let frontend = FrontendOrigin::parse("https://codewire.sh/app").unwrap();
        assert_eq!(webhook_url(None, &frontend).as_deref(), Some(URL));
        assert_eq!(webhook_url(Some(" "), &frontend).as_deref(), Some(URL));
        assert_eq!(webhook_url(Some("off"), &frontend), None);
        assert_eq!(
            webhook_url(Some("https://billing.example.test/hook"), &frontend).as_deref(),
            Some("https://billing.example.test/hook")
        );
    }

    /// A Stripe API that answers the webhook-endpoint list with `body`.
    async fn fake_stripe(body: &'static str) -> StripeHandle {
        let app = Router::new().route(
            "/v1/webhook_endpoints",
            get(move |RawQuery(query): RawQuery| async move {
                assert_eq!(query.as_deref(), Some("limit=100"));
                ([("content-type", "application/json")], body)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        StripeHandle::for_test(&format!("http://{address}"))
    }

    #[tokio::test]
    async fn run_once_reads_the_stripe_list_and_reports() {
        // A test-mode key, so the endpoint must be in test mode. Stripe's
        // other fields are ignored.
        let stripe = fake_stripe(
            r#"{"object":"list","url":"/v1/webhook_endpoints","has_more":false,"data":[
              {"id":"we_matching","object":"webhook_endpoint","url":"https://codewire.sh/api/webhooks/stripe",
               "status":"enabled","livemode":false,"api_version":"2026-04-22.dahlia","created":1,
               "metadata":{},"description":null,"application":null,
               "enabled_events":["checkout.session.completed","customer.subscription.updated",
                 "customer.subscription.deleted","customer.subscription.trial_will_end",
                 "invoice.created","invoice.paid","invoice.payment_failed","invoice.finalized"]},
              {"id":"we_elsewhere","object":"webhook_endpoint","url":"https://elsewhere.test/hook",
               "status":"disabled","livemode":false,"api_version":null,"enabled_events":["*"]}]}"#,
        )
        .await;
        let report = run_once(&stripe, URL).await;
        assert_eq!(report.status, Status::Ok, "{report:?}");
        assert_eq!(report.endpoint.as_deref(), Some("we_matching"));

        let report = run_once(&stripe, "https://missing.test/api/webhooks/stripe").await;
        assert_eq!(report.status, Status::Degraded);
        assert_eq!(
            report.failures,
            ["expected exactly one endpoint for the URL, found 0"]
        );
    }

    #[tokio::test]
    async fn more_than_one_page_or_an_unreachable_stripe_is_unknown() {
        let stripe = fake_stripe(r#"{"object":"list","has_more":true,"data":[]}"#).await;
        assert_eq!(run_once(&stripe, URL).await.status, Status::Unknown);
        let unreachable = StripeHandle::for_test("http://127.0.0.1:1");
        assert_eq!(run_once(&unreachable, URL).await.status, Status::Unknown);
    }
}
