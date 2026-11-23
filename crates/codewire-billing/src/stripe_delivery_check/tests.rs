use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;

use super::*;

/// Serves `answer` on a local port and keeps the signature header it saw.
async fn webhook_answering(answer: StatusCode) -> (String, Arc<Mutex<Option<String>>>) {
    let seen = Arc::new(Mutex::new(None));
    let kept = seen.clone();
    let app = axum::Router::new().route(
        "/api/webhooks/stripe",
        post(move |headers: HeaderMap| {
            let kept = kept.clone();
            async move {
                *kept.lock().unwrap() = headers
                    .get("stripe-signature")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                answer
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}/api/webhooks/stripe"), seen)
}

#[tokio::test]
async fn a_forged_event_carries_a_wrong_signature_and_reports_the_answer() {
    let (url, seen) = webhook_answering(StatusCode::BAD_REQUEST).await;
    assert_eq!(post_forged_event(&url).await.unwrap(), 400);
    let signature = seen.lock().unwrap().clone().unwrap();
    let (timestamp, digest) = signature.split_once(",v1=").unwrap();
    assert!(timestamp.starts_with("t=") && timestamp[2..].parse::<i64>().is_ok());
    assert_eq!(digest, "0".repeat(64));

    // A route that accepts it is reported as it answered.
    let (url, _) = webhook_answering(StatusCode::OK).await;
    assert_eq!(post_forged_event(&url).await.unwrap(), 200);
}

#[test]
fn a_report_names_its_status_and_step_in_lowercase() {
    let report = Report::degraded(Some("cus_sentinel"), Step::Delivery, "late".into());
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::json!({
            "status": "degraded", "sentinel": "cus_sentinel",
            "step": "delivery", "failure": "late"
        })
    );
    // The ERROR line, which infra's alert reads, names steps the same way.
    for step in [Step::Sentinel, Step::Touch, Step::Delivery, Step::Forged] {
        assert_eq!(serde_json::to_value(step).unwrap(), step.name());
    }
}

async fn record(pool: &PgPool, id: &str, event_type: &str, ago_seconds: f64) {
    sqlx::query(
        "INSERT INTO stripe_webhook_events (id, event_type, processed_at) \
         VALUES ($1, $2, now()::timestamp - make_interval(secs => $3))",
    )
    .bind(id)
    .bind(event_type)
    .bind(ago_seconds)
    .execute(pool)
    .await
    .unwrap();
}

/// `customer_updates_since`, narrowed to this test's rows: other tests may
/// record customer events too.
async fn seen(pool: &PgPool, since: NaiveDateTime, prefix: &str) -> Vec<String> {
    customer_updates_since(pool, since)
        .await
        .unwrap()
        .into_iter()
        .filter(|id| id.starts_with(prefix))
        .collect()
}

#[tokio::test]
async fn db_only_customer_events_recorded_after_the_touch_are_read_back() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset; skipping the delivery check database flow");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let prefix = format!("evt_delivery_test_{}", uuid::Uuid::new_v4().simple());

    // Rows from before the touch, and another type after it, do not count.
    record(
        &pool,
        &format!("{prefix}_before"),
        DELIVERY_SENTINEL_EVENT,
        600.0,
    )
    .await;
    record(&pool, &format!("{prefix}_other"), "invoice.paid", 0.0).await;
    let since: NaiveDateTime =
        sqlx::query_scalar("SELECT now()::timestamp - interval '60 seconds'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(seen(&pool, since, &prefix).await.is_empty());

    record(
        &pool,
        &format!("{prefix}_after"),
        DELIVERY_SENTINEL_EVENT,
        0.0,
    )
    .await;
    assert_eq!(
        seen(&pool, since, &prefix).await,
        [format!("{prefix}_after")]
    );

    sqlx::query("DELETE FROM stripe_webhook_events WHERE id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await
        .unwrap();
}

#[test]
fn only_the_sentinel_carrying_this_runs_probe_is_the_touch() {
    assert!(is_this_touch(
        "cus_sentinel",
        Some("probe-1"),
        "cus_sentinel",
        "probe-1"
    ));
    // Another customer's update in the same minutes, even with the same
    // metadata, proves nothing about the sentinel's round trip (#4862).
    assert!(!is_this_touch(
        "cus_other",
        Some("probe-1"),
        "cus_sentinel",
        "probe-1"
    ));
    // The sentinel's update from an earlier run, or one without a probe.
    assert!(!is_this_touch(
        "cus_sentinel",
        Some("probe-0"),
        "cus_sentinel",
        "probe-1"
    ));
    assert!(!is_this_touch(
        "cus_sentinel",
        None,
        "cus_sentinel",
        "probe-1"
    ));
}

/// Serves Stripe's event retrieval for one event about `customer`; any other
/// path is not found.
async fn stripe_with_event(
    event_id: &'static str,
    customer: &'static str,
    probe: &'static str,
) -> String {
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| async move {
        if uri.path() != format!("/v1/events/{event_id}") {
            return StatusCode::NOT_FOUND.into_response();
        }
        axum::Json(serde_json::json!({
            "id": event_id, "object": "event", "type": DELIVERY_SENTINEL_EVENT,
            "data": {"object": {"id": customer, "object": "customer",
                                "metadata": {"codewire_probe": probe, "codewire_sentinel": "delivery"}}}
        }))
        .into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

#[tokio::test]
async fn a_recorded_event_is_read_back_as_its_customer_and_probe() {
    let stripe =
        StripeHandle::for_test(&stripe_with_event("evt_other_1", "cus_other", "probe-1").await);
    let (customer, probe) = stripe.customer_event_probe("evt_other_1").await.unwrap();
    assert_eq!(
        (customer.as_str(), probe.as_deref()),
        ("cus_other", Some("probe-1"))
    );
    assert!(!is_this_touch(
        &customer,
        probe.as_deref(),
        "cus_sentinel",
        "probe-1"
    ));

    // An id that would change the request's path is refused before any call.
    for id in ["", "evt_1/../customers", "evt 1", "evt_1?expand=x"] {
        assert!(stripe.customer_event_probe(id).await.is_err(), "{id:?}");
    }
}
