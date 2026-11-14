use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
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

/// `delivered_since`, narrowed to this test's rows: other tests may record
/// sentinel events too.
async fn seen(pool: &PgPool, since: NaiveDateTime, prefix: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM stripe_webhook_events \
          WHERE event_type = $1 AND processed_at >= $2 AND id LIKE $3)",
    )
    .bind(DELIVERY_SENTINEL_EVENT)
    .bind(since)
    .bind(format!("{prefix}%"))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn db_only_a_sentinel_event_recorded_after_the_touch_counts() {
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
    assert!(!seen(&pool, since, &prefix).await);

    record(
        &pool,
        &format!("{prefix}_after"),
        DELIVERY_SENTINEL_EVENT,
        0.0,
    )
    .await;
    assert!(seen(&pool, since, &prefix).await);
    assert!(delivered_since(&pool, since).await.unwrap());

    sqlx::query("DELETE FROM stripe_webhook_events WHERE id LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await
        .unwrap();
}
