//! Billing proves its Stripe webhook delivery end to end (#3263 item 4).
//!
//! The endpoint check ([`crate::stripe_endpoint_check`]) proves the endpoint
//! is configured; this proves Stripe's deliveries arrive and pass signature
//! verification with the secret billing holds. Once a day, on the billing
//! leader:
//!
//! 1. **sentinel:** find the one customer marked
//!    `metadata.codewire_sentinel = delivery`;
//! 2. **touch:** set its `codewire_probe` metadata, which Stripe answers with
//!    a `customer.updated` event and no charge;
//! 3. **delivery:** within [`DELIVERY_WAIT`], see a `customer.updated` row in
//!    `stripe_webhook_events` recorded after the touch: billing records an
//!    event only after verifying its signature;
//! 4. **forged:** post one event signed with a wrong secret to billing's own
//!    webhook route and get 400.
//!
//! A failure logs one ERROR line naming the sentinel and the step, sets
//! `codewire_billing_stripe_webhook_delivery_healthy` to 0 and reports
//! `degraded` at billing's internal `/healthz/stripe-webhook-delivery`. Like
//! the endpoint check it never touches readiness or liveness. With no
//! sentinel customer the check reports `disabled`: a deployment opts in by
//! creating one (infra's checked-in helper does, for Production).

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::Json;
use chrono::NaiveDateTime;
use prometheus::{IntGauge, register_int_gauge};
use serde::Serialize;
use sqlx::PgPool;

use crate::stripe_client::StripeHandle;
use crate::stripe_endpoint_check::DELIVERY_SENTINEL_EVENT;

/// How often the leader runs the check.
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after start the first check runs, so a deploy that restarts
/// billing every day still gets one.
pub const FIRST_RUN_AFTER: Duration = Duration::from_secs(10 * 60);
/// How long Stripe has to deliver the sentinel's event.
pub const DELIVERY_WAIT: Duration = Duration::from_secs(10 * 60);
const POLL: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Stripe delivered, and a forged event was refused.
    Ok,
    /// A step failed; `step` names it.
    Degraded,
    /// No check has completed: the first is pending or Stripe could not be
    /// reached.
    Unknown,
    /// Stripe is not configured, or no sentinel customer exists.
    Disabled,
}

/// The step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    Sentinel,
    Touch,
    Delivery,
    Forged,
}

impl Step {
    /// The name the report and the ERROR line give the step.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sentinel => "sentinel",
            Self::Touch => "touch",
            Self::Delivery => "delivery",
            Self::Forged => "forged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub status: Status,
    pub sentinel: Option<String>,
    pub step: Option<Step>,
    pub failure: Option<String>,
}

impl Report {
    fn new(status: Status) -> Self {
        Self {
            status,
            sentinel: None,
            step: None,
            failure: None,
        }
    }

    fn degraded(sentinel: Option<&str>, step: Step, failure: String) -> Self {
        Self {
            status: Status::Degraded,
            sentinel: sentinel.map(str::to_owned),
            step: Some(step),
            failure: Some(failure),
        }
    }
}

static LATEST: Mutex<Option<Report>> = Mutex::new(None);

fn healthy_gauge() -> &'static IntGauge {
    static HEALTHY: OnceLock<IntGauge> = OnceLock::new();
    HEALTHY.get_or_init(|| {
        register_int_gauge!(
            "codewire_billing_stripe_webhook_delivery_healthy",
            "1 when the last completed check saw Stripe deliver the sentinel's event and a forged event refused, else 0"
        )
        .expect("register Stripe webhook delivery gauge")
    })
}

fn publish(report: &Report) {
    match report.status {
        Status::Ok => healthy_gauge().set(1),
        Status::Degraded => healthy_gauge().set(0),
        // The last completed result stands.
        Status::Unknown | Status::Disabled => {}
    }
    *LATEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(report.clone());
}

/// Whether a sentinel event reached billing's webhook after `since`, a
/// database time from the same clock that stamps the rows.
pub async fn delivered_since(pool: &PgPool, since: NaiveDateTime) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM stripe_webhook_events \
          WHERE event_type = $1 AND processed_at >= $2)",
    )
    .bind(DELIVERY_SENTINEL_EVENT)
    .bind(since)
    .fetch_one(pool)
    .await
}

/// Posts one event signed with a wrong secret to `webhook_url`; `Ok` with
/// the status code. Billing must answer 400 without recording it.
pub async fn post_forged_event(webhook_url: &str) -> Result<u16, reqwest::Error> {
    let timestamp = chrono::Utc::now().timestamp();
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .post(webhook_url)
        .header("content-type", "application/json")
        .header(
            "stripe-signature",
            format!("t={timestamp},v1={}", "0".repeat(64)),
        )
        .body(format!(
            r#"{{"id":"evt_codewire_forged_probe","object":"event","type":"{DELIVERY_SENTINEL_EVENT}","created":{timestamp},"data":{{"object":{{}}}}}}"#
        ))
        .send()
        .await?;
    Ok(response.status().as_u16())
}

/// Runs the check once, records it and returns the report.
pub async fn run_once(stripe: &StripeHandle, pool: &PgPool, webhook_url: &str) -> Report {
    let report = check(stripe, pool, webhook_url).await;
    match report.status {
        Status::Degraded => tracing::error!(
            sentinel = report.sentinel.as_deref().unwrap_or(""),
            step = report.step.map_or("", Step::name),
            failure = report.failure.as_deref().unwrap_or(""),
            "billing: Stripe webhook delivery check failed"
        ),
        Status::Ok => tracing::info!(
            sentinel = report.sentinel.as_deref().unwrap_or(""),
            "billing: Stripe webhook delivery check passed"
        ),
        Status::Unknown | Status::Disabled => {}
    }
    publish(&report);
    report
}

async fn check(stripe: &StripeHandle, pool: &PgPool, webhook_url: &str) -> Report {
    let sentinels = match stripe.delivery_sentinels().await {
        Ok(sentinels) => sentinels,
        Err(error) => {
            tracing::warn!(error = %error, "billing: Stripe webhook delivery check could not search customers");
            return Report::new(Status::Unknown);
        }
    };
    let sentinel = match sentinels.as_slice() {
        [] => return Report::new(Status::Disabled),
        [one] => one.clone(),
        _ => {
            return Report::degraded(
                None,
                Step::Sentinel,
                "more than one customer is marked codewire_sentinel=delivery".into(),
            );
        }
    };
    let since: NaiveDateTime = match sqlx::query_scalar("SELECT now()::timestamp")
        .fetch_one(pool)
        .await
    {
        Ok(now) => now,
        Err(error) => {
            tracing::warn!(error = %error, "billing: Stripe webhook delivery check could not read the database clock");
            return Report::new(Status::Unknown);
        }
    };
    let probe = uuid::Uuid::new_v4().to_string();
    if let Err(error) = stripe.touch_delivery_sentinel(&sentinel, &probe).await {
        return Report::degraded(Some(&sentinel), Step::Touch, error.to_string());
    }
    let deadline = tokio::time::Instant::now() + DELIVERY_WAIT;
    loop {
        match delivered_since(pool, since).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(error = %error, "billing: Stripe webhook delivery check could not read deliveries");
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Report::degraded(
                Some(&sentinel),
                Step::Delivery,
                format!(
                    "no {DELIVERY_SENTINEL_EVENT} delivery recorded within {}s of the touch",
                    DELIVERY_WAIT.as_secs()
                ),
            );
        }
        tokio::time::sleep(POLL).await;
    }
    match post_forged_event(webhook_url).await {
        Ok(400) => Report {
            sentinel: Some(sentinel),
            ..Report::new(Status::Ok)
        },
        Ok(status) => Report::degraded(
            Some(&sentinel),
            Step::Forged,
            format!("a wrongly signed event got {status}, not 400"),
        ),
        Err(error) => Report::degraded(Some(&sentinel), Step::Forged, error.to_string()),
    }
}

/// The latest report. Always 200: this is a report, not a probe.
pub async fn status() -> Json<Report> {
    let latest = LATEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    Json(latest.unwrap_or_else(|| Report::new(Status::Unknown)))
}

#[cfg(test)]
mod tests;
