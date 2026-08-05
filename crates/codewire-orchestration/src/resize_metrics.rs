//! Bounded Prometheus telemetry for durable environment resize operations.
//!
//! The process-local counters intentionally record a terminal operation only
//! after its durable state transition commits. Active gauges are refreshed
//! from Postgres, so a worker retry or process restart cannot leave a stale
//! in-memory view of pending work behind.

use std::sync::OnceLock;
use std::time::Duration;

use chrono::NaiveDateTime;
use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    register_histogram_vec, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};
use sqlx::PgPool;

use crate::api::environment_resize::EnvironmentResizeExecutionMode;

const ACTIVE_STATES: [&str; 3] = ["pending", "applying", "restarting"];
const ACTIVE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

static REQUESTS: OnceLock<IntCounterVec> = OnceLock::new();
static TERMINAL_OPERATIONS: OnceLock<IntCounterVec> = OnceLock::new();
static TERMINAL_DURATIONS: OnceLock<HistogramVec> = OnceLock::new();
static ACTIVE_OPERATIONS: OnceLock<IntGaugeVec> = OnceLock::new();
static OLDEST_ACTIVE_SECONDS: OnceLock<IntGauge> = OnceLock::new();
static FAILURES: OnceLock<IntCounterVec> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    Accepted,
    Idempotent,
    Rejected,
}

impl RequestOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Idempotent => "idempotent",
            Self::Rejected => "rejected",
        }
    }
}

fn requests_metric() -> &'static IntCounterVec {
    REQUESTS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_environment_resize_requests_total",
                "Environment resize requests by closed admission outcome."
            ),
            &["outcome"]
        )
        .expect("environment resize request metric registration must be unique")
    })
}

fn terminal_operations_metric() -> &'static IntCounterVec {
    TERMINAL_OPERATIONS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_environment_resize_operations_total",
                "Terminal environment resize operations by state and execution mode."
            ),
            &["state", "execution_mode"]
        )
        .expect("environment resize terminal metric registration must be unique")
    })
}

fn terminal_durations_metric() -> &'static HistogramVec {
    TERMINAL_DURATIONS.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "codewire_environment_resize_operation_duration_seconds",
                "Elapsed time from durable resize admission to terminal state."
            ),
            &["state", "execution_mode"]
        )
        .expect("environment resize duration metric registration must be unique")
    })
}

fn active_operations_metric() -> &'static IntGaugeVec {
    ACTIVE_OPERATIONS.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_environment_resize_active_operations",
                "Current durable environment resize operations by active state."
            ),
            &["state"]
        )
        .expect("environment resize active metric registration must be unique")
    })
}

fn oldest_active_seconds_metric() -> &'static IntGauge {
    OLDEST_ACTIVE_SECONDS.get_or_init(|| {
        register_int_gauge!(
            "codewire_environment_resize_oldest_active_seconds",
            "Age in seconds of the oldest active durable environment resize operation."
        )
        .expect("environment resize oldest-active metric registration must be unique")
    })
}

fn failures_metric() -> &'static IntCounterVec {
    FAILURES.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_environment_resize_failures_total",
                "Terminal environment resize failures by closed reason classifier."
            ),
            &["reason"]
        )
        .expect("environment resize failure metric registration must be unique")
    })
}

pub fn record_request(outcome: RequestOutcome) {
    requests_metric()
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Records a terminal state only after the durable transaction which made it
/// terminal has committed. `mode` is the applied execution mode for a
/// completed operation and the planned mode for a failure that did not reach
/// an applied mode.
fn record_terminal(
    state: &'static str,
    mode: EnvironmentResizeExecutionMode,
    created_at: NaiveDateTime,
    completed_at: NaiveDateTime,
) {
    let execution_mode = mode.as_str();
    terminal_operations_metric()
        .with_label_values(&[state, execution_mode])
        .inc();
    let duration = completed_at
        .signed_duration_since(created_at)
        .num_milliseconds()
        .max(0) as f64
        / 1_000.0;
    terminal_durations_metric()
        .with_label_values(&[state, execution_mode])
        .observe(duration);
}

/// Records a terminal observation only when the durable update returned the
/// transition that this process committed. A retry sees no returned row and
/// cannot duplicate the counter or histogram sample.
pub fn record_terminal_after_commit(
    state: &'static str,
    mode: EnvironmentResizeExecutionMode,
    transition: Option<(NaiveDateTime, NaiveDateTime)>,
) {
    let Some((created_at, completed_at)) = transition else {
        return;
    };
    record_terminal(state, mode, created_at, completed_at);
}

pub fn record_failure(code: &str) {
    failures_metric()
        .with_label_values(&[failure_reason(code)])
        .inc();
}

/// Keeps the label set closed even if a future caller supplies a new durable
/// failure code before the telemetry contract is updated.
fn failure_reason(code: &str) -> &'static str {
    match code {
        "active_sessions" => "active_sessions",
        "restart_consent_required" => "restart_consent_required",
        "runtime_apply_failed" => "runtime_apply_failed",
        _ => "other",
    }
}

/// Refresh active-operation gauges from the durable source of truth.
pub async fn refresh_active(pool: &PgPool) -> anyhow::Result<()> {
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT state, COUNT(*)::bigint
           FROM environment_resize_operations
          WHERE state = ANY($1)
          GROUP BY state",
    )
    .bind(&ACTIVE_STATES[..])
    .fetch_all(pool)
    .await?;
    let oldest: Option<f64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM NOW() - MIN(created_at))::float8
           FROM environment_resize_operations
          WHERE state = ANY($1)",
    )
    .bind(&ACTIVE_STATES[..])
    .fetch_one(pool)
    .await?;

    apply_active_snapshot(&counts, oldest);
    Ok(())
}

/// Starts the per-process active gauge refresher. Every instance reads the
/// same durable rows; no leader election is needed for this read-only work.
pub fn start_active_refresh(pool: PgPool) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = refresh_active(&pool).await {
                tracing::warn!(error = %error, "resize metrics: refresh active operations");
            }
            tokio::time::sleep(ACTIVE_REFRESH_INTERVAL).await;
        }
    });
}

/// Refresh failures are intentionally non-fatal: telemetry must never change
/// the result of a resize admission or worker transition.
pub async fn refresh_active_best_effort(pool: &PgPool) {
    if let Err(error) = refresh_active(pool).await {
        tracing::warn!(error = %error, "resize metrics: refresh active operations");
    }
}

fn apply_active_snapshot(counts: &[(String, i64)], oldest_seconds: Option<f64>) {
    for state in ACTIVE_STATES {
        active_operations_metric()
            .with_label_values(&[state])
            .set(0);
    }
    for (state, count) in counts {
        if ACTIVE_STATES.contains(&state.as_str()) {
            active_operations_metric()
                .with_label_values(&[state])
                .set((*count).max(0));
        }
    }
    oldest_active_seconds_metric().set(oldest_seconds.unwrap_or_default().max(0.0) as i64);
}

#[cfg(test)]
mod tests {
    use prometheus::{Encoder, TextEncoder};

    use super::*;

    fn terminal_count(state: &str, mode: &str) -> u64 {
        terminal_operations_metric()
            .get_metric_with_label_values(&[state, mode])
            .unwrap()
            .get()
    }

    #[test]
    fn registers_closed_metric_labels_and_renders_them() {
        record_request(RequestOutcome::Accepted);
        record_request(RequestOutcome::Idempotent);
        record_request(RequestOutcome::Rejected);
        record_failure("unrecognized_failure_code");
        assert_eq!(failure_reason("unrecognized_failure_code"), "other");

        let mut rendered = Vec::new();
        TextEncoder::new()
            .encode(&prometheus::gather(), &mut rendered)
            .unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("codewire_environment_resize_requests_total"));
        assert!(rendered.contains("outcome=\"accepted\""));
        assert!(rendered.contains("codewire_environment_resize_failures_total"));
        assert!(rendered.contains("reason=\"other\""));
    }

    #[test]
    fn terminal_accounting_only_advances_for_a_committed_transition() {
        let before = terminal_count("completed", "in_place");
        let created_at = chrono::DateTime::from_timestamp(1_000, 0)
            .unwrap()
            .naive_utc();
        let completed_at = chrono::DateTime::from_timestamp(1_005, 0)
            .unwrap()
            .naive_utc();
        record_terminal_after_commit(
            "completed",
            EnvironmentResizeExecutionMode::InPlace,
            Some((created_at, completed_at)),
        );
        // A Temporal retry sees no changed durable row.
        record_terminal_after_commit("completed", EnvironmentResizeExecutionMode::InPlace, None);
        assert_eq!(terminal_count("completed", "in_place"), before + 1);
    }

    #[test]
    fn durable_active_snapshot_replaces_stale_process_state_after_retry_or_restart() {
        apply_active_snapshot(
            &[("pending".into(), 2), ("restarting".into(), 1)],
            Some(45.9),
        );
        assert_eq!(
            active_operations_metric()
                .get_metric_with_label_values(&["pending"])
                .unwrap()
                .get(),
            2
        );
        assert_eq!(oldest_active_seconds_metric().get(), 45);

        apply_active_snapshot(&[], None);
        assert_eq!(
            active_operations_metric()
                .get_metric_with_label_values(&["pending"])
                .unwrap()
                .get(),
            0
        );
        assert_eq!(oldest_active_seconds_metric().get(), 0);
    }
}
