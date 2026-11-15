//! Bounded Prometheus exposition shared by Rust control-plane services.
//!
//! Deployment Services expose this endpoint to Prometheus; no dedicated
//! ingress route is added. Its registry is deliberately bounded: metric
//! labels are finite operational categories, and customer, environment,
//! session, and secret identifiers never belong here.

use axum::{Router, http::header, response::IntoResponse, routing::get};
use prometheus::{
    Encoder, IntGaugeVec, Opts, TextEncoder, register_int_counter_vec, register_int_gauge_vec,
};
use std::sync::OnceLock;

static SERVICE_INFO: OnceLock<IntGaugeVec> = OnceLock::new();
static RATE_LIMIT_REFUSALS: OnceLock<IntCounterVec> = OnceLock::new();

/// The counter types a service registers through [`counter`] and
/// [`counter_vec`], so a crate needs no Prometheus dependency of its own.
pub use prometheus::{IntCounter, IntCounterVec};

/// Registers a counter in the shared registry this module serves. Panics on a
/// duplicate name, which is a programming error caught by the first test.
pub fn counter(name: &str, help: &str) -> IntCounter {
    prometheus::register_int_counter!(name, help)
        .unwrap_or_else(|error| panic!("metric {name} must register once: {error}"))
}

/// Registers a counter with `labels`, which must be finite categories.
pub fn counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    register_int_counter_vec!(Opts::new(name, help), labels)
        .unwrap_or_else(|error| panic!("metric {name} must register once: {error}"))
}

/// Requests a named rate limit refused (#3297), by the limit's name only, a
/// finite set. Who was refused is in the service's warn line, never a label.
pub fn rate_limit_refusals() -> &'static IntCounterVec {
    RATE_LIMIT_REFUSALS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_rate_limit_refusals_total",
                "Requests refused by a named rate limit."
            ),
            &["limit"]
        )
        .expect("rate limit refusal metric registration must be unique")
    })
}
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Returns a router exposing the process-local Prometheus registry.
pub fn router(service_name: &str) -> Router {
    let info = SERVICE_INFO.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_control_plane_service_info",
                "Static identity of a Codewire control-plane process."
            ),
            &["service"]
        )
        .expect("control-plane service metric registration must be unique")
    });
    info.with_label_values(&[service_name]).set(1);
    Router::new().route("/metrics", get(render))
}

async fn render() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let mut body = Vec::new();
    if let Err(error) = encoder.encode(&prometheus::gather(), &mut body) {
        tracing::error!(?error, "failed to encode Prometheus metrics");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
            Vec::new(),
        );
    }
    (
        axum::http::StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}
