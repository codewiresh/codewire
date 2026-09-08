//! Tracing and observability setup.
//!
//! Each service calls [`init`] once at startup. By default:
//!
//! - `tracing-subscriber` emits JSON logs to stdout (production-friendly,
//!   kubectl-pipe-able).
//! - Log level comes from `RUST_LOG` (default `info`).
//!
//! With the `otel` feature enabled and `OTEL_EXPORTER_OTLP_ENDPOINT` set,
//! spans are additionally exported via OTLP — giving Rust services
//! distributed tracing the Go services don't currently have. That's the
//! main reason the OTel deps live in this crate: any future port lights
//! up traces for free.

use crate::config::ServiceConfig;

/// Initialize tracing for a service. Idempotent — repeated calls return
/// `Ok(())` after the first.
pub fn init(_cfg: &ServiceConfig) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(env_filter).with(
        fmt::layer()
            .json()
            .with_target(true)
            .with_current_span(false),
    );

    #[cfg(feature = "otel")]
    {
        use opentelemetry_otlp::WithExportConfig as _;

        if let Some(endpoint) = &_cfg.otlp_endpoint {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .build();
            let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, _cfg.name.clone());
            let otel = tracing_opentelemetry::OpenTelemetryLayer::new(tracer);
            subscriber.with(otel).try_init().ok();
            return Ok(());
        }
    }

    subscriber.try_init().ok();
    Ok(())
}
