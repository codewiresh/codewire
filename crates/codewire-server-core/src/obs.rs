//! Tracing and observability setup.
//!
//! Each service calls one initializer once at startup:
//!
//! - [`init`]: JSON logs to stdout (production-friendly, kubectl-pipe-able),
//!   level from `RUST_LOG` (default `info`). It never exports traces.
//! - [`init_with_traces`]: the same JSON logs and, with the `otel` feature
//!   compiled in and `OTEL_EXPORTER_OTLP_ENDPOINT` set, OpenTelemetry spans
//!   exported over OTLP/gRPC. Trace export is a per-service opt-in in code:
//!   the shared services image compiles the feature into every binary, and a
//!   service that calls [`init`] stays log-only whatever its environment says.
//! - [`init_traces_only`]: trace export without a log layer, for a server that
//!   has never written logs (the dashboard).
//!
//! When trace export is on, the standard `OTEL_TRACES_SAMPLER` and
//! `OTEL_TRACES_SAMPLER_ARG` choose the sampler (default
//! `parentbased_always_on`), `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`
//! override the resource, and the W3C TraceContext propagator is installed.
//! The exported span set is narrow and fixed:
//!
//! - spans from Codewire crates (`codewire_*` targets) at `DEBUG` and above,
//!   which stay out of the logs at the default `RUST_LOG=info`;
//! - Kubernetes API calls (kube-client's own `HTTP` client span), only as
//!   children of a Codewire span;
//! - one synthetic client span per Postgres statement (from sqlx's statement
//!   event), only as a child of a Codewire span. It carries sqlx's
//!   four-word statement summary, the row counts and the duration, never the
//!   statement text or a bound value.
//!
//! No log event becomes a span event, and URL-valued attributes lose their
//! query string before export. Span attributes never carry a secret, a token
//! or user content: instrumented functions record identifiers such as
//! `environment_id` only.
//!
//! Without an endpoint (or without the feature) nothing is installed beyond
//! the log layer, and the `DEBUG` spans are disabled at their callsites.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::ServiceConfig;

static EXPORT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether this process exports traces. False until an initializer installs
/// an exporter, and always false without the `otel` feature.
pub fn export_active() -> bool {
    EXPORT_ACTIVE.load(Ordering::Relaxed)
}

/// Initialize JSON logs for a service. Idempotent — repeated calls return
/// `Ok(())` after the first. Never exports traces; see [`init_with_traces`].
pub fn init(_cfg: &ServiceConfig) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(log_filter())
        .with(json_log_layer())
        .try_init()
        .ok();
    Ok(())
}

/// [`init`] plus OTLP trace export when the `otel` feature is compiled in and
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Logs one line saying whether export
/// is on. Keep the returned guard alive for the life of the process and call
/// [`TracingGuard::shutdown`] on the way out so queued spans are flushed.
pub fn init_with_traces(cfg: &ServiceConfig) -> anyhow::Result<TracingGuard> {
    init_service(&cfg.name, cfg.otlp_endpoint.as_deref(), true)
}

/// Trace export only, with no log layer: when `otlp_endpoint` is `None`
/// (or the feature is absent) this installs nothing at all.
pub fn init_traces_only(
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> anyhow::Result<TracingGuard> {
    init_service(service_name, otlp_endpoint, false)
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

fn json_log_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    json_log_layer_to(std::io::stdout)
}

fn json_log_layer_to<S, W>(writer: W) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::Layer as _;

    tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(false)
        .with_writer(writer)
        .with_filter(tracing_subscriber::filter::filter_fn(logged_span))
}

/// Keeps a library span whose fields hold request bodies out of every log
/// line's span list; its events still log. The Stripe SDK's `parse_payload`
/// span holds each webhook payload, customer details included (#3263).
fn logged_span(metadata: &tracing::Metadata<'_>) -> bool {
    !(metadata.is_span() && metadata.target().starts_with("stripe_webhook"))
}

fn init_service(
    service_name: &str,
    otlp_endpoint: Option<&str>,
    logs: bool,
) -> anyhow::Result<TracingGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let endpoint = otlp_endpoint.map(str::trim).filter(|e| !e.is_empty());

    #[cfg(feature = "otel")]
    if let Some(endpoint) = endpoint {
        use tracing_subscriber::Layer as _;

        let exporter = otel::Exporter::build(service_name, endpoint)?;
        let installed = tracing_subscriber::registry()
            .with(logs.then(|| json_log_layer().with_filter(log_filter())))
            .with(exporter.layers())
            .try_init()
            .is_ok();
        if !installed {
            // A subscriber was already installed; leave it and export nothing.
            exporter.discard();
            return Ok(TracingGuard::default());
        }
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        EXPORT_ACTIVE.store(true, Ordering::Relaxed);
        tracing::info!(
            service = service_name,
            otlp_export = true,
            endpoint = %display_endpoint(endpoint),
            "OpenTelemetry trace export is on"
        );
        return Ok(TracingGuard {
            provider: Some(exporter.into_provider()),
        });
    }

    if logs {
        tracing_subscriber::registry()
            .with(log_filter())
            .with(json_log_layer())
            .try_init()
            .ok();
        let reason = if cfg!(feature = "otel") {
            "OTEL_EXPORTER_OTLP_ENDPOINT is unset"
        } else {
            "this build has no otel feature"
        };
        tracing::info!(
            service = service_name,
            otlp_export = false,
            reason,
            "OpenTelemetry trace export is off"
        );
    }
    let _ = endpoint;
    Ok(TracingGuard::default())
}

/// The endpoint as it is safe to log: scheme, host and port only.
#[cfg(any(feature = "otel", test))]
fn display_endpoint(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            }
        }
        Err(_) => "<unparseable endpoint>".to_owned(),
    }
}

/// Owns the tracer provider. [`TracingGuard::shutdown`] flushes queued spans;
/// dropping the guard flushes too when that cannot stall the runtime.
#[derive(Default)]
#[must_use = "dropping the guard shuts trace export down"]
pub struct TracingGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TracingGuard {
    /// Whether this guard owns a live exporter.
    pub fn exporting(&self) -> bool {
        #[cfg(feature = "otel")]
        let exporting = self.provider.is_some();
        #[cfg(not(feature = "otel"))]
        let exporting = false;
        exporting
    }

    /// Flush queued spans and stop the exporter. The blocking shutdown runs
    /// on Tokio's blocking pool, so the exporter's own tasks keep running on
    /// either runtime flavour while it waits.
    pub async fn shutdown(self) {
        #[cfg(feature = "otel")]
        {
            let mut guard = self;
            if let Some(provider) = guard.provider.take() {
                EXPORT_ACTIVE.store(false, Ordering::Relaxed);
                let _ = tokio::task::spawn_blocking(move || provider.shutdown()).await;
            }
        }
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider.take() {
            EXPORT_ACTIVE.store(false, Ordering::Relaxed);
            // A current-thread runtime blocked here could not drive the
            // exporter's channel, so only a multi-thread runtime (or none)
            // waits for the flush; otherwise queued spans are dropped.
            let flavor = tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor());
            if !matches!(flavor, Ok(tokio::runtime::RuntimeFlavor::CurrentThread)) {
                let _ = std::thread::spawn(move || provider.shutdown()).join();
            }
        }
    }
}

/// W3C trace context carried inside a serialized message, such as a Temporal
/// signal or activity input, where no header map exists. Empty unless trace
/// export is on and the current span is traced; empty values serialize to
/// nothing, so payloads stay byte-identical while export is off.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
}

impl TraceContext {
    pub fn is_empty(&self) -> bool {
        self.traceparent.is_none() && self.tracestate.is_none()
    }

    /// The current span's context, or empty when nothing is traced.
    pub fn current() -> Self {
        #[cfg(feature = "otel")]
        if export_active() {
            use tracing_opentelemetry::OpenTelemetrySpanExt as _;
            let mut carrier = Self::default();
            otel::inject(&tracing::Span::current().context(), &mut carrier);
            return carrier;
        }
        Self::default()
    }

    /// Make this context the remote parent of `span`, which must not have
    /// been entered yet. A no-op when empty, malformed or not exporting.
    pub fn attach_to(&self, span: &tracing::Span) {
        if self.is_empty() {
            return;
        }
        #[cfg(feature = "otel")]
        if export_active() {
            otel::set_parent(span, self);
        }
        #[cfg(not(feature = "otel"))]
        let _ = span;
    }
}

/// Make the W3C context in `headers` the remote parent of `span`, which must
/// not have been entered yet. A no-op unless trace export is on.
pub fn attach_http_parent(span: &tracing::Span, headers: &http::HeaderMap) {
    #[cfg(feature = "otel")]
    if export_active() && headers.contains_key("traceparent") {
        otel::set_parent(span, &otel::HeaderCarrier(headers));
    }
    #[cfg(not(feature = "otel"))]
    let _ = (span, headers);
}

/// Write the current span's W3C context into outgoing request headers. A
/// no-op unless trace export is on.
pub fn inject_http_headers(headers: &mut http::HeaderMap) {
    #[cfg(feature = "otel")]
    if export_active() {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        otel::inject(
            &tracing::Span::current().context(),
            &mut otel::HeaderCarrierMut(headers),
        );
    }
    #[cfg(not(feature = "otel"))]
    let _ = headers;
}

/// Paths that never start a trace: probes and scrapes would otherwise be most
/// of every service's traces.
pub fn untraced_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/livez" | "/metrics")
}

#[cfg(feature = "otel")]
mod otel {
    use std::borrow::Cow;
    use std::time::{Duration, SystemTime};

    use opentelemetry::propagation::{Extractor, Injector};
    use opentelemetry::trace::{
        Link, SpanKind, TraceContextExt as _, TraceId, TraceState, Tracer as _,
    };
    use opentelemetry::{Context, Key, KeyValue, Value};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::trace::{
        BatchSpanProcessor, Config, SamplingDecision, SamplingResult, SdkTracer, SdkTracerProvider,
        ShouldSample, Span, SpanData, SpanProcessor,
    };
    use tracing::field::{Field, Visit};
    use tracing::{Level, Metadata, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::{LevelFilter, filter_fn};
    use tracing_subscriber::layer::Context as LayerContext;
    use tracing_subscriber::registry::LookupSpan;

    use super::TraceContext;

    const SCOPE: &str = "codewire";

    /// Longest accepted `traceparent` / `tracestate`, so a carrier never grows
    /// a payload beyond what W3C allows (`tracestate` caps at 32 members).
    const MAX_TRACEPARENT_LEN: usize = 55;
    const MAX_TRACESTATE_LEN: usize = 512;

    pub(super) struct Exporter {
        provider: SdkTracerProvider,
        tracer: SdkTracer,
    }

    impl Exporter {
        pub(super) fn build(service_name: &str, endpoint: &str) -> anyhow::Result<Self> {
            use opentelemetry_otlp::WithExportConfig as _;

            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            Ok(Self::with_processor(
                service_name,
                BatchSpanProcessor::builder(exporter).build(),
            ))
        }

        pub(super) fn with_processor(
            service_name: &str,
            processor: impl SpanProcessor + 'static,
        ) -> Self {
            use opentelemetry::trace::TracerProvider as _;

            let provider = SdkTracerProvider::builder()
                .with_span_processor(RedactUrlQueries(processor))
                .with_sampler(NoRootClientSpans(Config::default().sampler))
                .with_resource(resource(service_name))
                .build();
            let tracer = provider.tracer(SCOPE);
            Self { provider, tracer }
        }

        /// The span layer and the statement-span layer, each behind its own
        /// per-layer filter so the log layer's filter and output are
        /// unchanged.
        pub(super) fn layers<S>(&self) -> impl Layer<S> + use<S>
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            let spans = tracing_opentelemetry::layer()
                .with_tracer(self.tracer.clone())
                .with_filter(filter_fn(exported_span).with_max_level_hint(LevelFilter::DEBUG));
            let statements = StatementSpans {
                tracer: self.tracer.clone(),
            }
            .with_filter(filter_fn(statement_event).with_max_level_hint(LevelFilter::DEBUG));
            spans.and_then(statements)
        }

        #[cfg(test)]
        pub(super) fn provider(&self) -> &SdkTracerProvider {
            &self.provider
        }

        pub(super) fn into_provider(self) -> SdkTracerProvider {
            self.provider
        }

        pub(super) fn discard(self) {
            let _ = self.provider.shutdown();
        }
    }

    pub(super) fn resource(service_name: &str) -> Resource {
        // The default builder already applies OTEL_SERVICE_NAME and
        // OTEL_RESOURCE_ATTRIBUTES; only fill what they leave unset.
        let detected = Resource::builder().build();
        let mut builder = Resource::builder()
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")));
        let unnamed = detected
            .get(&Key::from_static_str("service.name"))
            .is_none_or(|name| name.as_str().starts_with("unknown_service"));
        if unnamed {
            builder = builder.with_service_name(service_resource_name(service_name));
        }
        if detected
            .get(&Key::from_static_str("deployment.environment.name"))
            .is_none()
            && let Some(environment) = std::env::var("ENVIRONMENT")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        {
            builder =
                builder.with_attribute(KeyValue::new("deployment.environment.name", environment));
        }
        builder.build()
    }

    pub(super) fn service_resource_name(service_name: &str) -> String {
        if service_name.starts_with("codewire-") {
            service_name.to_owned()
        } else {
            format!("codewire-{service_name}")
        }
    }

    /// Which spans the OpenTelemetry layer builds: Codewire's own and
    /// kube-client's request span. No event is ever exported.
    pub(super) fn exported_span(metadata: &Metadata<'_>) -> bool {
        metadata.is_span()
            && *metadata.level() <= Level::DEBUG
            && (metadata.target().starts_with("codewire")
                || metadata.target().starts_with("kube_client"))
    }

    /// sqlx's per-statement event, and the `enabled!` hint sqlx checks
    /// before it builds one (a hint is neither a span nor an event).
    pub(super) fn statement_event(metadata: &Metadata<'_>) -> bool {
        !metadata.is_span() && metadata.target() == "sqlx::query"
    }

    /// Drops a client span (kube-client's request span) that has no parent:
    /// background reconcilers would otherwise export one root trace per
    /// Kubernetes request. Everything else goes to the configured sampler.
    #[derive(Clone, Debug)]
    pub(super) struct NoRootClientSpans(pub(super) Box<dyn ShouldSample>);

    impl ShouldSample for NoRootClientSpans {
        fn should_sample(
            &self,
            parent_context: Option<&Context>,
            trace_id: TraceId,
            name: &str,
            span_kind: &SpanKind,
            attributes: &[KeyValue],
            links: &[Link],
        ) -> SamplingResult {
            let has_parent = parent_context
                .is_some_and(|cx| cx.has_active_span() && cx.span().span_context().is_valid());
            if !has_parent && *span_kind == SpanKind::Client {
                return SamplingResult {
                    decision: SamplingDecision::Drop,
                    attributes: Vec::new(),
                    trace_state: TraceState::default(),
                };
            }
            self.0
                .should_sample(parent_context, trace_id, name, span_kind, attributes, links)
        }
    }

    /// Strips the query string and fragment from URL-valued attributes before
    /// export: a Kubernetes exec URL carries its command line, and request
    /// URIs can carry tokens. Paths are kept.
    #[derive(Debug)]
    pub(super) struct RedactUrlQueries<P>(pub(super) P);

    const URL_ATTRIBUTES: [&str; 5] = ["uri", "http.url", "url.full", "http.target", "url.query"];

    pub(super) fn redact_url_attributes(attributes: &mut Vec<KeyValue>) {
        attributes.retain(|kv| kv.key.as_str() != "url.query");
        for kv in attributes.iter_mut() {
            if !URL_ATTRIBUTES.contains(&kv.key.as_str()) {
                continue;
            }
            let redacted = {
                let value = kv.value.as_str();
                value.find(['?', '#']).map(|cut| value[..cut].to_owned())
            };
            if let Some(redacted) = redacted {
                kv.value = Value::from(redacted);
            }
        }
    }

    impl<P: SpanProcessor> SpanProcessor for RedactUrlQueries<P> {
        fn on_start(&self, span: &mut Span, cx: &Context) {
            self.0.on_start(span, cx);
        }

        fn on_end(&self, mut span: SpanData) {
            redact_url_attributes(&mut span.attributes);
            self.0.on_end(span);
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.0.force_flush()
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            self.0.shutdown_with_timeout(timeout)
        }

        fn set_resource(&mut self, resource: &Resource) {
            self.0.set_resource(resource);
        }
    }

    /// Turns sqlx's per-statement event into a client span under the active
    /// Codewire span. The event fires as the statement finishes, so the span
    /// is back-dated by the elapsed time sqlx measured.
    struct StatementSpans {
        tracer: SdkTracer,
    }

    #[derive(Default)]
    struct StatementFields {
        summary: Option<String>,
        rows_affected: Option<u64>,
        rows_returned: Option<u64>,
        elapsed_secs: Option<f64>,
        slow: bool,
    }

    impl Visit for StatementFields {
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "summary" {
                self.summary = Some(value.trim_end_matches(" …").to_owned());
            }
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            match field.name() {
                "rows_affected" => self.rows_affected = Some(value),
                "rows_returned" => self.rows_returned = Some(value),
                _ => {}
            }
        }

        fn record_f64(&mut self, field: &Field, value: f64) {
            if field.name() == "elapsed_secs" {
                self.elapsed_secs = Some(value);
            }
        }

        fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
            if field.name() == "slow_threshold" {
                self.slow = true;
            }
        }
    }

    impl<S: Subscriber> Layer<S> for StatementSpans {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
            // The active context is the entered Codewire span's (context
            // activation is on by default). Never start a root trace here.
            let parent = Context::current();
            if !parent.has_active_span() || !parent.span().span_context().is_valid() {
                return;
            }
            let mut fields = StatementFields::default();
            event.record(&mut fields);
            let end = SystemTime::now();
            let elapsed = fields
                .elapsed_secs
                .filter(|secs| secs.is_finite() && *secs >= 0.0)
                .map(Duration::from_secs_f64)
                .unwrap_or_default();
            let summary = fields.summary.unwrap_or_default();
            let operation = summary
                .split_whitespace()
                .next()
                .unwrap_or("query")
                .to_ascii_uppercase();
            let mut attributes = vec![
                KeyValue::new("db.system.name", "postgresql"),
                KeyValue::new("db.operation.name", operation.clone()),
                KeyValue::new("db.query.summary", summary),
            ];
            if let Some(rows) = fields.rows_affected {
                attributes.push(KeyValue::new("db.response.rows_affected", rows as i64));
            }
            if let Some(rows) = fields.rows_returned {
                attributes.push(KeyValue::new("db.response.returned_rows", rows as i64));
            }
            if fields.slow {
                attributes.push(KeyValue::new("db.slow_statement", true));
            }
            let mut span = self
                .tracer
                .span_builder(Cow::Owned(format!("postgresql {operation}")))
                .with_kind(SpanKind::Client)
                .with_start_time(end.checked_sub(elapsed).unwrap_or(end))
                .with_attributes(attributes)
                .start_with_context(&self.tracer, &parent);
            opentelemetry::trace::Span::end_with_timestamp(&mut span, end);
        }
    }

    pub(super) fn inject(cx: &Context, carrier: &mut dyn Injector) {
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(cx, carrier)
        });
    }

    pub(super) fn set_parent(span: &tracing::Span, carrier: &dyn Extractor) {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(carrier)
        });
        if parent.span().span_context().is_valid() {
            let _ = span.set_parent(parent);
        }
    }

    impl Injector for TraceContext {
        fn set(&mut self, key: &str, value: String) {
            match key {
                "traceparent" if value.len() <= MAX_TRACEPARENT_LEN => {
                    self.traceparent = Some(value)
                }
                "tracestate" if !value.is_empty() && value.len() <= MAX_TRACESTATE_LEN => {
                    self.tracestate = Some(value)
                }
                _ => {}
            }
        }
    }

    impl Extractor for TraceContext {
        fn get(&self, key: &str) -> Option<&str> {
            match key {
                "traceparent" => self
                    .traceparent
                    .as_deref()
                    .filter(|value| value.len() <= MAX_TRACEPARENT_LEN),
                "tracestate" => self
                    .tracestate
                    .as_deref()
                    .filter(|value| value.len() <= MAX_TRACESTATE_LEN),
                _ => None,
            }
        }

        fn keys(&self) -> Vec<&str> {
            let mut keys = Vec::with_capacity(2);
            if self.traceparent.is_some() {
                keys.push("traceparent");
            }
            if self.tracestate.is_some() {
                keys.push("tracestate");
            }
            keys
        }
    }

    pub(super) struct HeaderCarrier<'a>(pub(super) &'a http::HeaderMap);

    impl Extractor for HeaderCarrier<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            let value = self.0.get(key)?.to_str().ok()?;
            let limit = match key {
                "traceparent" => MAX_TRACEPARENT_LEN,
                "tracestate" => MAX_TRACESTATE_LEN,
                _ => return None,
            };
            (value.len() <= limit).then_some(value)
        }

        fn keys(&self) -> Vec<&str> {
            ["traceparent", "tracestate"]
                .into_iter()
                .filter(|key| self.0.contains_key(*key))
                .collect()
        }
    }

    pub(super) struct HeaderCarrierMut<'a>(pub(super) &'a mut http::HeaderMap);

    impl Injector for HeaderCarrierMut<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(key.as_bytes()),
                http::HeaderValue::from_str(&value),
            ) {
                self.0.insert(name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_trace_context_serializes_to_nothing() {
        #[derive(Serialize, Deserialize)]
        struct Message {
            id: String,
            #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
            trace_context: TraceContext,
        }
        let json = serde_json::to_string(&Message {
            id: "env-1".into(),
            trace_context: TraceContext::default(),
        })
        .unwrap();
        assert_eq!(json, r#"{"id":"env-1"}"#);
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert!(parsed.trace_context.is_empty());
        assert!(
            serde_json::from_str::<TraceContext>(r#"{"traceparent":"x","baggage":"y"}"#).is_err()
        );
    }

    #[test]
    fn probes_and_scrapes_never_start_a_trace() {
        for path in ["/healthz", "/readyz", "/metrics"] {
            assert!(untraced_path(path), "{path}");
        }
        assert!(!untraced_path(
            "/codewire.v1.EnvironmentService/CreateEnvironment"
        ));
    }

    #[test]
    fn the_logged_endpoint_has_no_credentials_path_or_query() {
        assert_eq!(
            display_endpoint("http://user:pass@tempo.observability:4317/v1?token=x"),
            "http://tempo.observability:4317"
        );
        assert_eq!(display_endpoint("not a url"), "<unparseable endpoint>");
    }

    #[test]
    fn a_stripe_sdk_span_never_puts_its_payload_in_a_log_line() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt as _;

        #[derive(Clone, Default)]
        struct Lines(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber =
            tracing_subscriber::registry().with(json_log_layer_to(move || writer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let _request = tracing::info_span!(target: "codewire_billing::webhook", "webhook", route = "stripe").entered();
            let _parse = tracing::info_span!(target: "stripe_webhook::webhook", "parse_payload", payload = "SYNTHETIC_CUSTOMER_EMAIL").entered();
            tracing::warn!(target: "stripe_webhook::webhook", "API version mismatch");
        });
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["fields"]["message"], "API version mismatch", "{text}");
        assert!(!text.contains("SYNTHETIC_CUSTOMER_EMAIL"), "{text}");
        // Codewire's own spans still give the line its context.
        assert_eq!(line["spans"][0]["route"], "stripe", "{text}");
    }

    /// Without an endpoint the initializer installs no exporter, whatever the
    /// build's features, and nothing becomes a carrier.
    #[tokio::test]
    async fn init_without_an_endpoint_installs_no_exporter() {
        let guard = init_traces_only("test", None).unwrap();
        assert!(!guard.exporting());
        let guard_blank = init_traces_only("test", Some("  ")).unwrap();
        assert!(!guard_blank.exporting());
        let span = tracing::info_span!("probe");
        let _entered = span.enter();
        assert!(TraceContext::current().is_empty());
        let mut headers = http::HeaderMap::new();
        inject_http_headers(&mut headers);
        assert!(headers.is_empty());
        guard.shutdown().await;
    }

    #[cfg(feature = "otel")]
    mod otel_tests {
        use opentelemetry::propagation::TextMapPropagator as _;
        use opentelemetry::trace::{
            SpanContext, SpanId, SpanKind, TraceContextExt as _, TraceFlags, TraceId, TraceState,
        };
        use opentelemetry::{Context, KeyValue};
        use opentelemetry_sdk::propagation::TraceContextPropagator;
        use opentelemetry_sdk::trace::{Sampler, SamplingDecision, ShouldSample as _};

        use super::super::otel::{
            HeaderCarrier, HeaderCarrierMut, NoRootClientSpans, exported_span,
            redact_url_attributes, resource, service_resource_name,
        };
        use super::*;

        fn remote_context() -> Context {
            Context::new().with_remote_span_context(SpanContext::new(
                TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
                SpanId::from_hex("00f067aa0ba902b7").unwrap(),
                TraceFlags::SAMPLED,
                true,
                TraceState::from_key_value([("codewire", "dev")]).unwrap(),
            ))
        }

        /// The Temporal carrier round-trips a W3C context through its JSON
        /// payload form unchanged.
        #[test]
        fn a_traceparent_round_trips_through_the_temporal_carrier() {
            let propagator = TraceContextPropagator::new();
            let mut carrier = TraceContext::default();
            propagator.inject_context(&remote_context(), &mut carrier);
            assert_eq!(
                carrier.traceparent.as_deref(),
                Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            );
            assert_eq!(carrier.tracestate.as_deref(), Some("codewire=dev"));

            let json = serde_json::to_string(&carrier).unwrap();
            let decoded: TraceContext = serde_json::from_str(&json).unwrap();
            let extracted = propagator.extract(&decoded);
            let span = extracted.span();
            let context = span.span_context();
            assert!(context.is_valid());
            assert!(context.is_remote());
            assert_eq!(
                context.trace_id(),
                TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
            );
            assert_eq!(
                context.span_id(),
                SpanId::from_hex("00f067aa0ba902b7").unwrap()
            );
            assert!(context.is_sampled());
            assert_eq!(context.trace_state().header(), "codewire=dev");
        }

        #[test]
        fn an_oversized_or_malformed_carrier_yields_no_parent() {
            let propagator = TraceContextPropagator::new();
            let oversized = TraceContext {
                traceparent: Some(format!(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01{}",
                    "0".repeat(64)
                )),
                tracestate: None,
            };
            assert!(!propagator.extract(&oversized).has_active_span());
            let malformed = TraceContext {
                traceparent: Some("00-zz-00f067aa0ba902b7-01".into()),
                tracestate: None,
            };
            assert!(
                !propagator
                    .extract(&malformed)
                    .span()
                    .span_context()
                    .is_valid()
            );
        }

        #[test]
        fn a_traceparent_round_trips_through_http_headers() {
            let propagator = TraceContextPropagator::new();
            let mut headers = http::HeaderMap::new();
            propagator.inject_context(&remote_context(), &mut HeaderCarrierMut(&mut headers));
            assert_eq!(
                headers.get("traceparent").unwrap(),
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            );
            let extracted = propagator.extract(&HeaderCarrier(&headers));
            assert_eq!(
                extracted.span().span_context().trace_id(),
                TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
            );
        }

        #[test]
        fn url_attributes_lose_their_query_before_export() {
            let mut attributes = vec![
                KeyValue::new(
                    "http.url",
                    "https://10.0.0.1/api/v1/namespaces/s/pods/p/exec?command=sh&command=-c",
                ),
                KeyValue::new("uri", "/invite?token=secret#frag"),
                KeyValue::new("url.query", "token=secret"),
                KeyValue::new("environment_id", "env-1?kept"),
            ];
            redact_url_attributes(&mut attributes);
            let rendered: Vec<(String, String)> = attributes
                .iter()
                .map(|kv| (kv.key.to_string(), kv.value.as_str().into_owned()))
                .collect();
            assert_eq!(
                rendered,
                vec![
                    (
                        "http.url".into(),
                        "https://10.0.0.1/api/v1/namespaces/s/pods/p/exec".into()
                    ),
                    ("uri".into(), "/invite".into()),
                    ("environment_id".into(), "env-1?kept".into()),
                ]
            );
        }

        #[test]
        fn root_client_spans_are_dropped_and_children_follow_the_sampler() {
            let sampler =
                NoRootClientSpans(Box::new(Sampler::ParentBased(Box::new(Sampler::AlwaysOn))));
            let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
            let root_client =
                sampler.should_sample(None, trace_id, "HTTP", &SpanKind::Client, &[], &[]);
            assert_eq!(root_client.decision, SamplingDecision::Drop);
            let root_internal =
                sampler.should_sample(None, trace_id, "request", &SpanKind::Internal, &[], &[]);
            assert_eq!(root_internal.decision, SamplingDecision::RecordAndSample);
            let parent = remote_context();
            let child_client =
                sampler.should_sample(Some(&parent), trace_id, "HTTP", &SpanKind::Client, &[], &[]);
            assert_eq!(child_client.decision, SamplingDecision::RecordAndSample);
        }

        #[test]
        fn only_codewire_and_kube_spans_are_exported() {
            struct Probe;
            impl tracing::Subscriber for Probe {
                fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                    // Other tests' callsites register while this dispatcher
                    // lives; a panic here would poison tracing's dispatcher
                    // lock for the whole test binary. Judge only our own.
                    let name = metadata.name();
                    if name.starts_with("export") || name.starts_with("skip") {
                        let expected = name.starts_with("export");
                        assert_eq!(exported_span(metadata), expected, "{name}");
                    }
                    false
                }
                fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                    tracing::span::Id::from_u64(1)
                }
                fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
                fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
                fn event(&self, _: &tracing::Event<'_>) {}
                fn enter(&self, _: &tracing::span::Id) {}
                fn exit(&self, _: &tracing::span::Id) {}
                fn register_callsite(
                    &self,
                    metadata: &'static tracing::Metadata<'static>,
                ) -> tracing::subscriber::Interest {
                    let _ = self.enabled(metadata);
                    tracing::subscriber::Interest::never()
                }
            }
            tracing::subscriber::with_default(Probe, || {
                let _ = tracing::debug_span!("export_codewire_debug");
                let _ = tracing::info_span!("export_codewire_info");
                let _ = tracing::trace_span!("skip_codewire_trace");
                let _ = tracing::debug_span!(target: "kube_client::client::builder", "export_kube");
                let _ = tracing::debug_span!(target: "hyper::client", "skip_hyper");
                tracing::info!("skip_codewire_event");
            });
        }

        /// `EXPORT_ACTIVE` is process-wide: tests that turn it on run one at
        /// a time, or one would turn export off under another.
        static EXPORT_ACTIVE_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        #[derive(Clone, Debug, Default)]
        struct Collected(std::sync::Arc<std::sync::Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>);

        impl opentelemetry_sdk::trace::SpanExporter for Collected {
            async fn export(
                &self,
                batch: Vec<opentelemetry_sdk::trace::SpanData>,
            ) -> opentelemetry_sdk::error::OTelSdkResult {
                self.0.lock().unwrap().extend(batch);
                Ok(())
            }
        }

        /// End to end through the real layers, sampler and redaction: a
        /// request carrying a W3C traceparent produces a server span in that
        /// trace, a Codewire child span, a statement span under it, and an
        /// outgoing carrier that continues the same trace. A probe makes no
        /// span, and a statement outside any span makes no root trace.
        #[tokio::test]
        async fn a_traced_request_continues_the_incoming_trace() {
            use tower::ServiceExt as _;
            use tracing_subscriber::layer::SubscriberExt as _;

            let collected = Collected::default();
            let exporter = super::super::otel::Exporter::with_processor(
                "orchestration",
                opentelemetry_sdk::trace::SimpleSpanProcessor::new(collected.clone()),
            );
            let subscriber = tracing_subscriber::registry().with(exporter.layers());
            let _default = tracing::subscriber::set_default(subscriber);
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
            let _export_active = EXPORT_ACTIVE_TESTS.lock().await;
            EXPORT_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

            let carried = std::sync::Arc::new(std::sync::Mutex::new(TraceContext::default()));
            let handler_carried = carried.clone();
            let app = crate::AppBuilder::new("test")
                .with_health()
                .with_routes(axum::Router::new().route(
                    "/codewire.v1.EnvironmentService/CreateEnvironment",
                    axum::routing::post(move || {
                        let carried = handler_carried.clone();
                        async move {
                            let span = tracing::debug_span!(
                                "create_environment",
                                environment_id = "env-1"
                            );
                            let _entered = span.enter();
                            // As sqlx does: build the event only when enabled.
                            assert!(tracing::enabled!(
                                target: "sqlx::query",
                                tracing::Level::DEBUG
                            ));
                            tracing::debug!(
                                target: "sqlx::query",
                                summary = "INSERT INTO environments (id,",
                                db.statement = "\n\nINSERT INTO environments VALUES ($1)\n",
                                rows_affected = 1_u64,
                                rows_returned = 0_u64,
                                elapsed_secs = 0.002_f64,
                            );
                            *carried.lock().unwrap() = TraceContext::current();
                            "ok"
                        }
                    }),
                ))
                .into_router();

            let request = http::Request::post(
                "/codewire.v1.EnvironmentService/CreateEnvironment?token=secret",
            )
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(axum::body::Body::empty())
            .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            // The response body owns the request span until it ends.
            drop(response);
            let probe = http::Request::get("/healthz")
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                app.oneshot(probe).await.unwrap().status(),
                http::StatusCode::OK
            );
            tracing::debug!(
                target: "sqlx::query",
                summary = "SELECT 1",
                elapsed_secs = 0.001_f64,
            );
            exporter.provider().force_flush().unwrap();
            EXPORT_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);

            let spans = collected.0.lock().unwrap().clone();
            let names: Vec<&str> = spans.iter().map(|span| span.name.as_ref()).collect();
            assert_eq!(names.len(), 3, "{names:?}");
            let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
            assert!(
                spans
                    .iter()
                    .all(|span| span.span_context.trace_id() == trace_id)
            );
            let find = |name: &str| {
                spans
                    .iter()
                    .find(|span| span.name == name)
                    .unwrap_or_else(|| panic!("{name} in {names:?}"))
            };
            let server = find("POST /codewire.v1.EnvironmentService/CreateEnvironment");
            assert_eq!(server.span_kind, SpanKind::Server);
            assert_eq!(
                server.parent_span_id,
                SpanId::from_hex("00f067aa0ba902b7").unwrap()
            );
            let uri = server
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == "uri")
                .map(|kv| kv.value.as_str().into_owned());
            assert_eq!(
                uri.as_deref(),
                Some("/codewire.v1.EnvironmentService/CreateEnvironment")
            );
            let child = find("create_environment");
            assert_eq!(child.parent_span_id, server.span_context.span_id());
            let statement = find("postgresql INSERT");
            assert_eq!(statement.span_kind, SpanKind::Client);
            assert_eq!(statement.parent_span_id, child.span_context.span_id());
            assert!(statement.attributes.iter().all(
                |kv| kv.key.as_str() != "db.statement" && !kv.value.as_str().contains("VALUES")
            ));
            assert!(
                statement
                    .end_time
                    .duration_since(statement.start_time)
                    .unwrap()
                    >= std::time::Duration::from_millis(2)
            );

            let carried = carried.lock().unwrap().clone();
            let traceparent = carried.traceparent.expect("carrier filled");
            assert!(
                traceparent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"),
                "{traceparent}"
            );
            assert!(traceparent.contains(&child.span_context.span_id().to_string()));
        }

        /// A Temporal activity as the worker runs it: the SDK's `RunActivity`
        /// span (not a Codewire target), Codewire's activity span joined to
        /// the sender's trace, and Codewire work under it. Every exported
        /// span's parent is the sender's span or another exported span, so
        /// the trace is one connected tree (#3581).
        #[tokio::test]
        async fn an_activity_trace_has_no_orphaned_span() {
            use tracing::Instrument as _;
            use tracing_subscriber::layer::SubscriberExt as _;

            let collected = Collected::default();
            let exporter = super::super::otel::Exporter::with_processor(
                "orchestration",
                opentelemetry_sdk::trace::SimpleSpanProcessor::new(collected.clone()),
            );
            let subscriber = tracing_subscriber::registry().with(exporter.layers());
            let _default = tracing::subscriber::set_default(subscriber);
            opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
            let _export_active = EXPORT_ACTIVE_TESTS.lock().await;
            EXPORT_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

            let sender = TraceContext {
                traceparent: Some(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
                ),
                tracestate: None,
            };
            let run_activity = tracing::info_span!(
                target: "temporalio_sdk",
                "RunActivity",
                "otel.name" = "RunActivity:EnvironmentSetupActivity",
                "otel.kind" = "server",
            );
            async {
                let activity = tracing::debug_span!(
                    "temporal.activity",
                    otel.name = "EnvironmentSetupActivity",
                    otel.kind = "consumer",
                );
                sender.attach_to(&activity);
                async {
                    let step = tracing::debug_span!("configure_environment");
                    async {
                        tracing::debug!(
                            target: "sqlx::query",
                            summary = "SELECT 1",
                            elapsed_secs = 0.001_f64,
                        );
                    }
                    .instrument(step)
                    .await;
                }
                .instrument(activity)
                .await;
            }
            .instrument(run_activity)
            .await;
            exporter.provider().force_flush().unwrap();
            EXPORT_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);

            let spans = collected.0.lock().unwrap().clone();
            let names: Vec<&str> = spans.iter().map(|span| span.name.as_ref()).collect();
            let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
            let sender_span = SpanId::from_hex("00f067aa0ba902b7").unwrap();
            let exported: std::collections::HashSet<SpanId> = spans
                .iter()
                .map(|span| span.span_context.span_id())
                .collect();
            for span in &spans {
                assert_eq!(span.span_context.trace_id(), trace_id, "{names:?}");
                assert!(
                    span.parent_span_id == sender_span || exported.contains(&span.parent_span_id),
                    "{} names a parent that was not exported: {names:?}",
                    span.name
                );
            }
            assert!(names.contains(&"EnvironmentSetupActivity"), "{names:?}");
            assert!(names.contains(&"configure_environment"), "{names:?}");
        }

        #[test]
        fn the_resource_names_the_service_and_version() {
            assert_eq!(
                service_resource_name("orchestration"),
                "codewire-orchestration"
            );
            assert_eq!(
                service_resource_name("codewire-dashboard"),
                "codewire-dashboard"
            );
            let resource = resource("orchestration");
            let get = |key: &'static str| {
                resource
                    .get(&opentelemetry::Key::from_static_str(key))
                    .map(|value| value.as_str().into_owned())
            };
            if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
                assert_eq!(
                    get("service.name").as_deref(),
                    Some("codewire-orchestration")
                );
            }
            assert_eq!(
                get("service.version").as_deref(),
                Some(env!("CARGO_PKG_VERSION"))
            );
        }
    }
}
