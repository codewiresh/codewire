//! Secret-free per-phase timing for the isolated credential broker.
//!
//! The broker writes one `info` line on the dedicated [`TARGET`] for each
//! proxied HTTP request, each platform bridge epoch admission, each capacity
//! rejection and each Codex login refused for a timing cause. Its fields are only durations in milliseconds, counts,
//! booleans, closed static labels and a proxied request's opaque, canonical
//! UUID. This module accepts nothing else, so no token, header, URL, body,
//! account, owner, credential, environment or Pod identifier can reach a line.
//!
//! A phase is added to the request or epoch whose future is being polled (a
//! task-local record) and is a no-op anywhere else. A detached refresh task
//! therefore records nothing itself; its caller times the whole refresh.
//! Recording never changes control flow, ordering or results.

use std::cell::RefCell;
use std::future::Future;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::{BrokerHttpResponse, BrokerRequestError};

/// The dedicated tracing target of every timing line.
pub const TARGET: &str = "codewire_credential_broker::timing";

/// One measured phase of a proxied request or an epoch admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// One broker runtime-authority check (`current_session`), including any
    /// `resolve()` the authority performs.
    Authority,
    /// One current-grant evaluation: every capability slot of the session.
    Grants,
    /// One read of a credential's metadata record: the leased or withheld
    /// credential's, or the account's active GitHub connection.
    Record,
    /// One protected-material read: its database reads, the KEK unwrap and
    /// the final database fence.
    MaterialRead,
    /// One KEK unwrap (OpenBao Transit in production) inside a material read.
    Unwrap,
    /// One provider request until its response headers: connect, TLS and
    /// time to first byte.
    Provider,
    /// One OAuth refresh, including its own admission and durable publication.
    Refresh,
    /// TokenReviews of the relay and workspace identities at admission.
    TokenReview,
    /// An epoch's wait for the guest's Ready frame.
    Ready,
    /// One lease's wait for a slot in the service's concurrent-lease budget.
    LeaseWait,
}

/// Whether a request's material came from its bridge epoch's cache. A
/// request with several leases reports the most expensive: one read through
/// the store is a `miss` even if another lease reused a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaterialCacheUse {
    /// No lease consulted a cache: no lease reached its material step, or
    /// the provider, lease or credential kind never reuses material.
    #[default]
    Bypass,
    /// Every consulting lease reused a value and read no material.
    Hit,
    /// At least one consulting lease read its material through the store.
    Miss,
}

impl MaterialCacheUse {
    fn label(self) -> &'static str {
        match self {
            Self::Bypass => "bypass",
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
}

/// Whether a request's leases reused their hosted epoch's authority decision.
/// A request with several leases reports the most expensive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityUse {
    /// No lease reached an authority decision, such as a request refused
    /// before it leased.
    #[default]
    None,
    /// Every lease reused its epoch's decision and reread only its
    /// credential's record: no runtime authority resolve or grant evaluation.
    Reused,
    /// At least one lease ran an authority evaluation, or ran full
    /// per-request checks.
    Evaluated,
}

impl AuthorityUse {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reused => "reused",
            Self::Evaluated => "evaluated",
        }
    }
}

/// How often one phase ran and its summed wall time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub count: u32,
    pub elapsed: Duration,
}

impl Sample {
    fn add(&mut self, count: u32, elapsed: Duration) {
        self.count = self.count.saturating_add(count);
        self.elapsed = self.elapsed.saturating_add(elapsed);
    }
}

/// Everything one proxied request or epoch admission recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    /// Wall time of the whole measured future.
    pub total: Duration,
    pub authority: Sample,
    /// Runtime-authority `resolve()` calls and their total time.
    pub resolve: Sample,
    /// The part of [`Self::resolve`] spent in Kubernetes reads.
    pub resolve_kubernetes: Duration,
    pub grants: Sample,
    pub record: Sample,
    pub material_read: Sample,
    pub unwrap: Sample,
    pub provider: Sample,
    pub refresh: Sample,
    pub token_review: Sample,
    pub ready: Sample,
    pub lease_wait: Sample,
    pub material_cache: MaterialCacheUse,
    pub authority_decision: AuthorityUse,
}

impl Timings {
    fn sample(&mut self, phase: Phase) -> &mut Sample {
        match phase {
            Phase::Authority => &mut self.authority,
            Phase::Grants => &mut self.grants,
            Phase::Record => &mut self.record,
            Phase::MaterialRead => &mut self.material_read,
            Phase::Unwrap => &mut self.unwrap,
            Phase::Provider => &mut self.provider,
            Phase::Refresh => &mut self.refresh,
            Phase::TokenReview => &mut self.token_review,
            Phase::Ready => &mut self.ready,
            Phase::LeaseWait => &mut self.lease_wait,
        }
    }

    /// `resolve()` time not spent in Kubernetes reads: its SQL statements.
    pub fn resolve_sql(&self) -> Duration {
        self.resolve.elapsed.saturating_sub(self.resolve_kubernetes)
    }

    /// Material-read time not spent unwrapping: its database reads and fence.
    pub fn material_database(&self) -> Duration {
        self.material_read
            .elapsed
            .saturating_sub(self.unwrap.elapsed)
    }
}

tokio::task_local! {
    static CURRENT: RefCell<Timings>;
}

fn update(change: impl FnOnce(&mut Timings)) {
    // Outside a measured future there is no record; never fail the caller.
    let _ = CURRENT.try_with(|current| {
        if let Ok(mut timings) = current.try_borrow_mut() {
            change(&mut timings);
        }
    });
}

/// Add `count` runs of `phase` taking `elapsed` in total to the current record.
pub fn record(phase: Phase, count: u32, elapsed: Duration) {
    update(|timings| timings.sample(phase).add(count, elapsed));
}

/// Record one lease's material-cache decision in the current record.
pub fn material_cache(decision: MaterialCacheUse) {
    update(|timings| timings.material_cache = timings.material_cache.max(decision));
}

/// Record whether one lease reused or evaluated authority in the current record.
pub fn authority(decision: AuthorityUse) {
    update(|timings| timings.authority_decision = timings.authority_decision.max(decision));
}

/// Add one runtime-authority `resolve()`: its total time and the part spent in
/// Kubernetes reads. The remainder is its SQL.
pub fn record_resolve(kubernetes: Duration, total: Duration) {
    update(|timings| {
        timings.resolve.add(1, total);
        timings.resolve_kubernetes = timings
            .resolve_kubernetes
            .saturating_add(kubernetes.min(total));
    });
}

/// Await `future` and record it as one run of `phase`, whatever its result.
pub async fn timed<F: Future>(phase: Phase, future: F) -> F::Output {
    timed_count(phase, 1, future).await
}

/// Await `future` and record it as `count` concurrent runs of `phase`.
pub async fn timed_count<F: Future>(phase: Phase, count: u32, future: F) -> F::Output {
    let started = Instant::now();
    let output = future.await;
    record(phase, count, started.elapsed());
    output
}

/// Run `future` with a fresh record and return what it recorded. Tasks it
/// spawns do not inherit the record.
pub async fn measure<F: Future>(future: F) -> (F::Output, Timings) {
    let started = Instant::now();
    CURRENT
        .scope(RefCell::new(Timings::default()), async move {
            let output = future.await;
            let mut timings = CURRENT
                .try_with(|current| current.try_borrow().map(|timings| *timings))
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            timings.total = started.elapsed();
            (output, timings)
        })
        .await
}

/// A closed label for a guest-supplied capability slot, never the raw value.
pub(crate) fn slot_label(slot: &str) -> &'static str {
    match slot {
        "codex" => "codex",
        "openai" => "openai",
        "anthropic" => "anthropic",
        "github" => "github",
        _ => "invalid",
    }
}

/// A closed label for a guest-supplied route, never the raw value.
pub(crate) fn route_label(route: &str) -> &'static str {
    match route {
        "openai-api" => "openai-api",
        "anthropic-api" => "anthropic-api",
        "github-api" => "github-api",
        "github-https" => "github-https",
        _ => "invalid",
    }
}

fn error_label(error: BrokerRequestError) -> &'static str {
    match error {
        BrokerRequestError::InvalidRequest => "invalid_request",
        BrokerRequestError::Denied => "denied",
        BrokerRequestError::AuthorityUnavailable => "authority_unavailable",
        BrokerRequestError::UpstreamFailed => "upstream_failed",
        BrokerRequestError::ResponseTooLarge => "response_too_large",
        BrokerRequestError::ReconnectRequired => "reconnect_required",
    }
}

fn ms(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

/// One line per proxied request, written when its filtered response headers
/// are ready (or it failed). `total_ms` is broker time to response headers.
pub(crate) fn proxied_request(
    request_id: &str,
    slot: &'static str,
    route: &'static str,
    result: &Result<BrokerHttpResponse, BrokerRequestError>,
    timings: &Timings,
) {
    // Only the canonical form of an opaque UUID is ever written.
    let request_id = Uuid::parse_str(request_id).unwrap_or_default();
    let (outcome, status) = match result {
        Ok(response) => ("response", response.status().as_u16()),
        Err(error) => (error_label(*error), 0),
    };
    tracing::info!(
        target: TARGET,
        event = "proxied_request",
        request_id = %request_id,
        slot,
        route,
        outcome,
        status,
        total_ms = ms(timings.total),
        lease_wait_ms = ms(timings.lease_wait.elapsed),
        authority = timings.authority_decision.label(),
        authority_checks = timings.authority.count,
        authority_ms = ms(timings.authority.elapsed),
        resolves = timings.resolve.count,
        resolve_kubernetes_ms = ms(timings.resolve_kubernetes),
        resolve_sql_ms = ms(timings.resolve_sql()),
        grant_evaluations = timings.grants.count,
        grants_ms = ms(timings.grants.elapsed),
        record_reads = timings.record.count,
        record_ms = ms(timings.record.elapsed),
        material_reads = timings.material_read.count,
        cache = timings.material_cache.label(),
        read_db_ms = ms(timings.material_database()),
        unwraps = timings.unwrap.count,
        unwrap_ms = ms(timings.unwrap.elapsed),
        provider_requests = timings.provider.count,
        provider_connect_ttfb_ms = ms(timings.provider.elapsed),
        refresh = timings.refresh.count > 0,
        refreshes = timings.refresh.count,
        refresh_ms = ms(timings.refresh.elapsed),
        "proxied credential request timing"
    );
}

/// One line per platform bridge epoch admission. `outcome` is a closed label.
/// `streams_in_use` counts the service's held stream slots, this one included:
/// live, admitting and draining epochs.
#[cfg(feature = "platform")]
pub(crate) fn epoch_admission(outcome: &'static str, streams_in_use: usize, timings: &Timings) {
    tracing::info!(
        target: TARGET,
        event = "epoch_admission",
        outcome,
        streams_in_use,
        total_ms = ms(timings.total),
        token_reviews = timings.token_review.count,
        token_review_ms = ms(timings.token_review.elapsed),
        resolves = timings.resolve.count,
        resolve_kubernetes_ms = ms(timings.resolve_kubernetes),
        resolve_sql_ms = ms(timings.resolve_sql()),
        authority_checks = timings.authority.count,
        authority_ms = ms(timings.authority.elapsed),
        ready_wait_ms = ms(timings.ready.elapsed),
        "credential bridge epoch admission timing"
    );
}

/// One line per request or epoch refused because a capacity limit was full.
/// `limit` and `operation` are closed labels.
pub(crate) fn capacity_rejected(
    limit: &'static str,
    operation: &'static str,
    capacity: usize,
    in_use: usize,
) {
    tracing::info!(
        target: TARGET,
        event = "capacity_rejected",
        limit,
        operation,
        capacity,
        in_use,
        "credential broker capacity rejection"
    );
}

/// One line per Codex login answered UNAVAILABLE for a timing cause the daemon
/// cannot see, such as clock skew between daemon and broker. `reason` is a
/// closed label: `deadline_passed`, `deadline_too_far` or
/// `deadline_passed_before_seal`.
pub(crate) fn codex_login_refused(reason: &'static str) {
    tracing::info!(
        target: TARGET,
        event = "codex_login_refused",
        reason,
        "credential broker Codex login refused"
    );
}

/// [`codex_login_refused`] for the Claude login, with the same closed reasons
/// and `scopes_outside_sign_in`.
pub(crate) fn claude_login_refused(reason: &'static str) {
    tracing::info!(
        target: TARGET,
        event = "claude_login_refused",
        reason,
        "credential broker Claude login refused"
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use futures::stream;
    use http::{HeaderMap, StatusCode};
    use serde_json::Value;

    use super::*;

    /// Thread-local JSON capture of the timing target only.
    #[derive(Clone, Default)]
    pub(crate) struct TimingLog(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TimingLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Registered once per test process and never dropped. It enables nothing
    /// itself. Its `sometimes` interest keeps tracing-core from caching a
    /// timing callsite as never enabled when a parallel test thread, with no
    /// subscriber of its own, registers or rebuilds that callsite first, so a
    /// thread-local capture sees every event its own thread emits.
    struct InterestPeer;

    impl tracing::Subscriber for InterestPeer {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
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
    }

    static INTEREST_PEER: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();

    /// Keeps this thread's capture subscriber installed.
    pub(crate) struct TimingCapture {
        _default: tracing::subscriber::DefaultGuard,
    }

    impl TimingLog {
        pub(crate) fn install() -> (Self, TimingCapture) {
            use tracing_subscriber::layer::SubscriberExt as _;
            INTEREST_PEER.get_or_init(|| tracing::Dispatch::new(InterestPeer));
            let log = Self::default();
            let writer = log.clone();
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(format!(
                    "off,{TARGET}=info"
                )))
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_writer(move || writer.clone()),
                );
            let guard = tracing::subscriber::set_default(subscriber);
            // A parallel test may have cached this callsite's interest first.
            tracing::callsite::rebuild_interest_cache();
            (log, TimingCapture { _default: guard })
        }

        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        /// Every captured line, parsed; each must be one JSON object.
        pub(crate) fn lines(&self) -> Vec<Value> {
            self.text()
                .lines()
                .map(|line| serde_json::from_str(line).expect("timing line is JSON"))
                .collect()
        }
    }

    const REQUEST_FIELDS: &[&str] = &[
        "event",
        "request_id",
        "slot",
        "route",
        "outcome",
        "status",
        "total_ms",
        "lease_wait_ms",
        "authority",
        "authority_checks",
        "authority_ms",
        "resolves",
        "resolve_kubernetes_ms",
        "resolve_sql_ms",
        "grant_evaluations",
        "grants_ms",
        "record_reads",
        "record_ms",
        "material_reads",
        "cache",
        "read_db_ms",
        "unwraps",
        "unwrap_ms",
        "provider_requests",
        "provider_connect_ttfb_ms",
        "refresh",
        "refreshes",
        "refresh_ms",
        "message",
    ];
    const EPOCH_FIELDS: &[&str] = &[
        "event",
        "outcome",
        "streams_in_use",
        "total_ms",
        "token_reviews",
        "token_review_ms",
        "resolves",
        "resolve_kubernetes_ms",
        "resolve_sql_ms",
        "authority_checks",
        "authority_ms",
        "ready_wait_ms",
        "message",
    ];
    const CAPACITY_FIELDS: &[&str] = &[
        "event",
        "limit",
        "operation",
        "capacity",
        "in_use",
        "message",
    ];
    const LOGIN_REFUSED_FIELDS: &[&str] = &["event", "reason", "message"];
    /// Every string a timing line may carry besides a canonical request UUID.
    const CLOSED_LABELS: &[&str] = &[
        "proxied_request",
        "epoch_admission",
        "capacity_rejected",
        "proxied credential request timing",
        "credential bridge epoch admission timing",
        "credential broker capacity rejection",
        "codex",
        "openai",
        "anthropic",
        "github",
        "openai-api",
        "anthropic-api",
        "github-api",
        "github-https",
        "invalid",
        "response",
        "invalid_request",
        "denied",
        "authority_unavailable",
        "upstream_failed",
        "response_too_large",
        "reconnect_required",
        "admitted",
        "unauthenticated",
        "unavailable",
        "timed_out",
        "invalid_protocol",
        "failed",
        "bridge_streams",
        "bridge_in_flight",
        "broker_leases",
        "epoch",
        "lease",
        "http",
        "ssh",
        "projection",
        "codex_login",
        "codex_login_in_flight",
        "codex_login_refused",
        "credential broker Codex login refused",
        "claude_login",
        "claude_login_in_flight",
        "claude_login_refused",
        "credential broker Claude login refused",
        "deadline_passed",
        "deadline_too_far",
        "deadline_passed_before_seal",
        "scopes_outside_sign_in",
        "hit",
        "miss",
        "bypass",
        "none",
        "reused",
        "evaluated",
    ];

    /// The whole contract of a timing line: the dedicated target, exactly its
    /// event's field names, and only numbers, booleans, closed labels or the
    /// canonical request UUID as values.
    pub(crate) fn assert_secret_free(line: &Value) {
        assert_eq!(line["target"], TARGET, "{line}");
        assert_eq!(line["level"], "INFO", "{line}");
        let fields = line["fields"].as_object().expect("fields object");
        let expected: BTreeSet<&str> = match fields["event"].as_str() {
            Some("proxied_request") => REQUEST_FIELDS,
            Some("epoch_admission") => EPOCH_FIELDS,
            Some("capacity_rejected") => CAPACITY_FIELDS,
            Some("codex_login_refused" | "claude_login_refused") => LOGIN_REFUSED_FIELDS,
            other => panic!("unknown timing event {other:?}"),
        }
        .iter()
        .copied()
        .collect();
        let actual: BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        assert_eq!(actual, expected, "{line}");
        for (name, value) in fields {
            match value {
                Value::Number(number) => {
                    assert!(number.as_f64().is_some_and(|value| value >= 0.0), "{name}")
                }
                Value::Bool(_) => {}
                Value::String(text) if name == "request_id" => {
                    let id = Uuid::parse_str(text).expect("request_id is a UUID");
                    assert_eq!(&id.to_string(), text, "request_id is canonical");
                }
                Value::String(text) => {
                    assert!(CLOSED_LABELS.contains(&text.as_str()), "{name}={text}")
                }
                other => panic!("{name} carries a non-scalar value {other}"),
            }
        }
    }

    fn millis(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[tokio::test]
    async fn phases_count_each_call_only_inside_a_measured_future() {
        // Outside any measured future a phase is silently dropped.
        record(Phase::Authority, 1, millis(5));
        record_resolve(millis(1), millis(2));
        let ((), timings) = measure(async {
            for _ in 0..3 {
                record(Phase::Authority, 1, millis(2));
            }
            assert_eq!(timed(Phase::Grants, async { 7 }).await, 7);
            timed(Phase::Grants, async {}).await;
            record(Phase::TokenReview, 2, millis(9));
            record_resolve(millis(3), millis(10));
            record_resolve(millis(4), millis(6));
            // A Kubernetes share can never exceed its resolve.
            record_resolve(millis(50), millis(5));
            record(Phase::MaterialRead, 1, millis(8));
            record(Phase::Unwrap, 1, millis(3));
            record(Phase::Refresh, 1, millis(40));
        })
        .await;
        assert_eq!(timings.authority.count, 3);
        assert_eq!(timings.authority.elapsed, millis(6));
        assert_eq!(timings.grants.count, 2);
        assert_eq!(timings.token_review.count, 2);
        assert_eq!(timings.token_review.elapsed, millis(9));
        assert_eq!(timings.resolve.count, 3);
        assert_eq!(timings.resolve.elapsed, millis(21));
        assert_eq!(timings.resolve_kubernetes, millis(12));
        assert_eq!(timings.resolve_sql(), millis(9));
        assert_eq!(timings.material_database(), millis(5));
        assert_eq!(timings.refresh.count, 1);
        assert_eq!(timings.provider, Sample::default());
        assert_eq!(timings.material_cache, MaterialCacheUse::Bypass);
        assert_eq!(timings.authority_decision, AuthorityUse::None);
        assert!(timings.total < millis(1_000));
    }

    #[tokio::test]
    async fn a_request_reports_its_most_expensive_material_cache_decision() {
        material_cache(MaterialCacheUse::Miss);
        for (decisions, expected) in [
            (&[][..], MaterialCacheUse::Bypass),
            (&[MaterialCacheUse::Bypass][..], MaterialCacheUse::Bypass),
            (&[MaterialCacheUse::Hit][..], MaterialCacheUse::Hit),
            (
                &[MaterialCacheUse::Hit, MaterialCacheUse::Bypass][..],
                MaterialCacheUse::Hit,
            ),
            (
                &[MaterialCacheUse::Miss, MaterialCacheUse::Hit][..],
                MaterialCacheUse::Miss,
            ),
            (
                &[MaterialCacheUse::Hit, MaterialCacheUse::Miss][..],
                MaterialCacheUse::Miss,
            ),
        ] {
            let ((), timings) = measure(async {
                for decision in decisions {
                    material_cache(*decision);
                }
            })
            .await;
            assert_eq!(timings.material_cache, expected, "{decisions:?}");
        }
    }

    #[tokio::test]
    async fn a_request_reports_whether_any_lease_evaluated_authority() {
        authority(AuthorityUse::Evaluated);
        for (decisions, expected) in [
            (&[][..], AuthorityUse::None),
            (&[AuthorityUse::Reused][..], AuthorityUse::Reused),
            (
                &[AuthorityUse::Reused, AuthorityUse::Reused][..],
                AuthorityUse::Reused,
            ),
            (
                &[AuthorityUse::Reused, AuthorityUse::Evaluated][..],
                AuthorityUse::Evaluated,
            ),
            (
                &[AuthorityUse::Evaluated, AuthorityUse::Reused][..],
                AuthorityUse::Evaluated,
            ),
        ] {
            let ((), timings) = measure(async {
                for decision in decisions {
                    authority(*decision);
                }
            })
            .await;
            assert_eq!(timings.authority_decision, expected, "{decisions:?}");
        }
    }

    #[tokio::test]
    async fn concurrent_requests_and_detached_tasks_keep_separate_records() {
        let ((first, second), outer) = measure(async {
            record(Phase::Provider, 1, millis(1));
            let detached = tokio::spawn(async { record(Phase::Provider, 1, millis(100)) });
            detached.await.unwrap();
            tokio::join!(
                measure(async { record(Phase::Record, 1, millis(1)) }),
                measure(async {
                    record(Phase::Record, 1, millis(1));
                    record(Phase::Record, 1, millis(1));
                }),
            )
        })
        .await;
        assert_eq!(outer.provider.count, 1);
        assert_eq!(outer.provider.elapsed, millis(1));
        assert_eq!(outer.record.count, 0);
        assert_eq!(first.1.record.count, 1);
        assert_eq!(second.1.record.count, 2);
    }

    #[test]
    fn guest_slot_and_route_values_become_closed_labels() {
        for slot in ["codex", "openai", "anthropic", "github"] {
            assert_eq!(slot_label(slot), slot);
        }
        for route in ["openai-api", "anthropic-api", "github-api", "github-https"] {
            assert_eq!(route_label(route), route);
        }
        for guest in ["sk-synthetic-secret", "codex\n", "", "Codex", "openai-api "] {
            assert_eq!(slot_label(guest), "invalid");
            assert_eq!(route_label(guest), "invalid");
        }
    }

    #[test]
    fn timing_lines_carry_only_closed_secret_free_fields() {
        let (log, _guard) = TimingLog::install();
        let mut timings = Timings {
            total: millis(580),
            ..Timings::default()
        };
        timings.authority.add(4, millis(300));
        timings.resolve.add(4, millis(290));
        timings.resolve_kubernetes = millis(200);
        timings.grants.add(2, millis(20));
        timings.material_read.add(1, millis(30));
        timings.unwrap.add(1, millis(12));
        timings.provider.add(1, millis(240));
        timings.lease_wait.add(1, millis(7));
        timings.material_cache = MaterialCacheUse::Miss;
        timings.authority_decision = AuthorityUse::Reused;
        let canonical = Uuid::new_v4().to_string();
        let response = Ok(BrokerHttpResponse::new(
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            Box::pin(stream::empty::<Result<Bytes, BrokerRequestError>>()),
        ));
        proxied_request(&canonical, "openai", "openai-api", &response, &timings);
        // A non-UUID guest value is never echoed.
        proxied_request(
            "sk-synthetic-secret-request",
            slot_label("sk-synthetic-secret-slot"),
            route_label("https://api.example.test/?key=sk-synthetic"),
            &Err(BrokerRequestError::Denied),
            &timings,
        );
        #[cfg(feature = "platform")]
        epoch_admission("admitted", 9, &timings);
        capacity_rejected("bridge_in_flight", "http", 8, 8);

        let text = log.text();
        for canary in ["sk-synthetic", "api.example.test", "key="] {
            assert!(!text.contains(canary), "timing exposed {canary}");
        }
        let lines = log.lines();
        assert_eq!(lines.len(), if cfg!(feature = "platform") { 4 } else { 3 });
        for line in &lines {
            assert_secret_free(line);
        }
        let first = &lines[0]["fields"];
        assert_eq!(first["request_id"], canonical.as_str());
        assert_eq!(first["status"], 401);
        assert_eq!(first["outcome"], "response");
        assert_eq!(first["authority_checks"], 4);
        assert_eq!(first["resolve_kubernetes_ms"], 200.0);
        assert_eq!(first["resolve_sql_ms"], 90.0);
        assert_eq!(first["read_db_ms"], 18.0);
        assert_eq!(first["unwrap_ms"], 12.0);
        assert_eq!(first["provider_connect_ttfb_ms"], 240.0);
        assert_eq!(first["refresh"], false);
        assert_eq!(first["lease_wait_ms"], 7.0);
        assert_eq!(first["cache"], "miss");
        assert_eq!(first["authority"], "reused");
        let second = &lines[1]["fields"];
        assert_eq!(second["request_id"], Uuid::nil().to_string().as_str());
        assert_eq!(second["slot"], "invalid");
        assert_eq!(second["route"], "invalid");
        assert_eq!(second["outcome"], "denied");
        assert_eq!(second["status"], 0);
        #[cfg(feature = "platform")]
        assert_eq!(lines[2]["fields"]["streams_in_use"], 9);
    }
}
