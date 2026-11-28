//! Bounded Prometheus telemetry for the workspace-binding listener. Labels are
//! closed result codes only; no environment, Pod or peer identifier is ever a
//! label.

use std::sync::OnceLock;

use prometheus::{IntCounter, IntCounterVec, Opts, register_int_counter, register_int_counter_vec};

static REQUESTS: OnceLock<IntCounterVec> = OnceLock::new();
static TOKEN_REVIEWS: OnceLock<IntCounter> = OnceLock::new();
static UNSERVED: OnceLock<IntCounter> = OnceLock::new();
static BOUND_SECRETS_REFUSED: OnceLock<IntCounterVec> = OnceLock::new();

/// The closed set of `WorkspaceBindingService` methods.
pub(super) const METHODS: [&str; 8] = [
    "bind_workspace",
    "refresh_access",
    "record_host_key",
    "allocate_peer_relay",
    "issue_mesh_enrollment",
    "report_mesh_attachment",
    "report_wake",
    "issue_identity_token",
];

/// The closed set of outcomes.
pub(super) const CODES: [&str; 8] = [
    "ok",
    "unauthenticated",
    "permission_denied",
    "not_found",
    "resource_exhausted",
    "unavailable",
    "invalid_argument",
    "failed_precondition",
];

fn requests() -> &'static IntCounterVec {
    REQUESTS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_workspace_binding_requests_total",
                "WorkspaceBindingService requests by method and result code."
            ),
            &["method", "code"]
        )
        .expect("workspace binding request metric registration must be unique")
    })
}

fn token_reviews() -> &'static IntCounter {
    TOKEN_REVIEWS.get_or_init(|| {
        register_int_counter!(
            "codewire_workspace_binding_token_reviews_total",
            "TokenReviews submitted by the workspace-binding listener."
        )
        .expect("workspace binding review metric registration must be unique")
    })
}

pub(super) fn observe_request(method: &'static str, code: &'static str) {
    debug_assert!(METHODS.contains(&method) && CODES.contains(&code));
    requests().with_label_values(&[method, code]).inc();
}

pub(super) fn observe_token_review() {
    token_reviews().inc();
}

/// First binds refused because the Pod's front door does not serve a host
/// its selection would bind (#6290, `front_door_hosts_unserved`).
pub(super) fn observe_front_door_hosts_unserved() {
    UNSERVED
        .get_or_init(|| {
            register_int_counter!(
                "codewire_workspace_binding_front_door_hosts_unserved_total",
                "First binds refused because the Pod's front door does not serve a host the selection binds."
            )
            .expect("workspace binding unserved metric registration must be unique")
        })
        .inc();
}

/// First binds refused for their selected bound secrets (#4003), by the
/// refusal's code: `bound_host_reserved`, `bound_host_conflict` or
/// `too_many_bound_hosts`.
pub(super) fn observe_bound_secrets_refused(code: &'static str) {
    BOUND_SECRETS_REFUSED
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_workspace_binding_bound_secrets_refused_total",
                    "First binds refused because the hosts of their selected bound secrets don't hold together.",
                ),
                &["code"]
            )
            .expect("workspace binding bound-secret refusal metric registration must be unique")
        })
        .with_label_values(&[code])
        .inc();
}
