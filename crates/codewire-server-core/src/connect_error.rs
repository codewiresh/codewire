//! Connect renderer for [`AppError`] — the second renderer of the shared
//! error type (`codewire/plans:connect-rpc/01-error-model.md`, D6).
//!
//! This module is deliberately **transport-agnostic**: connect-rust is not
//! in the workspace yet (03 WI-1 pins it), so it defines the canonical
//! Connect code enum, typed carriers for the `google.rpc` well-known
//! detail messages vendored under `proto/google/rpc/` (D1), and the
//! mapping from [`AppError`] — the same single source the HTTP envelope
//! renders from, so the two surfaces cannot disagree while both are
//! served. Workstream 03 wires [`ConnectError`] onto the wire format
//! (protobuf `Any` details, `code`/`message` JSON, trailers).
//!
//! The mapping implements:
//! - **D2** — HTTP status → canonical Connect code, total by fallback
//!   (anything unmapped renders as `internal`).
//! - **D3** — JSON-pointer validation paths → dotted field paths in
//!   `BadRequest.field_violations` ([`json_pointer_to_field_path`]).
//! - **D4** — today's `code`/`hint`/`request_id` survive in `ErrorInfo`
//!   (`domain = "codewire.sh"`, `reason` = today's code in
//!   SCREAMING_SNAKE, `metadata` carries `hint` and `request_id`).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::StatusCode;

use crate::error::AppError;

/// `ErrorInfo.domain` for every Codewire-produced error (D4).
pub const ERROR_INFO_DOMAIN: &str = "codewire.sh";

/// The 16 canonical Connect/gRPC error codes.
///
/// [`ConnectCode::as_str`] yields the Connect protocol's wire spelling
/// (lowercase snake, e.g. `invalid_argument`). The full set is defined so
/// later workstreams share one enum, but today's mapping (D2) only
/// produces a subset. `deadline_exceeded` represents server-enforced
/// deadlines, including bounded Connect credential resolution; `aborted`
/// remains reserved for its first real producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectCode {
    Canceled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl ConnectCode {
    /// The Connect protocol wire name for the code.
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectCode::Canceled => "canceled",
            ConnectCode::Unknown => "unknown",
            ConnectCode::InvalidArgument => "invalid_argument",
            ConnectCode::DeadlineExceeded => "deadline_exceeded",
            ConnectCode::NotFound => "not_found",
            ConnectCode::AlreadyExists => "already_exists",
            ConnectCode::PermissionDenied => "permission_denied",
            ConnectCode::ResourceExhausted => "resource_exhausted",
            ConnectCode::FailedPrecondition => "failed_precondition",
            ConnectCode::Aborted => "aborted",
            ConnectCode::OutOfRange => "out_of_range",
            ConnectCode::Unimplemented => "unimplemented",
            ConnectCode::Internal => "internal",
            ConnectCode::Unavailable => "unavailable",
            ConnectCode::DataLoss => "data_loss",
            ConnectCode::Unauthenticated => "unauthenticated",
        }
    }
}

/// Carrier for `google.rpc.BadRequest.FieldViolation`
/// (`proto/google/rpc/error_details.proto`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldViolation {
    /// Dotted field path (D3): `spec.name`, `ports[0].target`; empty for
    /// a body-root violation.
    pub field: String,
    /// Human-readable violation description.
    pub description: String,
}

/// Carrier for `google.rpc.BadRequest`. Attached to `invalid_argument`
/// errors produced from 422 validation failures (D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadRequest {
    pub field_violations: Vec<FieldViolation>,
}

impl BadRequest {
    pub const TYPE_URL: &'static str = "type.googleapis.com/google.rpc.BadRequest";
}

/// Carrier for `google.rpc.ErrorInfo`. Preserves today's envelope
/// `code`/`hint`/`request_id` (D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorInfo {
    /// Today's machine-readable envelope `code` rendered in
    /// SCREAMING_SNAKE (`session_expired` → `SESSION_EXPIRED`), per the
    /// `google.rpc.ErrorInfo.reason` UPPER_SNAKE convention. Empty when
    /// today's envelope carried no `code` (mirrors the envelope's
    /// `omitempty`) but `hint`/`request_id` still need to survive.
    pub reason: String,
    /// Always [`ERROR_INFO_DOMAIN`].
    pub domain: String,
    /// `hint` and `request_id` keys, each present only when it exists.
    pub metadata: BTreeMap<String, String>,
}

impl ErrorInfo {
    pub const TYPE_URL: &'static str = "type.googleapis.com/google.rpc.ErrorInfo";
}

/// Carrier for `google.rpc.RetryInfo`. Attached where a retry delay is
/// actually known (D2: 429, and `unavailable` where a retry is sane).
/// No [`AppError`] variant carries a delay today, so the automatic
/// mapping never fabricates one; producers/renderers attach it via
/// [`ConnectError::with_retry_delay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryInfo {
    pub retry_delay: Duration,
}

impl RetryInfo {
    pub const TYPE_URL: &'static str = "type.googleapis.com/google.rpc.RetryInfo";
}

/// One typed error detail (the transport-agnostic analogue of a
/// `google.protobuf.Any` in `google.rpc.Status.details`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectErrorDetail {
    BadRequest(BadRequest),
    ErrorInfo(ErrorInfo),
    RetryInfo(RetryInfo),
}

impl ConnectErrorDetail {
    /// The `google.protobuf.Any` type URL of the underlying detail type.
    pub fn type_url(&self) -> &'static str {
        match self {
            ConnectErrorDetail::BadRequest(_) => BadRequest::TYPE_URL,
            ConnectErrorDetail::ErrorInfo(_) => ErrorInfo::TYPE_URL,
            ConnectErrorDetail::RetryInfo(_) => RetryInfo::TYPE_URL,
        }
    }
}

/// A fully-rendered Connect error: canonical code + message + typed
/// details. 03's server infrastructure converts this to the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    pub code: ConnectCode,
    /// Same text as the HTTP envelope's `detail` (never leaks internals;
    /// [`AppError::Internal`] renders as `internal error`).
    pub message: String,
    pub details: Vec<ConnectErrorDetail>,
}

impl ConnectError {
    /// Render an [`AppError`] per D2/D3/D4. `request_id` comes from the
    /// request-id middleware when available (the `x-request-id` response
    /// header continues unchanged either way — Connect is HTTP).
    pub fn from_app_error(err: &AppError, request_id: Option<&str>) -> Self {
        let code = if matches!(err, AppError::Precondition(_)) {
            ConnectCode::FailedPrecondition
        } else {
            connect_code_for(err.status(), err.code().as_deref())
        };

        let mut details = Vec::new();
        if let Some(issues) = err.errors() {
            details.push(ConnectErrorDetail::BadRequest(BadRequest {
                field_violations: issues
                    .iter()
                    .map(|issue| FieldViolation {
                        field: json_pointer_to_field_path(&issue.path),
                        description: issue.message.clone().into_owned(),
                    })
                    .collect(),
            }));
        }
        if let Some(info) = error_info_for(err, request_id) {
            details.push(ConnectErrorDetail::ErrorInfo(info));
        }

        ConnectError {
            code,
            message: err.detail().into_owned(),
            details,
        }
    }

    /// Attach a `google.rpc.RetryInfo` with the given delay (D2: 429 →
    /// `RetryInfo.retry_delay`; `unavailable` where a retry is sane).
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.details.push(ConnectErrorDetail::RetryInfo(RetryInfo {
            retry_delay: delay,
        }));
        self
    }
}

/// D2: HTTP status → canonical Connect code. Total by fallback, not
/// enumeration — anything unmapped renders as `internal`.
///
/// `reason` is today's machine-readable envelope `code`. The environment
/// contract gives lifecycle-state and quota reasons semantic precedence over
/// their legacy REST statuses; the remaining mapping follows the D2 table.
fn connect_code_for(status: StatusCode, reason: Option<&str>) -> ConnectCode {
    match reason {
        Some("invalid_state" | "environment_protected") => {
            return ConnectCode::FailedPrecondition;
        }
        Some("quota_exceeded" | "resource_limit_exceeded") => {
            return ConnectCode::ResourceExhausted;
        }
        _ => {}
    }

    match status {
        // 400 malformed request and 422 validation share invalid_argument.
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => ConnectCode::InvalidArgument,
        StatusCode::UNAUTHORIZED => ConnectCode::Unauthenticated,
        StatusCode::FORBIDDEN => ConnectCode::PermissionDenied,
        StatusCode::NOT_FOUND => ConnectCode::NotFound,
        StatusCode::CONFLICT => {
            if reason.is_some_and(is_state_conflict_reason) {
                ConnectCode::FailedPrecondition
            } else {
                ConnectCode::AlreadyExists
            }
        }
        StatusCode::TOO_MANY_REQUESTS => ConnectCode::ResourceExhausted,
        StatusCode::GATEWAY_TIMEOUT => ConnectCode::DeadlineExceeded,
        // Upstream/daemon unavailable (502 today) and explicit 503.
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => ConnectCode::Unavailable,
        // 5xx handler faults and everything unmapped (the fallback row).
        _ => ConnectCode::Internal,
    }
}

/// Envelope `code`s that denote a lifecycle/state conflict rather than a
/// create-collision in the D2 409 split. The reason-first environment rows
/// above also cover their legacy non-409 statuses.
fn is_state_conflict_reason(reason: &str) -> bool {
    matches!(
        reason,
        "preset_in_use"
            | "invalid_state"
            | "environment_protected"
            | "organization_write_blocked"
            | "organization_deletion_stale_generation"
            | "organization_mutation_lease_conflict"
            | "organization_mutation_barrier_not_drained"
            | "platform_agent_resume_refused"
            | "platform_agent_request_refused"
    )
}

/// D4: build the `ErrorInfo` detail when today's envelope would have
/// carried any of `code`, `hint`, or `request_id`; otherwise attach
/// nothing.
fn error_info_for(err: &AppError, request_id: Option<&str>) -> Option<ErrorInfo> {
    let code = err.code();
    let hint = err.hint();
    if code.is_none() && hint.is_none() && request_id.is_none() {
        return None;
    }
    let mut metadata = BTreeMap::new();
    if let Some(hint) = hint {
        metadata.insert("hint".to_string(), hint.into_owned());
    }
    if let Some(rid) = request_id {
        metadata.insert("request_id".to_string(), rid.to_string());
    }
    Some(ErrorInfo {
        reason: code.map(|c| c.to_ascii_uppercase()).unwrap_or_default(),
        domain: ERROR_INFO_DOMAIN.to_string(),
        metadata,
    })
}

/// D3: convert today's JSON-pointer validation path (`/spec/name`,
/// `/ports/0/target`; `/` = body root) to a dotted field path
/// (`spec.name`, `ports[0].target`; body root → empty string). Purely
/// numeric segments render as array indices; RFC 6901 escapes (`~1`,
/// `~0`) are decoded in that order.
pub fn json_pointer_to_field_path(pointer: &str) -> String {
    if pointer.is_empty() || pointer == "/" {
        return String::new();
    }
    let mut out = String::new();
    for raw in pointer.split('/').skip(1) {
        let segment = raw.replace("~1", "/").replace("~0", "~");
        if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
            out.push('[');
            out.push_str(&segment);
            out.push(']');
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&segment);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::error::ValidationIssue;

    fn coded(status: StatusCode, code: &'static str, detail: &'static str) -> AppError {
        AppError::Coded {
            status,
            code,
            detail: Cow::Borrowed(detail),
        }
    }

    /// Every row of the D2 table, including the fallback row.
    #[test]
    fn d2_status_to_connect_code_table() {
        let cases: Vec<(AppError, ConnectCode)> = vec![
            // 400 malformed request → invalid_argument.
            (
                AppError::BadRequest("invalid JSON: whatever".into()),
                ConnectCode::InvalidArgument,
            ),
            // Environment lifecycle reasons override their legacy 400 status.
            (
                coded(
                    StatusCode::BAD_REQUEST,
                    "invalid_state",
                    "environment is already destroyed or destroying",
                ),
                ConnectCode::FailedPrecondition,
            ),
            (
                coded(
                    StatusCode::BAD_REQUEST,
                    "environment_protected",
                    "environment is protected from deletion",
                ),
                ConnectCode::FailedPrecondition,
            ),
            // 422 validation → invalid_argument.
            (
                AppError::Validation {
                    errors: vec![ValidationIssue {
                        path: Cow::Borrowed("/role"),
                        message: Cow::Borrowed("missing required property"),
                    }],
                },
                ConnectCode::InvalidArgument,
            ),
            // 401 → unauthenticated.
            (AppError::Unauthorized, ConnectCode::Unauthenticated),
            // 403 → permission_denied.
            (AppError::Forbidden, ConnectCode::PermissionDenied),
            // Environment quota reasons override their legacy 403 status.
            (
                coded(
                    StatusCode::FORBIDDEN,
                    "quota_exceeded",
                    "organization environment quota exceeded",
                ),
                ConnectCode::ResourceExhausted,
            ),
            (
                coded(
                    StatusCode::FORBIDDEN,
                    "resource_limit_exceeded",
                    "organization resource limit exceeded",
                ),
                ConnectCode::ResourceExhausted,
            ),
            // 404 → not_found.
            (
                AppError::NotFound("env env_123".into()),
                ConnectCode::NotFound,
            ),
            // 409 create-collision → already_exists.
            (
                AppError::Conflict("organization slug already exists".into()),
                ConnectCode::AlreadyExists,
            ),
            (
                coded(
                    StatusCode::CONFLICT,
                    "preset_slug_conflict",
                    "preset with this slug already exists",
                ),
                ConnectCode::AlreadyExists,
            ),
            // 409 lifecycle-state conflict → failed_precondition.
            (
                coded(
                    StatusCode::CONFLICT,
                    "preset_in_use",
                    "preset is used by 2 active environment(s) — delete them first",
                ),
                ConnectCode::FailedPrecondition,
            ),
            (
                coded(
                    StatusCode::CONFLICT,
                    "invalid_state",
                    "cannot stop a deleting environment",
                ),
                ConnectCode::FailedPrecondition,
            ),
            (
                coded(
                    StatusCode::CONFLICT,
                    "organization_write_blocked",
                    "organization deletion is in progress",
                ),
                ConnectCode::FailedPrecondition,
            ),
            (
                coded(
                    StatusCode::CONFLICT,
                    "platform_agent_resume_refused",
                    "the environment's previous Pod is still stopping; try again shortly",
                ),
                ConnectCode::FailedPrecondition,
            ),
            (
                coded(
                    StatusCode::CONFLICT,
                    "platform_agent_request_refused",
                    "message 00000000-0000-4000-8000-000000000001 is still in progress; \
                     try again shortly",
                ),
                ConnectCode::FailedPrecondition,
            ),
            // 429 → resource_exhausted.
            (
                coded(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    "too many environment creates",
                ),
                ConnectCode::ResourceExhausted,
            ),
            // 504 → deadline_exceeded.
            (
                coded(
                    StatusCode::GATEWAY_TIMEOUT,
                    "authentication_timeout",
                    "authentication deadline exceeded",
                ),
                ConnectCode::DeadlineExceeded,
            ),
            // 5xx handler fault → internal.
            (
                AppError::InternalMsg("failed to create environment".into()),
                ConnectCode::Internal,
            ),
            (
                AppError::Internal(anyhow::anyhow!("boom")),
                ConnectCode::Internal,
            ),
            // Upstream/daemon unavailable → unavailable.
            (
                AppError::Upstream("daemon unreachable".into()),
                ConnectCode::Unavailable,
            ),
            (
                AppError::ServiceUnavailable("database not ready".into()),
                ConnectCode::Unavailable,
            ),
            // Fallback row: anything unmapped → internal.
            (
                coded(StatusCode::GONE, "", "device code expired"),
                ConnectCode::Internal,
            ),
            (
                coded(StatusCode::IM_A_TEAPOT, "", "unmapped"),
                ConnectCode::Internal,
            ),
        ];

        for (err, want) in cases {
            let got = ConnectError::from_app_error(&err, None);
            assert_eq!(got.code, want, "wrong Connect code for {err:?}");
        }
    }

    #[test]
    fn semantic_precondition_keeps_http_400_but_maps_to_failed_precondition() {
        let err = AppError::Precondition("GitHub not connected".into());
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let rendered = ConnectError::from_app_error(&err, None);
        assert_eq!(rendered.code, ConnectCode::FailedPrecondition);
        assert_eq!(rendered.message, "GitHub not connected");
        assert!(rendered.details.is_empty());
    }

    /// D3 conversion cases: root, nested, array index, plus edges.
    #[test]
    fn d3_json_pointer_to_field_path_table() {
        let cases = [
            // Body root → empty field.
            ("/", ""),
            // Defensive: RFC 6901 whole-document pointer.
            ("", ""),
            // Top-level field.
            ("/role", "role"),
            // Nested field.
            ("/spec/name", "spec.name"),
            // Array index mid-path.
            ("/ports/0/target", "ports[0].target"),
            // Trailing array index.
            ("/args/2", "args[2]"),
            // Index at the root.
            ("/0/name", "[0].name"),
            // RFC 6901 escapes: ~1 → '/', ~0 → '~' (in that order).
            ("/a~1b/c~0d", "a/b.c~d"),
        ];
        for (pointer, want) in cases {
            assert_eq!(
                json_pointer_to_field_path(pointer),
                want,
                "pointer {pointer:?}"
            );
        }
    }

    #[test]
    fn validation_renders_bad_request_field_violations() {
        let err = AppError::Validation {
            errors: vec![
                ValidationIssue {
                    path: Cow::Borrowed("/"),
                    message: Cow::Borrowed("body must be an object"),
                },
                ValidationIssue {
                    path: Cow::Borrowed("/spec/name"),
                    message: Cow::Borrowed("missing required property"),
                },
                ValidationIssue {
                    path: Cow::Borrowed("/ports/0/target"),
                    message: Cow::Borrowed("must be >= 1"),
                },
            ],
        };
        let rendered = ConnectError::from_app_error(&err, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        assert_eq!(rendered.message, "validation failed");
        let ConnectErrorDetail::BadRequest(bad) = &rendered.details[0] else {
            panic!("expected BadRequest detail, got {:?}", rendered.details);
        };
        assert_eq!(
            bad.field_violations,
            vec![
                // Body root → empty field; the description carries the
                // message (D3).
                FieldViolation {
                    field: String::new(),
                    description: "body must be an object".to_string(),
                },
                FieldViolation {
                    field: "spec.name".to_string(),
                    description: "missing required property".to_string(),
                },
                FieldViolation {
                    field: "ports[0].target".to_string(),
                    description: "must be >= 1".to_string(),
                },
            ]
        );
    }

    /// D4: code/hint/request_id survive in ErrorInfo, reason is
    /// SCREAMING_SNAKE, domain is codewire.sh.
    #[test]
    fn d4_error_info_carries_code_hint_and_request_id() {
        let rendered = ConnectError::from_app_error(&AppError::Unauthorized, Some("req_123"));
        assert_eq!(rendered.code, ConnectCode::Unauthenticated);
        assert_eq!(rendered.message, "unauthorized");
        let ConnectErrorDetail::ErrorInfo(info) = &rendered.details[0] else {
            panic!("expected ErrorInfo detail, got {:?}", rendered.details);
        };
        assert_eq!(info.reason, "SESSION_EXPIRED");
        assert_eq!(info.domain, "codewire.sh");
        assert_eq!(
            info.metadata.get("hint").map(String::as_str),
            Some("Run 'cw login' to re-authenticate")
        );
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_123")
        );
    }

    /// The D2 403 row attaches ErrorInfo even without a request id.
    #[test]
    fn forbidden_attaches_error_info() {
        let rendered = ConnectError::from_app_error(&AppError::Forbidden, None);
        assert_eq!(rendered.code, ConnectCode::PermissionDenied);
        let ConnectErrorDetail::ErrorInfo(info) = &rendered.details[0] else {
            panic!("expected ErrorInfo detail, got {:?}", rendered.details);
        };
        assert_eq!(info.reason, "FORBIDDEN");
        assert_eq!(info.domain, "codewire.sh");
        assert_eq!(
            info.metadata.get("hint").map(String::as_str),
            Some("Only org owners/admins can perform this action")
        );
        assert!(!info.metadata.contains_key("request_id"));
    }

    /// No code, no hint, no request id → no ErrorInfo (nothing to
    /// preserve); with a request id it appears with an empty reason
    /// (mirrors today's envelope omitting `code`).
    #[test]
    fn error_info_only_when_something_survives() {
        let plain = ConnectError::from_app_error(&AppError::NotFound("env env_123".into()), None);
        assert!(plain.details.is_empty(), "details: {:?}", plain.details);

        let with_rid =
            ConnectError::from_app_error(&AppError::NotFound("env env_123".into()), Some("req_9"));
        let ConnectErrorDetail::ErrorInfo(info) = &with_rid.details[0] else {
            panic!("expected ErrorInfo detail, got {:?}", with_rid.details);
        };
        assert_eq!(info.reason, "");
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_9")
        );
        assert!(!info.metadata.contains_key("hint"));
    }

    /// Internal errors keep hiding their source (same guarantee as the
    /// HTTP renderer).
    #[test]
    fn internal_errors_hide_their_source() {
        let err: AppError = anyhow::anyhow!("sensitive db connection string in here").into();
        let rendered = ConnectError::from_app_error(&err, None);
        assert_eq!(rendered.code, ConnectCode::Internal);
        assert_eq!(rendered.message, "internal error");
        assert!(!rendered.message.contains("sensitive"));
    }

    /// D2 429 row: RetryInfo.retry_delay attaches where the delay is
    /// known (no AppError variant carries one today, so it is attached
    /// explicitly by the producer/renderer).
    #[test]
    fn retry_info_attaches_via_builder() {
        let err = coded(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many environment creates",
        );
        let rendered =
            ConnectError::from_app_error(&err, None).with_retry_delay(Duration::from_secs(60));
        assert_eq!(rendered.code, ConnectCode::ResourceExhausted);
        let retry = rendered
            .details
            .iter()
            .find_map(|d| match d {
                ConnectErrorDetail::RetryInfo(r) => Some(r),
                _ => None,
            })
            .expect("RetryInfo detail attached");
        assert_eq!(retry.retry_delay, Duration::from_secs(60));
    }

    /// The wire spellings 03 will emit for the codes D2 produces.
    #[test]
    fn connect_code_wire_names() {
        let cases = [
            (ConnectCode::InvalidArgument, "invalid_argument"),
            (ConnectCode::Unauthenticated, "unauthenticated"),
            (ConnectCode::PermissionDenied, "permission_denied"),
            (ConnectCode::NotFound, "not_found"),
            (ConnectCode::AlreadyExists, "already_exists"),
            (ConnectCode::FailedPrecondition, "failed_precondition"),
            (ConnectCode::ResourceExhausted, "resource_exhausted"),
            (ConnectCode::Internal, "internal"),
            (ConnectCode::Unavailable, "unavailable"),
        ];
        for (code, want) in cases {
            assert_eq!(code.as_str(), want);
        }
    }

    /// Detail type URLs point at the vendored google.rpc types (D1).
    #[test]
    fn detail_type_urls_match_google_rpc() {
        assert_eq!(
            ConnectErrorDetail::BadRequest(BadRequest {
                field_violations: vec![]
            })
            .type_url(),
            "type.googleapis.com/google.rpc.BadRequest"
        );
        assert_eq!(
            ConnectErrorDetail::ErrorInfo(ErrorInfo {
                reason: String::new(),
                domain: ERROR_INFO_DOMAIN.to_string(),
                metadata: BTreeMap::new(),
            })
            .type_url(),
            "type.googleapis.com/google.rpc.ErrorInfo"
        );
        assert_eq!(
            ConnectErrorDetail::RetryInfo(RetryInfo {
                retry_delay: Duration::from_secs(1)
            })
            .type_url(),
            "type.googleapis.com/google.rpc.RetryInfo"
        );
    }
}
