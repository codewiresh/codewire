//! Typed application error and JSON envelope for HTTP responses.
//!
//! The stable envelope shape is
//! `{"status": ..., "title": ..., "detail": ..., "code": ..., "hint": ...}`
//! with `title` set to the HTTP status text and `code`/`hint` omitted when
//! empty. The Codewire SDKs read `detail`; the CLI additionally
//! reads `code` and `hint` for corrective messages, so auth rejections
//! must preserve this contract.

use std::borrow::Cow;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// One request-validation failure produced by Rust-native schema validation.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// JSON pointer-ish location inside the request body. The root is `/`.
    pub path: Cow<'static, str>,
    /// Stable, human-readable validation message.
    pub message: Cow<'static, str>,
}

/// The on-the-wire error shape returned for any non-2xx response.
#[derive(Debug, Serialize, Clone)]
pub struct ErrorEnvelope {
    /// Numeric HTTP status, duplicated in the body for clients that read
    /// the body without seeing the response status.
    pub status: u16,
    /// Short title matching the [`AppError`] variant.
    pub title: Cow<'static, str>,
    /// Human-readable detail. Safe to log; never includes secrets.
    pub detail: Cow<'static, str>,
    /// Machine-readable error code (Go: `CodedError.Code`). Omitted when
    /// there is no code for the error class, matching Go's `omitempty`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Cow<'static, str>>,
    /// Human-readable corrective hint (Go: `CodedError.Hint`, populated
    /// from `hintForCode`). Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<Cow<'static, str>>,
    /// Optional request ID; surfaced when the request-id middleware set one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Request-validation failures. Present only for 422 responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ValidationIssue>>,
}

/// Application-level error type for handlers. Convert from sqlx /
/// async-nats / serde_json errors with `?` (impls below).
#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(Cow<'static, str>),

    #[error("bad request: {0}")]
    BadRequest(Cow<'static, str>),

    /// A valid request whose required configuration or lifecycle prerequisite
    /// is absent. REST keeps the legacy 400 envelope while Connect renders the
    /// semantic `failed_precondition` code.
    #[error("precondition failed: {0}")]
    Precondition(Cow<'static, str>),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("conflict: {0}")]
    Conflict(Cow<'static, str>),

    #[error("validation failed")]
    Validation { errors: Vec<ValidationIssue> },

    #[error("upstream service unavailable: {0}")]
    Upstream(Cow<'static, str>),

    /// 503 with a caller-visible detail (Go's
    /// `huma.Error503ServiceUnavailable`).
    #[error("service unavailable: {0}")]
    ServiceUnavailable(Cow<'static, str>),

    /// 500 with a caller-visible detail — for handlers that
    /// deliberately surface a generic failure message (Go's
    /// `huma.Error500InternalServerError("failed to …")`) while the
    /// real cause goes to the log.
    #[error("internal: {0}")]
    InternalMsg(Cow<'static, str>),
    /// huma `CodedError` parity for handler-raised errors: status +
    /// machine-readable code (hint derived) + detail.
    #[error("{detail}")]
    Coded {
        status: axum::http::StatusCode,
        code: &'static str,
        detail: Cow<'static, str>,
    },

    /// Anything we didn't classify above. The original error is logged at
    /// `error` level; the response detail says "internal error" without
    /// leaking internals.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// `Result` alias for handlers and helpers.
pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    // The accessors below are `pub(crate)` so the Connect renderer
    // (`crate::connect_error`) derives its view of an error from the very
    // same single source the HTTP envelope uses (01-error-model D6: one
    // error type, two renderers that cannot disagree).
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Precondition(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::InternalMsg(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Coded { status, .. } => *status,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether this error represents authenticated-but-unauthorized access.
    /// Raw HTTP compatibility handlers use this to preserve their legacy body
    /// shape without collapsing a scope failure into `401`.
    pub fn is_forbidden(&self) -> bool {
        self.status() == StatusCode::FORBIDDEN
    }

    /// HTTP status text, exactly as Go's `http.StatusText` produces for
    /// `CodedError.Title`.
    fn title(&self) -> Cow<'static, str> {
        match self {
            AppError::NotFound(_) => Cow::Borrowed("Not Found"),
            AppError::BadRequest(_) => Cow::Borrowed("Bad Request"),
            AppError::Precondition(_) => Cow::Borrowed("Bad Request"),
            AppError::Unauthorized => Cow::Borrowed("Unauthorized"),
            AppError::Forbidden => Cow::Borrowed("Forbidden"),
            AppError::Conflict(_) => Cow::Borrowed("Conflict"),
            AppError::Validation { .. } => Cow::Borrowed("Unprocessable Entity"),
            AppError::Upstream(_) => Cow::Borrowed("Bad Gateway"),
            AppError::ServiceUnavailable(_) => Cow::Borrowed("Service Unavailable"),
            AppError::InternalMsg(_) => Cow::Borrowed("Internal Server Error"),
            AppError::Coded { status, .. } => Cow::Owned(
                status
                    .canonical_reason()
                    .unwrap_or("Internal Server Error")
                    .to_string(),
            ),
            AppError::Internal(_) => Cow::Borrowed("Internal Server Error"),
        }
    }

    pub(crate) fn detail(&self) -> Cow<'static, str> {
        match self {
            AppError::NotFound(m)
            | AppError::BadRequest(m)
            | AppError::Precondition(m)
            | AppError::Conflict(m)
            | AppError::Upstream(m)
            | AppError::ServiceUnavailable(m)
            | AppError::InternalMsg(m) => m.clone(),
            AppError::Validation { .. } => Cow::Borrowed("validation failed"),
            AppError::Coded { detail, .. } => detail.clone(),
            // Same literals the Go auth middlewares pass to
            // writeMiddlewareError.
            AppError::Unauthorized => Cow::Borrowed("unauthorized"),
            AppError::Forbidden => Cow::Borrowed("forbidden"),
            // Hide internal detail from the response; the full error is
            // emitted via tracing when the response is produced.
            AppError::Internal(_) => Cow::Borrowed("internal error"),
        }
    }

    /// Stable machine-readable error code.
    pub(crate) fn code(&self) -> Option<Cow<'static, str>> {
        match self {
            AppError::Unauthorized => Some(Cow::Borrowed("session_expired")),
            AppError::Forbidden => Some(Cow::Borrowed("forbidden")),
            // Empty code is omitted, matching Go's `CodedError.Code`
            // `omitempty` — lets handlers raise a bare status+detail
            // error (e.g. huma's `Error403Forbidden(msg)`) via `Coded`
            // with `code: ""` without emitting a `"code":""` field.
            AppError::Coded { code, .. } if !code.is_empty() => Some(Cow::Borrowed(code)),
            _ => None,
        }
    }

    /// Corrective hint for [`Self::code`].
    pub(crate) fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            AppError::Unauthorized => Some(Cow::Borrowed("Run 'cw login' to re-authenticate")),
            AppError::Forbidden => Some(Cow::Borrowed(
                "Only org owners/admins can perform this action",
            )),
            AppError::Coded { code, .. } => hint_for_code(code).map(Cow::Borrowed),
            _ => None,
        }
    }

    pub(crate) fn errors(&self) -> Option<Vec<ValidationIssue>> {
        match self {
            AppError::Validation { errors } => Some(errors.clone()),
            _ => None,
        }
    }
}

/// Returns the stable CLI corrective hint for a machine-readable code.
pub fn hint_for_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "session_expired" => "Run 'cw login' to re-authenticate",
        "org_not_found" => "Check org with 'cw org list'",
        "preset_not_found" => "List presets with 'cw preset list'",
        "ai_detection_unavailable" => "Provide --image or --preset instead",
        "invalid_repo_url" => "Check the repository URL format",
        "repo_not_accessible" => "Run 'cw github login' or check repo visibility",
        "repo_not_found" => "Check repo URL or run 'cw github login' for private repos",
        "ai_detection_failed" => "Retry, or provide --image or --preset",
        "unsupported_agent" => "Valid agents: claude-code, codex, gemini-cli, aider",
        "secret_project_not_found" => "List secrets with 'cw secrets list'",
        "missing_input" => "Provide a repo URL, --image, or --preset",
        "env_not_found" => "Check environment ID with 'cw env list'",
        "invalid_state" => "Check environment state with 'cw env info'",
        "forbidden" => "Only org owners/admins can perform this action",
        "insufficient_scope" => "Request the codewire.api scope and re-authorize",
        "api_key_scope_violation" => {
            "Use a user credential for account-level or global admin operations"
        }
        "preset_in_use" => "Delete all environments using this preset first",
        "quota_exceeded" => {
            "Destroy unused environments with 'cw env destroy' or upgrade your plan"
        }
        // Go's CodeResourceLimit constant carries this wire value.
        "resource_limit_exceeded" => {
            "Reduce CPU/memory on active environments or upgrade your plan"
        }
        "rate_limited" => "Wait a moment before creating more environments",
        "environment_protected" => "Unprotect with 'cw env unprotect <name>' first",
        "organization_write_blocked" => {
            "Wait for organization deletion to finish or retry the failed deletion"
        }
        "organization_deletion_stale_generation" => {
            "Reload the organization deletion state before retrying"
        }
        "organization_mutation_lease_conflict" => {
            "Reconcile the in-flight organization mutation before retrying"
        }
        "organization_mutation_barrier_not_drained" => {
            "Wait for in-flight organization mutations to be reconciled"
        }
        "access_denied" => "Only the environment creator or granted users can perform this action",
        _ => return None,
    })
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if let AppError::Internal(ref e) = self {
            tracing::error!(error = ?e, "handler returned internal error");
        }
        let body = ErrorEnvelope {
            status: status.as_u16(),
            title: self.title(),
            detail: self.detail(),
            code: self.code(),
            hint: self.hint(),
            request_id: None,
            errors: self.errors(),
        };
        (status, Json(body)).into_response()
    }
}

// Common convenience conversions so handlers can use `?`.
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::NotFound(Cow::Borrowed("resource not found")),
            other => AppError::Internal(anyhow::Error::from(other)),
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::BadRequest(Cow::Owned(format!("invalid JSON: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn envelope_shape_matches_sdk_expectations() {
        let resp = AppError::NotFound(Cow::Borrowed("env env_123")).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The SDKs read `detail`; verify the wire shape.
        assert_eq!(parsed["detail"], "env env_123");
        assert_eq!(parsed["status"], 404);
        assert_eq!(parsed["title"], "Not Found");
        // No code/hint for plain not-found; keys must be absent, not null.
        assert!(parsed.get("code").is_none());
        assert!(parsed.get("hint").is_none());
        assert!(parsed.get("errors").is_none());
    }

    #[tokio::test]
    async fn auth_rejections_match_published_coded_error_bytes() {
        let resp = AppError::Unauthorized.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], 401);
        assert_eq!(parsed["title"], "Unauthorized");
        assert_eq!(parsed["detail"], "unauthorized");
        assert_eq!(parsed["code"], "session_expired");
        assert_eq!(parsed["hint"], "Run 'cw login' to re-authenticate");

        let resp = AppError::Forbidden.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], 403);
        assert_eq!(parsed["title"], "Forbidden");
        assert_eq!(parsed["detail"], "forbidden");
        assert_eq!(parsed["code"], "forbidden");
        assert_eq!(
            parsed["hint"],
            "Only org owners/admins can perform this action"
        );
    }

    #[tokio::test]
    async fn internal_errors_hide_their_source_from_the_body() {
        let err: AppError = anyhow::anyhow!("sensitive db connection string in here").into();
        let resp = err.into_response();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["detail"], "internal error");
        // Pure smoke: the leaked detail should NOT show up in the body.
        assert!(!body.windows("sensitive".len()).any(|w| w == b"sensitive"));
    }

    #[tokio::test]
    async fn validation_errors_have_stable_422_shape() {
        let resp = AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/role"),
                message: Cow::Borrowed("missing required property"),
            }],
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = to_bytes(resp.into_body(), 2048).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], 422);
        assert_eq!(parsed["title"], "Unprocessable Entity");
        assert_eq!(parsed["detail"], "validation failed");
        assert_eq!(parsed["errors"][0]["path"], "/role");
        assert_eq!(parsed["errors"][0]["message"], "missing required property");
        assert!(parsed.get("code").is_none());
        assert!(parsed.get("hint").is_none());
    }

    #[tokio::test]
    async fn precondition_preserves_the_legacy_http_400_envelope() {
        let resp = AppError::Precondition(Cow::Borrowed("GitHub not connected")).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], 400);
        assert_eq!(parsed["title"], "Bad Request");
        assert_eq!(parsed["detail"], "GitHub not connected");
        assert!(parsed.get("code").is_none());
        assert!(parsed.get("hint").is_none());
    }
}
