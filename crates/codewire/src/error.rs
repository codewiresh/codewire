use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use codewire_proto::google::rpc::{BadRequest, ErrorInfo as GoogleErrorInfo, RetryInfo};
use connectrpc::{ConnectError, ErrorCode, ErrorDetail};

const RESPONSE_BODY_INTERRUPTION_PREFIX: &str = "failed to read response body:";

/// One field-level validation failure from `google.rpc.BadRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    field: String,
    message: String,
}

impl ValidationError {
    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Machine-readable corrective context from `google.rpc.ErrorInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    reason: String,
    domain: String,
    metadata: BTreeMap<String, String>,
}

impl ErrorInfo {
    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    pub fn hint(&self) -> Option<&str> {
        self.metadata.get("hint").map(String::as_str)
    }

    pub fn request_id(&self) -> Option<&str> {
        self.metadata.get("request_id").map(String::as_str)
    }
}

/// The single typed error returned by the shared Rust client.
///
/// Callers branch on [`code`](Self::code), [`validation_errors`](Self::validation_errors),
/// or [`reason`](Self::reason), never on the display message.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ClientError {
    code: ErrorCode,
    message: String,
    validation_errors: Vec<ValidationError>,
    error_info: Option<Box<ErrorInfo>>,
    retry_delay: Option<Duration>,
    answer_ids: Option<Box<AnswerIds>>,
    retryable_transport_interruption: bool,
}

impl ClientError {
    /// Construct a canonical local failure, including from a custom
    /// [`TokenProvider`](crate::TokenProvider) implementation.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            validation_errors: Vec::new(),
            error_info: None,
            retry_delay: None,
            answer_ids: None,
            retryable_transport_interruption: code == ErrorCode::Unavailable,
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn validation_errors(&self) -> &[ValidationError] {
        &self.validation_errors
    }

    pub fn error_info(&self) -> Option<&ErrorInfo> {
        self.error_info.as_deref()
    }

    pub fn reason(&self) -> Option<&str> {
        self.error_info
            .as_deref()
            .map(ErrorInfo::reason)
            .filter(|reason| !reason.is_empty())
    }

    pub fn hint(&self) -> Option<&str> {
        self.error_info.as_deref().and_then(ErrorInfo::hint)
    }

    pub fn request_id(&self) -> Option<&str> {
        self.answer_ids.as_deref()?.request_id.as_deref()
    }

    /// The id of the trace the server's answer named (`x-codewire-trace-id`),
    /// as 32 lowercase hex digits. `None` when the server sent none, as for a
    /// request its sampler dropped, or when no server answered.
    pub fn trace_id(&self) -> Option<&str> {
        self.answer_ids.as_deref()?.trace_id.as_deref()
    }

    pub fn retry_delay(&self) -> Option<Duration> {
        self.retry_delay
    }

    /// Whether a long-lived stream may be resumed without changing the
    /// application operation. This normalizes transport-specific failures at
    /// the shared client boundary so callers never inspect display text.
    pub fn is_retryable_transport_interruption(&self) -> bool {
        self.retryable_transport_interruption
    }
}

impl From<ConnectError> for ClientError {
    fn from(error: ConnectError) -> Self {
        let retryable_transport_interruption = error.code == ErrorCode::Unavailable
            || (error.code == ErrorCode::Internal
                && error
                    .message
                    .as_deref()
                    .is_some_and(|message| message.starts_with(RESPONSE_BODY_INTERRUPTION_PREFIX)));
        let mut validation_errors = Vec::new();
        let mut error_info = None;
        let mut retry_delay = None;

        for detail in &error.details {
            if detail_is(detail, "google.rpc.BadRequest") {
                if let Some(bad_request) = decode_detail::<BadRequest>(detail) {
                    validation_errors.extend(bad_request.field_violations.into_iter().map(
                        |violation| ValidationError {
                            field: violation.field,
                            message: violation.description,
                        },
                    ));
                }
            } else if detail_is(detail, "google.rpc.ErrorInfo") {
                if error_info.is_none()
                    && let Some(info) = decode_detail::<GoogleErrorInfo>(detail)
                {
                    error_info = Some(
                        ErrorInfo {
                            reason: info.reason,
                            domain: info.domain,
                            metadata: info.metadata.into_iter().collect(),
                        }
                        .into(),
                    );
                }
            } else if detail_is(detail, "google.rpc.RetryInfo")
                && retry_delay.is_none()
                && let Some(retry) = decode_detail::<RetryInfo>(detail)
            {
                retry_delay = retry
                    .retry_delay
                    .into_option()
                    .and_then(|delay| Duration::try_from(delay).ok());
            }
        }

        let request_id = error_info
            .as_deref()
            .and_then(ErrorInfo::request_id)
            .map(str::to_owned)
            .or_else(|| {
                error
                    .response_headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            });
        let trace_id = response_trace_id(error.response_headers()).map(str::to_owned);
        let answer_ids = (request_id.is_some() || trace_id.is_some()).then(|| {
            Box::new(AnswerIds {
                request_id,
                trace_id,
            })
        });
        let message = error
            .message
            .as_deref()
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| error.code.as_str())
            .to_owned();

        Self {
            code: error.code,
            message,
            validation_errors,
            error_info,
            retry_delay,
            answer_ids,
            retryable_transport_interruption,
        }
    }
}

/// The ids a server's answer named, boxed together so that every error type
/// wrapping [`ClientError`] stays under clippy's large-error bound.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AnswerIds {
    request_id: Option<String>,
    trace_id: Option<String>,
}

/// The trace id a Codewire server's answer names in `x-codewire-trace-id`
/// (docs/CONFIGURATION.md, "Tracing"), as 32 lowercase hex digits. Anything
/// else in the header is ignored, so it is never shown or logged.
pub fn response_trace_id(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get("x-codewire-trace-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| is_trace_id(id))
}

fn is_trace_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && id.bytes().any(|byte| byte != b'0')
}

fn detail_is(detail: &ErrorDetail, expected: &str) -> bool {
    detail.type_url == expected || detail.type_url.rsplit('/').next() == Some(expected)
}

fn decode_detail<M: buffa::Message>(detail: &ErrorDetail) -> Option<M> {
    let encoded = detail.value.as_deref()?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    M::decode_from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_unknown_details_do_not_hide_the_canonical_error() {
        let error = ConnectError::invalid_argument("invalid request")
            .with_detail(ErrorDetail {
                type_url: "google.rpc.BadRequest".into(),
                value: Some("not-base64".into()),
                debug: None,
            })
            .with_detail(ErrorDetail {
                type_url: "example.v1.FutureDetail".into(),
                value: None,
                debug: None,
            });

        let decoded = ClientError::from(error);
        assert_eq!(decoded.code(), ErrorCode::InvalidArgument);
        assert_eq!(decoded.message(), "invalid request");
        assert!(decoded.validation_errors().is_empty());
    }

    #[test]
    fn only_transport_interruptions_are_retryable() {
        let body = ClientError::from(ConnectError::internal(
            "failed to read response body: request or response body error",
        ));
        assert!(body.is_retryable_transport_interruption());

        let unavailable = ClientError::new(ErrorCode::Unavailable, "connection reset");
        assert!(unavailable.is_retryable_transport_interruption());

        let server = ClientError::from(ConnectError::internal("session engine failed"));
        assert!(!server.is_retryable_transport_interruption());

        let denied = ClientError::new(ErrorCode::PermissionDenied, "denied");
        assert!(!denied.is_retryable_transport_interruption());
    }

    #[test]
    fn only_a_well_formed_trace_id_header_is_kept() {
        let answered = |value: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-codewire-trace-id", value.parse().unwrap());
            let error = ConnectError::not_found("environment not found").with_headers(headers);
            ClientError::from(error).trace_id().map(str::to_owned)
        };
        assert_eq!(
            answered("4bf92f3577b34da6a3ce929d0e0e4736").as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        for refused in [
            "4BF92F3577B34DA6A3CE929D0E0E4736",
            "4bf92f3577b34da6a3ce929d0e0e473",
            "00000000000000000000000000000000",
            "4bf92f3577b34da6a3ce929d0e0e473g",
        ] {
            assert_eq!(answered(refused), None, "{refused}");
        }
        assert_eq!(
            ClientError::from(ConnectError::not_found("no header")).trace_id(),
            None
        );
        assert_eq!(
            ClientError::new(ErrorCode::Unavailable, "no answer").trace_id(),
            None
        );
    }
}
