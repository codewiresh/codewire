//! Closed, value-blind diagnostics for a provider token refresh that did not
//! publish rotated material.
//!
//! A failure after durable Start is terminal for the stored credential: the
//! previous refresh token is never replayed, so the owner must reconnect.
//! Operators still need to know why. Only static class names, a numeric HTTP status, a fixed
//! transport class and allowlisted provider error identifiers leave this
//! module. Tokens, response bodies, provider messages, descriptions and
//! transport error text are never retained or logged.

use std::error::Error as StdError;
use std::io;

use http::StatusCode;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{BrokerRefreshError, BrokerUpstreamError};

const FAILURE_MESSAGE: &str = "provider credential refresh failed";

/// Why one started refresh did not publish rotated material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshFailure {
    /// Durable Start or the final authority admission after it failed. No
    /// provider request was sent by this attempt.
    Start(BrokerRefreshError),
    /// The fixed provider request could not be constructed; nothing was sent.
    RequestBuild,
    /// The provider transport failed before a response status was received.
    Transport(BrokerUpstreamError),
    /// The whole exchange exceeded the shared provider refresh timeout.
    Timeout,
    /// The response used a content encoding other than identity.
    ResponseEncoding,
    /// The response body stream failed or exceeded its size ceiling.
    ResponseBody,
    /// The provider answered with a non-success status.
    Rejected(ProviderRejection),
    /// A success status carried no parseable token response or access token.
    ResponseParse,
    /// The returned tokens failed canonical bundle validation, for example a
    /// changed account identity.
    Material,
    /// The provider owner reported a definite rejection without exposing its
    /// status (GitHub App authorization).
    ProviderRejected,
    /// The provider owner reported an ambiguous failure without exposing its
    /// status (GitHub App authorization).
    ProviderUncertain,
    /// Rotated material could not be durably staged or promoted. A staged
    /// result stays recoverable; an unstaged one is abandoned after the
    /// storage execution deadline.
    Publication(BrokerRefreshError),
}

/// A provider's non-success refresh response, reduced to allowlisted values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderRejection {
    pub(crate) status: u16,
    pub(crate) code: ProviderErrorCode,
    pub(crate) error_type: ProviderErrorType,
    /// Whether the provider definitively rejected the refresh token.
    pub(crate) permanent: bool,
}

/// OAuth 2.0 (RFC 6749 section 5.2) and Codex refresh error codes. Any other
/// provider value is reported only as `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderErrorCode {
    Absent,
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    RefreshTokenExpired,
    RefreshTokenReused,
    RefreshTokenInvalidated,
    Other,
}

/// OpenAI-style error object `type` values. Any other value is `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderErrorType {
    Absent,
    InvalidRequestError,
    AuthenticationError,
    PermissionError,
    RateLimitError,
    ServerError,
    Other,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<ErrorValue>,
    code: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ErrorValue {
    Code(Zeroizing<String>),
    Detail {
        code: Option<Zeroizing<String>>,
        #[serde(rename = "type")]
        error_type: Option<Zeroizing<String>>,
    },
}

impl ProviderRejection {
    /// Classify a non-success OAuth refresh response. 401, and 400 with a
    /// definite refresh-token rejection code, are permanent. Every other status
    /// or body remains ambiguous. Both outcomes are terminal for the attempt.
    pub(crate) fn classify(status: StatusCode, body: &[u8]) -> Self {
        let (code, error_type) = match serde_json::from_slice::<ErrorBody>(body) {
            Ok(parsed) => {
                let (code, error_type) = match parsed.error {
                    Some(ErrorValue::Code(code)) => (Some(code), None),
                    Some(ErrorValue::Detail { code, error_type }) => (code, error_type),
                    None => (parsed.code, None),
                };
                (
                    ProviderErrorCode::parse(code.as_deref().map(String::as_str)),
                    ProviderErrorType::parse(error_type.as_deref().map(String::as_str)),
                )
            }
            Err(_) => (ProviderErrorCode::Absent, ProviderErrorType::Absent),
        };
        let permanent = status == StatusCode::UNAUTHORIZED
            || (status == StatusCode::BAD_REQUEST
                && matches!(
                    code,
                    ProviderErrorCode::InvalidGrant
                        | ProviderErrorCode::RefreshTokenExpired
                        | ProviderErrorCode::RefreshTokenReused
                        | ProviderErrorCode::RefreshTokenInvalidated
                ));
        Self {
            status: status.as_u16(),
            code,
            error_type,
            permanent,
        }
    }
}

impl ProviderErrorCode {
    fn parse(value: Option<&str>) -> Self {
        let Some(value) = value else {
            return Self::Absent;
        };
        [
            ("invalid_request", Self::InvalidRequest),
            ("invalid_client", Self::InvalidClient),
            ("invalid_grant", Self::InvalidGrant),
            ("unauthorized_client", Self::UnauthorizedClient),
            ("unsupported_grant_type", Self::UnsupportedGrantType),
            ("invalid_scope", Self::InvalidScope),
            ("refresh_token_expired", Self::RefreshTokenExpired),
            ("refresh_token_reused", Self::RefreshTokenReused),
            ("refresh_token_invalidated", Self::RefreshTokenInvalidated),
        ]
        .into_iter()
        .find(|(name, _)| value.eq_ignore_ascii_case(name))
        .map_or(Self::Other, |(_, code)| code)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::RefreshTokenExpired => "refresh_token_expired",
            Self::RefreshTokenReused => "refresh_token_reused",
            Self::RefreshTokenInvalidated => "refresh_token_invalidated",
            Self::Other => "other",
        }
    }
}

impl ProviderErrorType {
    fn parse(value: Option<&str>) -> Self {
        let Some(value) = value else {
            return Self::Absent;
        };
        [
            ("invalid_request_error", Self::InvalidRequestError),
            ("authentication_error", Self::AuthenticationError),
            ("permission_error", Self::PermissionError),
            ("rate_limit_error", Self::RateLimitError),
            ("server_error", Self::ServerError),
        ]
        .into_iter()
        .find(|(name, _)| value.eq_ignore_ascii_case(name))
        .map_or(Self::Other, |(_, error_type)| error_type)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::InvalidRequestError => "invalid_request_error",
            Self::AuthenticationError => "authentication_error",
            Self::PermissionError => "permission_error",
            Self::RateLimitError => "rate_limit_error",
            Self::ServerError => "server_error",
            Self::Other => "other",
        }
    }
}

impl RefreshFailure {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::Start(error) => match error {
                BrokerRefreshError::Denied => "start_denied",
                BrokerRefreshError::Unavailable => "start_unavailable",
                BrokerRefreshError::Stale => "start_stale",
                BrokerRefreshError::InProgress => "start_in_progress",
                BrokerRefreshError::InvalidRequest => "start_invalid_request",
                BrokerRefreshError::InvalidResponse => "start_invalid_response",
            },
            Self::RequestBuild => "request_build",
            Self::Transport(error) => match error {
                BrokerUpstreamError::Connect => "transport_connect",
                BrokerUpstreamError::Protocol => "transport_protocol",
                BrokerUpstreamError::DestinationDenied => "transport_destination_denied",
                BrokerUpstreamError::ResourceLimit => "transport_resource_limit",
            },
            Self::Timeout => "timeout",
            Self::ResponseEncoding => "response_encoding",
            Self::ResponseBody => "response_body",
            Self::Rejected(_) => "http_status",
            Self::ResponseParse => "response_parse",
            Self::Material => "material",
            Self::ProviderRejected => "provider_rejected",
            Self::ProviderUncertain => "provider_uncertain",
            Self::Publication(error) => match error {
                BrokerRefreshError::Denied => "publication_denied",
                BrokerRefreshError::Unavailable => "publication_unavailable",
                BrokerRefreshError::Stale => "publication_stale",
                BrokerRefreshError::InProgress => "publication_in_progress",
                BrokerRefreshError::InvalidRequest => "publication_invalid_request",
                BrokerRefreshError::InvalidResponse => "publication_invalid_response",
            },
        }
    }

    /// Emit exactly one value-blind WARN for this failure.
    pub(crate) fn warn(self, provider: &'static str) {
        match self {
            Self::Rejected(rejection) => tracing::warn!(
                provider,
                failure = self.class(),
                http_status = rejection.status,
                provider_error_code = rejection.code.as_str(),
                provider_error_type = rejection.error_type.as_str(),
                permanent = rejection.permanent,
                "{FAILURE_MESSAGE}"
            ),
            _ => tracing::warn!(provider, failure = self.class(), "{FAILURE_MESSAGE}"),
        }
    }
}

/// Fixed classes for a provider transport send failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportFailure {
    Timeout,
    Connect,
    Tls,
    Request,
    Other,
}

impl TransportFailure {
    /// Classify from closed reqwest flags plus the first `io::Error` kind in
    /// the source chain. rustls handshake and certificate failures surface as
    /// `InvalidData`. No error text is inspected or retained.
    pub(crate) fn classify(
        timeout: bool,
        connect: bool,
        request: bool,
        error: &(dyn StdError + 'static),
    ) -> (Self, Option<io::ErrorKind>) {
        let mut source = Some(error);
        let mut kind = None;
        while let Some(current) = source {
            if let Some(io) = current.downcast_ref::<io::Error>() {
                kind = Some(io.kind());
                break;
            }
            source = current.source();
        }
        let class = if timeout || kind == Some(io::ErrorKind::TimedOut) {
            Self::Timeout
        } else if kind == Some(io::ErrorKind::InvalidData) {
            Self::Tls
        } else if connect {
            Self::Connect
        } else if request {
            Self::Request
        } else {
            Self::Other
        };
        (class, kind)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Request => "request",
            Self::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(status: u16, body: &str) -> ProviderRejection {
        ProviderRejection::classify(StatusCode::from_u16(status).unwrap(), body.as_bytes())
    }

    #[test]
    fn rejection_reads_rfc_openai_and_top_level_codes_case_insensitively() {
        assert_eq!(
            classify(
                400,
                r#"{"error":"INVALID_GRANT","error_description":"secret detail"}"#
            ),
            ProviderRejection {
                status: 400,
                code: ProviderErrorCode::InvalidGrant,
                error_type: ProviderErrorType::Absent,
                permanent: true,
            }
        );
        assert_eq!(
            classify(
                401,
                r#"{"error":{"message":"secret detail","type":"invalid_request_error","code":"refresh_token_reused"}}"#
            ),
            ProviderRejection {
                status: 401,
                code: ProviderErrorCode::RefreshTokenReused,
                error_type: ProviderErrorType::InvalidRequestError,
                permanent: true,
            }
        );
        assert_eq!(
            classify(400, r#"{"code":"invalid_client"}"#),
            ProviderRejection {
                status: 400,
                code: ProviderErrorCode::InvalidClient,
                error_type: ProviderErrorType::Absent,
                permanent: false,
            }
        );
    }

    #[test]
    fn rejection_reports_unknown_values_only_as_other_or_absent() {
        let rejection = classify(
            403,
            r#"{"error":{"code":"synthetic-secret-code","type":"synthetic-secret-type"}}"#,
        );
        assert_eq!(rejection.code, ProviderErrorCode::Other);
        assert_eq!(rejection.error_type, ProviderErrorType::Other);
        assert!(!rejection.permanent);
        let html = classify(403, "<html>synthetic challenge</html>");
        assert_eq!(html.code, ProviderErrorCode::Absent);
        assert_eq!(html.error_type, ProviderErrorType::Absent);
        assert!(!html.permanent);
        // A 401 is permanent even without a parseable body.
        assert!(classify(401, "").permanent);
        // A server error is never permanent, whatever its body claims.
        assert!(!classify(503, r#"{"error":"invalid_grant"}"#).permanent);
    }

    #[test]
    fn transport_failure_uses_only_flags_and_io_kind() {
        #[derive(Debug)]
        struct Wrapper(io::Error);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("wrapper")
            }
        }
        impl StdError for Wrapper {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.0)
            }
        }
        let unreachable = Wrapper(io::Error::from(io::ErrorKind::NetworkUnreachable));
        assert_eq!(
            TransportFailure::classify(false, true, false, &unreachable),
            (
                TransportFailure::Connect,
                Some(io::ErrorKind::NetworkUnreachable)
            )
        );
        let tls = Wrapper(io::Error::new(io::ErrorKind::InvalidData, "synthetic"));
        assert_eq!(
            TransportFailure::classify(false, true, false, &tls).0,
            TransportFailure::Tls
        );
        let timed_out = Wrapper(io::Error::from(io::ErrorKind::TimedOut));
        assert_eq!(
            TransportFailure::classify(false, true, false, &timed_out).0,
            TransportFailure::Timeout
        );
        assert_eq!(
            TransportFailure::classify(true, false, false, &io::Error::other("synthetic")).0,
            TransportFailure::Timeout
        );
        assert_eq!(
            TransportFailure::classify(false, false, true, &std::fmt::Error),
            (TransportFailure::Request, None)
        );
    }
}
