//! The error wire bridge: 01's renderer onto the Connect wire (D4).

use super::*;
use crate::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

/// Renders an [`AppError`] onto the Connect wire via 01's renderer: D2 code
/// mapping, D3 field paths, D4 `ErrorInfo` (reason/hint/`request_id`), with
/// details protobuf-encoded from the vendored `google.rpc` types.
pub fn app_error_to_wire(err: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    wire_error(&ConnectError::from_app_error(err, request_id))
}

/// [`app_error_to_wire`] for Connect handlers: pulls the request id from the
/// dispatcher's [`connectrpc::RequestContext`] headers (minted by the
/// standard middleware stack, D7).
pub fn rpc_app_error(err: &AppError, ctx: &connectrpc::RequestContext) -> connectrpc::ConnectError {
    let request_id = ctx
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok());
    app_error_to_wire(err, request_id)
}

/// Converts 01's transport-agnostic [`ConnectError`] into connectrpc's wire
/// error: canonical code, message, and `details` entries carrying the bare
/// fully-qualified type name plus the base64-encoded protobuf value — the
/// Connect protocol's JSON error shape.
pub fn wire_error(rendered: &ConnectError) -> connectrpc::ConnectError {
    let mut wire =
        connectrpc::ConnectError::new(wire_code(rendered.code), rendered.message.clone());
    for detail in &rendered.details {
        wire = wire.with_detail(wire_detail(detail));
    }
    wire
}

/// 01's [`ConnectCode`] → connectrpc's wire enum (same 16 canonical codes).
fn wire_code(code: ConnectCode) -> connectrpc::ErrorCode {
    match code {
        ConnectCode::Canceled => connectrpc::ErrorCode::Canceled,
        ConnectCode::Unknown => connectrpc::ErrorCode::Unknown,
        ConnectCode::InvalidArgument => connectrpc::ErrorCode::InvalidArgument,
        ConnectCode::DeadlineExceeded => connectrpc::ErrorCode::DeadlineExceeded,
        ConnectCode::NotFound => connectrpc::ErrorCode::NotFound,
        ConnectCode::AlreadyExists => connectrpc::ErrorCode::AlreadyExists,
        ConnectCode::PermissionDenied => connectrpc::ErrorCode::PermissionDenied,
        ConnectCode::ResourceExhausted => connectrpc::ErrorCode::ResourceExhausted,
        ConnectCode::FailedPrecondition => connectrpc::ErrorCode::FailedPrecondition,
        ConnectCode::Aborted => connectrpc::ErrorCode::Aborted,
        ConnectCode::OutOfRange => connectrpc::ErrorCode::OutOfRange,
        ConnectCode::Unimplemented => connectrpc::ErrorCode::Unimplemented,
        ConnectCode::Internal => connectrpc::ErrorCode::Internal,
        ConnectCode::Unavailable => connectrpc::ErrorCode::Unavailable,
        ConnectCode::DataLoss => connectrpc::ErrorCode::DataLoss,
        ConnectCode::Unauthenticated => connectrpc::ErrorCode::Unauthenticated,
    }
}

/// Encodes one typed detail carrier as a Connect wire detail. The `type`
/// field carries the bare fully-qualified message name (the Connect JSON
/// convention; the gRPC path re-adds the `type.googleapis.com/` prefix),
/// `value` the base64 of the protobuf encoding.
fn wire_detail(detail: &ConnectErrorDetail) -> connectrpc::ErrorDetail {
    use codewire_proto::google::rpc;

    let bare_name = detail
        .type_url()
        .rsplit('/')
        .next()
        .expect("rsplit yields at least one segment");
    match detail {
        ConnectErrorDetail::BadRequest(bad) => {
            let msg = rpc::BadRequest {
                field_violations: bad
                    .field_violations
                    .iter()
                    .map(|v| rpc::bad_request::FieldViolation {
                        field: v.field.clone(),
                        description: v.description.clone(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
        ConnectErrorDetail::ErrorInfo(info) => {
            let mut msg = rpc::ErrorInfo {
                reason: info.reason.clone(),
                domain: info.domain.clone(),
                ..Default::default()
            };
            msg.metadata
                .extend(info.metadata.iter().map(|(k, v)| (k.clone(), v.clone())));
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
        ConnectErrorDetail::RetryInfo(retry) => {
            let msg = rpc::RetryInfo {
                retry_delay: buffa::MessageField::some(buffa_types::google::protobuf::Duration {
                    seconds: retry.retry_delay.as_secs() as i64,
                    nanos: retry.retry_delay.subsec_nanos() as i32,
                    ..Default::default()
                }),
                ..Default::default()
            };
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every canonical code crosses the bridge to the same wire spelling.
    #[test]
    fn wire_code_bridge_is_total_and_name_preserving() {
        let codes = [
            ConnectCode::Canceled,
            ConnectCode::Unknown,
            ConnectCode::InvalidArgument,
            ConnectCode::DeadlineExceeded,
            ConnectCode::NotFound,
            ConnectCode::AlreadyExists,
            ConnectCode::PermissionDenied,
            ConnectCode::ResourceExhausted,
            ConnectCode::FailedPrecondition,
            ConnectCode::Aborted,
            ConnectCode::OutOfRange,
            ConnectCode::Unimplemented,
            ConnectCode::Internal,
            ConnectCode::Unavailable,
            ConnectCode::DataLoss,
            ConnectCode::Unauthenticated,
        ];
        for code in codes {
            assert_eq!(code.as_str(), wire_code(code).as_str(), "{code:?}");
        }
    }

    /// BadRequest field violations survive the wire encoding (D2's 422 row
    /// end to end: renderer carrier → protobuf detail → decode).
    #[test]
    fn bad_request_detail_round_trips() {
        use crate::connect_error::{BadRequest, FieldViolation};
        use base64::Engine;

        let detail = ConnectErrorDetail::BadRequest(BadRequest {
            field_violations: vec![
                FieldViolation {
                    field: "spec.name".into(),
                    description: "missing required property".into(),
                },
                FieldViolation {
                    field: "ports[0].target".into(),
                    description: "must be >= 1".into(),
                },
            ],
        });
        let wire = wire_detail(&detail);
        assert_eq!(wire.type_url, "google.rpc.BadRequest");

        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(wire.value.expect("value"))
            .expect("base64");
        let decoded: codewire_proto::google::rpc::BadRequest =
            buffa::Message::decode_from_slice(&bytes).expect("protobuf BadRequest");
        assert_eq!(decoded.field_violations.len(), 2);
        assert_eq!(decoded.field_violations[0].field, "spec.name");
        assert_eq!(
            decoded.field_violations[0].description,
            "missing required property"
        );
        assert_eq!(decoded.field_violations[1].field, "ports[0].target");
    }

    /// RetryInfo carries the delay as a google.protobuf.Duration.
    #[test]
    fn retry_info_detail_round_trips() {
        use base64::Engine;
        use std::time::Duration;

        let detail = ConnectErrorDetail::RetryInfo(crate::connect_error::RetryInfo {
            retry_delay: Duration::new(60, 250_000_000),
        });
        let wire = wire_detail(&detail);
        assert_eq!(wire.type_url, "google.rpc.RetryInfo");

        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(wire.value.expect("value"))
            .expect("base64");
        let decoded: codewire_proto::google::rpc::RetryInfo =
            buffa::Message::decode_from_slice(&bytes).expect("protobuf RetryInfo");
        let delay = decoded.retry_delay.as_option().expect("retry_delay set");
        assert_eq!(delay.seconds, 60);
        assert_eq!(delay.nanos, 250_000_000);
    }
}
