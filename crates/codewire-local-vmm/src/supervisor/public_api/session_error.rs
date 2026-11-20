//! How a local session request's daemon status reads to a person.

use codewire_daemon::client::SessionClientError;

pub(super) fn local_session_error(error: SessionClientError) -> connectrpc::ConnectError {
    match error {
        SessionClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => {
                connectrpc::ConnectError::not_found("local environment session was not found")
            }
            tonic::Code::InvalidArgument => connectrpc::ConnectError::invalid_argument(
                "local environment session request is invalid",
            ),
            tonic::Code::Unimplemented => connectrpc::ConnectError::failed_precondition(
                "local environment daemon does not support this session operation",
            ),
            // The daemon refuses a request the session's state can't take,
            // most often input or a resize to a session that has ended. It
            // supports the operation, so never say it doesn't (#5584).
            tonic::Code::FailedPrecondition => connectrpc::ConnectError::failed_precondition(
                "local environment session can't take this request now; it may have ended",
            ),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable(
                    "local environment session transport was lost",
                )
            }
            _ => connectrpc::ConnectError::internal("local environment session request failed"),
        },
        SessionClientError::NotReady { .. } | SessionClientError::MissingCapability { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for sessions",
            )
        }
        SessionClientError::Connect | SessionClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local environment session transport was lost")
        }
        SessionClientError::InvalidEndpoint
        | SessionClientError::InvalidCredential
        | SessionClientError::MissingSessionRecord
        | SessionClientError::InvalidForwardFrame => {
            connectrpc::ConnectError::internal("local environment session request failed")
        }
    }
}
