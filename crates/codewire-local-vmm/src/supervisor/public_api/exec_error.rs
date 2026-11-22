//! A local exec's failure as the public API answers it: fixed messages, never
//! the guest's own text.

use codewire_daemon_bridge::client::DaemonClientError;

pub(super) fn local_exec_error(error: DaemonClientError) -> connectrpc::ConnectError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::InvalidArgument => {
                connectrpc::ConnectError::invalid_argument("local command request is invalid")
            }
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => {
                connectrpc::ConnectError::failed_precondition(
                    "local environment daemon does not support this command operation",
                )
            }
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable(
                    "local environment command transport was lost",
                )
            }
            _ => connectrpc::ConnectError::internal("local environment command failed"),
        },
        DaemonClientError::NotReady { .. }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for commands",
            )
        }
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local environment command transport was lost")
        }
        // The guest's launch never got its projection from the credential
        // broker: it was not answered in time, or refused (#5866).
        DaemonClientError::Remote(message)
            if message == codewire_daemon_proto::LAUNCH_PROJECTION_DENIED =>
        {
            connectrpc::ConnectError::unavailable(crate::public_client::LAUNCH_VALUES_UNAVAILABLE)
        }
        DaemonClientError::Remote(_) => {
            connectrpc::ConnectError::failed_precondition("local environment command failed")
        }
        DaemonClientError::InvalidEndpoint
        | DaemonClientError::InvalidCredential
        | DaemonClientError::MissingResponse(_)
        | DaemonClientError::InvalidFrame(_) => {
            connectrpc::ConnectError::internal("local environment command failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A launch the credential broker never served is said as that; any
    /// other text the guest sends stays the generic failure (#5866).
    #[test]
    fn a_launch_without_its_values_is_said_and_other_guest_text_is_not() {
        let unserved = local_exec_error(DaemonClientError::Remote(
            codewire_daemon_proto::LAUNCH_PROJECTION_DENIED.to_owned(),
        ));
        assert_eq!(unserved.code, connectrpc::ErrorCode::Unavailable);
        assert_eq!(
            unserved.message.as_deref(),
            Some(crate::public_client::LAUNCH_VALUES_UNAVAILABLE)
        );
        for text in ["exec failed", "environment launch denied", ""] {
            let other = local_exec_error(DaemonClientError::Remote(text.to_owned()));
            assert_eq!(
                other.code,
                connectrpc::ErrorCode::FailedPrecondition,
                "{text}"
            );
            assert_eq!(
                other.message.as_deref(),
                Some("local environment command failed")
            );
        }
    }
}
