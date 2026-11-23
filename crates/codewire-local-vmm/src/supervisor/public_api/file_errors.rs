//! How a local file operation's daemon error reaches the caller: a fixed reply
//! per kind of failure, so no guest text is shown (#4139).

use codewire_daemon_bridge::client::DaemonClientError;

pub(super) fn local_file_error(error: DaemonClientError) -> connectrpc::ConnectError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => {
                connectrpc::ConnectError::not_found("local file was not found")
            }
            // The daemon's fixed message for a path through another mount is
            // matched exactly and answered in the host's own words (#4139).
            tonic::Code::PermissionDenied
                if status.message() == codewire_daemon::service::NESTED_MOUNT_STATUS =>
            {
                connectrpc::ConnectError::invalid_argument(
                    "local file path runs through a separate mount inside the workspace, \
                     which file copy does not enter; it reaches the workspace, its live \
                     shares and the folders kept on the VM's disk",
                )
            }
            tonic::Code::InvalidArgument | tonic::Code::PermissionDenied => {
                connectrpc::ConnectError::invalid_argument("local file path is invalid or denied")
            }
            tonic::Code::AlreadyExists => {
                connectrpc::ConnectError::already_exists("local file already exists")
            }
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => {
                connectrpc::ConnectError::failed_precondition(
                    "local environment daemon does not support this file operation",
                )
            }
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable("local file transport was lost")
            }
            _ => connectrpc::ConnectError::internal("local file request failed"),
        },
        DaemonClientError::NotReady { .. }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for files",
            )
        }
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local file transport was lost")
        }
        DaemonClientError::InvalidEndpoint
        | DaemonClientError::InvalidCredential
        | DaemonClientError::MissingResponse(_)
        | DaemonClientError::InvalidFrame(_)
        | DaemonClientError::Remote(_) => {
            connectrpc::ConnectError::internal("local file request failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_daemons_exact_nested_mount_status_gets_its_own_reply() {
        let nested = local_file_error(DaemonClientError::Status(tonic::Status::permission_denied(
            codewire_daemon::service::NESTED_MOUNT_STATUS,
        )));
        assert!(
            nested
                .message
                .as_deref()
                .unwrap()
                .contains("separate mount")
        );
        // Any other guest text, however close, gets the generic reply and is
        // never shown (#4139).
        for message in [
            "path crosses a separate mount inside the workspace: /etc",
            "denied",
        ] {
            let other = local_file_error(DaemonClientError::Status(
                tonic::Status::permission_denied(message),
            ));
            assert_eq!(
                other.message.as_deref(),
                Some("local file path is invalid or denied")
            );
        }
    }

    #[test]
    fn a_missing_path_is_not_found_and_an_outside_one_is_refused() {
        let missing = local_file_error(DaemonClientError::Status(tonic::Status::not_found(
            "guest detail",
        )));
        assert_eq!(missing.code, connectrpc::ErrorCode::NotFound);
        assert_eq!(missing.message.as_deref(), Some("local file was not found"));
        let outside = local_file_error(DaemonClientError::Status(tonic::Status::invalid_argument(
            "guest detail",
        )));
        assert_eq!(outside.code, connectrpc::ErrorCode::InvalidArgument);
    }
}
