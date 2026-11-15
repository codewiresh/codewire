//! The public API's error for a failed local supervisor call.

pub(super) fn local_status(status: tonic::Status) -> connectrpc::ConnectError {
    let (code, message) = match status.code() {
        tonic::Code::Cancelled => (
            connectrpc::ErrorCode::Canceled,
            "local request was canceled",
        ),
        tonic::Code::InvalidArgument => (
            connectrpc::ErrorCode::InvalidArgument,
            "local request is invalid",
        ),
        tonic::Code::NotFound => (
            connectrpc::ErrorCode::NotFound,
            "local environment was not found",
        ),
        tonic::Code::AlreadyExists => (
            connectrpc::ErrorCode::AlreadyExists,
            "local environment already exists",
        ),
        tonic::Code::FailedPrecondition => (
            connectrpc::ErrorCode::FailedPrecondition,
            "local environment is not in the required state",
        ),
        tonic::Code::Aborted => (
            connectrpc::ErrorCode::Aborted,
            "local request conflicts with durable state",
        ),
        tonic::Code::OutOfRange => (
            connectrpc::ErrorCode::OutOfRange,
            "local request is out of range",
        ),
        tonic::Code::Unimplemented => (
            connectrpc::ErrorCode::Unimplemented,
            "local operation is not implemented",
        ),
        tonic::Code::Unavailable => (
            connectrpc::ErrorCode::Unavailable,
            "local supervisor is unavailable",
        ),
        tonic::Code::DeadlineExceeded => (
            connectrpc::ErrorCode::DeadlineExceeded,
            "local request deadline was exceeded",
        ),
        _ => (
            connectrpc::ErrorCode::Internal,
            "local supervisor request failed",
        ),
    };
    connectrpc::ConnectError::new(code, message)
}
