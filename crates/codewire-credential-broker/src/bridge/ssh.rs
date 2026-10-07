//! Typed selected-key dispatch. No provider key or arbitrary agent command is
//! transported here. The authority backend remains disabled by default.

use std::time::Duration;

use codewire_daemon_proto::ssh::{remaining_deadline, validate_request, validate_response};
use tokio::time::Instant;

use super::*;

const FAILURE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) async fn serve<E, S>(
    broker: &E,
    sender: &S,
    request: v1::CredentialSshRequest,
    cancellation: CancellationToken,
) -> Result<(), ()>
where
    E: BrokerRequestExecutor,
    S: CredentialBridgeResponseSink,
{
    let request_id = request.request_id.clone();
    let operation = match validate_request(&request) {
        Ok(operation) => operation,
        Err(_) => return send_failure(sender, request_id, BrokerRequestError::Denied).await,
    };
    let original_deadline = request.deadline_unix_ms;
    let remaining = match remaining_deadline(original_deadline) {
        Ok(remaining) => remaining,
        Err(_) => return send_failure(sender, request_id, BrokerRequestError::Denied).await,
    };
    let deadline = Instant::now() + remaining;
    if cancellation.is_cancelled() {
        return send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable).await;
    }
    let work = broker.execute_ssh(request, cancellation.clone());
    tokio::pin!(work);
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            // Keep the executor waiter and its slot alive until terminal work.
            work.await.map(|_| None)
        }
        _ = tokio::time::sleep_until(deadline) => {
            cancellation.cancel();
            work.await.map(|_| None)
        }
        result = &mut work => result.map(Some),
    };
    let result = match result {
        Ok(Some(result)) => result,
        Ok(None) => {
            return send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable)
                .await;
        }
        Err(error) => {
            send_failure(sender, request_id, error).await?;
            // A failed authority RPC is not proof of remote operation drain.
            // End this epoch so its owner closes/drains the authority channel.
            return if request_failure_ends_epoch(error) {
                Err(())
            } else {
                Ok(())
            };
        }
    };
    let response = v1::CredentialSshResponse {
        request_id: request_id.clone(),
        result: Some(result),
    };
    if cancellation.is_cancelled()
        || Instant::now() >= deadline
        || remaining_deadline(original_deadline).is_err()
    {
        cancellation.cancel();
        return send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable).await;
    }
    if validate_response(&response, operation).is_err() {
        return send_failure(sender, request_id, BrokerRequestError::Denied).await;
    }
    // A queued signature must not outlive its original deadline or a received
    // cancellation while output is backpressured. The failure terminal is also
    // bounded, so an unresponsive consumer cannot hold shutdown indefinitely.
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable).await
        }
        _ = tokio::time::sleep_until(deadline) => {
            cancellation.cancel();
            send_failure(sender, request_id, BrokerRequestError::AuthorityUnavailable).await
        }
        result = sender.send(v1::credential_bridge_host_message::Payload::Ssh(response)) => {
            result.map_err(|_| ())
        }
    }
}

pub(super) async fn send_failure<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    error: BrokerRequestError,
) -> Result<(), ()> {
    let reason = match error {
        BrokerRequestError::Denied
        | BrokerRequestError::InvalidRequest
        | BrokerRequestError::ReconnectRequired => v1::CredentialBridgeFailureReason::Denied,
        BrokerRequestError::AuthorityUnavailable => v1::CredentialBridgeFailureReason::Unavailable,
        BrokerRequestError::UpstreamFailed => v1::CredentialBridgeFailureReason::UpstreamFailed,
        BrokerRequestError::ResponseTooLarge => v1::CredentialBridgeFailureReason::ResponseTooLarge,
    };
    tokio::time::timeout(
        FAILURE_SEND_TIMEOUT,
        sender.send(v1::credential_bridge_host_message::Payload::Ssh(
            v1::CredentialSshResponse {
                request_id,
                result: Some(v1::credential_ssh_response::Result::Failure(reason as i32)),
            },
        )),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}
