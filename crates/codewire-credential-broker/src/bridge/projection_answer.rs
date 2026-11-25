//! The answer to an environment projection request.

use super::*;

/// A bounded sealed projection, or a closed failure: DENIED for a denial,
/// whatever its cause, UNAVAILABLE otherwise.
pub(super) async fn send_projection_response<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    response: Result<Vec<u8>, BrokerRequestError>,
) -> Result<(), ()> {
    use v1::environment_projection_response::Result as ProjectionResult;
    let result = match response {
        Ok(sealed)
            if !sealed.is_empty() && sealed.len() <= MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES =>
        {
            ProjectionResult::SealedProjection(sealed)
        }
        Ok(_) => {
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::ResponseTooLarge as i32)
        }
        Err(
            BrokerRequestError::InvalidRequest
            | BrokerRequestError::Denied
            | BrokerRequestError::CreatorDeparted
            | BrokerRequestError::CreatorDisabled,
        ) => ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
        Err(_) => ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32),
    };
    sender
        .send(
            v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionResponse {
                    request_id,
                    result: Some(result),
                },
            ),
        )
        .await
        .map_err(|_| ())
}
