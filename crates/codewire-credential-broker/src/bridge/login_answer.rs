//! The answer to a Codex or Claude login request.

use super::*;

/// Only a bounded sealed login, DENIED or UNAVAILABLE. DENIED means no login
/// is deliverable now (another credential form, a credential needing
/// Reconnect, a revoked, organization-owned or another user's credential, the
/// agent not selected, or the Sandbox's creator departed or disabled, #6406),
/// so the daemon removes the one it wrote; UNAVAILABLE changes nothing.
///
/// Unlike an HTTP request's `AuthorityUnavailable` (`request_failure_ends_epoch`),
/// neither answer ends the epoch. That is safe only because the platform
/// placement is the one implementing `BrokerLeaseProvider::lease_codex_login`
/// and `lease_claude_login`: a refresh the login started is drained by the
/// shared refresh owner, and a refresh Start that fails is fenced by the
/// platform store's durable reservation and execution deadlines rather than by
/// this epoch's lease channel. A local placement whose reservations are
/// released when its lease channel closes (see `complete_oauth_refresh`) must
/// revisit this before implementing either.
pub(super) async fn send_login_response<S: CredentialBridgeResponseSink>(
    sender: &S,
    kind: LoginKind,
    request_id: String,
    response: Result<Vec<u8>, BrokerRequestError>,
) -> Result<(), ()> {
    let max_sealed_bytes = match kind {
        LoginKind::Codex => MAX_SEALED_CODEX_LOGIN_BYTES,
        LoginKind::Claude => MAX_SEALED_CLAUDE_LOGIN_BYTES,
    };
    let result = match response {
        Ok(sealed) if !sealed.is_empty() && sealed.len() <= max_sealed_bytes => Ok(sealed),
        Ok(_)
        | Err(
            BrokerRequestError::InvalidRequest
            | BrokerRequestError::Denied
            | BrokerRequestError::CreatorDeparted
            | BrokerRequestError::CreatorDisabled
            | BrokerRequestError::ReconnectRequired(_)
            | BrokerRequestError::NotSelected
            | BrokerRequestError::NameNotAllowed
            | BrokerRequestError::SelectedCredentialOnly,
        ) => Err(v1::CredentialBridgeFailureReason::Denied as i32),
        Err(
            BrokerRequestError::AuthorityUnavailable
            | BrokerRequestError::RefreshRateLimited { .. }
            | BrokerRequestError::UpstreamFailed
            | BrokerRequestError::ResponseTooLarge,
        ) => Err(v1::CredentialBridgeFailureReason::Unavailable as i32),
    };
    let payload = match kind {
        LoginKind::Codex => {
            use v1::codex_login_response::Result as LoginResult;
            v1::credential_bridge_host_message::Payload::CodexLogin(v1::CodexLoginResponse {
                request_id,
                result: Some(match result {
                    Ok(sealed) => LoginResult::SealedLogin(sealed),
                    Err(reason) => LoginResult::Failure(reason),
                }),
            })
        }
        LoginKind::Claude => {
            use v1::claude_login_response::Result as LoginResult;
            v1::credential_bridge_host_message::Payload::ClaudeLogin(v1::ClaudeLoginResponse {
                request_id,
                result: Some(match result {
                    Ok(sealed) => LoginResult::SealedLogin(sealed),
                    Err(reason) => LoginResult::Failure(reason),
                }),
            })
        }
    };
    sender.send(payload).await.map_err(|_| ())
}
