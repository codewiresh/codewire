use codewire_access::Refusal;
use codewire_daemon_proto::codewire::bridge::v1;

use crate::BrokerRequestError;

/// The closed failure reason every guest decodes; a guest that knows the
/// frame's `refusal` answers from that instead.
pub(super) fn failure_reason(error: BrokerRequestError) -> v1::CredentialBridgeFailureReason {
    match error {
        BrokerRequestError::InvalidRequest
        | BrokerRequestError::Denied
        | BrokerRequestError::ReconnectRequired(_)
        | BrokerRequestError::NotSelected
        | BrokerRequestError::NameNotAllowed
        | BrokerRequestError::SelectedCredentialOnly => v1::CredentialBridgeFailureReason::Denied,
        BrokerRequestError::AuthorityUnavailable
        | BrokerRequestError::RefreshRateLimited { .. } => {
            v1::CredentialBridgeFailureReason::Unavailable
        }
        BrokerRequestError::UpstreamFailed => v1::CredentialBridgeFailureReason::UpstreamFailed,
        BrokerRequestError::ResponseTooLarge => v1::CredentialBridgeFailureReason::ResponseTooLarge,
    }
}

/// A refusal as the bridge protocol carries it. `denied` is left unspecified:
/// the frame's reason already says it, as every guest reads it.
pub(super) fn wire_refusal(refusal: Refusal) -> v1::CredentialBridgeRefusal {
    use v1::CredentialBridgeRefusal as Wire;
    match refusal {
        Refusal::CredentialRevoked => Wire::CredentialRevoked,
        Refusal::CredentialExpired => Wire::CredentialExpired,
        Refusal::CredentialNeedsReconnect => Wire::CredentialNeedsReconnect,
        Refusal::NoCredentialSelected => Wire::NoCredentialSelected,
        Refusal::CredentialUnavailable => Wire::CredentialUnavailable,
        Refusal::CredentialConflict => Wire::CredentialConflict,
        Refusal::PathNotServed => Wire::PathNotServed,
        Refusal::WebsocketNotServed => Wire::WebsocketNotServed,
        Refusal::RouteNotServed => Wire::RouteNotServed,
        Refusal::RequestNotForwarded(_) => Wire::RequestNotForwarded,
        Refusal::BodyTooLarge => Wire::BodyTooLarge,
        Refusal::Busy => Wire::Busy,
        Refusal::UpstreamFailed(_) => Wire::UpstreamFailed,
        Refusal::NameNotAllowed => Wire::NameNotAllowed,
        Refusal::SelectedCredentialOnly => Wire::SelectedCredentialOnly,
        Refusal::Unavailable => Wire::Unavailable,
        Refusal::Denied => Wire::Unspecified,
    }
}
