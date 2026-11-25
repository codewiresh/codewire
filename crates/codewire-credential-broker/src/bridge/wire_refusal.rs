use codewire_credential_bridge::wire_refusal;
use codewire_daemon_proto::codewire::bridge::v1;

use crate::BrokerRequestError;

/// The failure frame for `error`: its closed reason, its refusal, and a rate
/// limit's wait, which only that refusal carries (#4975).
pub(super) fn failure_frame(
    request_id: String,
    error: BrokerRequestError,
) -> v1::CredentialBridgeResponseFailure {
    let refusal = error.refusal();
    v1::CredentialBridgeResponseFailure {
        request_id,
        reason: failure_reason(error) as i32,
        refusal: wire_refusal(refusal) as i32,
        retry_after_seconds: refusal.retry_after_seconds().map_or(0, u32::from),
    }
}

/// The closed failure reason every guest decodes; a guest that knows the
/// frame's `refusal` answers from that instead.
pub(super) fn failure_reason(error: BrokerRequestError) -> v1::CredentialBridgeFailureReason {
    match error {
        BrokerRequestError::InvalidRequest
        | BrokerRequestError::Denied
        | BrokerRequestError::CreatorDeparted
        | BrokerRequestError::CreatorDisabled
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure frame carries the wait only with its own refusal, so an
    /// older guest, which ignores the field, answers unavailable (#4975).
    #[test]
    fn a_rate_limited_failure_frame_carries_its_wait() {
        let frame = failure_frame(
            "request".into(),
            BrokerRequestError::RefreshRateLimited { wait_seconds: 120 },
        );
        assert_eq!(
            frame.refusal,
            v1::CredentialBridgeRefusal::CredentialRefreshRateLimited as i32
        );
        assert_eq!(
            frame.reason,
            v1::CredentialBridgeFailureReason::Unavailable as i32
        );
        assert_eq!(frame.retry_after_seconds, 120);
        let other = failure_frame("request".into(), BrokerRequestError::AuthorityUnavailable);
        assert_eq!(other.retry_after_seconds, 0);
    }

    /// A departed or disabled creator's refusal is a denial with its name
    /// (#6406), so an older guest still reads the frame's reason as one.
    #[test]
    fn a_departed_or_disabled_creator_is_a_named_denial() {
        for (error, refusal) in [
            (
                BrokerRequestError::CreatorDeparted,
                v1::CredentialBridgeRefusal::CredentialOwnerDeparted,
            ),
            (
                BrokerRequestError::CreatorDisabled,
                v1::CredentialBridgeRefusal::CredentialOwnerDisabled,
            ),
        ] {
            let frame = failure_frame("request".into(), error);
            assert_eq!(frame.refusal, refusal as i32, "{error:?}");
            assert_eq!(
                frame.reason,
                v1::CredentialBridgeFailureReason::Denied as i32,
                "{error:?}"
            );
            assert_eq!(frame.retry_after_seconds, 0);
        }
    }
}
