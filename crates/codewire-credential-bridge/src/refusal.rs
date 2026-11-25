//! The guest's half of a refusal: the reason a host's failure frame carries,
//! and the one HTTP answer every managed route gives for it
//! (`docs/dev/SECRETS-AND-CREDENTIALS.md`, "Refusals an agent or a person
//! can read").

use axum::body::Body;
use axum::http::{Response, StatusCode};
use codewire_access::{Refusal, RefusalProvider, Unforwarded, UpstreamFailure};
use codewire_daemon_proto::codewire::bridge::v1;

/// Set on every response [`refusal_response`] makes, and on no other: the
/// refusal it answers, for a front door that reports its refusals (#5058).
/// Nothing a host or a provider sends can set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnsweredRefusal(pub Refusal);

/// The answer to a refused request. `host` is the canonical bound name the
/// front door intercepted, `None` on the loopback ingress.
pub fn refusal_response(
    refusal: Refusal,
    provider: Option<RefusalProvider>,
    host: Option<&str>,
) -> Response<Body> {
    let mut response = Response::builder().status(
        StatusCode::from_u16(refusal.status()).expect("every refusal status is a valid status"),
    );
    for (name, value) in refusal.headers() {
        response = response.header(name, value);
    }
    if let Some(seconds) = refusal.retry_after_seconds() {
        response = response.header("retry-after", seconds.to_string());
    }
    response
        .extension(AnsweredRefusal(refusal))
        .body(Body::from(refusal.body(provider, host)))
        .expect("a refusal response is valid")
}

/// The refusal a host's failure frame stands for, or `None` for a frame
/// with no valid failure reason. A frame without a refusal comes from an
/// older broker and is answered from its reason alone; a refusal this guest
/// doesn't know comes from a newer one and reads as `unavailable`. A rate
/// limit's wait outside 60 to 600 seconds, or none, reads as `unavailable`
/// too (#4975).
pub(crate) fn from_failure(reason: i32, refusal: i32, retry_after_seconds: u32) -> Option<Refusal> {
    use v1::CredentialBridgeFailureReason as Reason;
    use v1::CredentialBridgeRefusal as Wire;

    let reason = match Reason::try_from(reason) {
        Ok(Reason::Unspecified) | Err(_) => return None,
        Ok(reason) => reason,
    };
    Some(match Wire::try_from(refusal) {
        Ok(Wire::Unspecified) => match reason {
            Reason::Denied => Refusal::Denied,
            Reason::Unavailable => Refusal::CredentialUnavailable,
            Reason::UpstreamFailed | Reason::ResponseTooLarge => {
                Refusal::UpstreamFailed(UpstreamFailure::Failed)
            }
            Reason::Unspecified => return None,
        },
        Ok(Wire::CredentialRevoked) => Refusal::CredentialRevoked,
        Ok(Wire::CredentialExpired) => Refusal::CredentialExpired,
        Ok(Wire::CredentialNeedsReconnect) => Refusal::CredentialNeedsReconnect,
        Ok(Wire::NoCredentialSelected) => Refusal::NoCredentialSelected,
        Ok(Wire::CredentialUnavailable) => Refusal::CredentialUnavailable,
        Ok(Wire::CredentialRefreshRateLimited) => match u16::try_from(retry_after_seconds) {
            Ok(seconds @ 60..=600) => Refusal::CredentialRefreshRateLimited {
                retry_after_seconds: seconds,
            },
            _ => Refusal::CredentialUnavailable,
        },
        Ok(Wire::CredentialConflict) => Refusal::CredentialConflict,
        Ok(Wire::PathNotServed) => Refusal::PathNotServed,
        Ok(Wire::WebsocketNotServed) => Refusal::WebsocketNotServed,
        Ok(Wire::RouteNotServed) => Refusal::RouteNotServed,
        Ok(Wire::RequestNotForwarded) => Refusal::RequestNotForwarded(Unforwarded::Refused),
        Ok(Wire::BodyTooLarge) => Refusal::BodyTooLarge,
        Ok(Wire::Busy) => Refusal::Busy,
        Ok(Wire::UpstreamFailed) => Refusal::UpstreamFailed(UpstreamFailure::Failed),
        Ok(Wire::NameNotAllowed) => Refusal::NameNotAllowed,
        Ok(Wire::SelectedCredentialOnly) => Refusal::SelectedCredentialOnly,
        Ok(Wire::CredentialOwnerDeparted) => Refusal::CredentialOwnerDeparted,
        Ok(Wire::CredentialOwnerDisabled) => Refusal::CredentialOwnerDisabled,
        Ok(Wire::Unavailable) | Err(_) => Refusal::Unavailable,
    })
}

/// A refusal as the bridge protocol carries it. `denied` is left unspecified:
/// a failure frame's reason already says it, as every guest reads it.
pub fn to_wire(refusal: Refusal) -> v1::CredentialBridgeRefusal {
    use v1::CredentialBridgeRefusal as Wire;
    match refusal {
        Refusal::CredentialRevoked => Wire::CredentialRevoked,
        Refusal::CredentialExpired => Wire::CredentialExpired,
        Refusal::CredentialNeedsReconnect => Wire::CredentialNeedsReconnect,
        Refusal::NoCredentialSelected => Wire::NoCredentialSelected,
        Refusal::CredentialUnavailable => Wire::CredentialUnavailable,
        Refusal::CredentialRefreshRateLimited { .. } => Wire::CredentialRefreshRateLimited,
        Refusal::CredentialConflict => Wire::CredentialConflict,
        Refusal::PathNotServed => Wire::PathNotServed,
        Refusal::WebsocketNotServed => Wire::WebsocketNotServed,
        Refusal::RouteNotServed | Refusal::RouteLost => Wire::RouteNotServed,
        Refusal::RequestNotForwarded(_) => Wire::RequestNotForwarded,
        Refusal::BodyTooLarge => Wire::BodyTooLarge,
        Refusal::Busy => Wire::Busy,
        Refusal::UpstreamFailed(_) => Wire::UpstreamFailed,
        Refusal::NameNotAllowed => Wire::NameNotAllowed,
        Refusal::SelectedCredentialOnly => Wire::SelectedCredentialOnly,
        Refusal::Unavailable => Wire::Unavailable,
        Refusal::Denied => Wire::Unspecified,
        Refusal::CredentialOwnerDeparted => Wire::CredentialOwnerDeparted,
        Refusal::CredentialOwnerDisabled => Wire::CredentialOwnerDisabled,
    }
}

/// What a guest keeps of an epoch's refused admission (#6406): a 403 refusal
/// as itself, and anything else, a value it doesn't know included, as a
/// plain denial. A refused epoch never reads as one worth retrying with
/// material, so a guest that keeps it answers nothing of the epoch's.
pub fn epoch_refusal(refusal: i32) -> Refusal {
    match from_failure(v1::CredentialBridgeFailureReason::Denied as i32, refusal, 0) {
        Some(refusal) if refusal.status() == 403 => refusal,
        _ => Refusal::Denied,
    }
}

#[cfg(test)]
mod tests;
