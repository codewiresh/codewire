//! The guest's half of a refusal: the reason a host's failure frame carries,
//! and the one HTTP answer every managed route gives for it
//! (`docs/dev/SECRETS-AND-CREDENTIALS.md`, "Refusals an agent or a person
//! can read").

use axum::body::Body;
use axum::http::{Response, StatusCode};
use codewire_access::{Refusal, RefusalProvider, Unforwarded, UpstreamFailure};
use codewire_daemon_proto::codewire::bridge::v1;

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
    response
        .body(Body::from(refusal.body(provider, host)))
        .expect("a refusal response is valid")
}

/// The refusal a host's failure frame stands for, or `None` for a frame
/// with no valid failure reason. A frame without a refusal comes from an
/// older broker and is answered from its reason alone; a refusal this guest
/// doesn't know comes from a newer one and reads as `unavailable`.
pub(crate) fn from_failure(reason: i32, refusal: i32) -> Option<Refusal> {
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
        Ok(Wire::Unavailable) | Err(_) => Refusal::Unavailable,
    })
}

#[cfg(test)]
mod tests;
