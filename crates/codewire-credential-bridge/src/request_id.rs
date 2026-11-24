//! The id a TLS front door gives one intercepted request (#4001, #6181).
//!
//! The front door mints it, puts it in the request's extensions, and names it
//! in the [`REQUEST_ID_HEADER`] of whatever it answers, its own refusals
//! included. The bridge's frame for the request carries the same id, so the
//! credential service's timing line for it does too. A client's own
//! `codewire-request-id` is dropped before the frame is built, and the
//! response's header is the front door's, never the client's or the
//! provider's.
//!
//! The id is a v4 UUID from the OS CSPRNG: random per request, never a
//! counter, and derived from no environment, Pod, binding, credential or
//! epoch id. Knowing one grants nothing: the agent never speaks the bridge
//! protocol, and no frame, cancel or route takes an id from it.

use axum::http::{HeaderName, HeaderValue, Request, Response};
use uuid::Uuid;

/// The response header that names the intercepted request it answers.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("codewire-request-id");

/// A front door's id for one intercepted request, in its extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontDoorRequestId(Uuid);

impl FrontDoorRequestId {
    /// A fresh id, unrelated to any other.
    pub fn mint() -> Self {
        Self(Uuid::new_v4())
    }

    /// `response` naming this id, in place of any value it had.
    pub fn name_in<B>(self, mut response: Response<B>) -> Response<B> {
        let value = HeaderValue::try_from(self.0.to_string())
            .expect("a UUID's canonical form is a valid header value");
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
        response
    }
}

/// The front door's id for `request`, or a fresh one where no front door
/// named it (a loopback or local request, which never answers with it).
pub(crate) fn request_id_of<B>(request: &Request<B>) -> Uuid {
    request
        .extensions()
        .get::<FrontDoorRequestId>()
        .map_or_else(Uuid::new_v4, |id| id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_front_doors_id_is_the_frames_and_a_fresh_one_otherwise() {
        let id = FrontDoorRequestId::mint();
        let mut named = Request::new(());
        named.extensions_mut().insert(id);
        assert_eq!(request_id_of(&named), id.0);
        assert_ne!(request_id_of(&Request::new(())), id.0);
        assert_ne!(FrontDoorRequestId::mint(), FrontDoorRequestId::mint());
    }

    #[test]
    fn the_header_replaces_any_value_the_response_had() {
        let id = FrontDoorRequestId::mint();
        let response = Response::builder()
            .header(REQUEST_ID_HEADER, "the-providers")
            .header(REQUEST_ID_HEADER, "another")
            .body(())
            .unwrap();
        let named = id.name_in(response);
        let values = named
            .headers()
            .get_all(REQUEST_ID_HEADER)
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(values, [id.0.to_string().as_str()]);
    }

    /// The id's randomness is the OS CSPRNG's: uuid's `fast-rng` feature,
    /// which would draw it from a userspace generator instead, stays off.
    #[test]
    fn uuid_draws_from_the_os_csprng() {
        let lock = include_str!("../../../Cargo.lock");
        let entry = lock
            .split("\n[[package]]\n")
            .find(|package| package.starts_with("name = \"uuid\"\n"))
            .expect("uuid is in the workspace lock");
        assert!(entry.contains("\"getrandom"), "uuid draws from getrandom");
        assert!(
            !entry
                .lines()
                .any(|line| line.trim_start().starts_with("\"rand")),
            "uuid's fast-rng feature is on"
        );
    }
}
