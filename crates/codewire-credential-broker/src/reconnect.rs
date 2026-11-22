//! The answers the broker gives itself on an HTTP route, in the one rendering
//! every managed route uses (`docs/dev/SECRETS-AND-CREDENTIALS.md`,
//! "Refusals an agent or a person can read"). A body names only the provider
//! and the fix: no credential, provider response, account or identifier, and
//! no provider is contacted. The broker knows no bound host, and none of
//! these refusals names one.

use bytes::Bytes;
use codewire_access::{CapabilitySlot, Refusal, RefusalProvider};
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use crate::BrokerHttpResponse;

/// `refusal` for a request on `slot`'s route.
pub(crate) fn refusal_response(refusal: Refusal, slot: &CapabilitySlot) -> BrokerHttpResponse {
    let mut headers = HeaderMap::new();
    for (name, value) in refusal.headers() {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Some(seconds) = refusal.retry_after_seconds() {
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from(seconds));
    }
    let body = Bytes::from(refusal.body(RefusalProvider::for_slot(slot.as_str()), None));
    BrokerHttpResponse::new(
        StatusCode::from_u16(refusal.status()).expect("every refusal status is a valid status"),
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}
