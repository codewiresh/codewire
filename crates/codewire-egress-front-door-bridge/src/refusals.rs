//! What a front door reports of the requests it refuses (#5058): for each,
//! the route's bound host and port and the refusal's code, and nothing of
//! the request or of the answer. That is its own refusals (a path the route
//! doesn't serve, a request it doesn't forward) and each the credential
//! broker answers with. A local front door hands them to its runner; a
//! hosted one reports none.

use std::sync::Arc;

use axum::body::Body;
use codewire_access::{REFUSAL_HEADER, Refusal, RefusalCode};
use codewire_credential_bridge::AnsweredRefusal;
use http::Response;

use crate::{INTERCEPT_PORT, RouteTable};

/// Where a front door's refusals go. `host` is a host or suffix of the
/// front door's own route table, never a name a request gave.
pub trait RefusalSink: Send + Sync + 'static {
    fn refused(&self, host: &str, port: u16, code: RefusalCode);
}

/// The refusals the credential broker answers itself as an ordinary
/// response rather than a failure frame (its `reconnect` answers, 403, and
/// a placeholder sent beside another credential, 400), which the front door
/// can tell only by their status and header.
const BROKER_ANSWERED: [Refusal; 5] = [
    Refusal::NoCredentialSelected,
    Refusal::CredentialRevoked,
    Refusal::CredentialExpired,
    Refusal::CredentialNeedsReconnect,
    Refusal::CredentialConflict,
];

/// Bound-secret refusals the credential broker answers itself as 403
/// responses with `Codewire-Refusal`, reported to the local refusal log
/// under the route's bound host name (#4003).
const BROKER_ANSWERED_BOUND_SECRET: [RefusalCode; 4] = [
    RefusalCode::PlaceholderOutsideBinding,
    RefusalCode::SecretNotBoundToHost,
    RefusalCode::SecretBindingChanged,
    RefusalCode::SecretDeleted,
];

/// The refusal `response` answers, if it is one: one the bridge or the
/// front door rendered, or one of [`BROKER_ANSWERED`] /
/// [`BROKER_ANSWERED_BOUND_SECRET`] by its status and header. Any other
/// response is not a refusal.
pub(crate) fn refusal_of(response: &Response<Body>) -> Option<RefusalCode> {
    if let Some(AnsweredRefusal(refusal)) = response.extensions().get::<AnsweredRefusal>() {
        return Some(refusal.code());
    }
    let header = response.headers().get(REFUSAL_HEADER)?.to_str().ok()?;
    let code = RefusalCode::from_code(header)?;
    let status = response.status().as_u16();
    (BROKER_ANSWERED
        .iter()
        .any(|refusal| refusal.code() == code && refusal.status() == status)
        || (status == 403 && BROKER_ANSWERED_BOUND_SECRET.contains(&code)))
    .then_some(code)
}

impl RouteTable {
    /// The table's own name for a request to `host`: the exact host a route
    /// names, or the suffix `host` is one label under, as the table routes
    /// it. `None` for any other.
    pub(crate) fn bound_name(&self, host: &str) -> Option<&str> {
        if let Some(route) = self.routes.iter().find(|route| route.host == host) {
            return Some(&route.host);
        }
        self.suffixes
            .iter()
            .find(|route| codewire_access::one_label_under(host, &route.host))
            .map(|route| route.host.as_str())
    }
}

/// Reports one refusal on `host` to `sink`, under the table's own name.
pub(crate) fn note(
    sink: Option<&Arc<dyn RefusalSink>>,
    routes: &RouteTable,
    host: &str,
    code: RefusalCode,
) {
    if let (Some(sink), Some(bound)) = (sink, routes.bound_name(host)) {
        sink.refused(bound, INTERCEPT_PORT, code);
    }
}
