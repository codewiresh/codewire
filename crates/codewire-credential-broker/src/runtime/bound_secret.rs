//! The front door's swap for a host-bound application secret (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap").
//!
//! A request reaches here only on a front-door session, for a host the
//! Pod's own route table gives a bound-secret route. The secret is chosen
//! from the epoch's grants by the placeholder the request carries, never by
//! anything the frame names. In order:
//!
//! 1. A request that carries none of the environment's bound-secret
//!    placeholders is an untouched forward, which a hosted broker refuses
//!    (`selected_credential_only`, #5555).
//! 2. Two secrets' placeholders are `credential_conflict`; one whose record
//!    doesn't name this host is `secret_not_bound_to_host`.
//! 3. The lease rereads the secret's row and checks it against the record:
//!    `secret_not_bound_to_host`, `secret_binding_changed`, `secret_deleted`.
//! 4. The placeholder anywhere but the bound header, in the binding's exact
//!    shape, is `placeholder_outside_binding`; the bound header twice, the
//!    placeholder twice, or another credential beside it is
//!    `credential_conflict`. Nothing refused is ever sent.
//! 5. Otherwise the value is decrypted for this lease, swapped into the
//!    bound header, and sent with `accept-encoding: identity` to the address
//!    the egress broker admitted. The reply is redacted of the value in its
//!    raw, JSON-escaped, percent-encoded and base64 forms, and a reply in
//!    another content coding is refused (`upstream_failed`).
//!
//! Each request that names a secret writes one closed audit line.

mod scan;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};

use av_credential_proxy::RedactionSet;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use codewire_access::{
    BoundSecretRefusal, FirstBindSecret, HostBinding, Presentation, Scheme, SecretKind,
};
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use url::Url;
use zeroize::Zeroizing;

use super::swap::credential_conflict_response;
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError,
    BrokerUpstreamBody, BrokerUpstreamRequest, BrokerUpstreamTransport, OpenAiBroker, Phase,
    ProviderStreamingResponse, ValidatedGuestRequest, map_adapter_error, map_upstream_error,
    timing,
};
use crate::PreparedOpenAiResponse;
use crate::bound_secret::{BoundSecretLeaseError, BoundSecretSwap};
use crate::transparent::without_framing;

/// The most a bound host's reply may carry, as for the providers' routes.
const MAX_RESPONSE_BYTES: usize = crate::openai::MAX_RESPONSE_BYTES;

/// The port every bound host is served on.
const BOUND_PORT: u16 = 443;

/// A front-door request to a bound secret's host, as the frame named it and
/// the address its dial was admitted to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundDial {
    pub(crate) host: String,
    pub(crate) destination: Option<IpAddr>,
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A front-door request to `dial`'s host under the bound-secret swap.
    /// See the module documentation for the rule.
    pub(super) async fn execute_bound_secret(
        &self,
        dial: BoundDial,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let grants = self
            .leases
            .bound_secrets()
            .map_err(|_| BrokerRequestError::AuthorityUnavailable)?;
        let carried = scan::Carried {
            headers: &request.headers,
            query: request.query.as_deref(),
            body: &request.body,
        };
        let found = scan::find(&carried, grants);
        let grant = match scan::candidate(&found) {
            scan::Candidate::None => {
                let target = bound_target(&dial.host, &request.path, request.query.as_deref())?;
                self.untouched_forward_allowed(&target, false)?;
                let (status, headers, body) =
                    self.send(&dial, target, request, without_framing).await?;
                return Ok(BrokerHttpResponse::new(
                    status,
                    without_framing(&headers),
                    super::swap::forwarded_body(body, MAX_RESPONSE_BYTES),
                ));
            }
            scan::Candidate::Conflict => return Ok(credential_conflict_response()),
            scan::Candidate::Secret(index) => &grants[index],
        };
        let audit = Audit::new(&self.leases, &grant.record, &dial.host);
        if !grant.record.names(&dial.host) {
            return Ok(audit.refused(not_bound(&grant.record, &dial.host), "unread"));
        }
        let row = match self
            .leases
            .lease_bound_secret_row(&grant.record, &dial.host)
            .await
        {
            Ok(row) => row,
            Err(error) => return audit.lease_failed(error, &dial.host, "unread"),
        };
        let presentation = presentation_name(row.binding.presentation());
        let swapped = match scan::decide(&carried, &found, grant, &row.binding) {
            scan::Decision::Swap(swapped) => swapped,
            scan::Decision::Outside(sent) => {
                let refusal = BoundSecretRefusal::OutsideBinding {
                    key: grant.record.key.clone(),
                    kind: kind(&grant.record),
                    host: dial.host.clone(),
                    bound_header: bound_header_name(&row.binding),
                    sent,
                };
                return Ok(audit.refused(refusal, presentation));
            }
            scan::Decision::Conflict => {
                audit.write(presentation, "credential_conflict");
                return Ok(credential_conflict_response());
            }
        };
        let value = match self
            .leases
            .lease_bound_secret_value(&grant.record, &dial.host, &row)
            .await
        {
            Ok(value) => value,
            Err(error) => return audit.lease_failed(error, &dial.host, presentation),
        };
        let response = self
            .swap_and_send(&dial, request, &row.binding, &swapped, &value)
            .await;
        audit.write(
            presentation,
            match &response {
                Ok(_) => "swapped",
                Err(_) => "upstream_failed",
            },
        );
        response
    }

    /// `request` with `value` in each of `swapped`, sent, and its reply
    /// redacted of every form of the value and of each header sent with it.
    async fn swap_and_send(
        &self,
        dial: &BoundDial,
        request: ValidatedGuestRequest,
        binding: &HostBinding,
        swapped: &[HeaderName],
        value: &[u8],
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let presented = presented_value(binding.presentation(), value)?;
        let target = bound_target(&dial.host, &request.path, request.query.as_deref())?;
        let redaction = RedactionSet::new([value, presented.as_bytes()]);
        let headers = |guest: &HeaderMap| {
            let mut outbound = without_framing(guest);
            for name in swapped {
                outbound.insert(name.clone(), presented.clone());
            }
            outbound
        };
        let (status, headers, body) = self.send(dial, target, request, headers).await?;
        redacted(status, &headers, body, redaction)
    }

    /// One request to `target` at `dial`'s admitted address, its headers
    /// from `headers` with an identity coding asked for. The reply is
    /// returned as it came; the caller redacts what it injected.
    async fn send(
        &self,
        dial: &BoundDial,
        target: Url,
        request: ValidatedGuestRequest,
        headers: impl FnOnce(&HeaderMap) -> HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, BrokerUpstreamBody), BrokerRequestError> {
        let destination = dial.destination.ok_or(BrokerRequestError::UpstreamFailed)?;
        let mut headers = headers(&request.headers);
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        let response = timing::timed(
            Phase::Provider,
            self.upstream.send_bound_secret(BrokerUpstreamRequest {
                method: request.method,
                target,
                headers,
                body: request.body,
                body_stream: None,
                pinned: Some(SocketAddr::new(destination, BOUND_PORT)),
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        Ok((status, headers, body))
    }
}

/// The audit line of one request that named a secret.
struct Audit<'a, P: BrokerLeaseProvider> {
    leases: &'a P,
    record: &'a FirstBindSecret,
    host: &'a str,
}

impl<'a, P: BrokerLeaseProvider> Audit<'a, P> {
    fn new(leases: &'a std::sync::Arc<P>, record: &'a FirstBindSecret, host: &'a str) -> Self {
        Self {
            leases: leases.as_ref(),
            record,
            host,
        }
    }

    fn write(&self, presentation: &'static str, outcome: &'static str) {
        self.leases.audit_bound_secret(BoundSecretSwap {
            key: &self.record.key,
            scope: kind(self.record).as_str(),
            host: self.host,
            presentation,
            outcome,
        });
    }

    fn refused(
        &self,
        refusal: BoundSecretRefusal,
        presentation: &'static str,
    ) -> BrokerHttpResponse {
        self.write(presentation, refusal.code().as_str());
        refusal_response(&refusal)
    }

    /// A lease that failed: a named refusal, or the failure every lease
    /// answers with.
    fn lease_failed(
        &self,
        error: BoundSecretLeaseError,
        host: &str,
        presentation: &'static str,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let key = self.record.key.clone();
        let refusal = match error {
            BoundSecretLeaseError::NotBoundToHost => not_bound(self.record, host),
            BoundSecretLeaseError::BindingChanged => BoundSecretRefusal::BindingChanged { key },
            BoundSecretLeaseError::Deleted => BoundSecretRefusal::Deleted { key },
            BoundSecretLeaseError::Denied => {
                self.write(presentation, "denied");
                return Err(BrokerRequestError::Denied);
            }
            BoundSecretLeaseError::Unavailable => {
                self.write(presentation, "credential_unavailable");
                return Err(BrokerRequestError::AuthorityUnavailable);
            }
        };
        Ok(self.refused(refusal, presentation))
    }
}

fn not_bound(record: &FirstBindSecret, host: &str) -> BoundSecretRefusal {
    BoundSecretRefusal::NotBoundToHost {
        key: record.key.clone(),
        kind: kind(record),
        host: host.to_owned(),
    }
}

/// A record's set kind. A record whose path has no slot derived no
/// placeholder, so it is never a grant; `User` is only its fallback.
fn kind(record: &FirstBindSecret) -> SecretKind {
    record.kind().unwrap_or(SecretKind::User)
}

fn presentation_name(presentation: &Presentation) -> &'static str {
    match presentation {
        Presentation::Header { .. } => "header",
        Presentation::Basic { .. } => "basic",
        Presentation::BasicUser => "basic-user",
    }
}

/// The header a binding sends its value in, as the user wrote it: the first
/// of two.
fn bound_header_name(binding: &HostBinding) -> String {
    match binding.presentation() {
        Presentation::Header { headers, .. } => headers.first().map_or_else(
            || "Authorization".to_owned(),
            |name| name.as_str().to_owned(),
        ),
        Presentation::Basic { .. } | Presentation::BasicUser => "Authorization".to_owned(),
    }
}

/// The bound header's value the provider receives: `<scheme> <value>` or
/// the value alone; `Basic` of `username:value`, or of `value:`.
fn presented_value(
    presentation: &Presentation,
    value: &[u8],
) -> Result<HeaderValue, BrokerRequestError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(match presentation {
        Presentation::Header {
            scheme: Scheme::None,
            ..
        } => value.to_vec(),
        Presentation::Header {
            scheme: Scheme::Word(word),
            ..
        } => [word.as_bytes(), b" ", value].concat(),
        Presentation::Basic { username } => basic(&[username.as_bytes(), b":", value].concat()),
        Presentation::BasicUser => basic(&[value, b":"].concat()),
    });
    let mut presented = HeaderValue::from_bytes(&bytes).map_err(|_| BrokerRequestError::Denied)?;
    presented.set_sensitive(true);
    Ok(presented)
}

fn basic(credentials: &[u8]) -> Vec<u8> {
    let credentials = Zeroizing::new(credentials.to_vec());
    [
        b"Basic ".as_slice(),
        STANDARD.encode(&*credentials).as_bytes(),
    ]
    .concat()
}

/// `https://HOST` with `path` and `query` exactly as received; one the URL
/// parser would write differently is refused, so what is sent is what the
/// front door admitted.
fn bound_target(host: &str, path: &str, query: Option<&str>) -> Result<Url, BrokerRequestError> {
    let mut text = format!("https://{host}{path}");
    if let Some(query) = query {
        text.push('?');
        text.push_str(query);
    }
    let target = Url::parse(&text).map_err(|_| BrokerRequestError::InvalidRequest)?;
    if target.host_str() != Some(host)
        || target.path() != path
        || target.query() != query
        || target.fragment().is_some()
    {
        return Err(BrokerRequestError::InvalidRequest);
    }
    Ok(target)
}

/// A reply redacted by `redaction`, headers and body. A reply in a content
/// coding other than identity is refused before any of it is read.
fn redacted(
    status: StatusCode,
    headers: &HeaderMap,
    body: BrokerUpstreamBody,
    redaction: RedactionSet,
) -> Result<BrokerHttpResponse, BrokerRequestError> {
    let policy = PreparedOpenAiResponse::transparent(redaction, MAX_RESPONSE_BYTES);
    let (headers, redactor) = policy.begin(headers).map_err(map_adapter_error)?;
    Ok(BrokerHttpResponse::new(
        status,
        headers,
        Box::pin(BrokerRedactedBody {
            upstream: body,
            redactor: Some(ProviderStreamingResponse::OpenAi(redactor)),
            finished: false,
        }),
    ))
}

/// The answer to a bound-secret refusal: its status, headers and body,
/// nothing of the request's.
fn refusal_response(refusal: &BoundSecretRefusal) -> BrokerHttpResponse {
    let mut headers = HeaderMap::new();
    for (name, value) in refusal.headers() {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    let body = Bytes::from(refusal.body());
    BrokerHttpResponse::new(
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::FORBIDDEN),
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}
