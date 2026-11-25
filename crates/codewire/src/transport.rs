//! The HTTP transport every generated service client here is built on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use connectrpc::ConnectError;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header, request};
use http_body_util::{BodyExt as _, Limited};

use crate::{BearerToken, ClientConfig, ClientError, ErrorCode, TokenProvider};

/// The reason, in its domain, the shared Connect auth layer gives when it
/// refuses a bearer before any handler runs. Only that refusal is sent again
/// (docs/dev/AUTH-POLICY.md, "Native sign-in lifetimes").
const BEARER_REFUSED: &str = "BEARER_REFUSED";
const BEARER_REFUSED_DOMAIN: &str = "codewire.sh";

/// The most of a refused unary call's answer read to find its reason.
const REFUSAL_BYTES: usize = 64 * 1024;

/// How long a call waits for its connection: the DNS lookup, the TCP connect
/// and the TLS handshake together. It is well inside a call's deadline, so a
/// connection that never opens fails as a connection error before a caller's
/// own timeout ends the process (docs/dev/CONNECT-ERROR-MODEL.md, D7).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The DNS lookup's part of `CONNECT_TIMEOUT`, so a lookup that never answers
/// fails as a `dns error` of its own.
pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const _: () = assert!(DNS_TIMEOUT.as_secs() < CONNECT_TIMEOUT.as_secs());
const _: () = assert!(CONNECT_TIMEOUT.as_secs() < crate::DEFAULT_UNARY_TIMEOUT.as_secs());

/// Adapter for connect-rust's transport trait using the repository-standard
/// rustls-backed reqwest client.
#[doc(hidden)]
#[derive(Clone)]
pub struct ReqwestConnectTransport {
    http: reqwest::Client,
    /// Asked for another bearer, once, when the auth layer refuses the one a
    /// unary call carried. `None` sends every call once.
    tokens: Option<Arc<dyn TokenProvider>>,
}

impl ReqwestConnectTransport {
    pub fn new(http: reqwest::Client, tokens: Option<Arc<dyn TokenProvider>>) -> Self {
        Self { http, tokens }
    }

    async fn send_once(
        &self,
        parts: &request::Parts,
        body: reqwest::Body,
    ) -> Result<reqwest::Response, ConnectError> {
        self.http
            .request(parts.method.clone(), parts.uri.to_string())
            .headers(parts.headers.clone())
            .body(body)
            .send()
            .await
            .map_err(crate::transport_error::send_failure)
    }
}

pub(crate) fn default_http_client(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    // Connect bidi needs HTTP/2: cleartext direct endpoints use h2c prior
    // knowledge, and TLS endpoints negotiate it with ALPN.
    let builder = bounded_connections(
        config.http_client_builder()?,
        CONNECT_TIMEOUT,
        Lookup::system(DNS_TIMEOUT),
    );
    let builder = if config.server_url().scheme() == "http" {
        builder.http2_prior_knowledge()
    } else {
        builder
    };
    builder.build().map_err(|error| {
        ClientError::new(
            ErrorCode::Internal,
            format!("build Codewire HTTP client: {error}"),
        )
    })
}

/// `builder` with each connection bounded at `connect`, and its DNS lookups
/// made by `lookup`.
pub(crate) fn bounded_connections(
    builder: reqwest::ClientBuilder,
    connect: Duration,
    lookup: Lookup,
) -> reqwest::ClientBuilder {
    builder
        .connect_timeout(connect)
        .dns_resolver(Arc::new(lookup))
}

pub(crate) type LookupFuture = BoxFuture<'static, std::io::Result<Vec<SocketAddr>>>;

/// A DNS lookup with its own bound. The system one is `getaddrinfo` on a
/// blocking thread, as reqwest's own resolver is.
pub(crate) struct Lookup {
    bound: Duration,
    lookup: fn(String) -> LookupFuture,
}

impl Lookup {
    pub(crate) fn system(bound: Duration) -> Self {
        Self::with(bound, |host| {
            Box::pin(
                async move { Ok(tokio::net::lookup_host((host.as_str(), 0)).await?.collect()) },
            )
        })
    }

    pub(crate) fn with(bound: Duration, lookup: fn(String) -> LookupFuture) -> Self {
        Self { bound, lookup }
    }
}

impl reqwest::dns::Resolve for Lookup {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let bound = self.bound;
        let lookup = (self.lookup)(name.as_str().to_owned());
        Box::pin(async move {
            // Port 0: the connector takes the request's port.
            match tokio::time::timeout(bound, lookup).await {
                Ok(Ok(addresses)) => Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs),
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Err(format!("no answer within {bound:?}").into()),
            }
        })
    }
}

impl ClientTransport for ReqwestConnectTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let transport = self.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            // Use reqwest's lossless HTTP conversion. Rebuilding the response
            // from `bytes_stream()` discards HTTP/2 trailer frames, including
            // the mandatory `grpc-status` used by native gRPC.
            let tokens = transport.tokens.clone().filter(|_| unary(&parts.headers));
            let Some(tokens) = tokens else {
                // A stream is sent once: it is never buffered to be replayed.
                let body = reqwest::Body::wrap_stream(body.into_data_stream());
                return Ok(Response::from(transport.send_once(&parts, body).await?));
            };
            let body = body
                .collect()
                .await
                .map_err(|error| ConnectError::internal(format!("read the request: {error}")))?
                .to_bytes();
            let response = transport.send_once(&parts, body.clone().into()).await?;
            if response.status() != StatusCode::UNAUTHORIZED {
                return Ok(Response::from(response));
            }
            let (head, answer) = Response::<reqwest::Body>::from(response).into_parts();
            let answer = Limited::new(answer, REFUSAL_BYTES)
                .collect()
                .await
                .map_err(|error| ConnectError::unavailable(format!("read the refusal: {error}")))?
                .to_bytes();
            let refused = Response::from_parts(head, reqwest::Body::from(answer.clone()));
            let Some(rejected) = sent_bearer(&parts.headers).filter(|_| bearer_refused(&answer))
            else {
                return Ok(refused);
            };
            // No other bearer, or a renewal the IdP refused: the first
            // refusal stands, and says the sign-in has ended.
            let Ok(Some(token)) = tokens.after_refusal(&rejected).await else {
                return Ok(refused);
            };
            let Ok(value) = HeaderValue::from_str(&token.authorization_header()) else {
                return Ok(refused);
            };
            parts.headers.insert(header::AUTHORIZATION, value);
            Ok(Response::from(
                transport.send_once(&parts, body.into()).await?,
            ))
        })
    }
}

/// Whether the request is a Connect unary call, whose whole body can be sent
/// again. Streams, gRPC and Connect's GET form are not.
fn unary(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| matches!(value.trim(), "application/proto" | "application/json"))
}

/// The bearer a request carried.
fn sent_bearer(headers: &HeaderMap) -> Option<BearerToken> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    BearerToken::new(value.strip_prefix("Bearer ")?).ok()
}

/// Whether a unary call's answer is the auth layer's own refusal of its
/// bearer, rather than a handler's `Unauthenticated`, which may follow a
/// change and is never sent again.
fn bearer_refused(answer: &[u8]) -> bool {
    serde_json::from_slice::<ConnectError>(answer)
        .map(ClientError::from)
        .is_ok_and(|error| {
            error.code() == ErrorCode::Unauthenticated
                && error.error_info().is_some_and(|info| {
                    info.reason() == BEARER_REFUSED && info.domain() == BEARER_REFUSED_DOMAIN
                })
        })
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
