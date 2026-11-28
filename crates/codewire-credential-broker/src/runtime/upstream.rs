//! The broker's provider transport: the one boundary through which an
//! already-authorized request leaves the broker (#3999 adds the WebSocket
//! upgrade).

use async_trait::async_trait;
use http::HeaderMap;

use super::{
    BrokerRequestError, BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
};

/// Broker-owned transport for exactly one already-authorized upstream request.
/// Implementations own DNS resolution, socket creation, TLS, redirects, and
/// response framing; no credential-free process may implement this on behalf
/// of the broker.
#[async_trait]
pub trait BrokerUpstreamTransport: Send + Sync {
    /// Whether this transport cannot reach `slot`'s provider at all: a host
    /// the slot's requests or refreshes go to has no address here (#5286).
    /// The broker then refuses the slot's requests before any lease and
    /// begins no refresh for it, so a sign-in is never spent on a provider
    /// that was not asked.
    /// A transport that wraps another must pass the question on: the
    /// default answers for a transport that resolves nothing by itself.
    fn slot_unserved(&self, slot: &str) -> bool {
        let _ = slot;
        false
    }

    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError>;

    /// Send a front door's WebSocket opening request, already authorized and
    /// with its credential swapped (#3999). A `101` yields the provider's
    /// upgraded byte stream; any other status is an ordinary response. A
    /// `101`'s headers come back unfiltered, `Upgrade`, `Connection` and
    /// `Sec-WebSocket-Accept` included: the bridge decides which reach the
    /// client. A transport that cannot carry WebSockets refuses the
    /// destination.
    async fn upgrade(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
        drop(request);
        Err(BrokerUpstreamError::DestinationDenied)
    }

    /// Send a front-door request to one of GitHub's two hosts as the
    /// environment sent it, with nothing of the broker's in it (#3999). The
    /// destination check is its own: the host the front door intercepted,
    /// HTTPS on 443 and a plain method, on any path. [`Self::execute`] keeps
    /// the exact check for every request that carries leased material. A
    /// transport that does not forward refuses the destination.
    async fn forward_github(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        drop(request);
        Err(BrokerUpstreamError::DestinationDenied)
    }

    /// Send a front-door request to a host-bound secret's host, its value
    /// already swapped in (#4003). The host is no provider's, so it was never
    /// resolved here: the request is dialled only at its pinned address,
    /// the one the egress broker admitted under the environment's network
    /// policy, checked again, and TLS verifies the host's certificate. A
    /// transport that does not send bound secrets refuses the destination.
    async fn send_bound_secret(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        drop(request);
        Err(BrokerUpstreamError::DestinationDenied)
    }
}

/// A runtime with application sources only has no provider DNS/socket setup.
#[async_trait]
impl<T: BrokerUpstreamTransport> BrokerUpstreamTransport for Option<T> {
    fn slot_unserved(&self, slot: &str) -> bool {
        self.as_ref()
            .is_some_and(|transport| transport.slot_unserved(slot))
    }

    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        match self {
            Some(transport) => transport.execute(request).await,
            None => Err(BrokerUpstreamError::DestinationDenied),
        }
    }

    async fn upgrade(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
        match self {
            Some(transport) => transport.upgrade(request).await,
            None => Err(BrokerUpstreamError::DestinationDenied),
        }
    }

    async fn forward_github(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        match self {
            Some(transport) => transport.forward_github(request).await,
            None => Err(BrokerUpstreamError::DestinationDenied),
        }
    }

    async fn send_bound_secret(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        match self {
            Some(transport) => transport.send_bound_secret(request).await,
            None => Err(BrokerUpstreamError::DestinationDenied),
        }
    }
}

/// A provider's answer to a WebSocket opening request.
pub enum BrokerUpstreamUpgrade {
    /// `101 Switching Protocols`: its headers, before filtering, and the
    /// connection's bytes from here on, which are never parsed.
    Switched {
        headers: HeaderMap,
        stream: BrokerUpgradedStream,
    },
    /// Any other status, handled like the reply to an ordinary request.
    Response(BrokerUpstreamResponse),
}

/// An upgraded provider connection, in both directions.
pub type BrokerUpgradedStream = Box<dyn BrokerUpgradedIo>;

/// What an upgraded provider connection must be.
pub trait BrokerUpgradedIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static
{
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static> BrokerUpgradedIo
    for T
{
}

#[cfg(test)]
impl BrokerUpstreamRequest {
    /// This request with a streamed body, as only a GitHub Git upload has.
    pub(crate) fn with_body_stream(mut self, stream: super::BrokerRequestBodyStream) -> Self {
        self.body_stream = Some(stream);
        self
    }
}

/// What a guest's request gets for a transport failure.
pub(super) fn map_upstream_error(error: BrokerUpstreamError) -> BrokerRequestError {
    match error {
        BrokerUpstreamError::DestinationDenied => BrokerRequestError::Denied,
        BrokerUpstreamError::ResourceLimit => BrokerRequestError::ResponseTooLarge,
        BrokerUpstreamError::Connect | BrokerUpstreamError::Protocol => {
            BrokerRequestError::UpstreamFailed
        }
    }
}
