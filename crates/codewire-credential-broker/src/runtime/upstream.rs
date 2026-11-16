//! The broker's provider transport: the one boundary through which an
//! already-authorized request leaves the broker (#3999 adds the WebSocket
//! upgrade).

use async_trait::async_trait;
use http::HeaderMap;

use super::{BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse};

/// Broker-owned transport for exactly one already-authorized upstream request.
/// Implementations own DNS resolution, socket creation, TLS, redirects, and
/// response framing; no credential-free process may implement this on behalf
/// of the broker.
#[async_trait]
pub trait BrokerUpstreamTransport: Send + Sync {
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
}

/// A runtime with application sources only has no provider DNS/socket setup.
#[async_trait]
impl<T: BrokerUpstreamTransport> BrokerUpstreamTransport for Option<T> {
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
