//! The coordinator client's TCP and TLS connections: how a dial finds the
//! coordinator's address, and the TLS that verifies its URL's host.
//!
//! A dial races the coordinator's addresses (Happy Eyeballs, RFC 8305), as
//! the CLI's other HTTPS calls do through their HTTP client. A name with both
//! IPv6 and IPv4 addresses, such as the public edge's, is then reached on a
//! network whose IPv6 route drops SYNs: the IPv4 attempt starts 250 ms later
//! instead of after the first attempt gives up, which took the whole setup
//! timeout (#5120).

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;

use codewire_tailnet::dns::absolute_dns_name;
use codewire_tailnet::platform_dial::TcpDial;

use super::{Error, MAX_RESOLVED_COORDINATOR_ADDRESSES, coordinator_origin};

/// How a TLS dial reaches the coordinator URL's host. TLS verification and
/// the HTTP authority use the host as configured every way.
#[derive(Clone)]
pub(super) enum HostLookup {
    AsConfigured,
    /// As an absolute DNS name, so no resolver search domain is tried
    /// (#2701, see [`codewire_tailnet::dns`]).
    Absolute,
    /// No lookup: a hosted egress daemon's configured address, opened by its
    /// Pod-interface dial (#4000). The address stands for the host and port.
    Platform(SocketAddr, TcpDial),
}

impl HostLookup {
    /// The name a lookup asks for. A platform address is never looked up.
    pub(super) fn name<'a>(&self, host: &'a str) -> Cow<'a, str> {
        match self {
            Self::AsConfigured | Self::Platform(..) => Cow::Borrowed(host),
            Self::Absolute => absolute_dns_name(host),
        }
    }
}

pub(super) fn coordinator_tls_config() -> Result<Arc<rustls::ClientConfig>, Error> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    coordinator_tls_config_with_roots(roots)
}

#[cfg(feature = "kind-e2e")]
pub(super) fn coordinator_tls_config_with_root(
    root_certificate_der: Vec<u8>,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(root_certificate_der))
        .map_err(|error| Error::Url(format!("invalid KIND root certificate: {error}")))?;
    coordinator_tls_config_with_roots(roots)
}

pub(super) fn coordinator_tls_config_with_roots(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| Error::Url(format!("unsupported TLS protocol configuration: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

pub(super) async fn connect_ring_tls(
    uri: http::Uri,
    config: Arc<rustls::ClientConfig>,
    lookup: HostLookup,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS URI has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let tcp = match &lookup {
        HostLookup::Platform(address, dial) => dial(*address).await?,
        named => {
            let addresses = tokio::net::lookup_host((named.name(&host).as_ref(), port))
                .await?
                .collect::<Vec<_>>();
            connect_racing(&addresses).await?
        }
    };
    // The server name comes from the URI, never from the looked-up name.
    finish_ring_tls(&uri, config, tcp).await
}

pub(super) async fn connect_resolved_plain(
    uri: http::Uri,
    addresses: Arc<[SocketAddr]>,
) -> Result<hyper_util::rt::TokioIo<tokio::net::TcpStream>, io::Error> {
    ensure_resolved_connector_port(&uri, &addresses)?;
    connect_resolved_tcp(&addresses)
        .await
        .map(hyper_util::rt::TokioIo::new)
}

pub(super) async fn connect_ring_tls_resolved(
    uri: http::Uri,
    config: Arc<rustls::ClientConfig>,
    addresses: Arc<[SocketAddr]>,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    ensure_resolved_connector_port(&uri, &addresses)?;
    let tcp = connect_resolved_tcp(&addresses).await?;
    finish_ring_tls(&uri, config, tcp).await
}

pub(super) async fn finish_ring_tls(
    uri: &http::Uri,
    config: Arc<rustls::ClientConfig>,
    tcp: tokio::net::TcpStream,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS URI has no host"))?
        .to_owned();
    let server_name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS URI host is not a DNS name",
        )
    })?;
    tcp.set_nodelay(true)?;
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(io::Error::other)?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(io::Error::other(
            "coordinator TLS peer did not negotiate HTTP/2",
        ));
    }
    Ok(hyper_util::rt::TokioIo::new(tls))
}

pub(super) async fn connect_resolved_tcp(
    addresses: &[SocketAddr],
) -> io::Result<tokio::net::TcpStream> {
    let stream = connect_racing(addresses).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// How long a dial gives one address before it also tries the next: RFC
/// 8305's recommended Connection Attempt Delay. A family whose packets vanish
/// then costs this long, never the whole setup timeout (#5120).
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// The order a dial tries `addresses` in: the families alternate, starting
/// with the family of the first, and each keeps the resolver's order (RFC 8305
/// section 4).
fn interleaved(addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return Vec::new();
    };
    let (mut preferred, mut other): (Vec<_>, Vec<_>) = addresses
        .iter()
        .partition(|address| address.is_ipv6() == first.is_ipv6());
    preferred.reverse();
    other.reverse();
    let mut order = Vec::with_capacity(addresses.len());
    while let Some(address) = preferred.pop() {
        order.push(address);
        if let Some(address) = other.pop() {
            order.push(address);
        }
    }
    order.extend(other.into_iter().rev());
    order
}

/// A TCP connection to one of `addresses`, raced: each next address starts
/// after [`CONNECTION_ATTEMPT_DELAY`], or at once when an attempt fails. The
/// first connection wins, and the attempts still running are dropped with it.
/// All failing returns the last error.
pub(super) async fn connect_racing(addresses: &[SocketAddr]) -> io::Result<tokio::net::TcpStream> {
    connect_racing_with(
        addresses,
        CONNECTION_ATTEMPT_DELAY,
        tokio::net::TcpStream::connect,
    )
    .await
}

async fn connect_racing_with<S, F, Fut>(
    addresses: &[SocketAddr],
    attempt_delay: Duration,
    connect: F,
) -> io::Result<S>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<S>>,
{
    let mut waiting = interleaved(addresses).into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut last_error = None;
    let Some(first) = waiting.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the coordinator has no address to dial",
        ));
    };
    attempts.push(connect(first));
    loop {
        let next_due = tokio::time::sleep(attempt_delay);
        tokio::select! {
            result = attempts.next() => match result {
                Some(Ok(stream)) => return Ok(stream),
                Some(Err(error)) => {
                    last_error = Some(error);
                    match waiting.next() {
                        Some(address) => attempts.push(connect(address)),
                        None if attempts.is_empty() => break,
                        None => {}
                    }
                }
                None => break,
            },
            () = next_due, if waiting.len() > 0 => {
                if let Some(address) = waiting.next() {
                    attempts.push(connect(address));
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the coordinator has no address to dial",
        )
    }))
}

pub(super) fn validated_resolved_addresses(
    url: &str,
    addresses: Vec<SocketAddr>,
) -> Result<Arc<[SocketAddr]>, Error> {
    let uri = coordinator_origin(url)?;
    let port = coordinator_port(&uri)?;
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_COORDINATOR_ADDRESSES {
        return Err(Error::Url(
            "resolved coordinator address set is empty or exceeds its limit".into(),
        ));
    }
    if addresses.iter().any(|address| {
        address.port() != port || address.ip().is_unspecified() || address.ip().is_multicast()
    }) {
        return Err(Error::Url(
            "resolved coordinator address does not match the configured authority".into(),
        ));
    }
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    Ok(Arc::from(addresses))
}

pub(super) fn ensure_resolved_connector_port(
    uri: &http::Uri,
    addresses: &[SocketAddr],
) -> io::Result<()> {
    let port = coordinator_port(uri).map_err(io::Error::other)?;
    if addresses.is_empty() || addresses.iter().any(|address| address.port() != port) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved coordinator address port mismatch",
        ));
    }
    Ok(())
}

pub(super) fn coordinator_port(uri: &http::Uri) -> Result<u16, Error> {
    uri.port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        })
        .ok_or_else(|| Error::Url("coordinator URL has no supported port".into()))
}

#[cfg(test)]
mod tests;
