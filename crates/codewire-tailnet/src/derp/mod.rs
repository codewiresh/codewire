//! DERP relay **client** for Codewire's tailnet (#46).
//!
//! Codewire runs a `codewire-derp` server binary. This module is the Rust
//! client that interops with it: it speaks the Tailscale DERP wire protocol —
//! 1-byte frame type + 4-byte big-endian length framing, the `DERP🔑`
//! handshake preamble, and the NaCl-`crypto_box` server-key/client-key
//! exchange — and can relay packets between peers through the server.
//!
//! Layout:
//! - [`frame`]: typed [`frame::FrameType`] enum + header/frame
//!   encode/decode. The wire numbers are copied from `derp.go`.
//! - [`key`]: [`key::NodePrivate`] / [`key::NodePublic`] and the
//!   `SealTo`/`OpenFrom` NaCl-box crypto used in the handshake.
//! - [`client`]: the async [`client::Client`] (handshake, `send`,
//!   `recv`) over any `AsyncRead + AsyncWrite`, plus typed
//!   [`client::ReceivedMessage`]s.
//! - this file: the HTTP `Upgrade: DERP` connect helpers
//!   ([`connect_tls`], [`connect_plain`]) that establish the transport
//!   then hand the stream to [`client::Client::handshake`].
//!
//! Scope: this is the #46 feasibility spike. It proves a Rust client can
//! interop with the Codewire DERP server (relay A→B); it is deliberately
//! single-connection and does not yet do reconnect loops, mesh
//! (`WatchConns`/`ForwardPacket`/`ClosePeer`), region failover, or the
//! `meta cert` server-key fast path. Those are noted for #59 follow-up.

pub mod client;
pub mod frame;
pub mod key;

pub use client::{BoxedStream, Client, ReceivedMessage};
pub use key::{NodePrivate, NodePublic};

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Errors from the DERP client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("derp protocol: {0}")]
    Protocol(&'static str),
    #[error("derp crypto: {0}")]
    Crypto(&'static str),
    #[error("tls: {0}")]
    Tls(String),
    #[error("http upgrade: {0}")]
    Upgrade(String),
}

/// Send the `GET /derp` HTTP request with the DERP upgrade headers and
/// consume the `101 Switching Protocols` response, leaving `conn`
/// positioned at the start of the DERP protocol stream.
///
/// Mirrors `derphttp.Client.connect`: `Upgrade: DERP` /
/// `Connection: Upgrade`. We use the non-fast-start path (read the 101)
/// because we don't pre-learn the server key from a meta cert.
async fn http_upgrade<S>(conn: &mut S, host: &str) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET /derp HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: DERP\r\n\
         Connection: Upgrade\r\n\
         \r\n"
    );
    conn.write_all(req.as_bytes()).await?;
    conn.flush().await?;

    // Read the response head up to the blank line. Responses are tiny;
    // read byte-at-a-time so we never consume DERP bytes past the header.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8192 {
            return Err(Error::Upgrade("response header too large".into()));
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let status_line = head_str.lines().next().unwrap_or_default();
    // e.g. "HTTP/1.1 101 Switching Protocols"
    if !status_line.contains(" 101 ") {
        return Err(Error::Upgrade(format!("unexpected status: {status_line}")));
    }
    Ok(())
}

/// Connect to a DERP server over **plain TCP** (no TLS), perform the
/// HTTP upgrade and DERP handshake, and return a ready [`Client`].
///
/// Intended for the server binary's `PORT` (cleartext) listener — used by
/// the interop tests. Production deployments use [`connect_tls`].
pub async fn connect_plain<R>(
    addr: &str,
    host: &str,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<TcpStream>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let tcp = TcpStream::connect(addr).await?;
    finish_plain(tcp, host, private, rng).await
}

/// Connect to one already-resolved DERP address without invoking name
/// resolution. `host` remains the HTTP authority used by the DERP upgrade.
pub async fn connect_plain_resolved<R>(
    addr: SocketAddr,
    host: &str,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<TcpStream>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let tcp = TcpStream::connect(addr).await?;
    finish_plain(tcp, host, private, rng).await
}

async fn finish_plain<R>(
    mut tcp: TcpStream,
    host: &str,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<TcpStream>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    http_upgrade(&mut tcp, host).await?;
    Client::handshake(tcp, private, rng).await
}

/// Connect to a DERP server over **TLS**, perform the HTTP upgrade and
/// DERP handshake, and return a ready [`Client`].
///
/// `verifier` lets the caller plug a custom certificate verifier — dev
/// deployments can use a self-signed cert in `derpInsecure`, so a spike/test
/// wires a no-op verifier here. Production wires real roots.
pub async fn connect_tls<R>(
    addr: &str,
    host: &str,
    config: rustls::ClientConfig,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<tokio_rustls::client::TlsStream<TcpStream>>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let tcp = TcpStream::connect(addr).await?;
    finish_tls(tcp, host, config, private, rng).await
}

/// Connect to one already-resolved TLS DERP address while retaining `host`
/// for certificate identity and HTTP authority.
pub async fn connect_tls_resolved<R>(
    addr: SocketAddr,
    host: &str,
    config: rustls::ClientConfig,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<tokio_rustls::client::TlsStream<TcpStream>>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let tcp = TcpStream::connect(addr).await?;
    finish_tls(tcp, host, config, private, rng).await
}

async fn finish_tls<R>(
    tcp: TcpStream,
    host: &str,
    config: rustls::ClientConfig,
    private: key::NodePrivate,
    rng: &mut R,
) -> Result<Client<tokio_rustls::client::TlsStream<TcpStream>>, Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| Error::Tls("invalid server name".into()))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;
    http_upgrade(&mut tls, host).await?;
    Client::handshake(tls, private, rng).await
}

/// Build a rustls client configuration using the public WebPKI root set.
///
/// Production DERP connections use this helper; tests that run the DERP
/// server binary over cleartext use [`connect_plain`] instead.
pub fn webpki_tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Build a rustls client configuration that still uses TLS but skips server
/// certificate validation.
///
/// This matches Tailscale's `DERPNode.InsecureForTests`: dev can use the
/// in-cluster self-signed DERP TLS listener on a non-443 port without falling
/// back to cleartext. Only callers that already selected a TLS URL should use
/// this helper.
pub fn insecure_tls_config_for_tests() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
        .with_no_client_auth()
}

#[derive(Debug)]
struct NoServerCertVerification;

impl rustls::client::danger::ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme;

        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests;
