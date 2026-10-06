//! TLS for administrator-owned mounted service identities and public trust.
//!
//! New server handshakes reload the mounted identity. Each client `connect`
//! or Connect transport call loads current, explicit roots into a fresh
//! channel. Existing connections
//! retain their original TLS session; callers own their authority deadlines
//! and must not reuse a channel across newly admitted credential requests.
//! There is no plaintext, native-root, key-log or last-good-file fallback.

mod client;
mod connect;
mod files;
mod incoming;

pub use client::ClientTlsEndpoint;
pub use connect::ConnectOriginTransport;

#[cfg(feature = "test-support")]
pub mod test_support;
pub use files::ServerTlsFiles;
pub use incoming::{TlsIncoming, TlsListener};

/// A server connection after [`ServerTlsFiles::accept_http1_only`].
pub type ServerTlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

use std::time::Duration;

const TLS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HANDSHAKES: usize = 32;

/// Closed errors deliberately retain no paths, PEM, transport diagnostics or
/// nested sources. Operational callers may log the class, never raw TLS input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TlsError {
    #[error("invalid TLS configuration")]
    Configuration,
    #[error("TLS files unavailable")]
    Files,
    #[error("invalid TLS identity or public trust")]
    InvalidPem,
    #[error("TLS operation deadline elapsed")]
    Timeout,
    #[error("TLS handshake failed")]
    Handshake,
    #[error("verified TLS connection unavailable")]
    Connect,
}

#[cfg(test)]
mod tests;
