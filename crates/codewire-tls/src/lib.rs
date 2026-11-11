//! TLS for administrator-owned mounted service identities and public trust.
//!
//! New server handshakes reload the mounted identity, and the client roots of
//! an identity that asks for client certificates. Each client `connect`
//! or Connect transport call loads current, explicit roots into a fresh
//! channel. Existing connections
//! retain their original TLS session; callers own their authority deadlines
//! and must not reuse a channel across newly admitted credential requests.
//! There is no plaintext, native-root, key-log or last-good-file fallback.

// Predates this workspace lint; #4125 tracks removing the allow.
#![allow(clippy::undocumented_unsafe_blocks)]

mod client;
mod connect;
mod files;
mod incoming;
mod peer;

pub use client::ClientTlsEndpoint;
pub use connect::ConnectOriginTransport;

#[cfg(feature = "test-support")]
pub mod test_support;
pub use files::{ServerTlsFiles, read_optional_roots};
pub use incoming::{PeerTlsListener, TlsIncoming, TlsListener};
pub use peer::{TlsPeer, VerifiedClient};

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
