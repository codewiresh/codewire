//! A hosted egress daemon's platform connections (#4000;
//! `designs/hosted-egress.md`, "The daemon's platform path"). The daemon
//! resolves no names: each platform peer is a configured address, and every
//! connection to it is opened by one dial that binds the socket to the Pod's
//! own interface. The peer's name stays the TLS name and the HTTP authority.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub use rustls_pki_types::CertificateDer;
use tokio::net::TcpStream;

/// Opens a TCP connection to a platform address. The same type as
/// `codewire_tls::PeerDial`, so one value serves the binding, the coordinator,
/// Mesh and DERP.
pub type TcpDial = Arc<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> + Send + Sync,
>;

/// Roots a platform relay's certificate may chain to beside the WebPKI
/// roots: a deployment-owned authority, such as a local cluster's, mounted
/// for the daemon. Empty for a deployment whose relay has a public
/// certificate.
pub type PlatformRoots = Vec<CertificateDer<'static>>;
