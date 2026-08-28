use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_daemon::client::{SessionClient, SessionClientError};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tonic::transport::Endpoint;

use crate::linux::path::{PathError, SocketIdentity};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ACK_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum HybridVsockError {
    #[error("hybrid-vsock socket path must be absolute")]
    InvalidSocketPath,
    #[error("hybrid-vsock guest port is invalid")]
    InvalidGuestPort,
    #[error("hybrid-vsock connection timed out")]
    ConnectTimeout,
    #[error("connect to hybrid-vsock socket failed")]
    Connect(#[source] io::Error),
    #[error("hybrid-vsock handshake timed out")]
    HandshakeTimeout,
    #[error("hybrid-vsock handshake I/O failed")]
    HandshakeIo(#[source] io::Error),
    #[error("Cloud Hypervisor returned an invalid hybrid-vsock acknowledgement")]
    InvalidAcknowledgement,
    #[error("build daemon transport channel failed")]
    Channel,
    #[error(transparent)]
    DaemonClient(#[from] SessionClientError),
    #[error(transparent)]
    SocketIdentity(#[from] PathError),
}

pub async fn connect_hybrid_vsock(
    socket: &Path,
    guest_port: u32,
) -> Result<UnixStream, HybridVsockError> {
    validate_target(socket, guest_port)?;
    let identity = SocketIdentity::capture(socket)?;
    connect_admitted(socket, &identity, guest_port).await
}

async fn connect_admitted(
    socket: &Path,
    identity: &SocketIdentity,
    guest_port: u32,
) -> Result<UnixStream, HybridVsockError> {
    connect_admitted_with_timeouts(
        socket,
        identity,
        guest_port,
        CONNECT_TIMEOUT,
        HANDSHAKE_TIMEOUT,
    )
    .await
}

async fn connect_admitted_with_timeouts(
    socket: &Path,
    identity: &SocketIdentity,
    guest_port: u32,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<UnixStream, HybridVsockError> {
    identity.revalidate(socket)?;
    let stream = connect_stream(UnixStream::connect(socket), connect_timeout).await?;
    tokio::time::timeout(handshake_timeout, complete_handshake(stream, guest_port))
        .await
        .map_err(|_| HybridVsockError::HandshakeTimeout)?
}

async fn connect_stream(
    connect: impl Future<Output = io::Result<UnixStream>>,
    timeout: Duration,
) -> Result<UnixStream, HybridVsockError> {
    tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| HybridVsockError::ConnectTimeout)?
        .map_err(HybridVsockError::Connect)
}

pub async fn connect_daemon(
    socket: &Path,
    guest_port: u32,
    auth_token: impl AsRef<str>,
) -> Result<SessionClient, HybridVsockError> {
    HybridVsockTarget::new(socket.to_owned(), guest_port)?
        .connect_daemon(auth_token)
        .await
}

async fn connect_daemon_admitted(
    socket: PathBuf,
    identity: SocketIdentity,
    guest_port: u32,
    auth_token: impl AsRef<str>,
) -> Result<SessionClient, HybridVsockError> {
    let endpoint = Endpoint::from_static("http://codewire-guest-daemon")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(Duration::from_secs(10));
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            let identity = identity.clone();
            async move {
                connect_admitted(&socket, &identity, guest_port)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await
        .map_err(|_| HybridVsockError::Channel)?;
    SessionClient::from_channel(channel, auth_token).map_err(HybridVsockError::from)
}

fn validate_target(socket: &Path, guest_port: u32) -> Result<(), HybridVsockError> {
    if !socket.is_absolute() || socket.as_os_str().is_empty() {
        return Err(HybridVsockError::InvalidSocketPath);
    }
    if guest_port == 0 || guest_port == u32::MAX {
        return Err(HybridVsockError::InvalidGuestPort);
    }
    Ok(())
}

async fn complete_handshake(
    mut stream: UnixStream,
    guest_port: u32,
) -> Result<UnixStream, HybridVsockError> {
    stream
        .write_all(format!("CONNECT {guest_port}\n").as_bytes())
        .await
        .map_err(HybridVsockError::HandshakeIo)?;
    stream
        .flush()
        .await
        .map_err(HybridVsockError::HandshakeIo)?;

    // Read exactly through the newline one byte at a time. Cloud Hypervisor
    // may forward HTTP/2 bytes immediately afterwards; a buffered read here
    // would steal the start of tonic's preface.
    let mut acknowledgement = Vec::with_capacity(16);
    loop {
        if acknowledgement.len() == MAX_ACK_BYTES {
            return Err(HybridVsockError::InvalidAcknowledgement);
        }
        let mut byte = [0_u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .map_err(HybridVsockError::HandshakeIo)?;
        if read == 0 {
            return Err(HybridVsockError::InvalidAcknowledgement);
        }
        acknowledgement.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' || !byte[0].is_ascii() {
            return Err(HybridVsockError::InvalidAcknowledgement);
        }
    }

    let acknowledgement = std::str::from_utf8(&acknowledgement)
        .map_err(|_| HybridVsockError::InvalidAcknowledgement)?;
    let acknowledgement = acknowledgement
        .strip_suffix('\n')
        .ok_or(HybridVsockError::InvalidAcknowledgement)?;
    let mut fields = acknowledgement.split(' ');
    if fields.next() != Some("OK")
        || fields
            .next()
            .and_then(|port| port.parse::<u32>().ok())
            .filter(|port| *port > 0 && *port != u32::MAX)
            .is_none()
        || fields.next().is_some()
    {
        return Err(HybridVsockError::InvalidAcknowledgement);
    }
    Ok(stream)
}

#[derive(Debug, Clone)]
pub struct HybridVsockTarget {
    pub socket: PathBuf,
    pub guest_port: u32,
    identity: SocketIdentity,
}

impl HybridVsockTarget {
    pub fn new(socket: PathBuf, guest_port: u32) -> Result<Self, HybridVsockError> {
        validate_target(&socket, guest_port)?;
        let identity = SocketIdentity::capture(&socket)?;
        Ok(Self {
            socket,
            guest_port,
            identity,
        })
    }

    pub async fn connect_daemon(
        &self,
        auth_token: impl AsRef<str>,
    ) -> Result<SessionClient, HybridVsockError> {
        connect_daemon_admitted(
            self.socket.clone(),
            self.identity.clone(),
            self.guest_port,
            auth_token,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_daemon::{Config, serve_grpc_with_incoming};
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    fn privatize(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    async fn read_connect(stream: &mut UnixStream) -> String {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn fake_hybrid_socket_serves_authenticated_daemon_without_host_tcp_listener() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let socket = temp.path().join("hybrid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        privatize(&socket);
        let deliberately_invalid_tcp_address = "not a host TCP socket address";
        assert!(
            deliberately_invalid_tcp_address
                .parse::<std::net::SocketAddr>()
                .is_err()
        );
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(4);
            let acceptor = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    assert_eq!(read_connect(&mut stream).await, "CONNECT 7777\n");
                    stream.write_all(b"OK 49152\n").await.unwrap();
                    if incoming_tx.send(Ok::<_, io::Error>(stream)).await.is_err() {
                        break;
                    }
                }
            });
            serve_grpc_with_incoming(
                Config {
                    // The injected transport entrypoint must never parse or
                    // bind this legacy host-TCP address. Its successful Unix
                    // readiness below proves that the caller-owned hybrid
                    // transport is the daemon's only listener in this test.
                    listen_addr: deliberately_invalid_tcp_address.into(),
                    workspace_root: workspace,
                    home_root: home,
                    auth_token: Some("daemon-auth-token-for-hybrid-test".into()),
                },
                tokio_stream::wrappers::ReceiverStream::new(incoming_rx),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
            acceptor.abort();
        });

        let client = connect_daemon(&socket, 7777, "daemon-auth-token-for-hybrid-test")
            .await
            .unwrap();
        client.require_ready().await.unwrap();
        let health = client.get_health().await.unwrap();
        assert_ne!(health.state, 0);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn acknowledgement_parser_does_not_consume_following_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("hybrid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        privatize(&socket);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_connect(&mut stream).await, "CONNECT 7\n");
            stream
                .write_all(b"OK 42\nPRI * HTTP/2.0\r\n")
                .await
                .unwrap();
        });
        let mut stream = connect_hybrid_vsock(&socket, 7).await.unwrap();
        let mut preface = [0_u8; 16];
        stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_acknowledgements_fail_closed() {
        for acknowledgement in [b"NO 42\n".as_slice(), b"OK 0\n", b"OK 1 extra\n"] {
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("hybrid.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            privatize(&socket);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = read_connect(&mut stream).await;
                stream.write_all(acknowledgement).await.unwrap();
            });
            assert!(matches!(
                connect_hybrid_vsock(&socket, 7).await,
                Err(HybridVsockError::InvalidAcknowledgement)
            ));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn wrong_daemon_token_is_rejected_through_hybrid_transport() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let socket = temp.path().join("hybrid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        privatize(&socket);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_connect(&mut stream).await;
            stream.write_all(b"OK 49152\n").await.unwrap();
            serve_grpc_with_incoming(
                Config {
                    listen_addr: "vsock:7777".into(),
                    workspace_root: workspace,
                    home_root: home,
                    auth_token: Some("correct-daemon-token".into()),
                },
                tokio_stream::once(Ok::<_, io::Error>(stream)),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });
        let client = connect_daemon(&socket, 7777, "wrong-daemon-token")
            .await
            .unwrap();
        assert!(matches!(
            client.require_ready().await,
            Err(SessionClientError::Status(_))
        ));
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_and_eof_acknowledgements_fail_closed() {
        for acknowledgement in [Some(vec![b'A'; MAX_ACK_BYTES]), None] {
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("hybrid.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            privatize(&socket);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = read_connect(&mut stream).await;
                if let Some(acknowledgement) = acknowledgement {
                    stream.write_all(&acknowledgement).await.unwrap();
                }
            });
            assert!(matches!(
                connect_hybrid_vsock(&socket, 7).await,
                Err(HybridVsockError::InvalidAcknowledgement)
            ));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_and_handshake_timeouts_are_typed() {
        let pending = std::future::pending::<io::Result<UnixStream>>();
        assert!(matches!(
            connect_stream(pending, Duration::from_millis(1)).await,
            Err(HybridVsockError::ConnectTimeout)
        ));

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("hybrid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        privatize(&socket);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_connect(&mut stream).await;
            std::future::pending::<()>().await;
        });
        let identity = SocketIdentity::capture(&socket).unwrap();
        assert!(matches!(
            connect_admitted_with_timeouts(
                &socket,
                &identity,
                7,
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await,
            Err(HybridVsockError::HandshakeTimeout)
        ));
        server.abort();
    }
}
