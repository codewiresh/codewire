//! In-process connections to this daemon's gRPC service.
//!
//! The hosted daemon also serves workspace access (SSH, SFTP and SCP) from
//! the same process (#2460). Those sessions use the daemon's own gRPC service
//! over an in-memory duplex stream instead of a network listener, so no
//! connection leaves the process and nothing new listens. Each connection
//! still presents the daemon credential: per-RPC authorization is unchanged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tonic::transport::server::Connected;

/// In-memory buffer per direction of one local connection.
const LOCAL_CONNECTION_BUFFER_BYTES: usize = 256 * 1024;
/// Local connections waiting for the server to accept them.
const LOCAL_ACCEPT_BACKLOG: usize = 64;

/// Opens in-process connections to the daemon's gRPC service.
#[derive(Clone, Debug)]
pub struct LocalDaemonConnector {
    accept: mpsc::Sender<DuplexStream>,
}

/// The server half: every connection a [`LocalDaemonConnector`] opens.
#[derive(Debug)]
pub struct LocalDaemonIncoming {
    accept: mpsc::Receiver<DuplexStream>,
}

/// A connector and the incoming stream it feeds.
pub fn local_transport() -> (LocalDaemonConnector, LocalDaemonIncoming) {
    let (accept, incoming) = mpsc::channel(LOCAL_ACCEPT_BACKLOG);
    (
        LocalDaemonConnector { accept },
        LocalDaemonIncoming { accept: incoming },
    )
}

impl LocalDaemonConnector {
    /// One new connection, or an error once the daemon stopped serving.
    pub async fn connect(&self) -> io::Result<DuplexStream> {
        let (client, server) = tokio::io::duplex(LOCAL_CONNECTION_BUFFER_BYTES);
        self.accept.send(server).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "local daemon transport is closed",
            )
        })?;
        Ok(client)
    }
}

impl Stream for LocalDaemonIncoming {
    type Item = io::Result<DuplexStream>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.accept.poll_recv(cx).map(|stream| stream.map(Ok))
    }
}

/// One accepted connection: from the network listener or from this process.
#[derive(Debug)]
pub enum DaemonIo<T> {
    Network(T),
    Local(DuplexStream),
}

/// Merge the network listener's connections with in-process ones, so one
/// gRPC server, with one session engine, serves both.
pub fn with_local_connections<S, T>(
    network: S,
    local: LocalDaemonIncoming,
) -> impl Stream<Item = io::Result<DaemonIo<T>>> + Send + 'static
where
    S: Stream<Item = io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    use tokio_stream::StreamExt as _;

    let network = network.map(|result| result.map(DaemonIo::Network));
    let local = local.map(|result| result.map(DaemonIo::Local));
    network.merge(local)
}

impl<T> Connected for DaemonIo<T> {
    // No daemon RPC reads connection metadata; per-RPC authorization is the
    // daemon credential.
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl<T: AsyncRead + Unpin> AsyncRead for DaemonIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Network(io) => Pin::new(io).poll_read(cx, buf),
            Self::Local(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DaemonIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Network(io) => Pin::new(io).poll_write(cx, buf),
            Self::Local(io) => Pin::new(io).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Network(io) => Pin::new(io).poll_flush(cx),
            Self::Local(io) => Pin::new(io).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Network(io) => Pin::new(io).poll_shutdown(cx),
            Self::Local(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_stream::StreamExt as _;

    #[tokio::test]
    async fn local_connections_reach_the_merged_incoming_stream() {
        let (connector, local) = local_transport();
        let network = tokio_stream::iter(Vec::<io::Result<DuplexStream>>::new());
        let mut incoming = Box::pin(with_local_connections(network, local));
        let mut client = connector.connect().await.unwrap();
        let mut server = match incoming.next().await.unwrap().unwrap() {
            DaemonIo::Local(io) => io,
            DaemonIo::Network(_) => panic!("expected an in-process connection"),
        };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0_u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn connecting_after_the_server_stopped_fails() {
        let (connector, local) = local_transport();
        drop(local);
        let error = connector.connect().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }
}
