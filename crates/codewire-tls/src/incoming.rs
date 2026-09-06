use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::stream::{FuturesUnordered, Stream, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Sleep;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{MAX_HANDSHAKES, ServerTlsFiles, TLS_TIMEOUT, TlsError};

type Handshake = Pin<Box<dyn Future<Output = Result<TlsStream<TcpStream>, TlsError>> + Send>>;

/// Tonic-compatible TLS incoming stream. At most 32 handshakes are owned by
/// this value; none is spawned. Dropping it drops pending handshakes/sockets.
/// Malformed peers or changed invalid files reject that connection only.
pub struct TlsIncoming {
    listener: TcpListener,
    local_addr: SocketAddr,
    files: ServerTlsFiles,
    http1: bool,
    pending: FuturesUnordered<Handshake>,
    backoff: Option<Pin<Box<Sleep>>>,
}

impl TlsIncoming {
    pub fn new(listener: TcpListener, files: ServerTlsFiles) -> Result<Self, TlsError> {
        let local_addr = listener.local_addr().map_err(|_| TlsError::Configuration)?;
        Ok(Self {
            listener,
            local_addr,
            files,
            http1: false,
            pending: FuturesUnordered::new(),
            backoff: None,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[cfg(test)]
    pub(crate) fn pending_handshakes(&self) -> usize {
        self.pending.len()
    }
}

impl Stream for TlsIncoming {
    type Item = io::Result<TlsStream<TcpStream>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // Bound work per poll even under a flood of immediately failing peers.
        for _ in 0..MAX_HANDSHAKES * 2 {
            match this.pending.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(stream))) => return Poll::Ready(Some(Ok(stream))),
                Poll::Ready(Some(Err(_))) => continue,
                _ => {}
            }
            if let Some(backoff) = &mut this.backoff {
                if backoff.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.backoff = None;
            }
            if this.pending.len() == MAX_HANDSHAKES {
                return Poll::Pending;
            }
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((socket, _))) => {
                    let files = this.files.clone();
                    let http1 = this.http1;
                    let deadline = tokio::time::Instant::now() + TLS_TIMEOUT;
                    this.pending.push(Box::pin(async move {
                        tokio::time::timeout_at(deadline, async {
                            let config = files.load(http1).await?;
                            TlsAcceptor::from(config)
                                .accept(socket)
                                .await
                                .map_err(|_| TlsError::Handshake)
                        })
                        .await
                        .map_err(|_| TlsError::Timeout)?
                    }));
                }
                Poll::Ready(Err(_)) => {
                    this.backoff = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
                    return Poll::Ready(Some(Err(io::Error::other("TLS listener unavailable"))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Axum listener backed by the same bounded incoming stream. The runtime owns
/// graceful shutdown and must separately signal/drain application owners.
pub struct TlsListener {
    incoming: TlsIncoming,
}

impl TlsListener {
    pub fn new(listener: TcpListener, files: ServerTlsFiles) -> Result<Self, TlsError> {
        let mut incoming = TlsIncoming::new(listener, files)?;
        incoming.http1 = true;
        Ok(Self { incoming })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.incoming.next().await {
                Some(Ok(stream)) => {
                    if let Ok(address) = stream.get_ref().0.peer_addr() {
                        return (stream, address);
                    }
                }
                Some(Err(_)) => {}
                None => std::future::pending::<()>().await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.incoming.local_addr())
    }
}
