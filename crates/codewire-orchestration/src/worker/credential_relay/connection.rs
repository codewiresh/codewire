//! A daemon connection the relay can sever.
//!
//! Each epoch dials the daemon on its own connection. When an ending epoch's
//! request body does not drain, because the daemon stopped reading, the epoch
//! severs that connection: the daemon cannot keep the body, and the frames
//! queued in it, alive inside this process.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_daemon::client::SessionClient;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tonic::transport::{Endpoint, Uri};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// The bound Pod's daemon and the credential of exactly that Pod.
#[derive(Clone)]
pub(super) struct DaemonTarget {
    pub(super) endpoint: String,
    pub(super) credential: Zeroizing<String>,
}

/// A client for one epoch. Its connection is opened on first use, closes in
/// order once the client is dropped, and closes at once, whatever the daemon
/// does, when `severed` is cancelled.
pub(super) fn connect(
    target: &DaemonTarget,
    severed: CancellationToken,
) -> Result<SessionClient, ()> {
    let endpoint = Endpoint::from_shared(target.endpoint.clone())
        .map_err(|_| ())?
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_while_idle(true);
    let channel = endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: Uri| {
        let severed = severed.clone();
        async move {
            let host = uri.host().ok_or_else(|| io::Error::other("no host"))?;
            let port = uri.port_u16().unwrap_or(80);
            let stream = tokio::select! {
                _ = severed.cancelled() => return Err(severed_error()),
                stream = TcpStream::connect((host, port)) => stream?,
            };
            stream.set_nodelay(true)?;
            Ok::<_, io::Error>(TokioIo::new(Severable {
                stream,
                severed: Box::pin(severed.cancelled_owned()),
            }))
        }
    }));
    SessionClient::from_channel(channel, target.credential.as_str()).map_err(|_| ())
}

fn severed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "credential relay epoch ended",
    )
}

/// A TCP stream that fails every operation once its epoch is severed, which
/// wakes and ends the HTTP/2 connection task that owns it.
struct Severable {
    stream: TcpStream,
    severed: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl Severable {
    fn severed(&mut self, context: &mut Context<'_>) -> bool {
        self.severed.as_mut().poll(context).is_ready()
    }
}

impl AsyncRead for Severable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.severed(context) {
            return Poll::Ready(Err(severed_error()));
        }
        Pin::new(&mut self.stream).poll_read(context, buf)
    }
}

impl AsyncWrite for Severable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.severed(context) {
            return Poll::Ready(Err(severed_error()));
        }
        Pin::new(&mut self.stream).poll_write(context, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.severed(context) {
            return Poll::Ready(Err(severed_error()));
        }
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_severed_stream_fails_a_pending_read_at_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let severed = CancellationToken::new();
        let mut stream = Severable {
            stream: TcpStream::connect(address).await.unwrap(),
            severed: Box::pin(severed.clone().cancelled_owned()),
        };
        let mut peer = accepted.await.unwrap();
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        // The peer stays open and silent: only severing ends this read.
        let read = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!read.is_finished());
        severed.cancel();
        let error = tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        drop(peer);
    }
}
