//! Async-facing handles: [`TcpStream`] (an `AsyncRead + AsyncWrite` byte pipe
//! over one smoltcp socket) and [`TcpListener`] (an `accept()` queue of inbound
//! streams). These deliberately hold no smoltcp state — that lives in the
//! single-threaded [`super::driver`]. They are pure channel endpoints, which is
//! what lets the public API be `Send`/`Sync` and ordinary-tokio-shaped while
//! smoltcp's `!Send` sockets stay confined to one task.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::driver::Command;

/// Bytes flowing in one direction between a [`TcpStream`] and the driver.
/// `Vec<u8>` chunks keep the driver's per-poll servicing simple; the AsyncRead
/// side stitches them back into the caller's buffer.
pub(crate) type ByteChunk = Vec<u8>;

/// A userspace TCP stream over the consumer-supplied packet transport.
///
/// Mirrors the `net.Conn` returned by the Go `Conn.DialContextTCP` /
/// `listener.Accept`. Reads pull decrypted application bytes that the driver
/// drained from the smoltcp socket; writes push application bytes the driver
/// will feed into the smoltcp socket on its next poll.
pub struct TcpStream {
    /// Driver -> stream: received application bytes.
    pub(crate) rx: mpsc::UnboundedReceiver<ByteChunk>,
    /// Stream -> driver: bytes to send + flush/close signals.
    pub(crate) tx: mpsc::UnboundedSender<Command>,
    /// smoltcp socket handle this stream is bound to (for addressing commands).
    pub(crate) handle: smoltcp::iface::SocketHandle,
    /// Leftover bytes from a chunk that did not fit the last read buffer.
    pub(crate) read_carry: Option<(ByteChunk, usize)>,
    /// Set once the driver signals the receive half is closed (FIN/abort).
    pub(crate) rx_closed: bool,
}

impl TcpStream {
    pub(crate) fn new(
        handle: smoltcp::iface::SocketHandle,
        rx: mpsc::UnboundedReceiver<ByteChunk>,
        tx: mpsc::UnboundedSender<Command>,
    ) -> Self {
        Self {
            rx,
            tx,
            handle,
            read_carry: None,
            rx_closed: false,
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain any carried-over chunk first.
        if let Some((chunk, offset)) = self.read_carry.take() {
            let remaining = &chunk[offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            if offset + n < chunk.len() {
                self.read_carry = Some((chunk, offset + n));
            }
            return Poll::Ready(Ok(()));
        }

        if self.rx_closed {
            // Clean EOF.
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.read_carry = Some((chunk, n));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Driver dropped the sender => connection closed. EOF.
                self.rx_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // The driver's per-socket TX buffer is unbounded for the spike, so a
        // write never blocks here — it queues the bytes and wakes the driver.
        // Flow control / backpressure is deferred to the `Conn` wiring (#59).
        if self
            .tx
            .send(Command::Send {
                handle: self.handle,
                data: buf.to_vec(),
            })
            .is_err()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "netstack driver gone",
            )));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Sends are already queued to the driver; nothing buffered locally.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.tx.send(Command::Close {
            handle: self.handle,
        });
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Best-effort: ask the driver to tear down the socket so we do not leak
        // handles. Errors mean the driver is already gone.
        let _ = self.tx.send(Command::Drop {
            handle: self.handle,
        });
    }
}

/// A userspace TCP listener over the consumer-supplied packet transport.
///
/// Each `accept()` yields the next inbound [`TcpStream`].
pub struct TcpListener {
    pub(crate) endpoint: smoltcp::wire::IpListenEndpoint,
    pub(crate) incoming: mpsc::UnboundedReceiver<TcpStream>,
    /// Kept so the driver knows the listener is still alive; on drop the driver
    /// stops accepting on this port.
    pub(crate) _tx: mpsc::UnboundedSender<Command>,
}

impl TcpListener {
    /// Accept the next inbound connection. Returns `None` once the netstack is
    /// shut down (driver gone).
    pub async fn accept(&mut self) -> Option<TcpStream> {
        self.incoming.recv().await
    }

    /// The local port this listener is bound to.
    pub fn local_port(&self) -> u16 {
        self.endpoint.port
    }

    /// The exact address of this listener, when it is not a wildcard bind.
    pub fn local_endpoint(&self) -> Option<std::net::SocketAddr> {
        let address = match self.endpoint.addr? {
            smoltcp::wire::IpAddress::Ipv4(address) => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(address.octets()))
            }
            smoltcp::wire::IpAddress::Ipv6(address) => {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(address.octets()))
            }
        };
        Some(std::net::SocketAddr::new(address, self.endpoint.port))
    }
}
