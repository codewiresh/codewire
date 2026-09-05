//! Async-facing handles: [`TcpStream`] (an `AsyncRead + AsyncWrite` byte pipe
//! over one smoltcp socket) and [`TcpListener`] (an `accept()` queue of inbound
//! streams). These deliberately hold no smoltcp state — that lives in the
//! single-threaded [`super::driver`]. They are pure channel endpoints, which is
//! what lets the public API be `Send`/`Sync` and ordinary-tokio-shaped while
//! smoltcp's `!Send` sockets stay confined to one task.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio_util::sync::PollSender;

use super::driver::Command;

/// Bytes flowing in one direction between a [`TcpStream`] and the driver.
/// `Vec<u8>` chunks keep the driver's per-poll servicing simple; the AsyncRead
/// side stitches them back into the caller's buffer.
pub(crate) type ByteChunk = Vec<u8>;

/// Driver-visible lifecycle flags for a stream. These are bounded by the live
/// connection count and avoid relying on a possibly-full command queue for
/// shutdown or drop notification.
pub(crate) struct StreamControl {
    shutdown: AtomicBool,
    dropped: AtomicBool,
    peer_aborted: AtomicBool,
    flush_complete: AtomicBool,
    flush_waker: Mutex<Option<Waker>>,
    notify: Arc<Notify>,
}

impl StreamControl {
    pub(crate) fn new(notify: Arc<Notify>) -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            peer_aborted: AtomicBool::new(false),
            flush_complete: AtomicBool::new(true),
            flush_waker: Mutex::new(None),
            notify,
        }
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub(crate) fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }

    pub(crate) fn mark_peer_aborted(&self) {
        self.peer_aborted.store(true, Ordering::Release);
        if let Some(waker) = self.flush_waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn peer_aborted(&self) -> bool {
        self.peer_aborted.load(Ordering::Acquire)
    }

    fn mark_write(&self) {
        self.flush_complete.store(false, Ordering::Release);
    }

    pub(crate) fn mark_flushed(&self) {
        self.flush_complete.store(true, Ordering::Release);
        if let Some(waker) = self.flush_waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn poll_flushed(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.flush_complete.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *self.flush_waker.lock().unwrap() = Some(cx.waker().clone());
        if self.flush_complete.load(Ordering::Acquire) {
            self.flush_waker.lock().unwrap().take();
            Poll::Ready(())
        } else {
            self.notify.notify_one();
            Poll::Pending
        }
    }
}

/// A userspace TCP stream over the consumer-supplied packet transport.
///
/// Reads pull application bytes that the driver drained from the smoltcp
/// socket; writes push bounded application chunks that the driver feeds into
/// the socket on its next poll.
pub struct TcpStream {
    /// Driver -> stream: received application bytes.
    pub(crate) rx: mpsc::Receiver<ByteChunk>,
    /// Stream -> driver: bounded application-byte chunks.
    pub(crate) tx: PollSender<ByteChunk>,
    pub(crate) control: Arc<StreamControl>,
    /// Keeps the driver command channel alive while this stream exists.
    pub(crate) _driver_tx: mpsc::Sender<Command>,
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    max_write_chunk: usize,
    /// Leftover bytes from a chunk that did not fit the last read buffer.
    pub(crate) read_carry: Option<(ByteChunk, usize)>,
    /// Set once the driver signals the receive half is closed (FIN/abort).
    pub(crate) rx_closed: bool,
    abort_reported: bool,
}

impl TcpStream {
    pub(crate) fn new(
        rx: mpsc::Receiver<ByteChunk>,
        tx: mpsc::Sender<ByteChunk>,
        control: Arc<StreamControl>,
        driver_tx: mpsc::Sender<Command>,
        local: smoltcp::wire::IpEndpoint,
        peer: smoltcp::wire::IpEndpoint,
        max_write_chunk: usize,
    ) -> Self {
        Self {
            rx,
            tx: PollSender::new(tx),
            control,
            _driver_tx: driver_tx,
            local_addr: socket_addr(local),
            peer_addr: socket_addr(peer),
            max_write_chunk,
            read_carry: None,
            rx_closed: false,
            abort_reported: false,
        }
    }

    /// Address accepted by the userspace socket. In transparent AnyIP mode,
    /// this is the original destination requested by the guest.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Source address of the peer on the packet transport.
    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
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
            if self.control.peer_aborted() && !self.abort_reported {
                self.abort_reported = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "userspace TCP connection aborted",
                )));
            }
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
                if self.control.peer_aborted() && !self.abort_reported {
                    self.abort_reported = true;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "userspace TCP connection aborted",
                    )))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.control.shutdown_requested() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "userspace TCP write half is closed",
            )));
        }
        if this.control.peer_aborted() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "userspace TCP connection aborted",
            )));
        }
        match this.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "netstack driver gone",
            ))),
            Poll::Ready(Ok(())) => {
                let len = buf.len().min(this.max_write_chunk);
                this.control.mark_write();
                this.tx.send_item(buf[..len].to_vec()).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "netstack driver gone")
                })?;
                this.control.notify.notify_one();
                Poll::Ready(Ok(len))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.control.peer_aborted() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "userspace TCP connection aborted",
            )));
        }
        if this.tx.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "netstack driver gone",
            )));
        }
        this.control.poll_flushed(cx).map(Ok)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        self.control.shutdown.store(true, Ordering::Release);
        self.control.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // A successful AsyncWrite shutdown requests a FIN. Dropping the handle
        // afterward must let the bounded driver finish that graceful close;
        // dropping without shutdown is an abort and produces a peer-visible
        // reset.
        if !self.control.shutdown_requested() {
            self.control.dropped.store(true, Ordering::Release);
        }
        self.control.notify.notify_one();
    }
}

/// A userspace TCP listener over the consumer-supplied packet transport.
///
/// Each `accept()` yields the next inbound [`TcpStream`].
pub struct TcpListener {
    pub(crate) endpoint: smoltcp::wire::IpListenEndpoint,
    pub(crate) incoming: mpsc::Receiver<TcpStream>,
    /// Kept so the driver knows the listener is still alive; on drop the driver
    /// stops accepting on this port.
    pub(crate) _tx: mpsc::Sender<Command>,
    pub(crate) notify: Arc<Notify>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

fn socket_addr(endpoint: smoltcp::wire::IpEndpoint) -> std::net::SocketAddr {
    let address = match endpoint.addr {
        smoltcp::wire::IpAddress::Ipv4(address) => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(address.octets()))
        }
        smoltcp::wire::IpAddress::Ipv6(address) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(address.octets()))
        }
    };
    std::net::SocketAddr::new(address, endpoint.port)
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
