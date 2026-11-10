//! Async-facing handles: [`TcpStream`] (an `AsyncRead + AsyncWrite` byte pipe
//! over one smoltcp socket) and [`TcpListener`] (an `accept()` queue of inbound
//! streams). These deliberately hold no smoltcp state — that lives in the
//! single-threaded [`super::driver`]. They are pure channel endpoints, which is
//! what lets the public API be `Send`/`Sync` and ordinary-tokio-shaped while
//! smoltcp's `!Send` sockets stay confined to one task.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    driver_closed: AtomicBool,
    accepted: AtomicU64,
    handed_off: AtomicU64,
    acknowledged: AtomicU64,
    flush_waker: Mutex<Option<Waker>>,
    notify: Arc<Notify>,
}

impl StreamControl {
    pub(crate) fn new(notify: Arc<Notify>) -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            peer_aborted: AtomicBool::new(false),
            driver_closed: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            handed_off: AtomicU64::new(0),
            acknowledged: AtomicU64::new(0),
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
        self.wake_writer();
    }

    fn peer_aborted(&self) -> bool {
        self.peer_aborted.load(Ordering::Acquire)
    }

    fn mark_write(&self, bytes: usize) {
        self.accepted.fetch_add(bytes as u64, Ordering::Release);
    }

    pub(crate) fn mark_handed_off(&self, bytes: usize) {
        self.handed_off.fetch_add(bytes as u64, Ordering::Release);
        self.wake_writer();
    }

    pub(crate) fn mark_acknowledged(&self) {
        // Only the driver updates handed_off. Its empty socket send buffer
        // proves those bytes were ACKed, even if another queue send has not
        // yet published its accepted position.
        self.acknowledged
            .store(self.handed_off.load(Ordering::Acquire), Ordering::Release);
        self.wake_writer();
    }

    fn wake_writer(&self) {
        let waker = self.flush_waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(crate) fn mark_driver_closed(&self) {
        self.driver_closed.store(true, Ordering::Release);
        self.wake_writer();
    }

    fn write_error(&self) -> Option<io::Error> {
        if self.peer_aborted() {
            Some(connection_aborted())
        } else if self.driver_closed.load(Ordering::Acquire) {
            Some(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "netstack driver gone",
            ))
        } else {
            None
        }
    }

    fn poll_progress(&self, cx: &mut Context<'_>, progress: &AtomicU64) -> Poll<io::Result<()>> {
        // These are wrapping byte positions, not an ordering comparison.
        // Bounded queues/socket buffers keep the distance below one wrap.
        let ready = || self.accepted.load(Ordering::Acquire) == progress.load(Ordering::Acquire);
        if let Some(error) = self.write_error() {
            return Poll::Ready(Err(error));
        }
        if ready() {
            return Poll::Ready(Ok(()));
        }
        let waker = cx.waker().clone();
        *self.flush_waker.lock().unwrap() = Some(waker);
        // Progress or abort may have happened before the waker was installed.
        if let Some(error) = self.write_error() {
            self.flush_waker.lock().unwrap().take();
            Poll::Ready(Err(error))
        } else if ready() {
            self.flush_waker.lock().unwrap().take();
            Poll::Ready(Ok(()))
        } else {
            self.notify.notify_one();
            Poll::Pending
        }
    }
}

fn connection_aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "userspace TCP connection aborted",
    )
}

/// A userspace TCP stream over the consumer-supplied packet transport.
///
/// Reads pull application bytes that the driver drained from the smoltcp
/// socket; writes push bounded application chunks that the driver feeds into
/// the socket on its next poll. Flush waits for that socket handoff, without
/// waiting for TCP acknowledgments. Shutdown waits for acknowledgments before
/// requesting FIN, so dropping a successfully shut-down stream retains its tail.
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
                // Taking a chunk frees receive-queue space. Wake the driver so
                // it moves the socket's buffered bytes on and reopens the TCP
                // window now, not at its next unrelated wakeup.
                self.control.notify.notify_one();
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
                this.tx.send_item(buf[..len].to_vec()).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "netstack driver gone")
                })?;
                this.control.mark_write(len);
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
        this.control.poll_progress(cx, &this.control.handed_off)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let this = self.as_mut().get_mut();
        match this.control.poll_progress(cx, &this.control.acknowledged) {
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

#[cfg(test)]
mod progress_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn queue_publication_can_follow_socket_and_ack_progress() {
        let control = StreamControl::new(Arc::new(Notify::new()));
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut cx = Context::from_waker(&waker);
        // A driver on another thread may process the successful queue send
        // before poll_write publishes accepted. Neither barrier may mistake
        // this transient ordering for completion.
        control.mark_handed_off(8);
        control.mark_acknowledged();
        assert!(control
            .poll_progress(&mut cx, &control.handed_off)
            .is_pending());
        assert!(control
            .poll_progress(&mut cx, &control.acknowledged)
            .is_pending());
        control.mark_write(8);
        assert!(matches!(
            control.poll_progress(&mut cx, &control.handed_off),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            control.poll_progress(&mut cx, &control.acknowledged),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn partial_handoff_and_acknowledgment_are_distinct_barriers() {
        let control = StreamControl::new(Arc::new(Notify::new()));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        control.mark_write(8);
        assert!(control
            .poll_progress(&mut cx, &control.handed_off)
            .is_pending());
        control.mark_handed_off(3);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(control
            .poll_progress(&mut cx, &control.handed_off)
            .is_pending());
        control.mark_handed_off(5);
        assert!(matches!(
            control.poll_progress(&mut cx, &control.handed_off),
            Poll::Ready(Ok(()))
        ));
        assert!(control
            .poll_progress(&mut cx, &control.acknowledged)
            .is_pending());
        control.mark_acknowledged();
        assert!(matches!(
            control.poll_progress(&mut cx, &control.acknowledged),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn abort_and_driver_close_wake_registered_waiters() {
        for abort in [false, true] {
            let control = StreamControl::new(Arc::new(Notify::new()));
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            control.mark_write(8);
            assert!(control
                .poll_progress(&mut cx, &control.handed_off)
                .is_pending());
            if abort {
                control.mark_peer_aborted();
            } else {
                control.mark_driver_closed();
            }
            assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
            let Poll::Ready(Err(error)) = control.poll_progress(&mut cx, &control.handed_off)
            else {
                panic!("closed writer must fail")
            };
            assert_eq!(
                error.kind(),
                if abort {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::BrokenPipe
                }
            );
        }
    }

    #[test]
    fn closure_before_accepted_publication_is_not_lost() {
        let control = StreamControl::new(Arc::new(Notify::new()));
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut cx = Context::from_waker(&waker);
        control.mark_handed_off(8);
        control.mark_acknowledged();
        control.mark_driver_closed();
        control.mark_write(8);
        let Poll::Ready(Err(error)) = control.poll_progress(&mut cx, &control.handed_off) else {
            panic!("closure must remain observable")
        };
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            !control.peer_aborted(),
            "normal driver closure is not a fabricated peer reset"
        );
    }

    #[test]
    fn byte_positions_work_across_wrap_without_ordering_or_subtraction() {
        let control = StreamControl::new(Arc::new(Notify::new()));
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut cx = Context::from_waker(&waker);
        for position in [
            &control.accepted,
            &control.handed_off,
            &control.acknowledged,
        ] {
            position.store(u64::MAX - 3, Ordering::Release);
        }
        control.mark_write(8);
        control.mark_handed_off(3);
        assert!(control
            .poll_progress(&mut cx, &control.handed_off)
            .is_pending());
        control.mark_handed_off(5);
        assert!(matches!(
            control.poll_progress(&mut cx, &control.handed_off),
            Poll::Ready(Ok(()))
        ));
        assert!(control
            .poll_progress(&mut cx, &control.acknowledged)
            .is_pending());
        control.mark_acknowledged();
        assert!(matches!(
            control.poll_progress(&mut cx, &control.acknowledged),
            Poll::Ready(Ok(()))
        ));
    }
}
