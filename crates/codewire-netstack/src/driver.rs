//! The single-threaded netstack driver.
//!
//! smoltcp's `Interface`, `SocketSet`, and TCP sockets are `!Send` and assume
//! exclusive, synchronous access. We confine them all to one tokio task (this
//! driver) and talk to it exclusively over channels. That keeps the public
//! handles ([`super::stream::TcpStream`] / [`super::stream::TcpListener`])
//! `Send` and ordinary-async-shaped while smoltcp stays single-threaded.
//!
//! Responsibilities each wakeup:
//!   1. Stage inbound IP packets from the consumer transport into the device.
//!   2. Apply pending control commands (connect/bind/send/close/drop).
//!   3. `poll` smoltcp (advances handshakes, ACKs, retransmits, emits packets).
//!   4. Service every managed socket: drain RX -> stream, push queued TX into
//!      the socket, detect established/closed transitions, replenish LISTEN
//!      backlog.
//!   5. Sleep until the earliest of: a new inbound packet, a new command, or
//!      smoltcp's own `poll_at` deadline (retransmit/delayed-ACK timers).

use std::collections::HashMap;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;

use super::device::ChannelDevice;
use super::stream::{ByteChunk, TcpListener, TcpStream};

/// Per-socket send/receive ring sizes (bytes). 64 KiB matches a generous
/// default TCP window and is plenty for the spike's payloads.
const SOCKET_BUF: usize = 64 * 1024;

/// How many LISTEN-state sockets to keep parked per bound port.
///
/// smoltcp does not expose a kernel-style accept queue here; each parked
/// listener is a real TCP socket. Keeping multiple sockets on the same listen
/// endpoint can make later payload packets race sibling LISTEN sockets instead
/// of the newly-established socket. Keep one listener and replenish it
/// immediately after accept. A simultaneous SYN can retransmit during that
/// tiny handoff window, while established stream demux stays deterministic.
const LISTEN_BACKLOG: usize = 1;

/// Control messages from handles/the API into the driver.
pub(crate) enum Command {
    /// Bind a listener on `port`; reply with the listener's incoming-stream
    /// receiver wired up.
    Bind {
        endpoint: IpListenEndpoint,
        reply: tokio::sync::oneshot::Sender<TcpListener>,
    },
    /// Dial `remote`; reply with the connecting stream (resolves before the
    /// handshake completes — reads/writes drive it, mirroring tokio's
    /// `TcpStream::connect` returning a connected-enough socket).
    Connect {
        remote: IpEndpoint,
        reply: tokio::sync::oneshot::Sender<TcpStream>,
    },
    /// Application bytes to send on `handle`.
    Send { handle: SocketHandle, data: Vec<u8> },
    /// Half-close (FIN) `handle`.
    Close { handle: SocketHandle },
    /// The stream handle was dropped; abort + reap `handle`.
    Drop { handle: SocketHandle },
}

/// State the driver keeps for one connected (or connecting) socket.
struct Conn {
    /// Driver -> stream: received bytes. `None` once the stream side is gone.
    to_stream: Option<mpsc::UnboundedSender<ByteChunk>>,
    /// Bytes queued from the stream that did not fit the socket's tx buffer yet.
    pending_tx: std::collections::VecDeque<u8>,
    /// FIN requested by the stream; flush remaining tx then close.
    closing: bool,
    /// We have observed the socket become active (handshake done) at least once.
    was_active: bool,
}

impl Conn {
    fn new(to_stream: mpsc::UnboundedSender<ByteChunk>) -> Self {
        Self {
            to_stream: Some(to_stream),
            pending_tx: std::collections::VecDeque::new(),
            closing: false,
            was_active: false,
        }
    }
}

/// A bound listener's accept side, owned by the driver.
struct ListenSlot {
    /// Driver -> listener: newly accepted streams.
    to_listener: mpsc::UnboundedSender<TcpStream>,
    /// Handles currently parked in LISTEN on this port (the backlog).
    listening: Vec<SocketHandle>,
}

/// Owns all smoltcp state. Lives entirely inside [`run`].
struct Driver {
    iface: Interface,
    device: ChannelDevice,
    sockets: SocketSet<'static>,
    conns: HashMap<SocketHandle, Conn>,
    listeners: HashMap<IpListenEndpoint, ListenSlot>,
    /// Clone handed to every stream so its writes/closes reach us.
    cmd_tx: mpsc::UnboundedSender<Command>,
}

impl Driver {
    fn fresh_tcp_socket() -> tcp::Socket<'static> {
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        tcp::Socket::new(rx, tx)
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Bind { endpoint, reply } => {
                let (to_listener, incoming) = mpsc::unbounded_channel();
                let mut slot = ListenSlot {
                    to_listener,
                    listening: Vec::new(),
                };
                for _ in 0..LISTEN_BACKLOG {
                    if let Some(h) = self.spawn_listen_socket(endpoint) {
                        slot.listening.push(h);
                    }
                }
                self.listeners.insert(endpoint, slot);
                tracing::debug!(
                    listen_addr = ?endpoint.addr,
                    listen_port = endpoint.port,
                    backlog = LISTEN_BACKLOG,
                    "rust userspace netstack listener bound"
                );
                let listener = TcpListener {
                    endpoint,
                    incoming,
                    _tx: self.cmd_tx.clone(),
                };
                let _ = reply.send(listener);
            }
            Command::Connect { remote, reply } => {
                let mut socket = Self::fresh_tcp_socket();
                // Ephemeral local port. smoltcp picks one if we pass 0 as the
                // listen endpoint port; we give an explicit high port to keep
                // the handshake deterministic for the spike.
                let local_port = self.next_ephemeral_port();
                let result = socket.connect(self.iface.context(), remote, local_port);
                let handle = self.sockets.add(socket);
                let (to_stream, rx) = mpsc::unbounded_channel();
                let stream = TcpStream::new(handle, rx, self.cmd_tx.clone());
                if result.is_ok() {
                    tracing::debug!(
                        remote_addr = ?remote.addr,
                        remote_port = remote.port,
                        local_port,
                        "rust userspace netstack TCP connect started"
                    );
                    self.conns.insert(handle, Conn::new(to_stream));
                } else {
                    // Connect setup failed; drop the socket so the stream EOFs.
                    tracing::debug!(
                        remote_addr = ?remote.addr,
                        remote_port = remote.port,
                        local_port,
                        error = ?result.err(),
                        "rust userspace netstack TCP connect setup failed"
                    );
                    self.sockets.remove(handle);
                }
                let _ = reply.send(stream);
            }
            Command::Send { handle, data } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.pending_tx.extend(data);
                }
            }
            Command::Close { handle } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.closing = true;
                }
            }
            Command::Drop { handle } => {
                if self.conns.remove(&handle).is_some()
                    && self.sockets.iter().any(|(h, _)| h == handle)
                {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                }
            }
        }
    }

    /// Create a new socket parked on one listen endpoint.
    fn spawn_listen_socket(&mut self, endpoint: IpListenEndpoint) -> Option<SocketHandle> {
        let mut socket = Self::fresh_tcp_socket();
        socket.listen(endpoint).ok()?;
        Some(self.sockets.add(socket))
    }

    fn next_ephemeral_port(&mut self) -> u16 {
        // Simple rotating counter in the dynamic/private range. Good enough for
        // a single-process spike; the `Conn` wiring can adopt a real allocator.
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(49152);
        let p = NEXT.fetch_add(1, Ordering::Relaxed);
        if p == 0 {
            49152
        } else {
            p
        }
    }

    /// Drain inbound packets, apply timers, poll, and service sockets.
    /// Returns the instant smoltcp wants to be polled again (if any).
    fn pump(&mut self) -> Option<Instant> {
        let now = now();
        let mut poll_at = None;

        // smoltcp only emits TCP packets from bytes already queued in its
        // socket buffers. `service_sockets` is what moves application writes
        // into those buffers, so a single poll-before-service can strand
        // freshly queued SSH handshake bytes until another external wakeup.
        // Bound the loop to avoid a busy spin while still flushing immediate
        // receive/write/ACK work like Tailscale's gVisor netstack does.
        for _ in 0..8 {
            let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.service_sockets();
            poll_at = self.iface.poll_at(now, &self.sockets);
            if !self.has_immediate_work() {
                break;
            }
        }

        poll_at
    }

    fn has_immediate_work(&self) -> bool {
        if self.device.has_inbound() {
            return true;
        }

        for h in self.conns.keys().copied() {
            if !self.sockets.iter().any(|(x, _)| x == h) {
                continue;
            }
            if self
                .conns
                .get(&h)
                .is_some_and(|conn| !conn.pending_tx.is_empty())
            {
                return true;
            }
            let socket = self.sockets.get::<tcp::Socket>(h);
            if socket.recv_queue() > 0 || socket.send_queue() > 0 {
                return true;
            }
        }

        for slot in self.listeners.values() {
            for &h in &slot.listening {
                if !self.sockets.iter().any(|(x, _)| x == h) {
                    continue;
                }
                let socket = self.sockets.get::<tcp::Socket>(h);
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    return true;
                }
            }
        }

        false
    }

    /// Move bytes between smoltcp sockets and the stream channels, and react to
    /// connection state transitions (accept, established, closed).
    fn service_sockets(&mut self) {
        // 1) Promote any LISTEN socket that became connected into an accepted
        //    stream, and replenish the backlog.
        let mut promotions: Vec<(IpListenEndpoint, SocketHandle)> = Vec::new();
        for (endpoint, slot) in self.listeners.iter() {
            for &h in slot.listening.iter() {
                let socket = self.sockets.get::<tcp::Socket>(h);
                let state = socket.state();
                if matches!(state, tcp::State::Established | tcp::State::CloseWait) {
                    tracing::debug!(
                        listen_addr = ?endpoint.addr,
                        listen_port = endpoint.port,
                        ?state,
                        "rust userspace netstack TCP listener socket established"
                    );
                    promotions.push((*endpoint, h));
                }
            }
        }
        for (endpoint, h) in promotions {
            // Remove from the backlog list and wire up a stream.
            let mut new_listener: Option<SocketHandle> = None;
            if let Some(slot) = self.listeners.get_mut(&endpoint) {
                slot.listening.retain(|&x| x != h);
                let (to_stream, rx) = mpsc::unbounded_channel();
                let stream = TcpStream::new(h, rx, self.cmd_tx.clone());
                if slot.to_listener.send(stream).is_ok() {
                    tracing::debug!(
                        listen_addr = ?endpoint.addr,
                        listen_port = endpoint.port,
                        "rust userspace netstack TCP stream accepted"
                    );
                    self.conns.insert(h, Conn::new(to_stream));
                } else {
                    // Listener gone; abort the socket.
                    let socket = self.sockets.get_mut::<tcp::Socket>(h);
                    socket.abort();
                }
            }
            // Replenish backlog outside the borrow above.
            if self.listeners.contains_key(&endpoint) {
                new_listener = self.spawn_listen_socket(endpoint);
            }
            if let (Some(slot), Some(nh)) = (self.listeners.get_mut(&endpoint), new_listener) {
                slot.listening.push(nh);
            }
        }

        // 2) For every connected socket: push queued tx, drain rx, handle close.
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            if !self.sockets.iter().any(|(x, _)| x == h) {
                // Socket already reaped.
                self.conns.remove(&h);
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(h);

            // Track first activation.
            if socket.is_active() {
                if let Some(conn) = self.conns.get_mut(&h) {
                    conn.was_active = true;
                }
            }

            // Push queued tx bytes into the socket as far as it will take them.
            if socket.can_send() {
                if let Some(conn) = self.conns.get_mut(&h) {
                    while !conn.pending_tx.is_empty() {
                        let (front, _) = conn.pending_tx.as_slices();
                        if front.is_empty() {
                            break;
                        }
                        match socket.send_slice(front) {
                            Ok(0) => break,
                            Ok(n) => {
                                tracing::debug!(
                                    bytes = n,
                                    "rust userspace netstack queued TCP transmit bytes"
                                );
                                conn.pending_tx.drain(..n);
                            }
                            Err(_) => break,
                        }
                    }
                }
            }

            // Drain received bytes up to the stream.
            while socket.can_recv() {
                let chunk = socket.recv(|data| {
                    let v = data.to_vec();
                    (v.len(), v)
                });
                match chunk {
                    Ok(v) if !v.is_empty() => {
                        tracing::debug!(
                            bytes = v.len(),
                            "rust userspace netstack delivered TCP receive bytes"
                        );
                        if let Some(conn) = self.conns.get_mut(&h) {
                            if let Some(tx) = &conn.to_stream {
                                if tx.send(v).is_err() {
                                    conn.to_stream = None;
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }

            // Apply a requested half-close once tx is fully flushed.
            let drained = self
                .conns
                .get(&h)
                .map(|c| c.pending_tx.is_empty())
                .unwrap_or(true);
            let closing = self.conns.get(&h).map(|c| c.closing).unwrap_or(false);
            if closing && drained {
                let socket = self.sockets.get_mut::<tcp::Socket>(h);
                if socket.send_queue() == 0 {
                    socket.close();
                }
            }

            // Reap fully-closed sockets and signal EOF to the stream.
            let socket = self.sockets.get::<tcp::Socket>(h);
            let was_active = self.conns.get(&h).map(|c| c.was_active).unwrap_or(false);
            let dead = matches!(socket.state(), tcp::State::Closed)
                || (was_active && !socket.is_active() && socket.recv_queue() == 0);
            if dead {
                // Dropping `to_stream` signals EOF to the reader.
                if let Some(conn) = self.conns.get_mut(&h) {
                    conn.to_stream = None;
                }
                // Only fully remove once recv is drained and socket is closed.
                if matches!(socket.state(), tcp::State::Closed) {
                    self.sockets.remove(h);
                    self.conns.remove(&h);
                }
            }
        }
    }
}

/// Current time as a smoltcp `Instant`. smoltcp only needs a monotonically
/// increasing clock; tokio's wall clock via `SystemTime` is fine for the spike.
fn now() -> Instant {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Instant::from_micros(dur.as_micros() as i64)
}

/// Handle used by the public API to talk to a running driver.
#[derive(Clone)]
pub(crate) struct DriverHandle {
    pub(crate) cmd_tx: mpsc::UnboundedSender<Command>,
}

/// Spawn the driver task. `inbound` delivers IP packets from the consumer
/// transport; the driver's device emits outbound IP packets on the
/// `outbound` sender supplied when the device was built.
pub(crate) fn spawn(
    local_ip: IpAddress,
    prefix_len: u8,
    accept_any_ip: bool,
    default_gateway: Option<IpAddress>,
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    device: ChannelDevice,
) -> std::io::Result<DriverHandle> {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Command>();
    let handle = DriverHandle {
        cmd_tx: cmd_tx.clone(),
    };

    let mut device = device;
    // Build the interface at the bare-IP medium with the configured address.
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(local_ip, prefix_len));
    });
    iface.set_any_ip(accept_any_ip);
    match default_gateway {
        Some(IpAddress::Ipv4(gateway)) => {
            iface
                .routes_mut()
                .add_default_ipv4_route(gateway)
                .map_err(|_| std::io::Error::other("netstack IPv4 route table is full"))?;
        }
        Some(IpAddress::Ipv6(gateway)) => {
            iface
                .routes_mut()
                .add_default_ipv6_route(gateway)
                .map_err(|_| std::io::Error::other("netstack IPv6 route table is full"))?;
        }
        None => {}
    }

    let mut driver = Driver {
        iface,
        device,
        sockets: SocketSet::new(Vec::new()),
        conns: HashMap::new(),
        listeners: HashMap::new(),
        cmd_tx,
    };

    tokio::spawn(async move {
        // Prime once.
        let mut poll_at = driver.pump();
        loop {
            // Compute how long to sleep before smoltcp's next timer.
            let timer = match poll_at {
                Some(at) => {
                    let n = now();
                    if at <= n {
                        // Already due — don't sleep.
                        tokio::time::Duration::from_millis(0)
                    } else {
                        let micros = (at - n).total_micros();
                        tokio::time::Duration::from_micros(micros)
                    }
                }
                // No pending smoltcp timer; cap the idle wait so we still notice
                // device-level work that did not register a timer.
                None => tokio::time::Duration::from_millis(50),
            };

            tokio::select! {
                // Inbound IP packet from the consumer transport.
                pkt = inbound.recv() => {
                    match pkt {
                        Some(pkt) => {
                            driver.device.push_inbound(pkt);
                            // Drain any other immediately-available packets.
                            while let Ok(p) = inbound.try_recv() {
                                driver.device.push_inbound(p);
                            }
                            poll_at = driver.pump();
                        }
                        None => break, // inbound channel closed => shut down.
                    }
                }
                // Control command from a handle.
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            driver.handle_command(cmd);
                            // Drain any other queued commands before polling.
                            while let Ok(c) = cmd_rx.try_recv() {
                                driver.handle_command(c);
                            }
                            poll_at = driver.pump();
                        }
                        None => break,
                    }
                }
                // smoltcp timer fired (retransmit / delayed ACK / etc).
                _ = tokio::time::sleep(timer) => {
                    poll_at = driver.pump();
                }
            }

            // If the device still has staged inbound work or any socket has
            // queued tx, keep pumping promptly rather than sleeping.
            if driver.device.has_inbound() {
                poll_at = Some(now());
            }
        }
    });

    Ok(handle)
}
