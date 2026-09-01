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
//!   2. Apply pending control commands (connect/bind).
//!   3. `poll` smoltcp (advances handshakes, ACKs, retransmits, emits packets).
//!   4. Service every managed socket: drain RX -> stream, push queued TX into
//!      the socket, detect established/closed transitions, replenish LISTEN
//!      backlog.
//!   5. Sleep until the earliest of: a new inbound packet, a new command, or
//!      smoltcp's own `poll_at` deadline (retransmit/delayed-ACK timers).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;
use tokio::sync::Notify;

use super::device::ChannelDevice;
use super::stream::{ByteChunk, StreamControl, TcpListener, TcpStream};
use super::NetstackLimits;

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
        reply: tokio::sync::oneshot::Sender<std::io::Result<TcpListener>>,
    },
    /// Dial `remote`; reply with the connecting stream (resolves before the
    /// handshake completes — reads/writes drive it, mirroring tokio's
    /// `TcpStream::connect` returning a connected-enough socket).
    Connect {
        remote: IpEndpoint,
        reply: tokio::sync::oneshot::Sender<std::io::Result<TcpStream>>,
    },
}

/// State the driver keeps for one connected (or connecting) socket.
struct Conn {
    /// Driver -> stream: received bytes.
    to_stream: Option<mpsc::Sender<ByteChunk>>,
    /// Stream -> driver: bounded application writes.
    from_stream: mpsc::Receiver<ByteChunk>,
    control: Arc<StreamControl>,
    /// Bytes queued from the stream that did not fit the socket's tx buffer yet.
    pending_tx: VecDeque<u8>,
    /// We have observed the socket complete its handshake at least once.
    was_established: bool,
}

impl Conn {
    fn new(
        to_stream: mpsc::Sender<ByteChunk>,
        from_stream: mpsc::Receiver<ByteChunk>,
        control: Arc<StreamControl>,
    ) -> Self {
        Self {
            to_stream: Some(to_stream),
            from_stream,
            control,
            pending_tx: VecDeque::new(),
            was_established: false,
        }
    }
}

/// A bound listener's accept side, owned by the driver.
struct ListenSlot {
    /// Driver -> listener: newly accepted streams.
    to_listener: mpsc::Sender<TcpStream>,
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
    cmd_tx: mpsc::Sender<Command>,
    stream_notify: Arc<Notify>,
    limits: NetstackLimits,
    next_ephemeral_port: u16,
    abort_after_poll: HashSet<SocketHandle>,
}

impl Driver {
    fn fresh_tcp_socket(&self) -> tcp::Socket<'static> {
        let rx = tcp::SocketBuffer::new(vec![0u8; self.limits.socket_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0u8; self.limits.socket_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_timeout(Some(SmolDuration::from(self.limits.tcp_idle_timeout)));
        socket
    }

    fn handle_command(&mut self, cmd: Command) {
        self.reap_closed_handles();
        match cmd {
            Command::Bind { endpoint, reply } => {
                if self.listeners.contains_key(&endpoint) {
                    let _ = reply.send(Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "netstack TCP endpoint is already bound",
                    )));
                    return;
                }
                if self.listeners.len() >= self.limits.max_listeners {
                    let _ = reply.send(Err(std::io::Error::other(
                        "netstack TCP listener limit reached",
                    )));
                    return;
                }
                let (to_listener, incoming) = mpsc::channel(self.limits.accept_queue);
                let mut slot = ListenSlot {
                    to_listener,
                    listening: Vec::new(),
                };
                for _ in 0..LISTEN_BACKLOG {
                    if let Some(h) = self.spawn_listen_socket(endpoint) {
                        slot.listening.push(h);
                    }
                }
                if slot.listening.len() != LISTEN_BACKLOG {
                    let _ = reply.send(Err(std::io::Error::other(
                        "netstack could not allocate a TCP listener socket",
                    )));
                    return;
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
                    notify: self.stream_notify.clone(),
                };
                let _ = reply.send(Ok(listener));
            }
            Command::Connect { remote, reply } => {
                if self.conns.len() >= self.limits.max_connections {
                    let _ = reply.send(Err(std::io::Error::other(
                        "netstack TCP connection limit reached",
                    )));
                    return;
                }
                let mut socket = self.fresh_tcp_socket();
                // Ephemeral local port. smoltcp picks one if we pass 0 as the
                // listen endpoint port; we give an explicit high port to keep
                // allocation deterministic inside this bounded engine.
                let local_port = self.next_ephemeral_port();
                let result = socket.connect(self.iface.context(), remote, local_port);
                if let Err(error) = result {
                    tracing::debug!(
                        remote_addr = ?remote.addr,
                        remote_port = remote.port,
                        local_port,
                        ?error,
                        "rust userspace netstack TCP connect setup failed"
                    );
                    let _ = reply.send(Err(std::io::Error::other(format!(
                        "netstack TCP connect setup failed: {error:?}"
                    ))));
                    return;
                }
                let handle = self.sockets.add(socket);
                let Some((stream, conn)) = self.stream_for_socket(handle) else {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(std::io::Error::other(
                        "netstack TCP socket has no endpoints",
                    )));
                    return;
                };
                tracing::debug!(
                    remote_addr = ?remote.addr,
                    remote_port = remote.port,
                    local_port,
                    "rust userspace netstack TCP connect started"
                );
                self.conns.insert(handle, conn);
                let _ = reply.send(Ok(stream));
            }
        }
    }

    fn stream_for_socket(&self, handle: SocketHandle) -> Option<(TcpStream, Conn)> {
        let socket = self.sockets.get::<tcp::Socket>(handle);
        let local = socket.local_endpoint()?;
        let peer = socket.remote_endpoint()?;
        let (to_stream, rx) = mpsc::channel(self.limits.stream_receive_queue);
        let (tx, from_stream) = mpsc::channel(self.limits.stream_send_queue);
        let control = Arc::new(StreamControl::new(self.stream_notify.clone()));
        let stream = TcpStream::new(
            rx,
            tx,
            control.clone(),
            self.cmd_tx.clone(),
            local,
            peer,
            self.limits.stream_chunk_bytes,
        );
        Some((stream, Conn::new(to_stream, from_stream, control)))
    }

    fn reap_closed_handles(&mut self) {
        let endpoints: Vec<_> = self
            .listeners
            .iter()
            .filter_map(|(endpoint, slot)| slot.to_listener.is_closed().then_some(*endpoint))
            .collect();
        for endpoint in endpoints {
            if let Some(slot) = self.listeners.remove(&endpoint) {
                for handle in slot.listening {
                    self.schedule_abort(handle);
                }
            }
        }

        let handles: Vec<_> = self
            .conns
            .iter()
            .filter_map(|(handle, conn)| conn.control.dropped().then_some(*handle))
            .collect();
        for handle in handles {
            self.conns.remove(&handle);
            self.schedule_abort(handle);
        }
    }

    fn schedule_abort(&mut self, handle: SocketHandle) {
        if self
            .sockets
            .iter()
            .any(|(candidate, _)| candidate == handle)
        {
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
            self.abort_after_poll.insert(handle);
        }
    }

    /// Create a new socket parked on one listen endpoint.
    fn spawn_listen_socket(&mut self, endpoint: IpListenEndpoint) -> Option<SocketHandle> {
        let mut socket = self.fresh_tcp_socket();
        socket.listen(endpoint).ok()?;
        Some(self.sockets.add(socket))
    }

    fn next_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if port == u16::MAX { 49152 } else { port + 1 };
        port
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
        // receive/write/ACK work promptly.
        for _ in 0..8 {
            let pending_aborts: Vec<_> = self.abort_after_poll.iter().copied().collect();
            let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
            for handle in pending_aborts {
                if self
                    .sockets
                    .iter()
                    .any(|(candidate, _)| candidate == handle)
                {
                    self.sockets.remove(handle);
                }
                self.abort_after_poll.remove(&handle);
            }
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
        if !self.abort_after_poll.is_empty() {
            return true;
        }

        for h in self.conns.keys().copied() {
            if !self.sockets.iter().any(|(x, _)| x == h) {
                continue;
            }
            if self.conns.get(&h).is_some_and(|conn| {
                !conn.pending_tx.is_empty()
                    || !conn.from_stream.is_empty()
                    || conn.control.dropped()
            }) {
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
        self.reap_closed_handles();

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
            if let Some(slot) = self.listeners.get_mut(&endpoint) {
                slot.listening.retain(|&x| x != h);
            }

            let accepted = if self.conns.len() >= self.limits.max_connections {
                tracing::debug!(
                    listen_addr = ?endpoint.addr,
                    listen_port = endpoint.port,
                    connection_limit = self.limits.max_connections,
                    "rust userspace netstack rejected TCP stream at connection limit"
                );
                false
            } else if let Some((stream, conn)) = self.stream_for_socket(h) {
                let delivered = self
                    .listeners
                    .get(&endpoint)
                    .is_some_and(|slot| slot.to_listener.try_send(stream).is_ok());
                if delivered {
                    tracing::debug!(
                        listen_addr = ?endpoint.addr,
                        listen_port = endpoint.port,
                        "rust userspace netstack TCP stream accepted"
                    );
                    self.conns.insert(h, conn);
                }
                delivered
            } else {
                false
            };

            if !accepted {
                self.schedule_abort(h);
            }

            // Replenish the single parked socket only while the listener's
            // bounded accept receiver still exists.
            let replenish = self
                .listeners
                .get(&endpoint)
                .is_some_and(|slot| !slot.to_listener.is_closed());
            if replenish {
                let new_listener = self.spawn_listen_socket(endpoint);
                if let (Some(slot), Some(handle)) =
                    (self.listeners.get_mut(&endpoint), new_listener)
                {
                    slot.listening.push(handle);
                }
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
            if self
                .conns
                .get(&h)
                .is_some_and(|conn| conn.control.dropped())
            {
                self.conns.remove(&h);
                self.schedule_abort(h);
                continue;
            }

            let socket = self.sockets.get_mut::<tcp::Socket>(h);
            let conn = self.conns.get_mut(&h).expect("connection handle exists");

            // `is_active` includes SYN-SENT/SYN-RECEIVED. Track only a
            // completed handshake so a connecting socket cannot signal EOF.
            if matches!(
                socket.state(),
                tcp::State::Established
                    | tcp::State::CloseWait
                    | tcp::State::FinWait1
                    | tcp::State::FinWait2
                    | tcp::State::Closing
                    | tcp::State::LastAck
                    | tcp::State::TimeWait
            ) {
                conn.was_established = true;
            }

            // Pull at most one bounded stream chunk at a time, then move it
            // into smoltcp. Leaving later chunks in the bounded channel makes
            // AsyncWrite observe real TCP backpressure.
            while socket.can_send() {
                if conn.pending_tx.is_empty() {
                    match conn.from_stream.try_recv() {
                        Ok(chunk) => conn.pending_tx.extend(chunk),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
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

            // Drain received bytes only while the bounded application queue
            // has capacity. A full queue leaves bytes in the TCP receive
            // window, applying protocol-level backpressure to the peer.
            while socket.can_recv() {
                let Some(to_stream) = conn.to_stream.clone() else {
                    break;
                };
                let permit = match to_stream.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        conn.to_stream = None;
                        break;
                    }
                };
                let chunk = socket.recv(|data| {
                    let len = data.len().min(self.limits.stream_chunk_bytes);
                    (len, data[..len].to_vec())
                });
                match chunk {
                    Ok(v) if !v.is_empty() => {
                        tracing::debug!(
                            bytes = v.len(),
                            "rust userspace netstack delivered TCP receive bytes"
                        );
                        permit.send(v);
                    }
                    _ => break,
                }
            }

            if matches!(socket.state(), tcp::State::Closed) && !conn.control.shutdown_requested() {
                conn.control.mark_peer_aborted();
            }

            // A peer FIN closes only the receive half. Drop the application
            // sender once smoltcp has drained it so AsyncRead observes EOF,
            // while retaining the socket and write half for a response.
            if conn.was_established && !socket.may_recv() && socket.recv_queue() == 0 {
                conn.to_stream = None;
            }

            // Apply a requested half-close once tx is fully flushed.
            let drained = conn.pending_tx.is_empty() && conn.from_stream.is_empty();
            if drained && socket.send_queue() == 0 {
                conn.control.mark_flushed();
            }
            if conn.control.shutdown_requested() && drained && socket.send_queue() == 0 {
                socket.close();
            }

            // Reap fully-closed sockets and signal EOF to the stream.
            let was_established = conn.was_established;
            let dead = matches!(socket.state(), tcp::State::Closed)
                || (was_established && !socket.is_active() && socket.recv_queue() == 0);
            if dead {
                self.sockets.remove(h);
                self.conns.remove(&h);
            }
        }
    }
}

/// Current time as a smoltcp `Instant` from a process-local monotonic epoch.
fn now() -> Instant {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let dur = START.get_or_init(std::time::Instant::now).elapsed();
    Instant::from_micros(dur.as_micros() as i64)
}

/// Handle used by the public API to talk to a running driver.
#[derive(Clone)]
pub(crate) struct DriverHandle {
    pub(crate) cmd_tx: mpsc::Sender<Command>,
}

/// Spawn the driver task. `inbound` delivers IP packets from the consumer
/// transport; the driver's device emits outbound IP packets on the
/// `outbound` sender supplied when the device was built.
pub(crate) fn spawn(
    local_ip: IpAddress,
    prefix_len: u8,
    accept_any_ip: bool,
    default_gateway: Option<IpAddress>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    device: ChannelDevice,
    limits: NetstackLimits,
) -> std::io::Result<DriverHandle> {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(limits.command_queue);
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

    let stream_notify = Arc::new(Notify::new());
    let mut driver = Driver {
        iface,
        device,
        sockets: SocketSet::new(Vec::new()),
        conns: HashMap::new(),
        listeners: HashMap::new(),
        cmd_tx,
        stream_notify: stream_notify.clone(),
        limits,
        next_ephemeral_port: 49152,
        abort_after_poll: HashSet::new(),
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
                            // Bound work per wake so packet floods cannot
                            // starve lifecycle/control processing.
                            for _ in 1..driver.limits.max_packets_per_wake {
                                let Ok(packet) = inbound.try_recv() else { break; };
                                driver.device.push_inbound(packet);
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
                // Application stream write/shutdown/drop notification.
                _ = stream_notify.notified() => {
                    poll_at = driver.pump();
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
