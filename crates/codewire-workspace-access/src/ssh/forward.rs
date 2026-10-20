//! Local port forwarding: `direct-tcpip` channels, which `ssh -L`, `ssh -W`,
//! `ssh -D` and VS Code Remote-SSH open (#3045).
//!
//! A channel reaches only a loopback address inside the workload's own
//! network namespace: `localhost`, `127.0.0.0/8` or `::1` (and `0.0.0.0` or
//! `::`, which mean the same host). Every other target is refused before any
//! dial, so a forward never reaches the node, another Pod or a metadata
//! service. Names are never resolved: `localhost` is the two loopback
//! addresses themselves, not whatever a resolver or `/etc/hosts` says.
//!
//! Where the dial happens is the [`ForwardDialer`]'s job. The hosted daemon
//! serves SSH inside the workload's network namespace, so it dials loopback
//! itself ([`WorkloadLoopbackDialer`]). A server outside that namespace, such
//! as a local VM's supervisor on the host, must dial through the guest
//! instead; a loopback dial there would reach the host. A handler without a
//! dialer refuses every forward, with a reason.
//!
//! Each accepted channel copies bytes both ways and half-closes like a TCP
//! connection: the client's EOF shuts down writing to the target, and the
//! target's end of stream becomes the channel's EOF. Once both directions
//! are done the client closes the channel, as OpenSSH does; if it does not
//! within [`FORWARD_CLOSE_GRACE`], the server closes it. A channel the client
//! closes, or a connection that ends, ends the forward at once.
//!
//! Like a process session, a forward reads the client's data only as fast as
//! its target takes it. russh queues a bounded number of messages per channel
//! and then stops reading the connection, so a target that stops reading
//! while its client keeps sending pauses that SSH connection until the
//! target reads again.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use russh::{Channel, ChannelMsg, ChannelOpenFailure, server};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use super::SshSessionKey;

/// How long a forward's dial may take before the channel is refused.
pub const FORWARD_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Most forwards, open or dialing, on one SSH connection. Another is refused
/// with a resource shortage until one ends.
pub const MAX_FORWARDS_PER_CONNECTION: usize = 256;

/// How long a forward whose two directions are both done waits for the
/// client to close the channel before closing it itself.
pub const FORWARD_CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Most bytes read from the target per channel write.
const FORWARD_READ_CHUNK: usize = 32 * 1024;

/// A `direct-tcpip` target the policy admits: the loopback addresses to try,
/// in order. Only [`ForwardTarget::local`] makes one, so every address is a
/// loopback address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

impl ForwardTarget {
    /// The loopback addresses `host:port` names inside the workload, or why
    /// a channel may not reach it.
    pub fn local(host: &str, port: u32) -> Result<Self, ForwardRefusal> {
        let port = u16::try_from(port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| ForwardRefusal(format!("{port} is not a TCP port")))?;
        let requested = host.trim().to_ascii_lowercase();
        let ips: Vec<IpAddr> = match requested.as_str() {
            "" | "localhost" => vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
            _ => match requested.parse::<IpAddr>() {
                Ok(ip) if ip.is_loopback() => vec![ip],
                Ok(IpAddr::V4(ip)) if ip.is_unspecified() => vec![Ipv4Addr::LOCALHOST.into()],
                Ok(IpAddr::V6(ip)) if ip.is_unspecified() => vec![Ipv6Addr::LOCALHOST.into()],
                _ => {
                    return Err(ForwardRefusal(format!(
                        "port forwarding reaches only this environment's own loopback \
                         (localhost, 127.0.0.1, ::1), not {host:?}"
                    )));
                }
            },
        };
        Ok(Self {
            host: if requested.is_empty() {
                "localhost".into()
            } else {
                requested
            },
            port,
            addrs: ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        })
    }

    /// The addresses to try, in order; each is a loopback address.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for ForwardTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Why the policy refused a `direct-tcpip` target. The client sees it in the
/// channel's open failure.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ForwardRefusal(pub String);

/// A forward's connection to its target.
pub trait ForwardIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ForwardIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Why a dial failed. The client sees the message in the channel's open
/// failure.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ForwardDialError {
    /// Nothing accepted the connection: refused, reset or timed out.
    #[error("{0}")]
    ConnectFailed(String),
    /// This environment cannot forward now, for example because its runtime
    /// is too old.
    #[error("{0}")]
    Prohibited(String),
}

impl ForwardDialError {
    fn code(&self) -> ChannelOpenFailure {
        match self {
            Self::ConnectFailed(_) => ChannelOpenFailure::ConnectFailed,
            Self::Prohibited(_) => ChannelOpenFailure::AdministrativelyProhibited,
        }
    }
}

/// Connects a forward to its target inside the workload's network namespace.
#[async_trait]
pub trait ForwardDialer: Send + Sync + 'static {
    /// Connect to the first of `target`'s addresses that accepts. The handler
    /// bounds the whole dial by [`FORWARD_DIAL_TIMEOUT`].
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError>;
}

/// Dials the target's loopback addresses from this process.
///
/// Only for an SSH server that runs inside the workload's own network
/// namespace, as the hosted daemon does: its loopback is the workload's.
/// Anywhere else, such as a local VM's supervisor on the host, it would reach
/// that host's loopback instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkloadLoopbackDialer;

#[async_trait]
impl ForwardDialer for WorkloadLoopbackDialer {
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        let mut failures = Vec::new();
        for addr in target.addrs() {
            if !addr.ip().is_loopback() {
                return Err(ForwardDialError::Prohibited(format!(
                    "{addr} is not a loopback address"
                )));
            }
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Box::new(stream));
                }
                Err(error) => failures.push(format!("{addr}: {error}")),
            }
        }
        Err(ForwardDialError::ConnectFailed(format!(
            "nothing in the environment accepted a connection to {target} ({})",
            failures.join("; ")
        )))
    }
}

/// One connection's port forwarding: its dialer and its forward slots.
pub(super) struct Forwarding {
    dialer: Arc<dyn ForwardDialer>,
    slots: Arc<Semaphore>,
    close_grace: Duration,
}

impl Forwarding {
    pub(super) fn new(dialer: Arc<dyn ForwardDialer>) -> Self {
        Self {
            dialer,
            slots: Arc::new(Semaphore::new(MAX_FORWARDS_PER_CONNECTION)),
            close_grace: FORWARD_CLOSE_GRACE,
        }
    }

    #[cfg(test)]
    pub(super) fn with_close_grace(mut self, close_grace: Duration) -> Self {
        self.close_grace = close_grace;
        self
    }

    /// Answer one `direct-tcpip` open: refuse it, with a reason, or dial in
    /// the background and accept once connected. Returns the forward's stop
    /// token, which is cancelled when the forward ends, for the handler to
    /// cancel when the client closes the channel.
    pub(super) async fn open(
        &self,
        key: SshSessionKey,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        reply: server::ChannelOpenHandle,
        ended: &CancellationToken,
    ) -> Option<CancellationToken> {
        let target = match ForwardTarget::local(host, port) {
            Ok(target) => target,
            Err(refusal) => {
                refuse(
                    key,
                    reply,
                    ChannelOpenFailure::AdministrativelyProhibited,
                    refusal.0,
                )
                .await;
                return None;
            }
        };
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            let reason = format!(
                "too many forwarded connections on this SSH connection \
                 (at most {MAX_FORWARDS_PER_CONNECTION}); close some and retry"
            );
            refuse(key, reply, ChannelOpenFailure::ResourceShortage, reason).await;
            return None;
        };
        let stop = ended.child_token();
        let dialer = self.dialer.clone();
        let close_grace = self.close_grace;
        let (task_stop, connection) = (stop.clone(), ended.clone());
        tokio::spawn(async move {
            // Marks the forward finished for the handler, however it ends.
            let _finished = task_stop.clone().drop_guard();
            let _slot = slot;
            let dialed = tokio::select! {
                dialed = tokio::time::timeout(FORWARD_DIAL_TIMEOUT, dialer.dial(&target)) => dialed,
                // The connection ended while dialing; dropping the reply
                // refuses the channel.
                () = task_stop.cancelled() => return,
            };
            let io = match dialed {
                Ok(Ok(io)) => io,
                Ok(Err(error)) => {
                    refuse(key, reply, error.code(), error.to_string()).await;
                    return;
                }
                Err(_) => {
                    let reason = format!(
                        "connecting to {target} in the environment timed out after {}s",
                        FORWARD_DIAL_TIMEOUT.as_secs()
                    );
                    refuse(key, reply, ChannelOpenFailure::ConnectFailed, reason).await;
                    return;
                }
            };
            reply.accept().await;
            tracing::debug!(
                connection = key.connection,
                channel = %key.channel,
                port = target.port(),
                "workspace SSH forward opened"
            );
            let reason = pump_forward(channel, io, &task_stop, &connection, close_grace).await;
            tracing::debug!(
                connection = key.connection,
                channel = %key.channel,
                port = target.port(),
                reason,
                "workspace SSH forward ended"
            );
        });
        Some(stop)
    }
}

/// Refuse a forward on a handler that has no dialer.
pub(super) async fn refuse_unavailable(key: SshSessionKey, reply: server::ChannelOpenHandle) {
    refuse(
        key,
        reply,
        ChannelOpenFailure::AdministrativelyProhibited,
        "port forwarding is not available for this environment".to_owned(),
    )
    .await;
}

/// Refuse a channel with an open failure carrying `code`'s number and
/// `reason` as its description, which OpenSSH prints after the code's name.
async fn refuse(
    key: SshSessionKey,
    reply: server::ChannelOpenHandle,
    code: ChannelOpenFailure,
    reason: String,
) {
    tracing::info!(
        connection = key.connection,
        channel = %key.channel,
        reason,
        "workspace SSH forward refused"
    );
    reply
        .reject(ChannelOpenFailure::Other {
            code: code.code(),
            reason,
        })
        .await;
}

/// Copy bytes both ways between an accepted channel and its target until the
/// forward ends; returns why it ended.
///
/// `stop` is cancelled when the client closes the channel or the connection
/// ends. Data the client sent before closing still reaches a target that is
/// reading; only a write the target is not taking ends early.
async fn pump_forward(
    channel: Channel<server::Msg>,
    io: Box<dyn ForwardIo>,
    stop: &CancellationToken,
    connection: &CancellationToken,
    close_grace: Duration,
) -> &'static str {
    let (mut from_client, to_client) = channel.split();
    let (mut from_target, mut to_target) = tokio::io::split(io);
    let client_done = AtomicBool::new(false);
    let client_done_changed = Notify::new();

    // Client to target, in order, until the channel closes. The client's EOF
    // shuts down writing to the target.
    let upstream = async {
        loop {
            match from_client.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if client_done.load(Ordering::Acquire) {
                        continue;
                    }
                    tokio::select! {
                        biased;
                        written = to_target.write_all(&data) => {
                            if written.is_err() {
                                return "the target stopped taking data";
                            }
                        }
                        () = stop.cancelled() => return "the channel closed while the target was not reading",
                    }
                }
                Some(ChannelMsg::Eof) => {
                    tokio::select! {
                        biased;
                        _ = to_target.shutdown() => {}
                        () = stop.cancelled() => return "the channel closed while the target was not reading",
                    }
                    client_done.store(true, Ordering::Release);
                    client_done_changed.notify_one();
                }
                Some(ChannelMsg::Close) | None => return "the client closed the channel",
                Some(_) => {}
            }
        }
    };

    // Target to client until the target's end of stream, which becomes the
    // channel's EOF. Then, once the client is done too, it has a short while
    // to close the channel itself.
    let downstream = async {
        loop {
            let mut chunk = Vec::with_capacity(FORWARD_READ_CHUNK);
            match from_target.read_buf(&mut chunk).await {
                Ok(0) => break,
                Ok(_) => {
                    if to_client.data_bytes(chunk).await.is_err() {
                        return "the connection ended";
                    }
                }
                Err(_) => return "the target connection failed",
            }
        }
        if to_client.eof().await.is_err() {
            return "the connection ended";
        }
        loop {
            let changed = client_done_changed.notified();
            if client_done.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
        tokio::time::sleep(close_grace).await;
        "both sides finished and the client did not close the channel"
    };

    let reason = tokio::select! {
        reason = upstream => reason,
        reason = downstream => reason,
        () = connection.cancelled() => "the connection ended",
    };
    // A no-op when the client already closed it.
    let _ = to_client.close().await;
    reason
}

#[cfg(test)]
#[path = "forward/tests.rs"]
mod tests;
