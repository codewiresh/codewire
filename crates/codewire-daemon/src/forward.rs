//! `ForwardTcp`: one TCP connection to a loopback address inside the
//! workload's network namespace, made as the workload user (#3025).
//!
//! An SSH server outside that namespace, such as a local VM's supervisor on
//! the host, forwards `direct-tcpip` channels through it: a loopback dial
//! there would reach the host, not the workload.
//!
//! - **Target:** a literal loopback address and a port, never a name, and
//!   never one of the platform's own listeners
//!   (`codewire_daemon_proto::platform_listeners`), which the SSH server
//!   refuses first; this is the guest's own check of the same set (#3068).
//!   The daemon serves its API on vsock, not on a workload port.
//! - **Where:** where the daemon runs as root outside the workload (the
//!   `Runc` placement), the socket is created on one dedicated thread that
//!   joined the pinned workload network namespace and took the workload
//!   user's filesystem identity once, so the socket belongs to that namespace
//!   and that user. Elsewhere the daemon already runs as the workload user in
//!   its namespace and connects directly.
//! - **Stream:** `opened` once connected, then `data` both ways; each side's
//!   `end` (or the request stream's end) half-closes as TCP does, and the
//!   RPC ends once both directions are done.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::platform_listeners;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{OnceCell, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::config::Config;
use crate::execution::ProcessExecution;

/// How long a connection may take before the forward is refused.
pub(crate) const FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes read from the target per `data` message.
const FORWARD_READ_CHUNK: usize = 32 * 1024;
/// `data` messages queued toward the client before reading the target waits.
const FORWARD_QUEUE: usize = 8;

type Payload = v1::forward_tcp_message::Payload;

/// The address `open` names, if the daemon forwards to it. `daemon_port` is
/// the daemon's own TCP port where it serves on TCP, refused like the other
/// platform listeners.
pub(crate) fn admit(
    open: &v1::ForwardTcpOpen,
    daemon_port: Option<u16>,
) -> Result<SocketAddr, Status> {
    let port = u16::try_from(open.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| Status::invalid_argument(format!("{} is not a TCP port", open.port)))?;
    let ip: IpAddr = open.address.parse().map_err(|_| {
        Status::invalid_argument("a forward names a literal loopback address, never a name")
    })?;
    if !ip.is_loopback() {
        return Err(Status::permission_denied(format!(
            "port forwarding reaches only this environment's own loopback, not {ip}"
        )));
    }
    if let Some(listener) = platform_listeners(daemon_port).get(&port) {
        return Err(Status::permission_denied(format!(
            "port {port} is {listener}, which belongs to the platform; port forwarding \
             cannot reach it"
        )));
    }
    Ok(SocketAddr::new(ip, port))
}

/// Sockets in the workload's network namespace, created by one dedicated
/// thread started on first use; a failed start is tried again next time.
#[derive(Clone, Default)]
pub(crate) struct WorkloadSockets {
    thread: Arc<OnceCell<namespace::SocketThread>>,
}

impl WorkloadSockets {
    /// Connect to `target` inside the workload's network namespace, as the
    /// workload user.
    pub(crate) async fn connect(
        &self,
        config: &Config,
        target: SocketAddr,
    ) -> Result<TcpStream, Status> {
        let socket = match &config.process_execution {
            ProcessExecution::Native => if target.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(|error| Status::internal(format!("create a forward socket: {error}")))?,
            ProcessExecution::Runc(execution) => {
                let thread = self
                    .thread
                    .get_or_try_init(|| namespace::SocketThread::start(execution))
                    .await
                    .map_err(Status::unavailable)?;
                thread.socket(target).await?
            }
        };
        match tokio::time::timeout(FORWARD_CONNECT_TIMEOUT, socket.connect(target)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
            Ok(Err(error)) => Err(Status::unavailable(format!(
                "nothing in the environment accepted a connection to {target}: {error}"
            ))),
            Err(_) => Err(Status::unavailable(format!(
                "a connection to {target} did not complete within {} s",
                FORWARD_CONNECT_TIMEOUT.as_secs()
            ))),
        }
    }
}

/// Copy between the client's stream and the connected target until both
/// directions end, after telling the client the forward is open.
pub(crate) fn serve(
    target: TcpStream,
    mut inbound: Streaming<v1::ForwardTcpMessage>,
) -> ReceiverStream<Result<v1::ForwardTcpMessage, Status>> {
    let (outbound, receiver) = mpsc::channel(FORWARD_QUEUE);
    tokio::spawn(async move {
        let message = |payload| v1::ForwardTcpMessage {
            payload: Some(payload),
        };
        if outbound
            .send(Ok(message(Payload::Opened(()))))
            .await
            .is_err()
        {
            return;
        }
        let (mut from, mut to) = target.into_split();
        let to_target = async {
            loop {
                match inbound.message().await {
                    Ok(Some(v1::ForwardTcpMessage {
                        payload: Some(Payload::Data(bytes)),
                    })) => to.write_all(&bytes).await.map_err(|error| {
                        Status::unavailable(format!("write to the forward target: {error}"))
                    })?,
                    Ok(Some(v1::ForwardTcpMessage {
                        payload: Some(Payload::End(())),
                    }))
                    | Ok(None) => break,
                    Ok(Some(_)) => {
                        return Err(Status::invalid_argument(
                            "a forward carries only data and end after open",
                        ));
                    }
                    Err(status) => return Err(status),
                }
            }
            let _ = to.shutdown().await;
            Ok(())
        };
        let from_target = async {
            let mut buffer = vec![0; FORWARD_READ_CHUNK];
            loop {
                let read = from.read(&mut buffer).await.map_err(|error| {
                    Status::unavailable(format!("read from the forward target: {error}"))
                })?;
                let payload = if read == 0 {
                    Payload::End(())
                } else {
                    Payload::Data(buffer[..read].to_vec())
                };
                outbound
                    .send(Ok(message(payload)))
                    .await
                    .map_err(|_| Status::cancelled("the forward's client went away"))?;
                if read == 0 {
                    return Ok(());
                }
            }
        };
        if let Err(status) = tokio::try_join!(to_target, from_target) {
            let _ = outbound.send(Err(status)).await;
        }
    });
    ReceiverStream::new(receiver)
}

#[cfg(target_os = "linux")]
mod namespace {
    use std::fs::File;
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;

    use tokio::net::TcpSocket;
    use tokio::sync::oneshot;
    use tonic::Status;

    use crate::execution::RuncExecution;

    struct Request {
        domain: libc::c_int,
        reply: oneshot::Sender<io::Result<OwnedFd>>,
    }

    /// The thread that creates sockets in the workload's network namespace.
    /// It joins the namespace and takes the workload user's filesystem
    /// identity once, and does nothing else, so no other work ever runs with
    /// either.
    pub(super) struct SocketThread {
        requests: mpsc::Sender<Request>,
    }

    impl SocketThread {
        pub(super) async fn start(execution: &RuncExecution) -> Result<Self, String> {
            let namespace = execution.network_namespace.clone();
            let (uid, gid) = (execution.uid, execution.gid);
            tokio::task::spawn_blocking(move || Self::start_blocking(&namespace, uid, gid))
                .await
                .map_err(|error| format!("start the forward socket thread: {error}"))?
                .map_err(|error| {
                    format!("port forwarding cannot reach the workload's network: {error}")
                })
        }

        fn start_blocking(namespace: &Path, uid: u32, gid: u32) -> io::Result<Self> {
            let namespace = File::open(namespace)?;
            let (requests, incoming) = mpsc::channel::<Request>();
            let (ready, joined) = mpsc::sync_channel(1);
            thread::Builder::new()
                .name("workload-sockets".into())
                .spawn(move || {
                    let entered = enter(&namespace, uid, gid);
                    drop(namespace);
                    let ok = entered.is_ok();
                    let _ = ready.send(entered);
                    if ok {
                        for request in incoming {
                            let _ = request.reply.send(new_socket(request.domain));
                        }
                    }
                })?;
            joined
                .recv()
                .map_err(|_| io::Error::other("the forward socket thread exited"))??;
            Ok(Self { requests })
        }

        /// A new socket for `target`'s family in the workload's namespace.
        pub(super) async fn socket(&self, target: SocketAddr) -> Result<TcpSocket, Status> {
            let domain = if target.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            };
            let (reply, socket) = oneshot::channel();
            self.requests
                .send(Request { domain, reply })
                .map_err(|_| Status::unavailable("the forward socket thread exited"))?;
            let fd = socket
                .await
                .map_err(|_| Status::unavailable("the forward socket thread exited"))?
                .map_err(|error| Status::internal(format!("create a forward socket: {error}")))?;
            // The socket was created non-blocking, as Tokio requires.
            Ok(TcpSocket::from_std_stream(std::net::TcpStream::from(fd)))
        }
    }

    /// Join the workload's network namespace and take the workload user's
    /// filesystem identity, which a new socket's owner comes from. Both apply
    /// to this thread only, and each is read back.
    fn enter(namespace: &File, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: setns takes an open namespace descriptor and changes only
        // this thread's network namespace.
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: setfsgid and setfsuid take scalar IDs and change only this
        // thread's filesystem credentials; `u32::MAX` (-1) queries them. The
        // group is set first, while the thread still has the right to.
        let (current_gid, current_uid) = unsafe {
            libc::setfsgid(gid);
            libc::setfsuid(uid);
            (libc::setfsgid(u32::MAX), libc::setfsuid(u32::MAX))
        };
        if current_uid as u32 != uid || current_gid as u32 != gid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the forward socket thread could not act as the workload user",
            ));
        }
        Ok(())
    }

    fn new_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
        // SAFETY: socket takes scalar arguments; a non-negative result is a
        // new descriptor this function then owns.
        let fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(not(target_os = "linux"))]
mod namespace {
    use std::net::SocketAddr;

    use tokio::net::TcpSocket;
    use tonic::Status;

    use crate::execution::RuncExecution;

    /// The `Runc` placement runs only in a Linux guest.
    pub(super) struct SocketThread;

    impl SocketThread {
        pub(super) async fn start(_execution: &RuncExecution) -> Result<Self, String> {
            Err("port forwarding into a workload namespace needs Linux".into())
        }

        pub(super) async fn socket(&self, _target: SocketAddr) -> Result<TcpSocket, Status> {
            Err(Status::unimplemented(
                "port forwarding into a workload namespace needs Linux",
            ))
        }
    }
}
