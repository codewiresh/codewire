//! A standard Pod's ports in (#5602, cw-security's conditions). The Pod's
//! 7777 and 2222 reach the guest over two fixed vsock ports, and the guest
//! joins each connection to one fixed address in the workspace's network
//! namespace: the hosted daemon's gRPC port and its SSH port. The listeners
//! exist only in a standard Pod's boot, accept only the host CID, and refuse a
//! connection over [`HOSTED_INGRESS_MAX_JOINS`] rather than queue it. The
//! guest's local daemon and its `ForwardTcp`, which refuses the platform's
//! own listeners, are not involved.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::sync::Semaphore;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

mod workload_log;

use crate::hosted_control::{
    HOSTED_DAEMON_GUEST_PORT, HOSTED_DAEMON_INGRESS_VSOCK_PORT, HOSTED_INGRESS_CONNECT,
    HOSTED_INGRESS_IDLE, HOSTED_INGRESS_MAX_JOINS, HOSTED_SSH_INGRESS_VSOCK_PORT, hosted_guest,
    join_until_idle,
};

/// Each ingress port and the workspace-namespace port it joins.
const INGRESS: [(u32, u16); 2] = [
    (HOSTED_DAEMON_INGRESS_VSOCK_PORT, HOSTED_DAEMON_GUEST_PORT),
    (
        HOSTED_SSH_INGRESS_VSOCK_PORT,
        codewire_daemon_proto::WORKSPACE_SSH_PORT,
    ),
];

/// Starts both listeners on their own thread when a standard Pod's VMM
/// booted the kernel, in either egress mode, and waits until they listen; a
/// local VM's boot opens neither.
pub(super) fn start(command_line: &str) -> Result<()> {
    if !hosted_guest(command_line) {
        return Ok(());
    }
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("codewire-hosted-ingress".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    // The waiting side reports the failure.
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let mut listeners = Vec::with_capacity(INGRESS.len());
                for (vsock_port, target) in INGRESS {
                    match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
                        Ok(listener) => listeners.push((listener, target)),
                        Err(error) => {
                            // As above.
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    }
                }
                // The receiver waits for exactly this one message.
                let _ = ready_tx.send(Ok(()));
                let served = listeners
                    .into_iter()
                    .map(|(listener, target)| tokio::spawn(serve(listener, target)));
                for port in served.collect::<Vec<_>>() {
                    // A listener ends only with the guest.
                    let _ = port.await;
                }
            });
        })
        .context("spawn the hosted ingress listeners")?;
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .context("wait for the hosted ingress listeners")??;
    Ok(())
}

async fn serve(listener: VsockListener, target: u16) {
    let joins = Arc::new(Semaphore::new(HOSTED_INGRESS_MAX_JOINS));
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            // An accept error such as EMFILE would otherwise spin.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        if !super::is_host_cid(peer.cid()) {
            continue;
        }
        // Over the cap the connection is refused, never queued.
        let Ok(permit) = Arc::clone(&joins).try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(workspace)) =
                tokio::time::timeout(HOSTED_INGRESS_CONNECT, connect_in_workspace(target)).await
            else {
                return;
            };
            // Either side closing, or an idle join, ends it.
            let _ = join_until_idle(stream, workspace, HOSTED_INGRESS_IDLE).await;
        });
    }
}

/// A TCP connection to the workspace namespace's loopback `port`, made by a
/// thread of its own that enters that namespace, so no other thread's
/// namespace changes.
async fn connect_in_workspace(port: u16) -> std::io::Result<tokio::net::TcpStream> {
    let (sent, received) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("codewire-hosted-ingress-connect".to_owned())
        .spawn(move || {
            // The receiver has gone only if the connect timed out.
            let _ = sent.send(connect_from_workspace_namespace(port));
        })?;
    let stream = received
        .await
        .map_err(|_| std::io::Error::other("the workspace connect thread ended"))??;
    stream.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(stream)
}

fn connect_from_workspace_namespace(port: u16) -> std::io::Result<std::net::TcpStream> {
    let namespace = std::fs::File::open(super::NETWORK_NAMESPACE_PATH)?;
    // SAFETY: a valid descriptor of a network namespace file; this thread is
    // its own and ends after this one connection.
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    std::net::TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        HOSTED_INGRESS_CONNECT,
    )
}

/// Guest init's own copy of the hosted daemon's gRPC listener, bound to the
/// workspace namespace's 127.0.0.1 without `SO_REUSEPORT` before the
/// container starts and held for the guest's whole life, so no workspace
/// process can ever bind that address. It is held, never accepted on or
/// polled: only the daemon, which inherits it, accepts, so no connection
/// lands anywhere else. A container restart gets this same descriptor.
static DAEMON_LISTENER: std::sync::OnceLock<std::net::TcpListener> = std::sync::OnceLock::new();

/// Binds and holds the daemon's listener in a standard Pod's boot, once, and
/// the pipe its output leaves the guest by.
pub(super) fn hold_daemon_listener(command_line: &str, uid: u32, gid: u32) -> Result<()> {
    if !hosted_guest(command_line) || DAEMON_LISTENER.get().is_some() {
        return Ok(());
    }
    workload_log::hold(command_line)?;
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("codewire-hosted-listener".to_owned())
        .spawn(move || {
            let bound = std::fs::File::open(super::NETWORK_NAMESPACE_PATH).and_then(|namespace| {
                // SAFETY: as in `connect_from_workspace_namespace`.
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::net::TcpListener::bind(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    HOSTED_DAEMON_GUEST_PORT,
                ))
            });
            // The receiver waits for exactly this one message.
            let _ = sent.send(bound);
        })
        .context("spawn the hosted daemon listener thread")?;
    let listener = received
        .recv_timeout(std::time::Duration::from_secs(2))
        .context("wait for the hosted daemon listener")?
        .context("bind the hosted daemon listener in the workspace namespace")?;
    // A second call found it set above; the first set always succeeds.
    let _ = DAEMON_LISTENER.set(listener);
    verify_unbindable(uid, gid)
}

/// The held listener's descriptor, which runc passes into the container.
pub(super) fn daemon_listener_fd() -> Option<std::os::fd::RawFd> {
    DAEMON_LISTENER.get().map(AsRawFd::as_raw_fd)
}

/// runc's `--preserve-fds`: the readiness channel, and in a standard Pod's
/// boot the held listener and the log pipe, as descriptors 3, 4 and 5.
pub(super) fn preserved_fds() -> &'static str {
    match container_fds() {
        [Some(_), Some(_)] => "3",
        [Some(_), None] => "2",
        _ => "1",
    }
}

/// The descriptors runc passes after the readiness channel, in order: the
/// held listener and the log pipe's write end.
pub(super) fn container_fds() -> [Option<std::os::fd::RawFd>; 2] {
    [daemon_listener_fd(), workload_log::writer_fd()]
}

/// Between fork and exec of runc: places `fds` as descriptors 4 and on,
/// inherited. Only dup2 and fcntl, so it is safe there. False on failure.
pub(super) fn place_container_fds(fds: [Option<std::os::fd::RawFd>; 2]) -> bool {
    (4..).zip(fds).all(|(target, fd)| {
        fd.is_none_or(|fd| {
            // SAFETY: dup2 and fcntl on open descriptors, async-signal-safe.
            unsafe { libc::dup2(fd, target) != -1 && libc::fcntl(target, libc::F_SETFD, 0) != -1 }
        })
    })
}

/// Inside the container: the listener runc passed as descriptor 4, and the
/// log pipe as descriptor 5, each moved to a close-on-exec descriptor that no
/// process the container init starts inherits, save the hosted workload
/// (`spawn_workspace_process_with_projection`).
static CONTAINER_LISTENER: std::sync::OnceLock<std::os::fd::OwnedFd> = std::sync::OnceLock::new();
static CONTAINER_LOG: std::sync::OnceLock<std::os::fd::OwnedFd> = std::sync::OnceLock::new();

pub(super) fn claim_container_listener() -> Result<bool> {
    let Some(listener) = claim_inherited(4).context("move the hosted daemon listener")? else {
        return Ok(false);
    };
    // Claimed once per container start; a second set changes nothing.
    let _ = CONTAINER_LISTENER.set(listener);
    if let Some(log) = claim_inherited(5).context("move the hosted daemon's log pipe")? {
        // As above.
        let _ = CONTAINER_LOG.set(log);
    }
    Ok(true)
}

/// Descriptor `fd`, if runc passed it, moved to a close-on-exec descriptor.
fn claim_inherited(fd: std::os::fd::RawFd) -> Result<Option<std::os::fd::OwnedFd>> {
    // SAFETY: F_GETFD on a descriptor number only reads its flags.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Ok(None);
    }
    // SAFETY: `fd` is open, and runc passed it to this PID 1 alone.
    let inherited = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let moved = rustix::io::fcntl_dupfd_cloexec(&inherited, 10)?;
    drop(inherited);
    Ok(Some(moved))
}

/// The hosted workload's stdout or stderr: the log pipe when `listener` is
/// set, which only the workload's spawn passes, and nothing otherwise.
pub(super) fn workload_output(listener: Option<std::os::fd::RawFd>) -> std::process::Stdio {
    listener
        .and(CONTAINER_LOG.get())
        .and_then(|log| log.try_clone().ok())
        .map_or_else(std::process::Stdio::null, std::process::Stdio::from)
}

pub(super) fn container_listener_fd() -> Option<std::os::fd::RawFd> {
    CONTAINER_LISTENER.get().map(AsRawFd::as_raw_fd)
}

/// The binds a workspace process could try on `address`: plain, with
/// `SO_REUSEADDR`, with `SO_REUSEPORT`, and with both. Each must fail with
/// `EADDRINUSE`.
fn refuses_every_bind(address: SocketAddrV4) -> Result<()> {
    let raw = libc::sockaddr_in {
        sin_family: libc::sa_family_t::try_from(libc::AF_INET)?,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*address.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let option_length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())?;
    let address_length = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())?;
    for (reuse_address, reuse_port) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
        // SAFETY: a socket this function owns and closes, with live,
        // correctly sized option values and address.
        let error = unsafe {
            let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            anyhow::ensure!(socket >= 0, "create a bind-check socket");
            for (option, value) in [
                (libc::SO_REUSEADDR, reuse_address),
                (libc::SO_REUSEPORT, reuse_port),
            ] {
                let value: libc::c_int = value;
                let set = libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_ref(&value).cast(),
                    option_length,
                );
                if set != 0 {
                    libc::close(socket);
                    anyhow::bail!("set a bind-check socket option");
                }
            }
            let bound = libc::bind(socket, std::ptr::from_ref(&raw).cast(), address_length);
            let error = std::io::Error::last_os_error().raw_os_error();
            libc::close(socket);
            (bound, error)
        };
        anyhow::ensure!(
            error == (-1, Some(libc::EADDRINUSE)),
            "{address} accepted a bind with SO_REUSEADDR={reuse_address} SO_REUSEPORT={reuse_port}"
        );
    }
    Ok(())
}

/// `hosted-listener-check`: run as the workspace's uid inside its network
/// namespace, it proves no workspace process can bind the daemon's address
/// while guest init holds it.
pub fn run_listener_check() -> Result<()> {
    refuses_every_bind(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        HOSTED_DAEMON_GUEST_PORT,
    ))
}

/// Runs `hosted-listener-check` as `uid`:`gid` in the workspace namespace and
/// requires it to pass, so the held listener's guarantee is checked at
/// every boot, against root's own listener.
fn verify_unbindable(uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::process::CommandExt as _;
    let namespace = std::fs::File::open(super::NETWORK_NAMESPACE_PATH)
        .context("open the workspace namespace for the listener check")?;
    let namespace_fd = namespace.as_raw_fd();
    let mut command = std::process::Command::new(super::INIT_PATH);
    command
        .arg("hosted-listener-check")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setns(namespace_fd, libc::CLONE_NEWNET) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().context("run the hosted listener check")?;
    drop(namespace);
    anyhow::ensure!(
        status.success(),
        "the workspace uid could bind the hosted daemon's address; refusing to start"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim the held listener rests on, as one uid: while a listener
    /// without `SO_REUSEPORT` holds an address, no other socket can bind it.
    /// `hosted-listener-check` repeats this at every boot as the workspace's
    /// uid against root's listener.
    #[test]
    fn a_held_listener_refuses_every_other_bind_of_its_address() {
        let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let std::net::SocketAddr::V4(address) = held.local_addr().unwrap() else {
            unreachable!("bound to an IPv4 address")
        };
        refuses_every_bind(address).unwrap();
        drop(held);
        // Without a holder the same attempt binds, so the check can fail.
        assert!(refuses_every_bind(address).is_err());
    }

    #[test]
    fn a_local_vms_boot_opens_neither_ingress_port() {
        hold_daemon_listener("console=ttyS0 rdinit=/init panic=-1", 1000, 1000).unwrap();
        assert_eq!(daemon_listener_fd(), None);
        assert_eq!(preserved_fds(), "1");
        // Without the parameter `start` returns before it binds anything.
        start("console=ttyS0 rdinit=/init panic=-1").unwrap();
        for port in [
            HOSTED_DAEMON_INGRESS_VSOCK_PORT,
            HOSTED_SSH_INGRESS_VSOCK_PORT,
        ] {
            assert!(INGRESS.iter().any(|(ingress, _)| *ingress == port));
        }
        assert_eq!(INGRESS[1].1, codewire_daemon_proto::WORKSPACE_SSH_PORT);
    }
}
