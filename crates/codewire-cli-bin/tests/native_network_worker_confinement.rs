#![cfg(target_os = "macos")]

//! #1905 condition 2 on each supported macOS version: the confined packet
//! worker, started as the product starts it, holds only the descriptors it was
//! given, its broker IPC sessions (#2638) among them. Linux proves the same by reading `/proc/<pid>/fd`; Darwin reads the
//! worker's descriptor table with libproc. That Seatbelt refuses new files and
//! internet sockets after confinement is proved by the `darwin::sandbox` tests.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use codewire_egress_broker::ipc::{BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS};
use codewire_local_vmm::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, encode_egress_broker_bootstrap,
};
use codewire_local_vmm::host_addresses::{HostAddressSet, encode_frame};
use codewire_local_vmm::mesh_ingress::MESH_INGRESS_CONTROL_KEY_LEN;
use codewire_local_vmm::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, WORKER_BROKER_READY_MESSAGE,
    WORKER_PREPARED_MESSAGE, WORKER_READY_MESSAGE, WORKER_STATUS_MAX_BYTES,
    encode_product_worker_bootstrap,
};
use codewire_vmm_guest_probe::{
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
    NetworkHostReady, NetworkKey,
};
use uuid::Uuid;

const BROKER_DESCRIPTOR_MARKER: u8 = b'B';
const NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const CONTROL_BYTES: usize = 64;

/// `<sys/proc_info.h>` flavors and layout that the `libc` crate does not
/// carry. Offsets are into `struct socket_fdinfo` and `struct vnode_fdinfo`,
/// each a 24-byte `proc_fileinfo` followed by a 136-byte `vinfo_stat`; the
/// layout is checked against this process's own descriptors before use. A
/// socket's handle and a Unix socket's peer handle are opaque kernel values,
/// equal for the same socket in any process.
const PROC_PIDFDVNODEINFO: libc::c_int = 1;
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const SOCKET_HANDLE_OFFSET: usize = 24 + 136;
const SOCKET_FAMILY_OFFSET: usize = SOCKET_HANDLE_OFFSET + 8 + 8 + 4 + 4;
const UNIX_PEER_OFFSET: usize = 24 + 240;
const VNODE_RDEV_OFFSET: usize = 24 + 116;
const FD_INFO_BYTES: usize = 4096;

struct ChildGuard(Child);

impl ChildGuard {
    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "confined process {} did not terminate",
                self.0.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One descriptor in a process's table, as libproc reports it.
#[derive(Debug, PartialEq, Eq)]
enum Descriptor {
    Unix { handle: u64, peer: u64 },
    Socket { family: libc::c_int },
    Vnode { rdev: u32 },
    Kqueue,
    Other(u32),
}

fn descriptors(pid: libc::pid_t) -> Vec<(RawFd, Descriptor)> {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let mut table = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        1024
    ];
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            table.as_mut_ptr().cast(),
            (table.len() * entry) as libc::c_int,
        )
    };
    assert!(bytes > 0, "{}", std::io::Error::last_os_error());
    let count = bytes as usize / entry;
    assert!(count < table.len(), "descriptor table larger than expected");
    table[..count]
        .iter()
        .map(|info| {
            let kind = match info.proc_fdtype as libc::c_int {
                libc::PROX_FDTYPE_SOCKET => {
                    let socket = fd_info(pid, info.proc_fd, PROC_PIDFDSOCKETINFO);
                    match read_at::<libc::c_int>(&socket, SOCKET_FAMILY_OFFSET) {
                        libc::AF_UNIX => Descriptor::Unix {
                            handle: read_at(&socket, SOCKET_HANDLE_OFFSET),
                            peer: read_at(&socket, UNIX_PEER_OFFSET),
                        },
                        family => Descriptor::Socket { family },
                    }
                }
                libc::PROX_FDTYPE_VNODE => Descriptor::Vnode {
                    rdev: read_at::<u32>(
                        &fd_info(pid, info.proc_fd, PROC_PIDFDVNODEINFO),
                        VNODE_RDEV_OFFSET,
                    ),
                },
                libc::PROX_FDTYPE_KQUEUE => Descriptor::Kqueue,
                other => Descriptor::Other(other as u32),
            };
            (info.proc_fd, kind)
        })
        .collect()
}

fn fd_info(pid: libc::pid_t, fd: RawFd, flavor: libc::c_int) -> Vec<u8> {
    let mut buffer = vec![0_u8; FD_INFO_BYTES];
    let written = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            flavor,
            buffer.as_mut_ptr().cast(),
            buffer.len() as libc::c_int,
        )
    };
    assert!(
        written > 0,
        "proc_pidfdinfo({pid}, {fd}, {flavor}): {}",
        std::io::Error::last_os_error()
    );
    buffer.truncate(written as usize);
    buffer
}

fn read_at<T: Copy>(bytes: &[u8], offset: usize) -> T {
    assert!(offset + std::mem::size_of::<T>() <= bytes.len());
    unsafe { std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<T>()) }
}

fn dev_null_rdev() -> u32 {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::stat(c"/dev/null".as_ptr(), &raw mut stat) },
        0
    );
    stat.st_rdev as u32
}

fn unix_socket(pid: libc::pid_t, fd: RawFd) -> (u64, u64) {
    match descriptors(pid).into_iter().find(|(entry, _)| *entry == fd) {
        Some((_, Descriptor::Unix { handle, peer })) => (handle, peer),
        other => panic!("{fd} in {pid} is not a Unix socket: {other:?}"),
    }
}

/// The hand-written offsets read the right fields on this macOS: a Unix
/// socket pair, a TCP listener and `/dev/null` held by this test process.
fn check_layout() {
    let (unix, peer) = UnixStream::pair().unwrap();
    let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let pid = unsafe { libc::getpid() };
    let (one, one_peer) = unix_socket(pid, unix.as_raw_fd());
    let (other, other_peer) = unix_socket(pid, peer.as_raw_fd());
    assert!(one != 0 && one != other && one_peer == other && other_peer == one);
    let own = descriptors(pid);
    let find = |fd: RawFd| &own.iter().find(|(entry, _)| *entry == fd).unwrap().1;
    assert_eq!(
        *find(tcp.as_raw_fd()),
        Descriptor::Socket {
            family: libc::AF_INET
        }
    );
    assert_eq!(
        *find(null.as_raw_fd()),
        Descriptor::Vnode {
            rdev: dev_null_rdev()
        }
    );
}

#[test]
fn the_confined_worker_holds_only_the_descriptors_it_was_given() {
    check_layout();
    let directory = tempfile::tempdir().unwrap();
    let vm_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let generation = 9_u64;
    let broker_key = [0x5a; BROKER_IPC_KEY_LEN];

    let (mut broker_parent, broker_child) = UnixStream::pair().unwrap();
    set_timeouts(&broker_parent);
    let mut broker_command = cw(
        directory.path(),
        "__native-egress-broker",
        vm_id,
        generation,
    );
    // The broker also takes the runner's host-address control socket (#2614)
    // and its IPC sessions after the admission session (#2638).
    let (mut control, control_child) = UnixStream::pair().unwrap();
    let mut sources = vec![
        (above_targets(&broker_child), EGRESS_BROKER_BOOTSTRAP_FD),
        (
            above_targets(&control_child),
            EGRESS_BROKER_HOST_ADDRESSES_FD,
        ),
    ];
    let mut sessions = Vec::new();
    for index in 0..EGRESS_BROKER_INHERITED_SESSIONS {
        let (worker_end, broker_end) = UnixStream::pair().unwrap();
        sources.push((
            above_targets(&broker_end),
            EGRESS_BROKER_FIRST_SESSION_FD + index as RawFd,
        ));
        sessions.push(worker_end);
    }
    inherit_descriptors_only(
        &mut broker_command,
        sources
            .iter()
            .map(|(source, target)| (source.as_raw_fd(), *target))
            .collect(),
    );
    let mut broker = ChildGuard(broker_command.spawn().unwrap());
    drop(sources);
    drop(broker_child);
    drop(control_child);
    control
        .write_all(&encode_frame(&HostAddressSet::default()))
        .unwrap();
    broker_parent
        .write_all(
            encode_egress_broker_bootstrap(
                vm_id,
                generation,
                &broker_key,
                &codewire_egress_policy::CompiledPolicy::developer_baseline(),
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();
    assert_eq!(
        read_status_frame(&mut broker_parent),
        EGRESS_BROKER_PREPARED_MESSAGE
    );
    broker_parent
        .write_all(EGRESS_BROKER_CONFINE_MESSAGE)
        .unwrap();
    assert_eq!(
        read_status_frame(&mut broker_parent),
        EGRESS_BROKER_READY_MESSAGE
    );

    let (mut worker_parent, worker_child) = UnixStream::pair().unwrap();
    set_timeouts(&worker_parent);
    let network_key = NetworkKey::derive(
        "confinement-proof-worker-token-0123456789abcdef",
        vm_id,
        generation,
    )
    .unwrap();
    let bootstrap = encode_product_worker_bootstrap(
        vm_id,
        generation,
        &network_key,
        &broker_key,
        // The host-port control key (its module is crate-private on macOS).
        &[0x7b; 32],
        &[0x4d; MESH_INGRESS_CONTROL_KEY_LEN],
        &[3_001],
        codewire_egress_policy::CompiledPolicy::developer_baseline().digest(),
    )
    .unwrap();
    let mut worker_command = cw(
        directory.path(),
        "__native-network-worker",
        vm_id,
        generation,
    );
    inherit_only(
        &mut worker_command,
        worker_child.as_raw_fd(),
        NETWORK_BOOTSTRAP_FD,
    );
    let mut worker = ChildGuard(worker_command.spawn().unwrap());
    drop(worker_child);
    worker_parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(
        read_status_frame(&mut worker_parent),
        WORKER_PREPARED_MESSAGE
    );
    // The admission session (the broker's bootstrap stream), then the rest.
    for session in std::iter::once(&broker_parent).chain(&sessions) {
        send_descriptor(
            worker_parent.as_raw_fd(),
            session.as_raw_fd(),
            BROKER_DESCRIPTOR_MARKER,
        );
    }
    drop(broker_parent);
    drop(sessions);
    assert_eq!(
        read_status_frame(&mut worker_parent),
        WORKER_BROKER_READY_MESSAGE
    );

    let (mut guest, worker_network) = UnixStream::pair().unwrap();
    set_timeouts(&guest);
    send_descriptor(
        worker_parent.as_raw_fd(),
        worker_network.as_raw_fd(),
        NETWORK_DESCRIPTOR_MARKER,
    );
    drop(worker_network);
    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    guest.read_exact(&mut hello).unwrap();
    let hello = NetworkHostHello::decode(&hello, &network_key, vm_id, generation).unwrap();
    guest
        .write_all(
            &NetworkGuestAck::new(hello.nonce)
                .unwrap()
                .encode(&network_key),
        )
        .unwrap();
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    guest.read_exact(&mut ready).unwrap();
    NetworkHostReady::decode(&ready, &network_key, &hello.nonce).unwrap();
    assert_eq!(read_status_frame(&mut worker_parent), WORKER_READY_MESSAGE);

    // Serving, the worker holds standard I/O on /dev/null, kqueues, and Unix
    // sockets that lead only to this test, to the broker, or back into the
    // worker (its own event plumbing). No file, no internet socket.
    let held = descriptors(worker.0.id() as libc::pid_t);
    let null = dev_null_rdev();
    // The worker's ends of the bootstrap and guest channels are the peers of
    // the ends this test holds.
    let (_, bootstrap) = unix_socket(unsafe { libc::getpid() }, worker_parent.as_raw_fd());
    let (_, guest_end) = unix_socket(unsafe { libc::getpid() }, guest.as_raw_fd());
    let broker_ends: Vec<u64> = descriptors(broker.0.id() as libc::pid_t)
        .into_iter()
        .filter_map(|(_, kind)| match kind {
            Descriptor::Unix { handle, .. } => Some(handle),
            _ => None,
        })
        .collect();
    let internal: Vec<u64> = held
        .iter()
        .filter_map(|(_, kind)| match kind {
            Descriptor::Unix { handle, .. } => Some(*handle),
            _ => None,
        })
        .collect();
    let (mut to_test, mut to_broker) = (Vec::new(), 0);
    for (fd, kind) in &held {
        match kind {
            Descriptor::Vnode { rdev } if (0..=2).contains(fd) && *rdev == null => {}
            Descriptor::Kqueue => {}
            Descriptor::Unix { handle, .. } if [bootstrap, guest_end].contains(handle) => {
                to_test.push(*handle);
            }
            Descriptor::Unix { peer, .. } if broker_ends.contains(peer) => to_broker += 1,
            Descriptor::Unix { peer, .. } if internal.contains(peer) => {}
            _ => panic!("confined worker holds {fd}: {kind:?}; table {held:?}"),
        }
    }
    to_test.sort_unstable();
    to_test.dedup();
    assert_eq!(to_test.len(), 2, "bootstrap and guest: {held:?}");
    assert_eq!(to_broker, BROKER_IPC_SESSIONS, "broker sessions: {held:?}");

    drop(guest);
    assert_eq!(
        worker.wait_bounded().code(),
        Some(NetworkWorkerStartupFailure::FrameIo.exit_code())
    );
    broker.wait_bounded();
}

fn cw(directory: &std::path::Path, role: &str, vm_id: Uuid, generation: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg(role)
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn set_timeouts(stream: &UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
}

/// The child inherits standard I/O and `source` at `target`, nothing else:
/// a descriptor another test thread opened without close-on-exec yet is
/// closed on exec too.
/// A duplicate above every fixed target a role inherits, as the runner makes.
fn above_targets(descriptor: &UnixStream) -> OwnedFd {
    let duplicated = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    assert!(duplicated >= 64);
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

/// Like `inherit_only`, for several (source, target) pairs; sources are above
/// every target.
fn inherit_descriptors_only(command: &mut Command, pairs: Vec<(RawFd, RawFd)>) {
    assert!(pairs.iter().all(|(source, _)| *source >= 64));
    // SAFETY: the hook performs only async-signal-safe descriptor syscalls.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..libc::getdtablesize() {
                if !pairs.iter().any(|(source, _)| *source == fd) {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            for &(source, target) in &pairs {
                if source != target && libc::dup2(source, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for &(source, target) in &pairs {
                if source != target {
                    libc::fcntl(source, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
}

fn inherit_only(command: &mut Command, source: RawFd, target: RawFd) {
    // SAFETY: the hook performs only async-signal-safe descriptor syscalls.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..libc::getdtablesize() {
                if fd != source {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            if source != target && libc::dup2(source, target) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if source != target {
                libc::fcntl(source, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
}

fn read_status_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut frame = Vec::with_capacity(WORKER_STATUS_MAX_BYTES);
    loop {
        assert!(frame.len() < WORKER_STATUS_MAX_BYTES);
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return frame;
        }
    }
}

#[repr(C)]
union ControlBuffer {
    alignment: libc::cmsghdr,
    bytes: [u8; CONTROL_BYTES],
}

fn send_descriptor(bootstrap: RawFd, descriptor: RawFd, descriptor_marker: u8) {
    let mut marker = [descriptor_marker];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let mut control = ControlBuffer {
        bytes: [0_u8; CONTROL_BYTES],
    };
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
    assert!(control_space as usize <= CONTROL_BYTES);
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = control_space;
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32);
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }
    assert_eq!(
        unsafe { libc::sendmsg(bootstrap, &raw const message, 0) },
        marker.len() as isize
    );
}
