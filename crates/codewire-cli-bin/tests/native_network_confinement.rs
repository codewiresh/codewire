#![cfg(target_os = "linux")]

//! The Linux counterparts of the macOS #1905 conditions, run against the real
//! `cw` packet worker and egress broker started as the runner starts them.
//!
//! - Condition 1: when Landlock, seccomp or the capability drop cannot be
//!   applied, the worker and the broker report the typed failure, exit with
//!   its status and never serve. A seccomp filter installed before exec makes
//!   the one confinement syscall fail, as a kernel without that feature would.
//! - Condition 2: a serving worker holds only the descriptors it was given:
//!   its broker IPC sessions (#2638), bootstrap and guest streams. Its
//!   `/proc/<pid>/fd` table is read and every Unix socket's peer is resolved
//!   through `sock_diag`, as macOS reads the table with libproc.
//!
//! The roles are started with whatever capabilities this test process holds
//! (every default one as root in a CI container, an inherited one in some
//! shells), so a serving role with none proves that it discarded them itself.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use codewire_egress_broker::ipc::{BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS};
use codewire_local_vmm::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES,
    EgressBrokerStartupFailure, EgressBrokerStartupStatus, decode_egress_broker_startup_status,
    encode_egress_broker_bootstrap,
};
use codewire_local_vmm::host_addresses::{HostAddressSet, encode_frame};
use codewire_local_vmm::mesh_ingress::MESH_INGRESS_CONTROL_KEY_LEN;
use codewire_local_vmm::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, NetworkWorkerStartupStatus,
    WORKER_BROKER_READY_MESSAGE, WORKER_PREPARED_MESSAGE, WORKER_READY_MESSAGE,
    WORKER_STATUS_MAX_BYTES, decode_worker_startup_status, encode_product_worker_bootstrap,
};
use codewire_vmm_guest_probe::{
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
    NetworkHostReady, NetworkKey,
};
use uuid::Uuid;

const BROKER_DESCRIPTOR_MARKER: u8 = b'B';
const NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const CONTROL_BYTES: usize = 64;
const BROKER_KEY: [u8; BROKER_IPC_KEY_LEN] = [0x5a; BROKER_IPC_KEY_LEN];

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

/// The child; for a broker, the runner's end of its host-address control
/// socket, held open for the broker's lifetime, and the worker's ends of its
/// inherited IPC sessions.
struct ChildGuard(
    Child,
    #[allow(dead_code, reason = "held open, never read")] Option<UnixStream>,
    Vec<UnixStream>,
);

impl ChildGuard {
    fn pid(&self) -> u32 {
        self.0.id()
    }

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

fn identity() -> (Uuid, u64) {
    (
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        9,
    )
}

/// One syscall the kernel refuses with `errno`, as a kernel without that
/// confinement feature would. Everything else is allowed.
#[derive(Clone, Copy)]
struct RefusedSyscall {
    number: libc::c_long,
    errno: libc::c_int,
}

/// Starts a hidden `cw` role the way the runner does: an empty environment,
/// standard I/O on `/dev/null`, exactly one inherited bootstrap descriptor,
/// the parent-death signal and `no_new_privs`. Unlike the runner it leaves
/// the role this test's capabilities; discarding them is the role's own job.
fn spawn_role(
    role: &str,
    directory: &std::path::Path,
    target_fd: RawFd,
    refused: Option<RefusedSyscall>,
) -> (UnixStream, ChildGuard) {
    let (parent, child_socket) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (environment_id, generation) = identity();
    let mut filter = refused.map(refusal_filter);
    let source = child_socket.as_raw_fd();
    // A broker also takes the runner's host-address control socket (#2614)
    // and its IPC sessions after the admission session (#2638), whose sources
    // sit above every fixed target as the runner places them.
    let broker = role == "__native-egress-broker";
    let control = broker.then(|| UnixStream::pair().unwrap());
    let control_source = control.as_ref().map(|(_, child)| child.as_raw_fd());
    let mut sessions = Vec::new();
    let mut inherited_sessions = Vec::new();
    for _ in 0..if broker {
        EGRESS_BROKER_INHERITED_SESSIONS
    } else {
        0
    } {
        let (worker_end, broker_end) = UnixStream::pair().unwrap();
        // SAFETY: `broker_end` is open for the call; F_DUPFD_CLOEXEC takes an
        // integer and returns a new descriptor or -1.
        let duplicated = unsafe { libc::fcntl(broker_end.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        assert!(duplicated >= 64);
        // SAFETY: `duplicated` is a descriptor this loop just created, and
        // nothing else owns it.
        inherited_sessions.push(unsafe { OwnedFd::from_raw_fd(duplicated) });
        sessions.push(worker_end);
    }
    let session_descriptors: Vec<(RawFd, RawFd)> = inherited_sessions
        .iter()
        .map(|session| session.as_raw_fd())
        .zip(EGRESS_BROKER_FIRST_SESSION_FD..)
        .collect();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg(role)
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook performs only async-signal-safe syscalls on memory
    // allocated before fork, and admits exactly one bootstrap descriptor.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if source != target_fd && libc::dup2(source, target_fd) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(target_fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(control_source) = control_source
                && (libc::dup2(control_source, EGRESS_BROKER_HOST_ADDRESSES_FD) == -1
                    || libc::fcntl(EGRESS_BROKER_HOST_ADDRESSES_FD, libc::F_SETFD, 0) == -1)
            {
                return Err(std::io::Error::last_os_error());
            }
            for &(source, target) in &session_descriptors {
                if libc::dup2(source, target) == -1 || libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(filter) = filter.as_mut() {
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_mut_ptr(),
                };
                if libc::syscall(libc::SYS_seccomp, 1_u32, 0_u32, &raw const program) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(child_socket);
    drop(inherited_sessions);
    let control = control.map(|(mut control, control_child)| {
        drop(control_child);
        control
            .write_all(&encode_frame(&HostAddressSet::default()))
            .unwrap();
        control
    });
    (parent, ChildGuard(child, control, sessions))
}

fn refusal_filter(refused: RefusedSyscall) -> Vec<libc::sock_filter> {
    let statement = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let equal = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    vec![
        statement(load, 4),
        equal(AUDIT_ARCH_NATIVE, 0, 3),
        statement(load, 0),
        equal(refused.number as u32, 0, 1),
        statement(ret, libc::SECCOMP_RET_ERRNO | refused.errno as u32),
        statement(ret, libc::SECCOMP_RET_ALLOW),
    ]
}

fn read_status_frame(stream: &mut UnixStream, maximum: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(maximum);
    loop {
        assert!(frame.len() < maximum, "status frame exceeds its bound");
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return frame;
        }
    }
}

/// After a refusal the role writes nothing more and closes its bootstrap.
fn require_closed(stream: &mut UnixStream) {
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "refused role kept writing: {rest:?}");
}

fn product_worker_bootstrap(network_key: &NetworkKey) -> Vec<u8> {
    let (vm_id, generation) = identity();
    encode_product_worker_bootstrap(
        vm_id,
        generation,
        network_key,
        &BROKER_KEY,
        &[0x4d; MESH_INGRESS_CONTROL_KEY_LEN],
        &[3_001],
        codewire_egress_policy::CompiledPolicy::developer_baseline().digest(),
    )
    .unwrap()
    .to_vec()
}

fn network_key() -> NetworkKey {
    let (vm_id, generation) = identity();
    NetworkKey::derive(
        "confinement-proof-worker-token-0123456789abcdef",
        vm_id,
        generation,
    )
    .unwrap()
}

fn worker_refusal(refused: RefusedSyscall, expected: NetworkWorkerStartupFailure) {
    let directory = tempfile::tempdir().unwrap();
    let (mut bootstrap, mut worker) = spawn_role(
        "__native-network-worker",
        directory.path(),
        NETWORK_BOOTSTRAP_FD,
        Some(refused),
    );
    bootstrap
        .write_all(&product_worker_bootstrap(&network_key()))
        .unwrap();
    let frame = read_status_frame(&mut bootstrap, WORKER_STATUS_MAX_BYTES);
    assert_ne!(frame, WORKER_PREPARED_MESSAGE, "worker served unconfined");
    assert_eq!(
        decode_worker_startup_status(&frame),
        Some(NetworkWorkerStartupStatus::Failed(expected))
    );
    require_closed(&mut bootstrap);
    assert_eq!(worker.wait_bounded().code(), Some(expected.exit_code()));
}

fn broker_refusal(refused: RefusedSyscall, expected: EgressBrokerStartupFailure) {
    let directory = tempfile::tempdir().unwrap();
    let (mut bootstrap, mut broker) = spawn_role(
        "__native-egress-broker",
        directory.path(),
        EGRESS_BROKER_BOOTSTRAP_FD,
        Some(refused),
    );
    let (vm_id, generation) = identity();
    bootstrap
        .write_all(
            developer_broker_bootstrap(vm_id, generation, &BROKER_KEY)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES),
        EGRESS_BROKER_PREPARED_MESSAGE
    );
    bootstrap.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    let frame = read_status_frame(&mut bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES);
    assert_ne!(
        frame, EGRESS_BROKER_READY_MESSAGE,
        "broker served unconfined"
    );
    assert_eq!(
        decode_egress_broker_startup_status(&frame),
        Some(EgressBrokerStartupStatus::Failed(expected))
    );
    require_closed(&mut bootstrap);
    assert_eq!(broker.wait_bounded().code(), Some(expected.exit_code()));
}

/// A kernel with Landlock disabled answers `EOPNOTSUPP`.
const LANDLOCK_UNAVAILABLE: RefusedSyscall = RefusedSyscall {
    number: libc::SYS_landlock_create_ruleset,
    errno: libc::EOPNOTSUPP,
};

/// A kernel without seccomp filtering answers `EINVAL`.
const SECCOMP_UNAVAILABLE: RefusedSyscall = RefusedSyscall {
    number: libc::SYS_seccomp,
    errno: libc::EINVAL,
};

/// A process that may not change its capability sets gets `EPERM`.
const CAPABILITY_DROP_REFUSED: RefusedSyscall = RefusedSyscall {
    number: libc::SYS_capset,
    errno: libc::EPERM,
};

#[test]
fn worker_refuses_to_serve_without_its_capability_drop() {
    worker_refusal(
        CAPABILITY_DROP_REFUSED,
        NetworkWorkerStartupFailure::PrivilegeConfinement,
    );
}

#[test]
fn worker_refuses_to_serve_without_landlock() {
    worker_refusal(
        LANDLOCK_UNAVAILABLE,
        NetworkWorkerStartupFailure::FilesystemConfinement,
    );
}

#[test]
fn worker_refuses_to_serve_without_seccomp() {
    worker_refusal(
        SECCOMP_UNAVAILABLE,
        NetworkWorkerStartupFailure::SyscallConfinement,
    );
}

#[test]
fn broker_refuses_to_serve_without_its_privilege_lock() {
    broker_refusal(
        CAPABILITY_DROP_REFUSED,
        EgressBrokerStartupFailure::PrivilegeConfinement,
    );
}

#[test]
fn broker_refuses_to_serve_without_landlock() {
    broker_refusal(
        LANDLOCK_UNAVAILABLE,
        EgressBrokerStartupFailure::FilesystemConfinement,
    );
}

#[test]
fn broker_refuses_to_serve_without_seccomp() {
    broker_refusal(
        SECCOMP_UNAVAILABLE,
        EgressBrokerStartupFailure::SyscallConfinement,
    );
}

/// The broker holds standard I/O on /dev/null, its bootstrap (4), host-address
/// control (5) and IPC sessions (6 to 29), and otherwise only its runtime's
/// epoll, eventfd and Unix streams that lead back into itself. Read at
/// PREPARED: after confinement the broker is not dumpable, so its descriptor
/// table is closed to this test.
#[test]
fn a_prepared_broker_holds_exactly_its_inherited_descriptors() {
    // Metal CI Kata guest only; see metal_guest_skip.
    if skipped_on_metal_guest() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let (vm_id, generation) = identity();
    let (mut bootstrap, broker) = spawn_role(
        "__native-egress-broker",
        directory.path(),
        EGRESS_BROKER_BOOTSTRAP_FD,
        None,
    );
    bootstrap
        .write_all(
            developer_broker_bootstrap(vm_id, generation, &BROKER_KEY)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES),
        EGRESS_BROKER_PREPARED_MESSAGE
    );

    let pid = broker.pid();
    let held = descriptors(pid);
    let unix = unix_sockets();
    let own: BTreeSet<u64> = held
        .values()
        .filter_map(|target| socket_target_inode(target))
        .collect();
    let null = std::fs::metadata("/dev/null").unwrap().rdev();
    let mut inherited = Vec::new();
    for (fd, target) in &held {
        if (0..=2).contains(fd) {
            assert_eq!(target, "/dev/null", "broker standard fd {fd}");
            let metadata = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")).unwrap();
            assert_eq!(metadata.rdev(), null, "broker standard fd {fd}");
        } else if let Some(inode) = socket_target_inode(target) {
            let socket = unix
                .get(&inode)
                .unwrap_or_else(|| panic!("broker fd {fd} is not a Unix socket: {held:?}"));
            assert!(!socket.named, "broker fd {fd} is a named socket");
            match socket.peer {
                Some(peer) if own.contains(&peer) => {}
                _ => inherited.push(*fd),
            }
        } else {
            assert!(
                matches!(
                    target.as_str(),
                    "anon_inode:[eventpoll]" | "anon_inode:[eventfd]"
                ),
                "broker holds fd {fd} -> {target}: {held:?}"
            );
        }
    }
    let expected: Vec<RawFd> = [EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_HOST_ADDRESSES_FD]
        .into_iter()
        .chain(
            (0..EGRESS_BROKER_INHERITED_SESSIONS)
                .map(|index| EGRESS_BROKER_FIRST_SESSION_FD + index as RawFd),
        )
        .collect();
    assert_eq!(inherited, expected, "{held:?}");
}

#[test]
fn the_confined_worker_holds_only_the_descriptors_it_was_given() {
    // Metal CI Kata guest only; see metal_guest_skip.
    if skipped_on_metal_guest() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let (vm_id, generation) = identity();

    let (mut broker_bootstrap, mut broker) = spawn_role(
        "__native-egress-broker",
        directory.path(),
        EGRESS_BROKER_BOOTSTRAP_FD,
        None,
    );
    broker_bootstrap
        .write_all(
            developer_broker_bootstrap(vm_id, generation, &BROKER_KEY)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
    assert_eq!(
        read_status_frame(&mut broker_bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES),
        EGRESS_BROKER_PREPARED_MESSAGE
    );
    broker_bootstrap
        .write_all(EGRESS_BROKER_CONFINE_MESSAGE)
        .unwrap();
    assert_eq!(
        read_status_frame(&mut broker_bootstrap, EGRESS_BROKER_STATUS_MAX_BYTES),
        EGRESS_BROKER_READY_MESSAGE
    );
    require_confined_without_capabilities(broker.pid());

    let key = network_key();
    let (mut worker_bootstrap, mut worker) = spawn_role(
        "__native-network-worker",
        directory.path(),
        NETWORK_BOOTSTRAP_FD,
        None,
    );
    worker_bootstrap
        .write_all(&product_worker_bootstrap(&key))
        .unwrap();
    assert_eq!(
        read_status_frame(&mut worker_bootstrap, WORKER_STATUS_MAX_BYTES),
        WORKER_PREPARED_MESSAGE
    );
    // The broker's bootstrap stream becomes the worker's admission session,
    // and the other session ends follow, as the runner hands them over after
    // the broker is ready.
    let sessions: Vec<UnixStream> = std::iter::once(broker_bootstrap)
        .chain(std::mem::take(&mut broker.2))
        .collect();
    assert_eq!(sessions.len(), BROKER_IPC_SESSIONS);
    for session in &sessions {
        send_descriptor(
            worker_bootstrap.as_raw_fd(),
            session.as_raw_fd(),
            BROKER_DESCRIPTOR_MARKER,
        );
    }
    let broker_channels: BTreeSet<u64> = sessions
        .iter()
        .map(|session| socket_inode(session.as_raw_fd()))
        .collect();
    drop(sessions);
    assert_eq!(
        read_status_frame(&mut worker_bootstrap, WORKER_STATUS_MAX_BYTES),
        WORKER_BROKER_READY_MESSAGE
    );

    let (mut guest, worker_network) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    send_descriptor(
        worker_bootstrap.as_raw_fd(),
        worker_network.as_raw_fd(),
        NETWORK_DESCRIPTOR_MARKER,
    );
    drop(worker_network);
    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    guest.read_exact(&mut hello).unwrap();
    let hello = NetworkHostHello::decode(&hello, &key, vm_id, generation).unwrap();
    guest
        .write_all(&NetworkGuestAck::new(hello.nonce).unwrap().encode(&key))
        .unwrap();
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    guest.read_exact(&mut ready).unwrap();
    NetworkHostReady::decode(&ready, &key, &hello.nonce).unwrap();
    assert_eq!(
        read_status_frame(&mut worker_bootstrap, WORKER_STATUS_MAX_BYTES),
        WORKER_READY_MESSAGE
    );

    let pid = worker.pid();
    require_confined_without_capabilities(pid);
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert_eq!(status_field(&status, "Threads"), "1", "{status}");

    // Serving, the worker holds standard I/O on /dev/null, its epoll and
    // eventfd, and Unix streams that lead only to this test (bootstrap and
    // guest), to the broker, or back into the worker itself. No file, no
    // internet socket.
    let held = descriptors(pid);
    let inet = inet_socket_inodes(pid);
    let unix = unix_sockets();
    let worker_sockets: BTreeSet<u64> = held
        .values()
        .filter_map(|target| socket_target_inode(target))
        .collect();
    let null = std::fs::metadata("/dev/null").unwrap().rdev();
    let test_ends = BTreeSet::from([
        socket_inode(worker_bootstrap.as_raw_fd()),
        socket_inode(guest.as_raw_fd()),
    ]);
    let (mut to_test, mut to_broker, mut internal) = (BTreeSet::new(), 0, 0);
    for (fd, target) in &held {
        if let Some(inode) = socket_target_inode(target) {
            assert!(
                !inet.contains(&inode),
                "worker fd {fd} is an internet socket"
            );
            let socket = unix
                .get(&inode)
                .unwrap_or_else(|| panic!("worker fd {fd} is not a Unix socket: {held:?}"));
            assert_eq!(socket.kind, libc::SOCK_STREAM as u8, "worker fd {fd}");
            assert!(!socket.named, "worker fd {fd} is a named socket");
            // The broker's end is in a non-dumpable process: the worker's
            // broker channel is the exact socket this test handed over, still
            // connected to a peer neither this test nor the worker holds.
            match socket.peer {
                Some(peer) if test_ends.contains(&peer) => {
                    to_test.insert(peer);
                }
                Some(peer)
                    if broker_channels.contains(&inode)
                        && !worker_sockets.contains(&peer)
                        && !test_ends.contains(&peer) =>
                {
                    to_broker += 1
                }
                Some(peer) if worker_sockets.contains(&peer) => internal += 1,
                other => panic!("worker fd {fd} leads to {other:?}: {held:?}"),
            }
        } else if (0..=2).contains(fd) {
            assert_eq!(target, "/dev/null", "worker standard fd {fd}");
            let metadata = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")).unwrap();
            assert_eq!(metadata.rdev(), null, "worker standard fd {fd}");
        } else {
            assert!(
                matches!(
                    target.as_str(),
                    "anon_inode:[eventpoll]" | "anon_inode:[eventfd]"
                ),
                "worker holds fd {fd} -> {target}: {held:?}"
            );
        }
    }
    assert_eq!(to_test, test_ends, "bootstrap and guest: {held:?}");
    assert_eq!(to_broker, BROKER_IPC_SESSIONS, "broker sessions: {held:?}");
    eprintln!(
        "confined worker {pid}: {} descriptors, {} internal Unix streams, no file, no internet socket",
        held.len(),
        internal
    );

    drop(guest);
    assert_eq!(
        worker.wait_bounded().code(),
        Some(NetworkWorkerStartupFailure::FrameIo.exit_code())
    );
    broker.wait_bounded();
}

const NO_CAPABILITIES: &str = "0000000000000000";

/// A serving role is under `no_new_privs` and a seccomp filter and holds no
/// capability in any set it can change. Its bounding set is empty too when
/// it started able to change it.
fn require_confined_without_capabilities(pid: u32) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    for (field, expected) in [
        ("NoNewPrivs", "1"),
        ("Seccomp", "2"),
        ("CapInh", NO_CAPABILITIES),
        ("CapPrm", NO_CAPABILITIES),
        ("CapEff", NO_CAPABILITIES),
        ("CapAmb", NO_CAPABILITIES),
    ] {
        assert_eq!(status_field(&status, field), expected, "{field}: {status}");
    }
    if role_starts_able_to_empty_its_bounding_set() {
        assert_eq!(
            status_field(&status, "CapBnd"),
            NO_CAPABILITIES,
            "CapBnd: {status}"
        );
    }
}

/// Whether a role started by this test begins with `CAP_SETPCAP`, which the
/// kernel requires to drop a bounding capability. Across an exec under
/// `no_new_privs` root keeps the permitted capabilities its inheritable and
/// bounding sets allow; any other user keeps only its ambient set.
fn role_starts_able_to_empty_its_bounding_set() -> bool {
    const CAP_SETPCAP: u64 = 1 << 8;
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let set = |field| u64::from_str_radix(status_field(&status, field), 16).unwrap();
    // SAFETY: geteuid takes no argument and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let kept = if root {
        set("CapPrm") & (set("CapInh") | set("CapBnd"))
    } else {
        set("CapAmb")
    };
    kept & CAP_SETPCAP != 0
}

fn status_field<'a>(status: &'a str, field: &str) -> &'a str {
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .and_then(|rest| rest.strip_prefix(':'))
        })
        .map(str::trim)
        .unwrap_or_else(|| panic!("{field} missing from status"))
}

fn descriptors(pid: u32) -> BTreeMap<RawFd, String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let fd = entry.file_name().to_str().unwrap().parse().unwrap();
            let target = std::fs::read_link(entry.path()).unwrap();
            (fd, target.to_str().unwrap().to_owned())
        })
        .collect()
}

fn socket_target_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn socket_inode(fd: RawFd) -> u64 {
    // SAFETY: `stat` holds only integers, and all-zero is a valid value of each.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is writable; a bad descriptor only makes the call fail.
    let found = unsafe { libc::fstat(fd, &raw mut stat) };
    assert_eq!(found, 0);
    assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFSOCK);
    stat.st_ino
}

/// Inodes of every TCP, UDP and raw socket in the worker's network namespace.
fn inet_socket_inodes(pid: u32) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();
    for table in [
        "tcp", "tcp6", "udp", "udp6", "udplite", "udplite6", "raw", "raw6",
    ] {
        let Ok(contents) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let inode = line.split_whitespace().nth(9).unwrap().parse().unwrap();
            inodes.insert(inode);
        }
    }
    inodes
}

struct UnixSocket {
    kind: u8,
    named: bool,
    peer: Option<u64>,
}

/// Set to `1` by a CI job's step only inside a metal Kata guest, which alone
/// mounts the ext4 warm cache at `/ci-cache`; a cloud runner never sets it.
const METAL_KATA_GUEST: &str = "CODEWIRE_CI_METAL_KATA_GUEST";

/// The metal CI Kata guests' kernel has no `CONFIG_UNIX_DIAG`, so it refuses
/// the AF_UNIX sock_diag dump these descriptor proofs read. Owner, 2026-10-21
/// (codewire#2940): skip them there, and run them by name in the Linux release
/// host check, on a full kernel, before each release. Only a job that declares
/// the metal guest AND a refused dump skip; anywhere else a refused dump still
/// fails the test.
fn metal_guest_skip(declared: Option<&std::ffi::OsStr>, dump: Result<(), i32>) -> Option<String> {
    match (declared == Some(std::ffi::OsStr::new("1")), dump) {
        (true, Err(errno)) => Some(format!(
            "skipped on the metal CI Kata guest: its kernel has no CONFIG_UNIX_DIAG \
             (sock_diag errno {errno}); this descriptor proof runs in the Linux release \
             host check instead (owner, 2026-10-21, codewire#2940)"
        )),
        _ => None,
    }
}

fn skipped_on_metal_guest() -> bool {
    let declared = std::env::var_os(METAL_KATA_GUEST);
    if declared.is_none() {
        return false;
    }
    let dump = unix_socket_dump().map(|_| ());
    match metal_guest_skip(declared.as_deref(), dump) {
        Some(reason) => {
            eprintln!("{reason}");
            true
        }
        None => false,
    }
}

#[test]
fn the_unix_diag_skip_needs_the_metal_guest_declaration_and_a_refused_dump() {
    let metal = Some(std::ffi::OsStr::new("1"));
    let refused = Err(libc::ENOENT);
    let reason = metal_guest_skip(metal, refused).unwrap();
    assert!(reason.contains("CONFIG_UNIX_DIAG") && reason.contains("owner, 2026-10-21"));
    assert!(reason.contains("Linux release host check"));
    // A refused dump without the declaration, or with any other value, fails.
    assert_eq!(metal_guest_skip(None, refused), None);
    for other in ["0", "", "true", "yes", " 1"] {
        assert_eq!(
            metal_guest_skip(Some(std::ffi::OsStr::new(other)), refused),
            None
        );
    }
    // A declared guest whose kernel answers the dump runs the proof.
    assert_eq!(metal_guest_skip(metal, Ok(())), None);
    assert_eq!(metal_guest_skip(None, Ok(())), None);
}

/// Every AF_UNIX socket in this network namespace with its peer, read from
/// the kernel through `NETLINK_SOCK_DIAG`.
fn unix_sockets() -> BTreeMap<u64, UnixSocket> {
    unix_socket_dump().unwrap_or_else(|errno| panic!("sock_diag refused the dump (errno {errno})"))
}

/// The AF_UNIX sock_diag dump, or the errno with which the kernel refused it.
/// A kernel without `CONFIG_UNIX_DIAG` has no handler for the family.
fn unix_socket_dump() -> Result<BTreeMap<u64, UnixSocket>, i32> {
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const UDIAG_SHOW_NAME: u32 = 0x1;
    const UDIAG_SHOW_PEER: u32 = 0x4;
    const UNIX_DIAG_NAME: u16 = 0;
    const UNIX_DIAG_PEER: u16 = 2;
    const HEADER: usize = 16;
    const MESSAGE: usize = 16;

    // SAFETY: socket takes three integers and returns a new descriptor or -1.
    let socket = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    assert!(socket >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `socket` is a descriptor this function just created, and nothing
    // else owns it. Dropping it closes it on every return path.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut request = Vec::with_capacity(HEADER + 24);
    request.extend_from_slice(&((HEADER + 24) as u32).to_ne_bytes());
    request.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    request.extend_from_slice(&1_u32.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&[libc::AF_UNIX as u8, 0, 0, 0]);
    request.extend_from_slice(&u32::MAX.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&(UDIAG_SHOW_NAME | UDIAG_SHOW_PEER).to_ne_bytes());
    request.extend_from_slice(&[0xff; 8]);
    // SAFETY: the pointer and the length describe the whole of `request`.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    assert_eq!(sent, request.len() as isize);

    let u16_at = |bytes: &[u8], at: usize| u16::from_ne_bytes([bytes[at], bytes[at + 1]]);
    let u32_at =
        |bytes: &[u8], at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
    let mut sockets = BTreeMap::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    'receive: loop {
        // SAFETY: the pointer and the length describe the whole of `buffer`,
        // so the kernel writes only inside it.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        assert!(received > 0, "{}", std::io::Error::last_os_error());
        let mut messages = &buffer[..received as usize];
        while messages.len() >= HEADER {
            let length = u32_at(messages, 0) as usize;
            let kind = u16_at(messages, 4);
            assert!(length >= HEADER && length <= messages.len());
            if kind == libc::NLMSG_DONE as u16 {
                break 'receive;
            }
            let body = &messages[HEADER..length];
            if kind == libc::NLMSG_ERROR as u16 {
                // struct nlmsgerr begins with the negative errno.
                assert!(body.len() >= 4);
                let errno = -i32::from_ne_bytes(body[..4].try_into().unwrap());
                return Err(errno);
            }
            let mut socket = UnixSocket {
                kind: body[1],
                named: false,
                peer: None,
            };
            let inode = u64::from(u32_at(body, 4));
            let mut attributes = &body[MESSAGE..];
            while attributes.len() >= 4 {
                let attribute_length = u16_at(attributes, 0) as usize;
                assert!(attribute_length >= 4 && attribute_length <= attributes.len());
                match u16_at(attributes, 2) {
                    UNIX_DIAG_PEER => socket.peer = Some(u64::from(u32_at(attributes, 4))),
                    UNIX_DIAG_NAME => socket.named = true,
                    _ => {}
                }
                let aligned = (attribute_length + 3) & !3;
                attributes = &attributes[aligned.min(attributes.len())..];
            }
            sockets.insert(inode, socket);
            let aligned = (length + 3) & !3;
            messages = &messages[aligned.min(messages.len())..];
        }
    }
    Ok(sockets)
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
    // SAFETY: CMSG_SPACE only computes a size from its argument.
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
    assert!(control_space as usize <= CONTROL_BYTES);
    // SAFETY: `msghdr` holds integers and pointers, and all-zero is a valid
    // value of each.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    // SAFETY: the union was initialized through `bytes`, and any bytes are a
    // valid `[u8; N]`.
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = control_space as _;
    // SAFETY: `msg_control` points to `control`, which is at least
    // `msg_controllen` bytes long, as the assert above shows.
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    assert!(!header.is_null());
    // SAFETY: `header` is non-null and points into `control`, which the union
    // aligns for `cmsghdr` and which has room for one descriptor after it.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }
    // SAFETY: `message`, its one vector and its control buffer stay live and
    // unmoved for the call.
    let sent = unsafe { libc::sendmsg(bootstrap, &raw const message, libc::MSG_NOSIGNAL) };
    assert_eq!(sent, marker.len() as isize);
}

/// The broker bootstrap the runner writes for the developer baseline policy.
fn developer_broker_bootstrap(
    environment_id: Uuid,
    generation: u64,
    key: &[u8; BROKER_IPC_KEY_LEN],
) -> Result<zeroize::Zeroizing<Vec<u8>>, codewire_local_vmm::egress_broker::EgressBrokerProcessError>
{
    encode_egress_broker_bootstrap(
        environment_id,
        generation,
        key,
        &codewire_egress_policy::CompiledPolicy::developer_baseline(),
    )
}
