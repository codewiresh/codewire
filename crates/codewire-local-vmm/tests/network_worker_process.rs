#![cfg(target_os = "linux")]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]
// Predates this workspace lint; #4125 tracks removing the allow.
#![allow(clippy::undocumented_unsafe_blocks)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN;
use codewire_local_vmm::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, EgressBrokerStartupFailure,
    encode_egress_broker_bootstrap,
};
use codewire_local_vmm::host_addresses::{HostAddressSet, encode_frame};
use codewire_local_vmm::host_port::{
    HOST_PORT_CONTROL_KEY_LEN, HostPortBinding, HostPortControlFrame,
};
use codewire_local_vmm::mesh_enrollment::{
    MESH_ENROLLMENT_BOOTSTRAP_FD, MESH_ENROLLMENT_CONFINE_MESSAGE,
    MESH_ENROLLMENT_PREPARED_MESSAGE, MESH_ENROLLMENT_READY_MESSAGE, MESH_ENROLLMENT_TRANSFER_FD,
    encode_mesh_enrollment_bootstrap,
};
use codewire_local_vmm::mesh_ingress::{
    MESH_INGRESS_CONTROL_FRAME_LEN, MESH_INGRESS_CONTROL_KEY_LEN, MeshAttachment,
    MeshIngressBinding, MeshIngressControlFrame, MeshIngressControlReceiver,
};
use codewire_local_vmm::mesh_process::{
    MESH_TRANSPORT_BOOTSTRAP_FD, MESH_TRANSPORT_CONFINE_MESSAGE, MESH_TRANSPORT_CONFINED_MESSAGE,
    MESH_TRANSPORT_ENROLLMENT_FD, MESH_TRANSPORT_PREPARED_MESSAGE, MESH_TRANSPORT_READY_MESSAGE,
    encode_mesh_transport_bootstrap,
};
use codewire_local_vmm::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, WORKER_BROKER_READY_MESSAGE,
    WORKER_PREPARED_MESSAGE, WORKER_READY_MESSAGE, WORKER_STATUS_MAX_BYTES,
    encode_product_worker_bootstrap, encode_worker_bootstrap,
};
use codewire_vmm_guest_probe::{
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
    NetworkHostReady, NetworkKey,
};
use uuid::Uuid;

const BROKER_DESCRIPTOR_MARKER: u8 = b'B';
const NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const HOST_PORT_DESCRIPTOR_MARKER: u8 = b'P';
const MESH_INGRESS_DESCRIPTOR_MARKER: u8 = b'M';
const CONTROL_BYTES: usize = 64;
/// How long these tests wait on a child process before calling it hung. No
/// test here is about the wait itself: five seconds was missed on a starved
/// CI guest, where a worker took longer than that to write its status frame
/// (#4144, run 42486), so the guard is far above any healthy run.
const HANG_GUARD: Duration = Duration::from_secs(60);

#[repr(C)]
union ControlBuffer {
    alignment: libc::cmsghdr,
    bytes: [u8; CONTROL_BYTES],
}

struct ChildGuard(Child);

impl ChildGuard {
    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + HANG_GUARD;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "isolated network process {} did not terminate",
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

#[test]
fn confined_fixture_worker_completes_the_two_phase_authenticated_bootstrap() {
    let directory = tempfile::tempdir().unwrap();
    let (mut bootstrap_parent, bootstrap_child) = std::os::unix::net::UnixStream::pair().unwrap();
    bootstrap_parent.set_read_timeout(Some(HANG_GUARD)).unwrap();
    bootstrap_parent
        .set_write_timeout(Some(HANG_GUARD))
        .unwrap();

    let vm_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let generation = 9_u64;
    let token = "worker-process-test-token-0123456789abcdef";
    let key = NetworkKey::derive(token, vm_id, generation).unwrap();
    let bootstrap = encode_worker_bootstrap(vm_id, generation, &key).unwrap();
    let source = bootstrap_child.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    command
        .arg("__native-network-worker-fixture")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this child hook uses only async-signal-safe descriptor syscalls
    // and returns before the worker executable observes process state.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if source != NETWORK_BOOTSTRAP_FD && libc::dup2(source, NETWORK_BOOTSTRAP_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(NETWORK_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let mut child = ChildGuard(child);
    drop(bootstrap_child);

    bootstrap_parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap_parent),
        WORKER_PREPARED_MESSAGE
    );

    let (mut guest, worker_network) = std::os::unix::net::UnixStream::pair().unwrap();
    guest.set_read_timeout(Some(HANG_GUARD)).unwrap();
    guest.set_write_timeout(Some(HANG_GUARD)).unwrap();
    send_descriptor(
        bootstrap_parent.as_raw_fd(),
        worker_network.as_raw_fd(),
        NETWORK_DESCRIPTOR_MARKER,
    );
    drop(worker_network);

    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    if let Err(error) = guest.read_exact(&mut hello) {
        let status_frame = read_status_frame_result(&mut bootstrap_parent);
        let exit = child.0.wait().unwrap();
        panic!(
            "worker closed before hello: {error}; status={status_frame:?}; exit={:?}",
            exit.code()
        );
    }
    let hello = NetworkHostHello::decode(&hello, &key, vm_id, generation).unwrap();
    guest
        .write_all(&NetworkGuestAck::new(hello.nonce).unwrap().encode(&key))
        .unwrap();
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    guest.read_exact(&mut ready).unwrap();
    NetworkHostReady::decode(&ready, &key, &hello.nonce).unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap_parent),
        WORKER_READY_MESSAGE
    );
    let mut trailing = [0_u8; 1];
    assert_eq!(
        bootstrap_parent.read(&mut trailing).unwrap(),
        0,
        "fixture worker retained its bootstrap capability after readiness"
    );
    let descriptors = std::fs::read_dir(format!("/proc/{}/fd", child.0.id()))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read_link(entry.path()).unwrap())
        })
        .collect::<Vec<_>>();
    let sockets = descriptors
        .iter()
        .filter(|(_, target)| target.to_string_lossy().starts_with("socket:"))
        .collect::<Vec<_>>();
    let mut socket_inodes = BTreeMap::<u64, usize>::new();
    for (_, target) in &sockets {
        let target = target.to_string_lossy();
        let inode = target
            .strip_prefix("socket:[")
            .and_then(|target| target.strip_suffix(']'))
            .and_then(|target| target.parse().ok())
            .expect("worker socket descriptor target is malformed");
        *socket_inodes.entry(inode).or_default() += 1;
    }
    let mut multiplicity = socket_inodes.values().copied().collect::<Vec<_>>();
    multiplicity.sort_unstable();
    assert_eq!(
        sockets.len(),
        4,
        "confined product worker descriptors: {descriptors:?}"
    );
    assert_eq!(multiplicity, [1, 1, 2]);

    drop(guest);
    let status = child.0.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(NetworkWorkerStartupFailure::FrameIo.exit_code())
    );
}

#[test]
fn confined_product_worker_authenticates_the_separate_broker_capability() {
    let directory = tempfile::tempdir().unwrap();
    let vm_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let generation = 9_u64;
    let broker_key = [0x5a; BROKER_IPC_KEY_LEN];

    let (mut broker_parent, broker_child_socket) = std::os::unix::net::UnixStream::pair().unwrap();
    broker_parent.set_read_timeout(Some(HANG_GUARD)).unwrap();
    broker_parent.set_write_timeout(Some(HANG_GUARD)).unwrap();
    let broker_source = broker_child_socket.as_raw_fd();
    let mut broker_command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    broker_command
        .arg("__native-egress-broker")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The broker also takes the runner's host-address control socket (#2614)
    // and its IPC sessions after the admission session (#2638).
    let (mut _host_address_control, control_child_socket) =
        std::os::unix::net::UnixStream::pair().unwrap();
    let mut high = vec![
        (
            duplicate_above_targets(broker_source),
            EGRESS_BROKER_BOOTSTRAP_FD,
        ),
        (
            duplicate_above_targets(control_child_socket.as_raw_fd()),
            EGRESS_BROKER_HOST_ADDRESSES_FD,
        ),
    ];
    let mut broker_sessions = Vec::new();
    for index in 0..EGRESS_BROKER_INHERITED_SESSIONS {
        let (worker_end, broker_end) = std::os::unix::net::UnixStream::pair().unwrap();
        high.push((
            duplicate_above_targets(broker_end.as_raw_fd()),
            EGRESS_BROKER_FIRST_SESSION_FD + index as RawFd,
        ));
        broker_sessions.push(worker_end);
    }
    prepare_inherited_descriptors(
        &mut broker_command,
        high.iter()
            .map(|(source, target)| (source.as_raw_fd(), *target))
            .collect(),
    );
    let mut broker = ChildGuard(broker_command.spawn().unwrap());
    drop(broker_child_socket);
    drop(control_child_socket);
    drop(high);
    _host_address_control
        .write_all(&encode_frame(&HostAddressSet::default()))
        .unwrap();
    let broker_bootstrap = encode_egress_broker_bootstrap(
        vm_id,
        generation,
        &broker_key,
        &codewire_egress_policy::CompiledPolicy::developer_baseline(),
    )
    .unwrap();
    broker_parent.write_all(broker_bootstrap.as_ref()).unwrap();
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

    let (mut worker_parent, worker_child_socket) = std::os::unix::net::UnixStream::pair().unwrap();
    worker_parent.set_read_timeout(Some(HANG_GUARD)).unwrap();
    worker_parent.set_write_timeout(Some(HANG_GUARD)).unwrap();
    let token = "product-worker-process-test-token-0123456789abcdef";
    let network_key = NetworkKey::derive(token, vm_id, generation).unwrap();
    let host_port_key = [0x7b; HOST_PORT_CONTROL_KEY_LEN];
    let mesh_ingress_key = [0x4d; MESH_INGRESS_CONTROL_KEY_LEN];
    let mesh_ingress_port = 3_001;
    let worker_bootstrap = encode_product_worker_bootstrap(
        vm_id,
        generation,
        &network_key,
        &broker_key,
        &host_port_key,
        &mesh_ingress_key,
        &[mesh_ingress_port],
        codewire_egress_policy::CompiledPolicy::developer_baseline().digest(),
    )
    .unwrap();
    let worker_source = worker_child_socket.as_raw_fd();
    let mut worker_command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    worker_command
        .arg("__native-network-worker")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    prepare_inherited_descriptor(&mut worker_command, worker_source, NETWORK_BOOTSTRAP_FD);
    let mut worker = ChildGuard(worker_command.spawn().unwrap());
    drop(worker_child_socket);

    worker_parent.write_all(worker_bootstrap.as_ref()).unwrap();
    assert_eq!(
        read_status_frame(&mut worker_parent),
        WORKER_PREPARED_MESSAGE
    );
    // The admission session (the broker's bootstrap stream), then the rest.
    for session in std::iter::once(&broker_parent).chain(&broker_sessions) {
        send_descriptor(
            worker_parent.as_raw_fd(),
            session.as_raw_fd(),
            BROKER_DESCRIPTOR_MARKER,
        );
    }
    drop(broker_parent);
    drop(broker_sessions);
    assert_eq!(
        read_status_frame(&mut worker_parent),
        WORKER_BROKER_READY_MESSAGE
    );

    let (mut guest, worker_network) = std::os::unix::net::UnixStream::pair().unwrap();
    guest.set_read_timeout(Some(HANG_GUARD)).unwrap();
    guest.set_write_timeout(Some(HANG_GUARD)).unwrap();
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
    let ready_status = read_status_frame_result(&mut worker_parent);
    if let Err(error) = ready_status {
        let exit = worker.wait_bounded();
        panic!(
            "product worker closed before ready status: {error}; exit={:?}",
            exit.code()
        );
    }
    assert_eq!(ready_status.unwrap(), WORKER_READY_MESSAGE);

    // The confined broker takes a new policy on its control channel and
    // acknowledges the digest it enforces from then on (#2537).
    let locked = codewire_egress_policy::CompiledPolicy::locked();
    _host_address_control
        .set_read_timeout(Some(HANG_GUARD))
        .unwrap();
    _host_address_control
        .write_all(&codewire_local_vmm::broker_control::encode_policy_frame(&locked).unwrap())
        .unwrap();
    let mut ack = [0_u8; 37];
    _host_address_control.read_exact(&mut ack).unwrap();
    let enforced = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(codewire_local_vmm::broker_control::read_policy_ack(
            &mut ack.as_slice(),
        ))
        .unwrap();
    assert_eq!(enforced, locked.digest());

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let mut host_client = std::net::TcpStream::connect(address).unwrap();
    host_client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    assert!(peer.ip().is_loopback());
    let binding = HostPortBinding::new(address.port(), 3_000).unwrap();
    let frame =
        HostPortControlFrame::encode(vm_id, generation, 1, binding, &host_port_key).unwrap();
    worker_parent.write_all(&frame).unwrap();
    send_descriptor(
        worker_parent.as_raw_fd(),
        accepted.as_raw_fd(),
        HOST_PORT_DESCRIPTOR_MARKER,
    );
    drop(accepted);
    std::thread::sleep(Duration::from_millis(100));
    if let Some(status) = worker.0.try_wait().unwrap() {
        panic!(
            "confined product worker rejected host-port control before payload: exit={:?}",
            status.code()
        );
    }
    host_client
        .write_all(b"host-port-process-boundary")
        .unwrap();
    let mut byte = [0_u8; 1];
    let read = host_client.read(&mut byte);
    if !read.as_ref().is_err_and(|error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    }) {
        let status = worker.wait_bounded();
        panic!(
            "confined product worker rejected the transferred host-port stream: {read:?}; exit={:?}",
            status.code()
        );
    }
    assert!(worker.0.try_wait().unwrap().is_none());

    let (mut mesh_peer, mesh_bridge) = std::os::unix::net::UnixStream::pair().unwrap();
    let mesh_frame = MeshIngressControlFrame::encode(
        vm_id,
        generation,
        1,
        MeshIngressBinding::new(mesh_ingress_port).unwrap(),
        &mesh_ingress_key,
    )
    .unwrap();
    worker_parent.write_all(&mesh_frame).unwrap();
    send_descriptor(
        worker_parent.as_raw_fd(),
        mesh_bridge.as_raw_fd(),
        MESH_INGRESS_DESCRIPTOR_MARKER,
    );
    drop(mesh_bridge);
    mesh_peer.write_all(b"mesh-process-boundary").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(worker.0.try_wait().unwrap().is_none());

    drop(guest);
    // The worker ends its host session when the guest goes, which closes its
    // broker sessions and so ends the broker.
    let broker_status = broker.wait_bounded();
    assert_eq!(
        broker_status.code(),
        Some(EgressBrokerStartupFailure::Protocol.exit_code())
    );
    // Then the worker waits, for at most its handshake timeout, for the
    // runner to close the control socket. A real stop closes it first; left
    // open here, the worker would exit two seconds later (#4147).
    drop(worker_parent);
    let worker_status = worker.wait_bounded();
    assert_eq!(
        worker_status.code(),
        Some(NetworkWorkerStartupFailure::FrameIo.exit_code())
    );
}

#[test]
fn confined_mesh_fixture_completes_runner_handshake_and_stream_transfer() {
    const REQUEST: &[u8] = b"CWMESH1 host";
    const RESPONSE: &[u8] = b"CWMESH1 guest";
    const ACKNOWLEDGEMENT: &[u8] = b"CWMESH1 ack";

    let directory = tempfile::tempdir().unwrap();
    let vm_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let generation = 9_u64;
    let guest_port = 3_001;
    let submission_key = [0x6d; MESH_INGRESS_CONTROL_KEY_LEN];
    let attachment = MeshAttachment::new(
        "http://127.0.0.1:1",
        "org-qualified-smoke",
        "network-qualified-smoke",
        "native-qualified-smoke",
        [guest_port],
    )
    .unwrap();

    let (mut transport_control, transport_control_child) =
        std::os::unix::net::UnixStream::pair().unwrap();
    let (mut enrollment_control, enrollment_control_child) =
        std::os::unix::net::UnixStream::pair().unwrap();
    let (enrollment_transfer, transport_enrollment) =
        std::os::unix::net::UnixStream::pair().unwrap();
    for stream in [&transport_control, &enrollment_control] {
        stream.set_read_timeout(Some(HANG_GUARD)).unwrap();
        stream.set_write_timeout(Some(HANG_GUARD)).unwrap();
    }

    let mut transport_command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    transport_command
        .arg("__native-mesh-transport")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let transport_control_source = duplicate_high_fd(transport_control_child.as_raw_fd());
    let transport_enrollment_source = duplicate_high_fd(transport_enrollment.as_raw_fd());
    prepare_inherited_descriptor_pair(
        &mut transport_command,
        transport_control_source.as_raw_fd(),
        MESH_TRANSPORT_BOOTSTRAP_FD,
        transport_enrollment_source.as_raw_fd(),
        MESH_TRANSPORT_ENROLLMENT_FD,
    );
    let mut transport = ChildGuard(transport_command.spawn().unwrap());
    drop(transport_control_source);
    drop(transport_enrollment_source);
    drop(transport_control_child);
    drop(transport_enrollment);

    let mut enrollment_command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    enrollment_command
        .arg("__native-mesh-enrollment-broker")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .arg("--mesh-data-dir")
        .arg(directory.path())
        .arg("--platform-config-dir")
        .arg(directory.path())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let enrollment_control_source = duplicate_high_fd(enrollment_control_child.as_raw_fd());
    let enrollment_transfer_source = duplicate_high_fd(enrollment_transfer.as_raw_fd());
    prepare_inherited_descriptor_pair(
        &mut enrollment_command,
        enrollment_control_source.as_raw_fd(),
        MESH_ENROLLMENT_BOOTSTRAP_FD,
        enrollment_transfer_source.as_raw_fd(),
        MESH_ENROLLMENT_TRANSFER_FD,
    );
    let mut enrollment = ChildGuard(enrollment_command.spawn().unwrap());
    drop(enrollment_control_source);
    drop(enrollment_transfer_source);
    drop(enrollment_control_child);
    drop(enrollment_transfer);

    let transport_bootstrap =
        encode_mesh_transport_bootstrap(vm_id, generation, &attachment, &submission_key).unwrap();
    transport_control
        .write_all(transport_bootstrap.as_ref())
        .unwrap();
    assert_eq!(
        read_status_frame(&mut transport_control),
        MESH_TRANSPORT_PREPARED_MESSAGE
    );

    let enrollment_bootstrap =
        encode_mesh_enrollment_bootstrap(vm_id, generation, &attachment).unwrap();
    enrollment_control.write_all(&enrollment_bootstrap).unwrap();
    assert_eq!(
        read_status_frame(&mut enrollment_control),
        MESH_ENROLLMENT_PREPARED_MESSAGE
    );

    transport_control
        .write_all(MESH_TRANSPORT_CONFINE_MESSAGE)
        .unwrap();
    assert_eq!(
        read_status_frame(&mut transport_control),
        MESH_TRANSPORT_CONFINED_MESSAGE
    );
    enrollment_control
        .write_all(MESH_ENROLLMENT_CONFINE_MESSAGE)
        .unwrap();
    assert_eq!(
        read_status_frame(&mut enrollment_control),
        MESH_ENROLLMENT_READY_MESSAGE
    );
    assert!(enrollment.wait_bounded().success());
    assert_eq!(
        read_status_frame(&mut transport_control),
        MESH_TRANSPORT_READY_MESSAGE
    );

    let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
    transport_control.read_exact(&mut frame).unwrap();
    let decoded = MeshIngressControlReceiver::new(vm_id, generation, &[guest_port])
        .unwrap()
        .decode(&frame, &submission_key)
        .unwrap();
    assert_eq!(decoded.binding.guest_port, guest_port);
    let descriptor = receive_descriptor(
        transport_control.as_raw_fd(),
        MESH_INGRESS_DESCRIPTOR_MARKER,
    );
    let mut stream = std::os::unix::net::UnixStream::from(descriptor);
    stream.set_read_timeout(Some(HANG_GUARD)).unwrap();
    stream.set_write_timeout(Some(HANG_GUARD)).unwrap();
    let mut request = [0_u8; REQUEST.len()];
    stream.read_exact(&mut request).unwrap();
    assert_eq!(&request, REQUEST);
    stream.write_all(RESPONSE).unwrap();
    let mut acknowledgement = [0_u8; ACKNOWLEDGEMENT.len()];
    stream.read_exact(&mut acknowledgement).unwrap();
    assert_eq!(&acknowledgement, ACKNOWLEDGEMENT);

    drop(stream);
    drop(transport_control);
    assert!(transport.wait_bounded().success());
}

fn prepare_inherited_descriptor(command: &mut Command, source: RawFd, target: RawFd) {
    // SAFETY: the hook performs only descriptor syscalls before exec and
    // admits exactly one connected bootstrap capability at the fixed fd.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if source != target && libc::dup2(source, target) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// A duplicate above every fixed target a role inherits, as the runner makes.
fn duplicate_above_targets(source: RawFd) -> OwnedFd {
    let duplicated = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 64) };
    assert!(
        duplicated >= 64,
        "could not duplicate inherited fixture descriptor"
    );
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

/// Admit exactly `descriptors` at their targets; every source is above them.
fn prepare_inherited_descriptors(command: &mut Command, descriptors: Vec<(RawFd, RawFd)>) {
    assert!(descriptors.iter().all(|(source, _)| *source >= 64));
    // SAFETY: the sources are kept alive through spawn and sit above every
    // target. The hook performs only descriptor syscalls before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for &(source, target) in &descriptors {
                if libc::dup2(source, target) == -1 || libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn duplicate_high_fd(source: RawFd) -> OwnedFd {
    let duplicated = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 10) };
    assert!(
        duplicated >= 10,
        "could not duplicate inherited fixture descriptor"
    );
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

fn prepare_inherited_descriptor_pair(
    command: &mut Command,
    first_source: RawFd,
    first_target: RawFd,
    second_source: RawFd,
    second_target: RawFd,
) {
    assert_ne!(first_source, second_source);
    assert_ne!(first_target, second_target);
    assert!(first_source >= 10 && second_source >= 10);
    // SAFETY: both sources are collision-free high descriptors kept alive
    // through spawn. The hook performs only descriptor syscalls before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for (source, target) in [(first_source, first_target), (second_source, second_target)] {
                if libc::dup2(source, target) == -1 || libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn read_status_frame(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    read_status_frame_result(stream)
        .unwrap_or_else(|error| panic!("no status frame within the hang guard: {error}"))
}

fn read_status_frame_result(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(WORKER_STATUS_MAX_BYTES);
    loop {
        assert!(frame.len() < WORKER_STATUS_MAX_BYTES);
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
    }
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
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    assert!(control_space <= CONTROL_BYTES);
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
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }
    assert_eq!(
        unsafe { libc::sendmsg(bootstrap, &raw const message, libc::MSG_NOSIGNAL) },
        marker.len() as isize
    );
}

fn receive_descriptor(control_fd: RawFd, expected_marker: u8) -> OwnedFd {
    let mut marker = [0_u8];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let mut control = ControlBuffer {
        bytes: [0_u8; CONTROL_BYTES],
    };
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    assert!(control_space <= CONTROL_BYTES);
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = control_space;
    assert_eq!(
        unsafe { libc::recvmsg(control_fd, &raw mut message, libc::MSG_CMSG_CLOEXEC) },
        marker.len() as isize
    );
    assert_eq!(marker[0], expected_marker);
    assert_eq!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC), 0);
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    assert!(!header.is_null());
    assert_eq!(unsafe { (*header).cmsg_level }, libc::SOL_SOCKET);
    assert_eq!(unsafe { (*header).cmsg_type }, libc::SCM_RIGHTS);
    assert_eq!(unsafe { (*header).cmsg_len }, unsafe {
        libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize
    });
    assert!(unsafe { libc::CMSG_NXTHDR(&raw const message, header) }.is_null());
    let descriptor = unsafe { std::ptr::read(libc::CMSG_DATA(header).cast::<RawFd>()) };
    assert!(descriptor >= 0);
    assert_ne!(
        unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}
