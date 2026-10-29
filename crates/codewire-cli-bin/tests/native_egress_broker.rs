#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use codewire_egress_broker::ipc::{
    BrokerIpcBinding, BrokerIpcClient, BrokerIpcError, BrokerIpcKey,
};
use codewire_egress_policy::CompiledPolicy;
use codewire_local_vmm::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_FIRST_SESSION_FD,
    EGRESS_BROKER_HOST_ADDRESSES_FD, EGRESS_BROKER_INHERITED_SESSIONS,
    EGRESS_BROKER_POLICY_DIGEST_OFFSET, EGRESS_BROKER_PREPARED_MESSAGE,
    EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES, EgressBrokerStartupFailure,
    EgressBrokerStartupStatus, decode_egress_broker_startup_status, encode_egress_broker_bootstrap,
};
use codewire_local_vmm::host_addresses::{
    HostAddressMonitor, HostAddressSet, SystemHostAddressSource, encode_frame,
};
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0x5a; 32];

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "egress broker process {} did not terminate",
                self.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn identity() -> (Uuid, u64) {
    (
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        9,
    )
}

/// The runner's ends of a spawned broker: its bootstrap stream (the
/// admission session once ready), its other IPC sessions and its host-address
/// control socket, which has been sent `host_addresses` as its first frame.
fn spawn_broker(
    ambient_environment: bool,
    host_addresses: &[u8],
) -> (StdUnixStream, Vec<StdUnixStream>, StdUnixStream, ChildGuard) {
    spawn_broker_with_sessions(
        ambient_environment,
        host_addresses,
        EGRESS_BROKER_INHERITED_SESSIONS,
    )
}

/// Every source is duplicated above all fixed targets, as the runner does.
fn above_targets(descriptor: &impl std::os::fd::AsRawFd) -> OwnedFd {
    let duplicated = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    assert!(duplicated >= 64);
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

fn spawn_broker_with_sessions(
    ambient_environment: bool,
    host_addresses: &[u8],
    inherited_sessions: usize,
) -> (StdUnixStream, Vec<StdUnixStream>, StdUnixStream, ChildGuard) {
    let (parent, child_socket) = StdUnixStream::pair().unwrap();
    let (mut control, control_child) = StdUnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut sessions = Vec::new();
    let mut inherited = vec![above_targets(&child_socket), above_targets(&control_child)];
    for _ in 0..inherited_sessions {
        let (worker_end, broker_end) = StdUnixStream::pair().unwrap();
        inherited.push(above_targets(&broker_end));
        sessions.push(worker_end);
    }
    let targets = [EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_HOST_ADDRESSES_FD]
        .into_iter()
        .chain((0..inherited_sessions).map(|index| EGRESS_BROKER_FIRST_SESSION_FD + index as i32));
    let descriptors: Vec<(i32, i32)> = inherited
        .iter()
        .map(|descriptor| descriptor.as_raw_fd())
        .zip(targets)
        .collect();
    let (environment_id, generation) = identity();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-egress-broker")
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if ambient_environment {
        command.env("CODEWIRE_FORGED_BROKER_ENVIRONMENT", "rejected");
    }
    // SAFETY: the hook performs only descriptor syscalls before exec. It
    // admits exactly the connected bootstrap, host-address control and IPC
    // session capabilities at their fixed fds; every source is above them.
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
                if libc::dup2(source, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(inherited);
    drop(child_socket);
    drop(control_child);
    control.write_all(host_addresses).unwrap();
    (parent, sessions, control, ChildGuard(Some(child)))
}

/// A client over every session of a ready broker. Call it in a runtime.
fn ipc_client(parent: StdUnixStream, sessions: Vec<StdUnixStream>) -> BrokerIpcClient {
    let (environment_id, generation) = identity();
    let policy = CompiledPolicy::developer_baseline();
    let binding = BrokerIpcBinding::new(environment_id, generation, policy.digest()).unwrap();
    parent.set_read_timeout(None).unwrap();
    parent.set_write_timeout(None).unwrap();
    let streams = std::iter::once(parent)
        .chain(sessions)
        .map(|stream| {
            stream.set_nonblocking(true).unwrap();
            tokio::net::UnixStream::from_std(stream).unwrap()
        })
        .collect();
    BrokerIpcClient::new(
        streams,
        binding,
        BrokerIpcKey::from_bytes(TEST_KEY).unwrap(),
    )
    .unwrap()
}

fn no_host_addresses() -> Vec<u8> {
    encode_frame(&HostAddressSet::default())
}

#[test]
fn cw_hidden_egress_broker_preserves_its_typed_failure_exit() {
    let invalid_bootstrap = File::open("/dev/null").unwrap();
    let source = invalid_bootstrap.as_raw_fd();
    let (environment_id, generation) = identity();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-egress-broker")
        .arg("--environment-id")
        .arg(environment_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook deliberately installs a non-socket fixture at fd 4.
    unsafe {
        command.pre_exec(move || {
            if source != EGRESS_BROKER_BOOTSTRAP_FD
                && libc::dup2(source, EGRESS_BROKER_BOOTSTRAP_FD) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(EGRESS_BROKER_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().unwrap();
    assert_eq!(
        status.code(),
        Some(EgressBrokerStartupFailure::InheritedDescriptor.exit_code())
    );
}

#[test]
fn product_broker_rejects_ambient_environment_bootstrap_policy_and_admission_forgery() {
    let (ambient_parent, _sessions, _control, mut ambient_child) =
        spawn_broker(true, &no_host_addresses());
    assert_eq!(
        decode_egress_broker_startup_status(&read_status_frame(&ambient_parent)),
        Some(EgressBrokerStartupStatus::Failed(
            EgressBrokerStartupFailure::AmbientEnvironment
        ))
    );
    assert_eq!(
        ambient_child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::AmbientEnvironment.exit_code())
    );

    let (environment_id, generation) = identity();
    let mut invalid = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    invalid[0] ^= 1;
    let (mut invalid_parent, _sessions, _control, mut invalid_child) =
        spawn_broker(false, &no_host_addresses());
    invalid_parent.write_all(invalid.as_ref()).unwrap();
    assert_eq!(
        decode_egress_broker_startup_status(&read_status_frame(&invalid_parent)),
        Some(EgressBrokerStartupStatus::Failed(
            EgressBrokerStartupFailure::InvalidBootstrap
        ))
    );
    assert_eq!(
        invalid_child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::InvalidBootstrap.exit_code())
    );

    let mut wrong_policy =
        developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    wrong_policy[EGRESS_BROKER_POLICY_DIGEST_OFFSET] ^= 1;
    let (mut policy_parent, _sessions, _control, mut policy_child) =
        spawn_broker(false, &no_host_addresses());
    policy_parent.write_all(wrong_policy.as_ref()).unwrap();
    assert_eq!(
        decode_egress_broker_startup_status(&read_status_frame(&policy_parent)),
        Some(EgressBrokerStartupStatus::Failed(
            EgressBrokerStartupFailure::PolicyMismatch
        ))
    );
    assert_eq!(
        policy_child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::PolicyMismatch.exit_code())
    );

    let bootstrap = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut admission_parent, _sessions, _control, mut admission_child) =
        spawn_broker(false, &no_host_addresses());
    admission_parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(
        read_status_frame(&admission_parent),
        EGRESS_BROKER_PREPARED_MESSAGE
    );
    let mut forged_admission = EGRESS_BROKER_CONFINE_MESSAGE.to_vec();
    forged_admission[0] ^= 1;
    admission_parent.write_all(&forged_admission).unwrap();
    assert_eq!(
        decode_egress_broker_startup_status(&read_status_frame(&admission_parent)),
        Some(EgressBrokerStartupStatus::Failed(
            EgressBrokerStartupFailure::Protocol
        ))
    );
    assert_eq!(
        admission_child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::Protocol.exit_code())
    );
}

#[test]
fn a_broker_missing_an_ipc_session_refuses_to_start() {
    let (_parent, _sessions, _control, mut child) = spawn_broker_with_sessions(
        false,
        &no_host_addresses(),
        EGRESS_BROKER_INHERITED_SESSIONS - 1,
    );
    assert_eq!(
        child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::InheritedDescriptor.exit_code())
    );
}

#[test]
fn a_broker_without_readable_host_addresses_fails_closed_before_ready() {
    let (environment_id, generation) = identity();
    let bootstrap = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let mut malformed = no_host_addresses();
    malformed[0] ^= 1;
    let (mut parent, _sessions, _control, mut child) = spawn_broker(false, &malformed);
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(
        decode_egress_broker_startup_status(&read_status_frame(&parent)),
        Some(EgressBrokerStartupStatus::Failed(
            EgressBrokerStartupFailure::HostAddresses
        ))
    );
    assert_eq!(
        child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::HostAddresses.exit_code())
    );
}

#[test]
fn confined_product_broker_refuses_host_addresses_and_fails_closed_without_their_control() {
    // #2614: the host's own addresses arrive before ready and are refused like
    // private ones; an update replaces them; losing the runner's control
    // socket ends the broker.
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 114, 7));
    let public = IpAddr::V4(Ipv4Addr::new(87, 0, 0, 180));
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let (environment_id, generation) = identity();
    let bootstrap = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let initial = encode_frame(&HostAddressSet::new([host], [public]).unwrap());
    let (mut parent, sessions, mut control, mut child) = spawn_broker(false, &initial);
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        let client = ipc_client(parent, sessions);
        for refused in [SocketAddr::new(host, 22), SocketAddr::new(public, 443)] {
            assert_eq!(
                client.authorize_tcp(refused).await,
                Err(BrokerIpcError::Denied)
            );
        }
        assert!(client.authorize_tcp(other).await.is_ok());
        client
    });
    control
        .write_all(&encode_frame(
            &HostAddressSet::new([host], [public, other.ip()]).unwrap(),
        ))
        .unwrap();
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.authorize_tcp(other).await.is_ok() {
            assert!(
                Instant::now() < deadline,
                "the host-address update was not applied"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    drop(control);
    assert_eq!(
        child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::HostAddresses.exit_code())
    );
    drop(client);
    drop(runtime);
}

#[test]
fn confined_product_broker_serves_authenticated_policy_and_closes_with_its_capability() {
    let (environment_id, generation) = identity();
    let bootstrap = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut parent, sessions, _control, mut child) = spawn_broker(false, &no_host_addresses());
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let client = ipc_client(parent, sessions);
        // Every session, admission, DNS and connect, answers the confined
        // broker with its own key (#2638).
        client.verify_sessions().await.unwrap();
        assert_eq!(
            client
                .authorize_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443))
                .await,
            Err(BrokerIpcError::Denied)
        );
    });
    drop(runtime);

    assert_eq!(
        child.wait_bounded().code(),
        Some(EgressBrokerStartupFailure::Protocol.exit_code())
    );
}

/// One `connect_tcp` through a confined broker that was sent `host_addresses`.
fn connect_through_broker(
    host_addresses: &[u8],
    destination: SocketAddr,
) -> Result<std::os::fd::OwnedFd, BrokerIpcError> {
    let (environment_id, generation) = identity();
    let bootstrap = developer_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut parent, sessions, _control, _child) = spawn_broker(false, host_addresses);
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async move { ipc_client(parent, sessions).connect_tcp(destination).await })
}

/// #2614 against a real interface. Run it in a network namespace whose
/// interface holds the public address named by `CODEWIRE_TEST_HOST_ADDRESS`
/// (the loopback interface must be up), with `--ignored`.
///
/// A broker that does not know the host's addresses dials a listener on that
/// address. Sent the addresses exactly as the runner reads them, it refuses.
#[test]
#[ignore = "needs a network namespace with a public interface address; run it through run-in-public-netns.sh"]
fn a_connection_to_the_hosts_own_interface_address_is_refused() {
    let host: IpAddr = std::env::var("CODEWIRE_TEST_HOST_ADDRESS")
        .expect("CODEWIRE_TEST_HOST_ADDRESS")
        .parse()
        .unwrap();
    let destination = SocketAddr::new(host, 443);
    let listener = std::net::TcpListener::bind(destination).unwrap();
    let (_monitor, addresses) =
        HostAddressMonitor::start(SystemHostAddressSource::from_environment()).unwrap();
    assert!(addresses.interfaces().any(|address| address == host));

    connect_through_broker(&no_host_addresses(), destination).unwrap();
    listener.accept().unwrap();

    assert_eq!(
        connect_through_broker(&encode_frame(&addresses), destination).err(),
        Some(BrokerIpcError::Denied)
    );
    listener.set_nonblocking(true).unwrap();
    assert!(
        listener.accept().is_err(),
        "the refused connection reached the host"
    );
}

fn read_status_frame(stream: &std::os::unix::net::UnixStream) -> Vec<u8> {
    let mut stream = stream;
    let mut frame = Vec::with_capacity(EGRESS_BROKER_STATUS_MAX_BYTES);
    loop {
        assert!(frame.len() < EGRESS_BROKER_STATUS_MAX_BYTES);
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return frame;
        }
    }
}

/// The broker bootstrap the runner writes for the developer baseline policy.
fn developer_broker_bootstrap(
    environment_id: Uuid,
    generation: u64,
    key: &[u8; codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN],
) -> Result<zeroize::Zeroizing<Vec<u8>>, codewire_local_vmm::egress_broker::EgressBrokerProcessError>
{
    encode_egress_broker_bootstrap(
        environment_id,
        generation,
        key,
        &codewire_egress_policy::CompiledPolicy::developer_baseline(),
    )
}
