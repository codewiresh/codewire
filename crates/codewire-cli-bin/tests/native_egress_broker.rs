#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use codewire_egress_broker::ipc::{
    BrokerIpcBinding, BrokerIpcClient, BrokerIpcError, BrokerIpcKey,
};
use codewire_egress_policy::CompiledPolicy;
use codewire_local_vmm::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_HOST_ADDRESSES_FD,
    EGRESS_BROKER_POLICY_DIGEST_OFFSET, EGRESS_BROKER_PREPARED_MESSAGE,
    EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES, EgressBrokerStartupFailure,
    EgressBrokerStartupStatus, decode_egress_broker_startup_status,
    encode_developer_egress_broker_bootstrap,
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

/// The broker's bootstrap and host-address control sockets (runner ends) and
/// the broker, which has been sent `host_addresses` as its first control frame.
fn spawn_broker(
    ambient_environment: bool,
    host_addresses: &[u8],
) -> (
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
    ChildGuard,
) {
    let (parent, child_socket) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut control, control_child) = std::os::unix::net::UnixStream::pair().unwrap();
    let control_source = control_child.as_raw_fd();
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (environment_id, generation) = identity();
    let source = child_socket.as_raw_fd();
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
    // admits exactly the connected bootstrap and host-address control
    // capabilities at their fixed fds; both sources are well above them.
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
            for (source, target) in [
                (source, EGRESS_BROKER_BOOTSTRAP_FD),
                (control_source, EGRESS_BROKER_HOST_ADDRESSES_FD),
            ] {
                if source != target && libc::dup2(source, target) == -1 {
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
    drop(child_socket);
    drop(control_child);
    control.write_all(host_addresses).unwrap();
    (parent, control, ChildGuard(Some(child)))
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
    let (ambient_parent, _control, mut ambient_child) = spawn_broker(true, &no_host_addresses());
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
    let mut invalid =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    invalid[0] ^= 1;
    let (mut invalid_parent, _control, mut invalid_child) =
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
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    wrong_policy[EGRESS_BROKER_POLICY_DIGEST_OFFSET] ^= 1;
    let (mut policy_parent, _control, mut policy_child) = spawn_broker(false, &no_host_addresses());
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

    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut admission_parent, _control, mut admission_child) =
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
fn a_broker_without_readable_host_addresses_fails_closed_before_ready() {
    let (environment_id, generation) = identity();
    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let mut malformed = no_host_addresses();
    malformed[0] ^= 1;
    let (mut parent, _control, mut child) = spawn_broker(false, &malformed);
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
    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let initial = encode_frame(&HostAddressSet::new([host], [public]).unwrap());
    let (mut parent, mut control, mut child) = spawn_broker(false, &initial);
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);

    parent.set_read_timeout(None).unwrap();
    parent.set_write_timeout(None).unwrap();
    parent.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        let policy = CompiledPolicy::developer_baseline();
        let binding = BrokerIpcBinding::new(environment_id, generation, policy.digest()).unwrap();
        let key = BrokerIpcKey::from_bytes(TEST_KEY).unwrap();
        let client = BrokerIpcClient::new(
            tokio::net::UnixStream::from_std(parent).unwrap(),
            binding,
            key,
        );
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
    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut parent, _control, mut child) = spawn_broker(false, &no_host_addresses());
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);

    parent.set_read_timeout(None).unwrap();
    parent.set_write_timeout(None).unwrap();
    parent.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let policy = CompiledPolicy::developer_baseline();
        let binding = BrokerIpcBinding::new(environment_id, generation, policy.digest()).unwrap();
        let key = BrokerIpcKey::from_bytes(TEST_KEY).unwrap();
        let client = BrokerIpcClient::new(
            tokio::net::UnixStream::from_std(parent).unwrap(),
            binding,
            key,
        );
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
    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut parent, _control, _child) = spawn_broker(false, host_addresses);
    parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_PREPARED_MESSAGE);
    parent.write_all(EGRESS_BROKER_CONFINE_MESSAGE).unwrap();
    assert_eq!(read_status_frame(&parent), EGRESS_BROKER_READY_MESSAGE);
    parent.set_read_timeout(None).unwrap();
    parent.set_write_timeout(None).unwrap();
    parent.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let policy = CompiledPolicy::developer_baseline();
        let binding = BrokerIpcBinding::new(environment_id, generation, policy.digest()).unwrap();
        let client = BrokerIpcClient::new(
            tokio::net::UnixStream::from_std(parent).unwrap(),
            binding,
            BrokerIpcKey::from_bytes(TEST_KEY).unwrap(),
        );
        client.connect_tcp(destination).await
    })
}

/// #2614 against a real interface. Run it in a network namespace whose
/// interface holds the public address named by `CODEWIRE_TEST_HOST_ADDRESS`
/// (the loopback interface must be up), with `--ignored`.
///
/// A broker that does not know the host's addresses dials a listener on that
/// address. Sent the addresses exactly as the runner reads them, it refuses.
#[test]
#[ignore = "needs a network namespace with a public interface address"]
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
