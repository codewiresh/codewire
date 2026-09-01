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
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE, EGRESS_BROKER_POLICY_DIGEST_OFFSET,
    EGRESS_BROKER_PREPARED_MESSAGE, EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES,
    EgressBrokerStartupFailure, EgressBrokerStartupStatus, decode_egress_broker_startup_status,
    encode_developer_egress_broker_bootstrap,
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

fn spawn_broker(ambient_environment: bool) -> (std::os::unix::net::UnixStream, ChildGuard) {
    let (parent, child_socket) = std::os::unix::net::UnixStream::pair().unwrap();
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
    let child = command.spawn().unwrap();
    drop(child_socket);
    (parent, ChildGuard(Some(child)))
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
    let (ambient_parent, mut ambient_child) = spawn_broker(true);
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
    let (mut invalid_parent, mut invalid_child) = spawn_broker(false);
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
    let (mut policy_parent, mut policy_child) = spawn_broker(false);
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
    let (mut admission_parent, mut admission_child) = spawn_broker(false);
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
fn confined_product_broker_serves_authenticated_policy_and_closes_with_its_capability() {
    let (environment_id, generation) = identity();
    let bootstrap =
        encode_developer_egress_broker_bootstrap(environment_id, generation, &TEST_KEY).unwrap();
    let (mut parent, mut child) = spawn_broker(false);
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
