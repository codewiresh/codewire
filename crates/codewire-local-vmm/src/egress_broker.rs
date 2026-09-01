//! Confined host process for one local environment's general egress policy.
//!
//! The runner supplies one already-connected AF_UNIX stream containing a
//! generation-bound bootstrap record, an exact confinement admission after
//! process capture, and then the authenticated broker IPC. The process accepts
//! no configuration from files or environment variables.

use std::io::{self, Read as _, Write as _};
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use codewire_egress_broker::adapters::{SystemDnsResolver, SystemTcpConnector};
use codewire_egress_broker::ipc::{
    BROKER_IPC_KEY_LEN, BrokerIpcBinding, BrokerIpcKey, serve_broker_ipc,
};
use codewire_egress_broker::{PolicyEgressBroker, SystemBrokerClock};
use codewire_egress_policy::{CompiledPolicy, RouteClass};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::linux::confinement::{
    install_deny_all_filesystem_domain, install_inet_socket_only_syscalls, lock_process_privileges,
    require_single_threaded_process,
};

pub const EGRESS_BROKER_BOOTSTRAP_FD: RawFd = 4;
pub const EGRESS_BROKER_PREPARED_MESSAGE: &[u8] = b"CWEBB1 prepared\n";
pub const EGRESS_BROKER_CONFINE_MESSAGE: &[u8] = b"CWEBB1 confine\n";
pub const EGRESS_BROKER_READY_MESSAGE: &[u8] = b"CWEBB1 ready\n";
pub const EGRESS_BROKER_STATUS_MAX_BYTES: usize = 64;
pub const EGRESS_BROKER_BOOTSTRAP_LEN: usize = 96;
pub const EGRESS_BROKER_POLICY_DIGEST_OFFSET: usize = 32;

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWEBB1\0\0";
const POLICY_DIGEST_LEN: usize = 32;
const POLICY_DIGEST_END: usize = EGRESS_BROKER_POLICY_DIGEST_OFFSET + POLICY_DIGEST_LEN;
const KEY_OFFSET: usize = POLICY_DIGEST_END;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(20);

const BROKER_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socketpair,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_process_madvise,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_reboot,
    libc::SYS_capset,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
    libc::SYS_prctl,
];

#[cfg(target_arch = "x86_64")]
const BROKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const BROKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressBrokerStartupFailure {
    InvalidIdentity,
    InheritedDescriptor,
    AmbientEnvironment,
    ThreadConfinement,
    BootstrapIo,
    InvalidBootstrap,
    PolicyMismatch,
    ResolverInitialization,
    PrivilegeConfinement,
    FilesystemConfinement,
    SyscallConfinement,
    StatusIo,
    Protocol,
}

impl EgressBrokerStartupFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "invalid-identity",
            Self::InheritedDescriptor => "inherited-descriptor",
            Self::AmbientEnvironment => "ambient-environment",
            Self::ThreadConfinement => "thread-confinement",
            Self::BootstrapIo => "bootstrap-io",
            Self::InvalidBootstrap => "invalid-bootstrap",
            Self::PolicyMismatch => "policy-mismatch",
            Self::ResolverInitialization => "resolver-initialization",
            Self::PrivilegeConfinement => "privilege-confinement",
            Self::FilesystemConfinement => "filesystem-confinement",
            Self::SyscallConfinement => "syscall-confinement",
            Self::StatusIo => "status-io",
            Self::Protocol => "protocol",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidIdentity => 60,
            Self::InheritedDescriptor => 61,
            Self::AmbientEnvironment => 62,
            Self::ThreadConfinement => 63,
            Self::BootstrapIo => 64,
            Self::InvalidBootstrap => 65,
            Self::PolicyMismatch => 66,
            Self::ResolverInitialization => 67,
            Self::PrivilegeConfinement => 68,
            Self::FilesystemConfinement => 69,
            Self::SyscallConfinement => 70,
            Self::StatusIo => 71,
            Self::Protocol => 72,
        }
    }

    pub fn from_exit_code(code: i32) -> Option<Self> {
        ALL_FAILURES
            .into_iter()
            .find(|failure| failure.exit_code() == code)
    }

    fn message(self) -> &'static [u8] {
        match self {
            Self::InvalidIdentity => b"CWEBB1 failed-invalid-identity\n",
            Self::InheritedDescriptor => b"CWEBB1 failed-inherited-descriptor\n",
            Self::AmbientEnvironment => b"CWEBB1 failed-ambient-environment\n",
            Self::ThreadConfinement => b"CWEBB1 failed-thread-confinement\n",
            Self::BootstrapIo => b"CWEBB1 failed-bootstrap-io\n",
            Self::InvalidBootstrap => b"CWEBB1 failed-invalid-bootstrap\n",
            Self::PolicyMismatch => b"CWEBB1 failed-policy-mismatch\n",
            Self::ResolverInitialization => b"CWEBB1 failed-resolver-initialization\n",
            Self::PrivilegeConfinement => b"CWEBB1 failed-privilege-confinement\n",
            Self::FilesystemConfinement => b"CWEBB1 failed-filesystem-confinement\n",
            Self::SyscallConfinement => b"CWEBB1 failed-syscall-confinement\n",
            Self::StatusIo => b"CWEBB1 failed-status-io\n",
            Self::Protocol => b"CWEBB1 failed-protocol\n",
        }
    }
}

const ALL_FAILURES: [EgressBrokerStartupFailure; 13] = [
    EgressBrokerStartupFailure::InvalidIdentity,
    EgressBrokerStartupFailure::InheritedDescriptor,
    EgressBrokerStartupFailure::AmbientEnvironment,
    EgressBrokerStartupFailure::ThreadConfinement,
    EgressBrokerStartupFailure::BootstrapIo,
    EgressBrokerStartupFailure::InvalidBootstrap,
    EgressBrokerStartupFailure::PolicyMismatch,
    EgressBrokerStartupFailure::ResolverInitialization,
    EgressBrokerStartupFailure::PrivilegeConfinement,
    EgressBrokerStartupFailure::FilesystemConfinement,
    EgressBrokerStartupFailure::SyscallConfinement,
    EgressBrokerStartupFailure::StatusIo,
    EgressBrokerStartupFailure::Protocol,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressBrokerStartupStatus {
    Ready,
    Failed(EgressBrokerStartupFailure),
}

pub fn decode_egress_broker_startup_status(bytes: &[u8]) -> Option<EgressBrokerStartupStatus> {
    if bytes == EGRESS_BROKER_READY_MESSAGE {
        return Some(EgressBrokerStartupStatus::Ready);
    }
    ALL_FAILURES
        .into_iter()
        .find(|failure| bytes == failure.message())
        .map(EgressBrokerStartupStatus::Failed)
}

#[derive(Debug, thiserror::Error)]
pub enum EgressBrokerProcessError {
    #[error("egress broker identity is invalid")]
    InvalidIdentity,
    #[error("egress broker inherited descriptor is invalid")]
    InheritedDescriptor,
    #[error("egress broker refuses an ambient environment")]
    AmbientEnvironment,
    #[error("egress broker requires an exact single-threaded runtime")]
    ThreadConfinement,
    #[error("egress broker bootstrap I/O failed")]
    BootstrapIo,
    #[error("egress broker bootstrap is invalid")]
    InvalidBootstrap,
    #[error("egress broker bootstrap policy does not match the compiled policy")]
    PolicyMismatch,
    #[error("egress broker system resolver initialization failed")]
    ResolverInitialization,
    #[error("egress broker privilege confinement failed")]
    PrivilegeConfinement,
    #[error("egress broker filesystem confinement failed")]
    FilesystemConfinement,
    #[error("egress broker syscall confinement failed")]
    SyscallConfinement,
    #[error("egress broker startup-status I/O failed")]
    StatusIo,
    #[error("egress broker authenticated protocol failed")]
    Protocol,
}

impl EgressBrokerProcessError {
    pub fn exit_code(&self) -> i32 {
        self.startup_failure().exit_code()
    }

    fn startup_failure(&self) -> EgressBrokerStartupFailure {
        match self {
            Self::InvalidIdentity => EgressBrokerStartupFailure::InvalidIdentity,
            Self::InheritedDescriptor => EgressBrokerStartupFailure::InheritedDescriptor,
            Self::AmbientEnvironment => EgressBrokerStartupFailure::AmbientEnvironment,
            Self::ThreadConfinement => EgressBrokerStartupFailure::ThreadConfinement,
            Self::BootstrapIo => EgressBrokerStartupFailure::BootstrapIo,
            Self::InvalidBootstrap => EgressBrokerStartupFailure::InvalidBootstrap,
            Self::PolicyMismatch => EgressBrokerStartupFailure::PolicyMismatch,
            Self::ResolverInitialization => EgressBrokerStartupFailure::ResolverInitialization,
            Self::PrivilegeConfinement => EgressBrokerStartupFailure::PrivilegeConfinement,
            Self::FilesystemConfinement => EgressBrokerStartupFailure::FilesystemConfinement,
            Self::SyscallConfinement => EgressBrokerStartupFailure::SyscallConfinement,
            Self::StatusIo => EgressBrokerStartupFailure::StatusIo,
            Self::Protocol => EgressBrokerStartupFailure::Protocol,
        }
    }
}

struct Bootstrap {
    binding: BrokerIpcBinding,
    key: BrokerIpcKey,
}

struct PreparedBroker {
    bootstrap: Bootstrap,
    policy: CompiledPolicy,
}

/// Encode the fixed private bootstrap record written by the environment
/// runner. The HMAC key is never accepted through argv, environment, or disk.
pub fn encode_developer_egress_broker_bootstrap(
    environment_id: Uuid,
    generation: u64,
    key: &[u8; BROKER_IPC_KEY_LEN],
) -> Result<Zeroizing<[u8; EGRESS_BROKER_BOOTSTRAP_LEN]>, EgressBrokerProcessError> {
    validate_identity(environment_id, generation)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    let policy = CompiledPolicy::developer_baseline();
    let mut bytes = Zeroizing::new([0_u8; EGRESS_BROKER_BOOTSTRAP_LEN]);
    bytes[..8].copy_from_slice(BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(environment_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_be_bytes());
    bytes[EGRESS_BROKER_POLICY_DIGEST_OFFSET..POLICY_DIGEST_END]
        .copy_from_slice(policy.digest().as_bytes());
    bytes[KEY_OFFSET..].copy_from_slice(key);
    Ok(bytes)
}

/// Entrypoint used only by the hidden `cw` broker command.
pub async fn run_inherited_egress_broker(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), EgressBrokerProcessError> {
    let mut bootstrap = inherited_std_unix_stream(EGRESS_BROKER_BOOTSTRAP_FD)?;
    bootstrap
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    bootstrap
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;

    let (prepared, resolver) = match prepare_broker(&mut bootstrap, environment_id, generation) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = write_status(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };
    let PreparedBroker {
        bootstrap: decoded,
        policy,
    } = prepared;
    let broker = Arc::new(PolicyEgressBroker::new(
        policy,
        RouteClass::General,
        Arc::new(resolver),
        Arc::new(SystemTcpConnector::new()),
        Arc::new(SystemBrokerClock::new()),
    ));

    if let Err(error) = await_confinement_admission(&mut bootstrap) {
        let _ = write_status(&bootstrap, error.startup_failure().message());
        return Err(error);
    }

    bootstrap
        .set_read_timeout(None)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    bootstrap
        .set_write_timeout(None)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    bootstrap
        .set_nonblocking(true)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;

    let confinement = lock_process_privileges()
        .map_err(|_| EgressBrokerProcessError::PrivilegeConfinement)
        .and_then(|()| {
            install_deny_all_filesystem_domain()
                .map_err(|_| EgressBrokerProcessError::FilesystemConfinement)
        })
        .and_then(|()| {
            install_inet_socket_only_syscalls(BROKER_DENIED_SYSCALLS, BROKER_ARCH_DENIED_SYSCALLS)
                .map_err(|_| EgressBrokerProcessError::SyscallConfinement)
        });
    if let Err(error) = confinement {
        let _ = write_status(&bootstrap, error.startup_failure().message());
        return Err(error);
    }

    let mut stream = tokio::net::UnixStream::from_std(bootstrap)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    stream
        .write_all(EGRESS_BROKER_READY_MESSAGE)
        .await
        .map_err(|_| EgressBrokerProcessError::StatusIo)?;
    stream
        .flush()
        .await
        .map_err(|_| EgressBrokerProcessError::StatusIo)?;
    serve_broker_ipc(stream, decoded.binding, decoded.key, broker)
        .await
        .map_err(|_| EgressBrokerProcessError::Protocol)
}

fn await_confinement_admission(
    bootstrap: &mut StdUnixStream,
) -> Result<(), EgressBrokerProcessError> {
    write_status(bootstrap, EGRESS_BROKER_PREPARED_MESSAGE)
        .map_err(|_| EgressBrokerProcessError::StatusIo)?;
    bootstrap
        .set_read_timeout(Some(EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT))
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    let mut admission = [0_u8; EGRESS_BROKER_CONFINE_MESSAGE.len()];
    bootstrap
        .read_exact(&mut admission)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    if admission != EGRESS_BROKER_CONFINE_MESSAGE {
        return Err(EgressBrokerProcessError::Protocol);
    }
    Ok(())
}

fn prepare_broker(
    bootstrap: &mut StdUnixStream,
    environment_id: Uuid,
    generation: u64,
) -> Result<(PreparedBroker, SystemDnsResolver), EgressBrokerProcessError> {
    validate_identity(environment_id, generation)?;
    if std::env::vars_os().next().is_some() {
        return Err(EgressBrokerProcessError::AmbientEnvironment);
    }
    require_single_threaded_process().map_err(|_| EgressBrokerProcessError::ThreadConfinement)?;
    let mut bytes = Zeroizing::new([0_u8; EGRESS_BROKER_BOOTSTRAP_LEN]);
    bootstrap
        .read_exact(bytes.as_mut())
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    let policy = CompiledPolicy::developer_baseline();
    let decoded = decode_bootstrap(bytes.as_ref(), environment_id, generation, &policy)?;
    let resolver = SystemDnsResolver::from_system_config()
        .map_err(|_| EgressBrokerProcessError::ResolverInitialization)?;
    Ok((
        PreparedBroker {
            bootstrap: decoded,
            policy,
        },
        resolver,
    ))
}

fn decode_bootstrap(
    bytes: &[u8],
    expected_environment_id: Uuid,
    expected_generation: u64,
    policy: &CompiledPolicy,
) -> Result<Bootstrap, EgressBrokerProcessError> {
    validate_identity(expected_environment_id, expected_generation)?;
    if bytes.len() != EGRESS_BROKER_BOOTSTRAP_LEN || &bytes[..8] != BOOTSTRAP_MAGIC {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    let environment_id =
        Uuid::from_slice(&bytes[8..24]).map_err(|_| EgressBrokerProcessError::InvalidBootstrap)?;
    let generation = u64::from_be_bytes(
        bytes[24..32]
            .try_into()
            .expect("fixed egress broker bootstrap generation"),
    );
    if environment_id != expected_environment_id || generation != expected_generation {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    if bytes[EGRESS_BROKER_POLICY_DIGEST_OFFSET..POLICY_DIGEST_END] != *policy.digest().as_bytes() {
        return Err(EgressBrokerProcessError::PolicyMismatch);
    }
    let mut key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
    key.copy_from_slice(&bytes[KEY_OFFSET..]);
    let key =
        BrokerIpcKey::from_bytes(*key).map_err(|_| EgressBrokerProcessError::InvalidBootstrap)?;
    let binding = BrokerIpcBinding::new(environment_id, generation, policy.digest())
        .map_err(|_| EgressBrokerProcessError::InvalidBootstrap)?;
    Ok(Bootstrap { binding, key })
}

fn validate_identity(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), EgressBrokerProcessError> {
    if environment_id.is_nil() || generation == 0 {
        Err(EgressBrokerProcessError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn inherited_std_unix_stream(descriptor: RawFd) -> Result<StdUnixStream, EgressBrokerProcessError> {
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(EgressBrokerProcessError::InheritedDescriptor);
    }
    let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            descriptor,
            (&raw mut peer).cast::<libc::sockaddr>(),
            &mut peer_len,
        )
    } == -1
        || peer_len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t
        || peer_len as usize > std::mem::size_of::<libc::sockaddr_un>()
        || peer.sun_family as i32 != libc::AF_UNIX
    {
        return Err(EgressBrokerProcessError::InheritedDescriptor);
    }
    // SAFETY: the hidden process owns the fixed descriptor exactly once after
    // exec, and this is its only conversion into an owned stream.
    Ok(unsafe { StdUnixStream::from_raw_fd(descriptor) })
}

fn socket_option(descriptor: RawFd, option: i32) -> Result<i32, EgressBrokerProcessError> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &mut length,
        )
    } == -1
        || length as usize != std::mem::size_of::<i32>()
    {
        return Err(EgressBrokerProcessError::InheritedDescriptor);
    }
    Ok(value)
}

fn write_status(stream: &StdUnixStream, message: &[u8]) -> io::Result<()> {
    if message.is_empty()
        || message.len() > EGRESS_BROKER_STATUS_MAX_BYTES
        || !message.ends_with(b"\n")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid egress broker status message",
        ));
    }
    let mut stream = stream;
    stream.write_all(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    #[test]
    fn bootstrap_is_exact_and_generation_policy_bound() {
        let (environment_id, generation) = identity();
        let key = [0x5a; BROKER_IPC_KEY_LEN];
        let bytes =
            encode_developer_egress_broker_bootstrap(environment_id, generation, &key).unwrap();
        let policy = CompiledPolicy::developer_baseline();
        let decoded =
            decode_bootstrap(bytes.as_ref(), environment_id, generation, &policy).unwrap();
        assert_eq!(decoded.binding.environment_id(), environment_id);
        assert_eq!(decoded.binding.generation(), generation);
        assert_eq!(decoded.binding.policy_digest(), policy.digest());

        let mut wrong_generation = bytes.clone();
        wrong_generation[31] ^= 1;
        assert!(matches!(
            decode_bootstrap(
                wrong_generation.as_ref(),
                environment_id,
                generation,
                &policy
            ),
            Err(EgressBrokerProcessError::InvalidBootstrap)
        ));

        let mut wrong_policy = bytes.clone();
        wrong_policy[EGRESS_BROKER_POLICY_DIGEST_OFFSET] ^= 1;
        assert!(matches!(
            decode_bootstrap(wrong_policy.as_ref(), environment_id, generation, &policy),
            Err(EgressBrokerProcessError::PolicyMismatch)
        ));
    }

    #[test]
    fn bootstrap_rejects_invalid_identity_magic_and_key() {
        let (environment_id, generation) = identity();
        assert!(matches!(
            encode_developer_egress_broker_bootstrap(Uuid::nil(), generation, &[1; 32]),
            Err(EgressBrokerProcessError::InvalidIdentity)
        ));
        assert!(matches!(
            encode_developer_egress_broker_bootstrap(environment_id, 0, &[1; 32]),
            Err(EgressBrokerProcessError::InvalidIdentity)
        ));
        assert!(matches!(
            encode_developer_egress_broker_bootstrap(environment_id, generation, &[0; 32]),
            Err(EgressBrokerProcessError::InvalidBootstrap)
        ));
        let policy = CompiledPolicy::developer_baseline();
        let mut bytes =
            encode_developer_egress_broker_bootstrap(environment_id, generation, &[1; 32]).unwrap();
        bytes[0] ^= 1;
        assert!(matches!(
            decode_bootstrap(bytes.as_ref(), environment_id, generation, &policy),
            Err(EgressBrokerProcessError::InvalidBootstrap)
        ));
    }

    #[test]
    fn startup_status_is_exact_bounded_and_typed() {
        assert_eq!(
            decode_egress_broker_startup_status(EGRESS_BROKER_READY_MESSAGE),
            Some(EgressBrokerStartupStatus::Ready)
        );
        assert_eq!(
            decode_egress_broker_startup_status(EGRESS_BROKER_PREPARED_MESSAGE),
            None
        );
        assert_eq!(
            decode_egress_broker_startup_status(EGRESS_BROKER_CONFINE_MESSAGE),
            None
        );
        for failure in ALL_FAILURES {
            assert!(failure.message().len() <= EGRESS_BROKER_STATUS_MAX_BYTES);
            assert_eq!(
                decode_egress_broker_startup_status(failure.message()),
                Some(EgressBrokerStartupStatus::Failed(failure))
            );
            assert_eq!(
                EgressBrokerStartupFailure::from_exit_code(failure.exit_code()),
                Some(failure)
            );
            let mut trailing = failure.message().to_vec();
            trailing.push(b'x');
            assert_eq!(decode_egress_broker_startup_status(&trailing), None);
        }
        assert_eq!(
            decode_egress_broker_startup_status(b"CWEBB1 failed-forged\n"),
            None
        );
    }

    #[test]
    fn single_thread_guard_rejects_an_extra_thread() {
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            ready_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        });
        ready_receiver.recv().unwrap();
        assert!(require_single_threaded_process().is_err());
        release_sender.send(()).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn broker_confinement_denies_files_processes_and_non_inet_sockets() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_EGRESS_BROKER_CONFINEMENT";
        if std::env::var_os(CHILD_MARKER).is_some() {
            lock_process_privileges().unwrap();
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            install_deny_all_filesystem_domain().unwrap();
            install_inet_socket_only_syscalls(BROKER_DENIED_SYSCALLS, BROKER_ARCH_DENIED_SYSCALLS)
                .unwrap();

            let path_error = std::fs::File::open("/etc/passwd").unwrap_err();
            assert_eq!(path_error.raw_os_error(), Some(libc::EACCES));
            assert_eq!(
                unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_execve,
                        std::ptr::null::<libc::c_char>(),
                        std::ptr::null::<*const libc::c_char>(),
                        std::ptr::null::<*const libc::c_char>(),
                    )
                },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(
                    unsafe {
                        libc::syscall((0x4000_0000_u32 | libc::SYS_getpid as u32) as libc::c_long)
                    },
                    -1
                );
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            }

            assert_eq!(
                unsafe {
                    libc::socket(
                        libc::AF_INET,
                        libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                        libc::IPPROTO_ICMP,
                    )
                },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

            for (socket_type, protocol) in [
                (libc::SOCK_STREAM, 0),
                (libc::SOCK_STREAM, libc::IPPROTO_TCP),
                (libc::SOCK_DGRAM, 0),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
            ] {
                let descriptor = unsafe {
                    libc::socket(
                        libc::AF_INET,
                        socket_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                        protocol,
                    )
                };
                assert!(
                    descriptor >= 0,
                    "inet socket: {}",
                    io::Error::last_os_error()
                );
                let address = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
                    },
                    sin_zero: [0; 8],
                };
                assert_eq!(
                    unsafe {
                        libc::bind(
                            descriptor,
                            (&raw const address).cast::<libc::sockaddr>(),
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        )
                    },
                    0,
                    "loopback bind: {}",
                    io::Error::last_os_error()
                );
                unsafe {
                    libc::close(descriptor);
                }
            }
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("egress_broker::tests::broker_confinement_denies_files_processes_and_non_inet_sockets")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
