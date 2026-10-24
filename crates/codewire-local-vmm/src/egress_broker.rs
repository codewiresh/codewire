//! Confined host process for one local environment's general egress policy.
//!
//! The runner supplies one already-connected AF_UNIX stream containing a
//! generation-bound bootstrap record, an exact confinement admission after
//! process capture, and then the authenticated admission session of the broker
//! IPC. The other IPC sessions (#2638) are inherited at fixed descriptors. The
//! process accepts no configuration from files or environment variables.

use std::io::{self, Read as _, Write as _};
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use codewire_egress_broker::adapters::{SystemDnsResolver, SystemTcpConnector};
use codewire_egress_broker::ipc::{
    BROKER_IPC_KEY_LEN, BROKER_IPC_SESSIONS, BrokerIpcBinding, BrokerIpcKey, serve_broker_ipc,
};
use codewire_egress_broker::{PolicyEgressBroker, SystemBrokerClock};
use codewire_egress_policy::{CompiledPolicy, PolicyDocument, RouteClass};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use crate::linux::confinement::{
    install_deny_all_filesystem_domain, install_inet_socket_only_syscalls, lock_process_privileges,
    require_single_threaded_process,
};

pub const EGRESS_BROKER_BOOTSTRAP_FD: RawFd = 4;
/// The runner's one-way host-address control socket (#2614).
pub const EGRESS_BROKER_HOST_ADDRESSES_FD: RawFd = 5;
/// IPC sessions after the admission session (#2638) are inherited at this
/// descriptor and the ones after it, in session order.
pub const EGRESS_BROKER_FIRST_SESSION_FD: RawFd = 6;
/// Inherited IPC sessions: every session but the bootstrap stream's.
pub const EGRESS_BROKER_INHERITED_SESSIONS: usize = BROKER_IPC_SESSIONS - 1;
pub const EGRESS_BROKER_PREPARED_MESSAGE: &[u8] = b"CWEBB1 prepared\n";
pub const EGRESS_BROKER_CONFINE_MESSAGE: &[u8] = b"CWEBB1 confine\n";
pub const EGRESS_BROKER_READY_MESSAGE: &[u8] = b"CWEBB1 ready\n";
pub const EGRESS_BROKER_STATUS_MAX_BYTES: usize = 64;
/// The fixed header: magic, identity, the policy's digest and the IPC key.
/// The canonical policy document follows it, length-prefixed (#2537).
pub const EGRESS_BROKER_BOOTSTRAP_LEN: usize = 96;
pub const EGRESS_BROKER_POLICY_DIGEST_OFFSET: usize = 32;
/// The most document bytes a bootstrap carries: the library's ceiling.
pub const EGRESS_BROKER_POLICY_DOCUMENT_MAX: usize =
    codewire_egress_policy::MAX_POLICY_DOCUMENT_BYTES;

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWEBB2\0\0";
const POLICY_DIGEST_LEN: usize = 32;
const POLICY_DIGEST_END: usize = EGRESS_BROKER_POLICY_DIGEST_OFFSET + POLICY_DIGEST_LEN;
const KEY_OFFSET: usize = POLICY_DIGEST_END;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(target_os = "linux")]
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BROKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const BROKER_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

#[cfg(target_os = "macos")]
fn require_single_threaded_process() -> io::Result<()> {
    crate::host::sandbox::require_single_thread()
}

/// Darwin has no no-new-privileges or dumpability switch; the broker never
/// executes anything after the Seatbelt profile below refuses process
/// creation.
#[cfg(target_os = "macos")]
fn lock_process_privileges() -> io::Result<()> {
    Ok(())
}

/// Darwin replaces Landlock and the INET-only syscall filter with one Seatbelt
/// profile, installed at the same point: outbound TCP and the broker's own DNS
/// remain, and files, processes, signals, Mach services, Unix sockets and
/// listeners are refused.
#[cfg(target_os = "macos")]
fn install_deny_all_filesystem_domain() -> io::Result<()> {
    crate::host::sandbox::confine_egress_broker()
}

/// The Seatbelt profile installed with the filesystem layer already covers
/// what the Linux syscall layer adds.
#[cfg(target_os = "macos")]
fn install_inet_socket_only_syscalls() -> io::Result<()> {
    Ok(())
}

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
    HostAddresses,
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
            Self::HostAddresses => "host-addresses",
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
            Self::HostAddresses => 73,
        }
    }

    pub(crate) fn runner_error_code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "egress_broker_invalid_identity",
            Self::InheritedDescriptor => "egress_broker_inherited_descriptor",
            Self::AmbientEnvironment => "egress_broker_ambient_environment",
            Self::ThreadConfinement => "egress_broker_thread_confinement",
            Self::BootstrapIo => "egress_broker_bootstrap_io",
            Self::InvalidBootstrap => "egress_broker_invalid_bootstrap",
            Self::PolicyMismatch => "egress_broker_policy_mismatch",
            Self::ResolverInitialization => "egress_broker_resolver_initialization",
            Self::PrivilegeConfinement => "egress_broker_privilege_confinement",
            Self::FilesystemConfinement => "egress_broker_filesystem_confinement",
            Self::SyscallConfinement => "egress_broker_syscall_confinement",
            Self::StatusIo => "egress_broker_status_io",
            Self::Protocol => "egress_broker_protocol",
            Self::HostAddresses => "egress_broker_host_addresses",
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
            Self::HostAddresses => b"CWEBB1 failed-host-addresses\n",
        }
    }
}

const ALL_FAILURES: [EgressBrokerStartupFailure; 14] = [
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
    EgressBrokerStartupFailure::HostAddresses,
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
    /// The runner's host addresses could not be read: the broker never runs
    /// without them (#2614).
    #[error("egress broker host-address control failed")]
    HostAddresses,
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
            Self::HostAddresses => EgressBrokerStartupFailure::HostAddresses,
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

/// Encode the private bootstrap record written by the environment runner:
/// the fixed header, then the selected policy's canonical document, which the
/// broker compiles and checks against the header's digest. The HMAC key is
/// never accepted through argv, environment, or disk.
pub fn encode_egress_broker_bootstrap(
    environment_id: Uuid,
    generation: u64,
    key: &[u8; BROKER_IPC_KEY_LEN],
    policy: &CompiledPolicy,
) -> Result<Zeroizing<Vec<u8>>, EgressBrokerProcessError> {
    validate_identity(environment_id, generation)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    let document = policy
        .canonical_json()
        .map_err(|_| EgressBrokerProcessError::InvalidBootstrap)?;
    if document.len() > EGRESS_BROKER_POLICY_DOCUMENT_MAX {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        EGRESS_BROKER_BOOTSTRAP_LEN + 4 + document.len(),
    ));
    bytes.extend_from_slice(BOOTSTRAP_MAGIC);
    bytes.extend_from_slice(environment_id.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(policy.digest().as_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(
        &u32::try_from(document.len())
            .expect("bounded policy document")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&document);
    Ok(bytes)
}

/// Entrypoint used only by the hidden `cw` broker command.
pub async fn run_inherited_egress_broker(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), EgressBrokerProcessError> {
    let mut bootstrap = inherited_std_unix_stream(EGRESS_BROKER_BOOTSTRAP_FD)?;
    let control = inherited_std_unix_stream(EGRESS_BROKER_HOST_ADDRESSES_FD)?;
    let sessions = (0..EGRESS_BROKER_INHERITED_SESSIONS)
        .map(|index| {
            let session =
                inherited_std_unix_stream(EGRESS_BROKER_FIRST_SESSION_FD + index as RawFd)?;
            session
                .set_nonblocking(true)
                .map_err(|_| EgressBrokerProcessError::InheritedDescriptor)?;
            Ok(session)
        })
        .collect::<Result<Vec<_>, EgressBrokerProcessError>>()?;
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

    // The host's own addresses arrive before the broker can admit anything,
    // and every later update replaces them (#2614).
    let mut control = match receive_host_addresses(control, &broker).await {
        Ok(control) => control,
        Err(error) => {
            let _ = write_status(&bootstrap, error.startup_failure().message());
            return Err(error);
        }
    };

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
            #[cfg(target_os = "linux")]
            let installed = install_inet_socket_only_syscalls(
                BROKER_DENIED_SYSCALLS,
                BROKER_ARCH_DENIED_SYSCALLS,
            );
            #[cfg(target_os = "macos")]
            let installed = install_inet_socket_only_syscalls();
            installed.map_err(|_| EgressBrokerProcessError::SyscallConfinement)
        });
    if let Err(error) = confinement {
        let _ = write_status(&bootstrap, error.startup_failure().message());
        return Err(error);
    }

    let mut stream = tokio::net::UnixStream::from_std(bootstrap)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    // The bootstrap stream becomes the admission session, then the rest.
    let mut streams = Vec::with_capacity(BROKER_IPC_SESSIONS);
    for session in sessions {
        streams.push(
            tokio::net::UnixStream::from_std(session)
                .map_err(|_| EgressBrokerProcessError::InheritedDescriptor)?,
        );
    }
    stream
        .write_all(EGRESS_BROKER_READY_MESSAGE)
        .await
        .map_err(|_| EgressBrokerProcessError::StatusIo)?;
    stream
        .flush()
        .await
        .map_err(|_| EgressBrokerProcessError::StatusIo)?;
    streams.insert(0, stream);
    let updated = Arc::clone(&broker);
    let updates = async move {
        loop {
            match crate::host_addresses::read_frame(&mut control).await {
                Ok(addresses) => updated.set_host_addresses(addresses).await,
                Err(error) => break error,
            }
        }
    };
    // A malformed update or a closed control socket fails the broker closed.
    tokio::select! {
        served = serve_broker_ipc(streams, decoded.binding, decoded.key, broker) => {
            served.map_err(|_| EgressBrokerProcessError::Protocol)
        }
        _ = updates => Err(EgressBrokerProcessError::HostAddresses),
    }
}

async fn receive_host_addresses<R, C, K>(
    control: StdUnixStream,
    broker: &PolicyEgressBroker<R, C, K>,
) -> Result<tokio::net::UnixStream, EgressBrokerProcessError>
where
    R: codewire_egress_broker::DnsResolver,
    C: codewire_egress_broker::TcpConnector,
    K: codewire_egress_broker::BrokerClock,
{
    control
        .set_nonblocking(true)
        .map_err(|_| EgressBrokerProcessError::HostAddresses)?;
    let mut control = tokio::net::UnixStream::from_std(control)
        .map_err(|_| EgressBrokerProcessError::HostAddresses)?;
    let addresses = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::host_addresses::read_frame(&mut control),
    )
    .await
    .map_err(|_| EgressBrokerProcessError::HostAddresses)?
    .map_err(|_| EgressBrokerProcessError::HostAddresses)?;
    broker.set_host_addresses(addresses).await;
    Ok(control)
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
    if crate::network_worker::ambient_environment_present() {
        return Err(EgressBrokerProcessError::AmbientEnvironment);
    }
    require_single_threaded_process().map_err(|_| EgressBrokerProcessError::ThreadConfinement)?;
    let mut bytes = Zeroizing::new([0_u8; EGRESS_BROKER_BOOTSTRAP_LEN]);
    bootstrap
        .read_exact(bytes.as_mut())
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    let policy = read_bootstrap_policy(bootstrap)?;
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

/// The length-prefixed canonical document after the header, compiled. Its
/// digest is checked against the header by [`decode_bootstrap`].
fn read_bootstrap_policy(
    bootstrap: &mut StdUnixStream,
) -> Result<CompiledPolicy, EgressBrokerProcessError> {
    let mut length = [0_u8; 4];
    bootstrap
        .read_exact(&mut length)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| EgressBrokerProcessError::InvalidBootstrap)?;
    if length == 0 || length > EGRESS_BROKER_POLICY_DOCUMENT_MAX {
        return Err(EgressBrokerProcessError::InvalidBootstrap);
    }
    let mut document = vec![0_u8; length];
    bootstrap
        .read_exact(&mut document)
        .map_err(|_| EgressBrokerProcessError::BootstrapIo)?;
    compile_bootstrap_policy(&document)
}

fn compile_bootstrap_policy(document: &[u8]) -> Result<CompiledPolicy, EgressBrokerProcessError> {
    let document: PolicyDocument =
        serde_json::from_slice(document).map_err(|_| EgressBrokerProcessError::PolicyMismatch)?;
    CompiledPolicy::compile(document).map_err(|_| EgressBrokerProcessError::PolicyMismatch)
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
    // Darwin has no SO_DOMAIN and cannot read SO_ACCEPTCONN; the connected
    // AF_UNIX peer address below proves the domain and that it is no listener.
    #[cfg(target_os = "linux")]
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(EgressBrokerProcessError::InheritedDescriptor);
    }
    if socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM {
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
    #[cfg(target_os = "linux")]
    use std::net::Ipv4Addr;
    #[cfg(target_os = "linux")]
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
        let policy = CompiledPolicy::developer_baseline();
        let bytes =
            encode_egress_broker_bootstrap(environment_id, generation, &key, &policy).unwrap();
        let bytes = bytes[..EGRESS_BROKER_BOOTSTRAP_LEN].to_vec();
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

    /// #2537: the bootstrap carries the selected policy itself. The broker
    /// enforces the document it compiles, and only if it is the one the
    /// header's digest names.
    #[test]
    fn bootstrap_carries_the_selected_policy_document() {
        let (environment_id, generation) = identity();
        let selected = codewire_egress_policy::typed::TypedPolicy::new([
            codewire_egress_policy::typed::AllowRule::new(
                codewire_egress_policy::typed::AllowTarget::parse("github.com").unwrap(),
                [443],
            )
            .unwrap(),
        ])
        .unwrap()
        .compile();
        let bytes = encode_egress_broker_bootstrap(environment_id, generation, &[7; 32], &selected)
            .unwrap();
        let (header, rest) = bytes.split_at(EGRESS_BROKER_BOOTSTRAP_LEN);
        let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        assert_eq!(rest.len(), 4 + length);
        let compiled = compile_bootstrap_policy(&rest[4..]).unwrap();
        assert_eq!(compiled.digest(), selected.digest());
        let decoded = decode_bootstrap(header, environment_id, generation, &compiled).unwrap();
        assert_eq!(decoded.binding.policy_digest(), selected.digest());

        // A different document than the header names is refused.
        let open = CompiledPolicy::developer_baseline();
        assert!(matches!(
            decode_bootstrap(header, environment_id, generation, &open),
            Err(EgressBrokerProcessError::PolicyMismatch)
        ));
        assert!(matches!(
            compile_bootstrap_policy(b"{\"version\":1}"),
            Err(EgressBrokerProcessError::PolicyMismatch)
        ));
    }

    #[test]
    fn bootstrap_rejects_invalid_identity_magic_and_key() {
        let (environment_id, generation) = identity();
        assert!(matches!(
            encode_egress_broker_bootstrap(
                Uuid::nil(),
                generation,
                &[1; 32],
                &CompiledPolicy::developer_baseline()
            ),
            Err(EgressBrokerProcessError::InvalidIdentity)
        ));
        assert!(matches!(
            encode_egress_broker_bootstrap(
                environment_id,
                0,
                &[1; 32],
                &CompiledPolicy::developer_baseline()
            ),
            Err(EgressBrokerProcessError::InvalidIdentity)
        ));
        assert!(matches!(
            encode_egress_broker_bootstrap(
                environment_id,
                generation,
                &[0; 32],
                &CompiledPolicy::developer_baseline()
            ),
            Err(EgressBrokerProcessError::InvalidBootstrap)
        ));
        let policy = CompiledPolicy::developer_baseline();
        let mut bytes =
            encode_egress_broker_bootstrap(environment_id, generation, &[1; 32], &policy).unwrap();
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
            assert!(failure.runner_error_code().len() <= 64);
            assert!(
                failure
                    .runner_error_code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
