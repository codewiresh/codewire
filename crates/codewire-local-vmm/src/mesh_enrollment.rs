//! One-shot, credential-owning issuer for a native environment's Mesh setup.
//!
//! The runner supplies only a bounded non-secret request and two connected
//! Unix capabilities. The issuer resolves one explicitly selected owner
//! credential only after becoming non-dumpable, pins the exact Mesh origin,
//! enters a filesystem-denied and syscall-confined domain, creates one
//! fixed-name enrollment, and writes that capability directly to the Mesh
//! transport's enrollment socket. Neither the owner credential nor the
//! enrollment traverses runner or supervisor IPC.

use std::future::Future;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::time::Duration;

use codewire_client::{BearerToken, CodewireClient, ProtoDuration, StaticTokenProvider};
use codewire_egress_broker::adapters::SystemDnsResolver;
use codewire_proto::codewire::v1::CreateMeshNodeEnrollmentRequest;
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::linux::confinement::{
    install_deny_all_filesystem_domain, install_inet_stream_only_syscalls, lock_process_privileges,
    require_single_threaded_process,
};
use crate::mesh_ingress::MeshAttachment;
use crate::mesh_process::encode_mesh_transport_enrollment;

pub const MESH_ENROLLMENT_BOOTSTRAP_FD: RawFd = 4;
pub const MESH_ENROLLMENT_TRANSFER_FD: RawFd = 5;
pub const MESH_ENROLLMENT_PREPARED_MESSAGE: &[u8] = b"CWMENROLL1 prepared\n";
pub const MESH_ENROLLMENT_CONFINE_MESSAGE: &[u8] = b"CWMENROLL1 confine\n";
pub const MESH_ENROLLMENT_READY_MESSAGE: &[u8] = b"CWMENROLL1 ready\n";
pub const MESH_ENROLLMENT_STATUS_MAX_BYTES: usize = 64;

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWMENRB1";
const BOOTSTRAP_HEADER_LEN: usize = 40;
const MAX_BOOTSTRAP_BYTES: usize = 4_096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const ENROLLMENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
const MAX_RESPONSE_FIELD_BYTES: usize = 512;

const ENROLLMENT_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_socketpair,
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
const ENROLLMENT_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const ENROLLMENT_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshEnrollmentAuthSource {
    StandaloneLocal,
    HostedCurrent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BootstrapBody {
    auth_source: MeshEnrollmentAuthSource,
    attachment: MeshAttachment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshEnrollmentStartupFailure {
    InvalidIdentity,
    InheritedDescriptor,
    AmbientEnvironment,
    ThreadConfinement,
    BootstrapIo,
    InvalidBootstrap,
    CredentialUnavailable,
    ResolverInitialization,
    EndpointResolution,
    HttpClient,
    PrivilegeConfinement,
    FilesystemConfinement,
    SyscallConfinement,
    EnrollmentRequest,
    InvalidEnrollmentResponse,
    TransferIo,
    StatusIo,
    Protocol,
}

impl MeshEnrollmentStartupFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "invalid-identity",
            Self::InheritedDescriptor => "inherited-descriptor",
            Self::AmbientEnvironment => "ambient-environment",
            Self::ThreadConfinement => "thread-confinement",
            Self::BootstrapIo => "bootstrap-io",
            Self::InvalidBootstrap => "invalid-bootstrap",
            Self::CredentialUnavailable => "credential-unavailable",
            Self::ResolverInitialization => "resolver-initialization",
            Self::EndpointResolution => "endpoint-resolution",
            Self::HttpClient => "http-client",
            Self::PrivilegeConfinement => "privilege-confinement",
            Self::FilesystemConfinement => "filesystem-confinement",
            Self::SyscallConfinement => "syscall-confinement",
            Self::EnrollmentRequest => "enrollment-request",
            Self::InvalidEnrollmentResponse => "invalid-enrollment-response",
            Self::TransferIo => "transfer-io",
            Self::StatusIo => "status-io",
            Self::Protocol => "protocol",
        }
    }

    pub fn exit_code(self) -> i32 {
        100 + self as i32
    }

    pub fn from_exit_code(code: i32) -> Option<Self> {
        ALL_FAILURES
            .into_iter()
            .find(|failure| failure.exit_code() == code)
    }

    fn message(self) -> Vec<u8> {
        format!("CWMENROLL1 failed {}\n", self.code()).into_bytes()
    }
}

const ALL_FAILURES: [MeshEnrollmentStartupFailure; 18] = [
    MeshEnrollmentStartupFailure::InvalidIdentity,
    MeshEnrollmentStartupFailure::InheritedDescriptor,
    MeshEnrollmentStartupFailure::AmbientEnvironment,
    MeshEnrollmentStartupFailure::ThreadConfinement,
    MeshEnrollmentStartupFailure::BootstrapIo,
    MeshEnrollmentStartupFailure::InvalidBootstrap,
    MeshEnrollmentStartupFailure::CredentialUnavailable,
    MeshEnrollmentStartupFailure::ResolverInitialization,
    MeshEnrollmentStartupFailure::EndpointResolution,
    MeshEnrollmentStartupFailure::HttpClient,
    MeshEnrollmentStartupFailure::PrivilegeConfinement,
    MeshEnrollmentStartupFailure::FilesystemConfinement,
    MeshEnrollmentStartupFailure::SyscallConfinement,
    MeshEnrollmentStartupFailure::EnrollmentRequest,
    MeshEnrollmentStartupFailure::InvalidEnrollmentResponse,
    MeshEnrollmentStartupFailure::TransferIo,
    MeshEnrollmentStartupFailure::StatusIo,
    MeshEnrollmentStartupFailure::Protocol,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshEnrollmentStartupStatus {
    Ready,
    Failed(MeshEnrollmentStartupFailure),
}

pub fn decode_mesh_enrollment_startup_status(bytes: &[u8]) -> Option<MeshEnrollmentStartupStatus> {
    if bytes == MESH_ENROLLMENT_READY_MESSAGE {
        return Some(MeshEnrollmentStartupStatus::Ready);
    }
    ALL_FAILURES
        .into_iter()
        .find(|failure| bytes == failure.message())
        .map(MeshEnrollmentStartupStatus::Failed)
}

#[derive(Debug, thiserror::Error)]
pub enum MeshEnrollmentProcessError {
    #[error("Mesh enrollment issuer identity is invalid")]
    InvalidIdentity,
    #[error("Mesh enrollment issuer inherited descriptor is invalid")]
    InheritedDescriptor,
    #[error("Mesh enrollment issuer refuses an ambient environment")]
    AmbientEnvironment,
    #[error("Mesh enrollment issuer requires an exact single-threaded runtime")]
    ThreadConfinement,
    #[error("Mesh enrollment issuer bootstrap I/O failed")]
    BootstrapIo,
    #[error("Mesh enrollment issuer bootstrap is invalid")]
    InvalidBootstrap,
    #[error("Mesh enrollment owner credential is unavailable")]
    CredentialUnavailable,
    #[error("Mesh enrollment resolver initialization failed")]
    ResolverInitialization,
    #[error("Mesh enrollment endpoint resolution failed")]
    EndpointResolution,
    #[error("Mesh enrollment HTTP client initialization failed")]
    HttpClient,
    #[error("Mesh enrollment issuer privilege confinement failed")]
    PrivilegeConfinement,
    #[error("Mesh enrollment issuer filesystem confinement failed")]
    FilesystemConfinement,
    #[error("Mesh enrollment issuer syscall confinement failed")]
    SyscallConfinement,
    #[error("Mesh enrollment request failed")]
    EnrollmentRequest,
    #[error("Mesh enrollment response is invalid")]
    InvalidEnrollmentResponse,
    #[error("Mesh enrollment direct transfer failed")]
    TransferIo,
    #[error("Mesh enrollment issuer startup-status I/O failed")]
    StatusIo,
    #[error("Mesh enrollment issuer private protocol failed")]
    Protocol,
}

impl MeshEnrollmentProcessError {
    pub fn exit_code(&self) -> i32 {
        self.startup_failure().exit_code()
    }

    fn startup_failure(&self) -> MeshEnrollmentStartupFailure {
        match self {
            Self::InvalidIdentity => MeshEnrollmentStartupFailure::InvalidIdentity,
            Self::InheritedDescriptor => MeshEnrollmentStartupFailure::InheritedDescriptor,
            Self::AmbientEnvironment => MeshEnrollmentStartupFailure::AmbientEnvironment,
            Self::ThreadConfinement => MeshEnrollmentStartupFailure::ThreadConfinement,
            Self::BootstrapIo => MeshEnrollmentStartupFailure::BootstrapIo,
            Self::InvalidBootstrap => MeshEnrollmentStartupFailure::InvalidBootstrap,
            Self::CredentialUnavailable => MeshEnrollmentStartupFailure::CredentialUnavailable,
            Self::ResolverInitialization => MeshEnrollmentStartupFailure::ResolverInitialization,
            Self::EndpointResolution => MeshEnrollmentStartupFailure::EndpointResolution,
            Self::HttpClient => MeshEnrollmentStartupFailure::HttpClient,
            Self::PrivilegeConfinement => MeshEnrollmentStartupFailure::PrivilegeConfinement,
            Self::FilesystemConfinement => MeshEnrollmentStartupFailure::FilesystemConfinement,
            Self::SyscallConfinement => MeshEnrollmentStartupFailure::SyscallConfinement,
            Self::EnrollmentRequest => MeshEnrollmentStartupFailure::EnrollmentRequest,
            Self::InvalidEnrollmentResponse => {
                MeshEnrollmentStartupFailure::InvalidEnrollmentResponse
            }
            Self::TransferIo => MeshEnrollmentStartupFailure::TransferIo,
            Self::StatusIo => MeshEnrollmentStartupFailure::StatusIo,
            Self::Protocol => MeshEnrollmentStartupFailure::Protocol,
        }
    }
}

pub trait MeshEnrollmentCredentialResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        source: MeshEnrollmentAuthSource,
        attachment: &'a MeshAttachment,
    ) -> Pin<Box<dyn Future<Output = Result<BearerToken, ()>> + Send + 'a>>;
}

struct PreparedEnrollment {
    auth_source: MeshEnrollmentAuthSource,
    attachment: MeshAttachment,
    addresses: Vec<SocketAddr>,
}

struct AuthorizedEnrollment {
    attachment: MeshAttachment,
    client: CodewireClient,
}

pub fn encode_mesh_enrollment_bootstrap(
    environment_id: Uuid,
    generation: u64,
    auth_source: MeshEnrollmentAuthSource,
    attachment: &MeshAttachment,
) -> Result<Vec<u8>, MeshEnrollmentProcessError> {
    validate_identity(environment_id, generation)?;
    attachment
        .validate()
        .map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?;
    let body = serde_json::to_vec(&BootstrapBody {
        auth_source,
        attachment: attachment.clone(),
    })
    .map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?;
    let total_len = BOOTSTRAP_HEADER_LEN
        .checked_add(body.len())
        .filter(|length| *length <= MAX_BOOTSTRAP_BYTES)
        .ok_or(MeshEnrollmentProcessError::InvalidBootstrap)?;
    let mut bytes = vec![0_u8; total_len];
    bytes[..8].copy_from_slice(BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(environment_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_be_bytes());
    bytes[32..36].copy_from_slice(&(total_len as u32).to_be_bytes());
    bytes[BOOTSTRAP_HEADER_LEN..].copy_from_slice(&body);
    Ok(bytes)
}

/// Entrypoint used only by the hidden `cw` Mesh enrollment issuer command.
pub async fn run_inherited_mesh_enrollment_broker(
    environment_id: Uuid,
    generation: u64,
    credentials: &dyn MeshEnrollmentCredentialResolver,
) -> Result<(), MeshEnrollmentProcessError> {
    let mut control = inherited_std_unix_stream(MESH_ENROLLMENT_BOOTSTRAP_FD)?;
    let mut transfer = inherited_std_unix_stream(MESH_ENROLLMENT_TRANSFER_FD)?;
    configure_handshake_stream(&control, || MeshEnrollmentProcessError::BootstrapIo)?;
    configure_handshake_stream(&transfer, || MeshEnrollmentProcessError::TransferIo)?;
    transfer
        .shutdown(Shutdown::Read)
        .map_err(|_| MeshEnrollmentProcessError::TransferIo)?;

    let prepared = match prepare_enrollment(&mut control, environment_id, generation).await {
        Ok(prepared) => prepared,
        Err(error) => return fail_startup(&control, error),
    };
    if let Err(error) = await_confinement_admission(&mut control) {
        return fail_startup(&control, error);
    }
    if lock_process_privileges().is_err() {
        return fail_startup(&control, MeshEnrollmentProcessError::PrivilegeConfinement);
    }
    // Only this already non-dumpable child reads the selected owner store.
    // The parent may capture the exact executable after PREPARED, but the
    // protected value does not enter memory until after that admission.
    let authorized = match authorize_enrollment(prepared, credentials).await {
        Ok(authorized) => authorized,
        Err(error) => return fail_startup(&control, error),
    };
    if install_deny_all_filesystem_domain().is_err() {
        return fail_startup(&control, MeshEnrollmentProcessError::FilesystemConfinement);
    }
    if install_inet_stream_only_syscalls(
        ENROLLMENT_DENIED_SYSCALLS,
        ENROLLMENT_ARCH_DENIED_SYSCALLS,
    )
    .is_err()
    {
        return fail_startup(&control, MeshEnrollmentProcessError::SyscallConfinement);
    }

    let enrollment = match create_enrollment(authorized).await {
        Ok(enrollment) => enrollment,
        Err(error) => return fail_startup(&control, error),
    };
    if transfer.write_all(enrollment.as_ref()).is_err()
        || transfer.flush().is_err()
        || transfer.shutdown(Shutdown::Write).is_err()
    {
        return fail_startup(&control, MeshEnrollmentProcessError::TransferIo);
    }
    drop(enrollment);
    write_status(&control, MESH_ENROLLMENT_READY_MESSAGE)
        .map_err(|_| MeshEnrollmentProcessError::StatusIo)
}

async fn prepare_enrollment(
    control: &mut StdUnixStream,
    environment_id: Uuid,
    generation: u64,
) -> Result<PreparedEnrollment, MeshEnrollmentProcessError> {
    validate_identity(environment_id, generation)?;
    if std::env::vars_os().next().is_some() {
        return Err(MeshEnrollmentProcessError::AmbientEnvironment);
    }
    require_single_threaded_process().map_err(|_| MeshEnrollmentProcessError::ThreadConfinement)?;
    let bootstrap = read_bootstrap(control, environment_id, generation)?;
    let resolver = SystemDnsResolver::from_system_config()
        .map_err(|_| MeshEnrollmentProcessError::ResolverInitialization)?;
    let addresses = resolve_url(&bootstrap.attachment.mesh_url, &resolver).await?;
    drop(resolver);
    require_single_threaded_process().map_err(|_| MeshEnrollmentProcessError::ThreadConfinement)?;
    write_status(control, MESH_ENROLLMENT_PREPARED_MESSAGE)
        .map_err(|_| MeshEnrollmentProcessError::StatusIo)?;
    Ok(PreparedEnrollment {
        auth_source: bootstrap.auth_source,
        attachment: bootstrap.attachment,
        addresses,
    })
}

async fn authorize_enrollment(
    prepared: PreparedEnrollment,
    credentials: &dyn MeshEnrollmentCredentialResolver,
) -> Result<AuthorizedEnrollment, MeshEnrollmentProcessError> {
    let token = credentials
        .resolve(prepared.auth_source, &prepared.attachment)
        .await
        .map_err(|()| MeshEnrollmentProcessError::CredentialUnavailable)?;
    let http = pinned_http_client(&prepared.attachment.mesh_url, &prepared.addresses)?;
    let config = codewire_client::ClientConfig::new(&prepared.attachment.mesh_url)
        .and_then(|config| config.with_mesh_url(&prepared.attachment.mesh_url))
        .and_then(|config| config.with_user_agent("codewire-local-mesh-enrollment/1"))
        .map_err(|_| MeshEnrollmentProcessError::HttpClient)?;
    let client = CodewireClient::with_http(config, StaticTokenProvider::from_token(token), http)
        .map_err(|_| MeshEnrollmentProcessError::HttpClient)?;
    Ok(AuthorizedEnrollment {
        attachment: prepared.attachment,
        client,
    })
}

async fn create_enrollment(
    prepared: AuthorizedEnrollment,
) -> Result<Zeroizing<Vec<u8>>, MeshEnrollmentProcessError> {
    let response = prepared
        .client
        .create_mesh_node_enrollment(CreateMeshNodeEnrollmentRequest {
            org_id: prepared.attachment.organization_id.clone(),
            network_id: prepared.attachment.network_id.clone(),
            node_name: prepared.attachment.node_name.clone(),
            ttl: Some(ProtoDuration::from_secs(ENROLLMENT_TTL_SECONDS)).into(),
            ..Default::default()
        })
        .await
        .map_err(|_| MeshEnrollmentProcessError::EnrollmentRequest)?;
    let enrollment = response
        .enrollment
        .into_option()
        .ok_or(MeshEnrollmentProcessError::InvalidEnrollmentResponse)?;
    if enrollment.id.is_empty()
        || enrollment.id.len() > MAX_RESPONSE_FIELD_BYTES
        || enrollment.org_id != prepared.attachment.organization_id
        || enrollment.network_id != prepared.attachment.network_id
        || enrollment.node_name != prepared.attachment.node_name
        || enrollment.redeemed_at.into_option().is_some()
    {
        return Err(MeshEnrollmentProcessError::InvalidEnrollmentResponse);
    }
    let mut code = Zeroizing::new(response.enrollment_code);
    let encoded = encode_mesh_transport_enrollment(code.as_str())
        .map_err(|_| MeshEnrollmentProcessError::InvalidEnrollmentResponse)?;
    code.zeroize();
    Ok(encoded)
}

fn read_bootstrap(
    control: &mut StdUnixStream,
    environment_id: Uuid,
    generation: u64,
) -> Result<BootstrapBody, MeshEnrollmentProcessError> {
    let mut header = [0_u8; BOOTSTRAP_HEADER_LEN];
    control
        .read_exact(&mut header)
        .map_err(|_| MeshEnrollmentProcessError::BootstrapIo)?;
    if &header[..8] != BOOTSTRAP_MAGIC
        || &header[8..24] != environment_id.as_bytes()
        || header[24..32] != generation.to_be_bytes()
        || header[36..40] != [0_u8; 4]
    {
        return Err(MeshEnrollmentProcessError::InvalidBootstrap);
    }
    let total_len = u32::from_be_bytes(
        header[32..36]
            .try_into()
            .map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?,
    ) as usize;
    let body_len = total_len
        .checked_sub(BOOTSTRAP_HEADER_LEN)
        .filter(|_| total_len <= MAX_BOOTSTRAP_BYTES)
        .ok_or(MeshEnrollmentProcessError::InvalidBootstrap)?;
    let mut body = vec![0_u8; body_len];
    control
        .read_exact(&mut body)
        .map_err(|_| MeshEnrollmentProcessError::BootstrapIo)?;
    let decoded: BootstrapBody =
        serde_json::from_slice(&body).map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?;
    decoded
        .attachment
        .validate()
        .map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?;
    let canonical =
        serde_json::to_vec(&decoded).map_err(|_| MeshEnrollmentProcessError::InvalidBootstrap)?;
    if canonical != body {
        return Err(MeshEnrollmentProcessError::InvalidBootstrap);
    }
    Ok(decoded)
}

async fn resolve_url(
    raw_url: &str,
    resolver: &SystemDnsResolver,
) -> Result<Vec<SocketAddr>, MeshEnrollmentProcessError> {
    let url = Url::parse(raw_url).map_err(|_| MeshEnrollmentProcessError::EndpointResolution)?;
    let port = url
        .port_or_known_default()
        .ok_or(MeshEnrollmentProcessError::EndpointResolution)?;
    let mut addresses = match url.host() {
        Some(Host::Ipv4(address)) => vec![IpAddr::V4(address)],
        Some(Host::Ipv6(address)) => vec![IpAddr::V6(address)],
        Some(Host::Domain(domain)) => resolver
            .resolve_host_addresses(domain)
            .await
            .map_err(|_| MeshEnrollmentProcessError::EndpointResolution)?,
        None => return Err(MeshEnrollmentProcessError::EndpointResolution),
    }
    .into_iter()
    .map(|address| SocketAddr::new(address, port))
    .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(MeshEnrollmentProcessError::EndpointResolution);
    }
    Ok(addresses)
}

fn pinned_http_client(
    raw_url: &str,
    addresses: &[SocketAddr],
) -> Result<reqwest::Client, MeshEnrollmentProcessError> {
    let url = Url::parse(raw_url).map_err(|_| MeshEnrollmentProcessError::HttpClient)?;
    let host = url
        .host_str()
        .ok_or(MeshEnrollmentProcessError::HttpClient)?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(ENROLLMENT_REQUEST_TIMEOUT)
        .timeout(ENROLLMENT_REQUEST_TIMEOUT);
    if matches!(url.host(), Some(Host::Domain(_))) {
        builder = builder.resolve_to_addrs(host, addresses);
    }
    builder
        .build()
        .map_err(|_| MeshEnrollmentProcessError::HttpClient)
}

fn await_confinement_admission(
    control: &mut StdUnixStream,
) -> Result<(), MeshEnrollmentProcessError> {
    let mut admission = vec![0_u8; MESH_ENROLLMENT_CONFINE_MESSAGE.len()];
    control
        .read_exact(&mut admission)
        .map_err(|_| MeshEnrollmentProcessError::BootstrapIo)?;
    if admission != MESH_ENROLLMENT_CONFINE_MESSAGE {
        return Err(MeshEnrollmentProcessError::Protocol);
    }
    Ok(())
}

fn write_status(control: &StdUnixStream, status: &[u8]) -> io::Result<()> {
    let mut control = control;
    control.write_all(status)?;
    control.flush()
}

fn fail_startup(
    control: &StdUnixStream,
    error: MeshEnrollmentProcessError,
) -> Result<(), MeshEnrollmentProcessError> {
    let _ = write_status(control, &error.startup_failure().message());
    Err(error)
}

fn validate_identity(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), MeshEnrollmentProcessError> {
    if environment_id.is_nil() || generation == 0 {
        return Err(MeshEnrollmentProcessError::InvalidIdentity);
    }
    Ok(())
}

fn inherited_std_unix_stream(fd: RawFd) -> Result<StdUnixStream, MeshEnrollmentProcessError> {
    if fd < 3
        || socket_option(fd, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(fd, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(MeshEnrollmentProcessError::InheritedDescriptor);
    }
    let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::getpeername(fd, (&raw mut peer).cast::<libc::sockaddr>(), &mut peer_len) }
        == -1
        || peer_len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t
        || peer_len as usize > std::mem::size_of::<libc::sockaddr_un>()
        || peer.sun_family as i32 != libc::AF_UNIX
    {
        return Err(MeshEnrollmentProcessError::InheritedDescriptor);
    }
    // SAFETY: the hidden process owns each fixed descriptor exactly once after
    // exec, and this is its only conversion into an owned stream.
    Ok(unsafe { StdUnixStream::from_raw_fd(fd) })
}

fn socket_option(fd: RawFd, option: i32) -> Result<i32, MeshEnrollmentProcessError> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &raw mut length,
        )
    } == -1
        || length != std::mem::size_of::<i32>() as libc::socklen_t
    {
        return Err(MeshEnrollmentProcessError::InheritedDescriptor);
    }
    Ok(value)
}

fn configure_handshake_stream(
    stream: &StdUnixStream,
    error: impl Fn() -> MeshEnrollmentProcessError,
) -> Result<(), MeshEnrollmentProcessError> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| error())?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| error())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn bootstrap_is_canonical_bounded_and_generation_bound() {
        let environment_id = Uuid::new_v4();
        let attachment = MeshAttachment::new(
            "https://mesh.example.test",
            "org",
            "network",
            "sandbox",
            [3_000],
        )
        .unwrap();
        let bytes = encode_mesh_enrollment_bootstrap(
            environment_id,
            7,
            MeshEnrollmentAuthSource::StandaloneLocal,
            &attachment,
        )
        .unwrap();
        let (mut sender, mut receiver) = StdUnixStream::pair().unwrap();
        sender.write_all(&bytes).unwrap();
        let decoded = read_bootstrap(&mut receiver, environment_id, 7).unwrap();
        assert_eq!(decoded.attachment, attachment);
        assert_eq!(
            decoded.auth_source,
            MeshEnrollmentAuthSource::StandaloneLocal
        );

        let (mut sender, mut receiver) = StdUnixStream::pair().unwrap();
        sender.write_all(&bytes).unwrap();
        assert!(matches!(
            read_bootstrap(&mut receiver, environment_id, 8),
            Err(MeshEnrollmentProcessError::InvalidBootstrap)
        ));
    }

    #[test]
    fn status_and_exit_taxonomy_is_total() {
        for failure in ALL_FAILURES {
            assert_eq!(
                MeshEnrollmentStartupFailure::from_exit_code(failure.exit_code()),
                Some(failure)
            );
            assert_eq!(
                decode_mesh_enrollment_startup_status(&failure.message()),
                Some(MeshEnrollmentStartupStatus::Failed(failure))
            );
        }
        assert_eq!(
            decode_mesh_enrollment_startup_status(MESH_ENROLLMENT_READY_MESSAGE),
            Some(MeshEnrollmentStartupStatus::Ready)
        );
    }

    #[test]
    fn inherited_control_rejects_a_connected_inet_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(matches!(
            inherited_std_unix_stream(server.as_raw_fd()),
            Err(MeshEnrollmentProcessError::InheritedDescriptor)
        ));
        drop(client);
    }
}
