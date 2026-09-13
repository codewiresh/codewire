//! Isolated host owner for one local environment's Mesh transport.
//!
//! The process receives non-secret attachment intent and a generation HMAC
//! key on one inherited AF_UNIX stream. A distinct one-shot stream carries the
//! enrollment capability and closes immediately after transfer. The child
//! becomes non-dumpable before receiving enrollment, then resolves and pins
//! every network endpoint before entering a filesystem- and syscall-confined
//! domain. It never accepts a credential through argv, environment, disk, or
//! the runner submission path.

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use codewire_client::{
    CoordinatorError, CoordinatorHandlers, ErrorCode, MeshCoordinateIdentity,
    MeshCoordinatorPeerSession,
};
use codewire_egress_broker::adapters::SystemDnsResolver;
use codewire_tailnet::conn::{Conn, Options as ConnOptions};
use codewire_tailnet::derp_transport::{
    DerpTarget, DerpTransport, connect_derp_transport_resolved,
};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::DiscoPrivate;
use codewire_tailnet::node::{NodePublic, prefix_from_uuid};
use codewire_tailnet::wg::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use url::{Host, Url};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::linux::confinement::{
    install_deny_all_filesystem_domain, install_inet_and_unix_stream_pair_syscalls,
    lock_process_privileges, require_single_threaded_process,
};
use crate::mesh_ingress::{MAX_MESH_INGRESS_PORTS, MESH_INGRESS_CONTROL_KEY_LEN, MeshAttachment};
use crate::mesh_transport::{MeshIngressBridge, MeshIngressSubmitter, MeshTransportError};

pub const MESH_TRANSPORT_BOOTSTRAP_FD: RawFd = 4;
pub const MESH_TRANSPORT_ENROLLMENT_FD: RawFd = 5;
pub const MESH_TRANSPORT_PREPARED_MESSAGE: &[u8] = b"CWMESH1 prepared\n";
pub const MESH_TRANSPORT_CONFINE_MESSAGE: &[u8] = b"CWMESH1 confine\n";
pub const MESH_TRANSPORT_CONFINED_MESSAGE: &[u8] = b"CWMESH1 confined\n";
pub const MESH_TRANSPORT_READY_MESSAGE: &[u8] = b"CWMESH1 ready\n";
pub const MESH_TRANSPORT_STATUS_MAX_BYTES: usize = 64;

const BOOTSTRAP_MAGIC: &[u8; 8] = b"CWMESHB1";
const BOOTSTRAP_HEADER_LEN: usize = 80;
const BOOTSTRAP_TOTAL_LEN_OFFSET: usize = 64;
const BOOTSTRAP_MESH_URL_LEN_OFFSET: usize = 68;
const BOOTSTRAP_ORGANIZATION_LEN_OFFSET: usize = 70;
const BOOTSTRAP_NETWORK_LEN_OFFSET: usize = 72;
const BOOTSTRAP_NODE_LEN_OFFSET: usize = 74;
const BOOTSTRAP_PORT_COUNT_OFFSET: usize = 76;
const BOOTSTRAP_RESERVED_OFFSET: usize = 78;
const MAX_BOOTSTRAP_BYTES: usize = 4_096;

const ENROLLMENT_MAGIC: &[u8; 8] = b"CWMENR1\0";
const ENROLLMENT_HEADER_LEN: usize = 12;
const MAX_ENROLLMENT_BYTES: usize = 512;
const MAX_DERP_MAP_BYTES: usize = 256 * 1024;
const MAX_DERP_REGIONS: usize = 64;
const MAX_DERP_NODES: usize = 256;
const MAX_STUN_SERVERS: usize = 8;
const MAX_ENDPOINT_HOST_BYTES: usize = 253;
const MAX_RESOLVED_ENDPOINTS: usize = 16;
const MAX_RESOLVED_STUN_ENDPOINTS: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_SETUP_TIMEOUT: Duration = Duration::from_secs(15);
// The transport enters PREPARED before the runner spawns and admits the
// enrollment child, so this phase covers two exact executable captures. The
// runner retains a separate outer deadline around the complete Mesh stack.
pub(crate) const MESH_TRANSPORT_CONFINEMENT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(40);

const MESH_DENIED_SYSCALLS: &[libc::c_long] = &[
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
const MESH_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const MESH_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTransportStartupFailure {
    InvalidIdentity,
    InheritedDescriptor,
    AmbientEnvironment,
    ThreadConfinement,
    BootstrapIo,
    InvalidBootstrap,
    EnrollmentIo,
    InvalidEnrollment,
    ResolverInitialization,
    CoordinatorResolution,
    CoordinatorSetup,
    DerpMap,
    TransportResolution,
    PrivilegeConfinement,
    FilesystemConfinement,
    SyscallConfinement,
    TransportSetup,
    StatusIo,
    Protocol,
    CoordinatorUnauthenticated,
    CoordinatorPermissionDenied,
    CoordinatorUnavailable,
    CoordinatorTimeout,
    CoordinatorInvalid,
    CoordinatorUnimplemented,
    CoordinatorInternal,
}

impl MeshTransportStartupFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "invalid-identity",
            Self::InheritedDescriptor => "inherited-descriptor",
            Self::AmbientEnvironment => "ambient-environment",
            Self::ThreadConfinement => "thread-confinement",
            Self::BootstrapIo => "bootstrap-io",
            Self::InvalidBootstrap => "invalid-bootstrap",
            Self::EnrollmentIo => "enrollment-io",
            Self::InvalidEnrollment => "invalid-enrollment",
            Self::ResolverInitialization => "resolver-initialization",
            Self::CoordinatorResolution => "coordinator-resolution",
            Self::CoordinatorSetup => "coordinator-setup",
            Self::DerpMap => "derp-map",
            Self::TransportResolution => "transport-resolution",
            Self::PrivilegeConfinement => "privilege-confinement",
            Self::FilesystemConfinement => "filesystem-confinement",
            Self::SyscallConfinement => "syscall-confinement",
            Self::TransportSetup => "transport-setup",
            Self::StatusIo => "status-io",
            Self::Protocol => "protocol",
            Self::CoordinatorUnauthenticated => "coordinator-unauthenticated",
            Self::CoordinatorPermissionDenied => "coordinator-permission-denied",
            Self::CoordinatorUnavailable => "coordinator-unavailable",
            Self::CoordinatorTimeout => "coordinator-timeout",
            Self::CoordinatorInvalid => "coordinator-invalid",
            Self::CoordinatorUnimplemented => "coordinator-unimplemented",
            Self::CoordinatorInternal => "coordinator-internal",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidIdentity => 80,
            Self::InheritedDescriptor => 81,
            Self::AmbientEnvironment => 82,
            Self::ThreadConfinement => 83,
            Self::BootstrapIo => 84,
            Self::InvalidBootstrap => 85,
            Self::EnrollmentIo => 86,
            Self::InvalidEnrollment => 87,
            Self::ResolverInitialization => 88,
            Self::CoordinatorResolution => 89,
            Self::CoordinatorSetup => 90,
            Self::DerpMap => 91,
            Self::TransportResolution => 92,
            Self::PrivilegeConfinement => 93,
            Self::FilesystemConfinement => 94,
            Self::SyscallConfinement => 95,
            Self::TransportSetup => 96,
            Self::StatusIo => 97,
            Self::Protocol => 98,
            Self::CoordinatorUnauthenticated => 99,
            Self::CoordinatorPermissionDenied => 100,
            Self::CoordinatorUnavailable => 101,
            Self::CoordinatorTimeout => 102,
            Self::CoordinatorInvalid => 103,
            Self::CoordinatorUnimplemented => 104,
            Self::CoordinatorInternal => 105,
        }
    }

    pub(crate) fn runner_error_code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "mesh_transport_invalid_identity",
            Self::InheritedDescriptor => "mesh_transport_inherited_descriptor",
            Self::AmbientEnvironment => "mesh_transport_ambient_environment",
            Self::ThreadConfinement => "mesh_transport_thread_confinement",
            Self::BootstrapIo => "mesh_transport_bootstrap_io",
            Self::InvalidBootstrap => "mesh_transport_invalid_bootstrap",
            Self::EnrollmentIo => "mesh_transport_enrollment_io",
            Self::InvalidEnrollment => "mesh_transport_invalid_enrollment",
            Self::ResolverInitialization => "mesh_transport_resolver_initialization",
            Self::CoordinatorResolution => "mesh_transport_coordinator_resolution",
            Self::CoordinatorSetup => "mesh_transport_coordinator_setup",
            Self::DerpMap => "mesh_transport_derp_map",
            Self::TransportResolution => "mesh_transport_transport_resolution",
            Self::PrivilegeConfinement => "mesh_transport_privilege_confinement",
            Self::FilesystemConfinement => "mesh_transport_filesystem_confinement",
            Self::SyscallConfinement => "mesh_transport_syscall_confinement",
            Self::TransportSetup => "mesh_transport_transport_setup",
            Self::StatusIo => "mesh_transport_status_io",
            Self::Protocol => "mesh_transport_protocol",
            Self::CoordinatorUnauthenticated => "mesh_transport_coordinator_unauthenticated",
            Self::CoordinatorPermissionDenied => "mesh_transport_coordinator_permission_denied",
            Self::CoordinatorUnavailable => "mesh_transport_coordinator_unavailable",
            Self::CoordinatorTimeout => "mesh_transport_coordinator_timeout",
            Self::CoordinatorInvalid => "mesh_transport_coordinator_invalid",
            Self::CoordinatorUnimplemented => "mesh_transport_coordinator_unimplemented",
            Self::CoordinatorInternal => "mesh_transport_coordinator_internal",
        }
    }

    pub fn from_exit_code(code: i32) -> Option<Self> {
        match code {
            80 => Some(Self::InvalidIdentity),
            81 => Some(Self::InheritedDescriptor),
            82 => Some(Self::AmbientEnvironment),
            83 => Some(Self::ThreadConfinement),
            84 => Some(Self::BootstrapIo),
            85 => Some(Self::InvalidBootstrap),
            86 => Some(Self::EnrollmentIo),
            87 => Some(Self::InvalidEnrollment),
            88 => Some(Self::ResolverInitialization),
            89 => Some(Self::CoordinatorResolution),
            90 => Some(Self::CoordinatorSetup),
            91 => Some(Self::DerpMap),
            92 => Some(Self::TransportResolution),
            93 => Some(Self::PrivilegeConfinement),
            94 => Some(Self::FilesystemConfinement),
            95 => Some(Self::SyscallConfinement),
            96 => Some(Self::TransportSetup),
            97 => Some(Self::StatusIo),
            98 => Some(Self::Protocol),
            99 => Some(Self::CoordinatorUnauthenticated),
            100 => Some(Self::CoordinatorPermissionDenied),
            101 => Some(Self::CoordinatorUnavailable),
            102 => Some(Self::CoordinatorTimeout),
            103 => Some(Self::CoordinatorInvalid),
            104 => Some(Self::CoordinatorUnimplemented),
            105 => Some(Self::CoordinatorInternal),
            _ => None,
        }
    }

    fn message(self) -> Vec<u8> {
        format!("CWMESH1 failed-{}\n", self.code()).into_bytes()
    }
}

const ALL_FAILURES: [MeshTransportStartupFailure; 26] = [
    MeshTransportStartupFailure::InvalidIdentity,
    MeshTransportStartupFailure::InheritedDescriptor,
    MeshTransportStartupFailure::AmbientEnvironment,
    MeshTransportStartupFailure::ThreadConfinement,
    MeshTransportStartupFailure::BootstrapIo,
    MeshTransportStartupFailure::InvalidBootstrap,
    MeshTransportStartupFailure::EnrollmentIo,
    MeshTransportStartupFailure::InvalidEnrollment,
    MeshTransportStartupFailure::ResolverInitialization,
    MeshTransportStartupFailure::CoordinatorResolution,
    MeshTransportStartupFailure::CoordinatorSetup,
    MeshTransportStartupFailure::DerpMap,
    MeshTransportStartupFailure::TransportResolution,
    MeshTransportStartupFailure::PrivilegeConfinement,
    MeshTransportStartupFailure::FilesystemConfinement,
    MeshTransportStartupFailure::SyscallConfinement,
    MeshTransportStartupFailure::TransportSetup,
    MeshTransportStartupFailure::StatusIo,
    MeshTransportStartupFailure::Protocol,
    MeshTransportStartupFailure::CoordinatorUnauthenticated,
    MeshTransportStartupFailure::CoordinatorPermissionDenied,
    MeshTransportStartupFailure::CoordinatorUnavailable,
    MeshTransportStartupFailure::CoordinatorTimeout,
    MeshTransportStartupFailure::CoordinatorInvalid,
    MeshTransportStartupFailure::CoordinatorUnimplemented,
    MeshTransportStartupFailure::CoordinatorInternal,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTransportStartupStatus {
    Confined,
    Ready,
    Failed(MeshTransportStartupFailure),
}

pub fn decode_mesh_transport_startup_status(bytes: &[u8]) -> Option<MeshTransportStartupStatus> {
    if bytes == MESH_TRANSPORT_CONFINED_MESSAGE {
        return Some(MeshTransportStartupStatus::Confined);
    }
    if bytes == MESH_TRANSPORT_READY_MESSAGE {
        return Some(MeshTransportStartupStatus::Ready);
    }
    ALL_FAILURES
        .into_iter()
        .find(|failure| bytes == failure.message())
        .map(MeshTransportStartupStatus::Failed)
}

#[derive(Debug, thiserror::Error)]
pub enum MeshTransportProcessError {
    #[error("Mesh transport identity is invalid")]
    InvalidIdentity,
    #[error("Mesh transport inherited descriptor is invalid")]
    InheritedDescriptor,
    #[error("Mesh transport refuses an ambient environment")]
    AmbientEnvironment,
    #[error("Mesh transport requires an exact single-threaded runtime")]
    ThreadConfinement,
    #[error("Mesh transport bootstrap I/O failed")]
    BootstrapIo,
    #[error("Mesh transport bootstrap is invalid")]
    InvalidBootstrap,
    #[error("Mesh transport enrollment I/O failed")]
    EnrollmentIo,
    #[error("Mesh transport enrollment is invalid")]
    InvalidEnrollment,
    #[error("Mesh transport resolver initialization failed")]
    ResolverInitialization,
    #[error("Mesh coordinator resolution failed")]
    CoordinatorResolution,
    #[error("Mesh coordinator setup failed")]
    CoordinatorSetup,
    #[error("Mesh DERP map is invalid")]
    DerpMap,
    #[error("Mesh transport endpoint resolution failed")]
    TransportResolution,
    #[error("Mesh transport privilege confinement failed")]
    PrivilegeConfinement,
    #[error("Mesh transport filesystem confinement failed")]
    FilesystemConfinement,
    #[error("Mesh transport syscall confinement failed")]
    SyscallConfinement,
    #[error("Mesh encrypted transport setup failed")]
    TransportSetup,
    #[error("Mesh transport startup-status I/O failed")]
    StatusIo,
    #[error("Mesh transport private protocol failed")]
    Protocol,
    #[error("Mesh coordinator authentication failed")]
    CoordinatorUnauthenticated,
    #[error("Mesh coordinator permission was denied")]
    CoordinatorPermissionDenied,
    #[error("Mesh coordinator was unavailable")]
    CoordinatorUnavailable,
    #[error("Mesh coordinator setup timed out")]
    CoordinatorTimeout,
    #[error("Mesh coordinator setup request was invalid")]
    CoordinatorInvalid,
    #[error("Mesh coordinator setup is unimplemented")]
    CoordinatorUnimplemented,
    #[error("Mesh coordinator setup failed internally")]
    CoordinatorInternal,
}

impl MeshTransportProcessError {
    pub fn exit_code(&self) -> i32 {
        self.startup_failure().exit_code()
    }

    fn startup_failure(&self) -> MeshTransportStartupFailure {
        match self {
            Self::InvalidIdentity => MeshTransportStartupFailure::InvalidIdentity,
            Self::InheritedDescriptor => MeshTransportStartupFailure::InheritedDescriptor,
            Self::AmbientEnvironment => MeshTransportStartupFailure::AmbientEnvironment,
            Self::ThreadConfinement => MeshTransportStartupFailure::ThreadConfinement,
            Self::BootstrapIo => MeshTransportStartupFailure::BootstrapIo,
            Self::InvalidBootstrap => MeshTransportStartupFailure::InvalidBootstrap,
            Self::EnrollmentIo => MeshTransportStartupFailure::EnrollmentIo,
            Self::InvalidEnrollment => MeshTransportStartupFailure::InvalidEnrollment,
            Self::ResolverInitialization => MeshTransportStartupFailure::ResolverInitialization,
            Self::CoordinatorResolution => MeshTransportStartupFailure::CoordinatorResolution,
            Self::CoordinatorSetup => MeshTransportStartupFailure::CoordinatorSetup,
            Self::DerpMap => MeshTransportStartupFailure::DerpMap,
            Self::TransportResolution => MeshTransportStartupFailure::TransportResolution,
            Self::PrivilegeConfinement => MeshTransportStartupFailure::PrivilegeConfinement,
            Self::FilesystemConfinement => MeshTransportStartupFailure::FilesystemConfinement,
            Self::SyscallConfinement => MeshTransportStartupFailure::SyscallConfinement,
            Self::TransportSetup => MeshTransportStartupFailure::TransportSetup,
            Self::StatusIo => MeshTransportStartupFailure::StatusIo,
            Self::Protocol => MeshTransportStartupFailure::Protocol,
            Self::CoordinatorUnauthenticated => {
                MeshTransportStartupFailure::CoordinatorUnauthenticated
            }
            Self::CoordinatorPermissionDenied => {
                MeshTransportStartupFailure::CoordinatorPermissionDenied
            }
            Self::CoordinatorUnavailable => MeshTransportStartupFailure::CoordinatorUnavailable,
            Self::CoordinatorTimeout => MeshTransportStartupFailure::CoordinatorTimeout,
            Self::CoordinatorInvalid => MeshTransportStartupFailure::CoordinatorInvalid,
            Self::CoordinatorUnimplemented => MeshTransportStartupFailure::CoordinatorUnimplemented,
            Self::CoordinatorInternal => MeshTransportStartupFailure::CoordinatorInternal,
        }
    }
}

struct Bootstrap {
    attachment: MeshAttachment,
    submission_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
}

struct EndpointSpec {
    host: String,
    port: u16,
}

struct UnresolvedTransportPlan {
    relay: EndpointSpec,
    relay_transport: DerpTransport,
    preferred_derp: i32,
    stun: Vec<EndpointSpec>,
}

struct ResolvedTransportPlan {
    relay: DerpTarget,
    relay_addresses: Vec<SocketAddr>,
    preferred_derp: i32,
    stun_addresses: Vec<SocketAddr>,
}

struct PreparedMesh {
    bootstrap: Bootstrap,
    coordinator: MeshCoordinatorPeerSession,
    transport: ResolvedTransportPlan,
    wireguard_secret: StaticSecret,
    disco_private: DiscoPrivate,
}

/// Encode the private, generation-bound process bootstrap. The attachment is
/// non-secret; the submission key is ephemeral and never persisted.
pub fn encode_mesh_transport_bootstrap(
    environment_id: Uuid,
    generation: u64,
    attachment: &MeshAttachment,
    submission_key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, MeshTransportProcessError> {
    validate_identity(environment_id, generation)?;
    attachment
        .validate()
        .map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    if submission_key.iter().all(|byte| *byte == 0) {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let body_len = attachment
        .mesh_url
        .len()
        .checked_add(attachment.organization_id.len())
        .and_then(|length| length.checked_add(attachment.network_id.len()))
        .and_then(|length| length.checked_add(attachment.node_name.len()))
        .and_then(|length| length.checked_add(attachment.guest_ports.len() * 2))
        .ok_or(MeshTransportProcessError::InvalidBootstrap)?;
    let total_len = BOOTSTRAP_HEADER_LEN
        .checked_add(body_len)
        .filter(|length| *length <= MAX_BOOTSTRAP_BYTES)
        .ok_or(MeshTransportProcessError::InvalidBootstrap)?;
    let mut bytes = Zeroizing::new(vec![0_u8; total_len]);
    bytes[..8].copy_from_slice(BOOTSTRAP_MAGIC);
    bytes[8..24].copy_from_slice(environment_id.as_bytes());
    bytes[24..32].copy_from_slice(&generation.to_be_bytes());
    bytes[32..64].copy_from_slice(submission_key);
    bytes[BOOTSTRAP_TOTAL_LEN_OFFSET..BOOTSTRAP_TOTAL_LEN_OFFSET + 4]
        .copy_from_slice(&(total_len as u32).to_be_bytes());
    write_u16(
        &mut bytes,
        BOOTSTRAP_MESH_URL_LEN_OFFSET,
        attachment.mesh_url.len(),
    )?;
    write_u16(
        &mut bytes,
        BOOTSTRAP_ORGANIZATION_LEN_OFFSET,
        attachment.organization_id.len(),
    )?;
    write_u16(
        &mut bytes,
        BOOTSTRAP_NETWORK_LEN_OFFSET,
        attachment.network_id.len(),
    )?;
    write_u16(
        &mut bytes,
        BOOTSTRAP_NODE_LEN_OFFSET,
        attachment.node_name.len(),
    )?;
    write_u16(
        &mut bytes,
        BOOTSTRAP_PORT_COUNT_OFFSET,
        attachment.guest_ports.len(),
    )?;
    let mut offset = BOOTSTRAP_HEADER_LEN;
    for field in [
        attachment.mesh_url.as_bytes(),
        attachment.organization_id.as_bytes(),
        attachment.network_id.as_bytes(),
        attachment.node_name.as_bytes(),
    ] {
        bytes[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    for port in &attachment.guest_ports {
        bytes[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
        offset += 2;
    }
    Ok(bytes)
}

/// Encode the one-shot enrollment record transferred by the isolated owner.
/// The returned buffer zeroizes on drop and must be followed by write-half
/// shutdown so the child can reject trailing data.
pub fn encode_mesh_transport_enrollment(
    enrollment: &str,
) -> Result<Zeroizing<Vec<u8>>, MeshTransportProcessError> {
    validate_enrollment(enrollment)?;
    let mut bytes = Zeroizing::new(vec![0_u8; ENROLLMENT_HEADER_LEN + enrollment.len()]);
    bytes[..8].copy_from_slice(ENROLLMENT_MAGIC);
    bytes[8..10].copy_from_slice(&(enrollment.len() as u16).to_be_bytes());
    bytes[ENROLLMENT_HEADER_LEN..].copy_from_slice(enrollment.as_bytes());
    Ok(bytes)
}

/// Entrypoint used only by the hidden `cw` Mesh transport command.
pub async fn run_inherited_mesh_transport(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), MeshTransportProcessError> {
    let mut control = inherited_std_unix_stream(MESH_TRANSPORT_BOOTSTRAP_FD)?;
    let mut enrollment = inherited_std_unix_stream(MESH_TRANSPORT_ENROLLMENT_FD)?;
    configure_handshake_stream(&control, HANDSHAKE_TIMEOUT, || {
        MeshTransportProcessError::BootstrapIo
    })?;
    configure_handshake_stream(&enrollment, NETWORK_SETUP_TIMEOUT, || {
        MeshTransportProcessError::EnrollmentIo
    })?;

    let bootstrap = match prepare_mesh_bootstrap(&mut control, environment_id, generation) {
        Ok(bootstrap) => bootstrap,
        Err(error) => return fail_startup(&control, error),
    };
    if let Err(error) = await_confinement_admission(&mut control) {
        return fail_startup(&control, error);
    }
    if lock_process_privileges().is_err() {
        return fail_startup(&control, MeshTransportProcessError::PrivilegeConfinement);
    }
    if write_status(&control, MESH_TRANSPORT_CONFINED_MESSAGE).is_err() {
        return fail_startup(&control, MeshTransportProcessError::StatusIo);
    }
    // Enrollment and generated transport keys enter memory only after the
    // runner has admitted the exact process and the child is non-dumpable.
    let prepared = match prepare_mesh(bootstrap, &mut enrollment).await {
        Ok(prepared) => prepared,
        Err(error) => return fail_startup(&control, error),
    };
    drop(enrollment);
    if install_deny_all_filesystem_domain().is_err() {
        return fail_startup(&control, MeshTransportProcessError::FilesystemConfinement);
    }
    if install_inet_and_unix_stream_pair_syscalls(MESH_DENIED_SYSCALLS, MESH_ARCH_DENIED_SYSCALLS)
        .is_err()
    {
        return fail_startup(&control, MeshTransportProcessError::SyscallConfinement);
    }

    control
        .set_read_timeout(None)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    control
        .set_write_timeout(None)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let liveness = control
        .try_clone()
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let status = control
        .try_clone()
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    control
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    liveness
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    status
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let control = tokio::net::UnixStream::from_std(control)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let liveness = tokio::net::UnixStream::from_std(liveness)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let mut status = tokio::net::UnixStream::from_std(status)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;

    let runtime = match build_runtime(prepared, control, environment_id, generation).await {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = status.write_all(&error.startup_failure().message()).await;
            return Err(error);
        }
    };
    status
        .write_all(MESH_TRANSPORT_READY_MESSAGE)
        .await
        .map_err(|_| MeshTransportProcessError::StatusIo)?;
    status
        .flush()
        .await
        .map_err(|_| MeshTransportProcessError::StatusIo)?;
    drop(status);
    runtime.run(liveness).await
}

/// Checked-in qualified-host seam for proving the production runner and guest
/// ingress lifecycle without replacing the separately tested encrypted Mesh
/// implementation. This entrypoint is not wired into the product CLI.
#[doc(hidden)]
pub async fn run_inherited_mesh_transport_fixture(
    environment_id: Uuid,
    generation: u64,
    request: &'static [u8],
    response: &'static [u8],
    acknowledgement: &'static [u8],
) -> Result<(), MeshTransportProcessError> {
    if request.is_empty()
        || response.is_empty()
        || acknowledgement.is_empty()
        || request.len() > 256
        || response.len() > 256
        || acknowledgement.len() > 256
    {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let mut control = inherited_std_unix_stream(MESH_TRANSPORT_BOOTSTRAP_FD)?;
    let mut enrollment = inherited_std_unix_stream(MESH_TRANSPORT_ENROLLMENT_FD)?;
    configure_handshake_stream(&control, HANDSHAKE_TIMEOUT, || {
        MeshTransportProcessError::BootstrapIo
    })?;
    configure_handshake_stream(&enrollment, NETWORK_SETUP_TIMEOUT, || {
        MeshTransportProcessError::EnrollmentIo
    })?;

    let bootstrap = match prepare_mesh_bootstrap(&mut control, environment_id, generation) {
        Ok(bootstrap) => bootstrap,
        Err(error) => return fail_startup(&control, error),
    };
    if let Err(error) = await_confinement_admission(&mut control) {
        return fail_startup(&control, error);
    }
    if lock_process_privileges().is_err() {
        return fail_startup(&control, MeshTransportProcessError::PrivilegeConfinement);
    }
    if write_status(&control, MESH_TRANSPORT_CONFINED_MESSAGE).is_err() {
        return fail_startup(&control, MeshTransportProcessError::StatusIo);
    }
    let enrollment_code = match read_enrollment(&mut enrollment) {
        Ok(enrollment) => enrollment,
        Err(error) => return fail_startup(&control, error),
    };
    let expected_enrollment =
        crate::mesh_enrollment::qualified_host_fixture_enrollment(environment_id, generation);
    if enrollment_code.as_str() != expected_enrollment.as_str() {
        return fail_startup(&control, MeshTransportProcessError::InvalidEnrollment);
    }
    drop(enrollment_code);
    drop(expected_enrollment);
    drop(enrollment);
    if install_deny_all_filesystem_domain().is_err() {
        return fail_startup(&control, MeshTransportProcessError::FilesystemConfinement);
    }
    if install_inet_and_unix_stream_pair_syscalls(MESH_DENIED_SYSCALLS, MESH_ARCH_DENIED_SYSCALLS)
        .is_err()
    {
        return fail_startup(&control, MeshTransportProcessError::SyscallConfinement);
    }
    let guest_port = bootstrap
        .attachment
        .guest_ports
        .first()
        .copied()
        .ok_or(MeshTransportProcessError::InvalidBootstrap)?;

    control
        .set_read_timeout(None)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    control
        .set_write_timeout(None)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let liveness = control
        .try_clone()
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let startup_liveness = control
        .try_clone()
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    control
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    liveness
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    startup_liveness
        .set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let mut control = tokio::net::UnixStream::from_std(control)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let liveness = tokio::net::UnixStream::from_std(liveness)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let startup_liveness = tokio::net::UnixStream::from_std(startup_liveness)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    write_status_frame(&mut control, MESH_TRANSPORT_READY_MESSAGE).await?;
    let mut submitter = MeshIngressSubmitter::new(
        control,
        environment_id,
        generation,
        bootstrap.submission_key,
    )?;
    let round_trip = async {
        loop {
            if mesh_fixture_round_trip(
                &mut submitter,
                guest_port,
                request,
                response,
                acknowledgement,
            )
            .await?
            {
                return Ok::<(), MeshTransportProcessError>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::select! {
        parent = monitor_parent(startup_liveness) => return parent,
        result = round_trip => result?,
    }
    monitor_parent(liveness).await
}

async fn mesh_fixture_round_trip(
    submitter: &mut MeshIngressSubmitter,
    guest_port: u16,
    request: &[u8],
    expected_response: &[u8],
    acknowledgement: &[u8],
) -> Result<bool, MeshTransportProcessError> {
    let (published, peer) =
        StdUnixStream::pair().map_err(|_| MeshTransportProcessError::Protocol)?;
    peer.set_nonblocking(true)
        .map_err(|_| MeshTransportProcessError::Protocol)?;
    submitter.submit(guest_port, &published).await?;
    drop(published);
    let mut peer =
        tokio::net::UnixStream::from_std(peer).map_err(|_| MeshTransportProcessError::Protocol)?;
    let mut response = vec![0_u8; expected_response.len()];
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        peer.write_all(request).await?;
        peer.read_exact(&mut response).await?;
        if response != expected_response {
            return Ok::<bool, std::io::Error>(false);
        }
        peer.write_all(acknowledgement).await?;
        peer.shutdown().await?;
        Ok::<bool, std::io::Error>(true)
    })
    .await;
    match result {
        Ok(Ok(true)) => Ok(true),
        Ok(Ok(false)) => Err(MeshTransportProcessError::Protocol),
        Ok(Err(_)) | Err(_) => Ok(false),
    }
}

async fn write_status_frame(
    control: &mut tokio::net::UnixStream,
    message: &[u8],
) -> Result<(), MeshTransportProcessError> {
    control
        .write_all(message)
        .await
        .map_err(|_| MeshTransportProcessError::StatusIo)?;
    control
        .flush()
        .await
        .map_err(|_| MeshTransportProcessError::StatusIo)
}

struct MeshRuntime {
    coordinator: MeshCoordinatorPeerSession,
    conn: Arc<Conn>,
    bridge: MeshIngressBridge,
    direct_udp: direct_udp::Handle,
}

impl MeshRuntime {
    async fn run(self, liveness: tokio::net::UnixStream) -> Result<(), MeshTransportProcessError> {
        let Self {
            mut coordinator,
            conn,
            bridge,
            direct_udp,
        } = self;
        let _direct_udp = direct_udp;
        let (node_tx, node_rx) = mpsc::unbounded_channel();
        conn.set_node_callback(move |node| {
            let _ = node_tx.send(node.clone());
        });
        let (derp_map_tx, mut derp_map_rx) = mpsc::unbounded_channel();
        let update_conn = Arc::clone(&conn);
        let handlers = CoordinatorHandlers {
            on_peers: move |nodes| {
                let _ = update_conn.update_peers(nodes);
            },
            on_derp_map: move |_| {
                let _ = derp_map_tx.send(());
            },
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            RuntimeTaskExit::Coordinator(
                coordinator
                    .run_with_node_updates(node_rx, handlers)
                    .await
                    .is_ok(),
            )
        });
        tasks.spawn(async move {
            let _ = bridge.run(shutdown_rx).await;
            RuntimeTaskExit::Bridge
        });
        tasks.spawn(async move { RuntimeTaskExit::Parent(monitor_parent(liveness).await.is_ok()) });

        let result = tokio::select! {
            Some(()) = derp_map_rx.recv() => {
                Err(MeshTransportProcessError::Protocol)
            }
            completed = tasks.join_next() => match completed {
                Some(Ok(RuntimeTaskExit::Coordinator(true)))
                | Some(Ok(RuntimeTaskExit::Parent(true))) => Ok(()),
                Some(Ok(RuntimeTaskExit::Coordinator(false)))
                | Some(Ok(RuntimeTaskExit::Parent(false)))
                | Some(Err(_))
                | None => Err(MeshTransportProcessError::Protocol),
                Some(Ok(RuntimeTaskExit::Bridge)) => {
                    Err(MeshTransportProcessError::TransportSetup)
                }
            }
        };
        let _ = shutdown_tx.send(true);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        conn.clear_node_callback();
        conn.close();
        result
    }
}

enum RuntimeTaskExit {
    Coordinator(bool),
    Bridge,
    Parent(bool),
}

async fn build_runtime(
    prepared: PreparedMesh,
    control: tokio::net::UnixStream,
    environment_id: Uuid,
    generation: u64,
) -> Result<MeshRuntime, MeshTransportProcessError> {
    let fallback = tokio::time::timeout(
        NETWORK_SETUP_TIMEOUT,
        connect_derp_transport_resolved(
            &prepared.transport.relay,
            prepared.transport.relay_addresses.clone(),
            &prepared.wireguard_secret,
        ),
    )
    .await
    .map_err(|_| MeshTransportProcessError::TransportSetup)?
    .map_err(|_| MeshTransportProcessError::TransportSetup)?;
    let local_node_key =
        NodePublic::from_raw(PublicKey::from(&prepared.wireguard_secret).to_bytes());
    let (transport, direct_udp) = tokio::time::timeout(
        NETWORK_SETUP_TIMEOUT,
        direct_udp::wrap_transport(
            fallback,
            direct_udp::Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                Vec::new(),
                local_node_key,
                prepared.disco_private.clone(),
            )
            .with_stun_servers(prepared.transport.stun_addresses),
        ),
    )
    .await
    .map_err(|_| MeshTransportProcessError::TransportSetup)?
    .map_err(|_| MeshTransportProcessError::TransportSetup)?;
    let mut options = ConnOptions::new(environment_id);
    options.addresses = vec![prefix_from_uuid(&environment_id)];
    options.endpoints = direct_udp.advertised_endpoints();
    options.private_key = Some(prepared.wireguard_secret);
    options.disco_private = Some(prepared.disco_private);
    let conn = Arc::new(
        Conn::new(options, transport).map_err(|_| MeshTransportProcessError::TransportSetup)?,
    );
    conn.set_preferred_derp(prepared.transport.preferred_derp);
    let submitter = MeshIngressSubmitter::new(
        control,
        environment_id,
        generation,
        prepared.bootstrap.submission_key,
    )?;
    let bridge = MeshIngressBridge::bind_isolated(
        Arc::clone(&conn),
        &prepared.bootstrap.attachment.guest_ports,
        submitter,
    )
    .await?;
    Ok(MeshRuntime {
        coordinator: prepared.coordinator,
        conn,
        bridge,
        direct_udp,
    })
}

async fn monitor_parent(
    mut liveness: tokio::net::UnixStream,
) -> Result<(), MeshTransportProcessError> {
    let mut byte = [0_u8; 1];
    match liveness.read(&mut byte).await {
        Ok(0) => Ok(()),
        Ok(_) | Err(_) => Err(MeshTransportProcessError::Protocol),
    }
}

fn prepare_mesh_bootstrap(
    control: &mut StdUnixStream,
    environment_id: Uuid,
    generation: u64,
) -> Result<Bootstrap, MeshTransportProcessError> {
    validate_identity(environment_id, generation)?;
    if std::env::vars_os().next().is_some() {
        return Err(MeshTransportProcessError::AmbientEnvironment);
    }
    require_single_threaded_process().map_err(|_| MeshTransportProcessError::ThreadConfinement)?;
    let bootstrap = read_bootstrap(control, environment_id, generation)?;
    write_status(control, MESH_TRANSPORT_PREPARED_MESSAGE)
        .map_err(|_| MeshTransportProcessError::StatusIo)?;
    Ok(bootstrap)
}

async fn prepare_mesh(
    bootstrap: Bootstrap,
    enrollment: &mut StdUnixStream,
) -> Result<PreparedMesh, MeshTransportProcessError> {
    let enrollment = read_enrollment(enrollment)?;
    let resolver = SystemDnsResolver::from_system_config()
        .map_err(|_| MeshTransportProcessError::ResolverInitialization)?;
    let coordinator_addresses = resolve_url(&bootstrap.attachment.mesh_url, &resolver)
        .await
        .map_err(|_| MeshTransportProcessError::CoordinatorResolution)?;
    let mut coordinator = MeshCoordinatorPeerSession::connect_resolved_with_setup_timeout(
        &bootstrap.attachment.mesh_url,
        enrollment.as_str(),
        MeshCoordinateIdentity::peer(
            bootstrap.attachment.organization_id.clone(),
            bootstrap.attachment.network_id.clone(),
        ),
        coordinator_addresses,
        NETWORK_SETUP_TIMEOUT,
    )
    .await
    .map_err(coordinator_setup_error)?;
    drop(enrollment);
    let map = coordinator
        .take_setup_derp_map()
        .map_err(|_| MeshTransportProcessError::DerpMap)?;
    let unresolved = parse_derp_map(&map, &bootstrap.attachment.mesh_url)?;
    let transport = tokio::time::timeout(
        NETWORK_SETUP_TIMEOUT,
        resolve_transport_plan(unresolved, &resolver),
    )
    .await
    .map_err(|_| MeshTransportProcessError::TransportResolution)??;
    drop(resolver);
    let wireguard_secret = StaticSecret::random_from_rng(OsRng);
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    require_single_threaded_process().map_err(|_| MeshTransportProcessError::ThreadConfinement)?;
    Ok(PreparedMesh {
        bootstrap,
        coordinator,
        transport,
        wireguard_secret,
        disco_private,
    })
}

fn coordinator_setup_error(error: CoordinatorError) -> MeshTransportProcessError {
    match error {
        CoordinatorError::Connect(error) => match error.code {
            ErrorCode::Unauthenticated => MeshTransportProcessError::CoordinatorUnauthenticated,
            ErrorCode::PermissionDenied => MeshTransportProcessError::CoordinatorPermissionDenied,
            ErrorCode::Unavailable => MeshTransportProcessError::CoordinatorUnavailable,
            ErrorCode::DeadlineExceeded => MeshTransportProcessError::CoordinatorTimeout,
            ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition => {
                MeshTransportProcessError::CoordinatorInvalid
            }
            ErrorCode::Unimplemented => MeshTransportProcessError::CoordinatorUnimplemented,
            ErrorCode::Internal => MeshTransportProcessError::CoordinatorInternal,
            _ => MeshTransportProcessError::CoordinatorSetup,
        },
        CoordinatorError::SetupTimeout(_) => MeshTransportProcessError::CoordinatorTimeout,
        CoordinatorError::InvalidSetupResponse | CoordinatorError::Url(_) => {
            MeshTransportProcessError::CoordinatorInvalid
        }
        _ => MeshTransportProcessError::CoordinatorSetup,
    }
}

async fn resolve_transport_plan(
    unresolved: UnresolvedTransportPlan,
    resolver: &SystemDnsResolver,
) -> Result<ResolvedTransportPlan, MeshTransportProcessError> {
    let relay_addresses = resolve_endpoint(&unresolved.relay, resolver)
        .await
        .map_err(|_| MeshTransportProcessError::TransportResolution)?;
    let mut stun_addresses = Vec::new();
    for server in &unresolved.stun {
        for address in resolve_endpoint(server, resolver)
            .await
            .map_err(|_| MeshTransportProcessError::TransportResolution)?
        {
            if !stun_addresses.contains(&address) {
                if stun_addresses.len() >= MAX_RESOLVED_STUN_ENDPOINTS {
                    return Err(MeshTransportProcessError::TransportResolution);
                }
                stun_addresses.push(address);
            }
        }
    }
    Ok(ResolvedTransportPlan {
        relay: DerpTarget {
            host: unresolved.relay.host,
            port: unresolved.relay.port,
            transport: unresolved.relay_transport,
        },
        relay_addresses,
        preferred_derp: unresolved.preferred_derp,
        stun_addresses,
    })
}

async fn resolve_url(
    raw: &str,
    resolver: &SystemDnsResolver,
) -> Result<Vec<SocketAddr>, MeshTransportProcessError> {
    let url = Url::parse(raw).map_err(|_| MeshTransportProcessError::CoordinatorResolution)?;
    let port = url
        .port_or_known_default()
        .ok_or(MeshTransportProcessError::CoordinatorResolution)?;
    let host = url
        .host_str()
        .ok_or(MeshTransportProcessError::CoordinatorResolution)?;
    let host = Host::parse(host).map_err(|_| MeshTransportProcessError::CoordinatorResolution)?;
    resolve_host(host, port, resolver)
        .await
        .map_err(|_| MeshTransportProcessError::CoordinatorResolution)
}

async fn resolve_endpoint(
    endpoint: &EndpointSpec,
    resolver: &SystemDnsResolver,
) -> Result<Vec<SocketAddr>, MeshTransportProcessError> {
    let host =
        Host::parse(&endpoint.host).map_err(|_| MeshTransportProcessError::TransportResolution)?;
    resolve_host(host, endpoint.port, resolver).await
}

async fn resolve_host(
    host: Host<String>,
    port: u16,
    resolver: &SystemDnsResolver,
) -> Result<Vec<SocketAddr>, MeshTransportProcessError> {
    let addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(name) => resolver
            .resolve_host_addresses(&name)
            .await
            .map_err(|_| MeshTransportProcessError::TransportResolution)?,
    };
    if addresses.is_empty()
        || addresses.len() > MAX_RESOLVED_ENDPOINTS
        || addresses.iter().any(|address| match address {
            IpAddr::V4(address) => {
                address.is_unspecified() || address.is_multicast() || address.is_broadcast()
            }
            IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
        })
    {
        return Err(MeshTransportProcessError::TransportResolution);
    }
    let mut addresses = addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

fn parse_derp_map(
    map: &Value,
    mesh_url: &str,
) -> Result<UnresolvedTransportPlan, MeshTransportProcessError> {
    if serde_json::to_vec(map)
        .map_err(|_| MeshTransportProcessError::DerpMap)?
        .len()
        > MAX_DERP_MAP_BYTES
    {
        return Err(MeshTransportProcessError::DerpMap);
    }
    let regions = map
        .get("Regions")
        .and_then(Value::as_object)
        .filter(|regions| !regions.is_empty() && regions.len() <= MAX_DERP_REGIONS)
        .ok_or(MeshTransportProcessError::DerpMap)?;
    let allow_insecure = Url::parse(mesh_url)
        .ok()
        .and_then(|url| url.host().map(host_is_loopback))
        .unwrap_or(false);
    let mut region_keys = regions.keys().collect::<Vec<_>>();
    region_keys.sort();
    let mut relay = None;
    let mut stun = Vec::new();
    let mut node_count = 0_usize;
    for key in region_keys {
        let region = regions.get(key).ok_or(MeshTransportProcessError::DerpMap)?;
        let region_id = region
            .get("RegionID")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(MeshTransportProcessError::DerpMap)?;
        let nodes = region
            .get("Nodes")
            .and_then(Value::as_array)
            .ok_or(MeshTransportProcessError::DerpMap)?;
        node_count = node_count
            .checked_add(nodes.len())
            .filter(|count| *count <= MAX_DERP_NODES)
            .ok_or(MeshTransportProcessError::DerpMap)?;
        for node in nodes {
            let host = canonical_endpoint_host(
                node.get("HostName")
                    .and_then(Value::as_str)
                    .ok_or(MeshTransportProcessError::DerpMap)?,
            )?;
            let stun_only = node
                .get("STUNOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if stun_only {
                let port = node
                    .get("STUNPort")
                    .and_then(Value::as_i64)
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|value| *value != 0)
                    .ok_or(MeshTransportProcessError::DerpMap)?;
                let endpoint = EndpointSpec { host, port };
                if !stun.iter().any(|candidate: &EndpointSpec| {
                    candidate.host == endpoint.host && candidate.port == endpoint.port
                }) {
                    if stun.len() >= MAX_STUN_SERVERS {
                        return Err(MeshTransportProcessError::DerpMap);
                    }
                    stun.push(endpoint);
                }
                continue;
            }
            if relay.is_some() {
                continue;
            }
            let port = node
                .get("DERPPort")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value != 0)
                .unwrap_or(443);
            let insecure = node
                .get("InsecureForTests")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if insecure && (!allow_insecure || !endpoint_host_is_loopback(&host)) {
                return Err(MeshTransportProcessError::DerpMap);
            }
            relay = Some((
                EndpointSpec { host, port },
                DerpTransport::Tls {
                    skip_verify: insecure,
                },
                region_id,
            ));
        }
    }
    let (relay, relay_transport, preferred_derp) =
        relay.ok_or(MeshTransportProcessError::DerpMap)?;
    Ok(UnresolvedTransportPlan {
        relay,
        relay_transport,
        preferred_derp,
        stun,
    })
}

fn canonical_endpoint_host(raw: &str) -> Result<String, MeshTransportProcessError> {
    let raw = raw.trim().trim_end_matches('.');
    if raw.is_empty() || !raw.is_ascii() || raw.len() > MAX_ENDPOINT_HOST_BYTES {
        return Err(MeshTransportProcessError::DerpMap);
    }
    if let Ok(address) = raw.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    match Host::parse(raw).map_err(|_| MeshTransportProcessError::DerpMap)? {
        Host::Ipv4(_) | Host::Ipv6(_) => unreachable!("IP literals were parsed above"),
        Host::Domain(domain)
            if domain.is_ascii()
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }) =>
        {
            Ok(domain.to_ascii_lowercase())
        }
        Host::Domain(_) => Err(MeshTransportProcessError::DerpMap),
    }
}

fn endpoint_host_is_loopback(host: &str) -> bool {
    Host::parse(host).is_ok_and(host_is_loopback)
}

fn host_is_loopback<T: AsRef<str>>(host: Host<T>) -> bool {
    match host {
        Host::Domain(domain) => domain.as_ref().eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn await_confinement_admission(
    control: &mut StdUnixStream,
) -> Result<(), MeshTransportProcessError> {
    control
        .set_read_timeout(Some(MESH_TRANSPORT_CONFINEMENT_ADMISSION_TIMEOUT))
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let mut admission = [0_u8; MESH_TRANSPORT_CONFINE_MESSAGE.len()];
    control
        .read_exact(&mut admission)
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    if admission != MESH_TRANSPORT_CONFINE_MESSAGE {
        return Err(MeshTransportProcessError::Protocol);
    }
    Ok(())
}

fn read_bootstrap(
    stream: &mut StdUnixStream,
    expected_environment_id: Uuid,
    expected_generation: u64,
) -> Result<Bootstrap, MeshTransportProcessError> {
    let mut header = Zeroizing::new([0_u8; BOOTSTRAP_HEADER_LEN]);
    stream
        .read_exact(header.as_mut())
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    let total_len = usize::try_from(u32::from_be_bytes(
        header[BOOTSTRAP_TOTAL_LEN_OFFSET..BOOTSTRAP_TOTAL_LEN_OFFSET + 4]
            .try_into()
            .expect("fixed Mesh bootstrap total length"),
    ))
    .map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    if !(BOOTSTRAP_HEADER_LEN..=MAX_BOOTSTRAP_BYTES).contains(&total_len) {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; total_len]);
    bytes[..BOOTSTRAP_HEADER_LEN].copy_from_slice(header.as_ref());
    stream
        .read_exact(&mut bytes[BOOTSTRAP_HEADER_LEN..])
        .map_err(|_| MeshTransportProcessError::BootstrapIo)?;
    decode_bootstrap(&bytes, expected_environment_id, expected_generation)
}

fn decode_bootstrap(
    bytes: &[u8],
    expected_environment_id: Uuid,
    expected_generation: u64,
) -> Result<Bootstrap, MeshTransportProcessError> {
    validate_identity(expected_environment_id, expected_generation)?;
    if bytes.len() < BOOTSTRAP_HEADER_LEN
        || bytes.len() > MAX_BOOTSTRAP_BYTES
        || &bytes[..8] != BOOTSTRAP_MAGIC
        || bytes[BOOTSTRAP_RESERVED_OFFSET..BOOTSTRAP_HEADER_LEN]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let total_len = usize::try_from(u32::from_be_bytes(
        bytes[BOOTSTRAP_TOTAL_LEN_OFFSET..BOOTSTRAP_TOTAL_LEN_OFFSET + 4]
            .try_into()
            .expect("fixed Mesh bootstrap total length"),
    ))
    .map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    let environment_id =
        Uuid::from_slice(&bytes[8..24]).map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    let generation = u64::from_be_bytes(
        bytes[24..32]
            .try_into()
            .expect("fixed Mesh bootstrap generation"),
    );
    if total_len != bytes.len()
        || environment_id != expected_environment_id
        || generation != expected_generation
    {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let lengths = [
        read_u16(bytes, BOOTSTRAP_MESH_URL_LEN_OFFSET),
        read_u16(bytes, BOOTSTRAP_ORGANIZATION_LEN_OFFSET),
        read_u16(bytes, BOOTSTRAP_NETWORK_LEN_OFFSET),
        read_u16(bytes, BOOTSTRAP_NODE_LEN_OFFSET),
    ];
    let port_count = read_u16(bytes, BOOTSTRAP_PORT_COUNT_OFFSET);
    if port_count > MAX_MESH_INGRESS_PORTS {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let expected_body_len = lengths
        .iter()
        .try_fold(0_usize, |total, length| total.checked_add(*length))
        .and_then(|total| total.checked_add(port_count * 2))
        .ok_or(MeshTransportProcessError::InvalidBootstrap)?;
    if BOOTSTRAP_HEADER_LEN + expected_body_len != bytes.len() {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    let mut offset = BOOTSTRAP_HEADER_LEN;
    let mut next_string = |length: usize| {
        let value = std::str::from_utf8(&bytes[offset..offset + length])
            .map(str::to_owned)
            .map_err(|_| MeshTransportProcessError::InvalidBootstrap);
        offset += length;
        value
    };
    let mesh_url = next_string(lengths[0])?;
    let organization_id = next_string(lengths[1])?;
    let network_id = next_string(lengths[2])?;
    let node_name = next_string(lengths[3])?;
    let mut guest_ports = Vec::with_capacity(port_count);
    for _ in 0..port_count {
        guest_ports.push(u16::from_be_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("bounded Mesh bootstrap port"),
        ));
        offset += 2;
    }
    // Credential-store selection is intentionally absent from the transport
    // bootstrap. Only the enrollment broker needs that non-secret locator.
    let attachment = MeshAttachment::new(
        &mesh_url,
        &organization_id,
        &network_id,
        &node_name,
        guest_ports,
    )
    .map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    let mut submission_key = Zeroizing::new([0_u8; MESH_INGRESS_CONTROL_KEY_LEN]);
    submission_key.copy_from_slice(&bytes[32..64]);
    if submission_key.iter().all(|byte| *byte == 0) {
        return Err(MeshTransportProcessError::InvalidBootstrap);
    }
    Ok(Bootstrap {
        attachment,
        submission_key,
    })
}

fn read_enrollment(
    stream: &mut StdUnixStream,
) -> Result<Zeroizing<String>, MeshTransportProcessError> {
    let mut header = Zeroizing::new([0_u8; ENROLLMENT_HEADER_LEN]);
    stream
        .read_exact(header.as_mut())
        .map_err(|_| MeshTransportProcessError::EnrollmentIo)?;
    if &header[..8] != ENROLLMENT_MAGIC || header[10..].iter().any(|byte| *byte != 0) {
        return Err(MeshTransportProcessError::InvalidEnrollment);
    }
    let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
    if length == 0 || length > MAX_ENROLLMENT_BYTES {
        return Err(MeshTransportProcessError::InvalidEnrollment);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    stream
        .read_exact(bytes.as_mut())
        .map_err(|_| MeshTransportProcessError::EnrollmentIo)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .map_err(|_| MeshTransportProcessError::EnrollmentIo)?
        != 0
    {
        return Err(MeshTransportProcessError::InvalidEnrollment);
    }
    let value = String::from_utf8(bytes.to_vec())
        .map_err(|_| MeshTransportProcessError::InvalidEnrollment)?;
    validate_enrollment(&value)?;
    Ok(Zeroizing::new(value))
}

fn validate_enrollment(value: &str) -> Result<(), MeshTransportProcessError> {
    if value.len() <= "cw_enr_".len()
        || value.len() > MAX_ENROLLMENT_BYTES
        || !value.starts_with("cw_enr_")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(MeshTransportProcessError::InvalidEnrollment);
    }
    Ok(())
}

fn validate_identity(
    environment_id: Uuid,
    generation: u64,
) -> Result<(), MeshTransportProcessError> {
    if environment_id.is_nil() || generation == 0 {
        Err(MeshTransportProcessError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn write_u16(
    bytes: &mut [u8],
    offset: usize,
    value: usize,
) -> Result<(), MeshTransportProcessError> {
    let value = u16::try_from(value).map_err(|_| MeshTransportProcessError::InvalidBootstrap)?;
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

fn configure_handshake_stream(
    stream: &StdUnixStream,
    timeout: Duration,
    error: impl Fn() -> MeshTransportProcessError,
) -> Result<(), MeshTransportProcessError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| error())?;
    stream.set_write_timeout(Some(timeout)).map_err(|_| error())
}

fn inherited_std_unix_stream(
    descriptor: RawFd,
) -> Result<StdUnixStream, MeshTransportProcessError> {
    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 0
    {
        return Err(MeshTransportProcessError::InheritedDescriptor);
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
        return Err(MeshTransportProcessError::InheritedDescriptor);
    }
    // SAFETY: the hidden process owns each fixed descriptor exactly once after
    // exec, and this is its only conversion into an owned stream.
    Ok(unsafe { StdUnixStream::from_raw_fd(descriptor) })
}

fn socket_option(descriptor: RawFd, option: i32) -> Result<i32, MeshTransportProcessError> {
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
        return Err(MeshTransportProcessError::InheritedDescriptor);
    }
    Ok(value)
}

fn write_status(stream: &StdUnixStream, message: &[u8]) -> io::Result<()> {
    if message.is_empty()
        || message.len() > MESH_TRANSPORT_STATUS_MAX_BYTES
        || !message.ends_with(b"\n")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Mesh transport status message",
        ));
    }
    let mut stream = stream;
    stream.write_all(message)
}

fn fail_startup<T>(
    control: &StdUnixStream,
    error: MeshTransportProcessError,
) -> Result<T, MeshTransportProcessError> {
    let _ = write_status(control, &error.startup_failure().message());
    Err(error)
}

impl From<MeshTransportError> for MeshTransportProcessError {
    fn from(_: MeshTransportError) -> Self {
        Self::TransportSetup
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    fn attachment() -> MeshAttachment {
        MeshAttachment::new(
            "http://127.0.0.1:18090",
            "org-test",
            "network-test",
            "sandbox-test",
            [3_000, 8_080],
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_round_trips_exact_identity_attachment_and_key() {
        let (environment_id, generation) = identity();
        let key = [0x5a; MESH_INGRESS_CONTROL_KEY_LEN];
        let bytes =
            encode_mesh_transport_bootstrap(environment_id, generation, &attachment(), &key)
                .unwrap();
        let decoded = decode_bootstrap(&bytes, environment_id, generation).unwrap();
        assert_eq!(decoded.attachment, attachment());
        assert_eq!(decoded.submission_key.as_ref(), &key);

        assert!(decode_bootstrap(&bytes, environment_id, generation + 1).is_err());
        let mut malformed = bytes.clone();
        malformed[BOOTSTRAP_RESERVED_OFFSET] = 1;
        assert!(decode_bootstrap(&malformed, environment_id, generation).is_err());
    }

    #[test]
    fn enrollment_record_is_bounded_and_never_accepts_an_authorization_header() {
        let record = encode_mesh_transport_enrollment("cw_enr_synthetic-once").unwrap();
        assert_eq!(&record[..8], ENROLLMENT_MAGIC);
        assert!(encode_mesh_transport_enrollment("Bearer cw_enr_leak").is_err());
        assert!(encode_mesh_transport_enrollment("cw_enr_line\nbreak").is_err());
        assert!(encode_mesh_transport_enrollment("cw_enr_").is_err());
    }

    #[test]
    fn derp_map_requires_one_tls_relay_and_confines_insecure_mode_to_loopback() {
        let valid = serde_json::json!({
            "Regions": {
                "1": {
                    "RegionID": 1,
                    "Nodes": [
                        {
                            "HostName": "127.0.0.1",
                            "DERPPort": 18443,
                            "STUNPort": -1,
                            "InsecureForTests": true
                        },
                        {
                            "HostName": "stun.example.com",
                            "STUNOnly": true,
                            "STUNPort": 3478
                        }
                    ]
                }
            }
        });
        let plan = parse_derp_map(&valid, "http://127.0.0.1:18090").unwrap();
        assert_eq!(plan.relay.host, "127.0.0.1");
        assert_eq!(plan.relay.port, 18_443);
        assert_eq!(plan.preferred_derp, 1);
        assert_eq!(plan.stun.len(), 1);
        assert_eq!(
            plan.relay_transport,
            DerpTransport::Tls { skip_verify: true }
        );

        let remote_insecure = serde_json::json!({
            "Regions": {
                "1": {
                    "RegionID": 1,
                    "Nodes": [{
                        "HostName": "relay.example.com",
                        "DERPPort": 443,
                        "InsecureForTests": true
                    }]
                }
            }
        });
        assert!(parse_derp_map(&remote_insecure, "https://mesh.example.com").is_err());
        assert!(canonical_endpoint_host("stün.example.com").is_err());

        let relay = serde_json::json!({
            "HostName": "relay.example.com",
            "DERPPort": 443
        });
        let mut nodes = vec![relay];
        nodes.extend((0..MAX_STUN_SERVERS).map(|index| {
            serde_json::json!({
                "HostName": format!("stun-{index}.example.com"),
                "STUNOnly": true,
                "STUNPort": 3478
            })
        }));
        let at_limit = serde_json::json!({
            "Regions": {"1": {"RegionID": 1, "Nodes": nodes.clone()}}
        });
        assert!(parse_derp_map(&at_limit, "https://mesh.example.com").is_ok());
        nodes.push(serde_json::json!({
            "HostName": "one-too-many.example.com",
            "STUNOnly": true,
            "STUNPort": 3478
        }));
        let excessive = serde_json::json!({
            "Regions": {"1": {"RegionID": 1, "Nodes": nodes}}
        });
        assert!(parse_derp_map(&excessive, "https://mesh.example.com").is_err());
    }

    #[test]
    fn startup_status_and_exit_taxonomy_are_exact_and_bounded() {
        assert_eq!(
            decode_mesh_transport_startup_status(MESH_TRANSPORT_CONFINED_MESSAGE),
            Some(MeshTransportStartupStatus::Confined)
        );
        assert_eq!(
            decode_mesh_transport_startup_status(MESH_TRANSPORT_READY_MESSAGE),
            Some(MeshTransportStartupStatus::Ready)
        );
        assert_eq!(
            decode_mesh_transport_startup_status(MESH_TRANSPORT_PREPARED_MESSAGE),
            None
        );
        for (index, failure) in ALL_FAILURES.into_iter().enumerate() {
            assert!(failure.message().len() <= MESH_TRANSPORT_STATUS_MAX_BYTES);
            assert_eq!(failure.exit_code(), 80 + index as i32);
            assert_eq!(
                decode_mesh_transport_startup_status(&failure.message()),
                Some(MeshTransportStartupStatus::Failed(failure))
            );
            assert_eq!(
                MeshTransportStartupFailure::from_exit_code(failure.exit_code()),
                Some(failure)
            );
            assert!(failure.runner_error_code().len() <= 64);
            assert!(
                failure
                    .runner_error_code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }

    #[test]
    fn coordinator_setup_errors_map_only_closed_classes() {
        const CANARY: &str = "coordinator-private-message-must-not-escape";
        let classified = [
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::Unauthenticated,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorUnauthenticated,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::PermissionDenied,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorPermissionDenied,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::Unavailable,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorUnavailable,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorTimeout,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::InvalidArgument,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorInvalid,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::FailedPrecondition,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorInvalid,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::Unimplemented,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorUnimplemented,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::Internal,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorInternal,
            ),
            (
                CoordinatorError::SetupTimeout(Duration::from_secs(15)),
                MeshTransportStartupFailure::CoordinatorTimeout,
            ),
            (
                CoordinatorError::InvalidSetupResponse,
                MeshTransportStartupFailure::CoordinatorInvalid,
            ),
            (
                CoordinatorError::Url(CANARY.to_owned()),
                MeshTransportStartupFailure::CoordinatorInvalid,
            ),
            (
                CoordinatorError::Connect(connectrpc::ConnectError::new(
                    ErrorCode::ResourceExhausted,
                    CANARY,
                )),
                MeshTransportStartupFailure::CoordinatorSetup,
            ),
        ];
        for (error, expected) in classified {
            let mapped = coordinator_setup_error(error);
            assert_eq!(mapped.startup_failure(), expected);
            assert!(!mapped.to_string().contains(CANARY));
            assert!(
                !expected
                    .message()
                    .windows(CANARY.len())
                    .any(|value| value == CANARY.as_bytes())
            );
            assert!(!expected.runner_error_code().contains(CANARY));
        }
    }
}
