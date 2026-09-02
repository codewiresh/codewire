use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{
    FileType as RustixFileType, Mode as RustixMode, OFlags as RustixOFlags, ResolveFlags,
};
use rustix::io::Errno as RustixErrno;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::{
    io::unix::AsyncFd,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tokio_stream::Stream;
use tokio_vsock::{
    Incoming, VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener, VsockStream,
};
use zeroize::Zeroizing;

use crate::network::{
    GUEST_NETWORK_VSOCK_PORT, NETWORK_FRAME_HEADER_LEN, NETWORK_HOST_HELLO_LEN,
    NETWORK_HOST_READY_LEN, NETWORK_HOST_READY_TIMEOUT_SECONDS, NETWORK_MAX_PACKET_BYTES,
    NetworkGuestAck, NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
};
use crate::setup_apply::{
    OCI_LOWER_ROOT_MODE, SetupApplyError, apply_setup_layers, verify_completed_setup_generation,
};
use crate::setup_archive::ArchiveError;
use crate::setup_verify::{SetupContentError, verify_setup_contents};
use crate::workspace_plan::{
    CONTAINER_PLAN_PATH, MAX_PLAN_BYTES, WORKSPACE_PLAN_PATH, WorkspaceIdentity, WorkspacePlan,
};
use crate::{
    GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, PROGRESS_FRAME_LEN, PROGRESS_REQUEST_LEN,
    ProgressFrame, ProgressRequest, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN,
    SETUP_DISK_SERIAL, SETUP_HEADER_LEN, STATE_DISK_SERIAL, Seed, SetupArchitecture, SetupBinding,
    SetupHeader, Sha256Value,
};

pub const INIT_PATH: &str = "/init";
pub const STATE_MOUNT_PATH: &str = "/state";
pub const ROOT_MOUNT_PATH: &str = "/generation";
pub const WORKSPACE_PATH: &str = "/workspace";
pub const CONTROL_PATH: &str = "/state/codewire";
pub const BOOT_STAGE_PATH: &str = "/state/codewire/boot-stage";
pub const NETWORK_STATUS_PATH: &str = "/state/codewire/network-status";
pub const NONCE_PATH: &str = "/state/codewire/nonce";
pub const POWEROFF_MARKER_PATH: &str = "/state/codewire/poweroff.accepted";
pub const IDENTITY_MARKER: &str = "CWIDENTITY1";
pub const NONCE_MARKER: &str = "CWNONCE1";
pub const NETWORK_MARKER: &str = "CWNETWORK2 isolated-tun";
pub const POWEROFF_MARKER: &str = "CWPOWEROFF1 accepted";
pub const RUNC_PATH: &str = "/sbin/runc";
pub const RUNC_STATE_PATH: &str = "/run/codewire/runc";
pub const RUNC_PROCESS_PATH: &str = "/run/codewire/exec";
pub const WORKSPACE_CONTAINER_ID: &str = "codewire-workspace";
pub const CONTAINER_INIT_PATH: &str = "/run/codewire-runtime/init";

const HOME_MERGED_PATH: &str = "/run/codewire/home";
const EMPTY_HOME_LOWER_PATH: &str = "/run/codewire/empty-home";
const RUNC_BUNDLE_PATH: &str = "/generation/bundle";
const RUNC_CONFIG_PATH: &str = "/generation/bundle/config.json";
const RUNC_LOG_PATH: &str = "/state/codewire/runc.log";
const RUNC_STDERR_PATH: &str = "/state/codewire/runc.stderr";
const RUNC_LOG_LIMIT: u64 = 64 * 1024;
const CGROUP_ROOT_PATH: &str = "/sys/fs/cgroup";
const CGROUP_HIERARCHY_PATH: &str = "/sys/fs/cgroup/codewire";
const ROOT_LOWER_PATH: &str = "/generation/lower";
const ROOT_UPPER_PATH: &str = "/generation/upper";
const ROOT_WORK_PATH: &str = "/generation/work";
const ROOT_MERGED_PATH: &str = "/generation/merged";
const CONTAINER_CONTROL_PATH: &str = "/run/codewire/container";
const CONTAINER_IDENTITY_PATH: &str = "/run/codewire/container/identity.json";
const CONTAINER_MACHINE_ID_PATH: &str = "/run/codewire/container/machine-id";
const CONTAINER_RESOLV_CONF_PATH: &str = "/run/codewire/container/resolv.conf";
const CONTAINER_POWEROFF_SOCKET: &str = "/run/codewire/container/poweroff.sock";
const CONTAINER_CONTROL_DESTINATION: &str = "/run/codewire-host";
const CONTAINER_IDENTITY_DESTINATION: &str = "/run/codewire-host/identity.json";
const CONTAINER_MACHINE_ID_DESTINATION: &str = "/etc/machine-id";
const CONTAINER_RESOLV_CONF_DESTINATION: &str = "/etc/resolv.conf";
const CONTAINER_POWEROFF_DESTINATION: &str = "/run/codewire-host/poweroff.sock";
const INSTALL_STATE_PATH: &str = "/state/codewire/workspace-install.state";
const CONTAINER_INSTALL_STATE_PATH: &str = "/run/codewire-runtime/install.state";
const PERSISTENT_PROBE_PATH: &str = "/state/probe";
const CONTAINER_PROBE_DESTINATION: &str = "/run/codewire-probe";
const CONTAINER_NONCE_PATH: &str = "/run/codewire-probe/nonce";
const WORKSPACE_OWNER_VERSION_PATH: &str = "/state/codewire/workspace-owner.version";
const PENDING_INSTALL_STATE: &[u8] = b"codewire-workspace-install-v1 pending\n";
const INITIAL_OWNERSHIP_ENTRY_LIMIT: usize = 1_000_000;
const CONTAINER_POWEROFF_MARKER_PATH: &str = "/run/codewire-probe/poweroff.accepted";
const WORKSPACE_START_TIMEOUT: Duration = Duration::from_secs(600);
const WORKSPACE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const RUNC_CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_MESSAGE_LIMIT: usize = 32;
const WORKSPACE_READY_FD: RawFd = 3;
const NETWORK_AGENT_READY_FD: RawFd = 3;
const NETWORK_AGENT_READY: &[u8] = b"CWNETG1 namespace-ready\n";
const NETWORK_AGENT_HOST_READY: &[u8] = b"CWNETG1 host-ready\n";
const NETWORK_NAMESPACE_PATH: &str = "/run/codewire/netns/workspace";
const NETWORK_NAMESPACE_DIRECTORY: &str = "/run/codewire/netns";
const NETWORK_INTERFACE: &str = "cw0";
const NETWORK_GUEST_ADDRESS: &str = "192.0.2.2/30";
const NETWORK_GATEWAY_ADDRESS: &str = "192.0.2.1";
const NETWORK_MTU: usize = 1_500;
const NETWORK_AGENT_START_TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK_AGENT_HOST_TIMEOUT: Duration =
    Duration::from_secs(NETWORK_HOST_READY_TIMEOUT_SECONDS);
const NETWORK_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const NSFS_MAGIC: u64 = 0x6e73_6673;
const NETWORK_AGENT_FAILURE_STAGES: &[&str] = &[
    "workspace-net-seed-failed",
    "workspace-net-tun-open-failed",
    "workspace-net-tun-attach-failed",
    "workspace-net-loopback-failed",
    "workspace-net-link-failed",
    "workspace-net-address-failed",
    "workspace-net-route-failed",
    "workspace-net-ipv-six-failed",
    "workspace-net-topology-failed",
    "workspace-net-async-failed",
    "workspace-net-vsock-failed",
    "workspace-net-caps-failed",
    "workspace-net-ready-failed",
    "workspace-net-publish-failed",
    "workspace-net-peer-failed",
    "workspace-net-handshake-timeout",
    "workspace-net-hello-read-failed",
    "workspace-net-hello-auth-failed",
    "workspace-net-ack-write-failed",
    "workspace-net-ready-read-failed",
    "workspace-net-ready-auth-failed",
    "workspace-net-session-failed",
];
const NETWORK_AGENT_GENERIC_FAILURE_STAGE: &str = "workspace-net-start-failed";
const NETWORK_AGENT_HOST_FAILURE_STAGE: &str = "workspace-net-host-failed";
const NETWORK_STATUS_VALUES: &[&str] = &[
    "network-listening",
    "network-peer-rejected",
    "network-handshake-timeout",
    "network-hello-read-failed",
    "network-hello-auth-failed",
    "network-ack-write-failed",
    "network-ready-read-failed",
    "network-ready-auth-failed",
    "network-session-failed",
    "network-authenticated",
];
const WORKSPACE_READY_LIMIT: usize = 96;
const WORKSPACE_FAILURE_FRAMES: &[(&[u8], &str)] = &[
    (
        b"CWFAIL1 workspace-identity-failed\n",
        "workspace-identity-failed",
    ),
    (
        b"CWFAIL1 workspace-confinement-failed\n",
        "workspace-confinement-failed",
    ),
    (
        b"CWFAIL1 workspace-plan-invalid\n",
        "workspace-plan-invalid",
    ),
    (
        b"CWFAIL1 workspace-signal-failed\n",
        "workspace-signal-failed",
    ),
    (
        b"CWFAIL1 workspace-install-failed\n",
        "workspace-install-failed",
    ),
    (
        b"CWFAIL1 workspace-workload-failed\n",
        "workspace-workload-failed",
    ),
];

const SYS_BLOCK_PATH: &str = "/sys/class/block";
const DEV_PATH: &str = "/dev";
const DISK_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const PROGRESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const HOST_ONLY_REJECTION_BUDGET: usize = 32;
const NONCE_MAX_LEN: usize = 256;
const READ_LIMIT: usize = 4097;
const RUNC_PROCESS_SPEC_LIMIT: u64 = 1024 * 1024;
const PERSISTENT_WORKSPACE_PATH: &str = "/state/workspace";
const PERSISTENT_HOME_PATH: &str = "/state/home";
const PERSISTENT_HOME_WORK_PATH: &str = "/state/home-work";

static POWEROFF_REQUESTED: AtomicBool = AtomicBool::new(false);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static BOOT_PROGRESS: OnceLock<watch::Sender<BootProgressSnapshot>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootProgressSnapshot {
    sequence: u64,
    stage: GuestBootStage,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn run_init() -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } == 1,
        "guest init must run as PID 1"
    );
    POWEROFF_REQUESTED.store(false, Ordering::Release);

    mount_minimal_filesystems()?;
    install_poweroff_handlers()?;

    let state_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        STATE_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    validate_block_device(&state_device)?;
    mount_state(&state_device)?;
    create_dir(Path::new(CONTROL_PATH), 0o700)?;
    record_boot_stage("state-mounted")?;
    mount_workspace_cgroups()?;
    record_boot_stage("cgroups-ready")?;

    let seed_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        SEED_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    let root_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        ROOT_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    ensure!(
        state_device != seed_device && state_device != root_device && seed_device != root_device,
        "state, root, and seed disks must resolve to distinct devices"
    );
    validate_block_device(&seed_device)?;
    validate_block_device(&root_device)?;
    record_boot_stage("disks-admitted")?;
    mount_root_generation(&root_device)?;
    record_boot_stage("root-mounted")?;
    create_state_layout()?;

    // Validate the complete seed before starting anything that accepts guest
    // control traffic. The child deliberately rereads it from the immutable
    // disk rather than inheriting the token through argv or environment.
    let seed = read_seed_file(&seed_device)?;
    start_boot_progress(&seed, GuestBootStage::RootMounted)?;
    let plan = if let Some(binding) = seed.setup() {
        let setup_device = wait_for_disk_by_serial(
            Path::new(SYS_BLOCK_PATH),
            Path::new(DEV_PATH),
            SETUP_DISK_SERIAL,
            DISK_DISCOVERY_TIMEOUT,
        )?;
        ensure!(
            setup_device != state_device
                && setup_device != root_device
                && setup_device != seed_device,
            "setup disk must be distinct from every persistent or secret-bearing disk"
        );
        validate_block_device(&setup_device)?;
        let mut setup = open_setup_device(&setup_device)?;
        let header = verify_setup_header(&mut setup, binding)?;
        record_boot_stage("setup-header-ready")?;
        let contents = match verify_setup_contents(&mut setup, &header) {
            Ok(contents) => contents,
            Err(error) => {
                record_boot_stage(setup_content_failure_stage(&error))?;
                return Err(error).context("verify every guest setup object and layer digest");
            }
        };
        record_boot_stage("setup-content-ready")?;
        if let Err(error) =
            apply_setup_layers(&mut setup, &header, &contents, Path::new(ROOT_MOUNT_PATH))
        {
            record_boot_stage(setup_apply_failure_stage(&error))?;
            return Err(error).context("apply every admitted OCI layer into the staging root");
        }
        record_boot_stage("root-layers-ready")?;
        let plan = WorkspacePlan::from_verified_setup(
            &contents.project,
            &contents.config,
            &header,
            Path::new(ROOT_LOWER_PATH),
        )
        .context("derive sealed workspace execution plan")?;
        persist_workspace_plan(&plan)?;
        plan
    } else {
        require_persisted_workspace_plan(load_workspace_plan()?)?
    };
    record_boot_stage("workspace-plan-ready")?;
    normalize_initial_persistent_ownership(&plan)?;
    record_boot_stage("ownership-ready")?;
    prepare_install_state()?;
    let poweroff = prepare_container_control(&seed, &plan.identity)?;
    record_boot_stage("container-control-ready")?;
    let mut network = match spawn_guest_network_agent() {
        Ok(network) => network,
        Err(error) => {
            record_network_agent_failure(NETWORK_AGENT_GENERIC_FAILURE_STAGE)?;
            return Err(error);
        }
    };
    prepare_workspace_generation(&plan)?;
    record_boot_stage("root-generation-ready")?;
    expose_persistent_layout(&plan)?;
    record_boot_stage("persistent-layout-ready")?;
    if let Err(error) = network.wait_for_host() {
        record_network_agent_failure(NETWORK_AGENT_HOST_FAILURE_STAGE)?;
        return Err(error);
    }
    let workspace = spawn_workspace_container(&plan)?;
    record_boot_stage("workspace-running")?;

    let daemon = spawn_daemon()?;
    record_boot_stage("daemon-started")?;
    supervise_guest(daemon, workspace, network.into_child()?, poweroff)
}

fn require_persisted_workspace_plan(plan: Option<WorkspacePlan>) -> Result<WorkspacePlan> {
    plan.ok_or_else(|| {
        anyhow::anyhow!(
            "guest boot has neither an OCI setup binding nor an exact persisted workspace plan"
        )
    })
}

pub async fn run_daemon() -> Result<()> {
    ensure!(
        std::env::vars_os().next().is_none(),
        "guest daemon refuses an ambient environment"
    );
    let seed = read_seed_from_discovered_disk()?;
    let plan = load_workspace_plan()?
        .ok_or_else(|| anyhow::anyhow!("sealed workspace execution plan is absent"))?;
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, seed.daemon_vsock_port()))
        .with_context(|| {
            format!(
                "bind guest daemon AF_VSOCK port {}",
                seed.daemon_vsock_port()
            )
        })?;

    let config = codewire_daemon::Config {
        // The injected transport owns the listener; this value is never used
        // to bind TCP and intentionally contains no host address.
        listen_addr: format!("vsock:any:{}", seed.daemon_vsock_port()),
        workspace_root: PathBuf::from(WORKSPACE_PATH),
        home_root: PathBuf::from(&plan.identity.home),
        auth_token: Some(seed.auth_token().to_owned()),
        process_execution: codewire_daemon::execution::ProcessExecution::Runc(
            codewire_daemon::execution::RuncExecution {
                helper_path: PathBuf::from(INIT_PATH),
                process_directory: PathBuf::from(RUNC_PROCESS_PATH),
                container_id: WORKSPACE_CONTAINER_ID.to_owned(),
                process_wrapper: vec![CONTAINER_INIT_PATH.to_owned(), "workspace-exec".to_owned()],
                default_shell: plan.identity.shell.clone(),
                base_environment: plan.environment.clone(),
                uid: plan.identity.uid,
                gid: plan.identity.gid,
                additional_gids: plan.identity.additional_gids.clone(),
            },
        ),
    };

    codewire_daemon::serve_grpc_with_incoming(
        config,
        HostOnlyIncoming::new(listener.incoming()),
        shutdown_signal(),
    )
    .await
    .context("serve authenticated guest daemon over AF_VSOCK")
}

/// Trusted guest-side end of the raw-IP seam. This process is created by PID
/// 1 inside a fresh network namespace, configures exactly one TUN, drops every
/// capability, and then accepts only authenticated host-CID sessions.
pub async fn run_network_agent() -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } != 1,
        "guest network agent must not be PID 1"
    );
    ensure!(
        std::env::vars_os().next().is_none(),
        "guest network agent refuses an ambient environment"
    );
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == -1 {
        record_boot_stage("workspace-net-caps-failed")?;
        return Err(io::Error::last_os_error()).context("confine guest network agent state");
    }

    let mut readiness = network_agent_readiness_stream().inspect_err(|_| {
        let _ = record_boot_stage("workspace-net-ready-failed");
    })?;
    let seed = network_agent_startup(
        read_seed_from_discovered_disk(),
        "workspace-net-seed-failed",
    )?;
    let vm_id = seed.vm_id();
    let generation = seed.generation();
    let key = network_agent_startup(
        NetworkKey::derive(seed.auth_token(), vm_id, generation)
            .context("derive guest network session key"),
        "workspace-net-seed-failed",
    )?;
    let tun = Arc::new(network_agent_startup(
        AsyncFd::new(open_and_configure_tun()?)
            .context("register guest TUN with the async runtime"),
        "workspace-net-async-failed",
    )?);
    let listener = network_agent_startup(
        VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, GUEST_NETWORK_VSOCK_PORT))
            .context("bind guest network AF_VSOCK port"),
        "workspace-net-vsock-failed",
    )?;
    network_agent_startup(
        clear_process_capabilities().context("drop guest network agent capabilities"),
        "workspace-net-caps-failed",
    )?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        record_boot_stage("workspace-net-caps-failed")?;
        return Err(io::Error::last_os_error()).context("confine guest network agent privileges");
    }

    network_agent_startup(
        publish_network_agent_message(&mut readiness, NETWORK_AGENT_READY),
        "workspace-net-publish-failed",
    )?;
    let mut readiness = Some(readiness);
    record_network_status("network-listening")?;

    loop {
        tokio::select! {
            packet = read_tun_packet(&tun) => {
                // With no authenticated host, consuming and discarding the
                // bounded packet is the fail-closed path. It also prevents a
                // later worker from receiving pre-authentication traffic.
                let _ = packet?;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept guest network AF_VSOCK session")?;
                if peer.cid() != VMADDR_CID_HOST {
                    record_network_status("network-peer-rejected")?;
                    record_boot_stage("workspace-net-peer-failed")?;
                    bail!("guest network peer is not the host CID");
                }
                let authenticated = tokio::time::timeout(
                    NETWORK_HANDSHAKE_TIMEOUT,
                    authenticate_guest_network(stream, &key, vm_id, generation),
                )
                .await;
                let (stream, session) = match authenticated {
                    Ok(Ok(authenticated)) => authenticated,
                    Ok(Err(error)) => {
                        let status = error.status();
                        record_network_status(status)?;
                        record_boot_stage(error.failure_stage())?;
                        bail!("guest network authentication failed");
                    }
                    Err(_) => {
                        record_network_status("network-handshake-timeout")?;
                        record_boot_stage("workspace-net-handshake-timeout")?;
                        bail!("guest network authentication timed out");
                    }
                };
                record_network_status("network-authenticated")?;
                if let Some(mut channel) = readiness.take() {
                    publish_network_agent_message(&mut channel, NETWORK_AGENT_HOST_READY)?;
                }
                // A lost or malformed worker session never opens another
                // route. Return to the host-only accept loop and drain/drop
                // packets until a fresh authenticated worker arrives.
                if bridge_guest_network(stream, session, Arc::clone(&tun))
                    .await
                    .is_err()
                {
                    record_network_status("network-session-failed")?;
                }
            }
        }
    }
}

async fn authenticate_guest_network(
    mut stream: VsockStream,
    key: &NetworkKey,
    vm_id: uuid::Uuid,
    generation: u64,
) -> Result<(VsockStream, NetworkSession), GuestNetworkHandshakeError> {
    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    AsyncReadExt::read_exact(&mut stream, &mut hello)
        .await
        .map_err(|_| GuestNetworkHandshakeError::ReadHello)?;
    let hello = NetworkHostHello::decode(&hello, key, vm_id, generation)
        .map_err(|_| GuestNetworkHandshakeError::AuthenticateHello)?;
    let acknowledgement = NetworkGuestAck::new(hello.nonce)
        .map_err(|_| GuestNetworkHandshakeError::AuthenticateHello)?
        .encode(key);
    AsyncWriteExt::write_all(&mut stream, &acknowledgement)
        .await
        .map_err(|_| GuestNetworkHandshakeError::WriteAcknowledgement)?;
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    AsyncReadExt::read_exact(&mut stream, &mut ready)
        .await
        .map_err(|_| GuestNetworkHandshakeError::ReadReady)?;
    NetworkHostReady::decode(&ready, key, &hello.nonce)
        .map_err(|_| GuestNetworkHandshakeError::AuthenticateReady)?;
    let session = NetworkSession::new(key, &hello.nonce, NetworkRole::Guest)
        .map_err(|_| GuestNetworkHandshakeError::Session)?;
    Ok((stream, session))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestNetworkHandshakeError {
    ReadHello,
    AuthenticateHello,
    WriteAcknowledgement,
    ReadReady,
    AuthenticateReady,
    Session,
}

impl GuestNetworkHandshakeError {
    fn status(self) -> &'static str {
        match self {
            Self::ReadHello => "network-hello-read-failed",
            Self::AuthenticateHello => "network-hello-auth-failed",
            Self::WriteAcknowledgement => "network-ack-write-failed",
            Self::ReadReady => "network-ready-read-failed",
            Self::AuthenticateReady => "network-ready-auth-failed",
            Self::Session => "network-session-failed",
        }
    }

    fn failure_stage(self) -> &'static str {
        match self {
            Self::ReadHello => "workspace-net-hello-read-failed",
            Self::AuthenticateHello => "workspace-net-hello-auth-failed",
            Self::WriteAcknowledgement => "workspace-net-ack-write-failed",
            Self::ReadReady => "workspace-net-ready-read-failed",
            Self::AuthenticateReady => "workspace-net-ready-auth-failed",
            Self::Session => "workspace-net-session-failed",
        }
    }
}

async fn bridge_guest_network(
    stream: VsockStream,
    session: NetworkSession,
    tun: Arc<AsyncFd<OwnedFd>>,
) -> Result<()> {
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let outbound_session = Arc::clone(&session);
    let outbound_tun = Arc::clone(&tun);
    let outbound = async move {
        loop {
            let packet = read_tun_packet(&outbound_tun).await?;
            if !canonical_ipv4_packet(&packet) {
                continue;
            }
            let frame = outbound_session
                .lock()
                .await
                .encode_packet(&packet)
                .context("authenticate guest network outbound packet")?;
            stream_write
                .write_all(&frame)
                .await
                .context("write guest network packet frame")?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let inbound_session = Arc::clone(&session);
    let inbound = async move {
        loop {
            let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
            stream_read
                .read_exact(&mut header)
                .await
                .context("read guest network frame header")?;
            let frame_len =
                encoded_network_frame_len(&header).context("bound guest network frame")?;
            let mut frame = vec![0_u8; frame_len];
            frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
            stream_read
                .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
                .await
                .context("read guest network frame payload")?;
            let packet = inbound_session
                .lock()
                .await
                .decode_packet(&frame)
                .context("authenticate guest network inbound packet")?;
            ensure!(
                canonical_ipv4_packet(&packet),
                "host supplied a non-canonical IPv4 packet"
            );
            write_tun_packet(&tun, &packet).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(outbound, inbound)?;
    Ok(())
}

fn canonical_ipv4_packet(packet: &[u8]) -> bool {
    if !(20..=NETWORK_MTU).contains(&packet.len()) || packet[0] >> 4 != 4 {
        return false;
    }
    let header_words = usize::from(packet[0] & 0x0f);
    if header_words < 5
        || header_words
            .checked_mul(4)
            .is_none_or(|length| length > packet.len())
    {
        return false;
    }
    usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
}

async fn read_tun_packet(tun: &AsyncFd<OwnedFd>) -> io::Result<Vec<u8>> {
    let mut packet = vec![0_u8; NETWORK_MAX_PACKET_BYTES];
    loop {
        let mut ready = tun.readable().await?;
        match ready.try_io(|descriptor| {
            let length = unsafe {
                libc::read(
                    descriptor.get_ref().as_raw_fd(),
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                )
            };
            if length == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(Ok(length)) => {
                packet.truncate(length);
                return Ok(packet);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

async fn write_tun_packet(tun: &AsyncFd<OwnedFd>, packet: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = tun.writable().await?;
        match ready.try_io(|descriptor| {
            let length = unsafe {
                libc::write(
                    descriptor.get_ref().as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                )
            };
            if length == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(Ok(length)) if length == packet.len() => return Ok(()),
            Ok(Ok(_)) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

#[repr(C)]
struct TunIfreq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    flags: libc::c_short,
    padding: [u8; 22],
}

fn open_and_configure_tun() -> Result<OwnedFd> {
    let raw = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        record_boot_stage("workspace-net-tun-open-failed")?;
        return Err(io::Error::last_os_error()).context("open guest TUN device");
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = TunIfreq {
        name: [0; libc::IF_NAMESIZE],
        flags: (0x0001 | 0x1000) as libc::c_short,
        padding: [0; 22],
    };
    for (destination, byte) in request.name.iter_mut().zip(NETWORK_INTERFACE.bytes()) {
        *destination = byte as libc::c_char;
    }
    let tunsetiff = if cfg!(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc64"
    )) {
        0x8004_54ca_u64
    } else {
        0x4004_54ca_u64
    } as libc::c_ulong;
    if unsafe { libc::ioctl(descriptor.as_raw_fd(), tunsetiff as _, &mut request) } == -1 {
        record_boot_stage("workspace-net-tun-attach-failed")?;
        return Err(io::Error::last_os_error()).context("attach guest TUN interface");
    }

    for (arguments, failure_stage) in [
        (
            vec!["ip", "link", "set", "dev", "lo", "up"],
            "workspace-net-loopback-failed",
        ),
        (
            vec![
                "ip",
                "link",
                "set",
                "dev",
                NETWORK_INTERFACE,
                "mtu",
                "1500",
                "up",
            ],
            "workspace-net-link-failed",
        ),
        (
            vec![
                "ip",
                "addr",
                "add",
                NETWORK_GUEST_ADDRESS,
                "dev",
                NETWORK_INTERFACE,
            ],
            "workspace-net-address-failed",
        ),
        (
            vec![
                "ip",
                "route",
                "add",
                "default",
                "via",
                NETWORK_GATEWAY_ADDRESS,
                "dev",
                NETWORK_INTERFACE,
            ],
            "workspace-net-route-failed",
        ),
    ] {
        network_agent_startup(run_fixed_busybox(&arguments), failure_stage)?;
    }
    for path in [
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
        "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
        "/proc/sys/net/ipv6/conf/cw0/disable_ipv6",
    ] {
        network_agent_startup(
            write_proc_value(Path::new(path), b"1\n"),
            "workspace-net-ipv-six-failed",
        )?;
    }
    network_agent_startup(
        verify_isolated_tun(
            Path::new("/proc/net/dev"),
            Path::new("/proc/net/route"),
            Path::new("/proc/net/ipv6_route"),
        ),
        "workspace-net-topology-failed",
    )?;
    Ok(descriptor)
}

fn network_agent_startup<T>(result: Result<T>, failure_stage: &'static str) -> Result<T> {
    debug_assert!(NETWORK_AGENT_FAILURE_STAGES.contains(&failure_stage));
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            record_boot_stage(failure_stage)?;
            Err(error)
        }
    }
}

fn run_fixed_busybox(arguments: &[&str]) -> Result<()> {
    let status = Command::new("/bin/busybox")
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("configure isolated guest TUN")?;
    ensure!(status.success(), "isolated guest TUN configuration failed");
    Ok(())
}

fn write_proc_value(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open kernel network setting {}", path.display()))?;
    file.write_all(value)
        .with_context(|| format!("write kernel network setting {}", path.display()))
}

fn network_agent_readiness_stream() -> Result<UnixStream> {
    let flags = unsafe { libc::fcntl(NETWORK_AGENT_READY_FD, libc::F_GETFD) };
    ensure!(flags != -1, "guest network readiness descriptor is absent");
    if unsafe {
        libc::fcntl(
            NETWORK_AGENT_READY_FD,
            libc::F_SETFD,
            flags | libc::FD_CLOEXEC,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).context("confine guest network readiness channel");
    }
    let stream = unsafe { UnixStream::from_raw_fd(NETWORK_AGENT_READY_FD) };
    let stat = rustix::fs::fstat(&stream).context("inspect guest network readiness channel")?;
    ensure!(
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::Socket,
        "guest network readiness descriptor is not a socket"
    );
    Ok(stream)
}

fn publish_network_agent_message(stream: &mut UnixStream, message: &[u8]) -> Result<()> {
    stream
        .write_all(message)
        .context("publish guest network readiness")?;
    stream.flush().context("flush guest network readiness")
}

struct HostOnlyIncoming {
    incoming: Incoming,
}

impl HostOnlyIncoming {
    fn new(incoming: Incoming) -> Self {
        Self { incoming }
    }
}

fn is_host_cid(cid: u32) -> bool {
    cid == VMADDR_CID_HOST
}

impl Stream for HostOnlyIncoming {
    type Item = io::Result<VsockStream>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut rejected = 0;
        loop {
            match Pin::new(&mut self.incoming).poll_next(context) {
                Poll::Ready(Some(Ok(stream))) => match stream.peer_addr() {
                    Ok(peer) if is_host_cid(peer.cid()) => {
                        return Poll::Ready(Some(Ok(stream)));
                    }
                    Ok(_) | Err(_) => {
                        // Guest-local processes are hostile. Drop their
                        // transport without surfacing an error that would stop
                        // the authenticated host listener.
                        if rejected_connection_requires_yield(&mut rejected, context) {
                            return Poll::Pending;
                        }
                    }
                },
                other => return other,
            }
        }
    }
}

fn rejected_connection_requires_yield(rejected: &mut usize, context: &mut TaskContext<'_>) -> bool {
    *rejected += 1;
    if *rejected < HOST_ONLY_REJECTION_BUDGET {
        return false;
    }

    // A guest-local connect flood must not monopolize the Tokio worker that
    // also carries authenticated host control. The listener remains readable,
    // so arrange another poll after yielding to peer tasks.
    context.waker().wake_by_ref();
    true
}

pub fn run_identity() -> Result<()> {
    let identity = read_guest_identity()?;
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{IDENTITY_MARKER} vm_id={} generation={}",
        identity.vm_id, identity.generation
    )?;
    stdout.flush()?;
    Ok(())
}

pub fn run_write_nonce(nonce: &OsStr) -> Result<()> {
    let _ = read_guest_identity()?;
    let nonce = validate_nonce(nonce)?;
    write_durable(probe_nonce_path(), nonce.as_bytes(), 0o600).context("persist guest nonce")?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NONCE_MARKER} written")?;
    stdout.flush()?;
    Ok(())
}

pub fn run_read_nonce() -> Result<()> {
    let _ = read_guest_identity()?;
    let nonce = read_nonce(probe_nonce_path())?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NONCE_MARKER} {nonce}")?;
    stdout.flush()?;
    Ok(())
}

pub fn run_network_check() -> Result<()> {
    let _ = read_guest_identity()?;
    verify_isolated_tun(
        Path::new("/proc/net/dev"),
        Path::new("/proc/net/route"),
        Path::new("/proc/net/ipv6_route"),
    )?;
    for destination in [
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53),
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 19), 443),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
        SocketAddrV4::new(Ipv4Addr::new(169, 254, 169, 254), 80),
    ] {
        ensure!(
            TcpStream::connect_timeout(&SocketAddr::V4(destination), Duration::from_millis(100),)
                .is_err(),
            "isolated workspace unexpectedly completed a TCP connection"
        );
    }
    require_no_udp_response()?;
    require_raw_icmp_denied()?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NETWORK_MARKER}")?;
    stdout.flush()?;
    Ok(())
}

fn require_no_udp_response() -> Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .context("bind isolated workspace UDP canary")?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("bound isolated workspace UDP canary")?;
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x08codewire\x04test\x00\x00\x01\x00\x01";
    let mut response = [0_u8; 512];
    for destination in [
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53),
        SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
    ] {
        let _ = socket.send_to(query, destination);
        match socket.recv_from(&mut response) {
            Ok(_) => bail!("isolated workspace unexpectedly received a UDP response"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {}
        }
    }
    Ok(())
}

fn require_raw_icmp_denied() -> Result<()> {
    let descriptor = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if descriptor != -1 {
        unsafe {
            libc::close(descriptor);
        }
        bail!("isolated workspace unexpectedly created a raw ICMP socket");
    }
    ensure!(
        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "isolated workspace raw ICMP denial is not capability-enforced"
    );
    Ok(())
}

pub fn run_poweroff() -> Result<()> {
    let identity = read_guest_identity()?;
    let container = Path::new(CONTAINER_IDENTITY_DESTINATION).is_file();
    ensure_init_is_expected(container)?;
    let marker = format!(
        "{POWEROFF_MARKER} vm_id={} generation={}\n",
        identity.vm_id, identity.generation
    );
    let mut operations = RealPoweroffOperations {
        marker,
        marker_path: if container {
            PathBuf::from(CONTAINER_POWEROFF_MARKER_PATH)
        } else {
            PathBuf::from(POWEROFF_MARKER_PATH)
        },
        target: if container {
            PoweroffTarget::Socket(PathBuf::from(CONTAINER_POWEROFF_DESTINATION))
        } else {
            PoweroffTarget::SignalGuestInit
        },
    };
    request_poweroff(&mut operations)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GuestIdentity {
    vm_id: uuid::Uuid,
    generation: u64,
}

impl GuestIdentity {
    fn from_seed(seed: &Seed) -> Self {
        Self {
            vm_id: seed.vm_id(),
            generation: seed.generation(),
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.vm_id.is_nil() && self.generation > 0,
            "guest identity metadata is invalid"
        );
        Ok(())
    }

    fn machine_id(&self) -> String {
        format!("{}\n", self.vm_id.simple())
    }
}

fn read_guest_identity() -> Result<GuestIdentity> {
    let container_identity = Path::new(CONTAINER_IDENTITY_DESTINATION);
    if container_identity.is_file() {
        let bytes = read_bounded(container_identity, 4097)
            .context("read container guest identity metadata")?;
        ensure!(bytes.len() <= 4096, "guest identity metadata is too large");
        let identity: GuestIdentity =
            serde_json::from_slice(&bytes).context("decode guest identity metadata")?;
        identity.validate()?;
        return Ok(identity);
    }
    Ok(GuestIdentity::from_seed(&read_seed_from_discovered_disk()?))
}

fn probe_nonce_path() -> &'static Path {
    if Path::new(CONTAINER_IDENTITY_DESTINATION).is_file() {
        Path::new(CONTAINER_NONCE_PATH)
    } else {
        Path::new(NONCE_PATH)
    }
}

/// Execute a session through the sealed runc binary without placing the OCI
/// process environment on argv or in this helper's environment. The daemon
/// writes the specification only beneath owner-private tmpfs; this helper
/// opens and unlinks it before handing an inherited descriptor to runc.
pub fn run_runc_exec(container_id: &OsStr, process_spec: &Path) -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } != 1,
        "runc session helper must not be PID 1"
    );
    let helper_environment = std::env::vars_os().collect::<Vec<_>>();
    ensure!(
        runc_helper_environment_is_admitted(&helper_environment),
        "runc session helper refuses an ambient environment"
    );
    ensure!(
        unsafe { libc::clearenv() } == 0,
        "runc session helper could not clear its environment"
    );
    ensure!(
        container_id.as_bytes() == WORKSPACE_CONTAINER_ID.as_bytes(),
        "runc session container ID is invalid"
    );
    validate_runc_process_path(process_spec)?;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let process = options
        .open(process_spec)
        .context("open private runc process specification")?;
    let metadata = process
        .metadata()
        .context("inspect private runc process specification")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && (1..=RUNC_PROCESS_SPEC_LIMIT).contains(&metadata.len()),
        "runc process specification is not an admitted private file"
    );
    fs::remove_file(process_spec).context("unlink private runc process specification")?;

    let descriptor = process.as_raw_fd();
    ensure!(
        descriptor > libc::STDERR_FILENO,
        "runc process descriptor is invalid"
    );
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) } == -1 {
        return Err(io::Error::last_os_error()).context("inherit runc process descriptor");
    }
    let descriptor_path = format!("/proc/self/fd/{descriptor}");
    let arguments = [
        RUNC_PATH,
        "--root",
        RUNC_STATE_PATH,
        "exec",
        "--process",
        descriptor_path.as_str(),
        WORKSPACE_CONTAINER_ID,
    ];
    let arguments = arguments
        .iter()
        .map(|argument| CString::new(*argument).context("runc argument contains NUL"))
        .collect::<Result<Vec<_>>>()?;
    let pointers = arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let result = unsafe { libc::execv(arguments[0].as_ptr(), pointers.as_ptr()) };
    debug_assert_eq!(result, -1);
    Err(io::Error::last_os_error()).context("execute sealed runc session helper")
}

fn runc_helper_environment_is_admitted(environment: &[(OsString, OsString)]) -> bool {
    environment.is_empty()
        || (environment.len() == 1
            && environment[0].0 == OsStr::new("SHELL")
            && environment[0].1 == OsStr::new(INIT_PATH))
}

fn validate_runc_process_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "runc process path is not absolute");
    ensure!(
        path.parent() == Some(Path::new(RUNC_PROCESS_PATH)),
        "runc process path is outside private tmpfs"
    );
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("runc process filename is invalid"))?;
    let id = name
        .strip_suffix(".json")
        .ok_or_else(|| anyhow::anyhow!("runc process filename is invalid"))?;
    let parsed = uuid::Uuid::parse_str(id).context("runc process filename is invalid")?;
    ensure!(!parsed.is_nil(), "runc process filename is invalid");
    Ok(())
}

/// Stable trusted container PID 1 used beneath runc. It runs the generation-
/// bound install step, starts the image process and startup script as the
/// resolved image identity, reports readiness over its inherited private
/// descriptor, and then remains as the durable exec/PTY namespace target.
pub fn run_workspace_init() -> Result<()> {
    if unsafe { libc::getpid() } != 1 {
        return fail_workspace_init(
            "workspace-identity-failed",
            anyhow::anyhow!("workspace init must be container PID 1"),
        );
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == -1 {
        let error = anyhow::Error::new(io::Error::last_os_error())
            .context("confine workspace init process state");
        return fail_workspace_init("workspace-confinement-failed", error);
    }
    if let Err(error) = confine_workspace_readiness_descriptor() {
        return fail_workspace_init("workspace-confinement-failed", error);
    }
    let plan = match read_container_workspace_plan() {
        Ok(plan) => plan,
        Err(error) => return fail_workspace_init("workspace-plan-invalid", error),
    };
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_poweroff_signal as *const () as usize;
    action.sa_flags = libc::SA_NOCLDSTOP;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
            let error = anyhow::Error::new(io::Error::last_os_error())
                .context("install workspace init signal handler");
            return fail_workspace_init("workspace-signal-failed", error);
        }
    }
    POWEROFF_REQUESTED.store(false, Ordering::Release);

    if let Err(error) = run_workspace_install(&plan) {
        return fail_workspace_init("workspace-install-failed", error);
    }
    if !plan.workload_args.is_empty() {
        let _workload = match spawn_workspace_process(
            &plan,
            &plan.workload_args,
            &plan.workload_cwd,
            "start image workload",
        ) {
            Ok(workload) => workload,
            Err(error) => return fail_workspace_init("workspace-workload-failed", error),
        };
    }
    if !plan.startup_script.is_empty() {
        let arguments = vec![
            plan.identity.shell.clone(),
            "-lc".to_owned(),
            plan.startup_script.clone(),
        ];
        if let Err(error) = spawn_workspace_process(
            &plan,
            &arguments,
            &plan.session_cwd,
            "start workspace startup script",
        ) {
            eprintln!("workspace startup script warning: {error:#}");
        }
    }
    publish_workspace_readiness(&plan)?;

    loop {
        if POWEROFF_REQUESTED.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped > 0
            || (reaped == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        if reaped == 0 || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        return Err(io::Error::last_os_error()).context("reap workspace child");
    }
}

fn read_container_workspace_plan() -> Result<WorkspacePlan> {
    let metadata = fs::symlink_metadata(CONTAINER_PLAN_PATH)
        .context("inspect container workspace execution plan")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.permissions().mode() & 0o777 == 0o400
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAX_PLAN_BYTES as u64,
        "container workspace execution plan metadata is invalid"
    );
    let bytes = read_bounded(Path::new(CONTAINER_PLAN_PATH), MAX_PLAN_BYTES + 1)
        .context("read container workspace execution plan")?;
    WorkspacePlan::decode(&bytes).context("validate container workspace execution plan")
}

fn fail_workspace_init<T>(stage: &'static str, error: anyhow::Error) -> Result<T> {
    let _ = publish_workspace_failure(stage);
    Err(error)
}

fn publish_workspace_failure(stage: &'static str) -> Result<()> {
    let frame = WORKSPACE_FAILURE_FRAMES
        .iter()
        .find_map(|(frame, admitted)| (*admitted == stage).then_some(*frame))
        .ok_or_else(|| anyhow::anyhow!("workspace failure stage is invalid"))?;
    ensure!(
        unsafe { libc::fcntl(WORKSPACE_READY_FD, libc::F_GETFD) } != -1,
        "workspace readiness descriptor is absent"
    );
    let mut stream = unsafe { UnixStream::from_raw_fd(WORKSPACE_READY_FD) };
    stream
        .write_all(frame)
        .context("publish trusted workspace failure")?;
    stream.flush().context("flush trusted workspace failure")
}

fn run_workspace_install(plan: &WorkspacePlan) -> Result<()> {
    if plan.install_command.is_empty() {
        return Ok(());
    }
    let expected = install_completion(plan)?;
    let metadata = fs::symlink_metadata(CONTAINER_INSTALL_STATE_PATH)
        .context("inspect trusted workspace install state")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.permissions().mode() & 0o777 == 0o400
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= WORKSPACE_READY_LIMIT as u64,
        "trusted workspace install state is invalid"
    );
    let actual = read_bounded(
        Path::new(CONTAINER_INSTALL_STATE_PATH),
        WORKSPACE_READY_LIMIT + 1,
    )
    .context("read trusted workspace install state")?;
    ensure!(
        valid_install_state(&actual),
        "trusted workspace install state is invalid"
    );
    if actual == expected {
        return Ok(());
    }

    let arguments = vec![
        plan.identity.shell.clone(),
        "-lc".to_owned(),
        plan.install_command.clone(),
    ];
    let mut child = spawn_workspace_process(
        plan,
        &arguments,
        &plan.session_cwd,
        "start workspace install command",
    )?;
    let status = child.wait().context("wait for workspace install command")?;
    ensure!(status.success(), "workspace install command failed");
    Ok(())
}

fn spawn_workspace_process(
    plan: &WorkspacePlan,
    arguments: &[String],
    working_directory: &str,
    action: &'static str,
) -> Result<std::process::Child> {
    let (program, remaining) = arguments
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("workspace process command is empty"))?;
    ensure!(
        Path::new(working_directory).is_absolute(),
        "workspace process directory is not absolute"
    );
    let working_directory = CString::new(working_directory.as_bytes())
        .context("workspace process directory contains NUL")?;
    let mut command = Command::new(program);
    command
        .args(remaining)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for entry in &plan.environment {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("sealed workspace environment is invalid"))?;
        command.env(key, value);
    }
    let uid = plan.identity.uid;
    let gid = plan.identity.gid;
    let additional_gids = plan
        .identity
        .additional_gids
        .iter()
        .map(|gid| *gid as libc::gid_t)
        .collect::<Vec<_>>();
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(additional_gids.len(), additional_gids.as_ptr()) == -1
                || libc::setgid(gid as libc::gid_t) == -1
                || libc::setuid(uid as libc::uid_t) == -1
                // The workspace and home are deliberately mode 0700 and
                // owned by the image identity. Enter the sealed working
                // directory only after dropping identity; PID 1 does not
                // retain CAP_DAC_OVERRIDE merely to traverse it as root.
                || libc::chdir(working_directory.as_ptr()) == -1
            {
                return Err(io::Error::last_os_error());
            }
            clear_process_capabilities()?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().with_context(|| action)
}

fn clear_process_capabilities() -> io::Result<()> {
    let mut header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn install_completion(plan: &WorkspacePlan) -> Result<Vec<u8>> {
    let bytes = plan.encode().context("encode workspace install identity")?;
    Ok(format!(
        "codewire-workspace-install-v1 {}\n",
        Sha256Value::calculate(&bytes)
    )
    .into_bytes())
}

fn valid_install_state(bytes: &[u8]) -> bool {
    if bytes == PENDING_INSTALL_STATE {
        return true;
    }
    let Some(digest) = bytes
        .strip_prefix(b"codewire-workspace-install-v1 ")
        .and_then(|value| value.strip_suffix(b"\n"))
    else {
        return false;
    };
    digest.len() == 64
        && digest
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn workspace_ready_message(plan: &WorkspacePlan) -> Result<Vec<u8>> {
    let bytes = plan
        .encode()
        .context("encode workspace readiness identity")?;
    Ok(format!("CWREADY1 {}\n", Sha256Value::calculate(&bytes)).into_bytes())
}

fn confine_workspace_readiness_descriptor() -> Result<()> {
    let flags = unsafe { libc::fcntl(WORKSPACE_READY_FD, libc::F_GETFD) };
    if flags == -1
        || unsafe { libc::fcntl(WORKSPACE_READY_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
    {
        return Err(io::Error::last_os_error()).context("confine workspace readiness descriptor");
    }
    Ok(())
}

fn publish_workspace_readiness(plan: &WorkspacePlan) -> Result<()> {
    let flags = unsafe { libc::fcntl(WORKSPACE_READY_FD, libc::F_GETFD) };
    ensure!(flags != -1, "workspace readiness descriptor is absent");
    let mut stream = unsafe { UnixStream::from_raw_fd(WORKSPACE_READY_FD) };
    let stat = rustix::fs::fstat(&stream).context("inspect workspace readiness descriptor")?;
    ensure!(
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::Socket,
        "workspace readiness descriptor is not a socket"
    );
    let message = workspace_ready_message(plan)?;
    ensure!(
        message.len() <= WORKSPACE_READY_LIMIT,
        "workspace readiness message is invalid"
    );
    stream
        .write_all(&message)
        .context("publish trusted workspace readiness")?;
    stream.flush().context("flush trusted workspace readiness")
}

/// Preserve the daemon's exact-child lifecycle across the runc client hop.
/// The runc client is this process's parent; if transport cleanup kills that
/// client, the kernel kills the in-container command even when the command
/// ignores ordinary termination signals.
pub fn run_workspace_exec(command: Vec<OsString>) -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } != 1,
        "workspace exec trampoline must not be container PID 1"
    );
    ensure!(
        !command.is_empty() && !command[0].is_empty(),
        "workspace exec command is empty"
    );
    let parent = unsafe { libc::getppid() };
    ensure!(parent != 1, "workspace exec lost its runc parent");
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
        return Err(io::Error::last_os_error()).context("bind workspace exec to its runc parent");
    }
    ensure!(
        unsafe { libc::getppid() } == parent,
        "workspace exec runc parent changed during admission"
    );

    let arguments = command
        .iter()
        .map(|argument| {
            CString::new(argument.as_bytes()).context("workspace exec argument contains NUL")
        })
        .collect::<Result<Vec<_>>>()?;
    let pointers = arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let result = unsafe { libc::execvp(arguments[0].as_ptr(), pointers.as_ptr()) };
    debug_assert_eq!(result, -1);
    Err(io::Error::last_os_error()).context("execute workspace session command")
}

pub fn find_disk_by_serial(
    sys_block_path: &Path,
    dev_path: &Path,
    expected_serial: &str,
) -> Result<PathBuf> {
    ensure!(!expected_serial.is_empty(), "disk serial must not be empty");
    let mut matches = Vec::new();
    for entry in fs::read_dir(sys_block_path)
        .with_context(|| format!("read block-device class {}", sys_block_path.display()))?
    {
        let entry = entry.context("read block-device class entry")?;
        let name = entry.file_name();
        if !valid_virtio_block_name(&name) {
            continue;
        }
        let serial_path = entry.path().join("serial");
        let Ok(serial) = read_bounded(&serial_path, 64) else {
            continue;
        };
        let Ok(serial) = std::str::from_utf8(&serial) else {
            continue;
        };
        if serial.trim_end_matches(['\r', '\n']) == expected_serial {
            matches.push(dev_path.join(name));
        }
    }

    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("virtio block disk with required serial is absent"),
        _ => bail!("multiple virtio block disks use the required serial"),
    }
}

fn wait_for_disk_by_serial(
    sys_block_path: &Path,
    dev_path: &Path,
    serial: &str,
    timeout: Duration,
) -> Result<PathBuf> {
    let deadline = Instant::now() + timeout;
    loop {
        match find_disk_by_serial(sys_block_path, dev_path, serial) {
            Ok(path) => return Ok(path),
            Err(error) if error.to_string().starts_with("multiple ") => return Err(error),
            Err(error) if Instant::now() >= deadline => {
                return Err(error).with_context(|| format!("discover required {serial} disk"));
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn valid_virtio_block_name(name: &OsStr) -> bool {
    let name = name.as_bytes();
    name.len() >= 3 && name.starts_with(b"vd") && name[2..].iter().all(u8::is_ascii_lowercase)
}

fn validate_block_device(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect guest block device {}", path.display()))?;
    ensure!(
        metadata.file_type().is_block_device(),
        "guest disk path is not a block device"
    );
    Ok(())
}

fn read_seed_from_discovered_disk() -> Result<Seed> {
    let seed_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        SEED_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    validate_block_device(&seed_device)?;
    read_seed_file(&seed_device)
}

fn read_seed_file(path: &Path) -> Result<Seed> {
    // This limits one avoidable plaintext copy. The daemon's live Config must
    // retain its token to authenticate RPCs, so guest memory is not claimed as
    // a token-secrecy boundary.
    let bytes = Zeroizing::new(
        read_bounded(path, READ_LIMIT)
            .with_context(|| format!("read guest seed disk {}", path.display()))?,
    );
    ensure!(
        bytes.len() == SEED_LEN,
        "guest seed disk has invalid length"
    );
    Seed::decode(&bytes).context("decode guest seed")
}

fn open_setup_device(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let setup = options
        .open(path)
        .with_context(|| format!("open guest setup disk {}", path.display()))?;
    let metadata = setup
        .metadata()
        .with_context(|| format!("inspect guest setup disk {}", path.display()))?;
    ensure!(
        metadata.file_type().is_block_device(),
        "guest setup path is not a block device"
    );
    Ok(setup)
}

fn verify_setup_header(
    input: &mut (impl Read + Seek),
    binding: SetupBinding,
) -> Result<SetupHeader> {
    let total_bytes = input
        .seek(SeekFrom::End(0))
        .context("measure guest setup device")?;
    ensure!(
        total_bytes == binding.total_bytes(),
        "guest setup device size differs from its seed binding"
    );
    input
        .seek(SeekFrom::Start(0))
        .context("rewind guest setup device")?;
    let mut bytes = vec![0_u8; SETUP_HEADER_LEN];
    input
        .read_exact(&mut bytes)
        .context("read guest setup header")?;
    ensure!(
        Sha256Value::calculate(&bytes) == binding.header_sha256(),
        "guest setup header differs from its seed binding"
    );
    let header = SetupHeader::decode(&bytes).context("decode guest setup header")?;
    ensure!(
        header.total_bytes == binding.total_bytes()
            && header.root_generation == binding.root_generation(),
        "guest setup header identity differs from its seed binding"
    );
    let native = match std::env::consts::ARCH {
        "x86_64" => SetupArchitecture::Amd64,
        "aarch64" => SetupArchitecture::Arm64,
        _ => bail!("guest setup architecture is unsupported"),
    };
    ensure!(
        header.architecture == native,
        "guest setup architecture is not native"
    );
    Ok(header)
}

fn persist_workspace_plan(plan: &WorkspacePlan) -> Result<()> {
    let bytes = plan.encode().context("encode sealed workspace plan")?;
    ensure_exact_bytes(Path::new(WORKSPACE_PLAN_PATH), &bytes, 0o400)
        .context("publish sealed workspace plan")
}

fn load_workspace_plan() -> Result<Option<WorkspacePlan>> {
    let metadata = match fs::symlink_metadata(WORKSPACE_PLAN_PATH) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect sealed workspace plan"),
    };
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == unsafe { libc::getegid() }
            && metadata.permissions().mode() & 0o777 == 0o400
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAX_PLAN_BYTES as u64,
        "sealed workspace plan metadata is invalid"
    );
    let bytes = read_bounded(Path::new(WORKSPACE_PLAN_PATH), MAX_PLAN_BYTES + 1)
        .context("read sealed workspace plan")?;
    WorkspacePlan::decode(&bytes)
        .map(Some)
        .context("validate sealed workspace plan")
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    Read::by_ref(&mut file)
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn mount_minimal_filesystems() -> Result<()> {
    create_dir(Path::new("/dev"), 0o755)?;
    mount_fs(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    create_dir(Path::new("/proc"), 0o555)?;
    mount_fs(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    create_dir(Path::new("/sys"), 0o555)?;
    mount_fs(
        "sysfs",
        "/sys",
        "sysfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    create_dir(Path::new("/dev/pts"), 0o755)?;
    mount_fs(
        "devpts",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620",
    )?;
    create_dir(Path::new("/dev/shm"), 0o1777)?;
    create_dir(Path::new("/run"), 0o755)?;
    mount_fs(
        "tmpfs",
        "/run",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0755,size=32m",
    )?;
    create_dir(Path::new("/tmp"), 0o1777)?;
    replace_ptmx_link()?;
    create_symlink("/proc/self/fd", "/dev/fd")?;
    create_symlink("/proc/self/fd/0", "/dev/stdin")?;
    create_symlink("/proc/self/fd/1", "/dev/stdout")?;
    create_symlink("/proc/self/fd/2", "/dev/stderr")?;
    Ok(())
}

fn mount_workspace_cgroups() -> Result<()> {
    let root =
        fs::symlink_metadata(CGROUP_ROOT_PATH).context("inspect kernel cgroup mountpoint")?;
    ensure!(
        root.file_type().is_dir(),
        "kernel cgroup mountpoint is not a directory"
    );
    mount_fs(
        "codewire-cgroup-root",
        CGROUP_ROOT_PATH,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0755,size=1m",
    )
    .context("mount private cgroup root")?;
    create_dir(Path::new(CGROUP_HIERARCHY_PATH), 0o755)?;
    // This admitted kernel exposes cgroup v1. With no subsystem option the
    // kernel binds every registered controller into this single, private
    // hierarchy. runc can then enforce the OCI device allowlist without a
    // host-visible or shared cgroup boundary.
    mount_fs(
        "codewire",
        CGROUP_HIERARCHY_PATH,
        "cgroup",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )
    .context("mount private cgroup v1 hierarchy")?;
    let mut statistics: libc::statfs = unsafe { std::mem::zeroed() };
    let hierarchy = CString::new(CGROUP_HIERARCHY_PATH).expect("static path has no NUL");
    if unsafe { libc::statfs(hierarchy.as_ptr(), &mut statistics) } == -1 {
        return Err(io::Error::last_os_error()).context("inspect private cgroup hierarchy");
    }
    ensure!(
        statistics.f_type as u64 == libc::CGROUP_SUPER_MAGIC as u64,
        "private cgroup hierarchy has the wrong filesystem type"
    );
    for required in ["cgroup.procs", "devices.list"] {
        let path = Path::new(CGROUP_HIERARCHY_PATH).join(required);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect required cgroup file {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "required cgroup path is not a regular control file"
        );
    }
    Ok(())
}

fn mount_state(device: &Path) -> Result<()> {
    create_dir(Path::new(STATE_MOUNT_PATH), 0o700)?;
    let device = device
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("state disk path is not UTF-8"))?;
    mount_fs(
        device,
        STATE_MOUNT_PATH,
        "ext4",
        libc::MS_NOSUID | libc::MS_NODEV,
        "errors=remount-ro",
    )
    .context("mount persistent state disk")
}

fn mount_root_generation(device: &Path) -> Result<()> {
    create_dir(Path::new(ROOT_MOUNT_PATH), 0o700)?;
    let device = device
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("root generation disk path is not UTF-8"))?;
    mount_fs(
        device,
        ROOT_MOUNT_PATH,
        "ext4",
        libc::MS_NOSUID | libc::MS_NODEV,
        "errors=remount-ro",
    )
    .context("mount root generation disk")
}

fn start_boot_progress(seed: &Seed, initial_stage: GuestBootStage) -> Result<()> {
    let initial = BootProgressSnapshot {
        sequence: 1,
        stage: initial_stage,
    };
    let (progress_tx, progress_rx) = watch::channel(initial);
    let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
    let vm_id = seed.vm_id();
    let generation = seed.generation();
    let token = Zeroizing::new(seed.auth_token().to_owned());
    thread::Builder::new()
        .name("codewire-guest-progress".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let runtime = match runtime {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                // Tokio's AF_VSOCK listener registers with the current I/O
                // driver while binding, so construct it inside this runtime.
                let listener =
                    VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, GUEST_PROGRESS_VSOCK_PORT));
                let listener = match listener {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                serve_boot_progress(listener, vm_id, generation, token, progress_rx).await;
            });
        })
        .context("spawn guest progress server")?;
    ready_rx
        .recv_timeout(PROGRESS_REQUEST_TIMEOUT)
        .context("wait for guest progress listener")??;
    BOOT_PROGRESS
        .set(progress_tx)
        .map_err(|_| anyhow::anyhow!("guest progress sender is already installed"))?;
    Ok(())
}

async fn serve_boot_progress(
    listener: VsockListener,
    vm_id: uuid::Uuid,
    generation: u64,
    token: Zeroizing<String>,
    progress: watch::Receiver<BootProgressSnapshot>,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        if !is_host_cid(peer.cid()) {
            continue;
        }
        let _ = serve_boot_progress_connection(
            stream,
            vm_id,
            generation,
            token.as_str(),
            progress.clone(),
        )
        .await;
    }
}

async fn serve_boot_progress_connection(
    mut stream: VsockStream,
    vm_id: uuid::Uuid,
    generation: u64,
    token: &str,
    mut progress: watch::Receiver<BootProgressSnapshot>,
) -> Result<()> {
    let mut request = [0_u8; PROGRESS_REQUEST_LEN];
    tokio::time::timeout(
        PROGRESS_REQUEST_TIMEOUT,
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut request),
    )
    .await
    .context("guest progress request timed out")?
    .context("read guest progress request")?;
    let request = ProgressRequest::decode(&request).context("decode guest progress request")?;
    ensure!(
        request.vm_id == vm_id && request.generation == generation,
        "guest progress request identity mismatch"
    );

    loop {
        let snapshot = *progress.borrow_and_update();
        let frame = ProgressFrame {
            vm_id,
            generation,
            sequence: snapshot.sequence,
            stage: snapshot.stage,
        }
        .encode(&request.challenge, token)
        .context("encode authenticated guest progress")?;
        debug_assert_eq!(frame.len(), PROGRESS_FRAME_LEN);
        tokio::io::AsyncWriteExt::write_all(&mut stream, &frame)
            .await
            .context("write authenticated guest progress")?;
        tokio::io::AsyncWriteExt::flush(&mut stream)
            .await
            .context("flush guest progress")?;
        if snapshot.stage.is_terminal() {
            return Ok(());
        }
        progress
            .changed()
            .await
            .context("guest progress publisher closed")?;
    }
}

fn record_boot_stage(stage: &'static str) -> Result<()> {
    ensure!(
        !stage.is_empty()
            && stage.len() <= 32
            && stage
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
        "guest boot stage is invalid"
    );
    let progress_stage = GuestBootStage::from_persisted(stage)
        .ok_or_else(|| anyhow::anyhow!("guest boot stage is outside the progress allowlist"))?;
    let mut value = stage.as_bytes().to_vec();
    value.push(b'\n');
    write_durable(Path::new(BOOT_STAGE_PATH), &value, 0o600)
        .context("persist bounded guest boot stage")?;
    if let Some(progress) = BOOT_PROGRESS.get() {
        let previous = *progress.borrow();
        if previous.stage != progress_stage {
            let sequence = previous
                .sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("guest progress sequence overflow"))?;
            progress.send_replace(BootProgressSnapshot {
                sequence,
                stage: progress_stage,
            });
        }
    }
    Ok(())
}

fn record_network_status(status: &'static str) -> Result<()> {
    ensure!(
        NETWORK_STATUS_VALUES.contains(&status),
        "guest network status is outside the fixed allowlist"
    );
    let mut value = status.as_bytes().to_vec();
    value.push(b'\n');
    write_durable(Path::new(NETWORK_STATUS_PATH), &value, 0o600)
        .context("persist bounded guest network status")
}

fn record_network_agent_failure(fallback: &'static str) -> Result<()> {
    debug_assert!(
        fallback == NETWORK_AGENT_GENERIC_FAILURE_STAGE
            || fallback == NETWORK_AGENT_HOST_FAILURE_STAGE
    );
    let persisted = read_bounded(Path::new(BOOT_STAGE_PATH), 34)
        .ok()
        .and_then(|bytes| {
            let value = bytes.strip_suffix(b"\n")?;
            let value = std::str::from_utf8(value).ok()?;
            NETWORK_AGENT_FAILURE_STAGES
                .iter()
                .copied()
                .find(|candidate| *candidate == value)
        })
        .unwrap_or(fallback);
    record_boot_stage(persisted)
}

fn setup_content_failure_stage(error: &SetupContentError) -> &'static str {
    match error {
        SetupContentError::InvalidFraming => "setup-invalid-framing",
        SetupContentError::NonZeroPadding => "setup-nonzero-padding",
        SetupContentError::TruncatedObject => "setup-truncated-object",
        SetupContentError::ObjectDigestMismatch => "setup-object-digest",
        SetupContentError::LayerDiffIdMismatch => "setup-layer-diffid",
        SetupContentError::LayerExpansionLimit => "setup-layer-expansion",
        SetupContentError::ImageExpansionLimit => "setup-image-expansion",
        SetupContentError::UnsupportedLayerEncoding => "setup-layer-encoding",
        SetupContentError::Archive(error) => match error {
            ArchiveError::ExpansionLimit => "setup-tar-expansion",
            ArchiveError::MetadataReadLimit => "setup-tar-metadata-limit",
            ArchiveError::InvalidTar => "setup-tar-invalid",
            ArchiveError::InvalidRootEntry => "setup-tar-root-entry",
            ArchiveError::PathLengthLimit => "setup-tar-path-length",
            ArchiveError::AbsolutePath => "setup-tar-absolute-path",
            ArchiveError::NulPathByte => "setup-tar-path-nul",
            ArchiveError::EmptyPathComponent => "setup-tar-empty-component",
            ArchiveError::ParentPathComponent => "setup-tar-parent-component",
            ArchiveError::PathComponentLengthLimit => "setup-tar-component-length",
            ArchiveError::PathComponentLimit => "setup-tar-component-limit",
            ArchiveError::EmptyLinkPath => "setup-tar-empty-hardlink",
            ArchiveError::EmptySymlinkTarget => "setup-tar-empty-symlink",
            ArchiveError::NulSymlinkTarget => "setup-tar-symlink-nul",
            ArchiveError::DuplicatePath => "setup-tar-duplicate-path",
            ArchiveError::PathTypeConflict => "setup-tar-path-conflict",
            ArchiveError::InvalidMetadata => "setup-tar-invalid-metadata",
            ArchiveError::InvalidPax => "setup-tar-invalid-pax",
            ArchiveError::UnsupportedPax => "setup-tar-unsupported-pax",
            ArchiveError::UnsupportedXattr => "setup-tar-unsupported-xattr",
            ArchiveError::InvalidXattr => "setup-tar-invalid-xattr",
            ArchiveError::UnsupportedSparse => "setup-tar-unsupported-sparse",
            ArchiveError::UnsupportedEntryType => "setup-tar-unsupported-inode",
            ArchiveError::InvalidWhiteout => "setup-tar-invalid-whiteout",
            ArchiveError::LayerEntryLimit => "setup-tar-layer-entry-limit",
            ArchiveError::ImageEntryLimit => "setup-tar-image-entry-limit",
            ArchiveError::PathBudgetLimit => "setup-tar-path-budget",
            ArchiveError::WhiteoutBudgetLimit => "setup-tar-whiteout-budget",
            ArchiveError::TrailingData => "setup-tar-trailing-data",
        },
        SetupContentError::Read(_) => "setup-content-read",
    }
}

fn setup_apply_failure_stage(error: &SetupApplyError) -> &'static str {
    match error {
        SetupApplyError::Capability(_) => "setup-apply-capability",
        SetupApplyError::Archive(_) => "setup-apply-archive",
        SetupApplyError::InvalidVerifiedState
        | SetupApplyError::CompletionMismatch
        | SetupApplyError::GenerationIncomplete
        | SetupApplyError::TruncatedLayerObject
        | SetupApplyError::TruncatedEntryData
        | SetupApplyError::EntryDataNotConsumed
        | SetupApplyError::ReplayMismatch
        | SetupApplyError::UnsupportedLayerEncoding
        | SetupApplyError::InvalidHardlinkTarget
        | SetupApplyError::RemovalLimit
        | SetupApplyError::Io { .. }
        | SetupApplyError::Fs { .. } => "setup-apply-failed",
    }
}

fn create_state_layout() -> Result<()> {
    for (path, mode) in [
        (CONTROL_PATH, 0o700),
        (PERSISTENT_WORKSPACE_PATH, 0o700),
        (PERSISTENT_HOME_PATH, 0o700),
        (PERSISTENT_HOME_WORK_PATH, 0o700),
        (PERSISTENT_PROBE_PATH, 0o700),
    ] {
        create_dir(Path::new(path), mode)?;
    }
    File::open(STATE_MOUNT_PATH)
        .context("open state mount for fsync")?
        .sync_all()
        .context("fsync state layout")?;
    Ok(())
}

fn prepare_install_state() -> Result<()> {
    let path = Path::new(INSTALL_STATE_PATH);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.gid() == unsafe { libc::getegid() }
                    && metadata.permissions().mode() & 0o777 == 0o400
                    && metadata.nlink() == 1
                    && metadata.len() > 0
                    && metadata.len() <= WORKSPACE_READY_LIMIT as u64,
                "trusted workspace install state is invalid"
            );
            let state = read_bounded(path, WORKSPACE_READY_LIMIT + 1)
                .context("read trusted workspace install state")?;
            ensure!(
                valid_install_state(&state),
                "trusted workspace install state is invalid"
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_durable(path, PENDING_INSTALL_STATE, 0o400)
                .context("initialize trusted workspace install state")
        }
        Err(error) => Err(error).context("inspect trusted workspace install state"),
    }
}

fn publish_install_completion(plan: &WorkspacePlan) -> Result<()> {
    let expected = install_completion(plan)?;
    let actual = read_bounded(Path::new(INSTALL_STATE_PATH), WORKSPACE_READY_LIMIT + 1)
        .context("read trusted workspace install state before promotion")?;
    if actual == expected {
        return Ok(());
    }
    ensure!(
        valid_install_state(&actual),
        "trusted workspace install state is invalid"
    );
    write_durable(Path::new(INSTALL_STATE_PATH), &expected, 0o400)
        .context("publish trusted workspace install completion")
}

/// Convergently translate the shared workspace/home owner when a generation
/// changes image identity. A crash or rollback can safely repeat the bounded,
/// no-follow walk; the marker is published only after the filesystem sync.
fn normalize_initial_persistent_ownership(plan: &WorkspacePlan) -> Result<()> {
    let identity = &plan.identity;
    let expected_marker = format!(
        "codewire-workspace-owner-v3 oci {}:{}\n",
        identity.uid, identity.gid,
    );
    match fs::symlink_metadata(WORKSPACE_OWNER_VERSION_PATH) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.gid() == unsafe { libc::getegid() }
                    && metadata.permissions().mode() & 0o777 == 0o400
                    && metadata.len() <= 128,
                "persistent workspace ownership marker is invalid"
            );
            let actual = read_bounded(Path::new(WORKSPACE_OWNER_VERSION_PATH), 129)
                .context("read persistent workspace ownership marker")?;
            if actual == expected_marker.as_bytes() {
                return Ok(());
            }
            ensure!(
                valid_workspace_owner_marker(&actual),
                "persistent workspace ownership marker is invalid"
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect persistent workspace ownership marker"),
    }

    let mut pending = vec![
        PathBuf::from(PERSISTENT_WORKSPACE_PATH),
        PathBuf::from(PERSISTENT_HOME_PATH),
        PathBuf::from(PERSISTENT_PROBE_PATH),
    ];
    let mut visited = 0_usize;
    while let Some(path) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("persistent ownership entry count overflowed"))?;
        ensure!(
            visited <= INITIAL_OWNERSHIP_ENTRY_LIMIT,
            "persistent workspace exceeds its initial ownership entry bound"
        );
        let metadata = fs::symlink_metadata(&path).context("inspect persistent workspace entry")?;
        let kind = metadata.file_type();
        ensure!(
            kind.is_dir()
                || kind.is_file()
                || kind.is_symlink()
                || kind.is_fifo()
                || kind.is_socket(),
            "persistent workspace contains a forbidden inode type"
        );
        lchown(&path, identity.uid, identity.gid)?;
        if kind.is_dir() {
            for entry in fs::read_dir(&path).context("read persistent workspace directory")? {
                ensure!(
                    visited.saturating_add(pending.len()) < INITIAL_OWNERSHIP_ENTRY_LIMIT,
                    "persistent workspace exceeds its initial ownership entry bound"
                );
                pending.push(entry.context("read persistent workspace entry")?.path());
            }
        }
    }

    let state = File::open(STATE_MOUNT_PATH).context("open state filesystem for ownership sync")?;
    if unsafe { libc::syncfs(state.as_raw_fd()) } == -1 {
        return Err(io::Error::last_os_error()).context("sync persistent workspace ownership");
    }
    write_durable(
        Path::new(WORKSPACE_OWNER_VERSION_PATH),
        expected_marker.as_bytes(),
        0o400,
    )
    .context("publish persistent workspace ownership marker")
}

fn valid_workspace_owner_marker(bytes: &[u8]) -> bool {
    let Some(body) = bytes
        .strip_prefix(b"codewire-workspace-owner-v3 oci ")
        .and_then(|value| value.strip_suffix(b"\n"))
        .and_then(|value| std::str::from_utf8(value).ok())
    else {
        return false;
    };
    let Some((uid, gid)) = body.split_once(':') else {
        return false;
    };
    let canonical_id = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value == "0" || !value.starts_with('0'))
            && value.parse::<u32>().is_ok()
    };
    canonical_id(uid) && canonical_id(gid)
}

fn lchown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let path_bytes = CString::new(path.as_os_str().as_bytes())
        .context("persistent workspace path contains NUL")?;
    if unsafe { libc::lchown(path_bytes.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error()).context("normalize persistent workspace owner");
    }
    Ok(())
}

fn expose_persistent_layout(plan: &WorkspacePlan) -> Result<()> {
    create_dir(Path::new(WORKSPACE_PATH), 0o700)?;
    let home = Path::new(&plan.identity.home);
    let home_parent = home
        .parent()
        .ok_or_else(|| anyhow::anyhow!("workspace home has no parent"))?;
    if home_parent != Path::new("/") {
        create_dir(home_parent, 0o755)?;
    }
    create_dir(home, 0o700)?;
    bind_mount(PERSISTENT_WORKSPACE_PATH, WORKSPACE_PATH)?;

    let relative_home = home
        .strip_prefix("/")
        .map_err(|_| anyhow::anyhow!("workspace home is not absolute"))?;
    let image_home = Path::new(ROOT_LOWER_PATH).join(relative_home);
    let lower = if confined_image_directory_exists(relative_home)? {
        image_home
    } else {
        create_dir(Path::new(EMPTY_HOME_LOWER_PATH), 0o755)?;
        PathBuf::from(EMPTY_HOME_LOWER_PATH)
    };
    create_dir(Path::new(HOME_MERGED_PATH), 0o700)?;
    mount_fs(
        "overlay",
        HOME_MERGED_PATH,
        "overlay",
        libc::MS_NOSUID | libc::MS_NODEV,
        &format!(
            "lowerdir={},upperdir={PERSISTENT_HOME_PATH},workdir={PERSISTENT_HOME_WORK_PATH}",
            lower.display()
        ),
    )
    .context("mount persistent workspace home overlay")?;
    bind_mount(HOME_MERGED_PATH, &plan.identity.home)
}

fn confined_image_directory_exists(relative: &Path) -> Result<bool> {
    let root = rustix::fs::open(
        ROOT_LOWER_PATH,
        RustixOFlags::RDONLY
            | RustixOFlags::DIRECTORY
            | RustixOFlags::CLOEXEC
            | RustixOFlags::NOFOLLOW,
        RustixMode::empty(),
    )
    .context("open OCI lower root for confined home inspection")?;
    let descriptor = match rustix::fs::openat2(
        &root,
        relative,
        RustixOFlags::RDONLY
            | RustixOFlags::DIRECTORY
            | RustixOFlags::CLOEXEC
            | RustixOFlags::NOFOLLOW,
        RustixMode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) {
        Ok(descriptor) => descriptor,
        Err(RustixErrno::NOENT) => return Ok(false),
        Err(error) => return Err(error).context("open confined OCI image home"),
    };
    let stat = rustix::fs::fstat(&descriptor).context("inspect confined OCI image home")?;
    ensure!(
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::Directory,
        "OCI image home is not a directory"
    );
    Ok(true)
}

fn prepare_container_control(
    seed: &Seed,
    workspace_identity: &WorkspaceIdentity,
) -> Result<UnixDatagram> {
    for (path, mode) in [
        ("/run/codewire", 0o700),
        (RUNC_STATE_PATH, 0o700),
        (RUNC_PROCESS_PATH, 0o700),
        (CONTAINER_CONTROL_PATH, 0o700),
    ] {
        create_dir(Path::new(path), mode)?;
    }

    let identity = GuestIdentity::from_seed(seed);
    identity.validate()?;
    let identity_bytes = serde_json::to_vec(&identity).context("encode guest identity metadata")?;
    write_durable(Path::new(CONTAINER_IDENTITY_PATH), &identity_bytes, 0o400)
        .context("publish guest identity metadata")?;
    write_durable(
        Path::new(CONTAINER_MACHINE_ID_PATH),
        identity.machine_id().as_bytes(),
        0o444,
    )
    .context("publish environment-specific machine identity")?;
    write_durable(
        Path::new(CONTAINER_RESOLV_CONF_PATH),
        format!("nameserver {NETWORK_GATEWAY_ADDRESS}\noptions attempts:1 timeout:1\n").as_bytes(),
        0o444,
    )
    .context("publish isolated workspace resolver configuration")?;
    lchown(
        Path::new(CONTAINER_IDENTITY_PATH),
        workspace_identity.uid,
        workspace_identity.gid,
    )?;

    let socket_path = Path::new(CONTAINER_POWEROFF_SOCKET);
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(socket_path).context("remove stale guest poweroff socket")?;
        }
        Ok(_) => bail!("guest poweroff path contains an unexpected object"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect guest poweroff socket"),
    }
    let socket = UnixDatagram::bind(socket_path).context("bind guest poweroff socket")?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .context("confine guest poweroff socket")?;
    lchown(socket_path, workspace_identity.uid, workspace_identity.gid)?;
    lchown(
        Path::new(CONTAINER_CONTROL_PATH),
        workspace_identity.uid,
        workspace_identity.gid,
    )?;
    socket
        .set_nonblocking(true)
        .context("make guest poweroff socket nonblocking")?;
    Ok(socket)
}

struct GuestNetworkAgent {
    child: Option<std::process::Child>,
    readiness: UnixStream,
}

impl GuestNetworkAgent {
    fn wait_for_host(&mut self) -> Result<()> {
        wait_for_network_agent_message(
            &mut self.readiness,
            NETWORK_AGENT_HOST_READY,
            NETWORK_AGENT_HOST_TIMEOUT,
        )
    }

    fn into_child(mut self) -> Result<std::process::Child> {
        self.child
            .take()
            .ok_or_else(|| anyhow::anyhow!("guest network agent child is absent"))
    }
}

impl Drop for GuestNetworkAgent {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_guest_network_agent() -> Result<GuestNetworkAgent> {
    create_dir(Path::new(NETWORK_NAMESPACE_DIRECTORY), 0o700)?;
    let namespace = Path::new(NETWORK_NAMESPACE_PATH);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let namespace_file = options
        .open(namespace)
        .context("create private workspace network namespace mountpoint")?;
    namespace_file
        .sync_all()
        .context("sync workspace network namespace mountpoint")?;
    drop(namespace_file);

    let (readiness, readiness_writer) =
        UnixStream::pair().context("create guest network readiness channel")?;
    readiness
        .set_nonblocking(true)
        .context("make guest network readiness channel nonblocking")?;
    let readiness_fd = readiness_writer.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = Command::new(INIT_PATH);
    command
        .arg("network-agent")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                || libc::getppid() != expected_parent
                || libc::unshare(libc::CLONE_NEWNET) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if readiness_fd != NETWORK_AGENT_READY_FD
                && libc::dup2(readiness_fd, NETWORK_AGENT_READY_FD) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(NETWORK_AGENT_READY_FD, libc::F_SETFD, 0) == -1
                || libc::syscall(
                    libc::SYS_close_range,
                    4_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .context("spawn trusted guest network agent")?;
    let mut agent = GuestNetworkAgent {
        child: Some(child),
        readiness,
    };
    drop(readiness_writer);

    let pid = agent
        .child
        .as_ref()
        .map(std::process::Child::id)
        .ok_or_else(|| anyhow::anyhow!("guest network agent PID is absent"))?;
    let source = format!("/proc/{pid}/ns/net");
    let link = fs::read_link(&source).context("inspect guest network agent namespace")?;
    ensure!(
        link.as_os_str().as_bytes().starts_with(b"net:["),
        "guest network agent namespace identity is invalid"
    );
    mount_fs(&source, NETWORK_NAMESPACE_PATH, "none", libc::MS_BIND, "")
        .context("pin workspace network namespace")?;
    validate_network_namespace_mount(namespace)?;
    wait_for_network_agent_message(
        &mut agent.readiness,
        NETWORK_AGENT_READY,
        NETWORK_AGENT_START_TIMEOUT,
    )?;
    Ok(agent)
}

fn validate_network_namespace_mount(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .context("workspace network namespace path contains NUL")?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut filesystem) } == -1 {
        return Err(io::Error::last_os_error())
            .context("inspect workspace network namespace mount");
    }
    ensure!(
        filesystem.f_type as u64 == NSFS_MAGIC,
        "workspace network namespace is not an nsfs mount"
    );
    Ok(())
}

fn wait_for_network_agent_message(
    stream: &mut UnixStream,
    expected: &[u8],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut received = Vec::with_capacity(expected.len());
    while Instant::now() < deadline {
        let mut buffer = [0_u8; 64];
        let remaining = expected.len().saturating_sub(received.len());
        let chunk = remaining.min(buffer.len());
        match stream.read(&mut buffer[..chunk]) {
            Ok(0) => bail!("guest network readiness channel closed early"),
            Ok(length) => {
                received.extend_from_slice(&buffer[..length]);
                ensure!(
                    expected.starts_with(&received),
                    "guest network readiness message is invalid"
                );
                if received == expected {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error).context("read guest network readiness"),
        }
    }
    bail!("guest network readiness timed out")
}

fn prepare_workspace_generation(plan: &WorkspacePlan) -> Result<()> {
    for (path, mode) in [
        (ROOT_UPPER_PATH, 0o700),
        (ROOT_WORK_PATH, 0o700),
        (ROOT_MERGED_PATH, 0o700),
        (RUNC_BUNDLE_PATH, 0o700),
    ] {
        create_dir(Path::new(path), mode)?;
    }
    let generation = Sha256Value::parse_hex(&plan.root_generation)
        .context("decode sealed OCI root generation")?;
    verify_completed_setup_generation(Path::new(ROOT_MOUNT_PATH), generation)
        .context("validate completed OCI root generation")?;
    let metadata =
        fs::symlink_metadata(ROOT_LOWER_PATH).context("inspect completed OCI lower directory")?;
    ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == unsafe { libc::getegid() }
            && metadata.permissions().mode() & 0o777 == OCI_LOWER_ROOT_MODE,
        "completed OCI lower directory is invalid"
    );

    let config = workspace_oci_config(plan)?;
    ensure_exact_bytes(Path::new(RUNC_CONFIG_PATH), &config, 0o400)?;
    inherit_root_directory_metadata(Path::new(ROOT_LOWER_PATH), Path::new(ROOT_UPPER_PATH))?;

    mount_fs(
        "overlay",
        ROOT_MERGED_PATH,
        "overlay",
        libc::MS_NOSUID | libc::MS_NODEV,
        &format!("lowerdir={ROOT_LOWER_PATH},upperdir={ROOT_UPPER_PATH},workdir={ROOT_WORK_PATH}"),
    )
    .context("mount workspace root overlay")?;
    Ok(())
}

fn inherit_root_directory_metadata(lower: &Path, upper: &Path) -> Result<()> {
    let lower_metadata = fs::symlink_metadata(lower).context("inspect workspace lower root")?;
    let upper_metadata = fs::symlink_metadata(upper).context("inspect workspace upper root")?;
    ensure!(
        lower_metadata.file_type().is_dir() && upper_metadata.file_type().is_dir(),
        "workspace root overlay path is not a directory"
    );
    lchown(upper, lower_metadata.uid(), lower_metadata.gid())?;
    fs::set_permissions(
        upper,
        fs::Permissions::from_mode(lower_metadata.permissions().mode() & 0o7777),
    )
    .context("copy admitted OCI root mode to overlay upper")
}

fn ensure_exact_bytes(path: &Path, expected: &[u8], mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o777 == mode
                    && metadata.nlink() == 1
                    && metadata.len() == expected.len() as u64,
                "root generation contains an invalid sealed file"
            );
            let actual = read_bounded(path, expected.len().saturating_add(1))?;
            ensure!(
                Sha256::digest(&actual) == Sha256::digest(expected),
                "root generation sealed file digest changed"
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_durable(path, expected, mode).context("publish sealed root generation file")
        }
        Err(error) => Err(error).with_context(|| format!("inspect sealed file {}", path.display())),
    }
}

fn workspace_oci_config(plan: &WorkspacePlan) -> Result<Vec<u8>> {
    let standard_devices = [
        ("/dev/null", 1, 3, 0o666),
        ("/dev/zero", 1, 5, 0o666),
        ("/dev/full", 1, 7, 0o666),
        ("/dev/tty", 5, 0, 0o666),
        ("/dev/random", 1, 8, 0o666),
        ("/dev/urandom", 1, 9, 0o666),
    ];
    let devices = standard_devices
        .iter()
        .map(|(path, major, minor, mode)| {
            serde_json::json!({
                "path": path,
                "type": "c",
                "major": major,
                "minor": minor,
                "fileMode": mode,
                "uid": 0,
                "gid": 0
            })
        })
        .collect::<Vec<_>>();
    let allowed_devices = standard_devices
        .iter()
        .map(|(_, major, minor, _)| {
            serde_json::json!({
                "allow": true,
                "type": "c",
                "major": major,
                "minor": minor,
                "access": "rwm"
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "ociVersion": "1.2.0",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": [CONTAINER_INIT_PATH, "workspace-init"],
            "env": [
                "HOME=/root",
                "USER=root",
                "SHELL=/bin/sh",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C.UTF-8"
            ],
            "cwd": "/",
            "capabilities": {
                "bounding": ["CAP_SETGID", "CAP_SETUID"],
                "effective": ["CAP_SETGID", "CAP_SETUID"],
                "inheritable": [],
                "permitted": ["CAP_SETGID", "CAP_SETUID"],
                "ambient": []
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576 }
            ],
            "noNewPrivileges": true
        },
        "root": { "path": "../merged", "readonly": false },
        "hostname": "codewire",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev", "mode=0755", "size=16m"] },
            { "destination": CONTAINER_INIT_PATH, "type": "none", "source": INIT_PATH, "options": ["bind", "ro", "nosuid", "nodev", "exec"] },
            { "destination": CONTAINER_PLAN_PATH, "type": "none", "source": WORKSPACE_PLAN_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_INSTALL_STATE_PATH, "type": "none", "source": INSTALL_STATE_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_MACHINE_ID_DESTINATION, "type": "none", "source": CONTAINER_MACHINE_ID_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_RESOLV_CONF_DESTINATION, "type": "none", "source": CONTAINER_RESOLV_CONF_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", "size=256m"] },
            { "destination": WORKSPACE_PATH, "type": "none", "source": PERSISTENT_WORKSPACE_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": plan.identity.home, "type": "none", "source": HOME_MERGED_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": CONTAINER_CONTROL_DESTINATION, "type": "none", "source": CONTAINER_CONTROL_PATH, "options": ["rbind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_PROBE_DESTINATION, "type": "none", "source": PERSISTENT_PROBE_PATH, "options": ["rbind", "rw", "nosuid", "nodev", "noexec"] }
        ],
        "linux": {
            "rootfsPropagation": "rslave",
            "resources": {
                "devices": std::iter::once(serde_json::json!({ "allow": false, "access": "rwm" }))
                    .chain(allowed_devices)
                    .collect::<Vec<_>>()
            },
            "namespaces": [
                { "type": "pid" },
                { "type": "network", "path": NETWORK_NAMESPACE_PATH },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" }
            ],
            "devices": devices,
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
                "/proc/sched_debug", "/sys/firmware", "/sys/devices/virtual/powercap"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    }))
    .context("encode workspace OCI configuration")
}

fn bind_mount(source: &str, target: &str) -> Result<()> {
    mount_fs(source, target, "none", libc::MS_BIND, "")
        .with_context(|| format!("bind persistent guest path {source} at {target}"))?;
    mount_fs(
        source,
        target,
        "none",
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )
    .with_context(|| format!("confine persistent guest bind mount {target}"))
}

fn create_dir(path: &Path, mode: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "required path is not a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set directory mode {}", path.display()))?;
    Ok(())
}

fn create_symlink(target: &str, link: &str) -> Result<()> {
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::read_link(link).ok().as_deref() == Some(Path::new(target)),
                "existing guest device link has unexpected target"
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create guest device link {link}")),
    }
}

fn replace_ptmx_link() -> Result<()> {
    let path = Path::new("/dev/ptmx");
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_symlink() || metadata.file_type().is_char_device(),
                "existing /dev/ptmx has an unexpected file type"
            );
            if metadata.file_type().is_symlink()
                && fs::read_link(path).ok().as_deref() == Some(Path::new("/dev/pts/ptmx"))
            {
                return Ok(());
            }
            fs::remove_file(path).context("replace devtmpfs /dev/ptmx")?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect devtmpfs /dev/ptmx"),
    }
    std::os::unix::fs::symlink("/dev/pts/ptmx", path).context("link active devpts ptmx")
}

fn mount_fs(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    data: &str,
) -> Result<()> {
    let source = CString::new(source).context("mount source contains NUL")?;
    let target_c = CString::new(target).context("mount target contains NUL")?;
    let kind = CString::new(kind).context("mount type contains NUL")?;
    let data = CString::new(data).context("mount data contains NUL")?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            kind.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("mount {kind:?} at {target}"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RuncReportedState {
    id: String,
    status: String,
    pid: i64,
}

struct WorkspaceStartGuard(Option<std::process::Child>);

impl WorkspaceStartGuard {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn child(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("workspace start child is present")
    }

    fn finish(mut self) -> std::process::Child {
        self.0.take().expect("workspace start child is present")
    }
}

impl Drop for WorkspaceStartGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = force_delete_workspace_container();
        }
    }
}

fn spawn_workspace_container(plan: &WorkspacePlan) -> Result<std::process::Child> {
    prepare_runc_log()?;
    let runc_stderr = prepare_runc_stderr()?;
    record_boot_stage("runc-launching")?;
    let expected_readiness = workspace_ready_message(plan)?;
    let (mut readiness, readiness_writer) =
        UnixStream::pair().context("create trusted workspace readiness channel")?;
    readiness
        .set_nonblocking(true)
        .context("make workspace readiness channel nonblocking")?;
    let readiness_fd = readiness_writer.as_raw_fd();
    let mut command = Command::new(RUNC_PATH);
    command
        .args([
            "--root",
            RUNC_STATE_PATH,
            "--log",
            RUNC_LOG_PATH,
            "--log-format",
            "json",
            "run",
            "--no-pivot",
            "--preserve-fds",
            "1",
            "--bundle",
            RUNC_BUNDLE_PATH,
            WORKSPACE_CONTAINER_ID,
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(runc_stderr));
    unsafe {
        command.pre_exec(move || {
            if readiness_fd != WORKSPACE_READY_FD
                && libc::dup2(readiness_fd, WORKSPACE_READY_FD) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(WORKSPACE_READY_FD, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("start sealed runc workspace")?;
    let mut child = WorkspaceStartGuard::new(child);
    record_boot_stage("runc-running")?;
    drop(readiness_writer);
    let deadline = Instant::now() + WORKSPACE_START_TIMEOUT;
    let mut readiness_bytes = Vec::with_capacity(expected_readiness.len());
    loop {
        validate_runc_log()?;
        validate_runc_stderr()?;
        let readiness_state = match advance_workspace_readiness(
            &mut readiness,
            &expected_readiness,
            &mut readiness_bytes,
        ) {
            Ok(state) => state,
            Err(error) => {
                record_boot_stage("workspace-readiness-invalid")?;
                return Err(error);
            }
        };
        match readiness_state {
            WorkspaceReadiness::Pending => {}
            WorkspaceReadiness::Ready if workspace_container_is_running()? => {
                publish_install_completion(plan)?;
                return Ok(child.finish());
            }
            WorkspaceReadiness::Ready => {}
            WorkspaceReadiness::Failed(stage) => {
                record_boot_stage(stage)?;
                bail!("sealed workspace init reported a bounded startup failure");
            }
        }
        if child
            .child()
            .try_wait()
            .context("observe sealed runc workspace startup")?
            .is_some()
        {
            sync_runc_stderr()?;
            record_boot_stage("workspace-container-exited")?;
            bail!("sealed runc workspace exited during startup");
        }
        if Instant::now() >= deadline {
            record_boot_stage("workspace-readiness-timeout")?;
            bail!("sealed runc workspace startup timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceReadiness {
    Pending,
    Ready,
    Failed(&'static str),
}

fn advance_workspace_readiness(
    stream: &mut UnixStream,
    expected: &[u8],
    received: &mut Vec<u8>,
) -> Result<WorkspaceReadiness> {
    let mut buffer = [0_u8; WORKSPACE_READY_LIMIT + 1];
    match stream.read(&mut buffer) {
        Ok(0) => {
            if received == expected {
                return Ok(WorkspaceReadiness::Ready);
            }
            if let Some(stage) = admitted_workspace_failure(received) {
                return Ok(WorkspaceReadiness::Failed(stage));
            }
            bail!("trusted workspace readiness channel closed early")
        }
        Ok(length) => {
            received.extend_from_slice(&buffer[..length]);
            ensure!(
                received.len() <= WORKSPACE_READY_LIMIT
                    && (expected.starts_with(received)
                        || WORKSPACE_FAILURE_FRAMES
                            .iter()
                            .any(|(frame, _)| frame.starts_with(received))),
                "trusted workspace readiness message is invalid"
            );
            // runc retains its preserved descriptor while the container is
            // alive, so EOF is not a protocol delimiter. Only trusted PID 1
            // can write: it marks this descriptor close-on-exec before any
            // image process is spawned. The fixed, digest-bound length is the
            // complete frame.
            if received == expected {
                Ok(WorkspaceReadiness::Ready)
            } else if let Some(stage) = admitted_workspace_failure(received) {
                Ok(WorkspaceReadiness::Failed(stage))
            } else {
                Ok(WorkspaceReadiness::Pending)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(WorkspaceReadiness::Pending),
        Err(error) => Err(error).context("read trusted workspace readiness"),
    }
}

fn admitted_workspace_failure(received: &[u8]) -> Option<&'static str> {
    WORKSPACE_FAILURE_FRAMES
        .iter()
        .find_map(|(frame, stage)| (*frame == received).then_some(*stage))
}

fn prepare_runc_log() -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let log = options
        .open(RUNC_LOG_PATH)
        .context("prepare bounded runc log")?;
    let metadata = log.metadata().context("inspect bounded runc log")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1,
        "runc log is not an owner-private regular file"
    );
    log.sync_all().context("sync empty runc log")?;
    drop(log);
    validate_runc_log()
}

fn prepare_runc_stderr() -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let stderr = options
        .open(RUNC_STDERR_PATH)
        .context("prepare bounded runc stderr")?;
    validate_runc_stderr()?;
    stderr.sync_all().context("sync empty runc stderr")?;
    Ok(stderr)
}

fn validate_runc_stderr() -> Result<()> {
    let metadata = fs::symlink_metadata(RUNC_STDERR_PATH).context("inspect bounded runc stderr")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == unsafe { libc::getegid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1,
        "runc stderr is not an owner-private regular file"
    );
    ensure!(
        metadata.len() <= RUNC_LOG_LIMIT,
        "runc stderr exceeded its {} byte bound",
        RUNC_LOG_LIMIT
    );
    Ok(())
}

fn sync_runc_stderr() -> Result<()> {
    validate_runc_stderr()?;
    File::open(RUNC_STDERR_PATH)
        .context("open bounded runc stderr for sync")?
        .sync_all()
        .context("sync bounded runc stderr")
}

fn validate_runc_log() -> Result<()> {
    let metadata = fs::symlink_metadata(RUNC_LOG_PATH).context("inspect bounded runc log")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1,
        "runc log is not an owner-private regular file"
    );
    ensure!(
        metadata.len() <= RUNC_LOG_LIMIT,
        "runc log exceeded its {} byte bound",
        RUNC_LOG_LIMIT
    );
    Ok(())
}

fn workspace_container_is_running() -> Result<bool> {
    validate_runc_log()?;
    let mut command = Command::new(RUNC_PATH);
    command
        .args(["--root", RUNC_STATE_PATH, "state", WORKSPACE_CONTAINER_ID])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("query sealed runc workspace state")?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("runc state stdout is unavailable"))?;
    let Some((status, bytes)) =
        wait_for_bounded_child_output(&mut child, &mut stdout, 64 * 1024, RUNC_CONTROL_TIMEOUT)
            .context("collect sealed runc workspace state")?
    else {
        bail!("sealed runc workspace state query timed out");
    };
    if !status.success() {
        return Ok(false);
    }
    let state: RuncReportedState =
        serde_json::from_slice(&bytes).context("decode sealed runc workspace state")?;
    ensure!(
        state.id == WORKSPACE_CONTAINER_ID && state.pid > 1,
        "sealed runc workspace reported an invalid identity"
    );
    Ok(state.status == "running")
}

fn wait_for_bounded_child_output(
    child: &mut std::process::Child,
    stdout: &mut std::process::ChildStdout,
    limit: usize,
    timeout: Duration,
) -> io::Result<Option<(std::process::ExitStatus, Vec<u8>)>> {
    let descriptor = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        let error = io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut status = None;
    let mut eof = false;
    loop {
        let mut buffer = [0_u8; 4096];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(length) => {
                    if bytes.len().saturating_add(length) > limit {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "child output exceeded its bound",
                        ));
                    }
                    bytes.extend_from_slice(&buffer[..length]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
        }
        if let Some(status) = status
            && eof
        {
            return Ok(Some((status, bytes)));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_daemon() -> Result<std::process::Child> {
    let mut command = Command::new(INIT_PATH);
    command
        .arg("daemon")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
        .spawn()
        .context("spawn environment-free guest daemon")
}

fn supervise_guest(
    mut daemon: std::process::Child,
    mut workspace: std::process::Child,
    mut network: std::process::Child,
    poweroff: UnixDatagram,
) -> Result<()> {
    loop {
        validate_runc_log()?;
        if POWEROFF_REQUESTED.load(Ordering::Acquire) || container_poweroff_requested(&poweroff)? {
            stop_daemon(&mut daemon);
            stop_workspace_container(&mut workspace);
            stop_network_agent(&mut network);
            return power_off();
        }
        if daemon.try_wait().context("observe guest daemon")?.is_some() {
            eprintln!("guest daemon exited; powering off generation");
            stop_workspace_container(&mut workspace);
            stop_network_agent(&mut network);
            return power_off();
        }
        if workspace
            .try_wait()
            .context("observe sealed runc workspace")?
            .is_some()
        {
            eprintln!("workspace container exited; powering off generation");
            stop_daemon(&mut daemon);
            stop_network_agent(&mut network);
            let _ = force_delete_workspace_container();
            return power_off();
        }
        if network
            .try_wait()
            .context("observe trusted guest network agent")?
            .is_some()
        {
            eprintln!("guest network agent exited; powering off generation");
            stop_daemon(&mut daemon);
            stop_workspace_container(&mut workspace);
            return power_off();
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn stop_network_agent(network: &mut std::process::Child) {
    if network.try_wait().ok().flatten().is_some() {
        return;
    }
    if let Ok(pid) = libc::pid_t::try_from(network.id()) {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + DAEMON_SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        if network.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = network.kill();
    let _ = network.wait();
}

fn container_poweroff_requested(socket: &UnixDatagram) -> Result<bool> {
    let mut message = [0_u8; 16];
    for _ in 0..CONTROL_MESSAGE_LIMIT {
        match socket.recv(&mut message) {
            Ok(length) if &message[..length] == b"poweroff" => return Ok(true),
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error).context("receive workspace poweroff request"),
        }
    }
    Ok(false)
}

fn stop_daemon(daemon: &mut std::process::Child) {
    if daemon.try_wait().ok().flatten().is_some() {
        return;
    }
    if let Ok(pid) = libc::pid_t::try_from(daemon.id()) {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + DAEMON_SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        if daemon.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = daemon.kill();
    let _ = daemon.wait();
}

fn stop_workspace_container(workspace: &mut std::process::Child) {
    let kill_completed = run_runc_control(&[
        "--root",
        RUNC_STATE_PATH,
        "kill",
        WORKSPACE_CONTAINER_ID,
        "KILL",
    ])
    .ok()
    .flatten()
    .is_some();
    let deadline = if kill_completed {
        Instant::now() + WORKSPACE_STOP_TIMEOUT
    } else {
        Instant::now()
    };
    while Instant::now() < deadline {
        if workspace.try_wait().ok().flatten().is_some() {
            let _ = force_delete_workspace_container();
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = workspace.kill();
    let _ = workspace.wait();
    let _ = force_delete_workspace_container();
}

fn force_delete_workspace_container() -> io::Result<()> {
    let _ = run_runc_control(&[
        "--root",
        RUNC_STATE_PATH,
        "delete",
        "--force",
        WORKSPACE_CONTAINER_ID,
    ])?;
    Ok(())
}

fn run_runc_control(arguments: &[&str]) -> io::Result<Option<std::process::ExitStatus>> {
    let mut child = Command::new(RUNC_PATH)
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + RUNC_CONTROL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

extern "C" fn request_poweroff_signal(_: libc::c_int) {
    POWEROFF_REQUESTED.store(true, Ordering::Release);
}

fn install_poweroff_handlers() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_poweroff_signal as *const () as usize;
    action.sa_flags = libc::SA_NOCLDSTOP;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGUSR1, libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
            return Err(io::Error::last_os_error()).context("install guest init signal handler");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        return;
    };
    let Ok(mut interrupt) = signal(SignalKind::interrupt()) else {
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

fn power_off() -> Result<()> {
    unsafe {
        libc::sync();
    }
    let result = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("power off guest");
    }
    bail!("guest poweroff syscall unexpectedly returned")
}

/// PID 1 must not return into the kernel after a setup or supervision error.
/// Attempt a synchronized poweroff and, if the syscall itself fails, attempt
/// to kill the remaining workload and keep polling for exited children until
/// the host force-stops the failed VM.
pub fn halt_after_init_failure() -> ! {
    unsafe {
        libc::sync();
        if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) == -1 {
            // The VM should grant PID 1 CAP_SYS_BOOT. If it does not, make a
            // best-effort attempt to stop every other guest process while the
            // host times out and force-stops the failed VM.
            libc::kill(-1, libc::SIGKILL);
        }
    }
    eprintln!("guest PID 1 poweroff failed; halting without exiting");
    loop {
        unsafe {
            let mut status = 0;
            while libc::waitpid(-1, &mut status, libc::WNOHANG) > 0 {}
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn validate_nonce(nonce: &OsStr) -> Result<&str> {
    let nonce = nonce
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("nonce is not UTF-8"))?;
    ensure!(
        !nonce.is_empty() && nonce.len() <= NONCE_MAX_LEN,
        "nonce length is invalid"
    );
    ensure!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "nonce contains invalid characters"
    );
    Ok(nonce)
}

fn read_nonce(path: &Path) -> Result<String> {
    ensure!(path.is_absolute(), "nonce path must be absolute");
    let bytes = read_bounded(path, NONCE_MAX_LEN + 1).context("read guest nonce")?;
    let nonce = OsStr::from_bytes(&bytes);
    Ok(validate_nonce(nonce)?.to_owned())
}

fn write_durable(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    ensure!(path.is_absolute(), "durable output path must be absolute");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable output has no parent"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("durable output name is invalid"))?;

    for _ in 0..16 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp.{}.{}", std::process::id(), sequence));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create durable temporary file"),
        };
        let operation = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(parent)?.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = operation {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("commit durable guest file");
        }
        return Ok(());
    }
    bail!("durable temporary filename collisions exceeded limit")
}

fn verify_isolated_tun(net_dev: &Path, route: &Path, ipv6_route: &Path) -> Result<()> {
    // An inherited sysfs mount remains associated with the network namespace
    // in which it was mounted. /proc/net is process-namespace aware, so use
    // its bounded interface table to inspect this agent's actual namespace.
    let devices = fs::read_to_string(net_dev)
        .with_context(|| format!("read guest network interfaces {}", net_dev.display()))?;
    let mut lines = devices.lines();
    ensure!(
        lines.next().is_some() && lines.next().is_some(),
        "guest network interface table is malformed"
    );
    let mut interfaces = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let (interface, counters) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("guest network interface table is malformed"))?;
        let interface = interface.trim();
        let counters = counters.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(
            !interface.is_empty()
                && counters.len() == 16
                && counters
                    .iter()
                    .all(|value| !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())),
            "guest network interface table is malformed"
        );
        interfaces.push(interface);
    }
    interfaces.sort();
    ensure!(
        interfaces.as_slice() == [NETWORK_INTERFACE, "lo"],
        "guest network namespace does not contain exactly loopback and the trusted TUN"
    );

    let routes = fs::read_to_string(route)
        .with_context(|| format!("read guest route table {}", route.display()))?;
    let mut default_route = false;
    for line in routes
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() >= 8, "guest route table is malformed");
        ensure!(
            matches!(fields[0], "lo" | NETWORK_INTERFACE),
            "guest has a route through an unexpected interface"
        );
        if fields[1] == "00000000" {
            ensure!(
                fields[0] == NETWORK_INTERFACE
                    && fields[2].eq_ignore_ascii_case("010200C0")
                    && fields[7] == "00000000",
                "guest default route is not bound to the trusted TUN gateway"
            );
            default_route = true;
        }
    }
    ensure!(default_route, "guest trusted TUN default route is absent");

    match fs::read_to_string(ipv6_route) {
        Ok(routes) => {
            for line in routes.lines().filter(|line| !line.trim().is_empty()) {
                let interface = line
                    .split_ascii_whitespace()
                    .next_back()
                    .ok_or_else(|| anyhow::anyhow!("guest IPv6 route table is malformed"))?;
                ensure!(
                    interface == "lo",
                    "guest TUN unexpectedly has an IPv6 route"
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A kernel with IPv6 disabled has no IPv6 route surface.
        }
        Err(error) => return Err(error).context("read guest IPv6 route table"),
    }
    Ok(())
}

fn ensure_init_is_expected(container: bool) -> Result<()> {
    let (process, expected) = if container {
        ("self", Path::new(CONTAINER_INIT_PATH))
    } else {
        ("1", Path::new(INIT_PATH))
    };
    let executable = fs::read_link(format!("/proc/{process}/exe"))
        .context("inspect sealed guest init executable")?;
    ensure!(
        executable == expected,
        "guest helper is not the sealed Codewire init"
    );
    Ok(())
}

trait PoweroffOperations {
    fn persist_marker(&mut self) -> Result<()>;
    fn emit_marker(&mut self) -> Result<()>;
    fn signal_init(&mut self) -> Result<()>;
}

fn request_poweroff(operations: &mut impl PoweroffOperations) -> Result<()> {
    operations.persist_marker()?;
    operations.emit_marker()?;
    operations.signal_init()
}

struct RealPoweroffOperations {
    marker: String,
    marker_path: PathBuf,
    target: PoweroffTarget,
}

enum PoweroffTarget {
    SignalGuestInit,
    Socket(PathBuf),
}

impl PoweroffOperations for RealPoweroffOperations {
    fn persist_marker(&mut self) -> Result<()> {
        write_durable(&self.marker_path, self.marker.as_bytes(), 0o600)
    }

    fn emit_marker(&mut self) -> Result<()> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(self.marker.as_bytes())?;
        stdout.flush()?;
        Ok(())
    }

    fn signal_init(&mut self) -> Result<()> {
        match &self.target {
            PoweroffTarget::SignalGuestInit => {
                if unsafe { libc::kill(1, libc::SIGUSR1) } == -1 {
                    return Err(io::Error::last_os_error())
                        .context("signal guest init for poweroff");
                }
            }
            PoweroffTarget::Socket(path) => {
                let socket = UnixDatagram::unbound().context("open workspace poweroff socket")?;
                socket
                    .send_to(b"poweroff", path)
                    .context("request workspace VM poweroff")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_plan::PLAN_SCHEMA_VERSION;
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use tempfile::TempDir;

    #[derive(Default)]
    struct CountingWake(AtomicU64);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_workspace_plan() -> WorkspacePlan {
        WorkspacePlan {
            schema_version: PLAN_SCHEMA_VERSION,
            root_generation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            identity: WorkspaceIdentity {
                username: "root".to_owned(),
                home: "/root".to_owned(),
                shell: "/bin/sh".to_owned(),
                uid: 0,
                gid: 0,
                additional_gids: Vec::new(),
            },
            environment: vec![
                "HOME=/root".to_owned(),
                "LANG=C.UTF-8".to_owned(),
                "LOGNAME=root".to_owned(),
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
                "SHELL=/bin/sh".to_owned(),
                "USER=root".to_owned(),
            ],
            workload_args: Vec::new(),
            workload_cwd: "/workspace".to_owned(),
            session_cwd: "/workspace".to_owned(),
            install_command: String::new(),
            startup_script: String::new(),
        }
    }

    #[test]
    fn disk_discovery_requires_one_exact_whole_disk_serial() {
        let temporary = TempDir::new().unwrap();
        let sys = temporary.path().join("sys");
        let dev = temporary.path().join("dev");
        fs::create_dir_all(&sys).unwrap();
        fs::create_dir_all(&dev).unwrap();
        for (name, serial) in [
            ("vda", "CWSTATE1\n"),
            ("vda1", "CWSTATE1\n"),
            ("vdb", "other\n"),
        ] {
            fs::create_dir(sys.join(name)).unwrap();
            fs::write(sys.join(name).join("serial"), serial).unwrap();
        }

        assert_eq!(
            find_disk_by_serial(&sys, &dev, STATE_DISK_SERIAL).unwrap(),
            dev.join("vda")
        );
        fs::write(sys.join("vdb").join("serial"), "CWSTATE1\n").unwrap();
        assert!(
            find_disk_by_serial(&sys, &dev, STATE_DISK_SERIAL)
                .unwrap_err()
                .to_string()
                .contains("multiple")
        );
    }

    #[test]
    fn nonce_write_is_atomic_and_strict() {
        let temporary = TempDir::new().unwrap();
        let output = temporary.path().join("nonce");

        write_durable(&output, b"nonce_123", 0o600).unwrap();
        assert_eq!(read_nonce(&output).unwrap(), "nonce_123");
        write_durable(&output, b"replacement-456", 0o600).unwrap();
        assert_eq!(read_nonce(&output).unwrap(), "replacement-456");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(validate_nonce(OsStr::new("contains space")).is_err());
        assert!(!fs::read_dir(temporary.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")
        }));
    }

    #[test]
    fn network_check_requires_exactly_loopback_and_the_pinned_tun() {
        let temporary = TempDir::new().unwrap();
        let net_dev = temporary.path().join("dev");
        fs::write(
            &net_dev,
            "Inter-| Receive | Transmit\n\
             face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n\
             lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
             cw0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        )
        .unwrap();
        let route = temporary.path().join("route");
        fs::write(
            &route,
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
             cw0 00000000 010200C0 0003 0 0 0 00000000 0 0 0\n\
             cw0 000200C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
        )
        .unwrap();
        let ipv6_route = temporary.path().join("ipv6_route");
        fs::write(
            &ipv6_route,
            "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000 00000001 00000000 80200001 lo\n",
        )
        .unwrap();
        verify_isolated_tun(&net_dev, &route, &ipv6_route).unwrap();

        OpenOptions::new()
            .append(true)
            .open(&net_dev)
            .unwrap()
            .write_all(b"eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
            .unwrap();
        assert!(verify_isolated_tun(&net_dev, &route, &ipv6_route).is_err());
    }

    #[test]
    fn runc_helper_accepts_only_the_sealed_pty_shell_environment() {
        assert!(runc_helper_environment_is_admitted(&[]));
        assert!(runc_helper_environment_is_admitted(&[(
            OsString::from("SHELL"),
            OsString::from(INIT_PATH),
        )]));
        for rejected in [
            vec![(OsString::from("SHELL"), OsString::from("/bin/sh"))],
            vec![(OsString::from("PATH"), OsString::from("/bin"))],
            vec![
                (OsString::from("SHELL"), OsString::from(INIT_PATH)),
                (OsString::from("TOKEN"), OsString::from("secret")),
            ],
        ] {
            assert!(!runc_helper_environment_is_admitted(&rejected));
        }
    }

    #[test]
    fn workspace_init_is_a_read_only_sealed_bind_not_overlay_content() {
        let plan = test_workspace_plan();
        let config: serde_json::Value =
            serde_json::from_slice(&workspace_oci_config(&plan).unwrap()).unwrap();
        assert_eq!(
            config["process"]["args"],
            serde_json::json!([CONTAINER_INIT_PATH, "workspace-init"])
        );
        let mounts = config["mounts"].as_array().unwrap();
        let runtime = mounts
            .iter()
            .find(|mount| mount["destination"] == CONTAINER_INIT_PATH)
            .unwrap();
        assert_eq!(runtime["source"], INIT_PATH);
        assert_eq!(
            runtime["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "exec"])
        );
        let run = mounts
            .iter()
            .find(|mount| mount["destination"] == "/run")
            .unwrap();
        assert_eq!(
            run["options"],
            serde_json::json!(["nosuid", "noexec", "nodev", "mode=0755", "size=16m"])
        );
        let plan_mount = mounts
            .iter()
            .find(|mount| mount["destination"] == CONTAINER_PLAN_PATH)
            .unwrap();
        assert_eq!(plan_mount["source"], WORKSPACE_PLAN_PATH);
        assert_eq!(
            plan_mount["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
        let install_state = mounts
            .iter()
            .find(|mount| mount["destination"] == CONTAINER_INSTALL_STATE_PATH)
            .unwrap();
        assert_eq!(install_state["source"], INSTALL_STATE_PATH);
        assert_eq!(
            install_state["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
        let machine_id = mounts
            .iter()
            .find(|mount| mount["destination"] == CONTAINER_MACHINE_ID_DESTINATION)
            .unwrap();
        assert_eq!(machine_id["source"], CONTAINER_MACHINE_ID_PATH);
        assert_eq!(
            machine_id["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
        let resolver = mounts
            .iter()
            .find(|mount| mount["destination"] == CONTAINER_RESOLV_CONF_DESTINATION)
            .unwrap();
        assert_eq!(resolver["source"], CONTAINER_RESOLV_CONF_PATH);
        assert_eq!(
            resolver["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
        let home = mounts
            .iter()
            .find(|mount| mount["destination"] == plan.identity.home)
            .unwrap();
        assert_eq!(home["source"], HOME_MERGED_PATH);
        assert_eq!(
            config["process"]["capabilities"]["effective"],
            serde_json::json!(["CAP_SETGID", "CAP_SETUID"])
        );
        assert_eq!(
            config["process"]["capabilities"]["ambient"],
            serde_json::json!([])
        );
        assert_eq!(
            config["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|namespace| namespace["type"] == "network")
                .collect::<Vec<_>>(),
            vec![&serde_json::json!({
                "type": "network",
                "path": NETWORK_NAMESPACE_PATH
            })]
        );
        assert!(
            config["linux"]["devices"]
                .as_array()
                .unwrap()
                .iter()
                .all(|device| device["path"] != "/dev/net/tun")
        );
    }

    #[test]
    fn workspace_machine_id_is_stable_per_environment_without_image_identity_reuse() {
        let first = GuestIdentity {
            vm_id: uuid::Uuid::parse_str("20cf5e9e-5615-4f51-ae28-20d228223cc3").unwrap(),
            generation: 1,
        };
        let restarted = GuestIdentity {
            generation: 2,
            ..first.clone()
        };
        let second = GuestIdentity {
            vm_id: uuid::Uuid::parse_str("341eed6a-1529-4d77-a922-d185c58408da").unwrap(),
            generation: 1,
        };

        assert_eq!(first.machine_id(), "20cf5e9e56154f51ae2820d228223cc3\n");
        assert_eq!(restarted.machine_id(), first.machine_id());
        assert_ne!(second.machine_id(), first.machine_id());
    }

    #[test]
    fn boot_without_setup_requires_an_exact_persisted_oci_plan() {
        assert!(require_persisted_workspace_plan(None).is_err());
        let plan = test_workspace_plan();
        assert_eq!(
            require_persisted_workspace_plan(Some(plan.clone())).unwrap(),
            plan
        );
    }

    #[test]
    fn overlay_upper_inherits_the_admitted_root_directory_mode() {
        let temporary = TempDir::new().unwrap();
        let lower = temporary.path().join("lower");
        let upper = temporary.path().join("upper");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&upper).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o751)).unwrap();
        fs::set_permissions(&upper, fs::Permissions::from_mode(0o700)).unwrap();

        inherit_root_directory_metadata(&lower, &upper).unwrap();

        let lower_metadata = fs::symlink_metadata(&lower).unwrap();
        let upper_metadata = fs::symlink_metadata(&upper).unwrap();
        assert_eq!(upper_metadata.uid(), lower_metadata.uid());
        assert_eq!(upper_metadata.gid(), lower_metadata.gid());
        assert_eq!(upper_metadata.permissions().mode() & 0o7777, 0o751);
    }

    #[test]
    fn workspace_completion_messages_are_digest_only_and_plan_bound() {
        let mut plan = test_workspace_plan();
        plan.install_command = "attacker-install-canary".to_owned();
        plan.startup_script = "attacker-startup-canary".to_owned();
        let ready = workspace_ready_message(&plan).unwrap();
        let install = install_completion(&plan).unwrap();
        for message in [&ready, &install] {
            let message = std::str::from_utf8(message).unwrap();
            assert!(!message.contains("attacker-install-canary"));
            assert!(!message.contains("attacker-startup-canary"));
        }
        assert!(
            std::str::from_utf8(&ready)
                .unwrap()
                .starts_with("CWREADY1 ")
        );
        assert!(
            std::str::from_utf8(&install)
                .unwrap()
                .starts_with("codewire-workspace-install-v1 ")
        );
        assert!(valid_install_state(PENDING_INSTALL_STATE));
        assert!(valid_install_state(&install));
        assert!(!valid_install_state(
            b"codewire-workspace-install-v1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        ));
        assert!(valid_workspace_owner_marker(
            b"codewire-workspace-owner-v3 oci 1000:998\n"
        ));
        assert!(!valid_workspace_owner_marker(
            b"codewire-workspace-owner-v3 oci 01000:998\n"
        ));
        assert!(!valid_workspace_owner_marker(
            b"codewire-workspace-owner-v2 oci 1000:998\n"
        ));
        assert!(!valid_workspace_owner_marker(
            b"codewire-workspace-owner-v2 foundation 0:0\n"
        ));
        assert!(!valid_workspace_owner_marker(
            b"codewire-workspace-owner-v1\n"
        ));
    }

    #[test]
    fn workspace_readiness_requires_one_exact_fixed_length_message() {
        let expected = workspace_ready_message(&test_workspace_plan()).unwrap();
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let midpoint = expected.len() / 2;
        writer.write_all(&expected[..midpoint]).unwrap();
        let mut received = Vec::new();
        assert_eq!(
            advance_workspace_readiness(&mut reader, &expected, &mut received).unwrap(),
            WorkspaceReadiness::Pending
        );
        writer.write_all(&expected[midpoint..]).unwrap();
        assert_eq!(
            advance_workspace_readiness(&mut reader, &expected, &mut received).unwrap(),
            WorkspaceReadiness::Ready
        );

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let failure = WORKSPACE_FAILURE_FRAMES
            .iter()
            .copied()
            .find(|(_, stage)| *stage == "workspace-workload-failed")
            .unwrap();
        writer.write_all(&failure.0[..8]).unwrap();
        let mut received = Vec::new();
        assert_eq!(
            advance_workspace_readiness(&mut reader, &expected, &mut received).unwrap(),
            WorkspaceReadiness::Pending
        );
        writer.write_all(&failure.0[8..]).unwrap();
        assert_eq!(
            advance_workspace_readiness(&mut reader, &expected, &mut received).unwrap(),
            WorkspaceReadiness::Failed(failure.1)
        );

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(&expected).unwrap();
        writer.write_all(b"forged-suffix").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let error =
            advance_workspace_readiness(&mut reader, &expected, &mut Vec::new()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "trusted workspace readiness message is invalid"
        );
    }

    #[test]
    fn setup_header_is_seed_size_digest_generation_and_architecture_bound() {
        use std::io::Cursor;

        use crate::{SETUP_ALIGNMENT, SetupBlob};

        let architecture = match std::env::consts::ARCH {
            "x86_64" => SetupArchitecture::Amd64,
            "aarch64" => SetupArchitecture::Arm64,
            other => panic!("unsupported test architecture {other}"),
        };
        let project_sha256 = Sha256Value::calculate(b"{}");
        let manifest_sha256 = Sha256Value::calculate(b"manifest");
        let root_generation =
            crate::oci_root_generation(project_sha256, manifest_sha256, architecture);
        let header = SetupHeader::layout(
            root_generation,
            manifest_sha256,
            architecture,
            SetupBlob {
                size: 2,
                sha256: project_sha256,
            },
            SetupBlob {
                size: 2,
                sha256: Sha256Value::calculate(b"{}"),
            },
            Vec::new(),
        )
        .unwrap();
        let header_bytes = header.encode().unwrap();
        let binding = SetupBinding::new(
            header.total_bytes,
            root_generation,
            Sha256Value::calculate(&header_bytes),
        )
        .unwrap();
        let mut pack = header_bytes;
        pack.resize(header.total_bytes as usize, 0);
        assert_eq!(
            verify_setup_header(&mut Cursor::new(&pack), binding).unwrap(),
            header
        );

        let mut truncated = pack.clone();
        truncated.truncate(truncated.len() - SETUP_ALIGNMENT as usize);
        assert!(verify_setup_header(&mut Cursor::new(truncated), binding).is_err());

        let mut corrupt = pack;
        corrupt[100] ^= 1;
        assert!(verify_setup_header(&mut Cursor::new(corrupt), binding).is_err());

        let wrong_generation = SetupBinding::new(
            header.total_bytes,
            Sha256Value::calculate(b"other-root"),
            binding.header_sha256(),
        )
        .unwrap();
        let mut exact = header.encode().unwrap();
        exact.resize(header.total_bytes as usize, 0);
        assert!(verify_setup_header(&mut Cursor::new(exact), wrong_generation).is_err());
    }

    #[test]
    fn child_output_collection_is_bounded_and_reaps_a_timeout() {
        let mut child = Command::new("/usr/bin/printf")
            .arg("bounded")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (status, output) =
            wait_for_bounded_child_output(&mut child, &mut stdout, 64, Duration::from_secs(1))
                .unwrap()
                .unwrap();
        assert!(status.success());
        assert_eq!(output, b"bounded");

        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        assert!(
            wait_for_bounded_child_output(&mut child, &mut stdout, 64, Duration::from_millis(20),)
                .unwrap()
                .is_none()
        );
        assert!(child.try_wait().unwrap().is_some());
    }

    #[derive(Default)]
    struct RecordingPoweroff {
        events: Vec<&'static str>,
        fail_emit: bool,
    }

    impl PoweroffOperations for RecordingPoweroff {
        fn persist_marker(&mut self) -> Result<()> {
            self.events.push("persist");
            Ok(())
        }

        fn emit_marker(&mut self) -> Result<()> {
            self.events.push("emit");
            if self.fail_emit {
                bail!("emit failed")
            }
            Ok(())
        }

        fn signal_init(&mut self) -> Result<()> {
            self.events.push("signal");
            Ok(())
        }
    }

    #[test]
    fn poweroff_signals_only_after_durable_and_emitted_acceptance() {
        let mut operations = RecordingPoweroff::default();
        request_poweroff(&mut operations).unwrap();
        assert_eq!(operations.events, ["persist", "emit", "signal"]);

        let mut operations = RecordingPoweroff {
            fail_emit: true,
            ..RecordingPoweroff::default()
        };
        assert!(request_poweroff(&mut operations).is_err());
        assert_eq!(operations.events, ["persist", "emit"]);
    }

    #[test]
    fn daemon_transport_accepts_only_the_host_cid() {
        assert!(is_host_cid(VMADDR_CID_HOST));
        assert!(!is_host_cid(VMADDR_CID_ANY));
        assert!(!is_host_cid(3));
        assert!(!is_host_cid(u32::MAX));
    }

    #[test]
    fn network_startup_failures_are_fixed_bounded_progress_stages() {
        let mut stages = NETWORK_AGENT_FAILURE_STAGES.to_vec();
        stages.push(NETWORK_AGENT_GENERIC_FAILURE_STAGE);
        stages.push(NETWORK_AGENT_HOST_FAILURE_STAGE);
        let original_len = stages.len();
        stages.sort_unstable();
        stages.dedup();
        assert_eq!(stages.len(), original_len);
        for stage in stages {
            assert!(!stage.is_empty() && stage.len() <= 32);
            assert!(
                stage
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            );
            assert_eq!(
                GuestBootStage::from_persisted(stage),
                Some(GuestBootStage::WorkspaceFailed)
            );
        }
    }

    #[test]
    fn network_handshake_statuses_are_fixed_and_bounded() {
        let mut statuses = NETWORK_STATUS_VALUES.to_vec();
        let original_len = statuses.len();
        statuses.sort_unstable();
        statuses.dedup();
        assert_eq!(statuses.len(), original_len);
        for status in &statuses {
            assert!(!status.is_empty() && status.len() <= 32);
            assert!(
                status
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            );
        }
        for failure in [
            GuestNetworkHandshakeError::ReadHello,
            GuestNetworkHandshakeError::AuthenticateHello,
            GuestNetworkHandshakeError::WriteAcknowledgement,
            GuestNetworkHandshakeError::ReadReady,
            GuestNetworkHandshakeError::AuthenticateReady,
            GuestNetworkHandshakeError::Session,
        ] {
            assert!(NETWORK_STATUS_VALUES.contains(&failure.status()));
            assert!(NETWORK_AGENT_FAILURE_STAGES.contains(&failure.failure_stage()));
        }
    }

    #[test]
    fn rejected_guest_connections_yield_at_the_bounded_budget() {
        let wake = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = TaskContext::from_waker(&waker);
        let mut rejected = 0;

        for _ in 1..HOST_ONLY_REJECTION_BUDGET {
            assert!(!rejected_connection_requires_yield(
                &mut rejected,
                &mut context
            ));
        }
        assert_eq!(wake.0.load(Ordering::Relaxed), 0);
        assert!(rejected_connection_requires_yield(
            &mut rejected,
            &mut context
        ));
        assert_eq!(rejected, HOST_ONLY_REJECTION_BUDGET);
        assert_eq!(wake.0.load(Ordering::Relaxed), 1);
    }
}
