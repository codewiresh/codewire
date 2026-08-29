use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::Stream;
use tokio_vsock::{
    Incoming, VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener, VsockStream,
};
use zeroize::Zeroizing;

use crate::newc::BASIC_BUSYBOX_APPLETS;
use crate::setup_verify::verify_setup_contents;
use crate::{
    ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN, SETUP_DISK_SERIAL, SETUP_HEADER_LEN,
    STATE_DISK_SERIAL, Seed, SetupArchitecture, SetupBinding, SetupHeader, Sha256Value,
};

pub const INIT_PATH: &str = "/init";
pub const STATE_MOUNT_PATH: &str = "/state";
pub const ROOT_MOUNT_PATH: &str = "/generation";
pub const WORKSPACE_PATH: &str = "/workspace";
pub const HOME_PATH: &str = "/home/codewire";
pub const CONTROL_PATH: &str = "/state/codewire";
pub const BOOT_STAGE_PATH: &str = "/state/codewire/boot-stage";
pub const NONCE_PATH: &str = "/state/codewire/nonce";
pub const POWEROFF_MARKER_PATH: &str = "/state/codewire/poweroff.accepted";
pub const IDENTITY_MARKER: &str = "CWIDENTITY1";
pub const NONCE_MARKER: &str = "CWNONCE1";
pub const NETWORK_MARKER: &str = "CWNETWORK1 loopback-only";
pub const POWEROFF_MARKER: &str = "CWPOWEROFF1 accepted";
pub const RUNC_PATH: &str = "/sbin/runc";
pub const RUNC_STATE_PATH: &str = "/run/codewire/runc";
pub const RUNC_PROCESS_PATH: &str = "/run/codewire/exec";
pub const WORKSPACE_CONTAINER_ID: &str = "codewire-workspace";
pub const CONTAINER_INIT_PATH: &str = "/run/codewire-runtime/init";

const RUNC_BUNDLE_PATH: &str = "/generation/bundle";
const RUNC_CONFIG_PATH: &str = "/generation/bundle/config.json";
const RUNC_LOG_PATH: &str = "/state/codewire/runc.log";
const RUNC_LOG_LIMIT: u64 = 64 * 1024;
const CGROUP_ROOT_PATH: &str = "/sys/fs/cgroup";
const CGROUP_HIERARCHY_PATH: &str = "/sys/fs/cgroup/codewire";
const ROOT_LOWER_PATH: &str = "/generation/lower";
const ROOT_UPPER_PATH: &str = "/generation/upper";
const ROOT_WORK_PATH: &str = "/generation/work";
const ROOT_MERGED_PATH: &str = "/generation/merged";
const FOUNDATION_VERSION_PATH: &str = "/generation/foundation.version";
const FOUNDATION_VERSION: &str = "codewire-runc-foundation-v1\n";
const CONTAINER_CONTROL_PATH: &str = "/run/codewire/container";
const CONTAINER_IDENTITY_PATH: &str = "/run/codewire/container/identity.json";
const CONTAINER_POWEROFF_SOCKET: &str = "/run/codewire/container/poweroff.sock";
const CONTAINER_CONTROL_DESTINATION: &str = "/run/codewire-host";
const CONTAINER_IDENTITY_DESTINATION: &str = "/run/codewire-host/identity.json";
const CONTAINER_POWEROFF_DESTINATION: &str = "/run/codewire-host/poweroff.sock";
const PERSISTENT_PROBE_PATH: &str = "/state/probe";
const CONTAINER_PROBE_DESTINATION: &str = "/run/codewire-probe";
const CONTAINER_NONCE_PATH: &str = "/run/codewire-probe/nonce";
const WORKSPACE_OWNER_VERSION_PATH: &str = "/state/codewire/workspace-owner.version";
const WORKSPACE_OWNER_VERSION: &[u8] = b"codewire-workspace-owner-v1\n";
const INITIAL_OWNERSHIP_ENTRY_LIMIT: usize = 1_000_000;
const CONTAINER_POWEROFF_MARKER_PATH: &str = "/run/codewire-probe/poweroff.accepted";
const WORKSPACE_START_TIMEOUT: Duration = Duration::from_secs(10);
const WORKSPACE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const RUNC_CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_MESSAGE_LIMIT: usize = 32;

const SYS_BLOCK_PATH: &str = "/sys/class/block";
const DEV_PATH: &str = "/dev";
const DISK_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_ONLY_REJECTION_BUDGET: usize = 32;
const NONCE_MAX_LEN: usize = 256;
const READ_LIMIT: usize = 4097;
const RUNC_PROCESS_SPEC_LIMIT: u64 = 1024 * 1024;
const PERSISTENT_WORKSPACE_PATH: &str = "/state/workspace";
const PERSISTENT_HOME_PATH: &str = "/state/home";

static POWEROFF_REQUESTED: AtomicBool = AtomicBool::new(false);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    normalize_initial_persistent_ownership()?;
    record_boot_stage("ownership-ready")?;
    expose_persistent_layout()?;
    record_boot_stage("persistent-layout-ready")?;

    // Validate the complete seed before starting anything that accepts guest
    // control traffic. The child deliberately rereads it from the immutable
    // disk rather than inheriting the token through argv or environment.
    let seed = read_seed_file(&seed_device)?;
    if let Some(binding) = seed.setup() {
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
        let _contents = verify_setup_contents(&mut setup, &header)
            .context("verify every guest setup object and layer digest")?;
        record_boot_stage("setup-content-ready")?;
        bail!("verified OCI setup requires guest layer application support");
    }
    let poweroff = prepare_container_control(&seed)?;
    record_boot_stage("container-control-ready")?;
    prepare_workspace_generation()?;
    record_boot_stage("root-generation-ready")?;
    let workspace = spawn_workspace_container()?;
    record_boot_stage("workspace-running")?;

    let daemon = spawn_daemon()?;
    record_boot_stage("daemon-started")?;
    supervise_guest(daemon, workspace, poweroff)
}

pub async fn run_daemon() -> Result<()> {
    ensure!(
        std::env::vars_os().next().is_none(),
        "guest daemon refuses an ambient environment"
    );
    let seed = read_seed_from_discovered_disk()?;
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
        home_root: PathBuf::from(HOME_PATH),
        auth_token: Some(seed.auth_token().to_owned()),
        process_execution: codewire_daemon::execution::ProcessExecution::Runc(
            codewire_daemon::execution::RuncExecution {
                helper_path: PathBuf::from(INIT_PATH),
                process_directory: PathBuf::from(RUNC_PROCESS_PATH),
                container_id: WORKSPACE_CONTAINER_ID.to_owned(),
                process_wrapper: vec![CONTAINER_INIT_PATH.to_owned(), "workspace-exec".to_owned()],
                default_shell: "/bin/sh".to_owned(),
                base_environment: vec![
                    "HOME=/home/codewire".to_owned(),
                    "USER=codewire".to_owned(),
                    "SHELL=/bin/sh".to_owned(),
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
                    "LANG=C.UTF-8".to_owned(),
                ],
                uid: 0,
                gid: 0,
                additional_gids: Vec::new(),
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
    verify_loopback_only(
        Path::new("/sys/class/net"),
        Path::new("/proc/net/route"),
        Path::new("/proc/net/ipv6_route"),
    )?;
    verify_no_ip_egress_canaries()?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NETWORK_MARKER}")?;
    stdout.flush()?;
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

/// Stable container PID 1 used beneath runc. Image entrypoint/setup
/// supervision is added by the generation setup service; this foundation
/// process already gives daemon exec/PTY calls a durable namespace target.
pub fn run_workspace_init() -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } == 1,
        "workspace init must be container PID 1"
    );
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_poweroff_signal as *const () as usize;
    action.sa_flags = libc::SA_NOCLDSTOP;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
            return Err(io::Error::last_os_error())
                .context("install workspace init signal handler");
        }
    }
    POWEROFF_REQUESTED.store(false, Ordering::Release);
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

fn record_boot_stage(stage: &'static str) -> Result<()> {
    ensure!(
        !stage.is_empty()
            && stage.len() <= 32
            && stage
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
        "guest boot stage is invalid"
    );
    let mut value = stage.as_bytes().to_vec();
    value.push(b'\n');
    write_durable(Path::new(BOOT_STAGE_PATH), &value, 0o600)
        .context("persist bounded guest boot stage")
}

fn create_state_layout() -> Result<()> {
    for (path, mode) in [
        (CONTROL_PATH, 0o700),
        (PERSISTENT_WORKSPACE_PATH, 0o700),
        (PERSISTENT_HOME_PATH, 0o700),
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

fn normalize_initial_persistent_ownership() -> Result<()> {
    match fs::symlink_metadata(WORKSPACE_OWNER_VERSION_PATH) {
        Ok(_) => {
            return ensure_exact_bytes(
                Path::new(WORKSPACE_OWNER_VERSION_PATH),
                WORKSPACE_OWNER_VERSION,
                0o400,
            )
            .context("validate persistent workspace ownership marker");
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
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect persistent path {}", path.display()))?;
        let kind = metadata.file_type();
        ensure!(
            kind.is_dir() || (kind.is_file() && metadata.nlink() == 1),
            "persistent workspace contains a forbidden inode type"
        );
        lchown(&path, 0, 0)?;
        if kind.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("read persistent directory {}", path.display()))?
            {
                ensure!(
                    visited.saturating_add(pending.len()) < INITIAL_OWNERSHIP_ENTRY_LIMIT,
                    "persistent workspace exceeds its initial ownership entry bound"
                );
                pending.push(entry.context("read persistent directory entry")?.path());
            }
        }
    }

    let state = File::open(STATE_MOUNT_PATH).context("open state filesystem for ownership sync")?;
    if unsafe { libc::syncfs(state.as_raw_fd()) } == -1 {
        return Err(io::Error::last_os_error()).context("sync persistent workspace ownership");
    }
    ensure_exact_bytes(
        Path::new(WORKSPACE_OWNER_VERSION_PATH),
        WORKSPACE_OWNER_VERSION,
        0o400,
    )
    .context("publish persistent workspace ownership marker")
}

fn lchown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let path_bytes = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("persistent path contains NUL: {}", path.display()))?;
    if unsafe { libc::lchown(path_bytes.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("normalize persistent owner {}", path.display()));
    }
    Ok(())
}

fn expose_persistent_layout() -> Result<()> {
    create_dir(Path::new(WORKSPACE_PATH), 0o700)?;
    create_dir(Path::new("/home"), 0o755)?;
    create_dir(Path::new(HOME_PATH), 0o700)?;
    bind_mount(PERSISTENT_WORKSPACE_PATH, WORKSPACE_PATH)?;
    bind_mount(PERSISTENT_HOME_PATH, HOME_PATH)
}

fn prepare_container_control(seed: &Seed) -> Result<UnixDatagram> {
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
    socket
        .set_nonblocking(true)
        .context("make guest poweroff socket nonblocking")?;
    Ok(socket)
}

fn prepare_workspace_generation() -> Result<()> {
    for (path, mode) in [
        (ROOT_LOWER_PATH, 0o700),
        (ROOT_UPPER_PATH, 0o700),
        (ROOT_WORK_PATH, 0o700),
        (ROOT_MERGED_PATH, 0o700),
        (RUNC_BUNDLE_PATH, 0o700),
        ("/generation/lower/bin", 0o755),
        ("/generation/lower/sbin", 0o755),
        ("/generation/lower/etc", 0o755),
        ("/generation/lower/dev", 0o755),
        ("/generation/lower/dev/pts", 0o755),
        ("/generation/lower/dev/shm", 0o1777),
        ("/generation/lower/proc", 0o555),
        ("/generation/lower/sys", 0o555),
        ("/generation/lower/run", 0o755),
        ("/generation/lower/run/codewire-host", 0o700),
        ("/generation/lower/run/codewire-probe", 0o700),
        ("/generation/lower/tmp", 0o1777),
        ("/generation/lower/workspace", 0o700),
        ("/generation/lower/home", 0o755),
        ("/generation/lower/home/codewire", 0o700),
    ] {
        create_dir(Path::new(path), mode)?;
    }

    ensure_exact_regular(
        Path::new(INIT_PATH),
        Path::new("/generation/lower/init"),
        0o755,
    )?;
    ensure_exact_regular(
        Path::new("/bin/busybox"),
        Path::new("/generation/lower/bin/busybox"),
        0o755,
    )?;
    for applet in BASIC_BUSYBOX_APPLETS {
        create_symlink("busybox", &format!("/generation/lower/bin/{applet}"))?;
    }
    ensure_exact_bytes(
        Path::new("/generation/lower/etc/passwd"),
        b"root:x:0:0:root:/root:/bin/sh\ncodewire:x:0:0:Codewire:/home/codewire:/bin/sh\n",
        0o644,
    )?;
    ensure_exact_bytes(
        Path::new("/generation/lower/etc/group"),
        b"root:x:0:\ncodewire:x:0:\n",
        0o644,
    )?;
    ensure_exact_bytes(
        Path::new(FOUNDATION_VERSION_PATH),
        FOUNDATION_VERSION.as_bytes(),
        0o400,
    )?;

    let config = workspace_oci_config()?;
    ensure_exact_bytes(Path::new(RUNC_CONFIG_PATH), &config, 0o400)?;

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

fn ensure_exact_regular(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let source_metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect sealed source {}", source.display()))?;
    ensure!(
        source_metadata.file_type().is_file() && source_metadata.nlink() == 1,
        "sealed workspace source is not an admitted regular file"
    );
    let source_bytes =
        fs::read(source).with_context(|| format!("read sealed source {}", source.display()))?;
    ensure!(!source_bytes.is_empty(), "sealed workspace source is empty");
    ensure_exact_bytes(destination, &source_bytes, mode)
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

fn workspace_oci_config() -> Result<Vec<u8>> {
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
                "HOME=/home/codewire",
                "USER=codewire",
                "SHELL=/bin/sh",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C.UTF-8"
            ],
            "cwd": WORKSPACE_PATH,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
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
            { "destination": CONTAINER_INIT_PATH, "type": "none", "source": INIT_PATH, "options": ["bind", "ro", "nosuid", "nodev"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", "size=256m"] },
            { "destination": WORKSPACE_PATH, "type": "none", "source": PERSISTENT_WORKSPACE_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": HOME_PATH, "type": "none", "source": PERSISTENT_HOME_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
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
                { "type": "network" },
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

fn spawn_workspace_container() -> Result<std::process::Child> {
    prepare_runc_log()?;
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
            "--bundle",
            RUNC_BUNDLE_PATH,
            WORKSPACE_CONTAINER_ID,
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().context("start sealed runc workspace")?;
    let deadline = Instant::now() + WORKSPACE_START_TIMEOUT;
    loop {
        validate_runc_log()?;
        if child
            .try_wait()
            .context("observe sealed runc workspace startup")?
            .is_some()
        {
            bail!("sealed runc workspace exited during startup");
        }
        if workspace_container_is_running()? {
            return Ok(child);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = force_delete_workspace_container();
            bail!("sealed runc workspace startup timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
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
    poweroff: UnixDatagram,
) -> Result<()> {
    loop {
        validate_runc_log()?;
        if POWEROFF_REQUESTED.load(Ordering::Acquire) || container_poweroff_requested(&poweroff)? {
            stop_daemon(&mut daemon);
            stop_workspace_container(&mut workspace);
            return power_off();
        }
        if daemon.try_wait().context("observe guest daemon")?.is_some() {
            eprintln!("guest daemon exited; powering off generation");
            stop_workspace_container(&mut workspace);
            return power_off();
        }
        if workspace
            .try_wait()
            .context("observe sealed runc workspace")?
            .is_some()
        {
            eprintln!("workspace container exited; powering off generation");
            stop_daemon(&mut daemon);
            let _ = force_delete_workspace_container();
            return power_off();
        }
        thread::sleep(Duration::from_millis(20));
    }
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

fn verify_loopback_only(sys_net: &Path, route: &Path, ipv6_route: &Path) -> Result<()> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir(sys_net)
        .with_context(|| format!("read guest network interfaces {}", sys_net.display()))?
    {
        interfaces.push(entry.context("read guest network interface")?.file_name());
    }
    interfaces.sort();
    ensure!(
        interfaces.as_slice() == [OsStr::new("lo")],
        "guest has a non-loopback network interface"
    );

    let routes = fs::read_to_string(route)
        .with_context(|| format!("read guest route table {}", route.display()))?;
    for line in routes
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let interface = line
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("guest route table is malformed"))?;
        ensure!(interface == "lo", "guest has a non-loopback route");
    }

    match fs::read_to_string(ipv6_route) {
        Ok(routes) => {
            for line in routes.lines().filter(|line| !line.trim().is_empty()) {
                let interface = line
                    .split_ascii_whitespace()
                    .next_back()
                    .ok_or_else(|| anyhow::anyhow!("guest IPv6 route table is malformed"))?;
                ensure!(interface == "lo", "guest has a non-loopback IPv6 route");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A kernel with IPv6 disabled has no IPv6 route surface.
        }
        Err(error) => return Err(error).context("read guest IPv6 route table"),
    }
    Ok(())
}

fn verify_no_ip_egress_canaries() -> Result<()> {
    // TEST-NET-1 is reserved for documentation and must never be routed by
    // this no-net VM. Opening each socket is the positive control that the
    // corresponding syscall/protocol path ran; connect must then fail at
    // route lookup rather than silently succeeding.
    for (label, socket_type, protocol, address, port) in [
        (
            "TCP",
            libc::SOCK_STREAM,
            libc::IPPROTO_TCP,
            [192, 0, 2, 1],
            9,
        ),
        (
            "UDP",
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
            [192, 0, 2, 1],
            9,
        ),
        (
            "DNS",
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
            [192, 0, 2, 53],
            53,
        ),
        (
            "ICMP",
            libc::SOCK_DGRAM,
            libc::IPPROTO_ICMP,
            [192, 0, 2, 1],
            0,
        ),
    ] {
        verify_unroutable_ipv4(label, socket_type, protocol, address, port)?;
    }
    Ok(())
}

fn verify_unroutable_ipv4(
    label: &str,
    socket_type: libc::c_int,
    protocol: libc::c_int,
    address: [u8; 4],
    port: u16,
) -> Result<()> {
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, socket_type | libc::SOCK_CLOEXEC, protocol) };
    if descriptor == -1 {
        let error = io::Error::last_os_error();
        if label == "ICMP" && acceptable_icmp_socket_denial(error.raw_os_error()) {
            // Ping datagram sockets are subject to the kernel's ping-group and
            // protocol policy even for a uid-0 process without capabilities.
            // TCP/UDP/DNS above remain mandatory route-lookup canaries; an
            // narrow kernel policy denial is itself a fail-closed result rather
            // than evidence of an egress path. Unsupported protocol errors are
            // rejected because they would skip the intended ICMP canary.
            return Ok(());
        }
        return Err(error).with_context(|| format!("open {label} canary socket"));
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let endpoint = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address),
        },
        sin_zero: [0; 8],
    };
    let result = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&descriptor),
            (&raw const endpoint).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    ensure!(
        result == -1,
        "guest {label} canary unexpectedly found an IP route"
    );
    let error = io::Error::last_os_error();
    ensure!(
        matches!(
            error.raw_os_error(),
            Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH) | Some(libc::ENODEV)
        ),
        "guest {label} canary failed for a reason other than no route: {error}"
    );
    Ok(())
}

fn acceptable_icmp_socket_denial(error: Option<libc::c_int>) -> bool {
    matches!(error, Some(libc::EACCES | libc::EPERM))
}

fn ensure_init_is_expected(container: bool) -> Result<()> {
    let executable = fs::read_link("/proc/1/exe").context("inspect guest PID 1 executable")?;
    let expected = if container {
        Path::new(CONTAINER_INIT_PATH)
    } else {
        Path::new(INIT_PATH)
    };
    ensure!(
        executable == expected,
        "guest PID 1 is not the sealed Codewire init"
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
    fn network_check_requires_exactly_loopback() {
        let temporary = TempDir::new().unwrap();
        let sys = temporary.path().join("net");
        fs::create_dir(&sys).unwrap();
        fs::create_dir(sys.join("lo")).unwrap();
        let route = temporary.path().join("route");
        fs::write(&route, "Iface Destination Gateway Flags\n").unwrap();
        let ipv6_route = temporary.path().join("ipv6_route");
        fs::write(
            &ipv6_route,
            "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000 00000001 00000000 80200001 lo\n",
        )
        .unwrap();
        verify_loopback_only(&sys, &route, &ipv6_route).unwrap();

        fs::create_dir(sys.join("eth0")).unwrap();
        assert!(verify_loopback_only(&sys, &route, &ipv6_route).is_err());
    }

    #[test]
    fn only_explicit_icmp_socket_policy_denials_are_accepted() {
        for error in [libc::EACCES, libc::EPERM] {
            assert!(acceptable_icmp_socket_denial(Some(error)));
        }
        for error in [
            libc::EAFNOSUPPORT,
            libc::EPROTONOSUPPORT,
            libc::ENETUNREACH,
            libc::EINVAL,
            libc::EMFILE,
        ] {
            assert!(!acceptable_icmp_socket_denial(Some(error)));
        }
        assert!(!acceptable_icmp_socket_denial(None));
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
        let config: serde_json::Value =
            serde_json::from_slice(&workspace_oci_config().unwrap()).unwrap();
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
            serde_json::json!(["bind", "ro", "nosuid", "nodev"])
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
