//! A standard Pod's guest (#5602): the hosted control listener, and the
//! settings, roots and tokens it receives laid out for the workspace
//! container, at the paths a Kata Pod mounts them.
//!
//! The host sends; this side only acknowledges (`hosted_control`). Settings
//! arrive once, before the workload starts. Tokens arrive then and after
//! every rotation, and each is written whole, 0600, owned by the workspace
//! user, so the daemon never reads half a token.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use super::*;
use crate::hosted_control::{
    HOSTED_CONTROL_VSOCK_PORT, HOSTED_DAEMON_LISTENER_FD, HOSTED_DAEMON_LISTENER_FD_ENV,
    HOSTED_HELLO_LEN, HOSTED_REQUEST_HEADER_LEN, HostedControlKey, HostedEgressMode, HostedMessage,
    HostedSettings, HostedTokens, HostedWorkspaceInit, RestoreSettingsFile, encode_hello,
    encode_reply,
};

mod broker;
mod sleep_relay;

/// Everything the guest keeps for the hosted workspace, in memory.
pub(super) const HOSTED_ROOT: &str = "/run/codewire/hosted";
/// The daemon's environment, read by the container's init before it starts
/// the daemon.
pub(super) const HOSTED_ENVIRONMENT_PATH: &str = "/run/codewire/hosted/environment.json";
pub(super) const HOSTED_BINDING_ROOTS_PATH: &str = "/run/codewire/hosted/binding-roots";
pub(super) const HOSTED_COORDINATOR_ROOTS_PATH: &str = "/run/codewire/hosted/coordinator-roots";
pub(super) const HOSTED_BINDING_TOKEN_PATH: &str = "/run/codewire/hosted/binding-token";
pub(super) const HOSTED_CREDENTIAL_TOKEN_PATH: &str = "/run/codewire/hosted/credential-token";
/// The Pod's `cw-egress` token, in broker mode only.
pub(super) const HOSTED_EGRESS_TOKEN_PATH: &str = "/run/codewire/hosted/egress-token";
/// The TUN device a broker-mode daemon attaches `cwegress0` through.
const TUN_DEVICE: (&str, i64, i64) = ("/dev/net/tun", 10, 200);
/// The daemon's own state directory, the container's `/codewire/run`.
pub(super) const HOSTED_RUN_PATH: &str = "/run/codewire/hosted/run";
/// The daemon's readiness marker, as the guest sees it.
pub(super) const HOSTED_READY_PATH: &str = "/run/codewire/hosted/run/daemon/ready";
/// Root-owned read-only directory bind-mounted into the workspace container at
/// [`codewire_daemon_proto::HOSTED_DAEMON_RESTORE_SETTINGS_MOUNT_PATH`] so the
/// restored daemon reads the new Pod's `CODEWIRE_POD_UID` and peer settings
/// from an immutable host-owned mount (#6647).
pub(super) const HOSTED_RESTORE_DIR_PATH: &str = "/run/codewire/hosted/restore";
const RESTORE_SETTINGS_NAME: &str = "settings.json";
const DAEMON_RUN_SUBDIR: &CStr = c"daemon";
const CREDENTIAL_FILE_NAME: &CStr = c"credential";
const ACCESS_READY_FILE_NAME: &CStr = c"access-ready";
/// The file name both token directories hold, as the Kata Pod's do.
const TOKEN_NAME: &str = "token";
/// Where a Kata Pod's init puts `cw`, and where the daemon's launch
/// projection runs its helper from, so a sandbox with application secrets can
/// run commands.
const CONTAINER_CW_PATH: &str = "/codewire/bin/cw";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Filesystem paths owned by the hosted guest control plane. Production uses
/// [`HostedLayout::default`]; tests supply a temporary directory.
#[derive(Clone, Debug)]
struct HostedLayout {
    environment: PathBuf,
    binding_roots: PathBuf,
    coordinator_roots: PathBuf,
    binding_token_dir: PathBuf,
    credential_token_dir: PathBuf,
    egress_token_dir: PathBuf,
    run_dir: PathBuf,
    restore_dir: PathBuf,
}

impl Default for HostedLayout {
    fn default() -> Self {
        Self {
            environment: PathBuf::from(HOSTED_ENVIRONMENT_PATH),
            binding_roots: PathBuf::from(HOSTED_BINDING_ROOTS_PATH),
            coordinator_roots: PathBuf::from(HOSTED_COORDINATOR_ROOTS_PATH),
            binding_token_dir: PathBuf::from(HOSTED_BINDING_TOKEN_PATH),
            credential_token_dir: PathBuf::from(HOSTED_CREDENTIAL_TOKEN_PATH),
            egress_token_dir: PathBuf::from(HOSTED_EGRESS_TOKEN_PATH),
            run_dir: PathBuf::from(HOSTED_RUN_PATH),
            restore_dir: PathBuf::from(HOSTED_RESTORE_DIR_PATH),
        }
    }
}

/// Strict pre-thaw ordering for a hibernate restore (`docs/dev/SANDBOX-SLEEP.md`,
/// "After a restore", #6647):
/// 0. `checkpoint::resume` moves to `Resuming` before rotating `IDENTITY`, so
///    any failure during resume fails closed and refuses `Thaw`, `RestoreSettings`,
///    and `Tokens`.
/// 1. `prepare_restore` deletes the old daemon credential and access-ready
///    marker without following symlinks and arms `AwaitingSettings`.
/// 2. `HostedMessage::RestoreSettings` delivers the new Pod's settings and roots
///    into root-owned read-only mounts and moves to `AwaitingTokens`.
/// 3. `HostedMessage::Tokens` replaces every projected token whole and moves to
///    `ReadyToThaw`.
/// 4. `CheckpointAction::Thaw` verifies `ReadyToThaw` and the symlink-safe
///    absence of the old daemon credential before thawing `/workload`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RestorePhase {
    #[default]
    Idle,
    Resuming,
    AwaitingSettings {
        generation: u64,
    },
    AwaitingTokens {
        generation: u64,
    },
    ReadyToThaw {
        generation: u64,
    },
}

/// What the host has sent this boot, and the workspace identity its files
/// are written for once the plan names it.
#[derive(Default)]
struct Received {
    settings: Option<HostedSettings>,
    tokens: Option<HostedTokens>,
    owner: Option<(u32, u32)>,
    restore: RestorePhase,
}

pub(super) struct HostedState {
    layout: HostedLayout,
    broker_mode: bool,
    received: Mutex<Received>,
    changed: Condvar,
}

impl HostedState {
    fn new(layout: HostedLayout, broker_mode: bool) -> Self {
        Self {
            layout,
            broker_mode,
            received: Mutex::new(Received::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Received> {
        // A panic in one exchange leaves the last good message, which stays
        // valid for the next.
        self.received.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the host has sent the settings and the first tokens.
    pub(super) fn wait_for_first(&self, deadline: Instant) -> Result<HostedSettings> {
        let mut received = self.lock();
        loop {
            if let (Some(settings), Some(_)) = (&received.settings, &received.tokens) {
                return Ok(settings.clone());
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .context("the host sent no hosted settings in time")?;
            received = self
                .changed
                .wait_timeout(received, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Lays out the settings and tokens for the workspace user, and writes
    /// every later token to it.
    pub(super) fn publish(&self, uid: u32, gid: u32) -> Result<()> {
        let mut received = self.lock();
        received.owner = Some((uid, gid));
        let settings = received
            .settings
            .clone()
            .context("publish hosted settings before they arrived")?;
        write_settings(&self.layout, &settings)?;
        if let Some(tokens) = &received.tokens {
            write_tokens(&self.layout, tokens, self.broker_mode, uid, gid)?;
        }
        // Root-owned read-only directory bind-mounted into the workspace
        // container for post-restore settings (#6647).
        create_dir(&self.layout.restore_dir, 0o755)?;
        create_owned_dir(&self.layout.run_dir, uid, gid)
    }

    /// Locks the hosted guest out of `Idle` before `checkpoint::resume`
    /// rotates `IDENTITY`, so any failure during resume fails closed and
    /// refuses `Thaw`, `RestoreSettings`, and `Tokens` (#6647).
    fn begin_restore(&self) {
        let mut received = self.lock();
        received.restore = RestorePhase::Resuming;
    }

    /// Called by `checkpoint::resume` while `/workload` is still frozen:
    /// deletes the old Pod's daemon credential and access-ready marker without
    /// following symlinks in workspace-writable `/run/codewire/hosted/run`,
    /// and arms the one-shot restore settings exchange for `generation`.
    fn prepare_restore(&self, generation: u64) -> Result<()> {
        let mut received = self.lock();
        // Fail closed immediately so any error below never leaves RestorePhase::Idle.
        received.restore = RestorePhase::Resuming;
        ensure!(generation > 0, "restore generation must be non-zero");
        if let Some(daemon_dir) = open_run_daemon_dir(&self.layout.run_dir)? {
            unlink_at_if_present(&daemon_dir, CREDENTIAL_FILE_NAME)
                .context("remove the old daemon credential before thaw")?;
            unlink_at_if_present(&daemon_dir, ACCESS_READY_FILE_NAME)
                .context("remove the old access-ready marker before thaw")?;
        }
        received.restore = RestorePhase::AwaitingSettings { generation };
        Ok(())
    }

    /// Called by `checkpoint::act` before thawing `/workload`: refuses a thaw
    /// while a hosted restore failed/is incomplete or still awaits new Pod
    /// settings or tokens, or if an old daemon credential (or symlink/non-dir
    /// parent) is present.
    fn admit_thaw(&self) -> Result<()> {
        let mut received = self.lock();
        match received.restore {
            RestorePhase::Idle => Ok(()),
            RestorePhase::Resuming => {
                anyhow::bail!("hosted restore is incomplete or failed; refusing to thaw")
            }
            RestorePhase::AwaitingSettings { .. } => {
                anyhow::bail!("hosted restore cannot thaw before new Pod settings arrive")
            }
            RestorePhase::AwaitingTokens { .. } => {
                anyhow::bail!("hosted restore cannot thaw before new Pod tokens arrive")
            }
            RestorePhase::ReadyToThaw { .. } => {
                if let Some(daemon_dir) = open_run_daemon_dir(&self.layout.run_dir)? {
                    ensure!(
                        entry_is_absent(&daemon_dir, CREDENTIAL_FILE_NAME)?,
                        "hosted restore refuses to thaw while the old daemon credential exists"
                    );
                }
                received.restore = RestorePhase::Idle;
                Ok(())
            }
        }
    }

    fn accept(&self, message: HostedMessage) -> Result<()> {
        let mut received = self.lock();
        match message {
            HostedMessage::Settings(settings) => {
                // Settings are a boot's, read once (cw-security's condition).
                ensure!(
                    received.settings.is_none(),
                    "this boot's hosted settings already arrived"
                );
                received.settings = Some(settings);
            }
            HostedMessage::RestoreSettings(settings) => {
                let RestorePhase::AwaitingSettings { generation } = received.restore else {
                    anyhow::bail!("restore settings are refused outside a pending restore");
                };
                ensure!(
                    settings
                        .environment
                        .get(codewire_daemon_proto::WORKSPACE_POD_UID_ENV)
                        .is_some_and(|uid| !uid.is_empty()),
                    "restore settings must name the new Pod UID"
                );
                let (uid, gid) = received
                    .owner
                    .context("restore settings arrived before workspace ownership was set")?;
                write_roots(&self.layout, &settings)?;
                write_restore_settings(&self.layout, generation, &settings.environment, uid, gid)?;
                received.settings = Some(settings);
                received.restore = RestorePhase::AwaitingTokens { generation };
            }
            HostedMessage::Tokens(tokens) => {
                ensure!(
                    !matches!(
                        received.restore,
                        RestorePhase::Resuming | RestorePhase::AwaitingSettings { .. }
                    ),
                    "hosted tokens are refused before restore settings arrive"
                );
                ensure!(
                    received.settings.is_some(),
                    "hosted tokens arrived before the settings"
                );
                // The egress token is broker mode's alone, and that mode's
                // need: the two modes stay apart.
                ensure!(
                    tokens.egress.is_some() == self.broker_mode,
                    "the hosted tokens do not match this boot's egress mode"
                );
                if let Some((uid, gid)) = received.owner {
                    write_tokens(&self.layout, &tokens, self.broker_mode, uid, gid)?;
                }
                received.tokens = Some(tokens);
                if let RestorePhase::AwaitingTokens { generation } = received.restore {
                    received.restore = RestorePhase::ReadyToThaw { generation };
                }
            }
        }
        self.changed.notify_all();
        Ok(())
    }
}

/// Active hosted control state for this boot, shared with `checkpoint::resume`
/// and `checkpoint::act` (`Thaw`).
static HOSTED_STATE: std::sync::OnceLock<Arc<HostedState>> = std::sync::OnceLock::new();

/// Lock the hosted guest into `RestorePhase::Resuming` before `checkpoint::resume`
/// rotates `IDENTITY`.
pub(super) fn begin_restore() -> Result<()> {
    let state = HOSTED_STATE
        .get()
        .context("hosted control state is not initialized")?;
    state.begin_restore();
    Ok(())
}

/// Prepare the hosted guest for a hibernate restore before thawing `/workload`.
pub(super) fn prepare_restore(generation: u64) -> Result<()> {
    let state = HOSTED_STATE
        .get()
        .context("hosted control state is not initialized")?;
    state.prepare_restore(generation)
}

/// Verify that a pending hosted restore has completed all pre-thaw steps
/// before `/workload` thaws. Non-hosted boots and normal suspend wakes pass.
pub(super) fn admit_thaw() -> Result<()> {
    match HOSTED_STATE.get() {
        Some(state) => state.admit_thaw(),
        None => Ok(()),
    }
}

/// Starts the listener on its own thread and waits until it listens. Each
/// exchange derives its key from the current boot identity (`checkpoint`), so
/// a post-restore `Resume` rotates the hosted control key automatically.
pub(super) fn start(_seed: &Seed) -> Result<Arc<HostedState>> {
    // Verify the current boot identity yields a valid key before listening.
    current_control_key()?;
    let command_line = kernel_command_line()?;
    let mode = HostedEgressMode::from_command_line(&command_line)
        .ok()
        .flatten()
        .context("a standard Pod's boot names exactly one hosted egress mode")?;
    let _ = MODE.set(mode); // Set once per boot.
    create_dir(Path::new("/run/codewire"), 0o700)?;
    create_dir(Path::new(HOSTED_ROOT), 0o755)?;
    let state = Arc::new(HostedState::new(
        HostedLayout::default(),
        mode == HostedEgressMode::Broker,
    ));
    let _ = HOSTED_STATE.set(Arc::clone(&state)); // Set once per boot.
    let served = Arc::clone(&state);
    let _ = ACTIVE.set(()); // Set once per boot; a second set changes nothing.
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("codewire-hosted".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    // The waiting side reports the failure.
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match VsockListener::bind(VsockAddr::new(
                    VMADDR_CID_ANY,
                    HOSTED_CONTROL_VSOCK_PORT,
                )) {
                    Ok(listener) => listener,
                    Err(error) => {
                        // As above.
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                // The receiver waits for exactly this one message.
                let _ = ready_tx.send(Ok(()));
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        continue;
                    };
                    if !super::is_host_cid(peer.cid()) {
                        continue;
                    }
                    // One exchange at a time: the next connection waits.
                    if let Ok(Err(error)) =
                        tokio::time::timeout(REQUEST_TIMEOUT, serve(stream, &served)).await
                    {
                        eprintln!("codewire guest: hosted control: {error:#}");
                    }
                }
            });
        })
        .context("spawn the hosted control listener")?;
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .context("wait for the hosted control listener")??;
    let workspace_init = HostedWorkspaceInit::from_command_line(&command_line)
        .ok()
        .flatten()
        .context("a standard Pod's boot names exactly one hosted workspace init")?;
    let _ = WORKSPACE_INIT.set(workspace_init); // Set once per boot.
    super::hosted_ingress::start(&command_line)?;
    Ok(state)
}

fn current_control_key() -> Result<HostedControlKey> {
    super::checkpoint::with_identity(|identity| {
        HostedControlKey::derive(&identity.token, identity.vm_id, identity.generation)
            .context("derive this boot's hosted control key")
    })?
}

/// A broker-mode guest's `eth0` address and gateway, the host worker's
/// `SessionAddresses::HOSTED_BROKER` (#5602).
const BROKER_POD_ADDRESS: &str = "192.0.2.6/30";
const BROKER_POD_GATEWAY: &str = "192.0.2.5";

/// The guest network's address and gateway on `eth0`. A broker-mode guest's
/// `cwegress0` holds the usual /30, so its `eth0` takes the next one; every
/// other guest's is unchanged. Read from the kernel command line, in
/// whichever process asks (the network agent is not this one).
pub(super) fn eth0() -> (&'static str, &'static str) {
    eth0_addresses_for(&fs::read_to_string("/proc/cmdline").unwrap_or_default())
}

pub(super) fn eth0_addresses_for(command_line: &str) -> (&'static str, &'static str) {
    match HostedEgressMode::from_command_line(command_line) {
        Ok(Some(HostedEgressMode::Broker)) => (BROKER_POD_ADDRESS, BROKER_POD_GATEWAY),
        _ => (super::NETWORK_GUEST_ADDRESS, super::NETWORK_GATEWAY_ADDRESS),
    }
}

/// This boot's hosted egress mode, from the kernel command line.
static MODE: std::sync::OnceLock<HostedEgressMode> = std::sync::OnceLock::new();
/// This boot's workspace container init mode, from the kernel command line.
static WORKSPACE_INIT: std::sync::OnceLock<HostedWorkspaceInit> = std::sync::OnceLock::new();

/// Whether this boot runs hosted broker mode inside the VM.
pub(super) fn broker() -> bool {
    MODE.get() == Some(&HostedEgressMode::Broker)
}

/// Whether this boot hands container PID 1 over to `/sbin/init` (`systemd`).
pub(super) fn systemd_workspace() -> bool {
    WORKSPACE_INIT.get() == Some(&HostedWorkspaceInit::Systemd)
}

async fn serve(mut stream: VsockStream, state: &HostedState) -> Result<()> {
    let key = current_control_key()?;
    let mut challenge = [0_u8; crate::hosted_control::HOSTED_CHALLENGE_LEN];
    super::checkpoint::fill_random(&mut challenge)?;
    let hello: [u8; HOSTED_HELLO_LEN] = encode_hello(&challenge);
    tokio::io::AsyncWriteExt::write_all(&mut stream, &hello)
        .await
        .context("write the hosted hello")?;
    let mut frame = vec![0_u8; HOSTED_REQUEST_HEADER_LEN];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut frame)
        .await
        .context("read the hosted message header")?;
    let length = HostedMessage::payload_len(&frame).context("decode the hosted header")?;
    frame.resize(HOSTED_REQUEST_HEADER_LEN + length + 32, 0);
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut frame[HOSTED_REQUEST_HEADER_LEN..])
        .await
        .context("read the hosted message")?;
    let message = HostedMessage::decode(&frame, &key, &challenge)
        .context("authenticate the hosted message")?;
    let applied = match state.accept(message) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("codewire guest: hosted control: {error:#}");
            false
        }
    };
    tokio::io::AsyncWriteExt::write_all(&mut stream, &encode_reply(&key, &challenge, applied))
        .await
        .context("write the hosted reply")?;
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .context("flush the hosted reply")
}

fn write_settings(layout: &HostedLayout, settings: &HostedSettings) -> Result<()> {
    let environment = serde_json::to_vec(&settings.environment)
        .context("encode the hosted daemon's environment")?;
    write_durable(&layout.environment, &environment, 0o400)?;
    write_roots(layout, settings)
}

/// Replaces every TLS roots bundle directory cleanly, removing stale root
/// files from before a restore so only the current Pod's roots remain.
/// Propagates every directory-read and removal error so a stale or revoked
/// trust root cannot silently survive a restore.
fn write_roots(layout: &HostedLayout, settings: &HostedSettings) -> Result<()> {
    for (directory, files) in [
        (&layout.binding_roots, &settings.binding_tls_roots),
        (&layout.coordinator_roots, &settings.coordinator_extra_roots),
    ] {
        create_dir(directory, 0o755)?;
        for entry in fs::read_dir(directory).context("list hosted trust roots directory")? {
            let entry = entry.context("read hosted trust roots directory entry")?;
            let name = entry.file_name();
            let keep = name.to_str().is_some_and(|name| files.contains_key(name));
            if !keep {
                remove_if_present(&entry.path()).context("remove stale hosted trust root")?;
            }
        }
        for (name, contents) in files {
            let staged = directory.join(format!(".{name}"));
            write_durable(&staged, contents.as_bytes(), 0o444)?;
            fs::rename(&staged, directory.join(name))
                .context("publish a hosted trust roots file")?;
        }
    }
    Ok(())
}

/// Publishes the restored Pod's settings atomically inside the root-owned
/// read-only restore mount (`HOSTED_RESTORE_DIR_PATH` ->
/// `/run/codewire-hosted/restore/settings.json`), mode 0400 owned by `(uid, gid)`,
/// so the restored daemon reloads `CODEWIRE_POD_UID` and peer addresses from an
/// immutable host-owned file before re-binding (#6647).
fn write_restore_settings(
    layout: &HostedLayout,
    generation: u64,
    environment: &BTreeMap<String, String>,
    uid: u32,
    gid: u32,
) -> Result<()> {
    create_dir(&layout.restore_dir, 0o755)?;
    let bytes = serde_json::to_vec(&RestoreSettingsFile {
        restore_generation: generation,
        environment: environment.clone(),
    })
    .context("encode hosted restore settings")?;
    let staged = layout.restore_dir.join(format!(".{RESTORE_SETTINGS_NAME}"));
    write_durable(&staged, &bytes, 0o400)?;
    lchown(&staged, uid, gid)?;
    fs::rename(&staged, layout.restore_dir.join(RESTORE_SETTINGS_NAME))
        .context("publish hosted restore settings")
}

/// Opens `run_dir/daemon` without following symlinks at either component
/// (`O_DIRECTORY | O_NOFOLLOW`). Returns `Ok(None)` when either directory is
/// absent (`ENOENT`), and fails closed on symlinks (`ELOOP`), non-directories
/// (`ENOTDIR`), or any other error.
fn open_run_daemon_dir(run_dir: &Path) -> Result<Option<OwnedFd>> {
    let Some(run_fd) = open_dir_nofollow(run_dir)? else {
        return Ok(None);
    };
    open_child_dir_nofollow(&run_fd, DAEMON_RUN_SUBDIR)
}

fn open_dir_nofollow(path: &Path) -> Result<Option<OwnedFd>> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .context("hosted run directory path contains an interior NUL byte")?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `c_path` is a valid NUL-terminated path and `flags` needs no mode.
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd >= 0 {
        // SAFETY: `fd` is a newly opened descriptor owned exclusively here.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(None);
    }
    Err(error).with_context(|| format!("open {} without following symlinks", path.display()))
}

fn open_child_dir_nofollow(parent: &OwnedFd, name: &CStr) -> Result<Option<OwnedFd>> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `parent` is a valid directory fd and `name` is NUL-terminated.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd >= 0 {
        // SAFETY: `fd` is a newly opened descriptor owned exclusively here.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(None);
    }
    Err(error).with_context(|| {
        format!(
            "open hosted child directory {:?} without following symlinks",
            name
        )
    })
}

/// Unlinks `name` inside the already-verified directory `dir`, refusing
/// directories (`EISDIR`) or other errors while treating `ENOENT` as absent.
fn unlink_at_if_present(dir: &OwnedFd, name: &CStr) -> Result<()> {
    // SAFETY: `dir` is a valid directory fd and `name` is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(());
    }
    Err(error.into())
}

/// Returns `Ok(true)` only when `fstatat(..., AT_SYMLINK_NOFOLLOW)` reports
/// `ENOENT`. Any regular file, directory, or symlink (including a dangling
/// symlink) returns `Ok(false)`; any other I/O error fails closed.
fn entry_is_absent(dir: &OwnedFd, name: &CStr) -> Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir` is a valid directory fd, `name` is NUL-terminated, and
    // `stat` points to valid writable storage for `libc::stat`.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(true);
    }
    Err(error).with_context(|| format!("inspect {:?} without following symlinks", name))
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Each token is written to a new file and renamed over the old one, so the
/// daemon reads the old token or the new one, never a mix. If an optional
/// token is absent in the new Pod (such as `credential`), any stale copy from
/// before a restore is removed.
fn write_tokens(
    layout: &HostedLayout,
    tokens: &HostedTokens,
    broker_mode: bool,
    uid: u32,
    gid: u32,
) -> Result<()> {
    for (directory, token) in [
        (&layout.binding_token_dir, Some(&tokens.binding)),
        (&layout.credential_token_dir, tokens.credential.as_ref()),
        (&layout.egress_token_dir, tokens.egress.as_ref()),
    ] {
        if directory == &layout.egress_token_dir && !broker_mode {
            continue;
        }
        create_owned_dir(directory, uid, gid)?;
        match token {
            Some(token) => write_token(directory, token, uid, gid)?,
            None => remove_if_present(&directory.join(TOKEN_NAME))
                .context("remove stale hosted token")?,
        }
    }
    Ok(())
}

/// One token, written whole beside its file and renamed over it. A daemon
/// rereading it on every reconnect (the egress stream's included) reads the
/// last token or this one, never part of either.
fn write_token(directory: &Path, token: &str, uid: u32, gid: u32) -> Result<()> {
    let staged = directory.join(format!(".{TOKEN_NAME}"));
    write_durable(&staged, token.as_bytes(), 0o600)?;
    lchown(&staged, uid, gid)?;
    fs::rename(&staged, directory.join(TOKEN_NAME)).context("publish a hosted token")
}

fn create_owned_dir(path: &Path, uid: u32, gid: u32) -> Result<()> {
    create_dir(path, 0o700)?;
    lchown(path, uid, gid)
}

/// Set once this boot is hosted, so the workspace container's configuration
/// mounts the hosted files.
static ACTIVE: std::sync::OnceLock<()> = std::sync::OnceLock::new();

pub(super) fn active() -> bool {
    ACTIVE.get().is_some()
}

/// The guest TUN's name. A hosted daemon binds its platform dials to the
/// Pod interface's name, so a hosted guest's only interface takes it.
pub(super) fn network_interface(seed: &crate::seed::Seed) -> &'static str {
    if seed.hosted() {
        codewire_network_session::hosted::HOSTED_POD_INTERFACE
    } else {
        super::NETWORK_INTERFACE
    }
}

/// Where the container reads the daemon's environment.
const CONTAINER_ENVIRONMENT_PATH: &str = "/run/codewire-hosted/environment.json";
/// How long the hosted daemon may take to come up once the container runs.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const SETTINGS_TIMEOUT: Duration = Duration::from_secs(60);

impl HostedState {
    /// Before the workspace container starts: the host's settings and first
    /// tokens, laid out for the workspace user.
    pub(super) fn prepare(&self, plan: &WorkspacePlan) -> Result<()> {
        self.wait_for_first(Instant::now() + SETTINGS_TIMEOUT)?;
        super::hosted_ingress::hold_daemon_listener(
            &kernel_command_line()?,
            plan.identity.uid,
            plan.identity.gid,
        )?;
        self.publish(plan.identity.uid, plan.identity.gid)?;
        sleep_relay::start(plan.identity.uid, plan.identity.gid)?;
        // Broker mode's egress path exists before the workload's first packet.
        if broker() {
            broker::make_egress_path(plan.identity.uid)?;
        }
        if systemd_workspace() {
            super::systemd_init::prepare_cgroup2()?;
        }
        Ok(())
    }
}

/// The hosted files' mounts in the workspace container, at the paths a Kata
/// Pod mounts them. The daemon's state directory is its only writable one.
pub(super) fn container_mounts() -> Vec<serde_json::Value> {
    let token_directory = Path::new(codewire_access::CODEX_PLATFORM_TOKEN_FILE)
        .parent()
        .and_then(Path::to_str)
        .expect("the credential token file has a parent");
    [
        (HOSTED_ENVIRONMENT_PATH, CONTAINER_ENVIRONMENT_PATH, "ro"),
        (
            HOSTED_RESTORE_DIR_PATH,
            codewire_daemon_proto::HOSTED_DAEMON_RESTORE_SETTINGS_MOUNT_PATH,
            "ro",
        ),
        (
            HOSTED_BINDING_ROOTS_PATH,
            codewire_daemon_proto::WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH,
            "ro",
        ),
        (
            HOSTED_COORDINATOR_ROOTS_PATH,
            codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_MOUNT_PATH,
            "ro",
        ),
        (
            HOSTED_BINDING_TOKEN_PATH,
            codewire_daemon_proto::WORKSPACE_BINDING_TOKEN_MOUNT_PATH,
            "ro",
        ),
        (HOSTED_CREDENTIAL_TOKEN_PATH, token_directory, "ro"),
        (HOSTED_RUN_PATH, "/codewire/run", "rw"),
        (
            sleep_relay::HOSTED_SLEEP_DIR,
            sleep_relay::CONTAINER_SLEEP_DIR,
            "ro",
        ),
        (
            HOSTED_EGRESS_TOKEN_PATH,
            codewire_daemon_proto::EGRESS_TOKEN_MOUNT_PATH,
            "ro",
        ),
    ]
    .into_iter()
    .filter(|(source, ..)| *source != HOSTED_EGRESS_TOKEN_PATH || broker())
    .map(|(source, destination, access)| {
        serde_json::json!({
            "destination": destination, "type": "none", "source": source,
            "options": ["bind", access, "nosuid", "nodev", "noexec"]
        })
    })
    // A hosted boot always carries the runtime catalog: the Pod's runtime
    // installs it before every boot, and the daemon itself runs from its
    // launcher. Without it, this source is missing and the container fails
    // to start.
    .chain(std::iter::once(serde_json::json!({
        "destination": CONTAINER_CW_PATH, "type": "none",
        "source": format!("{}/cw", crate::cw_runtime_live::LIVE_RUNTIME_VIEW),
        "options": ["bind", "ro", "nosuid", "nodev", "exec"]
    })))
    .collect()
}

/// The devices a hosted workspace container adds to the standard set, and
/// their cgroup rules: in broker mode, the TUN device the daemon attaches
/// `cwegress0` through, as a Kata broker Pod's `egress-devnet` holds it.
pub(super) fn container_devices() -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    if !broker() {
        return (Vec::new(), Vec::new());
    }
    let (path, major, minor) = TUN_DEVICE;
    (
        vec![serde_json::json!({
            "path": path, "type": "c", "major": major, "minor": minor,
            "fileMode": 0o666, "uid": 0, "gid": 0
        })],
        vec![serde_json::json!({
            "allow": true, "type": "c", "major": major, "minor": minor, "access": "rwm"
        })],
    )
}

/// Inside the container: the plan every readiness message is made from,
/// which the guest's own copy must match, and the plan the workload runs
/// from, which for a hosted workspace is [`container_plan`]'s.
pub(super) fn with_workload(plan: WorkspacePlan) -> Result<(WorkspacePlan, WorkspacePlan)> {
    let mut workload = container_plan(plan.clone())?;
    // A standard Pod's container's workload alone inherits the daemon's
    // listener, passed at its spawn, and the variable that names it. The
    // image and the project may not set that variable themselves.
    if super::hosted_ingress::claim_container_listener()? {
        anyhow::ensure!(
            !names_listener_variable(&plan.environment),
            "{HOSTED_DAEMON_LISTENER_FD_ENV} is reserved for the hosted daemon's listener"
        );
        workload.environment.push(format!(
            "{HOSTED_DAEMON_LISTENER_FD_ENV}={HOSTED_DAEMON_LISTENER_FD}"
        ));
    }
    Ok((plan, workload))
}

/// The listener descriptor the hosted workload's spawn passes, and no other.
pub(super) fn workload_listener() -> Option<std::os::fd::RawFd> {
    super::hosted_ingress::container_listener_fd()
}

/// Whether container PID 1 spawns the local-VM credential loopback forwarder on
/// `CREDENTIAL_BRIDGE_LOOPBACK_PORT`. In a hosted `standard` Pod, the hosted
/// daemon binds that loopback port itself (`CredentialBridgeTransport::Hosted`),
/// so spawning the local forwarder holds the port and fails any Sandbox with a
/// credential profile with `EADDRINUSE`.
pub(super) fn uses_local_credential_forwarder() -> bool {
    uses_local_credential_forwarder_for(workload_listener())
}

fn uses_local_credential_forwarder_for(listener: Option<std::os::fd::RawFd>) -> bool {
    listener.is_none()
}

/// Whether an environment, as the image and the project give it, sets the
/// listener's variable.
fn names_listener_variable(environment: &[String]) -> bool {
    environment.iter().any(|entry| {
        entry
            .split_once('=')
            .is_some_and(|(name, _)| name == HOSTED_DAEMON_LISTENER_FD_ENV)
    })
}

/// The guest kernel's command line, which names this boot's hosted egress
/// mode.
fn kernel_command_line() -> Result<String> {
    fs::read_to_string("/proc/cmdline").context("read the guest kernel command line")
}

/// Inside the container: a hosted workspace's plan runs the hosted daemon in
/// place of the image's own command, with the settings' environment added.
/// Any other workspace's plan is unchanged.
fn container_plan(mut plan: WorkspacePlan) -> Result<WorkspacePlan> {
    let bytes = match fs::read(CONTAINER_ENVIRONMENT_PATH) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(plan),
        Err(error) => return Err(error).context("read the hosted daemon's environment"),
    };
    let environment: BTreeMap<String, String> =
        serde_json::from_slice(&bytes).context("decode the hosted daemon's environment")?;
    plan.environment.retain(|entry| {
        entry
            .split_once('=')
            .is_none_or(|(name, _)| !environment.contains_key(name))
    });
    plan.environment.extend(
        environment
            .iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
    plan.workload_args = vec![
        crate::cw_runtime_live::LIVE_RUNTIME_LAUNCHER.to_owned(),
        "__hosted-daemon".to_owned(),
    ];
    plan.workload_cwd = "/".to_owned();
    Ok(plan)
}

/// After the container starts: the hosted daemon's own readiness marker, and
/// for a systemd workspace the workspace user's systemd bus so `systemctl
/// --user` works immediately on the first session.
pub(super) fn wait_until_ready(
    identity: &WorkspaceIdentity,
    workspace: &mut std::process::Child,
) -> Result<()> {
    let deadline = Instant::now() + READY_TIMEOUT;
    while !Path::new(HOSTED_READY_PATH).exists() {
        if let Some(status) = workspace
            .try_wait()
            .context("observe workspace container waiting for hosted daemon ready")?
        {
            bail!("workspace container exited ({status}) before hosted daemon reported ready");
        }
        ensure!(
            Instant::now() < deadline,
            "the hosted daemon did not report ready in time"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    if systemd_workspace() {
        super::systemd_init::wait_for_user_manager(identity.uid, workspace, deadline)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rotation replaces the token by rename: a reader holding the old
    /// file keeps reading all of it, the path reads all of the new one, and
    /// no staged file is left.
    #[test]
    fn a_rotated_token_replaces_the_old_one_whole() {
        let directory = tempfile::tempdir().unwrap();
        // SAFETY: getuid and getgid read this process's ids and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        write_token(directory.path(), "eyJh.eyJv.b2xk", uid, gid).unwrap();
        let mut held = fs::File::open(directory.path().join(TOKEN_NAME)).unwrap();
        write_token(directory.path(), "eyJh.eyJuZXc.bmV3", uid, gid).unwrap();
        let mut old = String::new();
        held.read_to_string(&mut old).unwrap();
        assert_eq!(old, "eyJh.eyJv.b2xk");
        assert_eq!(
            fs::read_to_string(directory.path().join(TOKEN_NAME)).unwrap(),
            "eyJh.eyJuZXc.bmV3"
        );
        let names: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(TOKEN_NAME)]);
    }

    /// A broker-mode guest's `eth0` takes the /30 the host worker's session
    /// takes for it, beside `cwegress0`'s; every other guest's is unchanged.
    #[test]
    fn only_a_broker_mode_guests_eth0_takes_the_next_slash_30() {
        use codewire_network_session::hosted::{
            HOSTED_BROKER_POD_ADDRESS, HOSTED_BROKER_POD_GATEWAY, HOSTED_GUEST_ADDRESS,
            HOSTED_PREFIX_LEN,
        };
        let base = "console=ttyS0 rdinit=/init panic=-1";
        let broker = eth0_addresses_for(&format!("{base} codewire.hosted_broker=1"));
        assert_eq!(
            broker,
            (
                format!("{HOSTED_BROKER_POD_ADDRESS}/{HOSTED_PREFIX_LEN}").as_str(),
                HOSTED_BROKER_POD_GATEWAY.to_string().as_str(),
            )
        );
        // Not cwegress0's /30.
        assert!(!broker.0.starts_with(&format!("{HOSTED_GUEST_ADDRESS}/")));
        for line in [base.to_owned(), format!("{base} codewire.guest_carried=1")] {
            assert_eq!(
                eth0_addresses_for(&line),
                (
                    super::super::NETWORK_GUEST_ADDRESS,
                    super::super::NETWORK_GATEWAY_ADDRESS
                )
            );
        }
    }

    /// The broker-mode container adds exactly the TUN device, and no other
    /// boot adds any.
    #[test]
    fn only_a_broker_boot_adds_the_tun_device() {
        // MODE is unset in a test process: no hosted mode, no device.
        assert_eq!(container_devices(), (Vec::new(), Vec::new()));
        assert_eq!(TUN_DEVICE, ("/dev/net/tun", 10, 200));
    }

    /// The daemon's launch projection refuses to run without its helper at
    /// `/codewire/bin/cw` (`codewire-daemon`'s `apply_hosted_projection`), so
    /// the container gets the runtime's own `cw` there, read-only.
    #[test]
    fn the_container_has_cw_where_the_launch_projection_runs_it() {
        let mounts = container_mounts();
        let cw: Vec<_> = mounts
            .iter()
            .filter(|mount| mount["destination"] == "/codewire/bin/cw")
            .collect();
        assert_eq!(cw.len(), 1);
        assert_eq!(
            cw[0]["source"],
            format!("{}/cw", crate::cw_runtime_live::LIVE_RUNTIME_VIEW)
        );
        assert_eq!(
            cw[0]["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "exec"])
        );
        // Every other hosted mount stays non-executable.
        for mount in mounts
            .iter()
            .filter(|mount| mount["destination"] != "/codewire/bin/cw")
        {
            assert!(
                mount["options"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("noexec"))
            );
        }
    }

    #[test]
    fn the_image_and_project_may_not_name_the_listener_variable() {
        let named = vec![
            "PATH=/bin".to_owned(),
            format!("{HOSTED_DAEMON_LISTENER_FD_ENV}=9"),
        ];
        assert!(names_listener_variable(&named));
        let other = vec![
            "PATH=/bin".to_owned(),
            format!("{HOSTED_DAEMON_LISTENER_FD_ENV}_OTHER=9"),
            "CODEWIRE_WORKSPACE_SHIM_ADDR=127.0.0.1:17777".to_owned(),
        ];
        assert!(!names_listener_variable(&other));
    }

    #[test]
    fn hosted_workspace_leaves_credential_loopback_port_for_hosted_daemon() {
        assert!(!uses_local_credential_forwarder_for(Some(
            HOSTED_DAEMON_LISTENER_FD
        )));
        assert!(uses_local_credential_forwarder_for(None));
    }

    #[test]
    fn hosted_workspace_mounts_sleep_relay_directory_read_only() {
        let mounts = container_mounts();
        let sleep: Vec<_> = mounts
            .iter()
            .filter(|mount| mount["destination"] == sleep_relay::CONTAINER_SLEEP_DIR)
            .collect();
        assert_eq!(sleep.len(), 1);
        assert_eq!(sleep[0]["source"], sleep_relay::HOSTED_SLEEP_DIR);
        assert_eq!(
            sleep[0]["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
    }

    fn test_layout(root: &Path) -> HostedLayout {
        HostedLayout {
            environment: root.join("environment.json"),
            binding_roots: root.join("binding-roots"),
            coordinator_roots: root.join("coordinator-roots"),
            binding_token_dir: root.join("binding-token"),
            credential_token_dir: root.join("credential-token"),
            egress_token_dir: root.join("egress-token"),
            run_dir: root.join("run"),
            restore_dir: root.join("restore"),
        }
    }

    fn credential_path(layout: &HostedLayout) -> PathBuf {
        layout.run_dir.join("daemon/credential")
    }

    fn access_ready_path(layout: &HostedLayout) -> PathBuf {
        layout.run_dir.join("daemon/access-ready")
    }

    fn restore_settings_path(layout: &HostedLayout) -> PathBuf {
        layout.restore_dir.join(RESTORE_SETTINGS_NAME)
    }

    fn test_settings(pod_uid: &str, root_name: &str, root_pem: &str) -> HostedSettings {
        HostedSettings {
            environment: [
                ("CODEWIRE_POD_UID", pod_uid),
                ("CODEWIRE_WORKSPACE_SHIM_ADDR", "127.0.0.1:17777"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
            binding_tls_roots: [(root_name.to_owned(), root_pem.to_owned())]
                .into_iter()
                .collect(),
            coordinator_extra_roots: BTreeMap::new(),
        }
    }

    fn init_running_boot(layout: HostedLayout) -> HostedState {
        // SAFETY: getuid and getgid read this process's ids and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let state = HostedState::new(layout, true);
        state
            .accept(HostedMessage::Settings(test_settings(
                "old-pod-uid",
                "stale.crt",
                "old-ca",
            )))
            .unwrap();
        state
            .accept(HostedMessage::Tokens(HostedTokens {
                binding: "eyJh.eyJi.old".into(),
                credential: Some("eyJh.eyJj.old".into()),
                egress: Some("eyJh.eyJl.old".into()),
            }))
            .unwrap();
        state.publish(uid, gid).unwrap();
        state
    }

    /// Restore settings are mounted from a dedicated root-owned directory with
    /// `ro,nosuid,nodev,noexec` so the workspace container can never tamper
    /// with or forge them.
    #[test]
    fn restore_settings_mount_is_read_only_and_host_owned() {
        let mounts = container_mounts();
        let restore: Vec<_> = mounts
            .iter()
            .filter(|mount| {
                mount["destination"]
                    == codewire_daemon_proto::HOSTED_DAEMON_RESTORE_SETTINGS_MOUNT_PATH
            })
            .collect();
        assert_eq!(restore.len(), 1);
        assert_eq!(restore[0]["source"], HOSTED_RESTORE_DIR_PATH);
        assert_eq!(
            restore[0]["options"],
            serde_json::json!(["bind", "ro", "nosuid", "nodev", "noexec"])
        );
    }

    /// On a normal running boot, `RestoreSettings` is always refused so a
    /// running boot can never receive a second settings message.
    #[test]
    fn restore_settings_is_refused_on_a_running_boot() {
        let dir = tempfile::tempdir().unwrap();
        let state = init_running_boot(test_layout(dir.path()));
        // Normal thaw (suspend wake) is allowed while Idle.
        state.admit_thaw().unwrap();
        // RestoreSettings is refused on a running boot.
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "new-pod-uid",
                    "ca.crt",
                    "new-ca"
                )))
                .is_err()
        );
    }

    /// Strict pre-thaw order (#5484, #6647): `prepare_restore` deletes the old
    /// daemon credential and arms `RestoreSettings`; `Tokens` before
    /// `RestoreSettings` are refused; `Thaw` is refused until both
    /// `RestoreSettings` (once only) and `Tokens` arrive and the old
    /// credential remains absent.
    #[test]
    fn restore_enforces_strict_pre_thaw_order_and_deletes_old_credential() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let layout = test_layout(dir.path());
        let state = init_running_boot(layout.clone());

        // Simulate bound daemon credential and access-ready files on the old Pod.
        let credential = credential_path(&layout);
        let access_ready = access_ready_path(&layout);
        fs::create_dir_all(credential.parent().unwrap()).unwrap();
        fs::write(&credential, b"old-daemon-hmac").unwrap();
        fs::write(&access_ready, b"ready\n").unwrap();

        // Step 0: begin_restore locks the guest out of Idle before IDENTITY moves.
        state.begin_restore();
        assert!(state.admit_thaw().is_err());
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "premature-pod-uid",
                    "new-ca.crt",
                    "new-ca",
                )))
                .is_err()
        );
        assert!(
            state
                .accept(HostedMessage::Tokens(HostedTokens {
                    binding: "eyJh.eyJi.early".into(),
                    credential: None,
                    egress: Some("eyJh.eyJl.early".into()),
                }))
                .is_err()
        );

        // Step 1: checkpoint::resume calls prepare_restore while workload is frozen.
        state.prepare_restore(2).unwrap();
        assert!(!credential.exists());
        assert!(!access_ready.exists());
        // Cannot thaw before RestoreSettings and Tokens arrive.
        assert!(state.admit_thaw().is_err());

        // Tokens arriving before RestoreSettings are strictly refused.
        assert!(
            state
                .accept(HostedMessage::Tokens(HostedTokens {
                    binding: "eyJh.eyJi.early".into(),
                    credential: None,
                    egress: Some("eyJh.eyJl.early".into()),
                }))
                .is_err()
        );
        assert!(state.admit_thaw().is_err());

        // RestoreSettings without CODEWIRE_POD_UID is refused.
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(HostedSettings::default()))
                .is_err()
        );

        // Step 2a: RestoreSettings delivers new Pod UID and replaces roots cleanly.
        state
            .accept(HostedMessage::RestoreSettings(test_settings(
                "new-pod-uid",
                "new-ca.crt",
                "new-ca",
            )))
            .unwrap();
        assert!(!layout.binding_roots.join("stale.crt").exists());
        assert_eq!(
            fs::read_to_string(layout.binding_roots.join("new-ca.crt")).unwrap(),
            "new-ca"
        );
        let settings_file = restore_settings_path(&layout);
        assert_eq!(
            fs::symlink_metadata(&settings_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        let written: RestoreSettingsFile =
            serde_json::from_slice(&fs::read(&settings_file).unwrap()).unwrap();
        assert_eq!(written.restore_generation, 2);
        assert_eq!(
            written
                .environment
                .get("CODEWIRE_POD_UID")
                .map(String::as_str),
            Some("new-pod-uid")
        );
        // A second RestoreSettings is refused.
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "third-pod-uid",
                    "new-ca.crt",
                    "new-ca",
                )))
                .is_err()
        );
        // Still cannot thaw before new Pod tokens arrive.
        assert!(state.admit_thaw().is_err());

        // Step 2b: New Pod tokens replace old ones whole (and clear absent credential token).
        state
            .accept(HostedMessage::Tokens(HostedTokens {
                binding: "eyJh.eyJi.new".into(),
                credential: None,
                egress: Some("eyJh.eyJl.new".into()),
            }))
            .unwrap();
        assert_eq!(
            fs::read_to_string(layout.binding_token_dir.join(TOKEN_NAME)).unwrap(),
            "eyJh.eyJi.new"
        );
        assert!(!layout.credential_token_dir.join(TOKEN_NAME).exists());
        assert_eq!(
            fs::read_to_string(layout.egress_token_dir.join(TOKEN_NAME)).unwrap(),
            "eyJh.eyJl.new"
        );

        // Step 3 guard: if old credential reappeared, thaw is still refused.
        fs::write(&credential, b"stale-credential").unwrap();
        assert!(state.admit_thaw().is_err());
        fs::remove_file(&credential).unwrap();

        // All 3 pre-thaw invariants hold: thaw succeeds and returns to Idle.
        state.admit_thaw().unwrap();
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "after-thaw",
                    "new-ca.crt",
                    "new-ca",
                )))
                .is_err()
        );
    }

    /// cw-security (#6647): a workspace-planted symlink at `/codewire/run/daemon`
    /// must never be followed by guest PID 1; target files outside `/codewire/run`
    /// stay untouched and the restore fails closed (both `admit_thaw` and
    /// `RestoreSettings` remain refused).
    #[test]
    fn prepare_restore_refuses_symlinked_daemon_dir_and_leaves_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let layout = test_layout(dir.path());
        let state = init_running_boot(layout.clone());

        let outside = dir.path().join("outside-target");
        fs::create_dir_all(&outside).unwrap();
        let victim_cred = outside.join("credential");
        let victim_ready = outside.join("access-ready");
        fs::write(&victim_cred, b"do-not-delete").unwrap();
        fs::write(&victim_ready, b"do-not-delete").unwrap();

        std::os::unix::fs::symlink(&outside, layout.run_dir.join("daemon")).unwrap();

        assert!(state.prepare_restore(2).is_err());
        assert_eq!(fs::read(&victim_cred).unwrap(), b"do-not-delete");
        assert_eq!(fs::read(&victim_ready).unwrap(), b"do-not-delete");
        // Failed prepare_restore must NOT fall back to Idle.
        assert!(state.admit_thaw().is_err());
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "new-pod-uid",
                    "new-ca.crt",
                    "new-ca",
                )))
                .is_err()
        );
    }

    /// cw-security (#6647): if the workspace replaced `/codewire/run/daemon/credential`
    /// with a directory (`EISDIR`), `prepare_restore` fails and leaves both
    /// `admit_thaw` and `RestoreSettings` refused.
    #[test]
    fn prepare_restore_refuses_directory_at_credential_and_blocks_thaw() {
        let dir = tempfile::tempdir().unwrap();
        let layout = test_layout(dir.path());
        let state = init_running_boot(layout.clone());

        fs::create_dir_all(credential_path(&layout)).unwrap();

        assert!(state.prepare_restore(2).is_err());
        assert!(state.admit_thaw().is_err());
        assert!(
            state
                .accept(HostedMessage::RestoreSettings(test_settings(
                    "new-pod-uid",
                    "new-ca.crt",
                    "new-ca",
                )))
                .is_err()
        );
    }

    /// cw-security (#6647): `admit_thaw` uses `fstatat(AT_SYMLINK_NOFOLLOW)`, so
    /// a dangling symlink at `/codewire/run/daemon/credential` (where
    /// `Path::exists()` would return `false`) is caught and refused.
    #[test]
    fn admit_thaw_refuses_dangling_symlink_at_credential() {
        let dir = tempfile::tempdir().unwrap();
        let layout = test_layout(dir.path());
        let state = init_running_boot(layout.clone());

        state.begin_restore();
        state.prepare_restore(2).unwrap();
        state
            .accept(HostedMessage::RestoreSettings(test_settings(
                "new-pod-uid",
                "new-ca.crt",
                "new-ca",
            )))
            .unwrap();
        state
            .accept(HostedMessage::Tokens(HostedTokens {
                binding: "eyJh.eyJi.new".into(),
                credential: None,
                egress: Some("eyJh.eyJl.new".into()),
            }))
            .unwrap();

        let daemon_dir = layout.run_dir.join("daemon");
        fs::create_dir_all(&daemon_dir).unwrap();
        std::os::unix::fs::symlink("/nonexistent/dangling-target", credential_path(&layout))
            .unwrap();

        assert!(state.admit_thaw().is_err());
    }
}
