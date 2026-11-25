//! A standard Pod's guest (#5602): the hosted control listener, and the
//! settings, roots and tokens it receives laid out for the workspace
//! container, at the paths a Kata Pod mounts them.
//!
//! The host sends; this side only acknowledges (`hosted_control`). Settings
//! arrive once, before the workload starts. Tokens arrive then and after
//! every rotation, and each is written whole, 0600, owned by the workspace
//! user, so the daemon never reads half a token.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use super::*;
use crate::hosted_control::{
    HOSTED_CONTROL_VSOCK_PORT, HOSTED_DAEMON_LISTENER_FD, HOSTED_DAEMON_LISTENER_FD_ENV,
    HOSTED_HELLO_LEN, HOSTED_REQUEST_HEADER_LEN, HostedControlKey, HostedEgressMode, HostedMessage,
    HostedSettings, HostedTokens, encode_hello, encode_reply,
};

mod broker;

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
/// The file name both token directories hold, as the Kata Pod's do.
const TOKEN_NAME: &str = "token";
/// Where a Kata Pod's init puts `cw`, and where the daemon's launch
/// projection runs its helper from, so a sandbox with application secrets can
/// run commands.
const CONTAINER_CW_PATH: &str = "/codewire/bin/cw";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What the host has sent this boot, and the workspace identity its files
/// are written for once the plan names it.
#[derive(Default)]
struct Received {
    settings: Option<HostedSettings>,
    tokens: Option<HostedTokens>,
    owner: Option<(u32, u32)>,
}

#[derive(Default)]
pub(super) struct HostedState {
    received: Mutex<Received>,
    changed: Condvar,
}

impl HostedState {
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
        write_settings(&settings)?;
        if let Some(tokens) = &received.tokens {
            write_tokens(tokens, uid, gid)?;
        }
        create_owned_dir(Path::new(HOSTED_RUN_PATH), uid, gid)
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
            HostedMessage::Tokens(tokens) => {
                ensure!(
                    received.settings.is_some(),
                    "hosted tokens arrived before the settings"
                );
                // The egress token is broker mode's alone, and that mode's
                // need: the two modes stay apart.
                ensure!(
                    tokens.egress.is_some() == broker(),
                    "the hosted tokens do not match this boot's egress mode"
                );
                if let Some((uid, gid)) = received.owner {
                    write_tokens(&tokens, uid, gid)?;
                }
                received.tokens = Some(tokens);
            }
        }
        self.changed.notify_all();
        Ok(())
    }
}

/// Starts the listener on its own thread, with this boot's key, and waits
/// until it listens.
pub(super) fn start(seed: &Seed) -> Result<Arc<HostedState>> {
    let key = HostedControlKey::derive(seed.auth_token(), seed.vm_id(), seed.generation())
        .context("derive this boot's hosted control key")?;
    create_dir(Path::new("/run/codewire"), 0o700)?;
    create_dir(Path::new(HOSTED_ROOT), 0o755)?;
    let state = Arc::new(HostedState::default());
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
                        tokio::time::timeout(REQUEST_TIMEOUT, serve(stream, &key, &served)).await
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
    let command_line = kernel_command_line()?;
    let mode = HostedEgressMode::from_command_line(&command_line)
        .ok()
        .flatten()
        .context("a standard Pod's boot names exactly one hosted egress mode")?;
    let _ = MODE.set(mode); // Set once per boot.
    super::hosted_ingress::start(&command_line)?;
    Ok(state)
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

fn eth0_addresses_for(command_line: &str) -> (&'static str, &'static str) {
    match HostedEgressMode::from_command_line(command_line) {
        Ok(Some(HostedEgressMode::Broker)) => (BROKER_POD_ADDRESS, BROKER_POD_GATEWAY),
        _ => (super::NETWORK_GUEST_ADDRESS, super::NETWORK_GATEWAY_ADDRESS),
    }
}

/// This boot's hosted egress mode, from the kernel command line.
static MODE: std::sync::OnceLock<HostedEgressMode> = std::sync::OnceLock::new();

/// Whether this boot runs hosted broker mode inside the VM.
pub(super) fn broker() -> bool {
    MODE.get() == Some(&HostedEgressMode::Broker)
}

async fn serve(mut stream: VsockStream, key: &HostedControlKey, state: &HostedState) -> Result<()> {
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
    let message = HostedMessage::decode(&frame, key, &challenge)
        .context("authenticate the hosted message")?;
    let applied = match state.accept(message) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("codewire guest: hosted control: {error:#}");
            false
        }
    };
    tokio::io::AsyncWriteExt::write_all(&mut stream, &encode_reply(key, &challenge, applied))
        .await
        .context("write the hosted reply")?;
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .context("flush the hosted reply")
}

fn write_settings(settings: &HostedSettings) -> Result<()> {
    let environment = serde_json::to_vec(&settings.environment)
        .context("encode the hosted daemon's environment")?;
    write_durable(Path::new(HOSTED_ENVIRONMENT_PATH), &environment, 0o400)?;
    for (directory, files) in [
        (HOSTED_BINDING_ROOTS_PATH, &settings.binding_tls_roots),
        (
            HOSTED_COORDINATOR_ROOTS_PATH,
            &settings.coordinator_extra_roots,
        ),
    ] {
        create_dir(Path::new(directory), 0o755)?;
        for (name, contents) in files {
            write_durable(&Path::new(directory).join(name), contents.as_bytes(), 0o444)?;
        }
    }
    Ok(())
}

/// Each token is written to a new file and renamed over the old one, so the
/// daemon reads the old token or the new one, never a mix.
fn write_tokens(tokens: &HostedTokens, uid: u32, gid: u32) -> Result<()> {
    for (directory, token) in [
        (HOSTED_BINDING_TOKEN_PATH, Some(&tokens.binding)),
        (HOSTED_CREDENTIAL_TOKEN_PATH, tokens.credential.as_ref()),
        (HOSTED_EGRESS_TOKEN_PATH, tokens.egress.as_ref()),
    ] {
        if directory == HOSTED_EGRESS_TOKEN_PATH && !broker() {
            continue;
        }
        create_owned_dir(Path::new(directory), uid, gid)?;
        if let Some(token) = token {
            write_token(Path::new(directory), token, uid, gid)?;
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
        // Broker mode's egress path exists before the workload's first packet.
        if broker() {
            broker::make_egress_path(plan.identity.uid)?;
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

/// After the container starts: the hosted daemon's own readiness marker.
/// "Daemon started" means the hosted daemon is up and its bind loop runs.
pub(super) fn wait_until_ready() -> Result<()> {
    let deadline = Instant::now() + READY_TIMEOUT;
    while !Path::new(HOSTED_READY_PATH).exists() {
        ensure!(
            Instant::now() < deadline,
            "the hosted daemon did not report ready in time"
        );
        std::thread::sleep(Duration::from_millis(100));
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
}
