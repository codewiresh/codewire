//! The local Mesh owner, the same on Linux and macOS (#3797, #3794).
//!
//! `cw mesh up` starts `cw __local-mesh`, which serves the Mesh and owns it:
//! it starts `cw __local-derp` as its own child, which ends with it, and binds
//! an owner-only control socket. Every later `cw` reaches the running Mesh only
//! through that socket. It admits the peer as exactly the recorded process
//! birth, then speaks the launch nonce, so nothing ever signals a PID taken
//! from a record. Only the `cw mesh up` that spawned the owner may kill it, and
//! only before it publishes the record, while it still holds the unreaped
//! child. These are the user's own processes, not a sandbox: like any other
//! process of the user they are not confined.

use super::retained::StateDir;
use super::*;
use codewire_local_vmm::ProcessIdentity;
use codewire_local_vmm::process_peer::{self, PeerExit};
use std::io::{BufRead as _, BufReader, Read as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::os::unix::process::CommandExt as _;

pub(crate) const MESH_ROLE: &str = "__local-mesh";
pub(crate) const DERP_ROLE: &str = "__local-derp";
const STARTING: &str = "mesh-starting.json";
const SOCKET: &str = "mesh-control.sock";
const PROTOCOL: &str = "codewire-local-mesh/1";
const NONCE_ENV: &str = "CW_LOCAL_HELPER_NONCE";
const SOCKET_ENV: &str = "CW_LOCAL_MESH_CONTROL_SOCKET";
const STATE_ENV: &str = "CW_LOCAL_MESH_STATE_DIR";
const DERP_URL_ENV: &str = "CW_LOCAL_DERP_URL";
const DERP_LISTEN_ENV: &str = "CW_LOCAL_DERP_LISTEN";
const RECORD_SCHEMA: u32 = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const _: () = assert!(LocalMeshOwner::DRAIN_GRACE.as_secs() < STOP_TIMEOUT.as_secs());
const MAX_LINE: usize = 256;

/// The running owner, as `cw mesh up` recorded it: its birth, the socket it
/// answers on and the nonce only it knows, and the configuration it serves.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MeshOwnerRecord {
    schema_version: u32,
    process: ProcessIdentity,
    launch_nonce: String,
    socket: PathBuf,
    base_url: String,
    listen_addr: String,
    pub(crate) organization_id: String,
    api_key_hash: String,
    derp: Option<OwnedDerp>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnedDerp {
    url: String,
    listen_addr: String,
}

/// What the owner answers: its own PID and its DERP child's.
#[derive(Debug, PartialEq, Eq)]
struct OwnerReply {
    mesh_pid: u32,
    derp_pid: Option<u32>,
}

/// The refusal for a Mesh an earlier cw started, which this cw never stops.
fn earlier_cw_refusal(runtime: &LocalMeshRuntime, data_dir: &Path) -> anyhow::Error {
    let derp = runtime
        .derp
        .as_ref()
        .map(|derp| format!(" and its DERP process {}", derp.pid))
        .unwrap_or_default();
    anyhow::anyhow!(
        "the local Mesh process {}{derp} was started by an earlier cw, which this cw does not \
         stop: check with `ps -p PID` that each is a codewire Mesh or DERP process and stop it \
         yourself, then remove {}",
        runtime.pid,
        local_mesh_runtime_path(data_dir).display()
    )
}

fn record_of<'a>(
    runtime: &'a LocalMeshRuntime,
    data_dir: &Path,
) -> anyhow::Result<&'a MeshOwnerRecord> {
    let record = runtime
        .owner
        .as_ref()
        .ok_or_else(|| earlier_cw_refusal(runtime, data_dir))?;
    anyhow::ensure!(
        record.schema_version == RECORD_SCHEMA
            && record.process.pid == runtime.pid
            && record.base_url == runtime.base_url
            && record.listen_addr == runtime.listen_addr
            && record
                .derp
                .as_ref()
                .map(|derp| (&derp.url, &derp.listen_addr))
                == runtime
                    .derp
                    .as_ref()
                    .map(|derp| (&derp.url, &derp.listen_addr))
            && uuid::Uuid::parse_str(&record.launch_nonce).is_ok(),
        "local Mesh record does not match its owner binding"
    );
    Ok(record)
}

/// Ask the owner `command`. `None` means nothing answers on its socket; a
/// process other than the recorded owner answering is an error.
fn request(
    record: &MeshOwnerRecord,
    command: &str,
) -> anyhow::Result<Option<(OwnerReply, PeerExit)>> {
    let stream = match StdUnixStream::connect(&record.socket) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error).context("reach the local Mesh owner"),
    };
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let exit = process_peer::admit_process_socket(&stream, &record.process)
        .context("the local Mesh control socket is not served by the recorded owner")?;
    (&stream).write_all(format!("{PROTOCOL} {command} {}\n", record.launch_nonce).as_bytes())?;
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_LINE as u64)).read_line(&mut line)?;
    let reply = parse_reply(&line).context("the local Mesh owner refused or gave no answer")?;
    anyhow::ensure!(
        reply.mesh_pid == record.process.pid,
        "the local Mesh owner answered for another process"
    );
    Ok(Some((reply, exit)))
}

fn parse_reply(line: &str) -> Option<OwnerReply> {
    let mut fields = line.strip_suffix('\n')?.split(' ');
    if fields.next()? != "ok" {
        return None;
    }
    let mesh_pid = fields.next()?.parse().ok()?;
    let derp_pid = match fields.next()? {
        "-" => None,
        pid => Some(pid.parse().ok()?),
    };
    fields
        .next()
        .is_none()
        .then_some(OwnerReply { mesh_pid, derp_pid })
}

/// The running Mesh is the recorded owner and serves this record.
pub(crate) fn validate_runtime(runtime: &LocalMeshRuntime, data_dir: &Path) -> anyhow::Result<()> {
    let record = record_of(runtime, data_dir)?;
    let (reply, _) = request(record, "status")?
        .context("the local Mesh owner is not running; run `cw mesh down`, then `cw mesh up`")?;
    anyhow::ensure!(
        reply.derp_pid == runtime.derp.as_ref().map(|derp| derp.pid),
        "the local Mesh owner's DERP process differs from its record"
    );
    Ok(())
}

pub(crate) fn validate_owner(
    runtime: &LocalMeshRuntime,
    owner: &LocalMeshOwnerContext,
    data_dir: &Path,
) -> anyhow::Result<()> {
    validate_runtime(runtime, data_dir)?;
    let record = record_of(runtime, data_dir)?;
    anyhow::ensure!(
        owner.schema_version == 1
            && owner.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal
            && config::same_mesh_url(&owner.mesh_url, &runtime.base_url)
            && owner.organization_id == record.organization_id,
        "local Mesh owner projection differs from the owned running helper"
    );
    Ok(())
}

pub(crate) fn unresolved_start(data_dir: &Path) -> anyhow::Result<bool> {
    match StateDir::open(data_dir, false)? {
        Some(directory) => Ok(directory.read(STARTING)?.is_some()),
        None => Ok(false),
    }
}

/// The owner this `cw mesh up` started, until it publishes the record. Until
/// then it alone may kill it: it holds the unreaped child, so the PID cannot
/// name another process.
struct StartingOwner {
    child: std::process::Child,
    published: bool,
}

impl Drop for StartingOwner {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn owner_arguments(executable: &str, spec: &LocalMeshStartSpec) -> Vec<String> {
    let mut arguments = vec![
        executable.to_owned(),
        MESH_ROLE.to_owned(),
        "--base-url".to_owned(),
        spec.base_url.clone(),
        "--listen".to_owned(),
        spec.listen_addr.clone(),
    ];
    if let Some(derp) = &spec.derp {
        arguments.extend(["--derp-url".to_owned(), derp.url.clone()]);
    }
    arguments
}

fn spawn_owner(
    directory: &StateDir,
    executable: &Path,
    spec: &LocalMeshStartSpec,
    socket: &Path,
    data_dir: &Path,
    nonce: &str,
) -> anyhow::Result<StartingOwner> {
    let text = executable
        .to_str()
        .context("the cw executable path is not UTF-8")?;
    let arguments = owner_arguments(text, spec);
    let log = directory.log(LOCAL_MESH_LOG_FILE)?;
    let mut command = ProcessCommand::new(executable);
    command
        .arg0(&arguments[0])
        .args(&arguments[1..])
        .env_clear()
        .envs(owner_environment(spec, socket, data_dir, nonce))
        .stdin(Stdio::null())
        .stderr(Stdio::from(log.try_clone()?))
        .stdout(Stdio::from(log));
    // The owner outlives this command, so it leaves the terminal's session.
    // SAFETY: setsid and prctl are async-signal-safe and touch only the child.
    unsafe {
        command.pre_exec(|| {
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("start the local Mesh owner")?;
    Ok(StartingOwner {
        child,
        published: false,
    })
}

/// Everything the owner receives in its environment: its launch projection
/// and the logging settings, never the invoking shell's own environment.
pub(crate) fn owner_environment(
    spec: &LocalMeshStartSpec,
    socket: &Path,
    data_dir: &Path,
    nonce: &str,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut environment = local_service_logging_environment();
    let mut set = |name: &str, value: &std::ffi::OsStr| {
        environment.push((name.into(), value.to_owned()));
    };
    set(NONCE_ENV, nonce.as_ref());
    set(SOCKET_ENV, socket.as_os_str());
    set(STATE_ENV, data_dir.as_os_str());
    set(
        "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID",
        spec.local_identity.organization_id.as_ref(),
    );
    set(
        "CODEWIRE_MESH_LOCAL_API_KEY_HASH",
        spec.local_identity.api_key_hash().as_ref(),
    );
    if let Some(derp) = &spec.derp {
        set(DERP_URL_ENV, derp.url.as_ref());
        set(DERP_LISTEN_ENV, derp.listen_addr.as_ref());
    }
    environment
}

/// The DERP child's environment, from its owner's: only its listen settings
/// and the logging settings.
pub(crate) fn derp_environment(listen_addr: &str) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut environment = local_service_logging_environment();
    for (name, value) in [
        ("PORT", "-1"),
        ("TLS_LISTEN_ADDR", listen_addr),
        ("STUN_LISTEN_ADDR", "-1"),
    ] {
        environment.push((name.into(), value.into()));
    }
    environment
}

#[derive(serde::Serialize)]
struct StartingIntent<'a> {
    operation_id: &'a str,
    owner: Option<&'a ProcessIdentity>,
}

fn write_intent(
    directory: &StateDir,
    operation_id: &str,
    owner: Option<&ProcessIdentity>,
) -> anyhow::Result<()> {
    directory.write(
        STARTING,
        &serde_json::to_vec(&StartingIntent {
            operation_id,
            owner,
        })?,
    )
}

/// A socket path an earlier owner left behind in its own private directory.
fn remove_leftover_socket(socket: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(socket) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_socket() && metadata.uid() == current_euid(),
                "the local Mesh control socket path holds something else: {}",
                socket.display()
            );
            fs::remove_file(socket).context("remove the earlier local Mesh control socket")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect the local Mesh control socket"),
    }
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no arguments or effects.
    unsafe { libc::geteuid() }
}

fn control_socket(data_dir: &Path) -> anyhow::Result<PathBuf> {
    let data_dir = fs::canonicalize(data_dir).context("resolve the local Mesh directory")?;
    let directory = codewire_local_vmm::socket_dir::prepare(&data_dir)
        .context("prepare the local Mesh socket directory")?;
    let socket = directory.join(SOCKET);
    codewire_local_vmm::socket_dir::check_length(&socket)
        .context("the local Mesh control socket path is too long")?;
    Ok(socket)
}

pub(crate) async fn up(paths: &ResolvePaths, args: MeshUpArgs) -> anyhow::Result<MeshUpReport> {
    let data_dir = &paths.mesh_data_dir;
    let directory = StateDir::open(data_dir, true)?.context("local Mesh directory is absent")?;
    let lock = directory.lock().await?;
    anyhow::ensure!(
        directory.read(STARTING)?.is_none(),
        "local Mesh startup has an unresolved intent; nothing was started or replaced"
    );
    if let Some(runtime) = load_local_mesh_runtime(data_dir)? {
        validate_runtime(&runtime, data_dir)?;
        let owner = load_local_mesh_owner_context(data_dir)?
            .context("live local Mesh owner projection is absent")?;
        validate_owner(&runtime, &owner, data_dir)?;
        anyhow::ensure!(
            local_mesh_runtime_matches_args(&runtime, &args),
            "live local Mesh configuration differs; explicitly run cw mesh down before changing it"
        );
        lock.check(&directory)?;
        return Ok(mesh_up_report(false, &runtime));
    }
    let executable = fs::canonicalize(env::current_exe().context("locate the cw executable")?)
        .context("resolve the cw executable")?;
    directory.read(LOCAL_MESH_OWNER_CONTEXT_FILE)?;
    let mut mesh_config: config::MeshConfig = match directory.read("config.toml")? {
        None => config::MeshConfig::default(),
        Some(bytes) => toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid bounded local Mesh configuration"))?,
        )
        .map_err(|_| anyhow::anyhow!("invalid bounded local Mesh configuration"))?,
    };
    let local_identity = match mesh_config
        .local_identity
        .as_ref()
        .filter(|value| value.is_complete())
    {
        Some(identity) => identity.clone(),
        None => {
            let identity = config::new_local_mesh_identity();
            mesh_config.local_identity = Some(identity.clone());
            lock.check(&directory)?;
            directory.write(
                "config.toml",
                toml::to_string_pretty(&mesh_config)?.as_bytes(),
            )?;
            identity
        }
    };
    // The local service keeps its catalog in memory: a restart recreates the
    // selected local network, so the saved selection stays usable.
    let selected_network = super::selection::local_selection_for(
        data_dir,
        &args.base_url,
        &local_identity.organization_id,
    );
    let spec = local_mesh_start_spec(paths, &args, local_identity, &executable)?;
    let socket = control_socket(data_dir)?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    lock.check(&directory)?;
    remove_leftover_socket(&socket)?;
    write_intent(&directory, &operation_id, None)?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut starting = None;
    let start = async {
        lock.check(&directory)?;
        let owner = starting.insert(spawn_owner(
            &directory,
            &executable,
            &spec,
            &socket,
            data_dir,
            &nonce,
        )?);
        let process = codewire_local_vmm::LiveProcess::capture_child(owner.child.id(), &executable)
            .context("record the local Mesh owner's process birth")?
            .identity()
            .clone();
        write_intent(&directory, &operation_id, Some(&process))?;
        let record = MeshOwnerRecord {
            schema_version: RECORD_SCHEMA,
            process,
            launch_nonce: nonce.clone(),
            socket: socket.clone(),
            base_url: spec.base_url.clone(),
            listen_addr: spec.listen_addr.clone(),
            organization_id: spec.local_identity.organization_id.clone(),
            api_key_hash: spec.local_identity.api_key_hash(),
            derp: spec.derp.as_ref().map(|derp| OwnedDerp {
                url: derp.url.clone(),
                listen_addr: derp.listen_addr.clone(),
            }),
        };
        let reply = wait_for_owner(&record, owner).await?;
        anyhow::ensure!(
            reply.derp_pid.is_some() == spec.derp.is_some(),
            "the local Mesh owner did not start its DERP process as configured"
        );
        // Bounded by its own deadline, which reports the last error.
        wait_for_standalone_mesh_catalog(
            &spec,
            &spec.local_identity.organization_id,
            selected_network.as_deref(),
        )
        .await?;
        let runtime = LocalMeshRuntime {
            pid: record.process.pid,
            base_url: spec.base_url.clone(),
            listen_addr: spec.listen_addr.clone(),
            binary: executable.display().to_string(),
            log_path: spec.log_path.display().to_string(),
            started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            derp: spec
                .derp
                .as_ref()
                .zip(reply.derp_pid)
                .map(|(derp, pid)| LocalDerpRuntime {
                    pid,
                    url: derp.url.clone(),
                    listen_addr: derp.listen_addr.clone(),
                    binary: executable.display().to_string(),
                    log_path: derp.log_path.display().to_string(),
                    earlier_custody: None,
                }),
            owner: Some(record),
            earlier_custody: None,
        };
        lock.check(&directory)?;
        mesh_config.mesh_url = Some(spec.base_url.clone());
        mesh_config.mesh_auth_token = Some(spec.local_identity.api_key.clone());
        directory.write(
            "config.toml",
            toml::to_string_pretty(&mesh_config)?.as_bytes(),
        )?;
        save_local_mesh_owner_context(
            data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                mesh_url: spec.base_url.clone(),
                organization_id: spec.local_identity.organization_id.clone(),
                selected_network: None,
                auto_connect: false,
            },
        )?;
        save_local_mesh_runtime(data_dir, &runtime)?;
        owner.published = true;
        // A failed fsync or ACK after publication keeps the startup intent, so
        // a later controller cannot silently clear it into a new launch.
        let intent = directory
            .read(STARTING)?
            .context("local Mesh startup intent disappeared")?;
        directory.remove(STARTING, Some(&intent))?;
        Ok::<_, anyhow::Error>(runtime)
    }
    .await;
    match start {
        Ok(runtime) => Ok(mesh_up_report(true, &runtime)),
        Err(error) => {
            // Stop the owner this command started while it is still its
            // unreaped child; keep every record if publication happened.
            let published = starting.as_ref().is_some_and(|owner| owner.published);
            drop(starting);
            if !published && directory.read(LOCAL_MESH_RUNTIME_FILE)?.is_none() {
                let intent = directory.read(STARTING)?;
                directory.remove(STARTING, intent.as_deref())?;
            }
            Err(error)
        }
    }
}

/// Wait until the owner this command started answers on its socket.
async fn wait_for_owner(
    record: &MeshOwnerRecord,
    owner: &mut StartingOwner,
) -> anyhow::Result<OwnerReply> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        if let Some((reply, _)) = request(record, "status")? {
            return Ok(reply);
        }
        if let Some(status) = owner.child.try_wait()? {
            anyhow::bail!("the local Mesh owner exited before it was ready ({status})");
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the local Mesh owner did not answer within {} s",
            READY_TIMEOUT.as_secs()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) async fn down(paths: &ResolvePaths) -> anyhow::Result<MeshDownReport> {
    let data_dir = &paths.mesh_data_dir;
    let not_running = || MeshDownReport {
        stopped: false,
        pid: None,
        state: "not_running".to_owned(),
    };
    let Some(directory) = StateDir::open(data_dir, false)? else {
        return Ok(not_running());
    };
    let lock = directory.lock().await?;
    anyhow::ensure!(
        directory.read(STARTING)?.is_none(),
        "local Mesh startup is unresolved; all records were kept"
    );
    let Some(bytes) = directory.read(LOCAL_MESH_RUNTIME_FILE)? else {
        return Ok(not_running());
    };
    let runtime: LocalMeshRuntime = serde_json::from_slice(&bytes)?;
    let record = record_of(&runtime, data_dir)?;
    lock.check(&directory)?;
    let state = match request(record, "stop")? {
        Some((_, exit)) => {
            anyhow::ensure!(
                exit.wait(STOP_TIMEOUT).await?,
                "the local Mesh owner {} accepted the stop but did not exit within {} s",
                record.process.pid,
                STOP_TIMEOUT.as_secs()
            );
            "stopped"
        }
        None => {
            anyhow::ensure!(
                !process_peer::recorded_birth_alive(&record.process)?,
                "the local Mesh owner {} still runs but does not answer on its control socket; \
                 nothing was signalled: stop that process yourself, then run `cw mesh down` again",
                record.process.pid
            );
            "stale"
        }
    };
    anyhow::ensure!(
        directory.read(LOCAL_MESH_RUNTIME_FILE)?.as_deref() == Some(&bytes),
        "local Mesh record changed during shutdown"
    );
    directory.remove(LOCAL_MESH_RUNTIME_FILE, Some(&bytes))?;
    remove_mesh_owner_context_for_auth_source(data_dir, LocalMeshOwnerAuthSource::StandaloneLocal)?;
    // The stopped service's endpoint and key are no longer a usable Mesh; its
    // durable identity stays for the next `cw mesh up`.
    config::clear_local_mesh_connection(data_dir, &runtime.base_url)?;
    remove_leftover_socket(&record.socket)?;
    Ok(MeshDownReport {
        stopped: state == "stopped",
        pid: Some(runtime.pid),
        state: state.to_owned(),
    })
}

/// The owner side, run by `cw __local-mesh` before it serves the Mesh.
pub struct LocalMeshOwner {
    listener: StdUnixListener,
    socket: PathBuf,
    socket_inode: (u64, u64),
    nonce: String,
    derp: Option<std::process::Child>,
}

impl LocalMeshOwner {
    /// How long a stopping owner lets open Mesh connections drain before it
    /// exits anyway. An attached environment's coordinator stream stays open
    /// until the server goes, so an unbounded graceful drain never ends, and
    /// nothing signals the owner to end it. Shorter than a controller's wait.
    pub const DRAIN_GRACE: Duration = Duration::from_secs(2);

    /// Start the DERP child and bind the control socket. Call it from the
    /// main thread before any runtime starts: on Linux the child's
    /// parent-death signal follows the thread that spawned it.
    pub fn prepare() -> anyhow::Result<Self> {
        let required = |name: &str| {
            env::var_os(name).with_context(|| format!("the local Mesh owner needs {name}"))
        };
        let nonce = required(NONCE_ENV)?
            .into_string()
            .ok()
            .filter(|nonce| uuid::Uuid::parse_str(nonce).is_ok())
            .context("the local Mesh launch nonce is invalid")?;
        let socket = PathBuf::from(required(SOCKET_ENV)?);
        let data_dir = PathBuf::from(required(STATE_ENV)?);
        let derp = match (env::var(DERP_URL_ENV).ok(), env::var(DERP_LISTEN_ENV).ok()) {
            (Some(_), Some(listen_addr)) => Some(spawn_derp(&data_dir, &listen_addr)?),
            (None, None) => None,
            _ => anyhow::bail!("the local DERP configuration is incomplete"),
        };
        let listener = {
            // SAFETY: umask changes only this process's creation mask, and no
            // other thread exists yet.
            let previous = unsafe { libc::umask(0o177) };
            let bound = StdUnixListener::bind(&socket);
            // SAFETY: as above.
            unsafe { libc::umask(previous) };
            bound.context("bind the local Mesh control socket")?
        };
        let metadata = fs::symlink_metadata(&socket)?;
        Ok(Self {
            listener,
            socket,
            socket_inode: (metadata.dev(), metadata.ino()),
            nonce,
            derp,
        })
    }

    /// A future that answers controllers until one asks this owner to stop.
    /// It owns what it needs, so it can run as the Mesh's shutdown signal.
    pub fn control(
        &self,
    ) -> anyhow::Result<impl std::future::Future<Output = anyhow::Result<()>> + Send + 'static>
    {
        let listener = self.listener.try_clone()?;
        listener.set_nonblocking(true)?;
        let nonce = self.nonce.clone();
        let derp_pid = self
            .derp
            .as_ref()
            .map_or_else(|| "-".to_owned(), |child| child.id().to_string());
        let reply = format!("ok {} {derp_pid}\n", std::process::id());
        Ok(async move {
            let listener = tokio::net::UnixListener::from_std(listener)?;
            loop {
                let (stream, _) = listener.accept().await?;
                let answer = tokio::time::timeout(REQUEST_TIMEOUT, async {
                    anyhow::ensure!(
                        stream.peer_cred()?.uid() == current_euid(),
                        "a local Mesh controller of another user"
                    );
                    let mut stream = tokio::io::BufReader::new(stream);
                    let mut line = String::new();
                    tokio::io::AsyncBufReadExt::read_line(
                        &mut tokio::io::AsyncReadExt::take(&mut stream, MAX_LINE as u64),
                        &mut line,
                    )
                    .await?;
                    let command = parse_request(&line, &nonce);
                    let response = if command.is_some() {
                        reply.as_str()
                    } else {
                        "refused\n"
                    };
                    tokio::io::AsyncWriteExt::write_all(stream.get_mut(), response.as_bytes())
                        .await?;
                    Ok::<_, anyhow::Error>(command)
                })
                .await;
                if let Ok(Ok(Some(Command::Stop))) = answer {
                    return Ok(());
                }
            }
        })
    }

    /// Stop the DERP child and remove the control socket.
    pub fn finish(mut self) {
        if let Some(mut child) = self.derp.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.socket)
            && (metadata.dev(), metadata.ino()) == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Status,
    Stop,
}

fn parse_request(line: &str, nonce: &str) -> Option<Command> {
    let mut fields = line.strip_suffix('\n')?.split(' ');
    if fields.next()? != PROTOCOL {
        return None;
    }
    let command = match fields.next()? {
        "status" => Command::Status,
        "stop" => Command::Stop,
        _ => return None,
    };
    (fields.next()? == nonce && fields.next().is_none()).then_some(command)
}

/// Start `cw __local-derp` as this owner's child; it ends with its parent.
fn spawn_derp(data_dir: &Path, listen_addr: &str) -> anyhow::Result<std::process::Child> {
    let directory = StateDir::open(data_dir, false)?.context("local Mesh directory is absent")?;
    let log = directory.log(LOCAL_DERP_LOG_FILE)?;
    let executable = fs::canonicalize(env::current_exe()?)?;
    let mut command = ProcessCommand::new(&executable);
    command
        .arg0(&executable)
        .arg(DERP_ROLE)
        .env_clear()
        .envs(derp_environment(listen_addr))
        .stdin(Stdio::null())
        .stderr(Stdio::from(log.try_clone()?))
        .stdout(Stdio::from(log));
    command.spawn().context("start the local DERP process")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(root: &Path) -> ResolvePaths {
        ResolvePaths {
            mesh_data_dir: root.join("mesh"),
            platform_config_dir: root.join("unused-platform"),
        }
    }

    fn args() -> MeshUpArgs {
        MeshUpArgs {
            base_url: DEFAULT_LOCAL_MESH_URL.to_owned(),
            listen: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_owned(),
            derp_url: DEFAULT_LOCAL_DERP_URL.to_owned(),
            derp_listen: DEFAULT_LOCAL_DERP_LISTEN_ADDR.to_owned(),
            no_derp: false,
            output: OutputFormat::Json,
        }
    }

    /// A process of this user that no command here may signal.
    struct Sentinel(std::process::Child);

    impl Sentinel {
        fn start() -> Self {
            Self(ProcessCommand::new("sleep").arg("30").spawn().unwrap())
        }
        fn alive(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    impl Drop for Sentinel {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn runtime(pid: u32, owner: Option<MeshOwnerRecord>) -> LocalMeshRuntime {
        LocalMeshRuntime {
            pid,
            base_url: DEFAULT_LOCAL_MESH_URL.to_owned(),
            listen_addr: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_owned(),
            binary: "/synthetic/cw".to_owned(),
            log_path: "/synthetic/mesh.log".to_owned(),
            started_at: "synthetic".to_owned(),
            derp: None,
            owner,
            earlier_custody: None,
        }
    }

    fn record(process: ProcessIdentity, socket: PathBuf) -> MeshOwnerRecord {
        MeshOwnerRecord {
            schema_version: RECORD_SCHEMA,
            process,
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            socket,
            base_url: DEFAULT_LOCAL_MESH_URL.to_owned(),
            listen_addr: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_owned(),
            organization_id: "synthetic-org".to_owned(),
            api_key_hash: "ab".repeat(32),
            derp: None,
        }
    }

    #[tokio::test]
    async fn a_mesh_an_earlier_cw_started_is_refused_and_never_signalled() {
        let root = tempfile::tempdir().unwrap();
        let paths = paths(root.path());
        let directory = StateDir::open(&paths.mesh_data_dir, true).unwrap().unwrap();
        let mut sentinel = Sentinel::start();
        save_local_mesh_runtime(&paths.mesh_data_dir, &runtime(sentinel.0.id(), None)).unwrap();
        let original = directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap();
        for error in [
            up(&paths, args()).await.unwrap_err(),
            down(&paths).await.unwrap_err(),
        ] {
            assert!(error.to_string().contains("earlier cw"), "{error:#}");
        }
        assert_eq!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap(), original);
        assert!(sentinel.alive());
        assert_eq!(local_mesh_status(&paths.mesh_data_dir).state, "unknown");
    }

    #[tokio::test]
    async fn an_interrupted_startup_is_kept_for_diagnosis() {
        let root = tempfile::tempdir().unwrap();
        let paths = paths(root.path());
        let directory = StateDir::open(&paths.mesh_data_dir, true).unwrap().unwrap();
        directory.write(STARTING, b"{\"unresolved\":true}").unwrap();
        assert!(up(&paths, args()).await.is_err());
        assert!(down(&paths).await.is_err());
        assert_eq!(
            directory.read(STARTING).unwrap().unwrap(),
            b"{\"unresolved\":true}"
        );
        assert_eq!(local_mesh_status(&paths.mesh_data_dir).state, "unknown");
    }

    #[tokio::test]
    async fn a_dead_owner_is_cleared_as_stale_without_a_signal() {
        let root = tempfile::tempdir().unwrap();
        let paths = paths(root.path());
        StateDir::open(&paths.mesh_data_dir, true).unwrap().unwrap();
        let mut gone = ProcessCommand::new("sleep").arg("30").spawn().unwrap();
        let process = ProcessIdentity::capture(gone.id()).unwrap();
        gone.kill().unwrap();
        gone.wait().unwrap();
        let socket = root.path().join("absent.sock");
        save_local_mesh_runtime(
            &paths.mesh_data_dir,
            &runtime(process.pid, Some(record(process, socket))),
        )
        .unwrap();
        let report = down(&paths).await.unwrap();
        assert_eq!((report.stopped, report.state.as_str()), (false, "stale"));
        assert!(
            load_local_mesh_runtime(&paths.mesh_data_dir)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_live_owner_that_does_not_answer_is_refused_and_left_running() {
        let root = tempfile::tempdir().unwrap();
        let paths = paths(root.path());
        let directory = StateDir::open(&paths.mesh_data_dir, true).unwrap().unwrap();
        let mut sentinel = Sentinel::start();
        let process = ProcessIdentity::capture(sentinel.0.id()).unwrap();
        let socket = root.path().join("absent.sock");
        save_local_mesh_runtime(
            &paths.mesh_data_dir,
            &runtime(process.pid, Some(record(process, socket))),
        )
        .unwrap();
        let original = directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap();
        let error = down(&paths).await.unwrap_err();
        assert!(
            error.to_string().contains("nothing was signalled"),
            "{error:#}"
        );
        assert!(sentinel.alive());
        assert_eq!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap(), original);
    }

    #[test]
    fn a_request_needs_the_protocol_a_known_command_and_the_exact_nonce() {
        let nonce = "6f0b8b8e-6d3f-4b8a-9f5c-2b7e9c1d4a10";
        let line = |rest: &str| format!("{PROTOCOL} {rest}\n");
        assert_eq!(
            parse_request(&line(&format!("status {nonce}")), nonce),
            Some(Command::Status)
        );
        assert_eq!(
            parse_request(&line(&format!("stop {nonce}")), nonce),
            Some(Command::Stop)
        );
        for refused in [
            line("stop 00000000-0000-0000-0000-000000000000"),
            line(&format!("kill {nonce}")),
            line(&format!("stop {nonce} extra")),
            format!("codewire-local-mesh/0 stop {nonce}\n"),
            format!("{PROTOCOL} stop {nonce}"),
            String::new(),
        ] {
            assert_eq!(parse_request(&refused, nonce), None, "{refused:?}");
        }
    }

    #[test]
    fn a_reply_names_the_owner_and_its_derp_child_or_none() {
        assert_eq!(
            parse_reply("ok 41 42\n"),
            Some(OwnerReply {
                mesh_pid: 41,
                derp_pid: Some(42)
            })
        );
        assert_eq!(
            parse_reply("ok 41 -\n"),
            Some(OwnerReply {
                mesh_pid: 41,
                derp_pid: None
            })
        );
        for refused in [
            "refused\n",
            "ok 41\n",
            "ok 41 42 43\n",
            "ok x -\n",
            "ok 41 42",
        ] {
            assert_eq!(parse_reply(refused), None, "{refused:?}");
        }
    }
}
