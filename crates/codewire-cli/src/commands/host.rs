//! Trusted local placements use the ordinary daemon session owner, not a VM.
//! Runtime state is private and separate from the child's real HOME/workspace.
use super::*;
use codewire_daemon::stop_evidence::SHUTDOWN_MARKER;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};

const HOST_DATA_DIR_ENV: &str = "CW_HOST_DATA_DIR";
const START_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(25);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// A session stop or restart may first spend up to 10 s interrupting an
/// agent's active run; its request deadline covers that and the stop.
const SESSION_STOP_TIMEOUT: Duration = Duration::from_secs(20);

fn ensure_host_supported() -> anyhow::Result<()> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        anyhow::bail!("trusted host environments are supported on Linux and macOS");
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostEnvironment {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub created_at: String,
    pub state: String,
    #[serde(skip)]
    pub runtime_root: Option<PathBuf>,
}

impl HostEnvironment {
    pub fn current_target(&self) -> config::CurrentTargetConfig {
        config::CurrentTargetConfig {
            kind: "host".into(),
            target_ref: self.id.clone(),
            name: self.name.clone(),
        }
    }

    pub fn root(&self) -> PathBuf {
        self.runtime_root
            .clone()
            .unwrap_or_else(|| host_data_dir().join(&self.id))
    }
}

pub(crate) fn host_data_dir() -> PathBuf {
    let path = env::var_os(HOST_DATA_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".local/state")
                })
                .join("codewire/hosts")
        });
    if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    }
}

pub(crate) fn validate_host_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        anyhow::bail!("host name must be 1–64 letters, numbers, '-' or '_'");
    }
    Ok(())
}

pub(crate) fn private_directory(path: &std::path::Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            // SAFETY: geteuid reads the current process identity.
            if !meta.is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o077 != 0
            {
                anyhow::bail!(
                    "runtime directory must be owner-private and not a symlink: {}",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .with_context(|| format!("create private runtime directory {}", path.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn existing_private_directory(path: &std::path::Path) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("host runtime no longer exists: {}", path.display()))?;
    // SAFETY: geteuid reads the current process identity.
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!(
            "runtime directory must be existing, owner-private and not a symlink: {}",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn write_private_json<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
) -> anyhow::Result<()> {
    write_private(path, &serde_json::to_vec(value)?)
}

/// Replaces `path` with an owner-only file of `bytes`, in an existing
/// owner-private directory, through an exclusive temporary sibling and a
/// rename: a reader never sees part of it, and a symlink at `path` is
/// replaced, never followed.
pub(crate) fn write_private(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = path.parent().context("runtime file parent")?;
    existing_private_directory(parent)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_private<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> anyhow::Result<T> {
    use std::io::Read;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid reads the current process identity.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!(
            "runtime file must be owner-private and not a symlink: {}",
            path.display()
        );
    }
    if meta.len() > 4 * 1024 * 1024 {
        anyhow::bail!("runtime file exceeds 4 MiB limit");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        anyhow::bail!("runtime file exceeds 4 MiB limit");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Kernel locks fence daemon ownership; saved PIDs never grant kill authority.
struct HostLock(fs::File);
impl HostLock {
    fn acquire(path: &std::path::Path) -> anyhow::Result<Option<Self>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // SAFETY: the descriptor remains owned by this lock guard.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(Self(file)));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error.into())
        }
    }
    async fn wait(path: &std::path::Path) -> anyhow::Result<Self> {
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(guard) = Self::acquire(path)? {
                return Ok(guard);
            }
            if Instant::now() >= deadline {
                anyhow::bail!("host lifecycle operation is still owned by another process");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
impl Drop for HostLock {
    fn drop(&mut self) {
        // SAFETY: unlock the descriptor owned by this guard before close.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(crate) fn host_environments() -> anyhow::Result<Vec<HostEnvironment>> {
    let root = host_data_dir();
    if !root.exists() {
        return Ok(Vec::new());
    }
    existing_private_directory(&root)?;
    let mut environments = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if uuid::Uuid::parse_str(&id).is_err() {
            continue;
        }
        if !entry.path().exists() {
            continue;
        }
        existing_private_directory(&entry.path())?;
        let environment = match host_environment_at(&entry.path()) {
            Ok(environment) => environment,
            Err(_) if !entry.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if environment.id != id {
            anyhow::bail!("host environment identity mismatch");
        }
        validate_host_name(&environment.name)?;
        environments.push(environment);
    }
    environments.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(environments)
}

pub(crate) fn host_environment_at(root: &std::path::Path) -> anyhow::Result<HostEnvironment> {
    existing_private_directory(root.parent().context("host registry parent")?)?;
    existing_private_directory(root)?;
    let mut environment: HostEnvironment = read_private(&root.join("host.json"))?;
    if uuid::Uuid::parse_str(&environment.id)?.to_string() != environment.id {
        anyhow::bail!("host environment ID is not canonical");
    }
    if root.file_name().and_then(|name| name.to_str()) != Some(environment.id.as_str()) {
        anyhow::bail!("host runtime path does not match its canonical identity");
    }
    environment.runtime_root = Some(root.to_path_buf());
    Ok(environment)
}

pub(crate) fn host_environment(requested: &str) -> anyhow::Result<Option<HostEnvironment>> {
    let environments = host_environments()?;
    Ok(environments
        .iter()
        .find(|e| e.id == requested)
        .or_else(|| environments.iter().find(|e| e.name == requested))
        .cloned())
}

pub(crate) fn selected_host_environment() -> anyhow::Result<Option<HostEnvironment>> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let target = config::current_target(&paths.mesh_data_dir)?;
    if target.kind == "host" {
        host_environment(&target.target_ref)
    } else {
        Ok(None)
    }
}

/// An unqualified host name may never override a same-name sandbox.
pub(crate) async fn resolve_host_reference(
    globals: &Globals,
    requested: &str,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<Option<HostEnvironment>> {
    if placement == Some(EnvironmentPlacement::Platform) {
        return Ok(None);
    }
    let Some(host) = host_environment(requested)? else {
        return Ok(None);
    };
    if requested == host.id {
        return Ok(Some(host));
    }
    // Only a name the local VMs hold reaches their supervisor (#4156).
    #[cfg(target_os = "linux")]
    if local_environment_named(requested).await?
        && let Some(native) = native_environment(requested).await?
    {
        anyhow::bail!(
            "local environment name {requested:?} is ambiguous between host {} and sandbox {}; use an exact environment ID",
            host.id,
            native.id
        );
    }
    if placement.is_none() {
        let paths = ResolvePaths::from_env(&OsEnv)?;
        if let Ok(platform) = resolve_platform(globals, &paths, &OsEnv) {
            let orgs = organization_client(&platform)?.list_orgs().await.context(
                "check host/platform name ambiguity; use --local or exact host ID while offline",
            )?;
            let org_id = current_org_id(&platform, &orgs)?;
            let environments = EnvironmentClient::new(&platform)?
                .list_environments(&org_id, false)
                .await?;
            if find_environment_match(&environments, requested)?.is_some() {
                anyhow::bail!(
                    "environment name {requested:?} exists on the host and platform; use exact host ID {} or --cloud",
                    host.id
                );
            }
        }
    }
    Ok(Some(host))
}

pub(crate) fn validate_host_create(
    args: &EnvCreateArgs,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<()> {
    ensure_host_supported()?;
    if placement != Some(EnvironmentPlacement::Local) {
        anyhow::bail!("trusted host environments require --local --type host");
    }
    if !args.repo_urls.is_empty()
        || !args.repo_flags.is_empty()
        || args.backend.is_some()
        || args.path_mode.is_some()
        || !args.file.is_empty()
        || args.no_local_file
        || args.spec.is_some()
        || args.preset_slug.is_some()
        || args.preset_id.is_some()
        || args.ttl.is_some()
        || args.cpu.is_some()
        || args.memory.is_some()
        || args.disk.is_some()
        || args.docker_disk.is_some()
        || args.no_docker
        || args.isolation.is_some()
        || args.branch.is_some()
        || args.image.is_some()
        || args.install.is_some()
        || args.startup.is_some()
        || args.coding_agent.is_some()
        || !args.env.is_empty()
        || args.profile.is_some()
        || args.secrets.is_some()
        || args.user_secrets.is_some()
        || args.org_secrets
        || args.network.is_some()
        || args.no_network
        || args.write_preset
        || args.save_preset.is_some()
        || args.snapshot.is_some()
        || args.checkpoint.is_some()
    {
        anyhow::bail!(
            "host creation accepts --name and --path; VM, image, project, network and projection options require --type sandbox"
        );
    }
    validate_host_name(
        args.name
            .as_deref()
            .context("host creation requires --name")?,
    )
}

pub(crate) async fn create_host_environment(args: &EnvCreateArgs) -> anyhow::Result<()> {
    ensure_host_supported()?;
    let name = args
        .name
        .as_deref()
        .context("host creation requires --name")?;
    let path = fs::canonicalize(args.path.clone().unwrap_or(env::current_dir()?))
        .context("resolve host project directory")?;
    if !path.is_dir() {
        anyhow::bail!("host --path must be an existing directory");
    }
    let root = host_data_dir();
    let environment = HostEnvironment {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.into(),
        path,
        created_at: Utc::now().to_rfc3339(),
        state: "running".into(),
        runtime_root: None,
    };
    check_socket_path(&environment.root().join("daemon.sock"))?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    host_daemon_config(&environment, token.clone())?.validate_host()?;
    private_directory(&root)?;
    let _registry = HostLock::wait(&root.join("registry.lock")).await?;
    if host_environment(name)?.is_some() {
        anyhow::bail!("host environment {name:?} already exists");
    }
    let staging = root.join(format!(".creating-{}", environment.id));
    private_directory(&staging)?;
    write_private_json(&staging.join("host.json"), &environment)?;
    write_private_json(&staging.join("daemon-token.json"), &token)?;
    fs::rename(&staging, environment.root()).context("publish completed host registry entry")?;
    fs::File::open(&root)?.sync_all()?;
    let _client = host_session_client(&environment).await?;
    print_host_environment(&environment, args.output)
}

pub(crate) fn print_host_environment(
    environment: &HostEnvironment,
    output: OutputFormat,
) -> anyhow::Result<()> {
    print_host_environment_info(environment, output, None)
}

/// `cw info` for a trusted host and, while it runs, its managed
/// conversations that need attention (#2982). The JSON gains
/// `agents_attention` only when one does.
fn print_host_environment_info(
    environment: &HostEnvironment,
    output: OutputFormat,
    attention: Option<&super::sessions::agents::ManagedAttentionReport>,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => {
            let mut value = serde_json::json!({
                "id":environment.id,"name":environment.name,"type":"host","placement":"local",
                "state":environment.state,"path":environment.path,"created_at":environment.created_at
            });
            if let Some(entries) =
                attention.and_then(super::sessions::agents::managed_attention_json)
            {
                value["agents_attention"] = entries;
            }
            println!("{}", serde_json::to_string_pretty(&value)?)
        }
        OutputFormat::Text => {
            println!(
                "{}\thost\t{}\t{}",
                environment.name,
                environment.state,
                environment.path.display()
            );
            for row in attention
                .map(super::sessions::agents::managed_attention_rows)
                .unwrap_or_default()
            {
                println!("Attention:   {row}");
            }
        }
    }
    Ok(())
}

fn check_socket_path(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() >= 104 {
        anyhow::bail!(
            "host runtime path exceeds Unix socket limit; choose a shorter {HOST_DATA_DIR_ENV}"
        );
    }
    Ok(())
}

async fn connect_host_channel(
    environment: &HostEnvironment,
    request_timeout: Duration,
) -> anyhow::Result<(tonic::transport::Channel, String)> {
    let root = environment.root();
    existing_private_directory(&root)?;
    let socket = root.join("daemon.sock");
    check_socket_path(&socket)?;
    let before = fs::symlink_metadata(&socket)?;
    use std::os::unix::fs::FileTypeExt;
    // SAFETY: geteuid reads the current process identity.
    if !before.file_type().is_socket()
        || before.uid() != unsafe { libc::geteuid() }
        || before.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("host daemon socket is not owner-private");
    }
    let connector = tower::service_fn(move |_| {
        let socket = socket.clone();
        let identity = (before.dev(), before.ino());
        async move {
            let stream = UnixStream::connect(&socket).await?;
            let after = fs::symlink_metadata(&socket)?;
            // SAFETY: geteuid reads the current process identity.
            if (after.dev(), after.ino()) != identity
                || stream.peer_cred()?.uid() != unsafe { libc::geteuid() }
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "host daemon identity changed",
                ));
            }
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    });
    let channel = tonic::transport::Endpoint::from_static("http://codewire-host")
        .connect_timeout(Duration::from_secs(3))
        .timeout(request_timeout)
        .connect_with_connector(connector)
        .await?;
    let token: String = read_private(&root.join("daemon-token.json"))?;
    Ok((channel, token))
}

async fn connect_host(
    environment: &HostEnvironment,
    request_timeout: Duration,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    let (channel, token) = connect_host_channel(environment, request_timeout).await?;
    let client = codewire_daemon::client::SessionClient::from_channel(channel, token)?;
    client.require_ready().await?;
    Ok(client)
}

/// Grant inspection and delegated requests never start or repair an owner.
#[cfg(target_os = "linux")]
pub(crate) async fn host_control_client(
    environment: &HostEnvironment,
) -> anyhow::Result<codewire_daemon::client::HostControlClient> {
    host_control_client_within(environment, REQUEST_TIMEOUT).await
}

/// `host_control_client` with its own per-request timeout. Tests of the
/// protocol, not of its latency, use a long one on a loaded host (#3231).
#[cfg(target_os = "linux")]
pub(crate) async fn host_control_client_within(
    environment: &HostEnvironment,
    request_timeout: Duration,
) -> anyhow::Result<codewire_daemon::client::HostControlClient> {
    if environment.state != "running" {
        anyhow::bail!("host control requires an already running host environment");
    }
    let current = host_environment_at(&environment.root())?;
    if current.id != environment.id || current.state != "running" {
        anyhow::bail!("host control environment identity changed");
    }
    let (channel, token) = connect_host_channel(&current, request_timeout).await?;
    let client =
        codewire_daemon::client::HostControlClient::from_channel(channel, token, current.id)?;
    client.require_ready().await?;
    Ok(client)
}

pub(crate) async fn host_session_client(
    environment: &HostEnvironment,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    host_session_client_within(environment, REQUEST_TIMEOUT).await
}

/// For StopSession and RestartSession, whose daemon may first interrupt an
/// agent's active run.
pub(crate) async fn host_stop_client(
    environment: &HostEnvironment,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    host_session_client_within(environment, SESSION_STOP_TIMEOUT).await
}

async fn host_session_client_within(
    environment: &HostEnvironment,
    request_timeout: Duration,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    tokio::time::timeout(
        START_TIMEOUT,
        connect_or_start_host(environment, request_timeout),
    )
    .await
    .context("host readiness deadline exceeded; runtime retained for diagnosis")?
}

async fn connect_or_start_host(
    environment: &HostEnvironment,
    request_timeout: Duration,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    if environment.state != "running" {
        anyhow::bail!(
            "host environment is stopped; use cw start {}",
            environment.name
        );
    }
    if let Ok(client) = connect_host(environment, request_timeout).await {
        return Ok(client);
    }
    let root = environment.root();
    let _lifecycle = HostLock::wait(&root.join("lifecycle.lock")).await?;
    // Reread desired state after waiting for another lifecycle owner.
    let current: HostEnvironment = read_private(&root.join("host.json"))?;
    if current.state != "running" {
        anyhow::bail!("host environment was stopped during connection");
    }
    if let Ok(client) = connect_host(environment, request_timeout).await {
        return Ok(client);
    }
    let mut launched = None;
    if let Some(available) = HostLock::acquire(&root.join("daemon.lock"))? {
        drop(available);
        let log = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("daemon.log"))?;
        let mut command = ProcessCommand::new(env::current_exe()?);
        command
            .arg("_host-daemon")
            .arg("--environment")
            .arg(&environment.id)
            .arg("--registry-root")
            .arg(root.parent().context("host registry parent")?)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and runs only in this child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        launched = Some(command.spawn().context("launch host session daemon")?);
    }
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Ok(client) = connect_host(environment, request_timeout).await {
            return Ok(client);
        }
        if let Some(child) = launched.as_mut()
            && let Some(status) = child.try_wait()?
        {
            anyhow::bail!(
                "host daemon exited during startup ({status}); inspect {}",
                root.join("daemon.log").display()
            );
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "host daemon did not become ready; inspect {}",
                root.join("daemon.log").display()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(crate) async fn host_lifecycle(
    mut environment: HostEnvironment,
    operation: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let root = environment.root();
    if operation == "start" {
        {
            let _lifecycle = HostLock::wait(&root.join("lifecycle.lock")).await?;
            let current = host_environment_at(&root)?;
            if current.id != environment.id {
                anyhow::bail!("host identity changed during lifecycle operation");
            }
            environment = current;
            environment.state = "running".into();
            write_private_json(&root.join("host.json"), &environment)?;
        }
        host_session_client(&environment).await?;
    } else {
        let _lifecycle = HostLock::wait(&root.join("lifecycle.lock")).await?;
        let current = host_environment_at(&root)?;
        if current.id != environment.id {
            anyhow::bail!("host identity changed during lifecycle operation");
        }
        environment = current;
        environment.state = "stopped".into();
        write_private_json(&root.join("host.json"), &environment)?;
        write_private_json(&root.join(SHUTDOWN_MARKER), &true)?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(available) = HostLock::acquire(&root.join("daemon.lock"))? {
                drop(available);
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "host shutdown not confirmed; runtime retained at {}",
                    root.display()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        validate_host_stopped(&root)?;
        if operation == "rm" {
            let registry = host_data_dir();
            let _registry = HostLock::wait(&registry.join("registry.lock")).await?;
            fs::remove_dir_all(&root).context("remove owned host runtime metadata")?;
            let paths = ResolvePaths::from_env(&OsEnv)?;
            config::selection::clear_if(&paths.mesh_data_dir, |selection| {
                selection.location == config::selection::SelectionLocation::Host
                    && selection.id == environment.id
            })?;
            println!("Removed host environment {}", environment.name);
            return Ok(());
        }
    }
    print_host_environment(&environment, output)
}

pub(crate) async fn run_host_daemon(args: HostDaemonArgs) -> anyhow::Result<()> {
    if uuid::Uuid::parse_str(&args.environment)?.to_string() != args.environment {
        anyhow::bail!("host daemon requires a canonical environment ID");
    }
    let environment = match &args.registry_root {
        Some(registry) => host_environment_at(&registry.join(&args.environment))?,
        None => host_environment(&args.environment)?.context("host environment does not exist")?,
    };
    let root = environment.root();
    let _owner = HostLock::acquire(&root.join("daemon.lock"))?
        .context("host daemon already has an owner")?;
    let environment = host_environment_at(&root)?;
    if environment.state != "running" {
        anyhow::bail!("host environment is stopped");
    }
    let socket = root.join("daemon.sock");
    check_socket_path(&socket)?;
    if socket.exists() {
        use std::os::unix::fs::FileTypeExt;
        let meta = fs::symlink_metadata(&socket)?;
        // SAFETY: geteuid reads the current process identity.
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            anyhow::bail!("refusing to replace non-owned daemon socket");
        }
        fs::remove_file(&socket)?;
    }
    if root.join(SHUTDOWN_MARKER).exists() {
        fs::remove_file(root.join(SHUTDOWN_MARKER))?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let socket_identity = fs::symlink_metadata(&socket)?;
    // SAFETY: geteuid reads the current process identity.
    let uid = unsafe { libc::geteuid() };
    let incoming = UnixListenerStream::new(listener).filter_map(move |result| match result {
        Ok(stream) if stream.peer_cred().is_ok_and(|c| c.uid() == uid) => Some(Ok(stream)),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    });
    let token: String = read_private(&root.join("daemon-token.json"))?;
    let config = host_daemon_config(&environment, token)?;
    // daemon.log gets the daemon's value-blind warnings, and each interrupt
    // a stop or restart sends an agent's active run before it signals it.
    // It has no rotation, so an inherited RUST_LOG never widens it.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,codewire_daemon=info",
        ))
        .try_init();
    let shutdown_root = root.clone();
    let shutdown = async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install host daemon SIGTERM observer");
        // A signal takes the environment down as `cw stop ENV` does. The
        // daemon marks the takedown itself before it stops anything (see
        // `codewire_daemon::stop_evidence`), so a conversation's driver that
        // a rebooting host signals in the same moment finds the marker.
        tokio::select! {
            _=term.recv()=>{},
            _=tokio::signal::ctrl_c()=>{},
            _=async {
                loop {
                    if shutdown_root.join(SHUTDOWN_MARKER).is_file(){break;}
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }=>{},
        }
    };
    // The environment is its conversations' executor: each noel conversation
    // its takedown paused starts again with it, and no other.
    #[cfg(target_os = "linux")]
    let resume = tokio::spawn(resume_paused_conversations(environment.clone()));
    #[cfg(target_os = "linux")]
    let result = codewire_daemon::serve_host_control_grpc_with_incoming(
        config,
        codewire_daemon::host_control::HostControlBinding::new(environment.id.clone())?
            .with_managed_agents(),
        incoming,
        shutdown,
    )
    .await;
    #[cfg(target_os = "linux")]
    resume.abort();
    #[cfg(not(target_os = "linux"))]
    let result = codewire_daemon::serve_grpc_with_incoming(config, incoming, shutdown).await;
    if let Ok(after) = fs::symlink_metadata(&socket)
        && (after.dev(), after.ino()) == (socket_identity.dev(), socket_identity.ino())
    {
        fs::remove_file(&socket)?;
    }
    result
}

/// Once this daemon answers its own socket, restarts the noel conversations
/// its environment's takedown paused. It never starts or repairs a daemon:
/// it is the daemon, and connects only to itself.
#[cfg(target_os = "linux")]
async fn resume_paused_conversations(environment: HostEnvironment) {
    let deadline = Instant::now() + START_TIMEOUT;
    let client = loop {
        match connect_host(&environment, SESSION_STOP_TIMEOUT).await {
            Ok(client) => break client,
            Err(error) if Instant::now() >= deadline => {
                eprintln!("cw host daemon: paused noel conversations were not resumed: {error:#}");
                return;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    if let Err(error) = resume_paused(&environment, &client).await {
        eprintln!("cw host daemon: paused noel conversations were not all resumed: {error:#}");
    }
}

fn host_daemon_config(
    environment: &HostEnvironment,
    token: String,
) -> anyhow::Result<codewire_daemon::Config> {
    Ok(codewire_daemon::Config {
        listen_addr: String::new(),
        workspace_root: environment.path.clone(),
        home_root: env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is required for trusted host execution")?,
        mount_roots: Vec::new(),
        auth_token: codewire_daemon::DaemonAuthToken::new(token)?,
        process_execution: codewire_daemon::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        launch_projection: None,
        host: Some(codewire_daemon::config::HostConfig {
            state_root: environment.root(),
        }),
        session_working_dir: None,
    })
}

pub(crate) async fn host_daemon_health(environment: &HostEnvironment) -> String {
    if environment.state != "running" {
        return "stopped".into();
    }
    if connect_host(environment, REQUEST_TIMEOUT).await.is_ok() {
        "ready".into()
    } else {
        "unavailable".into()
    }
}

/// Intercept only registered host targets. Sandbox routes retain their owners.
pub(crate) async fn handle_host_environment_command(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: &EnvCommand,
) -> anyhow::Result<bool> {
    let requested = match command {
        EnvCommand::Info(a) => Some(a.environment.as_str()),
        EnvCommand::Report(a) => Some(a.environment.as_str()),
        EnvCommand::Start(a)
        | EnvCommand::Stop(a)
        | EnvCommand::Restart(a)
        | EnvCommand::RefreshSkills(a) => Some(a.environment.as_str()),
        EnvCommand::Rm(a) => Some(a.environment.as_str()),
        EnvCommand::Update(a) => Some(a.environment.as_str()),
        EnvCommand::Resize(a) => Some(a.environment.as_str()),
        EnvCommand::Daemon(a) => a.command.environment(),
        _ => return Ok(false),
    };
    let environment = match requested {
        Some(requested) => resolve_host_reference(globals, requested, placement).await?,
        None => selected_host_environment()?,
    };
    let Some(environment) = environment else {
        return Ok(false);
    };
    match command {
        EnvCommand::Info(a) => {
            // Managed conversations are read only while it runs (#2982).
            let attention = if environment.state == "running" {
                Some(
                    super::sessions::agents::managed_attention(
                        globals,
                        super::sessions::agents::AttentionEnvironment::Host(environment.clone()),
                    )
                    .await,
                )
            } else {
                None
            };
            print_host_environment_info(&environment, a.output, attention.as_ref())?
        }
        EnvCommand::Report(a) => {
            let report = serde_json::json!({"id":environment.id,"name":environment.name,
                "type":"host","placement":"local","isolation":"trusted user execution",
                "state":environment.state,"path":environment.path,
                "provider_credentials":"ordinary installed agent login",
                "process_ownership":"daemon-owned ordinary process groups; abrupt crash cleanup remains unknown",
                "workspace_deletion":false});
            match a.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                OutputFormat::Text => println!(
                    "{}: trusted host at {} ({})",
                    environment.name,
                    environment.path.display(),
                    environment.state
                ),
            }
        }
        EnvCommand::Start(a) => host_lifecycle(environment, "start", a.output).await?,
        EnvCommand::Stop(a) => host_lifecycle(environment, "stop", a.output).await?,
        EnvCommand::Restart(a) => {
            host_lifecycle(environment.clone(), "stop", a.output).await?;
            host_lifecycle(environment, "start", a.output).await?;
        }
        EnvCommand::Rm(a) => {
            if !confirm_removal(&environment.name, "trusted host", a.yes, a.output)? {
                return Ok(true);
            }
            host_lifecycle(environment, "rm", a.output).await?;
        }
        EnvCommand::Daemon(a) => match &a.command {
            EnvDaemonCommand::Status(a) => {
                let state = host_daemon_health(&environment).await;
                match a.output {
                    OutputFormat::Json => println!(
                        "{}",
                        serde_json::json!({"environment_id":environment.id,"state":state})
                    ),
                    OutputFormat::Text => println!("{}\t{}", environment.name, state),
                }
            }
            EnvDaemonCommand::Logs(_) => {
                std::io::stdout().write_all(&fs::read(environment.root().join("daemon.log"))?)?;
            }
            EnvDaemonCommand::Repair(_) => {
                host_session_client(&environment).await?;
                println!("Host daemon ready for {}", environment.name);
            }
        },
        _ => anyhow::bail!("this operation is not supported by trusted host environments"),
    }
    Ok(true)
}

fn validate_host_stopped(root: &std::path::Path) -> anyhow::Result<()> {
    let sessions = root.join("sessions");
    if !sessions.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&sessions)? {
        let path = entry?.path();
        let file = path.join("session.json");
        if !file.is_file() {
            anyhow::bail!(
                "host shutdown evidence is incomplete; runtime retained at {}",
                root.display()
            );
        }
        let record: serde_json::Value = read_private(&file)?;
        let state = record.get("state").and_then(serde_json::Value::as_i64);
        let unknown = record
            .get("cleanup_unknown")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let safe = !unknown
            && (matches!(state, Some(4 | 5))
                || (state == Some(6)
                    && record
                        .get("cleanup_confirmed")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)));
        if !safe {
            anyhow::bail!(
                "host shutdown has unresolved process cleanup; runtime retained at {}",
                root.display()
            );
        }
    }
    Ok(())
}
