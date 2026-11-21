use std::env;
#[cfg(target_os = "linux")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Env, OsEnv, ResolvePaths};
use anyhow::Context as _;
#[cfg(target_os = "linux")]
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, LocalBrokerProcessConfig, LocalBrokerProcessSpawner,
    LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner, LocalRepositorySpawnError,
    LocalRevocationProcessConfig, LocalRevocationProcessSpawner, LocalRevocationSpawnError,
    ProviderLookup,
};
use codewire_local_credentials::{
    AuthorityFeature, AuthorityProtectedStore, AuthorityRuntimeConfig, AuthorityRuntimeError,
    LocalBrokerSpawnError, LocalCredentialClient, LocalCredentialError,
    serve_os_local_credential_authority_with_process_spawners,
};
use codewire_protected_store::{ProtectedStoreBackend, ProtectedStoreError};

#[cfg(target_os = "linux")]
use super::credential_child_store::child_store_arguments;
use super::{
    LocalCredentialAuthorityArgs, LocalCredentialAuthorityProbeArgs, local_credential_root,
};

#[cfg(target_os = "macos")]
mod darwin;
mod platform;
mod ssh;

/// Test and synthetic-acceptance hook: keep Keychain items in this explicit
/// keychain file instead of the login keychain. Fixed when an authority starts.
#[cfg(target_os = "macos")]
const LOCAL_CREDENTIAL_KEYCHAIN_ENV: &str = "CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN";
const AUTHORITY_STOP_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The authority launches the confined broker per local VM generation and the
/// repository executor per credentialed checkout, signs SSH with one isolated
/// agent per signature and delegates platform selections to their platform.
/// On macOS the launcher already supplied a new session, an empty environment
/// and standard descriptors only.
pub(crate) async fn run_local_credential_authority(
    args: LocalCredentialAuthorityArgs,
) -> anyhow::Result<()> {
    // posix_spawn has no umask attribute; set it before any file exists.
    #[cfg(target_os = "macos")]
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    let store = authority_store_from_args(&args)?;
    let mut config = authority_config(args.root)?;
    config.socket_dir = codewire_local_vmm::socket_dir::prepare(&config.root)
        .context("prepare the local credential authority socket directory")?;
    #[cfg(target_os = "linux")]
    let spawner = Arc::new(CwLocalCredentialProcessSpawner {
        executable: config.executable.clone(),
        authority_root: config.root.clone(),
        store: store.clone(),
    });
    #[cfg(target_os = "macos")]
    let spawner = Arc::new(darwin::CwLocalCredentialProcessSpawner {
        executable: config.executable.clone(),
        authority_root: config.root.clone(),
        store: store.clone(),
        runtime: args.runtime_artifact_root.zip(args.runtime_artifact_lock),
    });
    let signer = Arc::new(ssh::LocalSshAgentAdapter::new(
        config.root.clone(),
        config.socket_dir.clone(),
    ));
    let result = serve_os_local_credential_authority_with_process_spawners(
        config,
        store,
        spawner.clone(),
        spawner.clone(),
        spawner,
        signer.clone(),
        Arc::new(platform::NativePlatformCredentialConnector::default()),
    )
    .await;
    // Always drain an initialized owner, including authority-server failure.
    // An ordinary non-SSH authority never initializes tools or staging.
    signer.shutdown().await.context("drain local SSH signer")?;
    result.context("run local credential authority")
}

fn authority_store_from_args(
    args: &LocalCredentialAuthorityArgs,
) -> anyhow::Result<AuthorityProtectedStore> {
    let backend = resolve_local_credential_store(args.protected_store.as_deref())?;
    #[cfg(target_os = "macos")]
    let keychain = args.keychain.clone();
    #[cfg(not(target_os = "macos"))]
    let keychain = None;
    validate_authority_store(AuthorityProtectedStore { backend, keychain })
}

pub(crate) async fn run_local_credential_authority_probe(
    args: LocalCredentialAuthorityProbeArgs,
) -> anyhow::Result<()> {
    let store = configured_authority_store(&OsEnv)?;
    let config = authority_config(args.root)?;
    let client = connect_configured_authority(&config, &store).await?;
    if args.shutdown {
        client
            .shutdown()
            .await
            .context("stop local credential authority")?;
    }
    Ok(())
}

pub(crate) async fn connect_local_credential_authority() -> anyhow::Result<LocalCredentialClient> {
    let env = OsEnv;
    let store = configured_authority_store(&env)?;
    let root = local_credential_root(&env)?;
    let config = authority_config(root)?;
    connect_configured_authority(&config, &store).await
}

/// The local credential authority already serving this root, if one is;
/// nothing is started.
pub(crate) async fn running_local_credential_authority() -> Option<LocalCredentialClient> {
    let config = authority_config(local_credential_root(&OsEnv).ok()?).ok()?;
    LocalCredentialClient::connect(&config).await.ok()
}

#[cfg(target_os = "linux")]
pub(crate) async fn admit_existing_local_credential_authority() -> anyhow::Result<()> {
    let env = OsEnv;
    let root = local_credential_root(&env)?;
    let config = authority_config(root)?;
    // A replacement opens the configured store, as `connect` does: never the
    // platform default over a root that keeps its credentials in files.
    let store = configured_authority_store(&env)?;
    drop(
        LocalCredentialClient::admit_existing_or_replace_with(&config, |config| {
            spawn_authority(config, &store)
        })
        .await
        .context("admit existing local credential authority")?,
    );
    Ok(())
}

/// Admit an authority already listening at the credential root, as on
/// Linux. An absent endpoint starts nothing, so credential-free native
/// operations continue without an authority.
#[cfg(target_os = "macos")]
pub(crate) async fn admit_existing_local_credential_authority() -> anyhow::Result<()> {
    let root = local_credential_root(&OsEnv)?;
    let config = authority_config(root)?;
    drop(
        LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
            Err::<std::process::Child, _>(AuthorityRuntimeError::Spawn)
        })
        .await
        .context("admit existing local credential authority")?,
    );
    Ok(())
}

/// Reuse or start the authority for `store`. An authority still running on
/// another backend was started under an earlier `local_credential_store`;
/// it is stopped so the next start moves the stored values.
async fn connect_configured_authority(
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
) -> anyhow::Result<LocalCredentialClient> {
    let client = start_authority(config, store).await?;
    if running_store(&client).as_ref() == Some(store) {
        return Ok(client);
    }
    eprintln!("Restarting the local credential authority to switch its store to {store}.");
    let client = restart_authority(client, config, store).await?;
    anyhow::ensure!(
        running_store(&client).as_ref() == Some(store),
        "local credential authority did not switch its store to {store}"
    );
    Ok(client)
}

/// The local credential authority, one that serves `feature`; `needed_for`
/// says what an older one can't do. An authority
/// older than this cw keeps serving after an update while a local VM may run;
/// once none does it is replaced here, as a boot command replaces it, before
/// the command asks anything of a provider. While one may run, the command
/// stops and says what to do, so no provider sign-in is spent on a store that
/// would refuse it.
pub(crate) async fn connect_local_credential_authority_serving(
    feature: AuthorityFeature,
    needed_for: &str,
) -> anyhow::Result<LocalCredentialClient> {
    let client = connect_local_credential_authority_preferring(feature).await?;
    anyhow::ensure!(
        feature.served_by(client.info().protocol_version),
        "your local credentials are still kept by the cw you updated from, which can't {needed_for}; it switches to this cw once no local VM runs: stop them (`cw --local stop NAME`), then run this again"
    );
    Ok(client)
}

/// The local credential authority, preferring one that serves `feature`: an
/// older authority is replaced once no local VM runs, as for
/// [`connect_local_credential_authority_serving`], but while one may run the
/// older authority is returned, and the caller does without `feature`.
pub(crate) async fn connect_local_credential_authority_preferring(
    feature: AuthorityFeature,
) -> anyhow::Result<LocalCredentialClient> {
    let client = connect_local_credential_authority().await?;
    if feature.served_by(client.info().protocol_version) {
        return Ok(client);
    }
    drop(client);
    replace_older_local_credential_authority(async {
        let config = super::native_runtime_config()?;
        let mut supervisor =
            codewire_local_vmm::supervisor::NativeSupervisorClient::connect_or_start(&config)
                .await
                .context("ask the local VM supervisor which VMs run")?;
        codewire_local_vmm::supervisor_upgrade::may_replace_older_authority(&mut supervisor)
            .await
            .map_err(anyhow::Error::from)
    })
    .await?;
    connect_local_credential_authority().await
}

/// The local credential authority, for a command that starts a VM which
/// needs one. An authority that is another cw's keeps serving while a local
/// VM may run, and its brokers cannot serve a VM this cw starts: the command
/// stops here, before it changes anything, and names the VMs to stop
/// (`docs/dev/LINUX-LOCAL-VMS.md`, "Credentials after an upgrade"). A boot
/// command has already replaced such an authority when no VM may run.
pub(crate) async fn connect_local_credential_authority_for_boot()
-> anyhow::Result<LocalCredentialClient> {
    let client = connect_local_credential_authority().await?;
    if !client.is_another_cws(codewire_local_vmm::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION) {
        return Ok(client);
    }
    drop(client);
    let config = super::native_runtime_config()?;
    let mut supervisor =
        codewire_local_vmm::supervisor::NativeSupervisorClient::connect_or_start(&config)
            .await
            .context("ask the local VM supervisor which VMs run")?;
    let running = codewire_local_vmm::supervisor_upgrade::vms_that_may_run(&mut supervisor)
        .await
        .map_err(anyhow::Error::from)?;
    // Boxed: the offer restarts VMs through this same boot path. It cannot
    // come back here, because the move retires the previous supervisor first.
    Err(Box::pin(super::offer_restart_when_refused(
        another_cws_authority_refusal(running).into(),
    ))
    .await)
}

/// What a user reads when a VM would start with credentials that another
/// cw's credential authority keeps: which VMs keep it serving, and the
/// command that stops one. Typed, so that the restart offer knows it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AnotherCwsAuthority {
    /// The VM that kept it serving stopped between the two looks.
    #[error(
        "your local credentials are still kept by the cw you updated from, which can't give a VM started by this cw its credentials; no local VM runs any more, so run this again"
    )]
    NoneRuns,
    #[error("{}", running_refusal(.0))]
    Running(Vec<String>),
}

fn running_refusal(names: &[String]) -> String {
    let (noun, keep, they) = if names.len() == 1 {
        ("VM", "keeps", "it stops")
    } else {
        ("VMs", "keep", "they stop")
    };
    format!(
        "your local {noun} {} {keep} your local credentials with the cw you updated from, which can't give a VM started by this cw its credentials; it switches to this cw once {they} (`cw --local stop NAME`)",
        names.join(", ")
    )
}

fn another_cws_authority_refusal(running: Vec<String>) -> AnotherCwsAuthority {
    if running.is_empty() {
        AnotherCwsAuthority::NoneRuns
    } else {
        AnotherCwsAuthority::Running(running)
    }
}

/// Replace a running authority that is another cw's, so the VM a boot command
/// starts gets this cw's: an older one (#2850's platform GitHub question
/// needs protocol 16), or one whose brokers accept another runner protocol
/// than this cw's runner speaks (#5238). Only once `no_vm_may_run`: each
/// running VM's broker belongs to the authority that started it, so while
/// one may run, that authority keeps serving. No authority, or this cw's,
/// changes nothing.
pub(crate) async fn replace_older_local_credential_authority(
    no_vm_may_run: impl std::future::Future<Output = anyhow::Result<bool>>,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let config = authority_config(local_credential_root(&env)?)?;
    let Some(client) = LocalCredentialClient::admit_existing_or_replace_with(&config, |_| {
        Err::<std::process::Child, _>(AuthorityRuntimeError::Spawn)
    })
    .await
    .context("admit existing local credential authority")?
    else {
        return Ok(());
    };
    let another_cws =
        client.is_another_cws(codewire_local_vmm::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION);
    if !another_cws || !no_vm_may_run.await? {
        return Ok(());
    }
    let store = configured_authority_store(&env)?;
    restart_authority(client, &config, &store).await.map(drop)
}

/// Stop `client`'s authority and start this cw's for `store`; a changed
/// store moves the stored values on that start.
async fn restart_authority(
    client: LocalCredentialClient,
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
) -> anyhow::Result<LocalCredentialClient> {
    client
        .shutdown()
        .await
        .context("stop local credential authority")?;
    let deadline = tokio::time::Instant::now() + AUTHORITY_STOP_TIMEOUT;
    // Either endpoint: the client may have reached an authority that a cw
    // before #2745 started in the credential root.
    let accepting = |path: PathBuf| std::os::unix::net::UnixStream::connect(path).is_ok();
    while accepting(config.socket()) || accepting(config.legacy_socket()) {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "local credential authority did not stop"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    start_authority(config, store).await
}

async fn start_authority(
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
) -> anyhow::Result<LocalCredentialClient> {
    match LocalCredentialClient::connect_or_start_with(config, |config| {
        spawn_authority(config, store)
    })
    .await
    {
        Ok(client) => Ok(client),
        Err(AuthorityRuntimeError::Credential(LocalCredentialError::ProtectedStoreSwitch(
            error,
        ))) => anyhow::bail!(
            "local credentials could not move to the configured store ({store}): {error}. Stored \
             values were left unchanged where they were; fix the cause and retry, or set \
             local_credential_store back in {}",
            local_config_path_hint()
        ),
        Err(AuthorityRuntimeError::Credential(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::AccessDenied,
        ))) => anyhow::bail!(
            "local protected storage ({store}) is locked or inaccessible; unlock it and retry"
        ),
        Err(AuthorityRuntimeError::Credential(LocalCredentialError::ProtectedStore(error))) => {
            anyhow::bail!("local credential authority could not open its store ({store}): {error}")
        }
        Err(error) => Err(error).context("connect to local credential authority"),
    }
}

fn running_store(client: &LocalCredentialClient) -> Option<AuthorityProtectedStore> {
    client
        .info()
        .protected_store
        .or_else(AuthorityProtectedStore::platform_default)
}

fn local_config_path_hint() -> String {
    ResolvePaths::from_env(&OsEnv)
        .map(|paths| {
            paths
                .mesh_data_dir
                .join("config.toml")
                .display()
                .to_string()
        })
        .unwrap_or_else(|_| "~/.codewire/config.toml".to_owned())
}

/// The backend selected by `local_credential_store`, plus the test-only
/// explicit keychain on macOS, which applies only to the keychain backend.
/// A previous store is always reached through the authority's own record.
pub(crate) fn configured_authority_store(
    env: &impl Env,
) -> anyhow::Result<AuthorityProtectedStore> {
    let paths = ResolvePaths::from_env(env)?;
    let backend = super::configured_local_credential_store(&paths.mesh_data_dir)?;
    #[cfg(target_os = "macos")]
    let keychain = (backend == ProtectedStoreBackend::Keychain)
        .then(|| env.var(LOCAL_CREDENTIAL_KEYCHAIN_ENV).map(PathBuf::from))
        .flatten();
    #[cfg(not(target_os = "macos"))]
    let keychain = None;
    validate_authority_store(AuthorityProtectedStore { backend, keychain })
}

fn validate_authority_store(
    store: AuthorityProtectedStore,
) -> anyhow::Result<AuthorityProtectedStore> {
    anyhow::ensure!(
        store.is_valid(),
        "an explicit keychain must be an absolute path and applies only to the keychain store"
    );
    Ok(store)
}

fn resolve_local_credential_store(value: Option<&str>) -> anyhow::Result<ProtectedStoreBackend> {
    super::resolve_local_credential_store(value)
}

/// Clients reach the authority at its root's short socket directory (#2745);
/// the authority itself prepares that directory before it binds.
fn authority_config(root: PathBuf) -> anyhow::Result<AuthorityRuntimeConfig> {
    Ok(AuthorityRuntimeConfig {
        socket_dir: codewire_local_vmm::socket_dir::predicted(&root),
        root,
        executable: canonical_current_executable()?,
    })
}

fn canonical_current_executable() -> anyhow::Result<PathBuf> {
    let executable = env::current_exe().context("resolve current cw executable")?;
    std::fs::canonicalize(&executable).with_context(|| {
        format!(
            "canonicalize current cw executable {}",
            executable.display()
        )
    })
}

/// The authority argv names only a non-default backend, so the default
/// Linux argv stays exactly `__local-credential-authority --root ROOT`.
fn authority_arguments(
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
    runtime: Option<&(PathBuf, PathBuf)>,
) -> Vec<std::ffi::OsString> {
    let mut arguments = vec![
        "__local-credential-authority".into(),
        "--root".into(),
        config.root.clone().into_os_string(),
    ];
    if Some(store.backend) != ProtectedStoreBackend::platform_default() {
        arguments.push("--protected-store".into());
        arguments.push(store.backend.as_str().into());
    }
    if let Some(keychain) = &store.keychain {
        arguments.push("--keychain".into());
        arguments.push(keychain.clone().into_os_string());
    }
    if let Some((root, lock)) = runtime {
        arguments.push("--runtime-artifact-root".into());
        arguments.push(root.clone().into_os_string());
        arguments.push("--runtime-artifact-lock".into());
        arguments.push(lock.clone().into_os_string());
    }
    arguments
}

#[cfg(target_os = "macos")]
fn spawn_authority(
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
) -> Result<darwin::SpawnedProcess, AuthorityRuntimeError> {
    // The authority has no environment: name the runtime whose git its
    // repository executors may run.
    let runtime = super::native::runtime_artifact_paths().ok();
    darwin::spawn_detached(
        &config.executable,
        &authority_arguments(config, store, runtime.as_ref()),
        &config.root,
    )
    .map_err(|_| AuthorityRuntimeError::Spawn)
}

#[cfg(target_os = "linux")]
fn spawn_authority(
    config: &AuthorityRuntimeConfig,
    store: &AuthorityProtectedStore,
) -> Result<Child, AuthorityRuntimeError> {
    let allowed_environment = authority_environment(|name| env::var_os(name));
    let mut command = Command::new(&config.executable);
    command
        .args(authority_arguments(config, store, None))
        .env_clear()
        .envs(allowed_environment)
        .current_dir(&config.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: scalar-only libc operations and one fixed-layout capset syscall
    // prepare a capability-empty, no-new-privileges, FD-clean detached
    // singleton before exec. No credential value or platform login variable is
    // inherited; only the two session-bus discovery variables are allowlisted.
    unsafe {
        command.pre_exec(|| {
            confine_spawned_process()?;
            if libc::setsid() < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    command.spawn().map_err(|_| AuthorityRuntimeError::Spawn)
}

#[cfg(target_os = "linux")]
struct CwLocalCredentialProcessSpawner {
    executable: PathBuf,
    authority_root: PathBuf,
    store: AuthorityProtectedStore,
}

#[cfg(target_os = "linux")]
impl CwLocalCredentialProcessSpawner {
    /// The authority's environment, without the session bus address for a
    /// file store, whose children read no Secret Service (#5255).
    fn child_environment(
        &self,
        read: impl Fn(&str) -> Option<OsString>,
    ) -> Vec<(OsString, OsString)> {
        let file_store = self.store.backend == ProtectedStoreBackend::File;
        authority_environment(|name| {
            if file_store && name == "DBUS_SESSION_BUS_ADDRESS" {
                None
            } else {
                read(name)
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl LocalBrokerProcessSpawner for CwLocalCredentialProcessSpawner {
    fn runner_protocol(&self) -> u32 {
        // The broker this starts is this cw's `__local-credential-broker`,
        // whose `RunnerClient` admits exactly this runner protocol.
        codewire_local_vmm::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        lookup: &ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        boot_secrets: &codewire_local_credentials::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        let boot_secrets = boot_secret_descriptor(boot_secrets)?;
        let secrets_fd = boot_secrets.as_ref().map(|secrets| secrets.as_raw_fd());
        let store_arguments = child_store_arguments(&self.store, &self.authority_root)
            .ok_or(LocalBrokerSpawnError::InvalidConfiguration)?;
        let parent_pid = unsafe { libc::getpid() };
        let allowed_environment = self.child_environment(|name| env::var_os(name));
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .arg("__local-credential-broker")
            .arg("--authority-fd")
            .arg("3")
            .arg("--environment-id")
            .arg(config.environment_id.to_string())
            .arg("--environment-generation")
            .arg(config.environment_generation.to_string())
            .arg("--environment-name")
            .arg(&config.environment_name)
            .arg("--runner-socket")
            .arg(&config.runner_socket)
            .args(store_arguments)
            .env_clear()
            .envs(allowed_environment)
            .current_dir(&self.authority_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // The authority keeps the tail of this pipe for its broker log.
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for provider in &config.http_providers {
            command.arg("--http-provider").arg(provider.as_str());
        }
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        if config.network_policy_allows_github {
            command.arg("--network-policy-allows-github");
        }
        for host in &config.network_policy_allowed_hosts {
            command.arg("--network-policy-allows-host").arg(host);
        }
        command.args(lookup.arguments());
        if secrets_fd.is_some() {
            command
                .arg("--boot-secrets-fd")
                .arg(BOOT_SECRETS_FD.to_string());
        }
        // SAFETY: this post-fork hook uses scalar libc operations only. It
        // transfers one authority-created socket to fixed FD 3, and a boot's
        // secrets, when it has any, to fixed FD 4, marks every other inherited
        // descriptor close-on-exec, removes capabilities, disables dumps, and
        // binds child death to the exact authority parent.
        unsafe {
            command.pre_exec(move || {
                confine_spawned_process()?;
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::setsid() < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                if authority_fd == 3 {
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup3(authority_fd, 3, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                // After FD 3: the secrets' descriptor is above it, so the
                // move to 3 never overwrites it.
                if let Some(secrets_fd) = secrets_fd
                    && libc::dup3(secrets_fd, BOOT_SECRETS_FD, 0) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                let first_closed = if secrets_fd.is_some() { 5_u32 } else { 4_u32 };
                if libc::syscall(
                    libc::SYS_close_range,
                    first_closed,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| LocalBrokerSpawnError::Spawn);
        // The authority keeps no open end once the child has its own.
        drop(boot_secrets);
        child
    }
}

/// The descriptor a broker child inherits a boot's secrets at (#3999).
pub(super) const BOOT_SECRETS_FD: i32 = 4;

/// A boot's secrets as the read end of a socket pair whose write end is
/// already closed, placed above every descriptor the spawn moves, or none
/// for a boot without secrets. The records never touch a file.
fn boot_secret_descriptor(
    secrets: &codewire_local_credentials::BrokerBootSecrets,
) -> Result<Option<std::os::fd::OwnedFd>, LocalBrokerSpawnError> {
    use std::io::Write as _;
    if secrets.is_empty() {
        return Ok(None);
    }
    let (mut writer, reader) =
        std::os::unix::net::UnixStream::pair().map_err(|_| LocalBrokerSpawnError::Spawn)?;
    writer
        .write_all(&secrets.records())
        .map_err(|_| LocalBrokerSpawnError::Spawn)?;
    drop(writer);
    let reader = std::os::fd::OwnedFd::from(reader);
    let raised = rustix::io::fcntl_dupfd_cloexec(&reader, BOOT_SECRETS_FD + 1)
        .map_err(|_| LocalBrokerSpawnError::Spawn)?;
    Ok(Some(raised))
}

#[cfg(target_os = "linux")]
impl LocalRepositoryProcessSpawner for CwLocalCredentialProcessSpawner {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        }
        let store_arguments = child_store_arguments(&self.store, &self.authority_root)
            .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
        let parent_pid = unsafe { libc::getpid() };
        // SSH uses the inherited signing channel and explicit public runtime
        // path only. Do not give its executor the Secret Service bus context.
        let allowed_environment = match config.transport {
            codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth
                if config.platform_delegated =>
            {
                // Only the helper's private runtime directory. No Secret
                // Service bus, owner HOME, agent socket or provider context.
                authority_environment(|name| {
                    if name == "XDG_RUNTIME_DIR" {
                        env::var_os(name)
                    } else {
                        None
                    }
                })
            }
            codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth => {
                self.child_environment(|name| env::var_os(name))
            }
            codewire_local_credentials::LocalRepositoryTransport::Ssh => Vec::new(),
        };
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .arg("__local-git-repository-executor")
            .arg("--transport")
            .arg(match config.transport {
                codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth => "github-oauth",
                codewire_local_credentials::LocalRepositoryTransport::Ssh => "ssh",
            })
            .arg("--authority-fd")
            .arg("3")
            .arg("--request-id")
            .arg(config.request_id.to_string())
            .arg("--staging-directory")
            .arg(&config.staging_directory)
            .args(store_arguments)
            .env_clear()
            .envs(allowed_environment)
            .current_dir(&config.staging_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        if config.transport == codewire_local_credentials::LocalRepositoryTransport::Ssh {
            let runtime = config
                .ssh_runtime_directory
                .as_ref()
                .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
            command.arg("--ssh-runtime-directory").arg(runtime);
            // The existing preparation owner drains this inherited lifetime
            // pipe, discarding diagnostics, before acknowledging cleanup.
            command.stderr(Stdio::piped());
        }
        confine_executor_to_fd3(&mut command, authority_fd, parent_pid);
        command
            .spawn()
            .map_err(|_| LocalRepositorySpawnError::Spawn)
    }
}

/// The one-shot provider revocation executor (#4717): the local GitHub
/// executor's store, environment and confinement.
#[cfg(target_os = "linux")]
impl LocalRevocationProcessSpawner for CwLocalCredentialProcessSpawner {
    fn spawn(
        &self,
        config: &LocalRevocationProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRevocationSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalRevocationSpawnError::InvalidConfiguration);
        }
        let store_arguments = child_store_arguments(&self.store, &self.authority_root)
            .ok_or(LocalRevocationSpawnError::InvalidConfiguration)?;
        let parent_pid = unsafe { libc::getpid() };
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .arg("__local-provider-revocation-executor")
            .arg("--authority-fd")
            .arg("3")
            .arg("--request-id")
            .arg(config.request_id.to_string())
            .args(store_arguments)
            .env_clear()
            .envs(self.child_environment(|name| env::var_os(name)))
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        confine_executor_to_fd3(&mut command, authority_fd, parent_pid);
        command
            .spawn()
            .map_err(|_| LocalRevocationSpawnError::Spawn)
    }
}

/// The post-fork setup both one-shot executors share: the one
/// authority-created socket moved to FD 3, and the long-lived broker's
/// capability-empty, no-new-privileges, non-dumpable, parent-bound
/// confinement.
#[cfg(target_os = "linux")]
fn confine_executor_to_fd3(
    command: &mut tokio::process::Command,
    authority_fd: std::os::fd::RawFd,
    parent_pid: libc::pid_t,
) {
    // SAFETY: this post-fork hook transfers one authority-created socket
    // to FD 3 and applies the same capability-empty, no-new-privileges,
    // non-dumpable, parent-bound confinement as the long-lived broker.
    unsafe {
        command.pre_exec(move || {
            confine_spawned_process()?;
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::setsid() < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if authority_fd == 3 {
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup3(authority_fd, 3, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                4_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
fn authority_environment(read: impl Fn(&str) -> Option<OsString>) -> Vec<(OsString, OsString)> {
    let runtime_dir = read("XDG_RUNTIME_DIR").filter(|value| valid_runtime_dir(value));
    let bus_address = runtime_dir.as_ref().and_then(|runtime_dir| {
        let expected = OsString::from(format!(
            "unix:path={}",
            PathBuf::from(runtime_dir).join("bus").display()
        ));
        read("DBUS_SESSION_BUS_ADDRESS").filter(|value| *value == expected)
    });
    let mut environment = Vec::with_capacity(AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES.len());
    if let Some(bus_address) = bus_address {
        environment.push((OsString::from("DBUS_SESSION_BUS_ADDRESS"), bus_address));
    }
    if let Some(runtime_dir) = runtime_dir {
        environment.push((OsString::from("XDG_RUNTIME_DIR"), runtime_dir));
    }
    environment
}

#[cfg(target_os = "linux")]
fn valid_runtime_dir(value: &OsStr) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(target_os = "linux")]
pub(super) fn confine_spawned_process() -> io::Result<()> {
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [empty; 2];
    // SAFETY: capset v3 reads one fixed header and exactly two fixed data
    // elements. pid=0 targets only this post-fork child thread.
    if unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of!(header), data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both prctl operations use scalar arguments and mutate only this
    // post-fork child. Failure is fatal rather than launching less confined.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::collections::BTreeMap;

    use crate::config::MapEnv;

    use super::super::LOCAL_CREDENTIAL_ROOT_ENV;
    use super::*;

    /// The words of `docs/dev/LINUX-LOCAL-VMS.md`, "Credentials after an
    /// upgrade": the VMs that keep another cw's credential service serving,
    /// and a stop command that runs (`cw stop` takes one name).
    #[test]
    fn a_boot_another_cws_credential_service_cannot_serve_names_the_vms_to_stop() {
        let refusal =
            another_cws_authority_refusal(vec!["dev".to_owned(), "web".to_owned()]).to_string();
        assert_eq!(
            refusal,
            "your local VMs dev, web keep your local credentials with the cw you updated from, which can't give a VM started by this cw its credentials; it switches to this cw once they stop (`cw --local stop NAME`)"
        );
        let one = another_cws_authority_refusal(vec!["dev".to_owned()]).to_string();
        assert!(
            one.starts_with("your local VM dev keeps your local credentials")
                && one.contains("once it stops"),
            "{one}"
        );
        let raced = another_cws_authority_refusal(Vec::new()).to_string();
        assert!(raced.ends_with("run this again"), "{raced}");
        assert!(!raced.contains("cw --local stop"), "{raced}");
    }

    fn runtime_config() -> AuthorityRuntimeConfig {
        AuthorityRuntimeConfig {
            root: "/synthetic/home/.codewire/credentials-v1".into(),
            executable: "/synthetic/bin/cw".into(),
            socket_dir: "/tmp/cw-1000/0123456789abcdef".into(),
        }
    }

    /// #2745: with an 80-byte HOME every authority socket still fits, because
    /// they live in the root's short socket directory, not under HOME.
    #[test]
    fn the_authority_sockets_fit_for_a_long_home() {
        let home = format!("/home/{}", "h".repeat(74));
        assert_eq!(home.len(), 80);
        let root = PathBuf::from(&home).join(".codewire/credentials-v1");
        let config = authority_config(root.clone()).unwrap();
        assert_eq!(
            config.socket_dir,
            codewire_local_vmm::socket_dir::predicted(&root)
        );
        assert!(!config.socket_dir.starts_with(&home));
        let id = uuid::Uuid::new_v4();
        for socket in [
            config.socket(),
            config.socket_dir.join(format!("ssh-{id}/agent")),
            config
                .socket_dir
                .join(format!("signer/.cw-{}/a", id.simple())),
            config.socket_dir.join(format!("cwgr-{id}/c")),
        ] {
            codewire_local_credentials::check_socket_path(&socket).unwrap();
        }
        // Where the authority listened before #2745 does not fit.
        assert!(codewire_local_credentials::check_socket_path(&config.legacy_socket()).is_err());
    }

    #[test]
    fn the_default_store_keeps_the_exact_authority_argv() {
        let store = AuthorityProtectedStore::platform_default().unwrap();
        assert_eq!(
            authority_arguments(&runtime_config(), &store, None),
            [
                "__local-credential-authority",
                "--root",
                "/synthetic/home/.codewire/credentials-v1"
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_selected_store_and_test_keychain_are_explicit_authority_arguments() {
        use clap::Parser as _;

        let store = AuthorityProtectedStore {
            backend: ProtectedStoreBackend::File,
            keychain: None,
        };
        assert_eq!(
            authority_arguments(&runtime_config(), &store, None),
            [
                "__local-credential-authority",
                "--root",
                "/synthetic/home/.codewire/credentials-v1",
                "--protected-store",
                "file"
            ]
        );
        let store = AuthorityProtectedStore {
            backend: ProtectedStoreBackend::Keychain,
            keychain: Some("/private/tmp/synthetic.keychain-db".into()),
        };
        assert_eq!(
            authority_arguments(&runtime_config(), &store, None),
            [
                "__local-credential-authority",
                "--root",
                "/synthetic/home/.codewire/credentials-v1",
                "--keychain",
                "/private/tmp/synthetic.keychain-db"
            ]
        );
        let parsed = crate::Cli::try_parse_from(
            std::iter::once(std::ffi::OsString::from("cw")).chain(authority_arguments(
                &runtime_config(),
                &store,
                None,
            )),
        )
        .unwrap();
        let crate::Command::LocalCredentialAuthority(args) = parsed.command else {
            panic!("authority argv must parse as the authority entrypoint");
        };
        assert_eq!(authority_store_from_args(&args).unwrap(), store);
    }

    #[test]
    fn configured_stores_reject_a_keychain_for_other_backends_and_relative_paths() {
        for (backend, keychain) in [
            (ProtectedStoreBackend::File, "/private/tmp/k.keychain-db"),
            (ProtectedStoreBackend::Keychain, "relative.keychain-db"),
        ] {
            assert!(
                validate_authority_store(AuthorityProtectedStore {
                    backend,
                    keychain: Some(keychain.into()),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn the_store_setting_comes_from_local_config_and_defaults_per_platform() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([("HOME", home.path().to_str().unwrap())]);
        assert_eq!(
            configured_authority_store(&env).unwrap(),
            AuthorityProtectedStore::platform_default().unwrap()
        );
        let data = home.path().join(".codewire");
        std::fs::create_dir(&data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let write = |value: &str| {
            let path = data.join("config.toml");
            std::fs::write(&path, format!("local_credential_store = {value:?}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        };
        write("keyring");
        assert!(configured_authority_store(&env).is_err());
        #[cfg(target_os = "macos")]
        {
            write("file");
            assert_eq!(
                configured_authority_store(&env).unwrap().backend,
                ProtectedStoreBackend::File
            );
            write("secret-service");
            assert!(configured_authority_store(&env).is_err());
        }
        #[cfg(target_os = "linux")]
        {
            write("secret-service");
            assert_eq!(
                configured_authority_store(&env).unwrap().backend,
                ProtectedStoreBackend::SecretService
            );
            // The file store is a Linux choice too (#5255); the keychain isn't.
            write("file");
            assert_eq!(
                configured_authority_store(&env).unwrap().backend,
                ProtectedStoreBackend::File
            );
            write("keychain");
            let error = configured_authority_store(&env).unwrap_err();
            assert!(error.to_string().contains("secret-service"), "{error}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_process_inherits_only_session_bus_discovery() {
        let [authority_dbus_env, authority_xdg_runtime_env] =
            AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
        let ambient = BTreeMap::from([
            (authority_dbus_env, "unix:path=/run/user/1000/bus"),
            (authority_xdg_runtime_env, "/run/user/1000"),
            ("CODEWIRE_API_KEY", "synthetic-platform-token"),
            ("OPENAI_API_KEY", "synthetic-provider-token"),
            ("SSH_AUTH_SOCK", "/tmp/synthetic-agent.sock"),
        ]);
        let inherited = authority_environment(|name| ambient.get(name).map(OsString::from));

        assert_eq!(
            inherited,
            vec![
                (
                    OsString::from(authority_dbus_env),
                    OsString::from("unix:path=/run/user/1000/bus"),
                ),
                (
                    OsString::from(authority_xdg_runtime_env),
                    OsString::from("/run/user/1000"),
                ),
            ]
        );
    }

    /// #5255: a file store's broker and repository executor read no Secret
    /// Service, so they get no session bus; a Secret Service root's keep it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_store_child_gets_no_session_bus() {
        let ambient = BTreeMap::from([
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ]);
        let spawner = |backend| CwLocalCredentialProcessSpawner {
            executable: "/synthetic/bin/cw".into(),
            authority_root: "/synthetic/home/.codewire/credentials-v1".into(),
            store: AuthorityProtectedStore {
                backend,
                keychain: None,
            },
        };
        let names = |backend| {
            spawner(backend)
                .child_environment(|name| ambient.get(name).map(OsString::from))
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(ProtectedStoreBackend::File),
            vec![OsString::from("XDG_RUNTIME_DIR")]
        );
        assert_eq!(
            names(ProtectedStoreBackend::SecretService),
            vec![
                OsString::from("DBUS_SESSION_BUS_ADDRESS"),
                OsString::from("XDG_RUNTIME_DIR")
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_rejects_remote_or_noncanonical_session_bus_discovery() {
        for (runtime, bus) in [
            ("relative", "unix:path=relative/bus"),
            ("/run/user/1000/../1001", "unix:path=/run/user/1001/bus"),
            ("/run/user/1000", "tcp:host=127.0.0.1,port=5555"),
            ("/run/user/1000", "unix:path=/tmp/other-bus"),
        ] {
            let ambient = BTreeMap::from([
                ("XDG_RUNTIME_DIR", runtime),
                ("DBUS_SESSION_BUS_ADDRESS", bus),
            ]);
            let inherited = authority_environment(|name| ambient.get(name).map(OsString::from));
            assert!(
                inherited
                    .iter()
                    .all(|(name, _)| name != "DBUS_SESSION_BUS_ADDRESS"),
                "{runtime} {bus}"
            );
        }
    }

    #[test]
    fn local_credential_state_is_separate_from_platform_login() {
        let env = MapEnv::new([
            ("HOME", "/home/tester"),
            ("CW_CONFIG_DIR", "/tmp/platform-login"),
        ]);
        assert_eq!(
            local_credential_root(&env).unwrap(),
            PathBuf::from("/home/tester/.codewire/credentials-v1")
        );

        let overridden = MapEnv::new([
            ("HOME", "/home/tester"),
            (LOCAL_CREDENTIAL_ROOT_ENV, "/tmp/private/credentials"),
        ]);
        assert_eq!(
            local_credential_root(&overridden).unwrap(),
            PathBuf::from("/tmp/private/credentials")
        );
        assert!(
            local_credential_root(&MapEnv::new([(LOCAL_CREDENTIAL_ROOT_ENV, "relative")])).is_err()
        );
    }
}
