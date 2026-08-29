//! Per-user native local-environment supervisor.
//!
//! The durable JSON document in this module is intentionally a bounded
//! precursor to the journal/SQLite recovery model owned by the next work item.
//! It contains process and socket identities, but never daemon capabilities or
//! workload credentials.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};
use rustix::process::Signal;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::linux::path::{PathError, PrivateRoot, SocketIdentity};
use crate::linux::process::signal_unreaped_child;
use crate::linux::{LiveProcess, ProcessIdentity, RecoveryError};
use crate::runner_service::{RunnerClient, RunnerServiceError};
use crate::uds::{UdsError, bind_owner_only, connect_owner_only, remove_bound_socket};
use crate::workspace::{WorkspaceError, provision_clean_git_workspace};
use crate::{CloudHypervisorRunner, RunnerConfig, RunnerError};

const SUPERVISOR_STATE_SCHEMA: u32 = 1;
const MAXIMUM_STATE_BYTES: u64 = 1024 * 1024;
const RUNNER_START_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_DRAIN_DELAY: Duration = Duration::from_millis(100);
const DAEMON_VSOCK_PORT: u32 = 7777;
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

#[derive(Debug, Clone)]
pub struct NativeRuntimeConfig {
    pub root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
    pub executable: PathBuf,
}

impl NativeRuntimeConfig {
    pub fn supervisor_socket(&self) -> PathBuf {
        self.root.join("supervisor.sock")
    }

    fn engine_root(&self) -> PathBuf {
        self.root.join("engine")
    }

    fn runner_socket(&self, environment_id: Uuid) -> PathBuf {
        self.root
            .join("runners")
            .join(format!("{environment_id}.sock"))
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        for path in [
            &self.root,
            &self.artifact_root,
            &self.artifact_lock,
            &self.executable,
        ] {
            if !path.is_absolute() {
                return Err(SupervisorError::InvalidConfiguration);
            }
        }
        if self.artifact_root.parent() != self.artifact_lock.parent() {
            return Err(SupervisorError::InvalidConfiguration);
        }
        let executable =
            fs::canonicalize(&self.executable).map_err(|source| SupervisorError::Io {
                path: self.executable.clone(),
                source,
            })?;
        if executable != self.executable {
            return Err(SupervisorError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
}

impl NativeSupervisorClient {
    pub async fn connect_or_start(config: &NativeRuntimeConfig) -> Result<Self, SupervisorError> {
        config.validate()?;
        prepare_runtime_root(&config.root)?;
        let socket = config.supervisor_socket();
        if fs::symlink_metadata(&socket).is_ok() {
            // A killed supervisor leaves a mode-0600 socket name behind. A
            // replacement singleton owns the lock and performs the exact
            // nofollow removal; the CLI never unlinks a control endpoint.
            if let Ok(client) = Self::connect(&socket).await {
                return Ok(client);
            }
        }
        let mut child = spawn_supervisor(config)?;
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        loop {
            if fs::symlink_metadata(&socket).is_ok() {
                match Self::connect(&socket).await {
                    Ok(client) => return Ok(client),
                    Err(error) if tokio::time::Instant::now() < deadline => {
                        let _ = error;
                    }
                    Err(error) => {
                        terminate_unadmitted_child(&mut child);
                        return Err(error);
                    }
                }
            }
            if child
                .try_wait()
                .map_err(|_| SupervisorError::SpawnSupervisor)?
                .is_some()
                && fs::symlink_metadata(&socket).is_err()
            {
                return Err(SupervisorError::SpawnSupervisor);
            }
            if tokio::time::Instant::now() >= deadline {
                terminate_unadmitted_child(&mut child);
                return Err(SupervisorError::SupervisorStartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn connect(socket: &Path) -> Result<Self, SupervisorError> {
        let channel = connect_owner_only(socket).await?;
        Ok(Self {
            inner: LocalSupervisorServiceClient::new(channel),
        })
    }

    pub async fn create(
        &mut self,
        request: v1::CreateEnvironmentRequest,
    ) -> Result<v1::Environment, Status> {
        Ok(self.inner.create_environment(request).await?.into_inner())
    }

    pub async fn list(&mut self) -> Result<Vec<v1::Environment>, Status> {
        Ok(self
            .inner
            .list_environments(v1::ListEnvironmentsRequest {})
            .await?
            .into_inner()
            .environments)
    }

    pub async fn get(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .get_environment(selector(name))
            .await?
            .into_inner())
    }

    pub async fn start(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .start_environment(selector(name))
            .await?
            .into_inner())
    }

    pub async fn stop(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .stop_environment(selector(name))
            .await?
            .into_inner())
    }

    pub async fn delete(&mut self, name: &str) -> Result<v1::DeleteEnvironmentResponse, Status> {
        Ok(self
            .inner
            .delete_environment(selector(name))
            .await?
            .into_inner())
    }

    pub async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, Status> {
        Ok(self
            .inner
            .get_daemon_access(selector(name))
            .await?
            .into_inner())
    }
}

fn selector(name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
    }
}

pub async fn serve_supervisor(config: NativeRuntimeConfig) -> Result<(), SupervisorError> {
    config.validate()?;
    let root = prepare_runtime_root(&config.root)?;
    let lock = SupervisorLock::acquire(&root)?;
    let state = SupervisorState::read(&root)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let service = SupervisorRpc {
        core: Arc::new(Mutex::new(SupervisorCore {
            config: config.clone(),
            root,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            _lock: lock,
        })),
        shutdown: shutdown_tx,
    };
    let socket = config.supervisor_socket();
    let (incoming, socket_identity) = bind_owner_only(&socket)?;
    let result = tonic::transport::Server::builder()
        .add_service(LocalSupervisorServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, async move {
            while shutdown_rx.changed().await.is_ok() {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        })
        .await
        .map_err(|_| SupervisorError::Serve);
    remove_bound_socket(&socket, &socket_identity)?;
    result
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StoredEnvironmentState {
    Stopped,
    Starting,
    Running,
    Error,
}

impl StoredEnvironmentState {
    fn proto(self) -> v1::EnvironmentState {
        match self {
            Self::Stopped => v1::EnvironmentState::Stopped,
            Self::Starting => v1::EnvironmentState::Starting,
            Self::Running => v1::EnvironmentState::Running,
            Self::Error => v1::EnvironmentState::Error,
        }
    }

    fn from_proto(value: i32) -> Result<Self, SupervisorError> {
        match v1::EnvironmentState::try_from(value) {
            Ok(v1::EnvironmentState::Stopped) => Ok(Self::Stopped),
            Ok(v1::EnvironmentState::Starting) => Ok(Self::Starting),
            Ok(v1::EnvironmentState::Running) => Ok(Self::Running),
            Ok(v1::EnvironmentState::Error) => Ok(Self::Error),
            _ => Err(SupervisorError::InvalidRunnerResponse),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RunnerRecord {
    process: ProcessIdentity,
    socket: SocketIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnvironmentRecord {
    id: Uuid,
    name: String,
    state: StoredEnvironmentState,
    vcpus: u8,
    memory_mib: u32,
    disk_bytes: u64,
    generation: u64,
    workspace_commit: String,
    source_path: PathBuf,
    runner: Option<RunnerRecord>,
}

impl EnvironmentRecord {
    fn proto(&self, selected: bool) -> v1::Environment {
        v1::Environment {
            id: self.id.to_string(),
            name: self.name.clone(),
            state: self.state.proto() as i32,
            vcpus: u32::from(self.vcpus),
            memory_mib: self.memory_mib,
            disk_bytes: self.disk_bytes,
            generation: self.generation,
            workspace_commit: self.workspace_commit.clone(),
            source_path: self.source_path.to_string_lossy().into_owned(),
            selected,
        }
    }

    fn validate(&self, key: &str) -> Result<(), SupervisorError> {
        if self.id.is_nil()
            || self.name != key
            || !valid_environment_name(&self.name)
            || self.vcpus == 0
            || self.vcpus > 32
            || !(128..=65_536).contains(&self.memory_mib)
            || self.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(1024 * 1024)
            || !valid_object_id(&self.workspace_commit)
            || !self.source_path.is_absolute()
        {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SupervisorState {
    schema_version: u32,
    current: Option<String>,
    environments: BTreeMap<String, EnvironmentRecord>,
}

impl Default for SupervisorState {
    fn default() -> Self {
        Self {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: None,
            environments: BTreeMap::new(),
        }
    }
}

impl SupervisorState {
    fn read(root: &PrivateRoot) -> Result<Self, SupervisorError> {
        let path = root.path().join("state.json");
        let mut file =
            match root.open_regular(Path::new("state.json"), false, None, false, Some(0o600)) {
                Ok(opened) => opened.into_file(),
                Err(PathError::Openat2 {
                    source: rustix::io::Errno::NOENT,
                    ..
                }) => return Ok(Self::default()),
                Err(error) => return Err(error.into()),
            };
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAXIMUM_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| SupervisorError::Io {
                path: path.clone(),
                source,
            })?;
        if bytes.len() as u64 > MAXIMUM_STATE_BYTES {
            return Err(SupervisorError::InvalidState);
        }
        let state: Self =
            serde_json::from_slice(&bytes).map_err(|_| SupervisorError::InvalidState)?;
        state.validate()?;
        Ok(state)
    }

    fn write(&self, root: &PrivateRoot) -> Result<(), SupervisorError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SupervisorError::InvalidState)?;
        if bytes.len() as u64 > MAXIMUM_STATE_BYTES {
            return Err(SupervisorError::InvalidState);
        }
        root.atomic_replace(Path::new("state.json"), &bytes, 0o600)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        if self.schema_version != SUPERVISOR_STATE_SCHEMA
            || self
                .current
                .as_ref()
                .is_some_and(|name| !self.environments.contains_key(name))
        {
            return Err(SupervisorError::InvalidState);
        }
        for (name, environment) in &self.environments {
            environment.validate(name)?;
        }
        let value = serde_json::to_value(self).map_err(|_| SupervisorError::InvalidState)?;
        if contains_forbidden_state_key(&value) {
            return Err(SupervisorError::SecretInState);
        }
        Ok(())
    }
}

fn contains_forbidden_state_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(name, value)| {
            let name = name.to_ascii_lowercase();
            name.contains("capability")
                || name.contains("credential")
                || name.contains("token")
                || contains_forbidden_state_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_forbidden_state_key),
        _ => false,
    }
}

struct SupervisorLock(File);

impl SupervisorLock {
    fn acquire(root: &PrivateRoot) -> Result<Self, SupervisorError> {
        let opened = root.create_regular(Path::new("supervisor.lock"), 0o600, false)?;
        flock(opened.file(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SupervisorError::AlreadyRunning)?;
        Ok(Self(opened.into_file()))
    }
}

impl std::fmt::Debug for SupervisorLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorLock")
            .field("file", &self.0)
            .finish_non_exhaustive()
    }
}

struct SupervisorCore {
    config: NativeRuntimeConfig,
    root: PrivateRoot,
    state: SupervisorState,
    children: HashMap<Uuid, Child>,
    live_runners: HashMap<Uuid, LiveProcess>,
    _lock: SupervisorLock,
}

impl SupervisorCore {
    fn save(&self) -> Result<(), SupervisorError> {
        self.state.write(&self.root)
    }

    fn selected(&self, name: &str) -> bool {
        self.state.current.as_deref() == Some(name)
    }

    fn environment(&self, name: &str) -> Result<&EnvironmentRecord, SupervisorError> {
        self.state
            .environments
            .get(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))
    }

    fn environment_mut(&mut self, name: &str) -> Result<&mut EnvironmentRecord, SupervisorError> {
        self.state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))
    }

    async fn preflight(&self) -> Result<(), SupervisorError> {
        let runner = CloudHypervisorRunner::new(RunnerConfig {
            state_root: self.config.engine_root(),
            artifact_root: self.config.artifact_root.clone(),
            artifact_lock: self.config.artifact_lock.clone(),
        })
        .await?;
        runner.preflight()?;
        Ok(())
    }

    async fn reconcile(&mut self, name: &str) -> Result<(), SupervisorError> {
        let Some(record) = self.environment(name)?.runner.clone() else {
            return Ok(());
        };
        let environment_id = self.environment(name)?.id;
        let expected_socket = self.config.runner_socket(environment_id);
        let exited = if let Some(live) = self.live_runners.get(&environment_id) {
            if live.identity() != &record.process {
                return Err(SupervisorError::InvalidState);
            }
            live.is_exited()?
        } else {
            let live = match LiveProcess::recover(&record.process) {
                Ok(live) => live,
                Err(RecoveryError::ReadProcess(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    self.mark_runner_dead(name)?;
                    return Ok(());
                }
                Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => {
                    self.mark_runner_dead(name)?;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            let exited = live.is_exited()?;
            if !exited {
                self.live_runners.insert(environment_id, live);
            }
            exited
        };
        if exited {
            self.mark_runner_dead(name)?;
            return Ok(());
        }
        record.socket.revalidate(&expected_socket)?;
        let mut client = RunnerClient::connect(&expected_socket).await?;
        let info = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if info.environment_id != environment_id.to_string() {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let state = StoredEnvironmentState::from_proto(info.state)?;
        let environment = self.environment_mut(name)?;
        environment.state = state;
        environment.generation = environment.generation.max(info.generation);
        self.save()
    }

    fn mark_runner_dead(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        self.live_runners.remove(&environment_id);
        if let Some(mut child) = self.children.remove(&environment_id) {
            let _ = child.try_wait();
        }
        let environment = self.environment_mut(name)?;
        environment.runner = None;
        if matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting
        ) {
            environment.state = StoredEnvironmentState::Error;
        }
        self.save()
    }

    async fn runner_client(&mut self, name: &str) -> Result<RunnerClient, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.runner.is_none() {
            return self.spawn_runner(name).await;
        }
        let socket = self.config.runner_socket(self.environment(name)?.id);
        RunnerClient::connect(&socket).await.map_err(Into::into)
    }

    async fn spawn_runner(&mut self, name: &str) -> Result<RunnerClient, SupervisorError> {
        let environment_id = self.environment(name)?.id;
        let socket = self.config.runner_socket(environment_id);
        let runners = PrivateRoot::open(&self.root.path().join("runners"))?;
        let socket_name = socket
            .file_name()
            .map(Path::new)
            .ok_or(SupervisorError::InvalidConfiguration)?;
        runners.remove_private_socket(socket_name)?;
        let expected_parent = unsafe { libc::getpid() };
        let mut command = Command::new(&self.config.executable);
        command
            .arg("__native-runner")
            .arg("--environment-id")
            .arg(environment_id.to_string())
            .arg("--socket")
            .arg(&socket)
            .arg("--engine-state-root")
            .arg(self.config.engine_root())
            .arg("--artifact-root")
            .arg(&self.config.artifact_root)
            .arg("--artifact-lock")
            .arg(&self.config.artifact_lock)
            .env_clear()
            .current_dir(&self.config.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: these libc calls use only scalar arguments between fork and
        // exec. PDEATHSIG closes the spawn-to-manifest orphan window; the
        // runner clears it only after its exact identity is durable.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != expected_parent
                    || libc::setsid() < 0
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
        let mut child = command.spawn().map_err(|_| SupervisorError::SpawnRunner)?;
        let pid = child.id();
        let live = match LiveProcess::capture_child(pid, &self.config.executable) {
            Ok(live) => live,
            Err(error) => {
                terminate_unadmitted_child(&mut child);
                return Err(error.into());
            }
        };
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        let socket_identity = loop {
            if child
                .try_wait()
                .map_err(|_| SupervisorError::SpawnRunner)?
                .is_some()
            {
                return Err(SupervisorError::SpawnRunner);
            }
            if fs::symlink_metadata(&socket).is_ok() {
                match SocketIdentity::capture(&socket) {
                    Ok(identity) => break identity,
                    Err(error) => {
                        let _ = error;
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = live.signal(Signal::KILL);
                let _ = child.wait();
                return Err(SupervisorError::RunnerStartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let runner_record = RunnerRecord {
            process: live.identity().clone(),
            socket: socket_identity,
        };
        self.environment_mut(name)?.runner = Some(runner_record);
        if let Err(error) = self.save() {
            self.environment_mut(name)?.runner = None;
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            return Err(error);
        }
        let mut client = match RunnerClient::connect(&socket).await {
            Ok(client) => client,
            Err(error) => {
                let _ = live.signal(Signal::KILL);
                let _ = child.wait();
                self.environment_mut(name)?.runner = None;
                self.save()?;
                return Err(error.into());
            }
        };
        if client.adopt(environment_id).await.is_err() {
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            self.environment_mut(name)?.runner = None;
            self.save()?;
            return Err(SupervisorError::RunnerAdoption);
        }
        self.live_runners.insert(environment_id, live);
        self.children.insert(environment_id, child);
        Ok(client)
    }

    async fn start(&mut self, name: &str) -> Result<v1::Environment, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Running {
            return Ok(self.environment(name)?.proto(self.selected(name)));
        }
        let generation = self
            .environment(name)?
            .generation
            .checked_add(1)
            .ok_or(SupervisorError::InvalidState)?;
        self.environment_mut(name)?.state = StoredEnvironmentState::Starting;
        self.save()?;
        let mut client = self.runner_client(name).await?;
        let environment = self.environment(name)?.clone();
        let info = match client
            .start(v1::StartVmRequest {
                environment_id: environment.id.to_string(),
                generation,
                vsock_cid: allocate_vsock_cid(environment.id),
                daemon_vsock_port: DAEMON_VSOCK_PORT,
                state_disk_bytes: environment.disk_bytes,
                vcpus: u32::from(environment.vcpus),
                memory_mib: environment.memory_mib,
            })
            .await
        {
            Ok(info) => info,
            Err(status) => {
                self.environment_mut(name)?.state = StoredEnvironmentState::Error;
                self.save()?;
                return Err(SupervisorError::VmStart(status.message().to_owned()));
            }
        };
        if info.environment_id != environment.id.to_string()
            || info.generation != generation
            || info.state != v1::EnvironmentState::Running as i32
        {
            self.environment_mut(name)?.state = StoredEnvironmentState::Error;
            self.save()?;
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let selected = self.selected(name);
        let environment = self.environment_mut(name)?;
        environment.generation = generation;
        environment.state = StoredEnvironmentState::Running;
        self.save()?;
        Ok(self.environment(name)?.proto(selected))
    }

    async fn stop(&mut self, name: &str) -> Result<v1::Environment, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Stopped {
            return Ok(self.environment(name)?.proto(self.selected(name)));
        }
        let mut client = self.runner_client(name).await?;
        let info = client.stop().await.map_err(|_| SupervisorError::VmStop)?;
        if info.environment_id != self.environment(name)?.id.to_string()
            || info.state != v1::EnvironmentState::Stopped as i32
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let selected = self.selected(name);
        self.environment_mut(name)?.state = StoredEnvironmentState::Stopped;
        self.save()?;
        Ok(self.environment(name)?.proto(selected))
    }

    async fn delete(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        let mut client = self.runner_client(name).await?;
        let runner = self.environment(name)?.runner.clone();
        client
            .delete()
            .await
            .map_err(|_| SupervisorError::VmDelete)?;
        drop(client);
        let mut child = self.children.remove(&environment_id);
        if let Some(runner) = runner {
            let live = self
                .live_runners
                .remove(&environment_id)
                .map(Ok)
                .unwrap_or_else(|| LiveProcess::recover(&runner.process));
            if let Ok(live) = live {
                live.signal(Signal::KILL)?;
                let exited = if let Some(mut owned_child) = child.take() {
                    matches!(
                        tokio::time::timeout(
                            RUNNER_EXIT_TIMEOUT,
                            tokio::task::spawn_blocking(move || owned_child.wait())
                        )
                        .await,
                        Ok(Ok(Ok(_)))
                    )
                } else {
                    live.wait_exited(RUNNER_EXIT_TIMEOUT).await?
                };
                if !exited {
                    return Err(SupervisorError::RunnerExitTimeout);
                }
            }
            remove_bound_socket(&self.config.runner_socket(environment_id), &runner.socket)?;
        }
        if let Some(mut child) = child {
            let _ = child.try_wait();
        }
        self.state.environments.remove(name);
        if self.state.current.as_deref() == Some(name) {
            self.state.current = self.state.environments.keys().next().cloned();
        }
        self.save()
    }

    async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state != StoredEnvironmentState::Running {
            return Err(SupervisorError::NotRunning);
        }
        let mut client = self.runner_client(name).await?;
        client
            .daemon_access()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)
    }
}

#[derive(Clone)]
struct SupervisorRpc {
    core: Arc<Mutex<SupervisorCore>>,
    shutdown: watch::Sender<bool>,
}

#[tonic::async_trait]
impl LocalSupervisorService for SupervisorRpc {
    async fn create_environment(
        &self,
        request: Request<v1::CreateEnvironmentRequest>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        validate_create(&request).map_err(Status::from)?;
        let mut core = self.core.lock().await;
        if core.state.environments.contains_key(&request.name) {
            return Err(Status::already_exists("local environment already exists"));
        }
        core.preflight().await.map_err(Status::from)?;
        let id = Uuid::new_v4();
        let source_path = PathBuf::from(&request.source_path);
        let disk_bytes = request.disk_bytes;
        let engine_root = core.config.engine_root();
        let snapshot = tokio::task::spawn_blocking(move || {
            provision_clean_git_workspace(&engine_root, id, &source_path, disk_bytes)
        })
        .await
        .map_err(|_| Status::internal("workspace provisioning task failed"))?
        .map_err(SupervisorError::from)
        .map_err(Status::from)?;
        let vcpus = u8::try_from(request.vcpus)
            .map_err(|_| Status::invalid_argument("invalid vCPU count"))?;
        core.state.environments.insert(
            request.name.clone(),
            EnvironmentRecord {
                id,
                name: request.name.clone(),
                state: StoredEnvironmentState::Stopped,
                vcpus,
                memory_mib: request.memory_mib,
                disk_bytes: request.disk_bytes,
                generation: 0,
                workspace_commit: snapshot.commit,
                source_path: snapshot.source_path,
                runner: None,
            },
        );
        core.state.current = Some(request.name.clone());
        core.save().map_err(Status::from)?;
        match core.start(&request.name).await {
            Ok(environment) => Ok(Response::new(environment)),
            Err(error) => {
                if let Ok(environment) = core.environment_mut(&request.name) {
                    environment.state = StoredEnvironmentState::Error;
                    let _ = core.save();
                }
                Err(Status::from(error))
            }
        }
    }

    async fn list_environments(
        &self,
        _request: Request<v1::ListEnvironmentsRequest>,
    ) -> Result<Response<v1::ListEnvironmentsResponse>, Status> {
        let mut core = self.core.lock().await;
        let names = core.state.environments.keys().cloned().collect::<Vec<_>>();
        for name in &names {
            core.reconcile(name).await.map_err(Status::from)?;
        }
        let environments = core
            .state
            .environments
            .iter()
            .map(|(name, environment)| environment.proto(core.selected(name)))
            .collect();
        Ok(Response::new(v1::ListEnvironmentsResponse { environments }))
    }

    async fn get_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.reconcile(&name).await.map_err(Status::from)?;
        Ok(Response::new(
            core.environment(&name)
                .map_err(Status::from)?
                .proto(core.selected(&name)),
        ))
    }

    async fn start_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.start(&name)
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn stop_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.stop(&name)
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn delete_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DeleteEnvironmentResponse>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.delete(&name).await.map_err(Status::from)?;
        let empty = core.state.environments.is_empty();
        drop(core);
        if empty {
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(RESPONSE_DRAIN_DELAY).await;
                let _ = shutdown.send(true);
            });
        }
        Ok(Response::new(v1::DeleteEnvironmentResponse {
            name,
            removed: true,
        }))
    }

    async fn get_daemon_access(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.daemon_access(&name)
            .await
            .map(Response::new)
            .map_err(Status::from)
    }
}

fn selected_name(request: v1::EnvironmentSelector) -> Result<String, Status> {
    if !valid_environment_name(&request.name) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(request.name)
}

fn validate_create(request: &v1::CreateEnvironmentRequest) -> Result<(), SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.source_path.is_empty()
        || !Path::new(&request.source_path).is_absolute()
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
    {
        return Err(SupervisorError::InvalidRequest);
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn allocate_vsock_cid(environment_id: Uuid) -> u32 {
    let bytes = environment_id.as_bytes();
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    3 + value % (u32::MAX - 4)
}

fn prepare_runtime_root(path: &Path) -> Result<PrivateRoot, SupervisorError> {
    if !path.is_absolute() {
        return Err(SupervisorError::InvalidConfiguration);
    }
    let parent = path
        .parent()
        .filter(|parent| *parent != path)
        .ok_or(SupervisorError::InvalidConfiguration)?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|source| SupervisorError::Io {
            path: parent.to_owned(),
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            SupervisorError::Io {
                path: parent.to_owned(),
                source,
            }
        })?;
    }
    let parent_root = PrivateRoot::open(parent)?;
    let root = match PrivateRoot::open(path) {
        Ok(root) => root,
        Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            let leaf = path
                .file_name()
                .map(Path::new)
                .ok_or(SupervisorError::InvalidConfiguration)?;
            parent_root.create_dir(leaf, 0o700)?;
            PrivateRoot::open(path)?
        }
        Err(error) => return Err(error.into()),
    };
    root.ensure_dir(Path::new("engine"), 0o700)?;
    root.ensure_dir(Path::new("runners"), 0o700)?;
    Ok(root)
}

fn spawn_supervisor(config: &NativeRuntimeConfig) -> Result<Child, SupervisorError> {
    let mut command = Command::new(&config.executable);
    command
        .arg("__native-supervisor")
        .arg("--root")
        .arg(&config.root)
        .arg("--artifact-root")
        .arg(&config.artifact_root)
        .arg("--artifact-lock")
        .arg(&config.artifact_lock)
        .env_clear()
        .current_dir(&config.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: scalar-only libc operations and one fixed-layout capset syscall
    // prepare a capability-empty, no-new-privileges, FD-clean detached
    // singleton before exec. The supervisor intentionally outlives this CLI.
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
    command
        .spawn()
        .map_err(|_| SupervisorError::SpawnSupervisor)
}

fn terminate_unadmitted_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = signal_unreaped_child(child.id(), Signal::KILL);
        let _ = child.wait();
    }
}

fn confine_spawned_process() -> io::Result<()> {
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

impl From<SupervisorError> for Status {
    fn from(error: SupervisorError) -> Self {
        match error {
            SupervisorError::InvalidRequest => Status::invalid_argument(error.to_string()),
            SupervisorError::NotFound(_) => Status::not_found(error.to_string()),
            SupervisorError::NotRunning => Status::failed_precondition(error.to_string()),
            SupervisorError::Workspace(workspace) => {
                Status::failed_precondition(workspace.to_string())
            }
            SupervisorError::Runner(_) => Status::failed_precondition(error.to_string()),
            SupervisorError::VmStart(_) | SupervisorError::VmStop | SupervisorError::VmDelete => {
                Status::failed_precondition(error.to_string())
            }
            _ => Status::internal("native local supervisor operation failed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("native runtime configuration is invalid")]
    InvalidConfiguration,
    #[error("native environment request is invalid")]
    InvalidRequest,
    #[error("native supervisor state is invalid")]
    InvalidState,
    #[error("native supervisor state must never contain a secret")]
    SecretInState,
    #[error("local environment {0:?} was not found")]
    NotFound(String),
    #[error("local environment is not running")]
    NotRunning,
    #[error("the native supervisor is already running")]
    AlreadyRunning,
    #[error("spawn native supervisor failed")]
    SpawnSupervisor,
    #[error("native supervisor startup timed out")]
    SupervisorStartTimeout,
    #[error("spawn native environment runner failed")]
    SpawnRunner,
    #[error("native environment runner startup timed out")]
    RunnerStartTimeout,
    #[error("native environment runner adoption failed")]
    RunnerAdoption,
    #[error("native environment runner is unavailable")]
    RunnerUnavailable,
    #[error("native environment runner did not exit")]
    RunnerExitTimeout,
    #[error("native environment runner returned invalid state")]
    InvalidRunnerResponse,
    #[error("native VM start failed: {0}")]
    VmStart(String),
    #[error("native VM stop failed")]
    VmStop,
    #[error("native VM delete failed")]
    VmDelete,
    #[error("serve native supervisor failed")]
    Serve,
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    RunnerService(#[from] RunnerServiceError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    Uds(#[from] UdsError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_names_are_single_safe_components() {
        for valid in ["dev", "dev-1", "a_b.c", "9"] {
            assert!(valid_environment_name(valid));
        }
        for invalid in ["", "-dev", "../dev", "dev/name", "two words"] {
            assert!(!valid_environment_name(invalid));
        }
    }

    #[test]
    fn supervisor_state_serialization_contains_no_secret_field() {
        let state = SupervisorState::default();
        state.validate().unwrap();
        let encoded = serde_json::to_string(&state).unwrap().to_ascii_lowercase();
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("capability"));
    }

    #[test]
    fn vsock_cid_is_stable_and_not_reserved() {
        let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        assert_eq!(allocate_vsock_cid(id), allocate_vsock_cid(id));
        assert!((3..u32::MAX).contains(&allocate_vsock_cid(id)));
    }
}
