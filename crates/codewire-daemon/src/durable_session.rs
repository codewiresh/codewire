use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io::{Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_gateway_proto::daemon::v1;
use portable_pty::{PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;
use tonic::Status;
use uuid::Uuid;

use crate::Config;
use crate::credential_bridge::CredentialBridge;
use crate::env::{build_process_env, default_shell_for};
use crate::execution::{PreparedProcess, ProcessExecution};

const SESSION_DIRECTORY: &str = ".codewire/daemon/sessions";
const METADATA_FILE: &str = "session.json";
const METADATA_TEMP_FILE: &str = ".session.json.tmp";
const OUTPUT_FILE: &str = "output.bin";
const OUTPUT_TEMP_FILE: &str = ".output.bin.tmp";
const OUTPUT_BUFFER_SIZE: usize = 32 * 1024;
const OUTPUT_FRAME_HEADER_SIZE: usize = 17;
const DEFAULT_OUTPUT_READ_LIMIT: u64 = 256 * 1024;
const MAX_OUTPUT_READ_LIMIT: u64 = 4 * 1024 * 1024;
const LAUNCH_OPERATION_TIMEOUT: Duration = Duration::from_secs(40);
const LAUNCH_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const LAUNCH_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
// Compact at twice the retained byte/frame budget, amortizing disk rewrites.
const RETAINED_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const RETAINED_OUTPUT_FRAMES: usize = 2048;
const MAX_SESSION_RECORDS: usize = 128;
const RETIRED_SESSION_PREFIX: &str = ".retired-";

#[derive(Clone)]
pub struct SessionEngine {
    inner: Arc<SessionEngineInner>,
}

impl std::fmt::Debug for SessionEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionEngine")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

struct SessionEngineInner {
    config: Config,
    credential_bridge: CredentialBridge,
    root: PathBuf,
    initialized: OnceCell<Result<(), String>>,
    sessions: Mutex<BTreeMap<String, Arc<SessionHandle>>>,
    active: Mutex<HashMap<String, ActiveSession>>,
    retention_admission: AsyncMutex<()>,
    launch_admission: Mutex<()>,
    launches: TaskTracker,
    shutdown: CancellationToken,
}

struct SessionHandle {
    metadata: AsyncMutex<PersistedSession>,
    output_index: Mutex<Vec<OutputFrameIndex>>,
    operation: AsyncMutex<()>,
    launch_cancellation: watch::Sender<bool>,
}

#[derive(Clone, Debug)]
struct OutputFrameIndex {
    offset: u64,
    physical_data_offset: u64,
    length: u64,
    stream: v1::SessionOutputStream,
}

struct ActiveSession {
    token: Uuid,
    control: mpsc::Sender<SessionControl>,
    task: JoinHandle<()>,
}

enum SessionControl {
    Stop {
        reply: oneshot::Sender<()>,
    },
    Input {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Resize {
        width: i32,
        height: i32,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

enum ProcessCompletion {
    Exited(Result<i32, String>),
    Stopped {
        result: Result<(), String>,
        reply: oneshot::Sender<()>,
    },
}

struct ProcessMonitor {
    inner: Weak<SessionEngineInner>,
    session_id: String,
    token: Uuid,
    handle: Arc<SessionHandle>,
    child: Child,
    stdin: Option<ChildStdin>,
    control: mpsc::Receiver<SessionControl>,
    stdout_task: JoinHandle<Result<(), SessionError>>,
    stderr_task: JoinHandle<Result<(), SessionError>>,
}

struct PtyProcessMonitor {
    inner: Weak<SessionEngineInner>,
    session_id: String,
    token: Uuid,
    handle: Arc<SessionHandle>,
    killer: PtyKillerGuard,
    wait_task: JoinHandle<Result<i32, String>>,
    control: mpsc::Receiver<SessionControl>,
    pty_control: std_mpsc::Sender<PtyRuntimeControl>,
    control_thread: std::thread::JoinHandle<()>,
    output_task: JoinHandle<Result<(), SessionError>>,
}

struct PtyKillerGuard {
    killer: Option<Box<dyn portable_pty::ChildKiller + Send + Sync>>,
}

impl PtyKillerGuard {
    fn new(killer: Box<dyn portable_pty::ChildKiller + Send + Sync>) -> Self {
        Self {
            killer: Some(killer),
        }
    }

    fn take(&mut self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        self.killer.take().expect("session PTY killer is armed")
    }

    fn disarm(&mut self) {
        self.killer = None;
    }
}

impl Drop for PtyKillerGuard {
    fn drop(&mut self) {
        if let Some(killer) = self.killer.as_mut() {
            let _ = killer.kill();
        }
    }
}

enum PtyRuntimeControl {
    Input {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Resize {
        width: i32,
        height: i32,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedSession {
    session_id: String,
    state: i32,
    command: Vec<String>,
    working_dir: String,
    env: Vec<String>,
    pty: bool,
    term: String,
    width: i32,
    height: i32,
    created_at: PersistedTimestamp,
    started_at: Option<PersistedTimestamp>,
    finished_at: Option<PersistedTimestamp>,
    exit_code: Option<i32>,
    output_end_offset: u64,
    #[serde(default)]
    output_start_offset: u64,
    // Only failures before any process was spawned are automatically safe to
    // retire. Older/ambiguous failures keep their cleanup obligation.
    #[serde(default)]
    cleanup_confirmed: bool,
    // An interrupted launch may still own a child; preserve this recovery fence.
    #[serde(default)]
    cleanup_unknown: bool,
    status_message: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PersistedTimestamp {
    seconds: i64,
    nanos: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    FailedPrecondition(String),
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("{0}")]
    Internal(String),
}

impl SessionEngine {
    /// Test-only transcript preparation through the real append/compaction
    /// path. Fixed capture-size frames separate Attach control assertions from
    /// platform-dependent PTY read fragmentation and fsync throughput.
    #[cfg(test)]
    pub(crate) async fn append_test_output(
        &self,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), SessionError> {
        self.ensure_initialized().await?;
        let handle = self.handle(session_id)?;
        for frame in data.chunks(OUTPUT_BUFFER_SIZE) {
            append_output(
                &self.inner.root,
                &handle,
                v1::SessionOutputStream::Pty,
                frame,
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) fn new(config: &Config, credential_bridge: CredentialBridge) -> Self {
        Self {
            inner: Arc::new(SessionEngineInner {
                config: config.clone(),
                credential_bridge,
                root: config.home_root.join(SESSION_DIRECTORY),
                initialized: OnceCell::new(),
                sessions: Mutex::new(BTreeMap::new()),
                active: Mutex::new(HashMap::new()),
                retention_admission: AsyncMutex::new(()),
                launch_admission: Mutex::new(()),
                launches: TaskTracker::new(),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    pub async fn launch(
        &self,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, SessionError> {
        let engine = self.clone();
        self.own_launch(move |cancel| async move { engine.launch_inner(request, cancel).await })
            .await
    }

    pub(crate) fn cancel_on_drop(&self) -> DropGuard {
        self.inner.shutdown.clone().drop_guard()
    }

    pub(crate) fn cancel_launches(&self) {
        let _admission = lock(&self.inner.launch_admission);
        self.inner.shutdown.cancel();
        self.inner.launches.close();
    }

    pub(crate) async fn shutdown(&self) -> Result<(), SessionError> {
        self.cancel_launches();
        let deadline = tokio::time::Instant::now() + LAUNCH_SHUTDOWN_TIMEOUT;
        tokio::time::timeout_at(deadline, self.inner.launches.wait())
            .await
            .map_err(|_| SessionError::Internal("session launch cleanup did not settle".into()))?;
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            let metadata = tokio::time::timeout_at(deadline, handle.metadata.lock())
                .await
                .map_err(|_| {
                    SessionError::Internal("session launch cleanup did not settle".into())
                })?;
            if metadata.cleanup_unknown {
                return Err(SessionError::Internal(
                    "session launch cleanup remains unconfirmed".into(),
                ));
            }
        }
        Ok(())
    }

    async fn own_launch<F, Fut>(&self, operation: F) -> Result<v1::SessionRecord, SessionError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<v1::SessionRecord, SessionError>> + Send + 'static,
    {
        let (task, guard) = {
            let _admission = lock(&self.inner.launch_admission);
            if self.inner.shutdown.is_cancelled() {
                return Err(launch_cancelled_error());
            }
            let cancel = self.inner.shutdown.child_token();
            let guard = cancel.clone().drop_guard();
            let operation = operation(cancel.clone());
            let task = self.inner.launches.spawn(async move {
                tokio::pin!(operation);
                tokio::select! {
                    result = &mut operation => result,
                    _ = tokio::time::sleep(LAUNCH_OPERATION_TIMEOUT) => {
                        // Cooperative cancellation retains the operation lock and
                        // exact child until cleanup/persistence has completed.
                        cancel.cancel();
                        operation.await
                    }
                }
            });
            (task, guard)
        };
        let result = task.await.map_err(|_| {
            SessionError::Internal("session launch outcome could not be confirmed".into())
        });
        guard.disarm();
        result?
    }

    async fn launch_inner(
        &self,
        request: v1::LaunchSessionRequest,
        cancel: CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        let command = if request.command.is_empty() {
            vec![default_shell_for(&self.inner.config)]
        } else {
            request.command
        };
        if command[0].trim().is_empty() {
            return Err(SessionError::InvalidArgument(
                "session command executable is empty".into(),
            ));
        }
        let working_dir = if request.working_dir.trim().is_empty() {
            self.inner.config.home_root.to_string_lossy().into_owned()
        } else {
            request.working_dir
        };
        if matches!(
            &self.inner.config.process_execution,
            ProcessExecution::Native
        ) && !path_is_directory(&working_dir).await
        {
            return Err(SessionError::InvalidArgument(format!(
                "session working directory does not exist: {working_dir}"
            )));
        }

        let admission = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            admission = self.inner.retention_admission.lock() => admission,
        };
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        self.make_record_room().await?;
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        let session_id = self.create_session_id().await?;
        let persisted = PersistedSession {
            session_id: session_id.clone(),
            state: v1::SessionLifecycleState::Starting as i32,
            command,
            working_dir,
            env: request.env,
            pty: request.pty,
            term: request.term,
            width: request.width,
            height: request.height,
            created_at: PersistedTimestamp::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            cleanup_confirmed: false,
            cleanup_unknown: true,
            status_message: "session starting".into(),
        };
        let handle = Arc::new(SessionHandle {
            metadata: AsyncMutex::new(persisted),
            output_index: Mutex::new(Vec::new()),
            operation: AsyncMutex::new(()),
            launch_cancellation: watch::channel(false).0,
        });
        let _operation = handle.operation.lock().await;
        {
            let metadata = handle.metadata.lock().await;
            persist_metadata(&self.inner.root, &metadata).await?;
        }
        lock(&self.inner.sessions).insert(session_id, handle.clone());
        drop(admission);
        self.start_process(handle.clone(), &cancel).await
    }

    async fn make_record_room(&self) -> Result<(), SessionError> {
        drain_retired_records(&self.inner.root).await?;
        prune_session_records(&self.inner, MAX_SESSION_RECORDS - 1, true).await
    }

    pub async fn list(&self) -> Result<Vec<v1::SessionRecord>, SessionError> {
        self.ensure_initialized().await?;
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut sessions = Vec::with_capacity(handles.len());
        for handle in handles {
            sessions.push(handle.metadata.lock().await.to_record());
        }
        sessions.sort_by(|left, right| {
            timestamp_key(left.created_at.as_ref())
                .cmp(&timestamp_key(right.created_at.as_ref()))
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        Ok(sessions)
    }

    pub async fn get(&self, session_id: &str) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        Ok(self.handle(session_id)?.metadata.lock().await.to_record())
    }

    pub async fn stop(&self, session_id: &str) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        validate_session_id(session_id)?;
        let handle = self.handle(session_id)?;
        // Interrupt a pending projection before waiting for the serial session
        // operation lock. A queued Stop must not wait for secret delivery.
        handle.launch_cancellation.send_replace(true);
        let _operation = handle.operation.lock().await;
        self.stop_active(session_id, &handle).await
    }

    async fn stop_active(
        &self,
        session_id: &str,
        handle: &SessionHandle,
    ) -> Result<v1::SessionRecord, SessionError> {
        let control = lock(&self.inner.active)
            .get(session_id)
            .map(|active| active.control.clone());

        if let Some(control) = control {
            let (reply_tx, reply_rx) = oneshot::channel();
            if control
                .send(SessionControl::Stop { reply: reply_tx })
                .await
                .is_ok()
            {
                let _ = reply_rx.await;
            }
        }

        let record = handle.metadata.lock().await.to_record();
        let state = lifecycle_state(record.state);
        if matches!(
            state,
            v1::SessionLifecycleState::Starting
                | v1::SessionLifecycleState::Running
                | v1::SessionLifecycleState::Stopping
        ) {
            return Err(SessionError::FailedPrecondition(format!(
                "session {session_id} has no controllable process"
            )));
        }
        Ok(record)
    }

    pub async fn restart(&self, session_id: &str) -> Result<v1::SessionRecord, SessionError> {
        let engine = self.clone();
        let session_id = session_id.to_string();
        self.own_launch(
            move |cancel| async move { engine.restart_inner(&session_id, cancel).await },
        )
        .await
    }

    async fn restart_inner(
        &self,
        session_id: &str,
        cancel: CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        let admission = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            admission = self.inner.retention_admission.lock() => admission,
        };
        validate_session_id(session_id)?;
        let handle = self.handle(session_id)?;
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        handle.launch_cancellation.send_replace(true);
        let _operation = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            operation = handle.operation.lock() => operation,
        };
        if handle.metadata.lock().await.cleanup_unknown {
            return Err(SessionError::FailedPrecondition(
                "session launch cleanup is unconfirmed; restart is unavailable".into(),
            ));
        }
        if lock(&self.inner.active).contains_key(session_id) {
            // Once Stop is dispatched, retain the operation lock until the
            // previous monitor settles. Caller loss cannot cancel its cleanup.
            self.stop_active(session_id, &handle).await?;
        }
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        handle.launch_cancellation.send_replace(false);

        {
            let mut metadata = handle.metadata.lock().await;
            metadata.state = v1::SessionLifecycleState::Starting as i32;
            metadata.started_at = None;
            metadata.finished_at = None;
            metadata.exit_code = None;
            metadata.status_message = "session restarting".into();
            metadata.cleanup_unknown = true;
            metadata.cleanup_confirmed = false;
            persist_metadata(&self.inner.root, &metadata).await?;
        }
        drop(admission);
        self.start_process(handle.clone(), &cancel).await
    }

    pub async fn read_output(
        &self,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, SessionError> {
        self.ensure_initialized().await?;
        let handle = self.handle(&request.session_id)?;
        let output = read_output(&self.inner.root, &handle, request.offset, request.limit).await?;
        if output.history_gap && !request.allow_history_gap {
            return Err(SessionError::FailedPrecondition(format!(
                "older terminal output is unavailable; retained history starts at {}; opt in to history gaps or resume from that cursor",
                output.retained_start_offset,
            )));
        }
        Ok(output)
    }

    pub async fn input(&self, session_id: &str, data: Vec<u8>) -> Result<(), SessionError> {
        self.ensure_initialized().await?;
        validate_session_id(session_id)?;
        if data.is_empty() {
            return Ok(());
        }
        let control = lock(&self.inner.active)
            .get(session_id)
            .map(|active| active.control.clone())
            .ok_or_else(|| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} is not accepting input"
                ))
            })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        control
            .send(SessionControl::Input {
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} is not accepting input"
                ))
            })?;
        reply_rx
            .await
            .map_err(|_| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} stopped while accepting input"
                ))
            })?
            .map_err(SessionError::FailedPrecondition)
    }

    pub async fn resize(
        &self,
        session_id: &str,
        width: i32,
        height: i32,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        validate_session_id(session_id)?;
        if width <= 0 || height <= 0 {
            return Err(SessionError::InvalidArgument(
                "session resize width and height must be positive".into(),
            ));
        }
        let handle = self.handle(session_id)?;
        let _operation = handle.operation.lock().await;
        if !handle.metadata.lock().await.pty {
            return Err(SessionError::FailedPrecondition(format!(
                "session {session_id} is not a PTY session"
            )));
        }
        let control = lock(&self.inner.active)
            .get(session_id)
            .map(|active| active.control.clone())
            .ok_or_else(|| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} is not accepting resize requests"
                ))
            })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        control
            .send(SessionControl::Resize {
                width,
                height,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} is not accepting resize requests"
                ))
            })?;
        reply_rx
            .await
            .map_err(|_| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} stopped while resizing"
                ))
            })?
            .map_err(SessionError::FailedPrecondition)?;

        let mut metadata = handle.metadata.lock().await;
        metadata.width = width;
        metadata.height = height;
        metadata.status_message = format!("session resized to {width}x{height}");
        persist_metadata(&self.inner.root, &metadata).await?;
        Ok(metadata.to_record())
    }

    async fn ensure_initialized(&self) -> Result<(), SessionError> {
        let result = self
            .inner
            .initialized
            .get_or_init(|| async {
                self.inner
                    .initialize()
                    .await
                    .map_err(|error| error.to_string())
            })
            .await;
        result.clone().map_err(SessionError::Internal)
    }

    async fn create_session_id(&self) -> Result<String, SessionError> {
        for _ in 0..4 {
            let session_id = format!("session-{}", Uuid::new_v4());
            let directory = session_directory(&self.inner.root, &session_id)?;
            match tokio::fs::create_dir(&directory).await {
                Ok(()) => {
                    set_private_directory_permissions(&directory).await?;
                    let output_path = directory.join(OUTPUT_FILE);
                    let file = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&output_path)
                        .await
                        .map_err(|error| {
                            SessionError::Internal(format!(
                                "create session output {}: {error}",
                                output_path.display()
                            ))
                        })?;
                    file.sync_all().await.map_err(|error| {
                        SessionError::Internal(format!(
                            "sync session output {}: {error}",
                            output_path.display()
                        ))
                    })?;
                    set_private_file_permissions(&output_path).await?;
                    return Ok(session_id);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(SessionError::Internal(format!(
                        "create session directory {}: {error}",
                        directory.display()
                    )));
                }
            }
        }
        Err(SessionError::Internal(
            "could not allocate a unique session identifier".into(),
        ))
    }

    fn handle(&self, session_id: &str) -> Result<Arc<SessionHandle>, SessionError> {
        validate_session_id(session_id)?;
        lock(&self.inner.sessions)
            .get(session_id)
            .cloned()
            .ok_or_else(|| SessionError::NotFound(format!("session not found: {session_id}")))
    }

    async fn start_process(
        &self,
        handle: Arc<SessionHandle>,
        cancel: &CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        if launch_is_cancelled(&handle, cancel) {
            return self
                .record_unspawned_failure(handle, "session launch cancelled".into())
                .await;
        }
        let snapshot = handle.metadata.lock().await.clone();
        if snapshot.pty {
            return self.start_pty_process(handle, snapshot, cancel).await;
        }
        let command = &snapshot.command;
        let environment = match build_process_env(&self.inner.config, &snapshot.env, &snapshot.term)
        {
            Ok(environment) => environment,
            Err(error) => {
                return self
                    .record_unspawned_failure(
                        handle,
                        format!("prepare session environment: {error}"),
                    )
                    .await;
            }
        };
        let mut prepared = match PreparedProcess::prepare_configured(
            (&self.inner.config, &self.inner.credential_bridge),
            command,
            &snapshot.working_dir,
            &environment,
            false,
            0,
            0,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return self
                    .record_unspawned_failure(handle, format!("prepare session process: {error}"))
                    .await;
            }
        };
        let mut process = prepared.tokio_command();

        if launch_is_cancelled(&handle, cancel) {
            return self
                .record_unspawned_failure(handle, "session launch cancelled".into())
                .await;
        }

        let mut child = match process.spawn() {
            Ok(child) => {
                prepared.spawned();
                child
            }
            Err(error) => {
                return self
                    .record_unspawned_failure(handle, format!("launch session process: {error}"))
                    .await;
            }
        };
        let projection = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(std::io::Error::other("environment launch cancelled")),
            _ = wait_for_launch_cancellation(&handle) => Err(std::io::Error::other("environment launch cancelled")),
            result = prepared.project_spawned(child.id()) => result,
        };
        if projection.is_err() {
            let confirmed = terminate_native_launch(&mut child).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "environment launch denied or expired".into(),
                )
                .await;
        }
        let Some(stdin) = child.stdin.take() else {
            let confirmed = terminate_native_launch(&mut child).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session stdin pipe is unavailable".into(),
                )
                .await;
        };
        let Some(stdout) = child.stdout.take() else {
            let confirmed = terminate_native_launch(&mut child).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session stdout pipe is unavailable".into(),
                )
                .await;
        };
        let Some(stderr) = child.stderr.take() else {
            let confirmed = terminate_native_launch(&mut child).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session stderr pipe is unavailable".into(),
                )
                .await;
        };

        let running = self.record_starting_running(&handle).await;
        if running.is_err() || launch_is_cancelled(&handle, cancel) {
            let confirmed = terminate_native_launch(&mut child).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session launch cancelled or could not be recorded".into(),
                )
                .await;
        }
        let record = running?;

        // Ownership transfers below without an intervening await.
        let monitor_handle = handle.clone();

        let stdout_task = tokio::spawn(capture_output(
            self.inner.root.clone(),
            handle.clone(),
            v1::SessionOutputStream::Stdout,
            stdout,
        ));
        let stderr_task = tokio::spawn(capture_output(
            self.inner.root.clone(),
            handle.clone(),
            v1::SessionOutputStream::Stderr,
            stderr,
        ));
        let (control_tx, control_rx) = mpsc::channel(32);
        let (start_tx, start_rx) = oneshot::channel();
        let token = Uuid::new_v4();
        let inner = Arc::downgrade(&self.inner);
        let session_id = snapshot.session_id.clone();
        let task = tokio::spawn(async move {
            let _ = start_rx.await;
            monitor_process(ProcessMonitor {
                inner,
                session_id,
                token,
                handle: monitor_handle,
                child,
                stdin: Some(stdin),
                control: control_rx,
                stdout_task,
                stderr_task,
            })
            .await;
        });
        lock(&self.inner.active).insert(
            snapshot.session_id,
            ActiveSession {
                token,
                control: control_tx,
                task,
            },
        );
        self.complete_handoff(handle, start_tx, record).await
    }

    async fn start_pty_process(
        &self,
        handle: Arc<SessionHandle>,
        snapshot: PersistedSession,
        cancel: &CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        let environment = match build_process_env(&self.inner.config, &snapshot.env, &snapshot.term)
        {
            Ok(environment) => environment,
            Err(error) => {
                return self
                    .record_unspawned_failure(
                        handle,
                        format!("prepare session PTY environment: {error}"),
                    )
                    .await;
            }
        };
        let size = pty_size(snapshot.width, snapshot.height);
        let pair = match native_pty_system().openpty(size) {
            Ok(pair) => pair,
            Err(error) => {
                return self
                    .record_unspawned_failure(handle, format!("open session PTY: {error}"))
                    .await;
            }
        };

        let mut prepared = match PreparedProcess::prepare_configured(
            (&self.inner.config, &self.inner.credential_bridge),
            &snapshot.command,
            &snapshot.working_dir,
            &environment,
            true,
            size.cols,
            size.rows,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return self
                    .record_unspawned_failure(
                        handle,
                        format!("prepare session PTY process: {error}"),
                    )
                    .await;
            }
        };
        let command = prepared.pty_command();

        if launch_is_cancelled(&handle, cancel) {
            return self
                .record_unspawned_failure(handle, "session launch cancelled".into())
                .await;
        }

        let child = match pair.slave.spawn_command(command) {
            Ok(child) => {
                prepared.spawned();
                child
            }
            Err(error) => {
                return self
                    .record_unspawned_failure(
                        handle,
                        format!("launch session PTY process: {error}"),
                    )
                    .await;
            }
        };
        drop(pair.slave);

        let mut child = crate::execution::PtyLaunchGuard::new(child);
        let projection = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(std::io::Error::other("environment launch cancelled")),
            _ = wait_for_launch_cancellation(&handle) => Err(std::io::Error::other("environment launch cancelled")),
            result = prepared.project_spawned(child.process_id()) => result,
        };
        if projection.is_err() {
            let confirmed = child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "environment launch denied or expired".into(),
                )
                .await;
        }

        let reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(error) => {
                let confirmed = child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await;
                return self
                    .record_launch_cleanup(
                        handle,
                        confirmed,
                        format!("clone session PTY reader: {error}"),
                    )
                    .await;
            }
        };
        let writer = match pair.master.take_writer() {
            Ok(writer) => writer,
            Err(error) => {
                let confirmed = child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await;
                return self
                    .record_launch_cleanup(
                        handle,
                        confirmed,
                        format!("take session PTY writer: {error}"),
                    )
                    .await;
            }
        };

        let running = self.record_starting_running(&handle).await;
        if running.is_err() || launch_is_cancelled(&handle, cancel) {
            let confirmed = child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session launch cancelled or could not be recorded".into(),
                )
                .await;
        }
        let record = running?;
        let monitor_handle = handle.clone();

        let (output_tx, output_rx) = mpsc::channel(32);
        let reader_thread = tokio::task::spawn_blocking(move || copy_pty_output(reader, output_tx));
        let output_task = tokio::spawn(capture_pty_output(
            self.inner.root.clone(),
            handle.clone(),
            output_rx,
            reader_thread,
        ));
        let child = child.release();
        let killer = child.clone_killer();
        let wait_task = tokio::task::spawn_blocking(move || {
            let mut child = child;
            child
                .wait()
                .map(|status| status.exit_code() as i32)
                .map_err(|error| format!("wait for session PTY process: {error}"))
        });
        let (pty_control_tx, pty_control_rx) = std_mpsc::channel();
        let master = pair.master;
        let control_thread =
            std::thread::spawn(move || pty_control_loop(master, writer, pty_control_rx));

        let (control_tx, control_rx) = mpsc::channel(32);
        let (start_tx, start_rx) = oneshot::channel();
        let token = Uuid::new_v4();
        let inner = Arc::downgrade(&self.inner);
        let session_id = snapshot.session_id.clone();
        let task = tokio::spawn(async move {
            let _ = start_rx.await;
            monitor_pty_process(PtyProcessMonitor {
                inner,
                session_id,
                token,
                handle: monitor_handle,
                killer: PtyKillerGuard::new(killer),
                wait_task,
                control: control_rx,
                pty_control: pty_control_tx,
                control_thread,
                output_task,
            })
            .await;
        });
        lock(&self.inner.active).insert(
            snapshot.session_id,
            ActiveSession {
                token,
                control: control_tx,
                task,
            },
        );
        self.complete_handoff(handle, start_tx, record).await
    }

    async fn record_starting_running(
        &self,
        handle: &SessionHandle,
    ) -> Result<v1::SessionRecord, SessionError> {
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Running as i32;
        metadata.started_at = Some(PersistedTimestamp::now());
        metadata.finished_at = None;
        metadata.exit_code = None;
        metadata.status_message = "session running".into();
        persist_metadata(&self.inner.root, &metadata).await?;
        Ok(metadata.to_record())
    }

    async fn complete_handoff(
        &self,
        handle: Arc<SessionHandle>,
        start: oneshot::Sender<()>,
        record: v1::SessionRecord,
    ) -> Result<v1::SessionRecord, SessionError> {
        // The active monitor now owns the child. Caller loss must not stop it.
        let result = {
            let mut metadata = handle.metadata.lock().await;
            metadata.cleanup_unknown = false;
            metadata.cleanup_confirmed = false;
            persist_metadata(&self.inner.root, &metadata).await
        };
        let _ = start.send(());
        result?;
        Ok(record)
    }

    async fn record_launch_cleanup(
        &self,
        handle: Arc<SessionHandle>,
        confirmed: bool,
        message: String,
    ) -> Result<v1::SessionRecord, SessionError> {
        if confirmed {
            return self.record_unspawned_failure(handle, message).await;
        }
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Interrupted as i32;
        metadata.cleanup_unknown = true;
        metadata.cleanup_confirmed = false;
        metadata.finished_at = Some(PersistedTimestamp::now());
        metadata.exit_code = None;
        metadata.status_message =
            "session launch cleanup could not be confirmed; restart is unavailable".into();
        persist_metadata(&self.inner.root, &metadata).await?;
        Ok(metadata.to_record())
    }

    async fn record_unspawned_failure(
        &self,
        handle: Arc<SessionHandle>,
        message: String,
    ) -> Result<v1::SessionRecord, SessionError> {
        handle.metadata.lock().await.cleanup_confirmed = true;
        self.record_startup_failure(handle, message).await
    }

    async fn record_startup_failure(
        &self,
        handle: Arc<SessionHandle>,
        message: String,
    ) -> Result<v1::SessionRecord, SessionError> {
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Failed as i32;
        metadata.cleanup_unknown = false;
        metadata.started_at = None;
        metadata.finished_at = Some(PersistedTimestamp::now());
        metadata.exit_code = None;
        metadata.status_message = message;
        persist_metadata(&self.inner.root, &metadata).await?;
        Ok(metadata.to_record())
    }
}

impl SessionEngineInner {
    async fn initialize(&self) -> Result<(), SessionError> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|error| {
                SessionError::Internal(format!(
                    "create session store {}: {error}",
                    self.root.display()
                ))
            })?;
        set_private_directory_permissions(&self.root).await?;
        drain_retired_records(&self.root).await?;

        let mut entries = tokio::fs::read_dir(&self.root).await.map_err(|error| {
            SessionError::Internal(format!(
                "read session store {}: {error}",
                self.root.display()
            ))
        })?;
        let mut loaded = BTreeMap::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            SessionError::Internal(format!(
                "read session store entry {}: {error}",
                self.root.display()
            ))
        })? {
            if !entry
                .file_type()
                .await
                .map_err(|error| {
                    SessionError::Internal(format!(
                        "read session entry type {}: {error}",
                        entry.path().display()
                    ))
                })?
                .is_dir()
            {
                continue;
            }
            let session_id = entry.file_name().to_string_lossy().into_owned();
            if let Some(retired_id) = session_id.strip_prefix(RETIRED_SESSION_PREFIX) {
                validate_session_id(retired_id)?;
                tokio::fs::remove_dir_all(entry.path())
                    .await
                    .map_err(|error| {
                        SessionError::Internal(format!("clean retired session record: {error}"))
                    })?;
                continue;
            }
            validate_session_id(&session_id)?;
            let path = entry.path().join(METADATA_FILE);
            let bytes = tokio::fs::read(&path).await.map_err(|error| {
                SessionError::Internal(format!("read session metadata {}: {error}", path.display()))
            })?;
            let mut metadata =
                serde_json::from_slice::<PersistedSession>(&bytes).map_err(|error| {
                    SessionError::Internal(format!(
                        "decode session metadata {}: {error}",
                        path.display()
                    ))
                })?;
            if metadata.session_id != session_id {
                return Err(SessionError::Internal(format!(
                    "session metadata identity mismatch in {}",
                    path.display()
                )));
            }
            let (mut metadata_changed, output_index) =
                reconcile_output_cursor(&self.root, &mut metadata).await?;
            if is_live_state(metadata.state) {
                metadata.state = v1::SessionLifecycleState::Interrupted as i32;
                metadata.finished_at = Some(PersistedTimestamp::now());
                metadata.exit_code = None;
                metadata.status_message =
                    "session interrupted because the environment daemon restarted".into();
                metadata_changed = true;
            }
            if metadata_changed {
                persist_metadata(&self.root, &metadata).await?;
            }
            let handle = Arc::new(SessionHandle {
                metadata: AsyncMutex::new(metadata),
                output_index: Mutex::new(output_index),
                operation: AsyncMutex::new(()),
                launch_cancellation: watch::channel(false).0,
            });
            compact_output(&self.root, &handle, &mut *handle.metadata.lock().await).await?;
            loaded.insert(session_id, handle);
        }
        *lock(&self.sessions) = loaded;
        // Grandfather unresolved records from older unbounded stores rather
        // than deleting a possible live process's recovery obligation. New
        // admission remains blocked until enough safe records are available.
        prune_session_records(self, MAX_SESSION_RECORDS, false).await
    }
}

impl Drop for SessionEngineInner {
    fn drop(&mut self) {
        let active = match self.active.get_mut() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (_, active) in active.drain() {
            active.task.abort();
        }
    }
}

async fn drain_retired_records(root: &Path) -> Result<(), SessionError> {
    let mut entries = tokio::fs::read_dir(root).await.map_err(|error| {
        SessionError::Internal(format!("read retired session records: {error}"))
    })?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| SessionError::Internal(format!("read retired session entry: {error}")))?
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(session_id) = name.strip_prefix(RETIRED_SESSION_PREFIX) {
            validate_session_id(session_id)?;
            tokio::fs::remove_dir_all(entry.path())
                .await
                .map_err(|error| {
                    SessionError::Internal(format!("remove retired session record: {error}"))
                })?;
        }
    }
    Ok(())
}

async fn prune_session_records(
    inner: &SessionEngineInner,
    maximum: usize,
    require_room: bool,
) -> Result<(), SessionError> {
    let handles = lock(&inner.sessions).values().cloned().collect::<Vec<_>>();
    let needed = handles.len().saturating_sub(maximum);
    if needed == 0 {
        return Ok(());
    }
    let mut candidates = Vec::new();
    for handle in handles {
        let metadata = handle.metadata.lock().await;
        let state = lifecycle_state(metadata.state);
        if (matches!(
            state,
            v1::SessionLifecycleState::Exited | v1::SessionLifecycleState::Stopped
        ) || (state == v1::SessionLifecycleState::Failed && metadata.cleanup_confirmed))
            && !metadata.cleanup_unknown
            && !lock(&inner.active).contains_key(&metadata.session_id)
        {
            candidates.push((
                timestamp_key(metadata.finished_at.map(Into::into).as_ref()),
                metadata.session_id.clone(),
                handle.clone(),
            ));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    if require_room && candidates.len() < needed {
        return Err(SessionError::ResourceExhausted(
            "terminal session limit reached; live or unresolved sessions cannot be removed automatically".into(),
        ));
    }
    for (_, session_id, handle) in candidates.into_iter().take(needed) {
        let _operation = handle.operation.lock().await;
        let path = session_directory(&inner.root, &session_id)?;
        let retired = inner
            .root
            .join(format!("{RETIRED_SESSION_PREFIX}{session_id}"));
        // Admission and restart share the retention lock. Retire atomically
        // before deleting files so incomplete cleanup is never a visible record.
        tokio::fs::rename(&path, &retired).await.map_err(|error| {
            SessionError::Internal(format!("retire expired session record: {error}"))
        })?;
        lock(&inner.sessions).remove(&session_id);
        tokio::fs::remove_dir_all(&retired).await.map_err(|error| {
            SessionError::Internal(format!("remove retired session record: {error}"))
        })?;
    }
    Ok(())
}

async fn wait_for_launch_cancellation(handle: &SessionHandle) {
    let mut cancellation = handle.launch_cancellation.subscribe();
    let _ = cancellation.wait_for(|cancelled| *cancelled).await;
}

fn launch_cancelled_error() -> SessionError {
    SessionError::FailedPrecondition("session launch cancelled before completion".into())
}

fn launch_is_cancelled(handle: &SessionHandle, cancel: &CancellationToken) -> bool {
    cancel.is_cancelled() || *handle.launch_cancellation.borrow()
}

async fn terminate_native_launch(child: &mut Child) -> bool {
    let _ = child.start_kill();
    let deadline = tokio::time::Instant::now() + LAUNCH_CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) if tokio::time::Instant::now() >= deadline => return false,
            Ok(None) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

async fn monitor_process(monitor: ProcessMonitor) {
    let ProcessMonitor {
        inner,
        session_id,
        token,
        handle,
        mut child,
        mut stdin,
        mut control,
        stdout_task,
        stderr_task,
    } = monitor;
    let completion = loop {
        tokio::select! {
            result = child.wait() => {
                break ProcessCompletion::Exited(
                    result
                        .map(|status| status.code().unwrap_or(1))
                        .map_err(|error| format!("wait for session process: {error}"))
                );
            }
            command = control.recv() => match command {
                Some(SessionControl::Stop { reply }) => {
                    if let Some(inner) = inner.upgrade() {
                        let mut metadata = handle.metadata.lock().await;
                        metadata.state = v1::SessionLifecycleState::Stopping as i32;
                        metadata.status_message = "session stopping".into();
                        let _ = persist_metadata(&inner.root, &metadata).await;
                    }
                    break ProcessCompletion::Stopped {
                        result: child
                            .kill()
                            .await
                            .map_err(|error| format!("stop session process: {error}")),
                        reply,
                    };
                }
                Some(SessionControl::Input { data, reply }) => {
                    let result = match stdin.as_mut() {
                        Some(stdin) => stdin
                            .write_all(&data)
                            .await
                            .map_err(|error| format!("write session input: {error}")),
                        None => Err("session stdin is closed".into()),
                    };
                    let _ = reply.send(result);
                }
                Some(SessionControl::Resize { reply, .. }) => {
                    let _ = reply.send(Err("session is not a PTY session".into()));
                }
                None => {
                    break ProcessCompletion::Exited(
                        child
                            .wait()
                            .await
                            .map(|status| status.code().unwrap_or(1))
                            .map_err(|error| format!("wait for session process: {error}"))
                    );
                }
            },
        }
    };

    let output_error = join_output_tasks(stdout_task, stderr_task).await;
    finish_process(inner, session_id, token, handle, completion, output_error).await;
}

async fn monitor_pty_process(monitor: PtyProcessMonitor) {
    let PtyProcessMonitor {
        inner,
        session_id,
        token,
        handle,
        mut killer,
        mut wait_task,
        mut control,
        pty_control,
        control_thread,
        output_task,
    } = monitor;
    let completion = loop {
        tokio::select! {
            result = &mut wait_task => {
                killer.disarm();
                break ProcessCompletion::Exited(
                    result.unwrap_or_else(|error| {
                        Err(format!("join session PTY wait task: {error}"))
                    })
                );
            }
            command = control.recv() => match command {
                Some(SessionControl::Stop { reply }) => {
                    if let Some(inner) = inner.upgrade() {
                        let mut metadata = handle.metadata.lock().await;
                        metadata.state = v1::SessionLifecycleState::Stopping as i32;
                        metadata.status_message = "session stopping".into();
                        let _ = persist_metadata(&inner.root, &metadata).await;
                    }
                    let mut process_killer = killer.take();
                    let result = tokio::task::spawn_blocking(move || {
                        process_killer
                            .kill()
                            .map_err(|error| format!("stop session PTY process: {error}"))
                    })
                    .await
                    .unwrap_or_else(|error| {
                        Err(format!("join session PTY stop task: {error}"))
                    });
                    let _ = (&mut wait_task).await;
                    break ProcessCompletion::Stopped { result, reply };
                }
                Some(SessionControl::Input { data, reply }) => {
                    if let Err(error) = pty_control.send(PtyRuntimeControl::Input { data, reply })
                        && let PtyRuntimeControl::Input { reply, .. } = error.0
                    {
                        let _ = reply.send(Err("session PTY input is closed".into()));
                    }
                }
                Some(SessionControl::Resize {
                    width,
                    height,
                    reply,
                }) => {
                    if let Err(error) = pty_control.send(PtyRuntimeControl::Resize {
                        width,
                        height,
                        reply,
                    }) && let PtyRuntimeControl::Resize { reply, .. } = error.0
                    {
                        let _ = reply.send(Err("session PTY resize control is closed".into()));
                    }
                }
                None => {
                    let result = (&mut wait_task).await.unwrap_or_else(|error| {
                        Err(format!("join session PTY wait task: {error}"))
                    });
                    killer.disarm();
                    break ProcessCompletion::Exited(result);
                }
            },
        }
    };

    drop(pty_control);
    let control_error = tokio::task::spawn_blocking(move || control_thread.join())
        .await
        .ok()
        .and_then(|result| result.err())
        .map(|_| "session PTY control thread panicked".to_string());
    let output_error = match output_task.await {
        Ok(Ok(())) => control_error,
        Ok(Err(error)) => Some(error.to_string()),
        Err(error) => Some(format!("join session PTY output task: {error}")),
    };
    finish_process(inner, session_id, token, handle, completion, output_error).await;
}

async fn finish_process(
    inner: Weak<SessionEngineInner>,
    session_id: String,
    token: Uuid,
    handle: Arc<SessionHandle>,
    completion: ProcessCompletion,
    output_error: Option<String>,
) {
    if let Some(inner) = inner.upgrade() {
        {
            let mut metadata = handle.metadata.lock().await;
            metadata.finished_at = Some(PersistedTimestamp::now());
            match (completion_result(&completion), output_error) {
                (_, Some(error)) => {
                    metadata.state = v1::SessionLifecycleState::Failed as i32;
                    metadata.exit_code = None;
                    metadata.status_message = error;
                }
                (Ok(ProcessResult::Exited(code)), None) => {
                    metadata.state = v1::SessionLifecycleState::Exited as i32;
                    metadata.exit_code = Some(code);
                    metadata.status_message = format!("session exited with status {code}");
                }
                (Ok(ProcessResult::Stopped), None) => {
                    metadata.state = v1::SessionLifecycleState::Stopped as i32;
                    metadata.exit_code = None;
                    metadata.status_message = "session stopped".into();
                }
                (Err(error), None) => {
                    metadata.state = v1::SessionLifecycleState::Failed as i32;
                    metadata.exit_code = None;
                    metadata.status_message = error;
                }
            }
            let _ = persist_metadata(&inner.root, &metadata).await;
        }
        remove_active(&inner, &session_id, token);
    }

    if let ProcessCompletion::Stopped { reply, .. } = completion {
        let _ = reply.send(());
    }
}

enum ProcessResult {
    Exited(i32),
    Stopped,
}

fn completion_result(completion: &ProcessCompletion) -> Result<ProcessResult, String> {
    match completion {
        ProcessCompletion::Exited(Ok(code)) => Ok(ProcessResult::Exited(*code)),
        ProcessCompletion::Exited(Err(error)) => Err(error.clone()),
        ProcessCompletion::Stopped { result: Ok(()), .. } => Ok(ProcessResult::Stopped),
        ProcessCompletion::Stopped {
            result: Err(error), ..
        } => Err(error.clone()),
    }
}

async fn join_output_tasks(
    stdout_task: JoinHandle<Result<(), SessionError>>,
    stderr_task: JoinHandle<Result<(), SessionError>>,
) -> Option<String> {
    let stdout = stdout_task.await;
    let stderr = stderr_task.await;
    for result in [stdout, stderr] {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Some(error.to_string()),
            Err(error) => return Some(format!("join session output task: {error}")),
        }
    }
    None
}

fn remove_active(inner: &SessionEngineInner, session_id: &str, token: Uuid) {
    let mut active = lock(&inner.active);
    if active
        .get(session_id)
        .is_some_and(|current| current.token == token)
    {
        active.remove(session_id);
    }
}

async fn capture_output<R>(
    root: PathBuf,
    handle: Arc<SessionHandle>,
    stream: v1::SessionOutputStream,
    mut reader: R,
) -> Result<(), SessionError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; OUTPUT_BUFFER_SIZE];
    loop {
        let size = reader
            .read(&mut buffer)
            .await
            .map_err(|error| SessionError::Internal(format!("read session output: {error}")))?;
        if size == 0 {
            return Ok(());
        }
        append_output(&root, &handle, stream, &buffer[..size]).await?;
    }
}

fn copy_pty_output(
    mut reader: Box<dyn Read + Send>,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<(), String> {
    let mut buffer = vec![0; OUTPUT_BUFFER_SIZE];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                if output.blocking_send(buffer[..size].to_vec()).is_err() {
                    return Ok(());
                }
            }
            Err(error) if error.raw_os_error() == Some(5) => return Ok(()),
            Err(error) => return Err(format!("read session PTY output: {error}")),
        }
    }
}

async fn capture_pty_output(
    root: PathBuf,
    handle: Arc<SessionHandle>,
    mut output: mpsc::Receiver<Vec<u8>>,
    reader_task: JoinHandle<Result<(), String>>,
) -> Result<(), SessionError> {
    while let Some(data) = output.recv().await {
        append_output(&root, &handle, v1::SessionOutputStream::Pty, &data).await?;
    }
    match reader_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SessionError::Internal(error)),
        Err(error) => Err(SessionError::Internal(format!(
            "join session PTY reader task: {error}"
        ))),
    }
}

fn pty_control_loop(
    master: Box<dyn portable_pty::MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    control: std_mpsc::Receiver<PtyRuntimeControl>,
) {
    for command in control {
        match command {
            PtyRuntimeControl::Input { data, reply } => {
                let result = writer
                    .write_all(&data)
                    .and_then(|()| writer.flush())
                    .map_err(|error| format!("write session PTY input: {error}"));
                let _ = reply.send(result);
            }
            PtyRuntimeControl::Resize {
                width,
                height,
                reply,
            } => {
                let result = master
                    .resize(pty_size(width, height))
                    .map_err(|error| format!("resize session PTY: {error}"));
                let _ = reply.send(result);
            }
        }
    }
}

fn pty_size(width: i32, height: i32) -> PtySize {
    PtySize {
        rows: u16::try_from(if height > 0 { height } else { 24 }).unwrap_or(u16::MAX),
        cols: u16::try_from(if width > 0 { width } else { 80 }).unwrap_or(u16::MAX),
        pixel_width: 0,
        pixel_height: 0,
    }
}

async fn read_output(
    root: &Path,
    handle: &SessionHandle,
    offset: u64,
    requested_limit: u64,
) -> Result<v1::ReadSessionOutputResponse, SessionError> {
    let metadata = handle.metadata.lock().await;
    let output_end_offset = metadata.output_end_offset;
    let retained_start_offset = metadata.output_start_offset;
    let history_gap = offset < retained_start_offset;
    if offset > output_end_offset {
        return Err(SessionError::InvalidArgument(format!(
            "session output offset {offset} exceeds current end offset {output_end_offset}"
        )));
    }
    let limit = if requested_limit == 0 {
        DEFAULT_OUTPUT_READ_LIMIT
    } else if requested_limit > MAX_OUTPUT_READ_LIMIT {
        return Err(SessionError::InvalidArgument(format!(
            "session output read limit {requested_limit} exceeds maximum {MAX_OUTPUT_READ_LIMIT}"
        )));
    } else {
        requested_limit
    };
    let offset = offset.max(retained_start_offset);
    if offset == output_end_offset {
        return Ok(v1::ReadSessionOutputResponse {
            chunks: Vec::new(),
            next_offset: offset,
            eof: true,
            retained_start_offset,
            history_gap,
        });
    }

    let path = session_directory(root, &metadata.session_id)?.join(OUTPUT_FILE);
    let output_index = lock(&handle.output_index).clone();
    let mut file = tokio::fs::File::open(&path).await.map_err(|error| {
        SessionError::Internal(format!(
            "open session output {} for read: {error}",
            path.display()
        ))
    })?;
    // Pin the inode and matching index before allowing atomic compaction.
    drop(metadata);
    let mut next_offset = offset;
    let mut remaining = limit;
    let mut chunks = Vec::new();
    let first_frame = output_index.partition_point(|frame| {
        frame
            .offset
            .checked_add(frame.length)
            .is_some_and(|end| end <= offset)
    });
    for frame in &output_index[first_frame..] {
        if remaining == 0 || next_offset == output_end_offset {
            break;
        }
        let frame_end = frame.offset.checked_add(frame.length).ok_or_else(|| {
            SessionError::Internal(format!(
                "session output frame length overflows in {}",
                path.display()
            ))
        })?;
        if frame.offset > next_offset || frame_end <= next_offset {
            return Err(SessionError::Internal(format!(
                "session output index in {} does not contain cursor {next_offset}",
                path.display()
            )));
        }
        let skip = next_offset - frame.offset;
        let chunk_offset = next_offset;
        let length = (frame.length - skip).min(remaining);
        let physical_offset = frame
            .physical_data_offset
            .checked_add(skip)
            .ok_or_else(|| {
                SessionError::Internal(format!(
                    "session output physical cursor overflows in {}",
                    path.display()
                ))
            })?;
        file.seek(SeekFrom::Start(physical_offset))
            .await
            .map_err(|error| {
                SessionError::Internal(format!(
                    "seek session output {} to {physical_offset}: {error}",
                    path.display()
                ))
            })?;
        let mut data = vec![
            0;
            usize::try_from(length).map_err(|_| {
                SessionError::Internal("session output chunk is too large to allocate".into())
            })?
        ];
        file.read_exact(&mut data).await.map_err(|error| {
            SessionError::Internal(format!(
                "read session output data {}: {error}",
                path.display()
            ))
        })?;
        next_offset = chunk_offset + length;
        remaining -= length;
        chunks.push(v1::SessionOutputChunk {
            offset: chunk_offset,
            next_offset,
            stream: frame.stream as i32,
            data,
        });
        if length < frame.length - skip {
            break;
        }
    }
    if next_offset < output_end_offset && remaining > 0 {
        return Err(SessionError::Internal(format!(
            "session output index in {} ends before durable cursor {output_end_offset}",
            path.display()
        )));
    }

    Ok(v1::ReadSessionOutputResponse {
        chunks,
        next_offset,
        eof: next_offset == output_end_offset,
        retained_start_offset,
        history_gap,
    })
}

async fn append_output(
    root: &Path,
    handle: &SessionHandle,
    stream: v1::SessionOutputStream,
    data: &[u8],
) -> Result<(), SessionError> {
    if data.is_empty() {
        return Ok(());
    }
    if data.len() > OUTPUT_BUFFER_SIZE {
        return Err(SessionError::Internal(
            "session capture frame exceeds its buffer".into(),
        ));
    }
    let mut metadata = handle.metadata.lock().await;
    let path = session_directory(root, &metadata.session_id)?.join(OUTPUT_FILE);
    let offset = metadata.output_end_offset;
    let length = u64::try_from(data.len())
        .map_err(|_| SessionError::Internal("session output chunk is too large".into()))?;
    let mut header = [0_u8; OUTPUT_FRAME_HEADER_SIZE];
    header[0..8].copy_from_slice(&offset.to_le_bytes());
    header[8] = stream as u8;
    header[9..17].copy_from_slice(&length.to_le_bytes());
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .await
        .map_err(|error| {
            SessionError::Internal(format!("open session output {}: {error}", path.display()))
        })?;
    let physical_offset = file
        .metadata()
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "read session output metadata {}: {error}",
                path.display()
            ))
        })?
        .len();
    file.write_all(&header)
        .await
        .map_err(|error| SessionError::Internal(format!("write session output header: {error}")))?;
    file.write_all(data)
        .await
        .map_err(|error| SessionError::Internal(format!("write session output data: {error}")))?;
    file.sync_data()
        .await
        .map_err(|error| SessionError::Internal(format!("sync session output: {error}")))?;
    let physical_data_offset = physical_offset
        .checked_add(OUTPUT_FRAME_HEADER_SIZE as u64)
        .ok_or_else(|| SessionError::Internal("session output file offset overflow".into()))?;
    lock(&handle.output_index).push(OutputFrameIndex {
        offset,
        physical_data_offset,
        length,
        stream,
    });
    metadata.output_end_offset = offset
        .checked_add(length)
        .ok_or_else(|| SessionError::Internal("session output offset overflow".into()))?;
    persist_metadata(root, &metadata).await?;
    drop(file);
    compact_output(root, handle, &mut metadata).await
}

async fn compact_output(
    root: &Path,
    handle: &SessionHandle,
    metadata: &mut PersistedSession,
) -> Result<(), SessionError> {
    let index = lock(&handle.output_index).clone();
    if metadata.output_end_offset - metadata.output_start_offset <= RETAINED_OUTPUT_BYTES * 2
        && index.len() <= RETAINED_OUTPUT_FRAMES * 2
    {
        return Ok(());
    }
    let minimum = metadata
        .output_end_offset
        .saturating_sub(RETAINED_OUTPUT_BYTES);
    let first = index
        .partition_point(|frame| frame.offset.saturating_add(frame.length) <= minimum)
        .max(index.len().saturating_sub(RETAINED_OUTPUT_FRAMES));
    let retained = &index[first..];
    let start = retained
        .first()
        .map_or(metadata.output_end_offset, |frame| frame.offset);
    let directory = session_directory(root, &metadata.session_id)?;
    let path = directory.join(OUTPUT_FILE);
    let temporary = directory.join(OUTPUT_TEMP_FILE);
    let mut source = tokio::fs::File::open(&path)
        .await
        .map_err(|error| SessionError::Internal(format!("open retained output: {error}")))?;
    let mut target = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .await
        .map_err(|error| SessionError::Internal(format!("create retained output: {error}")))?;
    set_private_file_permissions(&temporary).await?;
    let mut physical = 0;
    let mut replacement = Vec::with_capacity(retained.len());
    for frame in retained {
        // Keep complete capture frames: at most one 32 KiB frame over the byte
        // budget. Absolute output cursors remain unchanged after compaction.
        source
            .seek(SeekFrom::Start(frame.physical_data_offset))
            .await
            .map_err(|error| SessionError::Internal(format!("seek retained output: {error}")))?;
        let mut header = [0_u8; OUTPUT_FRAME_HEADER_SIZE];
        header[0..8].copy_from_slice(&frame.offset.to_le_bytes());
        header[8] = frame.stream as u8;
        header[9..17].copy_from_slice(&frame.length.to_le_bytes());
        target
            .write_all(&header)
            .await
            .map_err(|error| SessionError::Internal(format!("write retained header: {error}")))?;
        let copied = tokio::io::copy(&mut (&mut source).take(frame.length), &mut target)
            .await
            .map_err(|error| SessionError::Internal(format!("copy retained output: {error}")))?;
        if copied != frame.length {
            return Err(SessionError::Internal(
                "incomplete retained output frame".into(),
            ));
        }
        replacement.push(OutputFrameIndex {
            physical_data_offset: physical + OUTPUT_FRAME_HEADER_SIZE as u64,
            ..frame.clone()
        });
        physical += OUTPUT_FRAME_HEADER_SIZE as u64 + frame.length;
    }
    target
        .sync_all()
        .await
        .map_err(|error| SessionError::Internal(format!("sync retained output: {error}")))?;
    drop(target);
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|error| SessionError::Internal(format!("publish retained output: {error}")))?;
    // Publish the matching in-memory cursor/index immediately after rename.
    // Recovery derives the first cursor from the replacement file if the
    // process exits before the metadata rename completes.
    metadata.output_start_offset = start;
    *lock(&handle.output_index) = replacement;
    tokio::fs::File::open(&directory)
        .await
        .map_err(|error| {
            SessionError::Internal(format!("open retained output directory: {error}"))
        })?
        .sync_all()
        .await
        .map_err(|error| {
            SessionError::Internal(format!("sync retained output directory: {error}"))
        })?;
    persist_metadata(root, metadata).await
}

async fn reconcile_output_cursor(
    root: &Path,
    metadata: &mut PersistedSession,
) -> Result<(bool, Vec<OutputFrameIndex>), SessionError> {
    let path = session_directory(root, &metadata.session_id)?.join(OUTPUT_FILE);
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .await
        .map_err(|error| {
            SessionError::Internal(format!("open session output {}: {error}", path.display()))
        })?;
    let file_length = file
        .metadata()
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "read session output metadata {}: {error}",
                path.display()
            ))
        })?
        .len();
    let mut physical_offset = 0_u64;
    let mut logical_offset = metadata.output_start_offset;
    let mut retained_start = metadata.output_start_offset;
    let mut output_index = Vec::new();

    while physical_offset < file_length {
        let remaining = file_length - physical_offset;
        if remaining < OUTPUT_FRAME_HEADER_SIZE as u64 {
            truncate_incomplete_output(&mut file, &path, physical_offset).await?;
            break;
        }

        let mut header = [0_u8; OUTPUT_FRAME_HEADER_SIZE];
        file.read_exact(&mut header).await.map_err(|error| {
            SessionError::Internal(format!(
                "read session output header {} at {physical_offset}: {error}",
                path.display()
            ))
        })?;
        let frame_offset = u64::from_le_bytes(
            header[0..8]
                .try_into()
                .expect("session output offset header width"),
        );
        if physical_offset == 0
            && frame_offset >= metadata.output_start_offset
            && frame_offset <= metadata.output_end_offset
        {
            logical_offset = frame_offset;
            retained_start = frame_offset;
        }
        if frame_offset != logical_offset {
            return Err(SessionError::Internal(format!(
                "session output {} has non-contiguous cursor {frame_offset}, expected {logical_offset}",
                path.display()
            )));
        }
        let stream = v1::SessionOutputStream::try_from(i32::from(header[8])).map_err(|_| {
            SessionError::Internal(format!(
                "session output {} has unknown stream {}",
                path.display(),
                header[8]
            ))
        })?;
        if stream == v1::SessionOutputStream::Unspecified {
            return Err(SessionError::Internal(format!(
                "session output {} has an unspecified stream",
                path.display()
            )));
        }
        let length = u64::from_le_bytes(
            header[9..17]
                .try_into()
                .expect("session output length header width"),
        );
        if length == 0 || length > OUTPUT_BUFFER_SIZE as u64 {
            return Err(SessionError::Internal(
                "invalid session capture frame length".into(),
            ));
        }
        let frame_end = physical_offset
            .checked_add(OUTPUT_FRAME_HEADER_SIZE as u64)
            .and_then(|offset| offset.checked_add(length))
            .ok_or_else(|| {
                SessionError::Internal(format!(
                    "session output frame length overflows in {}",
                    path.display()
                ))
            })?;
        if frame_end > file_length {
            truncate_incomplete_output(&mut file, &path, physical_offset).await?;
            break;
        }
        let physical_data_offset = physical_offset
            .checked_add(OUTPUT_FRAME_HEADER_SIZE as u64)
            .ok_or_else(|| {
                SessionError::Internal(format!(
                    "session output physical cursor overflows in {}",
                    path.display()
                ))
            })?;
        output_index.push(OutputFrameIndex {
            offset: frame_offset,
            physical_data_offset,
            length,
            stream,
        });
        logical_offset = logical_offset.checked_add(length).ok_or_else(|| {
            SessionError::Internal(format!(
                "session output cursor overflows in {}",
                path.display()
            ))
        })?;
        physical_offset = frame_end;
        file.seek(SeekFrom::Start(physical_offset))
            .await
            .map_err(|error| {
                SessionError::Internal(format!(
                    "seek session output {} to {physical_offset}: {error}",
                    path.display()
                ))
            })?;
    }

    if metadata.output_end_offset > logical_offset {
        return Err(SessionError::Internal(format!(
            "session metadata cursor {} exceeds durable output cursor {logical_offset} in {}",
            metadata.output_end_offset,
            path.display()
        )));
    }
    if metadata.output_end_offset == logical_offset
        && metadata.output_start_offset == retained_start
    {
        return Ok((false, output_index));
    }
    metadata.output_end_offset = logical_offset;
    metadata.output_start_offset = retained_start;
    Ok((true, output_index))
}

async fn truncate_incomplete_output(
    file: &mut tokio::fs::File,
    path: &Path,
    length: u64,
) -> Result<(), SessionError> {
    file.set_len(length).await.map_err(|error| {
        SessionError::Internal(format!(
            "truncate incomplete session output {} to {length}: {error}",
            path.display()
        ))
    })?;
    file.sync_data().await.map_err(|error| {
        SessionError::Internal(format!(
            "sync repaired session output {}: {error}",
            path.display()
        ))
    })
}

async fn persist_metadata(root: &Path, metadata: &PersistedSession) -> Result<(), SessionError> {
    validate_session_id(&metadata.session_id)?;
    let directory = session_directory(root, &metadata.session_id)?;
    let path = directory.join(METADATA_FILE);
    let temporary = directory.join(METADATA_TEMP_FILE);
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|error| SessionError::Internal(format!("encode session metadata: {error}")))?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "open session metadata {}: {error}",
                temporary.display()
            ))
        })?;
    file.write_all(&bytes).await.map_err(|error| {
        SessionError::Internal(format!(
            "write session metadata {}: {error}",
            temporary.display()
        ))
    })?;
    file.sync_all().await.map_err(|error| {
        SessionError::Internal(format!(
            "sync session metadata {}: {error}",
            temporary.display()
        ))
    })?;
    drop(file);
    set_private_file_permissions(&temporary).await?;
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "replace session metadata {}: {error}",
                path.display()
            ))
        })?;
    Ok(())
}

fn session_directory(root: &Path, session_id: &str) -> Result<PathBuf, SessionError> {
    validate_session_id(session_id)?;
    Ok(root.join(session_id))
}

fn validate_session_id(session_id: &str) -> Result<(), SessionError> {
    let Some(raw_id) = session_id.strip_prefix("session-") else {
        return Err(SessionError::InvalidArgument(
            "session identifier must start with session-".into(),
        ));
    };
    Uuid::parse_str(raw_id).map_err(|_| {
        SessionError::InvalidArgument(format!("invalid session identifier: {session_id}"))
    })?;
    Ok(())
}

fn lifecycle_state(value: i32) -> v1::SessionLifecycleState {
    v1::SessionLifecycleState::try_from(value).unwrap_or(v1::SessionLifecycleState::Unspecified)
}

fn is_live_state(value: i32) -> bool {
    matches!(
        lifecycle_state(value),
        v1::SessionLifecycleState::Starting
            | v1::SessionLifecycleState::Running
            | v1::SessionLifecycleState::Stopping
    )
}

fn timestamp_key(timestamp: Option<&prost_types::Timestamp>) -> (i64, i32) {
    timestamp
        .map(|timestamp| (timestamp.seconds, timestamp.nanos))
        .unwrap_or_default()
}

async fn path_is_directory(path: &str) -> bool {
    tokio::fs::metadata(path)
        .await
        .is_ok_and(|metadata| metadata.is_dir())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl PersistedSession {
    fn to_record(&self) -> v1::SessionRecord {
        v1::SessionRecord {
            session_id: self.session_id.clone(),
            state: self.state,
            command: self.command.clone(),
            working_dir: self.working_dir.clone(),
            pty: self.pty,
            created_at: Some(self.created_at.into()),
            started_at: self.started_at.map(Into::into),
            finished_at: self.finished_at.map(Into::into),
            exit_code: self.exit_code,
            output_end_offset: self.output_end_offset,
            output_start_offset: self.output_start_offset,
            status_message: self.status_message.clone(),
        }
    }
}

impl PersistedTimestamp {
    fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        }
    }
}

impl From<PersistedTimestamp> for prost_types::Timestamp {
    fn from(timestamp: PersistedTimestamp) -> Self {
        Self {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        }
    }
}

#[cfg(unix)]
async fn set_private_directory_permissions(path: &Path) -> Result<(), SessionError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "set session directory permissions {}: {error}",
                path.display()
            ))
        })
}

#[cfg(not(unix))]
async fn set_private_directory_permissions(_path: &Path) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(unix)]
async fn set_private_file_permissions(path: &Path) -> Result<(), SessionError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "set session file permissions {}: {error}",
                path.display()
            ))
        })
}

#[cfg(not(unix))]
async fn set_private_file_permissions(_path: &Path) -> Result<(), SessionError> {
    Ok(())
}

pub fn status_from_session_error(error: SessionError) -> Status {
    match error {
        SessionError::InvalidArgument(message) => Status::invalid_argument(message),
        SessionError::NotFound(message) => Status::not_found(message),
        SessionError::FailedPrecondition(message) => Status::failed_precondition(message),
        SessionError::ResourceExhausted(message) => Status::resource_exhausted(message),
        SessionError::Internal(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn cancellation_engine() -> (tempfile::TempDir, SessionEngine) {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_owned(),
            home_root: temp.path().to_owned(),
            auth_token: crate::DaemonAuthToken::new("synthetic-cancellation-test").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
        };
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        engine.ensure_initialized().await.unwrap();
        (temp, engine)
    }

    fn marker_request(marker: &Path) -> v1::LaunchSessionRequest {
        v1::LaunchSessionRequest {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf spawned > \"$1\"".into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            ..Default::default()
        }
    }

    async fn pending_handle(engine: &SessionEngine, marker: &Path) -> Arc<SessionHandle> {
        let session_id = engine.create_session_id().await.unwrap();
        let metadata = PersistedSession {
            session_id: session_id.clone(),
            state: v1::SessionLifecycleState::Starting as i32,
            command: marker_request(marker).command,
            working_dir: engine.inner.config.home_root.to_string_lossy().into_owned(),
            env: Vec::new(),
            pty: false,
            term: String::new(),
            width: 80,
            height: 24,
            created_at: PersistedTimestamp::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            cleanup_confirmed: false,
            status_message: "session starting".into(),
            cleanup_unknown: true,
        };
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
        let handle = Arc::new(SessionHandle {
            metadata: AsyncMutex::new(metadata),
            operation: AsyncMutex::new(()),
            output_index: Mutex::new(Vec::new()),
            launch_cancellation: watch::channel(false).0,
        });
        lock(&engine.inner.sessions).insert(session_id, handle.clone());
        handle
    }

    #[tokio::test]
    async fn cancelled_owned_launch_before_persistence_creates_no_session() {
        let (temp, engine) = cancellation_engine().await;
        let request = marker_request(&temp.path().join("must-not-spawn"));
        let (entered_tx, entered_rx) = oneshot::channel();
        let (settled_tx, settled_rx) = oneshot::channel();
        let owner = engine.clone();
        let worker = engine.clone();
        let caller = tokio::spawn(async move {
            owner
                .own_launch(move |cancel| async move {
                    let _ = entered_tx.send(());
                    cancel.cancelled().await;
                    let result = worker.launch_inner(request, cancel).await;
                    let _ = settled_tx.send(());
                    result
                })
                .await
        });
        entered_rx.await.unwrap();
        caller.abort();
        tokio::time::timeout(Duration::from_secs(1), settled_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(engine.list().await.unwrap().is_empty());
        assert!(!temp.path().join("must-not-spawn").exists());
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_persisted_launch_settles_failed_before_spawn() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("must-not-spawn");
        let handle = pending_handle(&engine, &marker).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let _operation = handle.operation.lock().await;
        let record = engine.start_process(handle.clone(), &cancel).await.unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Failed as i32);
        assert!(record.started_at.is_none());
        assert!(record.finished_at.is_some());
        assert!(!handle.metadata.lock().await.cleanup_unknown);
        assert!(!marker.exists());
        let persisted: PersistedSession = serde_json::from_slice(
            &tokio::fs::read(
                engine
                    .inner
                    .root
                    .join(&record.session_id)
                    .join(METADATA_FILE),
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.state, record.state);
        assert!(!persisted.cleanup_unknown);
    }

    #[tokio::test]
    async fn unconfirmed_cleanup_blocks_restart_and_survives_reload() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("must-not-spawn");
        let handle = pending_handle(&engine, &marker).await;
        let record = engine
            .record_launch_cleanup(handle, false, "not rendered".into())
            .await
            .unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Interrupted as i32);
        assert!(!record.status_message.contains("not rendered"));
        assert!(matches!(
            engine.restart(&record.session_id).await,
            Err(SessionError::FailedPrecondition(_))
        ));
        assert_eq!(
            engine.stop(&record.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Interrupted as i32
        );
        let config = engine.inner.config.clone();
        assert!(engine.shutdown().await.is_err());
        drop(engine);
        let recovered = SessionEngine::new(&config, CredentialBridge::new(None));
        assert!(matches!(
            recovered.restart(&record.session_id).await,
            Err(SessionError::FailedPrecondition(_))
        ));
        assert!(!marker.exists());
        assert!(recovered.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn caller_loss_holds_operation_lock_until_cleanup_settles() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("must-not-spawn");
        let handle = pending_handle(&engine, &marker).await;
        let session_id = handle.metadata.lock().await.session_id.clone();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (cancelled_tx, cancelled_rx) = oneshot::channel();
        let (settle_tx, settle_rx) = oneshot::channel();
        let owner = engine.clone();
        let worker = engine.clone();
        let pending = handle.clone();
        let caller = tokio::spawn(async move {
            owner
                .own_launch(move |cancel| async move {
                    let _operation = pending.operation.lock().await;
                    let _ = entered_tx.send(());
                    cancel.cancelled().await;
                    let _ = cancelled_tx.send(());
                    let _ = settle_rx.await;
                    worker
                        .record_startup_failure(pending.clone(), "session launch cancelled".into())
                        .await
                })
                .await
        });
        entered_rx.await.unwrap();
        caller.abort();
        cancelled_rx.await.unwrap();
        assert!(handle.operation.try_lock().is_err());
        assert!(
            !*handle.launch_cancellation.borrow(),
            "request-local cancellation must not cancel another attempt"
        );
        let stop_engine = engine.clone();
        let stop_id = session_id.clone();
        let stopping = tokio::spawn(async move { stop_engine.stop(&stop_id).await });
        tokio::task::yield_now().await;
        assert!(!stopping.is_finished());
        settle_tx.send(()).unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(1), stopping)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stopped.state, v1::SessionLifecycleState::Failed as i32);
        assert!(!handle.metadata.lock().await.cleanup_unknown);
        assert!(!marker.exists());
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_restart_retains_serial_ownership_until_dispatched_stop_settles() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("next-attempt");
        let handle = pending_handle(&engine, &marker).await;
        let id = {
            let mut metadata = handle.metadata.lock().await;
            metadata.state = v1::SessionLifecycleState::Running as i32;
            metadata.cleanup_unknown = false;
            metadata.session_id.clone()
        };
        let (control, mut commands) = mpsc::channel(1);
        let (entered, dispatched) = oneshot::channel();
        let (release, settled) = oneshot::channel();
        let monitor_engine = engine.clone();
        let monitor_handle = handle.clone();
        let monitor_id = id.clone();
        let monitor = tokio::spawn(async move {
            let Some(SessionControl::Stop { reply }) = commands.recv().await else {
                panic!("expected Stop from first Restart");
            };
            entered.send(()).unwrap();
            settled.await.unwrap();
            {
                let mut metadata = monitor_handle.metadata.lock().await;
                metadata.state = v1::SessionLifecycleState::Stopped as i32;
                persist_metadata(&monitor_engine.inner.root, &metadata)
                    .await
                    .unwrap();
            }
            lock(&monitor_engine.inner.active).remove(&monitor_id);
            reply.send(()).unwrap();
        });
        lock(&engine.inner.active).insert(
            id.clone(),
            ActiveSession {
                token: Uuid::new_v4(),
                control,
                task: monitor,
            },
        );
        let first_engine = engine.clone();
        let first_id = id.clone();
        let first = tokio::spawn(async move { first_engine.restart(&first_id).await });
        tokio::time::timeout(Duration::from_secs(1), dispatched)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        let second_engine = engine.clone();
        let second_id = id.clone();
        let second = tokio::spawn(async move { second_engine.restart(&second_id).await });
        tokio::task::yield_now().await;
        assert!(
            handle.operation.try_lock().is_err(),
            "caller loss must not drop the Stop owner"
        );
        assert!(!second.is_finished());
        assert!(!marker.exists());
        release.send(()).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(3), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(next.session_id, id);
        tokio::time::timeout(Duration::from_secs(3), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        engine.stop(&id).await.unwrap();
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_and_drains_launch_owner_and_closes_admission() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("must-not-spawn");
        let handle = pending_handle(&engine, &marker).await;
        let (entered_tx, entered_rx) = oneshot::channel();
        let owner = engine.clone();
        let worker = engine.clone();
        let caller = tokio::spawn(async move {
            owner
                .own_launch(move |cancel| async move {
                    let _operation = handle.operation.lock().await;
                    let _ = entered_tx.send(());
                    cancel.cancelled().await;
                    worker
                        .record_startup_failure(handle.clone(), "session launch cancelled".into())
                        .await
                })
                .await
        });
        entered_rx.await.unwrap();
        engine.shutdown().await.unwrap();
        assert_eq!(
            caller.await.unwrap().unwrap().state,
            v1::SessionLifecycleState::Failed as i32
        );
        assert!(engine.inner.launches.is_empty());
        assert!(matches!(
            engine.launch(marker_request(&marker)).await,
            Err(SessionError::FailedPrecondition(_))
        ));
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn unconfirmed_cleanup_fence_overrides_retirable_state_and_confirmation() {
        let (temp, engine) = cancellation_engine().await;
        let handle = pending_handle(&engine, &temp.path().join("must-not-spawn")).await;
        let id = {
            let mut metadata = handle.metadata.lock().await;
            metadata.state = v1::SessionLifecycleState::Stopped as i32;
            metadata.cleanup_confirmed = true;
            metadata.session_id.clone()
        };
        assert!(matches!(
            prune_session_records(&engine.inner, 0, true).await,
            Err(SessionError::ResourceExhausted(_))
        ));
        assert!(engine.inner.root.join(&id).exists());
        assert!(matches!(
            engine.restart(&id).await,
            Err(SessionError::FailedPrecondition(_))
        ));
        assert!(engine.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn completed_handoff_keeps_shell_alive_after_original_launch_caller_loss() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("same-shell-input");
        let request = v1::LaunchSessionRequest {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "IFS= read -r line; printf '%s' \"$line\" > \"$1\"; exec sleep 30".into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            ..Default::default()
        };
        let (handed_off, observed) = oneshot::channel();
        let (settled, finished) = oneshot::channel();
        let owner = engine.clone();
        let worker = engine.clone();
        let caller = tokio::spawn(async move {
            owner
                .own_launch(move |cancel| async move {
                    let record = worker.launch_inner(request, cancel.clone()).await?;
                    handed_off.send(record.clone()).unwrap();
                    cancel.cancelled().await;
                    settled.send(()).unwrap();
                    Ok(record)
                })
                .await
        });
        let record = tokio::time::timeout(Duration::from_secs(3), observed)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        let _ = caller.await;
        tokio::time::timeout(Duration::from_secs(1), finished)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            engine.get(&record.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Running as i32
        );
        engine
            .input(&record.session_id, b"still-alive\n".to_vec())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !std::fs::read_to_string(&marker).is_ok_and(|value| value == "still-alive") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        engine.stop(&record.session_id).await.unwrap();
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn recovered_starting_retains_cleanup_fence_and_legacy_default_is_false() {
        let (temp, engine) = cancellation_engine().await;
        let handle = pending_handle(&engine, &temp.path().join("must-not-spawn")).await;
        let metadata = handle.metadata.lock().await.clone();
        let mut legacy = serde_json::to_value(&metadata).unwrap();
        legacy.as_object_mut().unwrap().remove("cleanup_unknown");
        assert!(
            !serde_json::from_value::<PersistedSession>(legacy)
                .unwrap()
                .cleanup_unknown
        );
        let config = engine.inner.config.clone();
        drop(engine);
        let recovered = SessionEngine::new(&config, CredentialBridge::new(None));
        assert_eq!(
            recovered.get(&metadata.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Interrupted as i32
        );
        assert!(matches!(
            recovered.restart(&metadata.session_id).await,
            Err(SessionError::FailedPrecondition(_))
        ));
    }

    #[tokio::test]
    async fn durable_restart_rejects_explicit_selected_client_collision_before_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let workspace = temp.path().join("workspace");
        tokio::fs::create_dir(&home).await.unwrap();
        tokio::fs::create_dir(&workspace).await.unwrap();
        let marker = temp.path().join("must-not-spawn");
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: workspace.clone(),
            home_root: home,
            auth_token: crate::DaemonAuthToken::new("synthetic-managed-client-test").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: Some(crate::CredentialBridgeConfig {
                transport: crate::CredentialBridgeTransport::Local,
                environment_id: uuid::Uuid::from_u128(41),
                environment_generation: 7,
                ingress_socket: temp.path().join("unused-credentials.sock"),
                ingress_uid: 1000,
                ingress_gid: 1000,
            }),
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
            launch_projection: Some(crate::LaunchProjectionConfig {
                selection_sha256: [4; 32],
                native: Some(crate::NativeLaunchProjectionConfig {
                    helper_path: temp.path().join("must-not-inspect-helper"),
                    process_directory: temp.path().join("must-not-inspect-processes"),
                }),
            }),
        };
        let bridge = CredentialBridge::new(config.credential_bridge.clone());
        let engine = SessionEngine::new(&config, bridge);
        let record = engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("touch {}", marker.display()),
                ],
                working_dir: workspace.to_string_lossy().into_owned(),
                env: vec!["CODEX_HOME=".into()],
                pty: false,
                term: String::new(),
                width: 0,
                height: 0,
            })
            .await
            .unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Failed as i32);
        assert!(record.status_message.contains("managed credential client"));
        assert!(!marker.exists());

        let restarted = engine.restart(&record.session_id).await.unwrap();
        assert_eq!(restarted.state, v1::SessionLifecycleState::Failed as i32);
        assert!(
            restarted
                .status_message
                .contains("managed credential client")
        );
        assert!(!marker.exists());
    }

    #[test]
    fn output_frame_header_has_stable_offset_stream_and_length_layout() {
        let offset = 41_u64;
        let stream = v1::SessionOutputStream::Stderr;
        let length = 7_u64;
        let mut header = Vec::new();
        header.extend_from_slice(&offset.to_le_bytes());
        header.push(stream as u8);
        header.extend_from_slice(&length.to_le_bytes());

        assert_eq!(header.len(), OUTPUT_FRAME_HEADER_SIZE);
        assert_eq!(
            u64::from_le_bytes(header[0..8].try_into().expect("offset bytes")),
            offset
        );
        assert_eq!(header[8], stream as u8);
        assert_eq!(
            u64::from_le_bytes(header[9..17].try_into().expect("length bytes")),
            length
        );
    }

    #[test]
    fn session_identifier_rejects_paths_and_non_uuid_values() {
        assert!(validate_session_id("../session-deadbeef").is_err());
        assert!(validate_session_id("session-not-a-uuid").is_err());
        assert!(validate_session_id("session-00000000-0000-4000-8000-000000000001").is_ok());
    }

    async fn retained_fixture(root: &Path, frames: usize, size: usize) -> SessionHandle {
        let session_id = "session-00000000-0000-4000-8000-000000000001";
        let directory = root.join(session_id);
        tokio::fs::create_dir(&directory).await.unwrap();
        let mut file = tokio::fs::File::create(directory.join(OUTPUT_FILE))
            .await
            .unwrap();
        let mut index = Vec::new();
        let mut physical = 0;
        for number in 0..frames {
            let offset = (number * size) as u64;
            file.write_all(&offset.to_le_bytes()).await.unwrap();
            file.write_all(&[v1::SessionOutputStream::Pty as u8])
                .await
                .unwrap();
            file.write_all(&(size as u64).to_le_bytes()).await.unwrap();
            file.write_all(&vec![(number % 251) as u8; size])
                .await
                .unwrap();
            index.push(OutputFrameIndex {
                offset,
                physical_data_offset: physical + OUTPUT_FRAME_HEADER_SIZE as u64,
                length: size as u64,
                stream: v1::SessionOutputStream::Pty,
            });
            physical += OUTPUT_FRAME_HEADER_SIZE as u64 + size as u64;
        }
        file.sync_all().await.unwrap();
        let metadata = PersistedSession {
            session_id: session_id.into(),
            state: v1::SessionLifecycleState::Running as i32,
            command: vec!["sh".into()],
            working_dir: root.to_string_lossy().into_owned(),
            env: Vec::new(),
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            created_at: PersistedTimestamp::now(),
            started_at: Some(PersistedTimestamp::now()),
            finished_at: None,
            exit_code: None,
            output_end_offset: (frames * size) as u64,
            output_start_offset: 0,
            cleanup_confirmed: false,
            cleanup_unknown: false,
            status_message: "session running".into(),
        };
        persist_metadata(root, &metadata).await.unwrap();
        SessionHandle {
            metadata: AsyncMutex::new(metadata),
            output_index: Mutex::new(index),
            operation: AsyncMutex::new(()),
            launch_cancellation: watch::channel(false).0,
        }
    }

    fn test_engine(root: &Path) -> SessionEngine {
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: root.join("workspace"),
            home_root: root.join("home"),
            auth_token: crate::DaemonAuthToken::new("synthetic-retention-test").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
        };
        SessionEngine::new(&config, CredentialBridge::new(None))
    }

    async fn record_fixture(
        engine: &SessionEngine,
        number: u128,
        state: v1::SessionLifecycleState,
    ) -> String {
        tokio::fs::create_dir_all(&engine.inner.root).await.unwrap();
        let handle = Arc::new(retained_fixture(&engine.inner.root, 0, 1).await);
        let mut metadata = handle.metadata.lock().await;
        let session_id = format!("session-{}", Uuid::from_u128(number));
        tokio::fs::rename(
            engine.inner.root.join(&metadata.session_id),
            engine.inner.root.join(&session_id),
        )
        .await
        .unwrap();
        metadata.session_id = session_id.clone();
        metadata.state = state as i32;
        metadata.finished_at = Some(PersistedTimestamp {
            seconds: number as i64,
            nanos: 0,
        });
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
        drop(metadata);
        lock(&engine.inner.sessions).insert(session_id.clone(), handle);
        session_id
    }

    #[tokio::test]
    async fn record_retention_prunes_oldest_confirmed_end_and_keeps_live_or_unresolved() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let live = record_fixture(&engine, 1, v1::SessionLifecycleState::Running).await;
        let unknown = record_fixture(&engine, 2, v1::SessionLifecycleState::Interrupted).await;
        let oldest = record_fixture(&engine, 3, v1::SessionLifecycleState::Exited).await;
        for number in 4..=MAX_SESSION_RECORDS as u128 {
            record_fixture(&engine, number, v1::SessionLifecycleState::Stopped).await;
        }
        engine.make_record_room().await.unwrap();
        assert_eq!(lock(&engine.inner.sessions).len(), MAX_SESSION_RECORDS - 1);
        assert!(engine.handle(&live).is_ok());
        assert!(engine.handle(&unknown).is_ok());
        assert!(matches!(
            engine.handle(&oldest),
            Err(SessionError::NotFound(_))
        ));
        assert!(!engine.inner.root.join(oldest).exists());
        assert!(engine.inner.root.join(live).exists());
        assert!(engine.inner.root.join(unknown).exists());
    }

    #[tokio::test]
    async fn record_retention_rejects_admission_instead_of_deleting_live_sessions() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        for number in 1..=MAX_SESSION_RECORDS as u128 {
            record_fixture(&engine, number, v1::SessionLifecycleState::Running).await;
        }
        assert!(matches!(
            engine.make_record_room().await,
            Err(SessionError::ResourceExhausted(_))
        ));
        assert_eq!(lock(&engine.inner.sessions).len(), MAX_SESSION_RECORDS);
        let mut entries = tokio::fs::read_dir(&engine.inner.root).await.unwrap();
        let mut count = 0;
        while entries.next_entry().await.unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, MAX_SESSION_RECORDS);
    }

    #[tokio::test]
    async fn startup_cleans_interrupted_retirement_without_loading_partial_record() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let retired_id = record_fixture(&engine, 2, v1::SessionLifecycleState::Exited).await;
        let retained_id = record_fixture(&engine, 3, v1::SessionLifecycleState::Stopped).await;
        let retired_path = engine
            .inner
            .root
            .join(format!("{RETIRED_SESSION_PREFIX}{retired_id}"));
        tokio::fs::rename(engine.inner.root.join(&retired_id), &retired_path)
            .await
            .unwrap();
        tokio::fs::remove_file(retired_path.join(METADATA_FILE))
            .await
            .unwrap();
        let recovered = test_engine(temp.path());
        let sessions = recovered.list().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, retained_id);
        assert!(!retired_path.exists());
    }

    #[tokio::test]
    async fn startup_prunes_inherited_over_limit_confirmed_records() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        for number in 1..=(MAX_SESSION_RECORDS + 2) as u128 {
            record_fixture(&engine, number, v1::SessionLifecycleState::Exited).await;
        }
        let recovered = test_engine(temp.path());
        let sessions = recovered.list().await.unwrap();
        assert_eq!(sessions.len(), MAX_SESSION_RECORDS);
        assert!(
            !engine
                .inner
                .root
                .join(format!("session-{}", Uuid::from_u128(1)))
                .exists()
        );
        assert!(
            !engine
                .inner
                .root
                .join(format!("session-{}", Uuid::from_u128(2)))
                .exists()
        );
    }

    #[tokio::test]
    async fn startup_compacts_inherited_output_without_renumbering_or_deleting_record() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        tokio::fs::create_dir_all(&engine.inner.root).await.unwrap();
        let frames = (RETAINED_OUTPUT_BYTES * 2 / OUTPUT_BUFFER_SIZE as u64) as usize + 1;
        let handle = retained_fixture(&engine.inner.root, frames, OUTPUT_BUFFER_SIZE).await;
        let before = handle.metadata.lock().await.to_record();
        let sessions = engine.list().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, before.session_id);
        assert_eq!(sessions[0].output_end_offset, before.output_end_offset);
        assert!(sessions[0].output_start_offset > 0);
        assert_eq!(
            sessions[0].state,
            v1::SessionLifecycleState::Interrupted as i32
        );
        let output = engine
            .read_output(v1::ReadSessionOutputRequest {
                session_id: before.session_id,
                offset: 0,
                limit: 1,
                allow_history_gap: true,
            })
            .await
            .unwrap();
        assert!(output.history_gap);
        assert_eq!(output.chunks[0].offset, sessions[0].output_start_offset);
    }

    #[tokio::test]
    async fn failed_retirement_cleanup_blocks_admission_until_recovered() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let id = record_fixture(&engine, 2, v1::SessionLifecycleState::Exited).await;
        let retired_path = engine
            .inner
            .root
            .join(format!("{RETIRED_SESSION_PREFIX}{id}"));
        // A non-directory tombstone produces a deterministic cleanup failure
        // even on privileged test runners. No replacement record is admitted.
        tokio::fs::write(&retired_path, b"incomplete cleanup")
            .await
            .unwrap();
        assert!(matches!(
            engine.make_record_room().await,
            Err(SessionError::Internal(_))
        ));
        assert_eq!(lock(&engine.inner.sessions).len(), 1);
        assert!(engine.inner.root.join(&id).exists());
        tokio::fs::remove_file(&retired_path).await.unwrap();
        tokio::fs::create_dir(&retired_path).await.unwrap();
        tokio::fs::write(retired_path.join(OUTPUT_FILE), b"old output")
            .await
            .unwrap();
        engine.make_record_room().await.unwrap();
        assert!(!retired_path.exists());
        assert_eq!(lock(&engine.inner.sessions).len(), 1);
    }

    #[tokio::test]
    async fn only_confirmed_unspawned_failures_are_eligible_for_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let ambiguous = record_fixture(&engine, 1, v1::SessionLifecycleState::Failed).await;
        let safe = record_fixture(&engine, 2, v1::SessionLifecycleState::Starting).await;
        let handle = engine.handle(&safe).unwrap();
        engine
            .record_unspawned_failure(handle, "synthetic spawn failure".into())
            .await
            .unwrap();
        prune_session_records(&engine.inner, 1, true).await.unwrap();
        assert!(engine.handle(&ambiguous).is_ok());
        assert!(matches!(
            engine.handle(&safe),
            Err(SessionError::NotFound(_))
        ));
        let recovered = test_engine(temp.path());
        assert_eq!(recovered.list().await.unwrap().len(), 1);
        assert!(recovered.handle(&ambiguous).is_ok());
    }

    #[tokio::test]
    async fn restart_waiting_for_retention_cannot_resurrect_a_pruned_record() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let oldest = record_fixture(&engine, 1, v1::SessionLifecycleState::Exited).await;
        for number in 2..=MAX_SESSION_RECORDS as u128 {
            record_fixture(&engine, number, v1::SessionLifecycleState::Stopped).await;
        }
        engine.ensure_initialized().await.unwrap();
        let admission = engine.inner.retention_admission.lock().await;
        let restarting = engine.clone();
        let restarting_id = oldest.clone();
        let task = tokio::spawn(async move { restarting.restart(&restarting_id).await });
        engine.make_record_room().await.unwrap();
        drop(admission);
        assert!(matches!(
            task.await.unwrap(),
            Err(SessionError::NotFound(_))
        ));
        assert!(!engine.inner.root.join(&oldest).exists());
        assert!(!lock(&engine.inner.active).contains_key(&oldest));
    }

    #[tokio::test]
    async fn retention_preserves_live_identity_absolute_cursors_and_recent_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let frames = (RETAINED_OUTPUT_BYTES * 2 / OUTPUT_BUFFER_SIZE as u64) as usize + 1;
        let handle = retained_fixture(temp.path(), frames, OUTPUT_BUFFER_SIZE).await;
        let before = handle.metadata.lock().await.clone();
        compact_output(temp.path(), &handle, &mut *handle.metadata.lock().await)
            .await
            .unwrap();
        let record = handle.metadata.lock().await.clone();
        assert_eq!(record.session_id, before.session_id);
        assert_eq!(record.state, before.state);
        assert_eq!(record.output_end_offset, before.output_end_offset);
        assert!(record.output_start_offset > 0);
        assert!(
            record.output_end_offset - record.output_start_offset
                <= RETAINED_OUTPUT_BYTES + OUTPUT_BUFFER_SIZE as u64
        );
        let replay = read_output(temp.path(), &handle, 0, 1).await.unwrap();
        assert!(replay.history_gap);
        assert_eq!(replay.retained_start_offset, record.output_start_offset);
        assert_eq!(replay.chunks[0].offset, record.output_start_offset);
        let number = record.output_start_offset / OUTPUT_BUFFER_SIZE as u64;
        assert_eq!(replay.chunks[0].data, vec![(number % 251) as u8]);
        let resumed = read_output(temp.path(), &handle, replay.next_offset, 1)
            .await
            .unwrap();
        assert!(!resumed.history_gap);
        assert_eq!(resumed.chunks[0].offset, replay.next_offset);
        assert!(matches!(
            read_output(temp.path(), &handle, record.output_end_offset + 1, 1).await,
            Err(SessionError::InvalidArgument(_))
        ));
        let mut recovered = before;
        let (changed, index) = reconcile_output_cursor(temp.path(), &mut recovered)
            .await
            .unwrap();
        assert!(
            changed,
            "recover compaction published before metadata update"
        );
        assert_eq!(recovered.output_start_offset, record.output_start_offset);
        assert_eq!(recovered.output_end_offset, record.output_end_offset);
        assert_eq!(index.len(), lock(&handle.output_index).len());
        append_output(
            temp.path(),
            &handle,
            v1::SessionOutputStream::Pty,
            b"still-live",
        )
        .await
        .unwrap();
        let tail = read_output(temp.path(), &handle, record.output_end_offset, 10)
            .await
            .unwrap();
        assert_eq!(tail.chunks[0].data, b"still-live");
        assert!(!tail.history_gap);
    }

    #[tokio::test]
    async fn retention_bounds_index_for_tiny_writes_and_pins_existing_reader_inode() {
        let temp = tempfile::tempdir().unwrap();
        let frames = RETAINED_OUTPUT_FRAMES * 2 + 1;
        let handle = retained_fixture(temp.path(), frames, 1).await;
        let path = session_directory(temp.path(), &handle.metadata.lock().await.session_id)
            .unwrap()
            .join(OUTPUT_FILE);
        let mut existing_reader = tokio::fs::File::open(&path).await.unwrap();
        compact_output(temp.path(), &handle, &mut *handle.metadata.lock().await)
            .await
            .unwrap();
        assert_eq!(lock(&handle.output_index).len(), RETAINED_OUTPUT_FRAMES);
        assert_eq!(
            tokio::fs::metadata(&path).await.unwrap().len(),
            (RETAINED_OUTPUT_FRAMES * (OUTPUT_FRAME_HEADER_SIZE + 1)) as u64
        );
        let mut first = [0; OUTPUT_FRAME_HEADER_SIZE + 1];
        existing_reader.read_exact(&mut first).await.unwrap();
        assert_eq!(&first[..8], &0_u64.to_le_bytes());
        assert_eq!(first[OUTPUT_FRAME_HEADER_SIZE], 0);
        assert!(
            read_output(temp.path(), &handle, 0, 1)
                .await
                .unwrap()
                .history_gap
        );
    }

    #[tokio::test]
    async fn output_reconciliation_advances_stale_cursor_and_trims_partial_tail() {
        let temp = tempfile::tempdir().expect("session store");
        let root = temp.path();
        let session_id = "session-00000000-0000-4000-8000-000000000001";
        let directory = root.join(session_id);
        tokio::fs::create_dir(&directory)
            .await
            .expect("session directory");
        let output_path = directory.join(OUTPUT_FILE);
        let mut output = tokio::fs::File::create(&output_path)
            .await
            .expect("session output");
        output.write_all(&0_u64.to_le_bytes()).await.unwrap();
        output
            .write_all(&[v1::SessionOutputStream::Stdout as u8])
            .await
            .unwrap();
        output.write_all(&3_u64.to_le_bytes()).await.unwrap();
        output.write_all(b"abc").await.unwrap();
        output.write_all(&[0_u8; 4]).await.unwrap();
        output.sync_all().await.unwrap();
        drop(output);

        let mut metadata = PersistedSession {
            session_id: session_id.into(),
            state: v1::SessionLifecycleState::Exited as i32,
            command: vec!["true".into()],
            working_dir: root.to_string_lossy().into_owned(),
            env: Vec::new(),
            pty: false,
            term: String::new(),
            width: 0,
            height: 0,
            created_at: PersistedTimestamp::now(),
            started_at: None,
            finished_at: Some(PersistedTimestamp::now()),
            exit_code: Some(0),
            output_end_offset: 0,
            output_start_offset: 0,
            cleanup_confirmed: false,
            cleanup_unknown: false,
            status_message: "session exited with status 0".into(),
        };

        let (changed, index) = reconcile_output_cursor(root, &mut metadata)
            .await
            .expect("reconcile output");
        assert!(changed);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].offset, 0);
        assert_eq!(
            index[0].physical_data_offset,
            OUTPUT_FRAME_HEADER_SIZE as u64
        );
        assert_eq!(index[0].length, 3);
        assert_eq!(metadata.output_end_offset, 3);
        assert_eq!(
            tokio::fs::metadata(output_path).await.unwrap().len(),
            OUTPUT_FRAME_HEADER_SIZE as u64 + 3
        );
    }
}
