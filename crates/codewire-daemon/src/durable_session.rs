use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io::{Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{SESSION_INPUT_MAX_BYTES, SESSION_INPUT_TIMEOUT};
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
use crate::env::{build_process_env, build_process_env_in, default_shell_for};
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
/// The status of a launch whose environment projection was refused, expired or
/// cancelled before the program was started: the launcher never executed it.
pub(crate) const LAUNCH_PROJECTION_DENIED: &str = "environment launch denied or expired";
/// The status of a launch whose projection failed after the launcher was
/// told to execute: its program may have started, so this is never a
/// denial (#2769).
pub(crate) const LAUNCH_COMMITTED_UNKNOWN: &str =
    "environment launch committed; its outcome is unknown";

/// A failed projection is a denial only while the launcher had not been
/// told to execute (#2769).
pub(crate) fn launch_failure_status(committed: bool) -> &'static str {
    if committed {
        LAUNCH_COMMITTED_UNKNOWN
    } else {
        LAUNCH_PROJECTION_DENIED
    }
}
const LAUNCH_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const LAUNCH_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a host-control RPC waits for its request's outcome
/// ([`HostBounds::rpc_join`]). Host control is Linux only.
#[cfg(target_os = "linux")]
const HOST_CONTROL_RPC_JOIN: Duration = Duration::from_secs(3);
// Compact at twice the retained byte/frame budget, amortizing disk rewrites.
const RETAINED_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const RETAINED_OUTPUT_FRAMES: usize = 2048;
const MAX_SESSION_RECORDS: usize = 128;
const RETIRED_SESSION_PREFIX: &str = ".retired-";
/// Input and resize run inline in a terminal's attach loop, so a slow one
/// holds up that terminal's later input. Report any that takes this long.
const SLOW_SESSION_CONTROL: Duration = Duration::from_secs(1);

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

/// Host sessions' wall-clock bounds. Each one that runs out leaves its
/// outcome unknown, never retried.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HostBounds {
    /// Each step of a host process group's cleanup: descendants settling
    /// after KILL, the leader's reap and the output drain.
    pub(crate) cleanup_step: Duration,
    /// A host-control input's or stop's dispatch: queueing and the
    /// monitor's write and flush, or its whole cleanup. Host control is
    /// Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) control_dispatch: Duration,
    /// The daemon's whole shutdown: its launches' cleanup, then every host
    /// session's pause and stop, together.
    pub(crate) shutdown: Duration,
    /// How long a host-control RPC waits for its request's outcome before it
    /// answers with the receipt it has. The request goes on either way. Zero,
    /// a test bound, answers at once with the receipt as admitted.
    #[cfg(target_os = "linux")]
    pub(crate) rpc_join: Duration,
}

impl HostBounds {
    pub(crate) const PRODUCT: Self = Self {
        cleanup_step: crate::host_process::JOIN_TIMEOUT,
        #[cfg(target_os = "linux")]
        control_dispatch: SESSION_INPUT_TIMEOUT,
        shutdown: LAUNCH_SHUTDOWN_TIMEOUT,
        #[cfg(target_os = "linux")]
        rpc_join: HOST_CONTROL_RPC_JOIN,
    };

    /// Every host bound replaced by `bound`: the Linux host-control
    /// entrypoint's test seam and the tests' hang guard.
    #[cfg(target_os = "linux")]
    pub(crate) const fn all(bound: Duration) -> Self {
        Self {
            cleanup_step: bound,
            #[cfg(target_os = "linux")]
            control_dispatch: bound,
            shutdown: bound,
            #[cfg(target_os = "linux")]
            rpc_join: bound,
        }
    }

    /// The product's bounds, except the two that only bound how long a
    /// caller waits for an outcome, the daemon's whole shutdown and a
    /// host-control RPC's join, which become `bound`. For a test whose
    /// subject may be a host session's own bounds but is never those waits.
    #[cfg(test)]
    pub(crate) const fn waits_within(bound: Duration) -> Self {
        Self {
            shutdown: bound,
            #[cfg(target_os = "linux")]
            rpc_join: bound,
            ..Self::PRODUCT
        }
    }
}

struct SessionEngineInner {
    config: Config,
    credential_bridge: CredentialBridge,
    root: PathBuf,
    initialized: OnceCell<()>,
    sessions: Mutex<BTreeMap<String, Arc<SessionHandle>>>,
    active: Mutex<HashMap<String, ActiveSession>>,
    retention_admission: AsyncMutex<()>,
    launch_admission: Mutex<()>,
    launches: TaskTracker,
    shutdown: CancellationToken,
    /// The reason the store last refused to open, logged once and reported
    /// in health diagnostics until the store opens.
    store_refusal: Mutex<Option<String>>,
    /// Host sessions' wall-clock bounds: [`HostBounds::PRODUCT`] in the
    /// product.
    host_bounds: HostBounds,
    /// How many stops and restarts asked the record helper about an active
    /// run to interrupt first.
    #[cfg(all(test, target_os = "linux"))]
    stop_interrupt_checks: std::sync::atomic::AtomicUsize,
    /// How many shutdown stops asked the record helper to pause an active
    /// run first.
    #[cfg(all(test, target_os = "linux"))]
    shutdown_pause_checks: std::sync::atomic::AtomicUsize,
    /// How many session records retention removed after asking the record
    /// helper to resolve what could then never resume.
    #[cfg(all(test, target_os = "linux"))]
    prune_retire_checks: std::sync::atomic::AtomicUsize,
    /// How many explicit stops of a conversation that was not running asked
    /// the record helper to end its paused messages.
    #[cfg(all(test, target_os = "linux"))]
    stopped_pause_checks: std::sync::atomic::AtomicUsize,
}

/// The fenced interrupt recorded for an explicit stop or restart, before it
/// is delivered to the incarnation that was inspected.
#[cfg(target_os = "linux")]
struct StopInterrupt {
    environment: String,
    driver_id: String,
    message_id: String,
    deliver: bool,
    token: Uuid,
    control: mpsc::Sender<SessionControl>,
    deadline: tokio::time::Instant,
}

struct SessionHandle {
    metadata: AsyncMutex<PersistedSession>,
    /// Whether the session has a platform managed origin, which is set
    /// when the session is created; a Resume only replaces one origin with
    /// another. Input reads it here, never under `metadata`, which output
    /// capture holds across its writes and fsyncs.
    #[cfg(target_os = "linux")]
    platform_managed: std::sync::atomic::AtomicBool,
    output_index: Mutex<Vec<OutputFrameIndex>>,
    /// The output end offset, published after each capture is recorded, so
    /// an attachment reads new output at once instead of on its next poll.
    output_end: watch::Sender<u64>,
    operation: AsyncMutex<()>,
    launch_cancellation: watch::Sender<bool>,
    /// The clients attached now, and the timer of a session launched with
    /// `end_after_detached_seconds`; see [`unattended`].
    presence: Mutex<unattended::Presence>,
    /// That launch setting, which the record keeps for its whole life.
    end_after_detached: Option<Duration>,
}

impl SessionHandle {
    fn new(metadata: PersistedSession, output_index: Vec<OutputFrameIndex>) -> Arc<Self> {
        let end_after_detached = (metadata.end_after_detached_seconds != 0)
            .then(|| Duration::from_secs(metadata.end_after_detached_seconds.into()));
        Arc::new(Self {
            #[cfg(target_os = "linux")]
            platform_managed: std::sync::atomic::AtomicBool::new(
                metadata.platform_managed_origin.is_some(),
            ),
            output_end: watch::channel(metadata.output_end_offset).0,
            metadata: AsyncMutex::new(metadata),
            output_index: Mutex::new(output_index),
            operation: AsyncMutex::new(()),
            launch_cancellation: watch::channel(false).0,
            presence: Mutex::new(unattended::Presence::default()),
            end_after_detached,
        })
    }
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

/// Times the phases of one input or resize and, when the whole call is slow,
/// logs which phase waited: a lock, the session monitor or the PTY.
struct SlowControl<'a> {
    operation: &'static str,
    session_id: &'a str,
    started: Instant,
    mark: Instant,
    phases: Vec<(&'static str, u128)>,
}

impl<'a> SlowControl<'a> {
    fn new(operation: &'static str, session_id: &'a str) -> Self {
        let now = Instant::now();
        Self {
            operation,
            session_id,
            started: now,
            mark: now,
            phases: Vec::new(),
        }
    }

    fn phase(&mut self, name: &'static str) {
        let now = Instant::now();
        self.phases
            .push((name, now.duration_since(self.mark).as_millis()));
        self.mark = now;
    }
}

impl Drop for SlowControl<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed >= SLOW_SESSION_CONTROL {
            tracing::warn!(
                session_id = self.session_id,
                operation = self.operation,
                elapsed_ms = elapsed.as_millis(),
                phases_ms = ?self.phases,
                "terminal session control was slow"
            );
        }
    }
}

enum SessionControl {
    Stop {
        reply: oneshot::Sender<()>,
        /// The status a confirmed stop records; `None` is "session stopped".
        reason: Option<String>,
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
        reason: Option<String>,
    },
}

struct ProcessMonitor {
    inner: Weak<SessionEngineInner>,
    session_id: String,
    token: Uuid,
    handle: Arc<SessionHandle>,
    #[cfg(unix)]
    host_group: Option<crate::host_process::OwnedProcessGroup>,
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

#[cfg(unix)]
struct HostPtyProcessMonitor {
    inner: Weak<SessionEngineInner>,
    session_id: String,
    token: Uuid,
    handle: Arc<SessionHandle>,
    // Drop ordering must signal before the child's own reap/drop machinery.
    group: crate::host_process::OwnedProcessGroup,
    child: crate::execution::PtyLaunchGuard,
    control: mpsc::Receiver<SessionControl>,
    pty_control: std_mpsc::Sender<PtyRuntimeControl>,
    control_thread: std::thread::JoinHandle<()>,
    output_task: JoinHandle<Result<(), SessionError>>,
    io_cancel: Arc<std::sync::atomic::AtomicBool>,
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
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_origin: Option<crate::host_control::Origin>,
    // A platform correlation never confers Host/Mesh grants or CW-update authority.
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform_managed_origin: Option<crate::platform_managed::Origin>,
    // Incarnation identity is admitted durably before launch effects. Zero is
    // an older record without a usable guarded-restart token.
    #[serde(default)]
    launch_generation: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    parent_session_id: Option<String>,
    state: i32,
    command: Vec<String>,
    working_dir: String,
    // Launch values stay with the live owner. Legacy values are discarded on
    // recovery; a saved record is not authority to replay an old projection.
    #[serde(skip_serializing, default)]
    env: Vec<String>,
    #[serde(default)]
    environment_projection_required: bool,
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
    // The launch setting: end once no client has been attached this long.
    // Zero, and every record written before it existed, never ends.
    #[serde(default)]
    end_after_detached_seconds: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PersistedTimestamp {
    seconds: i64,
    nanos: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("{0}")]
    AlreadyExists(String),
    #[error("{0}")]
    DeadlineExceeded(String),
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
    /// The durable store did not open, so no session request ran. Its reason
    /// names paths, modes and record checks, never values.
    #[error("session store refused: {0}")]
    StoreRefused(String),
    /// A restart that is refused the same way on every later attempt.
    #[error("{1}")]
    NeverRestarts(NeverRestarts, String),
}

/// Why a session can never be started again. A restart refused for one of
/// these is refused the same way on every later attempt, so a caller that
/// keeps work for the session's next start can stop waiting for it.
///
/// The reason travels with the refusal's gRPC status as metadata, beside the
/// code and message the refusal always had: [`Self::status`] writes it and
/// [`Self::of`] reads it. No caller decides this from a message's text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeverRestarts {
    /// The daemon has no record of the session.
    NoSession,
    /// The session was launched with inline environment values, which are
    /// not kept across a daemon restart.
    ProjectionLost,
    /// The cleanup of the session's last process was never confirmed.
    CleanupUnconfirmed,
    /// The session has used every launch generation.
    GenerationExhausted,
}

impl NeverRestarts {
    pub const ALL: [Self; 4] = [
        Self::NoSession,
        Self::ProjectionLost,
        Self::CleanupUnconfirmed,
        Self::GenerationExhausted,
    ];
    const METADATA_KEY: &str = "codewire-never-restarts";

    fn name(self) -> &'static str {
        match self {
            Self::NoSession => "no-session",
            Self::ProjectionLost => "projection-lost",
            Self::CleanupUnconfirmed => "cleanup-unconfirmed",
            Self::GenerationExhausted => "generation-exhausted",
        }
    }

    /// The refusal as the daemon answers it.
    pub fn status(self, message: impl Into<String>) -> Status {
        let mut status = match self {
            Self::NoSession => Status::not_found(message),
            Self::ProjectionLost | Self::CleanupUnconfirmed => Status::failed_precondition(message),
            Self::GenerationExhausted => Status::resource_exhausted(message),
        };
        status.metadata_mut().insert(
            Self::METADATA_KEY,
            tonic::metadata::MetadataValue::from_static(self.name()),
        );
        status
    }

    /// The reason a refusal carries, if it carries one.
    pub fn of(status: &Status) -> Option<Self> {
        let name = status.metadata().get(Self::METADATA_KEY)?.to_str().ok()?;
        Self::ALL.into_iter().find(|reason| reason.name() == name)
    }
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

    /// Test-only: holds a session's metadata lock, as output capture does
    /// across each chunk's write and fdatasync, from `held` until `release`.
    #[cfg(test)]
    pub(crate) async fn hold_test_metadata_lock(
        &self,
        session_id: &str,
        held: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    ) -> Result<(), SessionError> {
        let handle = self.handle(session_id)?;
        let _metadata = handle.metadata.lock().await;
        let _ = held.send(());
        let _ = release.await;
        Ok(())
    }

    /// This engine's host bounds ([`HostBounds::PRODUCT`] in the product).
    #[cfg(target_os = "linux")]
    pub(crate) fn host_bounds(&self) -> HostBounds {
        self.inner.host_bounds
    }

    pub(crate) fn new(config: &Config, credential_bridge: CredentialBridge) -> Self {
        Self::with_host_bounds(config, credential_bridge, HostBounds::PRODUCT)
    }

    /// [`Self::new`] with `bounds` in place of host sessions' product bounds.
    /// A test whose subject is none of them lengthens them into a hang guard
    /// ([`HostBounds::all`]), so a stalled CI slot cannot spend one and turn
    /// a confirmed stop into an unknown one.
    pub(crate) fn with_host_bounds(
        config: &Config,
        credential_bridge: CredentialBridge,
        bounds: HostBounds,
    ) -> Self {
        Self {
            inner: Arc::new(SessionEngineInner {
                config: config.clone(),
                credential_bridge,
                root: match &config.host {
                    Some(host) => host.state_root.join("sessions"),
                    None => config.home_root.join(SESSION_DIRECTORY),
                },
                initialized: OnceCell::new(),
                sessions: Mutex::new(BTreeMap::new()),
                active: Mutex::new(HashMap::new()),
                retention_admission: AsyncMutex::new(()),
                launch_admission: Mutex::new(()),
                launches: TaskTracker::new(),
                shutdown: CancellationToken::new(),
                store_refusal: Mutex::new(None),
                host_bounds: bounds,
                #[cfg(all(test, target_os = "linux"))]
                stop_interrupt_checks: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(all(test, target_os = "linux"))]
                shutdown_pause_checks: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(all(test, target_os = "linux"))]
                prune_retire_checks: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(all(test, target_os = "linux"))]
                stopped_pause_checks: std::sync::atomic::AtomicUsize::new(0),
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

    /// The daemon is going down: nothing more launches. A host daemon first
    /// marks its environment as being taken down, so the marker is on disk
    /// before a cancelled launch or [`Self::shutdown`] signals any session.
    /// A marker that cannot be written is logged; a driver without it leaves
    /// its run to the next start, as after a crash.
    pub(crate) fn cancel_launches(&self) {
        if let Some(host) = &self.inner.config.host
            && let Err(error) = crate::stop_evidence::mark_takedown(&host.state_root)
        {
            tracing::warn!(%error, "could not mark the environment as being taken down");
        }
        let _admission = lock(&self.inner.launch_admission);
        self.inner.shutdown.cancel();
        self.inner.launches.close();
    }

    pub(crate) async fn shutdown(&self) -> Result<(), SessionError> {
        self.cancel_launches();
        let deadline = tokio::time::Instant::now() + self.inner.host_bounds.shutdown;
        tokio::time::timeout_at(deadline, self.inner.launches.wait())
            .await
            .map_err(|_| SessionError::Internal("session launch cleanup did not settle".into()))?;
        if self.inner.config.host.is_some() {
            let ids = lock(&self.inner.active).keys().cloned().collect::<Vec<_>>();
            // Every managed conversation's resumable run is paused before
            // any session is signalled: its record is then on disk whatever
            // becomes of its driver, and no record helper competes with a
            // stopping session for the short time its processes have to
            // end. What does not answer within the shutdown budget is left
            // to its driver.
            #[cfg(target_os = "linux")]
            {
                let mut pauses = tokio::task::JoinSet::new();
                for id in &ids {
                    let (engine, id) = (self.clone(), id.clone());
                    pauses.spawn(async move {
                        if let Ok(handle) = engine.handle(&id) {
                            let _operation = handle.operation.lock().await;
                            engine.pause_active_run_before_shutdown(&id, &handle).await;
                        }
                    });
                }
                while let Ok(Some(_)) = tokio::time::timeout_at(deadline, pauses.join_next()).await
                {
                }
            }
            let mut stops = tokio::task::JoinSet::new();
            for id in ids {
                let engine = self.clone();
                stops.spawn(async move { engine.stop_for_shutdown(&id).await });
            }
            while let Some(result) = tokio::time::timeout_at(deadline, stops.join_next())
                .await
                .map_err(|_| {
                    SessionError::Internal("host session shutdown did not settle".into())
                })?
            {
                result.map_err(|_| {
                    SessionError::Internal("host session shutdown task failed".into())
                })??;
            }
        }
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
        validate_session_name(&request.name)?;
        if let Some(parent) = &request.parent_session_id {
            validate_session_id(parent)?;
        }
        if request.end_after_detached_seconds
            > codewire_daemon_proto::SESSION_END_AFTER_DETACHED_MAX_SECONDS
        {
            return Err(SessionError::InvalidArgument(format!(
                "end_after_detached_seconds must be at most {}",
                codewire_daemon_proto::SESSION_END_AFTER_DETACHED_MAX_SECONDS
            )));
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
            match hosted_default_working_dir(&self.inner.config).await {
                Some(directory) => directory,
                None => self.inner.config.home_root.to_string_lossy().into_owned(),
            }
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
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            if !request.name.is_empty() && handle.metadata.lock().await.name == request.name {
                return Err(SessionError::AlreadyExists(format!(
                    "session name is already retained: {}",
                    request.name
                )));
            }
        }
        if let Some(parent) = &request.parent_session_id {
            self.handle(parent)?;
        }
        self.make_record_room_preserving(request.parent_session_id.as_deref())
            .await?;
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        let session_id = self.create_session_id().await?;
        let persisted = PersistedSession {
            session_id: session_id.clone(),
            #[cfg(target_os = "linux")]
            control_origin: None,
            #[cfg(target_os = "linux")]
            platform_managed_origin: None,
            launch_generation: 1,
            name: request.name,
            parent_session_id: request.parent_session_id,
            state: v1::SessionLifecycleState::Starting as i32,
            command,
            working_dir,
            environment_projection_required: !request.env.is_empty(),
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
            end_after_detached_seconds: request.end_after_detached_seconds,
        };
        let handle = SessionHandle::new(persisted, Vec::new());
        let _operation = handle.operation.lock().await;
        {
            let metadata = handle.metadata.lock().await;
            persist_metadata(&self.inner.root, &metadata).await?;
        }
        lock(&self.inner.sessions).insert(session_id.clone(), handle.clone());
        drop(admission);
        let record = self.start_process(handle.clone(), &cancel).await?;
        // A session nobody ever attaches to ends after its grace too.
        self.arm_unattended(&session_id, &handle);
        Ok(record)
    }

    #[cfg(test)]
    async fn make_record_room(&self) -> Result<(), SessionError> {
        self.make_record_room_preserving(None).await
    }

    async fn make_record_room_preserving(&self, parent: Option<&str>) -> Result<(), SessionError> {
        drain_retired_records(&self.inner.root).await?;
        prune_session_records_preserving(&self.inner, MAX_SESSION_RECORDS - 1, true, parent).await
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

    /// An explicit stop: a client asked for it. A host owner's managed
    /// conversation has the stop recorded first; see
    /// [`Self::record_stop_intent`]. A managed conversation whose agent takes
    /// it then has its active run interrupted; see
    /// [`Self::interrupt_active_run_before_stop`].
    pub async fn stop(&self, session_id: &str) -> Result<v1::SessionRecord, SessionError> {
        let handle = self.admit_stop(session_id).await?;
        #[cfg(target_os = "linux")]
        if owner_conversation(&self.inner.config, &*handle.metadata.lock().await).is_some() {
            // From its recorded intent on, the stop finishes even if this
            // caller goes away: a conversation is never left running with a
            // stop recorded against it.
            let engine = self.clone();
            let session_id = session_id.to_owned();
            return tokio::spawn(async move {
                engine.record_stop_intent(&session_id)?;
                engine.stop_admitted(&session_id, handle).await
            })
            .await
            .map_err(|_| {
                SessionError::Internal("session stop outcome could not be confirmed".into())
            })?;
        }
        self.stop_admitted(session_id, handle).await
    }

    /// Records, before anything of an explicit stop or restart can signal a
    /// host owner's managed conversation, that the stop is explicit: a stop
    /// intent in the session's own directory (see [`crate::stop_evidence`]).
    /// The daemon writes it itself, so it does not depend on the
    /// conversation's record helper. The conversation's driver reads it when
    /// its stop signal arrives and never pauses the run; if the driver is
    /// killed first, the conversation's next start reads it and never resumes
    /// the run. A stop whose intent cannot be written signals nothing and
    /// fails.
    #[cfg(target_os = "linux")]
    fn record_stop_intent(&self, session_id: &str) -> Result<(), SessionError> {
        let Some(host) = &self.inner.config.host else {
            return Ok(());
        };
        crate::stop_evidence::record_stop_intent(&host.state_root, session_id).map_err(|error| {
            SessionError::Internal(format!(
                "could not record the stop of session {session_id}; nothing was signalled: {error}"
            ))
        })
    }

    async fn stop_admitted(
        &self,
        session_id: &str,
        handle: Arc<SessionHandle>,
    ) -> Result<v1::SessionRecord, SessionError> {
        // Interrupt a pending projection before waiting for the serial session
        // operation lock. A queued Stop must not wait for secret delivery.
        handle.launch_cancellation.send_replace(true);
        #[cfg(target_os = "linux")]
        if let Some(interrupt) = self
            .interrupt_active_run_before_stop(session_id, &handle)
            .await
        {
            // Once its interrupt is recorded, the stop finishes even if this
            // caller goes away, so a conversation is never left interrupted
            // but running.
            let engine = self.clone();
            let session_id = session_id.to_owned();
            return tokio::spawn(async move {
                let _operation = handle.operation.lock().await;
                engine
                    .finish_interrupt_before_stop(&session_id, interrupt)
                    .await;
                engine.stop_active(&session_id, &handle).await
            })
            .await
            .map_err(|_| {
                SessionError::Internal("session stop outcome could not be confirmed".into())
            })?;
        }
        let _operation = handle.operation.lock().await;
        #[cfg(target_os = "linux")]
        self.end_paused_run_of_stopped_conversation(session_id, &handle)
            .await;
        self.stop_active(session_id, &handle).await
    }

    /// An explicit stop of a managed conversation that is not running asks
    /// its record helper to end a message that its environment's takedown
    /// paused: the conversation's next start would otherwise resume a run
    /// its owner has since stopped. A running conversation never comes
    /// here; its active run is interrupted instead. Every such stop of a
    /// host owner's own managed driver costs one bounded helper run; a
    /// refusal or timeout is logged and the stop answers as before.
    #[cfg(target_os = "linux")]
    async fn end_paused_run_of_stopped_conversation(
        &self,
        session_id: &str,
        handle: &SessionHandle,
    ) {
        use crate::host_control::managed;
        if lock(&self.inner.active).contains_key(session_id) {
            return;
        }
        let (environment, driver_id) = {
            let metadata = handle.metadata.lock().await;
            if is_live_state(metadata.state) {
                return;
            }
            let Some(conversation) = owner_conversation(&self.inner.config, &metadata) else {
                return;
            };
            conversation
        };
        #[cfg(test)]
        self.inner
            .stopped_pause_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match managed::helper_within(
            &self.inner.config,
            &environment,
            managed::stop_paused(&driver_id, session_id),
            managed::RESOLVE_PAUSED_BOUND,
        )
        .await
        {
            Ok(reply) => {
                if reply["resolved"]
                    .as_array()
                    .is_some_and(|resolved| !resolved.is_empty())
                {
                    tracing::info!(
                        session_id,
                        driver_id = driver_id.as_str(),
                        resolved = %reply["resolved"],
                        "ended the paused messages of a stopped conversation"
                    );
                }
            }
            Err(_) => tracing::warn!(
                session_id,
                driver_id = driver_id.as_str(),
                "could not check a stopped conversation for paused messages; its next start resumes them"
            ),
        }
    }

    /// Daemon shutdown stops each session without interrupting an agent's
    /// run: like a crash, kill or host reboot, it leaves the run resumable.
    /// [`Self::shutdown`] has by then paused each managed conversation's run
    /// that its agent can resume; see
    /// [`Self::pause_active_run_before_shutdown`].
    async fn stop_for_shutdown(&self, session_id: &str) -> Result<v1::SessionRecord, SessionError> {
        let handle = self.admit_stop(session_id).await?;
        handle.launch_cancellation.send_replace(true);
        let _operation = handle.operation.lock().await;
        self.stop_active(session_id, &handle).await
    }

    /// Before shutdown signals any session, asks the record helper of each
    /// running managed conversation on a trusted host to pause its active
    /// run: the message is recorded paused and its parent's notice queued
    /// before the first signal, so neither depends on what the driver
    /// manages to do between its SIGTERM and SIGKILL. The helper decides
    /// from the conversation's own state: it pauses only a run the agent can
    /// resume (noel) and answers at once for any other.
    ///
    /// The daemon cannot tell an agent's kind from a session, so every
    /// shutdown stop of a running managed driver costs one helper run,
    /// bounded well inside the shutdown budget. An explicit stop or restart
    /// never comes here: it interrupts instead. Shutdown itself does not
    /// cancel the helper, which exists because of it. A refusal or timeout is
    /// logged and the stop goes on; the driver then decides by its own
    /// evidence of the takedown.
    #[cfg(target_os = "linux")]
    async fn pause_active_run_before_shutdown(&self, session_id: &str, handle: &SessionHandle) {
        use crate::host_control::managed;
        let (environment, driver_id) = {
            let metadata = handle.metadata.lock().await;
            if metadata.state != v1::SessionLifecycleState::Running as i32 {
                return;
            }
            let Some(conversation) = owner_conversation(&self.inner.config, &metadata) else {
                return;
            };
            conversation
        };
        #[cfg(test)]
        self.inner
            .shutdown_pause_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match managed::helper_within(
            &self.inner.config,
            &environment,
            managed::pause_before_shutdown(&driver_id, session_id),
            managed::SHUTDOWN_PAUSE_BOUND,
        )
        .await
        {
            Ok(reply) => {
                if let Some(message_id) = reply["paused"].as_str() {
                    tracing::info!(
                        session_id,
                        driver_id = driver_id.as_str(),
                        message_id,
                        "paused the active run before shutting down"
                    );
                }
            }
            Err(_) => tracing::warn!(
                session_id,
                driver_id = driver_id.as_str(),
                "could not check for an active run to pause before shutting down; its driver decides by the takedown marker"
            ),
        }
    }

    async fn admit_stop(&self, session_id: &str) -> Result<Arc<SessionHandle>, SessionError> {
        self.ensure_initialized().await?;
        validate_session_id(session_id)?;
        let handle = self.handle(session_id)?;
        #[cfg(target_os = "linux")]
        refuse_platform_managed_bypass(&*handle.metadata.lock().await)?;
        Ok(handle)
    }

    /// Before an explicit stop or restart signals a running managed
    /// conversation on a trusted host, asks its record helper to interrupt
    /// the active run, so the message ends interrupted and its parent is
    /// notified first. The helper decides from the conversation's own
    /// config: it records the fenced interrupt only for an agent that takes
    /// one (noel) and answers at once for any other. The interrupt is then
    /// delivered and awaited by [`Self::finish_interrupt_before_stop`].
    ///
    /// The daemon cannot tell an agent's kind from a session, so every stop
    /// of a running managed driver costs one helper run. Daemon shutdown
    /// never comes here. A refusal or timeout is logged and the stop goes on,
    /// leaving the message's outcome unknown as before.
    #[cfg(target_os = "linux")]
    async fn interrupt_active_run_before_stop(
        &self,
        session_id: &str,
        handle: &SessionHandle,
    ) -> Option<StopInterrupt> {
        use crate::host_control::managed;
        let environment = self
            .inner
            .config
            .host
            .as_ref()?
            .state_root
            .file_name()?
            .to_str()?
            .to_owned();
        let (driver_id, token, control) = {
            let metadata = handle.metadata.lock().await;
            let driver_id = metadata.command.get(5)?.clone();
            if metadata.state != v1::SessionLifecycleState::Running as i32
                || metadata.pty
                || metadata.platform_managed_origin.is_some()
                || crate::host_control::canonical_uuid(&environment).is_err()
                || crate::host_control::canonical_uuid(&driver_id).is_err()
                || !managed::driver_command_shape(&metadata.command, &environment, &driver_id)
            {
                return None;
            }
            let (token, control) = lock(&self.inner.active)
                .get(session_id)
                .map(|active| (active.token, active.control.clone()))?;
            (driver_id, token, control)
        };
        #[cfg(test)]
        self.inner
            .stop_interrupt_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + managed::STOP_INTERRUPT_BOUND;
        let reply = tokio::select! {
            biased;
            _ = self.inner.shutdown.cancelled() => return None,
            reply = tokio::time::timeout_at(
                deadline,
                managed::helper(
                    &self.inner.config,
                    &environment,
                    managed::interrupt_before_stop(&driver_id, session_id),
                ),
            ) => reply,
        };
        let reply = match reply {
            Ok(Ok(reply)) => reply,
            outcome => {
                tracing::warn!(
                    session_id,
                    driver_id = driver_id.as_str(),
                    timed_out = outcome.is_err(),
                    "could not check for an active run to interrupt before stopping; stopping without it"
                );
                return None;
            }
        };
        let interrupt = &reply["interrupt"];
        if interrupt.is_null() {
            return None;
        }
        let message_id = interrupt["message_id"]
            .as_str()
            .filter(|id| crate::host_control::canonical_uuid(id).is_ok());
        let (Some(message_id), Some(deliver)) = (message_id, interrupt["deliver"].as_bool()) else {
            tracing::warn!(
                session_id,
                driver_id = driver_id.as_str(),
                "the record helper answered an unusable interrupt; stopping without it"
            );
            return None;
        };
        Some(StopInterrupt {
            environment,
            driver_id,
            message_id: message_id.to_owned(),
            deliver,
            token,
            control,
            deadline,
        })
    }

    /// Delivers a recorded interrupt to the incarnation it was recorded for,
    /// then lets the helper wait, at most 10 s, for the interrupted message to
    /// end and its parent notification to be written. Bounded as a whole by
    /// the recording's deadline; daemon shutdown ends the wait at once.
    #[cfg(target_os = "linux")]
    async fn finish_interrupt_before_stop(&self, session_id: &str, interrupt: StopInterrupt) {
        use crate::host_control::managed;
        let settle = async {
            if interrupt.deliver {
                let current = lock(&self.inner.active)
                    .get(session_id)
                    .is_some_and(|active| active.token == interrupt.token);
                if !current {
                    // Another stop or restart already ended this incarnation.
                    return Ok(serde_json::Value::Null);
                }
                let line = managed::line(&interrupt.driver_id, &interrupt.message_id, false)
                    .map_err(|_| "the control line could not be encoded")?;
                self.host_managed_input(interrupt.control.clone(), line)
                    .await
                    .map_err(|_| "the driver did not acknowledge the control line")?;
            }
            managed::helper_within(
                &self.inner.config,
                &interrupt.environment,
                managed::await_interrupt_before_stop(
                    &interrupt.driver_id,
                    session_id,
                    &interrupt.message_id,
                ),
                managed::STOP_INTERRUPT_BOUND,
            )
            .await
            .map_err(|_| "the record helper refused or timed out")
        };
        let outcome = tokio::select! {
            biased;
            _ = self.inner.shutdown.cancelled() => Err("the daemon is shutting down"),
            outcome = tokio::time::timeout_at(interrupt.deadline, settle) => {
                outcome.unwrap_or(Err("the bound expired"))
            }
        };
        match outcome {
            Ok(serde_json::Value::Null) => {}
            Ok(settled) if settled["settled"].as_bool() == Some(true) => tracing::info!(
                session_id,
                driver_id = interrupt.driver_id.as_str(),
                message_id = interrupt.message_id.as_str(),
                message_state = settled["message_state"].as_str().unwrap_or("-"),
                notification_state = settled["notification_state"].as_str().unwrap_or("-"),
                "interrupted the active run before stopping"
            ),
            Ok(settled) => tracing::warn!(
                session_id,
                driver_id = interrupt.driver_id.as_str(),
                message_id = interrupt.message_id.as_str(),
                message_state = settled["message_state"].as_str().unwrap_or("-"),
                interrupt_state = settled["interrupt_state"].as_str().unwrap_or("-"),
                "the active run did not end before stopping; its outcome stays unknown"
            ),
            Err(reason) => tracing::warn!(
                session_id,
                driver_id = interrupt.driver_id.as_str(),
                message_id = interrupt.message_id.as_str(),
                reason,
                "the interrupt before stopping did not settle; the run's outcome stays unknown"
            ),
        }
    }

    async fn stop_active(
        &self,
        session_id: &str,
        handle: &SessionHandle,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.stop_active_because(session_id, handle, None).await
    }

    /// [`Self::stop_active`], recording `reason` as the stopped session's
    /// status in place of "session stopped". The caller holds the session's
    /// operation lock.
    async fn stop_active_because(
        &self,
        session_id: &str,
        handle: &SessionHandle,
        reason: Option<String>,
    ) -> Result<v1::SessionRecord, SessionError> {
        let control = lock(&self.inner.active)
            .get(session_id)
            .map(|active| active.control.clone());

        if let Some(control) = control {
            let (reply_tx, reply_rx) = oneshot::channel();
            if control
                .send(SessionControl::Stop {
                    reply: reply_tx,
                    reason,
                })
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
        self.restart_with_generation(session_id, None).await
    }

    /// A guarded restart consumes one terminal incarnation. A stale or missing
    /// token cannot interrupt an admitted replacement, even after caller loss.
    pub async fn restart_with_generation(
        &self,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<v1::SessionRecord, SessionError> {
        let engine = self.clone();
        let session_id = session_id.to_string();
        self.own_launch(move |cancel| async move {
            engine
                .restart_inner(&session_id, expected_launch_generation, cancel)
                .await
        })
        .await
    }

    async fn restart_inner(
        &self,
        session_id: &str,
        expected_launch_generation: Option<u64>,
        cancel: CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        let admission = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            admission = self.inner.retention_admission.lock() => admission,
        };
        validate_session_id(session_id)?;
        let handle = self.handle(session_id).map_err(|error| match error {
            SessionError::NotFound(message) => {
                SessionError::NeverRestarts(NeverRestarts::NoSession, message)
            }
            error => error,
        })?;
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        {
            let metadata = handle.metadata.lock().await;
            #[cfg(target_os = "linux")]
            refuse_platform_managed_bypass(&metadata)?;
            #[cfg(target_os = "linux")]
            if metadata.control_origin.as_ref().is_some_and(|origin| {
                metadata
                    .session_id
                    .strip_prefix("session-")
                    .is_some_and(|driver| {
                        crate::host_control::managed::driver_command_shape(
                            &metadata.command,
                            &origin.scope.environment_id,
                            driver,
                        )
                    })
            }) {
                return Err(SessionError::FailedPrecondition(
                    "member managed restart requires its exact guardian and target-owned generation transaction".into()));
            }
            if metadata.environment_projection_required && metadata.env.is_empty() {
                return Err(SessionError::NeverRestarts(
                    NeverRestarts::ProjectionLost,
                    "the launch environment projection is no longer available after daemon recovery; launch a new session with the required environment overrides".into(),
                ));
            }
        }
        // Legacy Restart may interrupt a pending projection before acquiring
        // the operation lock. A guarded caller must first prove it still owns
        // the terminal incarnation; it cannot cancel another caller's launch.
        if expected_launch_generation.is_none() {
            handle.launch_cancellation.send_replace(true);
        }
        let _operation = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            operation = handle.operation.lock() => operation,
        };
        let next_generation = {
            let metadata = handle.metadata.lock().await;
            if let Some(expected) = expected_launch_generation {
                if expected == 0 || metadata.launch_generation != expected {
                    return Err(SessionError::FailedPrecondition(
                        "session launch generation changed or is unavailable; restart was not admitted"
                            .into(),
                    ));
                }
                if !matches!(
                    lifecycle_state(metadata.state),
                    v1::SessionLifecycleState::Exited
                        | v1::SessionLifecycleState::Stopped
                        | v1::SessionLifecycleState::Failed
                        | v1::SessionLifecycleState::Interrupted
                ) || lock(&self.inner.active).contains_key(session_id)
                {
                    return Err(SessionError::FailedPrecondition(
                        "guarded restart requires a terminal session with confirmed cleanup".into(),
                    ));
                }
            }
            if metadata.cleanup_unknown {
                return Err(SessionError::NeverRestarts(
                    NeverRestarts::CleanupUnconfirmed,
                    "session launch cleanup is unconfirmed; restart is unavailable".into(),
                ));
            }
            metadata.launch_generation.checked_add(1).ok_or_else(|| {
                SessionError::NeverRestarts(
                    NeverRestarts::GenerationExhausted,
                    "session launch generation is exhausted; launch a new session".into(),
                )
            })?
        };
        if lock(&self.inner.active).contains_key(session_id) {
            // An explicit restart of a running conversation records its stop
            // and interrupts an agent's active run first, as an explicit
            // stop does. A restart of a conversation that is not running
            // stops nothing and records nothing: it is how a run resumes.
            #[cfg(target_os = "linux")]
            {
                if owner_conversation(&self.inner.config, &*handle.metadata.lock().await).is_some()
                {
                    self.record_stop_intent(session_id)?;
                }
                if let Some(interrupt) = self
                    .interrupt_active_run_before_stop(session_id, &handle)
                    .await
                {
                    self.finish_interrupt_before_stop(session_id, interrupt)
                        .await;
                }
            }
            // Once Stop is dispatched, retain the operation lock until the
            // previous monitor settles. Caller loss cannot cancel its cleanup.
            self.stop_active(session_id, &handle).await?;
        }
        // Stop can settle Interrupted when group/join/drain cleanup failed.
        // Do not overwrite that newly published fence with a new launch.
        if handle.metadata.lock().await.cleanup_unknown {
            return Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                "session process cleanup is unconfirmed; restart is unavailable".into(),
            ));
        }
        if cancel.is_cancelled() {
            return Err(launch_cancelled_error());
        }
        handle.launch_cancellation.send_replace(false);

        {
            let mut metadata = handle.metadata.lock().await;
            metadata.launch_generation = next_generation;
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
        let record = self.start_process(handle.clone(), &cancel).await?;
        // The new incarnation has the whole grace while nobody is attached.
        self.arm_unattended(session_id, &handle);
        Ok(record)
    }

    /// The session's output end offset, changed whenever output is recorded.
    /// An attachment waits on it so a keystroke's echo is sent as soon as it
    /// is captured (#3827).
    pub(crate) fn watch_output(
        &self,
        session_id: &str,
    ) -> Result<watch::Receiver<u64>, SessionError> {
        Ok(self.handle(session_id)?.output_end.subscribe())
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
        let mut timing = SlowControl::new("input", session_id);
        self.ensure_initialized().await?;
        validate_session_id(session_id)?;
        if data.is_empty() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let retained = { lock(&self.inner.sessions).get(session_id).cloned() };
            // This also covers Attach input, which calls input directly
            // rather than SendSessionInput.
            if retained.is_some_and(|handle| {
                handle
                    .platform_managed
                    .load(std::sync::atomic::Ordering::Acquire)
            }) {
                return Err(platform_managed_bypass_refused());
            }
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
        timing.phase("monitor_queue");
        let reply = reply_rx.await;
        timing.phase("pty_write");
        reply
            .map_err(|_| {
                SessionError::FailedPrecondition(format!(
                    "session {session_id} stopped while accepting input"
                ))
            })?
            .map_err(SessionError::FailedPrecondition)
    }

    pub async fn send_input(&self, session_id: &str, data: Vec<u8>) -> Result<(), SessionError> {
        if data.is_empty() || data.len() > SESSION_INPUT_MAX_BYTES {
            return Err(SessionError::InvalidArgument(
                "session input must contain 1..65536 bytes".into(),
            ));
        }
        // Queueing, write and acknowledgement share one budget. Cancellation
        // after a partial write is inherently ambiguous; never replay it.
        tokio::time::timeout(SESSION_INPUT_TIMEOUT, self.input(session_id, data))
            .await
            .map_err(|_| SessionError::DeadlineExceeded("session input acknowledgement timed out; input may have been written; do not retry automatically".into()))?
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
        let mut timing = SlowControl::new("resize", session_id);
        let handle = self.handle(session_id)?;
        let _operation = handle.operation.lock().await;
        timing.phase("operation_lock");
        if !handle.metadata.lock().await.pty {
            return Err(SessionError::FailedPrecondition(format!(
                "session {session_id} is not a PTY session"
            )));
        }
        timing.phase("metadata_lock");
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
        timing.phase("pty_resize");

        let mut metadata = handle.metadata.lock().await;
        timing.phase("metadata_lock_again");
        metadata.width = width;
        metadata.height = height;
        metadata.status_message = format!("session resized to {width}x{height}");
        persist_metadata(&self.inner.root, &metadata).await?;
        timing.phase("persist");
        Ok(metadata.to_record())
    }

    /// A refused store is not cached: each request repeats every check, so a
    /// corrected owner or mode is admitted without restarting the daemon.
    /// Every refusal precedes the request's own effects, so it is returned as
    /// `StoreRefused`, never as an ambiguous outcome.
    async fn ensure_initialized(&self) -> Result<(), SessionError> {
        self.inner
            .initialized
            .get_or_try_init(|| async {
                let result = self.inner.initialize().await;
                let mut last = lock(&self.inner.store_refusal);
                match result {
                    Ok(()) => {
                        if last.take().is_some() {
                            tracing::info!("workspace daemon: the session store opened");
                        }
                        Ok(())
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        if last.as_deref() != Some(reason.as_str()) {
                            tracing::error!(
                                %reason,
                                "workspace daemon: the session store is refused; every session request fails until it is corrected"
                            );
                            *last = Some(reason.clone());
                        }
                        Err(SessionError::StoreRefused(reason))
                    }
                }
            })
            .await
            .map(|_| ())
    }

    /// The store's refusal for health diagnostics, once a request has met one.
    pub(crate) fn store_diagnostic(&self) -> Option<v1::HealthDiagnostic> {
        lock(&self.inner.store_refusal)
            .as_ref()
            .map(|reason| v1::HealthDiagnostic {
                name: "session-store".into(),
                healthy: false,
                message: format!("refused: {reason}"),
            })
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn initialize_host_control(&self) -> Result<(), SessionError> {
        if self.inner.config.host.is_none() {
            return Err(SessionError::FailedPrecondition(
                "host control requires the host owner".into(),
            ));
        }
        self.ensure_initialized().await
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_host_control_stage(
        bytes: &[u8],
        origin: &crate::host_control::Origin,
    ) -> Result<(), crate::host_control::Error> {
        use crate::host_control::Error;
        let metadata: PersistedSession =
            serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
        if metadata.platform_managed_origin.is_some()
            || metadata.control_origin.as_ref() != Some(origin)
            || metadata.session_id != format!("session-{}", origin.request_id)
            || metadata.launch_generation != 1
            || metadata.state != v1::SessionLifecycleState::Starting as i32
            || metadata.started_at.is_some()
            || metadata.finished_at.is_some()
            || metadata.exit_code.is_some()
            || metadata.output_end_offset != 0
            || metadata.output_start_offset != 0
            || !metadata.cleanup_unknown
            || metadata.cleanup_confirmed
            || !metadata.env.is_empty()
            || metadata.environment_projection_required
            || (metadata.parent_session_id.is_some()
                && !crate::host_control::managed::driver_command_shape(
                    &metadata.command,
                    &origin.scope.environment_id,
                    &origin.request_id,
                ))
        {
            return Err(Error::Storage);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn execute_host_control(
        &self,
        owner: crate::host_control::Owner,
        request: crate::host_control::Mutation,
    ) -> Result<v1::SessionRecord, crate::host_control::Error> {
        use crate::host_control::{Error, Operation};
        if self.inner.config.host.is_none()
            || request.scope.environment_id != owner.environment_id()
        {
            return Err(Error::Denied);
        }
        match &request.operation {
            Operation::Launch(launch) => {
                let launch = launch.clone();
                let engine = self.clone();
                self.own_launch(move |cancel| async move {
                    engine
                        .launch_host_control(owner, request, launch, None, cancel)
                        .await
                })
                .await
                .map_err(|_| Error::Unavailable)
            }
            Operation::Input(input) => {
                let input = input.clone();
                self.with_host_control_process(
                    owner,
                    request,
                    &input.session_id,
                    input.expected_launch_generation,
                    Some(input.data),
                )
                .await
            }
            Operation::Stop(stop) => {
                let stop = stop.clone();
                self.with_host_control_process(
                    owner,
                    request,
                    &stop.session_id,
                    stop.expected_launch_generation,
                    None,
                )
                .await
            }
            Operation::ManagedLaunch(managed) => {
                if !owner.managed_agents() {
                    return Err(Error::Unavailable);
                }
                let managed = managed.clone();
                let command = crate::host_control::managed::driver_command(
                    &self.inner.config,
                    owner.environment_id(),
                    &request.request_id,
                )?;
                let launch = v1::HostControlLaunch {
                    command,
                    working_dir: managed.working_dir.clone(),
                    name: managed.name.clone(),
                    pty: false,
                    term: String::new(),
                    width: 0,
                    height: 0,
                };
                let engine = self.clone();
                self.own_launch(move |cancel| async move {
                    engine
                        .launch_host_control(owner, request, launch, Some(managed), cancel)
                        .await
                })
                .await
                .map_err(|_| Error::Unavailable)
            }
            Operation::ManagedControl(control) => {
                if !owner.managed_agents() {
                    return Err(Error::Unavailable);
                }
                let control = control.clone();
                self.with_host_managed_process(owner, request, control)
                    .await
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn launch_host_control(
        &self,
        owner: crate::host_control::Owner,
        request: crate::host_control::Mutation,
        launch: v1::HostControlLaunch,
        mut managed: Option<v1::HostControlManagedLaunch>,
        cancel: CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        self.ensure_initialized().await?;
        let admission = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(launch_cancelled_error()),
            admission = self.inner.retention_admission.lock() => admission,
        };
        let session_id = format!("session-{}", request.request_id);
        if lock(&self.inner.sessions).contains_key(&session_id) {
            return Err(SessionError::AlreadyExists(
                "controlled session identity is already retained".into(),
            ));
        }
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            if !launch.name.is_empty() && handle.metadata.lock().await.name == launch.name {
                return Err(SessionError::AlreadyExists(
                    "controlled session name is already retained".into(),
                ));
            }
        }
        let working_dir = if launch.working_dir.is_empty() {
            match hosted_default_working_dir(&self.inner.config).await {
                Some(directory) => directory,
                None => self
                    .inner
                    .config
                    .workspace_root
                    .to_string_lossy()
                    .into_owned(),
            }
        } else {
            launch.working_dir
        };
        if !path_is_directory(&working_dir).await {
            return Err(SessionError::InvalidArgument(
                "controlled session working directory is unavailable".into(),
            ));
        }
        if let Some(managed) = &mut managed {
            managed.working_dir = working_dir.clone();
        }
        let parent = match managed
            .as_ref()
            .filter(|value| !value.parent_session_id.is_empty())
        {
            Some(value) => Some(self.handle(&value.parent_session_id)?),
            None => None,
        };
        let _parent_operation = match &parent {
            Some(handle) => Some(handle.operation.lock().await),
            None => None,
        };
        if let (Some(parent), Some(managed)) = (&parent, &managed) {
            let metadata = parent.metadata.lock().await;
            if metadata.platform_managed_origin.is_some()
                || metadata.launch_generation != managed.expected_parent_launch_generation
                || metadata.cleanup_unknown
                || !metadata
                    .control_origin
                    .as_ref()
                    .is_some_and(|origin| origin.scope.same_principal(&request.scope))
                || !crate::host_control::managed::driver_command_shape(
                    &metadata.command,
                    owner.environment_id(),
                    managed
                        .parent_session_id
                        .strip_prefix("session-")
                        .unwrap_or_default(),
                )
            {
                return Err(SessionError::FailedPrecondition(
                    "controlled parent binding changed".into(),
                ));
            }
        }
        let handle = SessionHandle::new(
            PersistedSession {
                session_id: session_id.clone(),
                control_origin: Some(request.origin()),
                platform_managed_origin: None,
                launch_generation: 1,
                name: launch.name,
                parent_session_id: managed
                    .as_ref()
                    .filter(|m| !m.parent_session_id.is_empty())
                    .map(|m| m.parent_session_id.clone()),
                state: v1::SessionLifecycleState::Starting as i32,
                command: launch.command,
                working_dir,
                env: Vec::new(),
                environment_projection_required: false,
                pty: launch.pty,
                term: launch.term,
                width: launch.width,
                height: launch.height,
                created_at: PersistedTimestamp::now(),
                started_at: None,
                finished_at: None,
                exit_code: None,
                output_end_offset: 0,
                output_start_offset: 0,
                cleanup_confirmed: false,
                cleanup_unknown: true,
                status_message: "session starting".into(),
                end_after_detached_seconds: 0,
            },
            Vec::new(),
        );
        let _operation = handle.operation.lock().await;
        // Retention -> exact session operation -> grant/journal. This must
        // precede even pruning or directory creation, not only process spawn.
        owner.issue(&request).await.map_err(|_| {
            SessionError::FailedPrecondition("controlled launch admission refused".into())
        })?;
        self.make_record_room_preserving(None).await?;
        if let Some(managed) = &managed {
            let refused =
                |_| SessionError::FailedPrecondition("managed preparation refused".into());
            let prepared = crate::host_control::managed::helper(
                &self.inner.config,
                owner.environment_id(),
                crate::host_control::managed::prepare(&request.origin(), managed)
                    .map_err(refused)?,
            )
            .await
            .map_err(refused)?;
            if prepared["driver_id"].as_str() != Some(request.request_id.as_str())
                || prepared["message_id"].as_str()
                    != Some(if managed.prompt.is_some() {
                        request.request_id.as_str()
                    } else {
                        ""
                    })
            {
                return Err(SessionError::FailedPrecondition(
                    "managed preparation identity changed".into(),
                ));
            }
        }
        {
            let metadata = handle.metadata.lock().await;
            let bytes = serde_json::to_vec(&*metadata)
                .map_err(|_| SessionError::Internal("encode controlled session".into()))?;
            owner
                .publish_session(&request, &bytes)
                .await
                .map_err(|_| SessionError::Internal("publish controlled session".into()))?;
        }
        lock(&self.inner.sessions).insert(session_id, handle.clone());
        drop(_parent_operation);
        drop(admission);
        self.start_process(handle.clone(), &cancel).await
    }

    #[cfg(target_os = "linux")]
    async fn with_host_control_process(
        &self,
        owner: crate::host_control::Owner,
        request: crate::host_control::Mutation,
        session_id: &str,
        generation: u64,
        input: Option<Vec<u8>>,
    ) -> Result<v1::SessionRecord, crate::host_control::Error> {
        use crate::host_control::Error;
        self.ensure_initialized()
            .await
            .map_err(|_| Error::Unavailable)?;
        validate_session_id(session_id).map_err(|_| Error::Invalid)?;
        let handle = self.handle(session_id).map_err(|_| Error::Unavailable)?;
        let cancel = owner.cancellation();
        let _operation = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Closed),
            operation = handle.operation.lock() => operation,
        };
        let metadata = handle.metadata.lock().await;
        if metadata.platform_managed_origin.is_some()
            || !metadata
                .control_origin
                .as_ref()
                .is_some_and(|origin| origin.scope.same_principal(&request.scope))
        {
            return Err(Error::Denied);
        }
        if generation == 0 || metadata.launch_generation != generation || metadata.cleanup_unknown {
            return Err(Error::Unavailable);
        }
        if crate::host_control::managed::is_driver(&metadata.command) {
            // Raw terminal actions cannot bypass managed turn/custody admission.
            return Err(Error::Denied);
        }
        let captured = lock(&self.inner.active)
            .get(session_id)
            .map(|active| (active.token, active.control.clone()));
        if input.is_some()
            && (metadata.state != v1::SessionLifecycleState::Running as i32 || captured.is_none())
        {
            return Err(Error::Unavailable);
        }
        if captured.is_none() && is_live_state(metadata.state) {
            return Err(Error::Unavailable);
        }
        drop(metadata);
        owner.issue(&request).await?;
        if let Some((_token, control)) = captured {
            let dispatch = async {
                match input {
                    Some(data) => {
                        let (reply, received) = oneshot::channel();
                        control
                            .send(SessionControl::Input { data, reply })
                            .await
                            .map_err(|_| Error::Unavailable)?;
                        // The owning task keeps this receiver alive across RPC
                        // loss, including the monitor's bounded write/flush.
                        received
                            .await
                            .map_err(|_| Error::Unavailable)?
                            .map_err(|_| Error::Unavailable)?;
                    }
                    None => {
                        // Unlike legacy local Stop, no flag can precede admission.
                        handle.launch_cancellation.send_replace(true);
                        let (reply, received) = oneshot::channel();
                        control
                            .send(SessionControl::Stop {
                                reply,
                                reason: None,
                            })
                            .await
                            .map_err(|_| Error::Unavailable)?;
                        received.await.map_err(|_| Error::Unavailable)?;
                    }
                }
                Ok::<_, Error>(())
            };
            // Queueing and the monitor's write/flush or cleanup share one
            // bound. An issued timeout is retained Unknown, never replayable.
            tokio::time::timeout(self.inner.host_bounds.control_dispatch, dispatch)
                .await
                .map_err(|_| Error::Unavailable)??;
        }
        let record = handle.metadata.lock().await.to_record();
        if record.launch_generation != generation
            || (request.verb() == v1::HostControlVerb::Stop
                && (is_live_state(record.state) || record.cleanup_unknown))
        {
            return Err(Error::Unavailable);
        }
        Ok(record)
    }

    #[cfg(target_os = "linux")]
    async fn with_host_managed_process(
        &self,
        owner: crate::host_control::Owner,
        request: crate::host_control::Mutation,
        control: v1::HostControlManagedControl,
    ) -> Result<v1::SessionRecord, crate::host_control::Error> {
        use crate::host_control::{Error, managed};
        use serde_json::json;
        self.ensure_initialized()
            .await
            .map_err(|_| Error::Unavailable)?;
        let cancellation = owner.cancellation();
        // Retention -> exact incarnation operation -> grant/journal. The
        // captured control belongs to this incarnation even if its monitor dies.
        let admission = tokio::select! {
            biased;
            _=cancellation.cancelled()=>return Err(Error::Closed),
            admission=self.inner.retention_admission.lock()=>admission,
        };
        let handle = self
            .handle(&control.session_id)
            .map_err(|_| Error::Unavailable)?;
        let _operation = tokio::select! {
            biased;
            _=cancellation.cancelled()=>return Err(Error::Closed),
            operation=handle.operation.lock()=>operation,
        };
        let metadata = handle.metadata.lock().await;
        if metadata.platform_managed_origin.is_some()
            || !metadata
                .control_origin
                .as_ref()
                .is_some_and(|origin| origin.scope.same_principal(&request.scope))
        {
            return Err(Error::Denied);
        }
        if metadata.launch_generation != control.expected_launch_generation
            || !managed::driver_command_shape(
                &metadata.command,
                owner.environment_id(),
                &control.driver_id,
            )
            || metadata.pty
            || metadata.environment_projection_required
        {
            return Err(Error::Unavailable);
        }
        let captured = lock(&self.inner.active)
            .get(&control.session_id)
            .map(|active| (active.token, active.control.clone()));
        let action = v1::HostManagedAction::try_from(control.action).map_err(|_| Error::Invalid)?;
        let shutdown = matches!(
            action,
            v1::HostManagedAction::Stop | v1::HostManagedAction::Restart
        );
        if !shutdown
            && (metadata.state != v1::SessionLifecycleState::Running as i32
                || metadata.cleanup_unknown
                || captured.is_none())
        {
            return Err(Error::Unavailable);
        }
        if captured.is_none() && is_live_state(metadata.state) {
            return Err(Error::Unavailable);
        }
        drop(metadata);

        // Captured peer evidence is read-only. Missing/stale/unknown proof can
        // never grant restart; a guardian remains responsible after driver death.
        let peer = if shutdown {
            Some(
                managed::helper(
                    &self.inner.config,
                    owner.environment_id(),
                    managed::scoped(
                        "peer_status",
                        &request.scope,
                        &control.driver_id,
                        &control.session_id,
                    ),
                )
                .await?,
            )
        } else {
            None
        };
        if let Some(peer) = &peer {
            let identity = &peer["peer"]["identity"];
            if identity["environment_id"].as_str() != Some(owner.environment_id())
                || identity["driver_id"].as_str() != Some(control.driver_id.as_str())
                || identity["session_id"].as_str() != Some(control.session_id.as_str())
                || peer["peer"]["cleanup_unknown"].as_bool().is_none()
            {
                return Err(Error::Unavailable);
            }
            crate::host_control::canonical_uuid(
                identity["instance_id"].as_str().ok_or(Error::Unavailable)?,
            )?;
        }
        if action == v1::HostManagedAction::Restart {
            // Admission of B must retain A's exact immutable executable, not
            // the latest selected host cw or a caller-controlled path.
            let metadata = handle.metadata.lock().await;
            let expected = managed::driver_command(
                &self.inner.config,
                owner.environment_id(),
                &control.driver_id,
            )?;
            if metadata.command != expected {
                return Err(Error::Unavailable);
            }
            metadata
                .launch_generation
                .checked_add(1)
                .ok_or(Error::Capacity)?;
        }
        owner.issue(&request).await?;
        if !shutdown {
            let queued = managed::helper(
                &self.inner.config,
                owner.environment_id(),
                managed::queue(&request.origin(), &control)?,
            )
            .await?;
            if queued["message_id"].as_str() != Some(request.request_id.as_str()) {
                return Err(Error::Unavailable);
            }
            let (_, sender) = captured.ok_or(Error::Unavailable)?;
            let delivered = self
                .host_managed_input(
                    sender,
                    managed::line(&control.driver_id, &request.request_id, false)?,
                )
                .await;
            let mut outcome = managed::scoped(
                "mark_delivery",
                &request.scope,
                &control.driver_id,
                &control.session_id,
            );
            outcome["message_id"] = json!(request.request_id);
            outcome["outcome"] = json!(if delivered.is_ok() {
                "written"
            } else {
                "ambiguous_failure"
            });
            // Lost pipe ACK never downgrades a native Accepted/Completed record.
            managed::helper(&self.inner.config, owner.environment_id(), outcome).await?;
            delivered?;
            let record = handle.metadata.lock().await.to_record();
            if record.launch_generation != control.expected_launch_generation {
                return Err(Error::Unavailable);
            }
            return Ok(record);
        }

        let peer = peer.ok_or(Error::Unavailable)?;
        let identity = peer["peer"]["identity"].clone();
        let instance = identity["instance_id"]
            .as_str()
            .ok_or(Error::Unavailable)?
            .to_owned();
        crate::host_control::canonical_uuid(&instance)?;
        let clean = peer["peer"]["cleanup_unknown"].as_bool() == Some(false)
            && peer["peer"]["finished_at"].as_str().is_some();
        if !clean {
            let mut shutdown = managed::scoped(
                "shutdown",
                &request.scope,
                &control.driver_id,
                &control.session_id,
            );
            shutdown["operation_id"] = json!(request.request_id);
            shutdown["peer"] = identity;
            managed::helper(&self.inner.config, owner.environment_id(), shutdown).await?;
            if let Some((_, sender)) = captured {
                // This is only a wake hint. The durable intent is independently
                // adopted by the exact driver, including after pipe ambiguity.
                let _ = self
                    .host_managed_input(
                        sender,
                        managed::line(&control.driver_id, &request.request_id, true)?,
                    )
                    .await;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut read = managed::scoped(
                if clean { "peer_status" } else { "get_shutdown" },
                &request.scope,
                &control.driver_id,
                &control.session_id,
            );
            if !clean {
                read["operation_id"] = json!(request.request_id);
                read["instance_id"] = json!(instance);
            }
            let status = managed::helper(&self.inner.config, owner.environment_id(), read).await?;
            if status["peer"]["identity"]["instance_id"].as_str() != Some(instance.as_str()) {
                return Err(Error::Unavailable);
            }
            let record = handle.metadata.lock().await.to_record();
            if record.launch_generation != control.expected_launch_generation {
                return Err(Error::Unavailable);
            }
            let peer_clean = status["peer"]["cleanup_unknown"].as_bool() == Some(false)
                && status["peer"]["finished_at"].as_str().is_some();
            let shutdown_clean = clean
                || (status["shutdown"]["cleanup_unknown"].as_bool() == Some(false)
                    && status["shutdown"]["finished_at"].as_str().is_some());
            if peer_clean
                && shutdown_clean
                && !is_live_state(record.state)
                && !record.cleanup_unknown
                && !lock(&self.inner.active).contains_key(&control.session_id)
            {
                if action == v1::HostManagedAction::Stop {
                    return Ok(record);
                }
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The same operation guard covers old family closure and authoritative
        // generation CAS. Persist B before spawn; failures never reset to A.
        handle.launch_cancellation.send_replace(false);
        {
            let mut metadata = handle.metadata.lock().await;
            if metadata.launch_generation != control.expected_launch_generation
                || metadata.cleanup_unknown
                || is_live_state(metadata.state)
            {
                return Err(Error::Unavailable);
            }
            metadata.launch_generation = metadata
                .launch_generation
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            metadata.state = v1::SessionLifecycleState::Starting as i32;
            metadata.started_at = None;
            metadata.finished_at = None;
            metadata.exit_code = None;
            metadata.cleanup_unknown = true;
            metadata.cleanup_confirmed = false;
            metadata.status_message = "managed session restarting".into();
            persist_metadata(&self.inner.root, &metadata)
                .await
                .map_err(|_| Error::Storage)?;
        }
        // The private mailbox generation advances only after the authoritative
        // session CAS and old guardian closure. A crash between these writes
        // fences B instead of adopting A's unissued messages or replaying them.
        let mut advance = managed::scoped(
            "advance_generation",
            &request.scope,
            &control.driver_id,
            &control.session_id,
        );
        advance
            .as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("scope");
        advance["origin"] = json!(request.origin());
        advance["expected_generation"] = json!(control.expected_launch_generation);
        let advanced = managed::helper(&self.inner.config, owner.environment_id(), advance).await?;
        if advanced["launch_generation"].as_u64()
            != control.expected_launch_generation.checked_add(1)
        {
            return Err(Error::Unavailable);
        }
        drop(admission);
        let _ = self.start_process(handle.clone(), &cancellation).await;
        Ok(handle.metadata.lock().await.to_record())
    }

    #[cfg(target_os = "linux")]
    async fn host_managed_input(
        &self,
        sender: mpsc::Sender<SessionControl>,
        data: Vec<u8>,
    ) -> Result<(), crate::host_control::Error> {
        use crate::host_control::Error;
        tokio::time::timeout(SESSION_INPUT_TIMEOUT, async {
            let (reply, received) = oneshot::channel();
            sender
                .send(SessionControl::Input { data, reply })
                .await
                .map_err(|_| Error::Unavailable)?;
            received
                .await
                .map_err(|_| Error::Unavailable)?
                .map_err(|_| Error::Unavailable)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn read_host_managed(
        &self,
        owner: &crate::host_control::Owner,
        request: &v1::HostControlManagedReadRequest,
        scope: &crate::host_control::Scope,
    ) -> Result<Vec<u8>, crate::host_control::Error> {
        use crate::host_control::{Error, managed};
        use serde_json::json;
        self.ensure_initialized()
            .await
            .map_err(|_| Error::Unavailable)?;
        let handle = self
            .handle(&request.session_id)
            .map_err(|_| Error::Unavailable)?;
        let _operation = handle.operation.lock().await;
        let metadata = handle.metadata.lock().await;
        if metadata.launch_generation != request.expected_launch_generation
            || !metadata
                .control_origin
                .as_ref()
                .is_some_and(|o| o.scope.same_principal(scope))
            || !managed::driver_command_shape(
                &metadata.command,
                owner.environment_id(),
                &request.driver_id,
            )
        {
            return Err(Error::Denied);
        }
        drop(metadata);
        // A reader queued behind an incarnation operation must re-admit its
        // current explicit read grant after that operation, including revoke.
        owner.authorize_managed_read(scope).await?;
        let mut read = managed::scoped("read", scope, &request.driver_id, &request.session_id);
        read["message_id"] = json!(request.message_id);
        read["limit"] = json!(request.limit);
        read["launch_generation"] = json!(request.expected_launch_generation);
        let value = managed::helper(&self.inner.config, owner.environment_id(), read).await?;
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?;
        if bytes.len() > managed::MAX_RECORD_REPLY {
            return Err(Error::Capacity);
        }
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn get_host_control(
        &self,
        scope: &crate::host_control::Scope,
        session_id: &str,
    ) -> Result<v1::SessionRecord, crate::host_control::Error> {
        use crate::host_control::Error;
        self.ensure_initialized()
            .await
            .map_err(|_| Error::Unavailable)?;
        validate_session_id(session_id).map_err(|_| Error::Invalid)?;
        let handle = self.handle(session_id).map_err(|_| Error::Unavailable)?;
        let metadata = handle.metadata.lock().await;
        if !metadata
            .control_origin
            .as_ref()
            .is_some_and(|origin| origin.scope.same_principal(scope))
        {
            return Err(Error::Denied);
        }
        Ok(metadata.to_record())
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn list_host_control(
        &self,
        scope: &crate::host_control::Scope,
    ) -> Result<Vec<v1::SessionRecord>, crate::host_control::Error> {
        self.ensure_initialized()
            .await
            .map_err(|_| crate::host_control::Error::Unavailable)?;
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut records = Vec::new();
        for handle in handles {
            let metadata = handle.metadata.lock().await;
            if metadata
                .control_origin
                .as_ref()
                .is_some_and(|origin| origin.scope.same_principal(scope))
            {
                records.push(metadata.to_record());
            }
        }
        records.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        Ok(records)
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
        self.start_pipe_process(handle, snapshot, cancel).await
    }

    async fn start_pipe_process(
        &self,
        handle: Arc<SessionHandle>,
        snapshot: PersistedSession,
        cancel: &CancellationToken,
    ) -> Result<v1::SessionRecord, SessionError> {
        #[cfg(target_os = "linux")]
        let platform_image = match snapshot.platform_managed_origin.as_ref() {
            Some(origin) => {
                if origin.validate(&snapshot.session_id).is_err()
                    || snapshot.command != origin.command()
                    || snapshot.launch_generation == 0
                    || !snapshot.env.is_empty()
                    || snapshot.environment_projection_required
                    || snapshot.pty
                    || snapshot.control_origin.is_some()
                {
                    return self
                        .record_unspawned_failure(handle, "platform managed process refused".into())
                        .await;
                }
                match crate::platform_managed::ImagePin::admit(&self.inner.config, origin) {
                    Ok(pin) => Some(pin),
                    Err(_) => {
                        return self
                            .record_unspawned_failure(
                                handle,
                                "platform managed image refused".into(),
                            )
                            .await;
                    }
                }
            }
            None => None,
        };
        let mut prepared = match prepare_pipe_process(
            &self.inner.config,
            &self.inner.credential_bridge,
            &snapshot,
            std::env::vars(),
        ) {
            Ok(prepared) => prepared,
            Err(message) => return self.record_unspawned_failure(handle, message).await,
        };
        let mut process = prepared.tokio_command();
        #[cfg(target_os = "linux")]
        if platform_image.is_some() {
            let parent = unsafe { libc::getpid() };
            // Fixed owned-child confinement. No daemon/foreign PID signaling
            // is exposed through the private service.
            unsafe {
                process.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != parent
                    {
                        return Err(std::io::Error::other("platform driver parent changed"));
                    }
                    Ok(())
                });
            }
        }
        #[cfg(unix)]
        if self.inner.config.host.is_some() {
            // SAFETY: prepare_host_child makes only async-signal-safe calls
            // and does not touch allocator state after fork.
            unsafe {
                process.pre_exec(prepare_host_child);
            }
        }

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
        #[cfg(unix)]
        let mut host_group = if self.inner.config.host.is_some() {
            match child.id().and_then(|pid| {
                crate::host_process::OwnedProcessGroup::new(
                    pid,
                    self.inner.host_bounds.cleanup_step,
                )
                .ok()
            }) {
                Some(group) => Some(group),
                None => {
                    let _ = terminate_native_launch(&mut child).await;
                    return self
                        .record_launch_cleanup(
                            handle,
                            false,
                            "host process ownership could not be established".into(),
                        )
                        .await;
                }
            }
        } else {
            None
        };
        let projection = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(std::io::Error::other("environment launch cancelled")),
            _ = wait_for_launch_cancellation(&handle) => Err(std::io::Error::other("environment launch cancelled")),
            result = prepared.project_spawned(child.id()) => result,
        };
        if projection.is_err() {
            let confirmed = terminate_session_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    launch_failure_status(prepared.launch_committed()).into(),
                )
                .await;
        }
        let Some(stdin) = child.stdin.take() else {
            let confirmed = terminate_session_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session stdin pipe is unavailable".into(),
                )
                .await;
        };
        let Some(stdout) = child.stdout.take() else {
            let confirmed = terminate_session_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    "session stdout pipe is unavailable".into(),
                )
                .await;
        };
        let Some(stderr) = child.stderr.take() else {
            let confirmed = terminate_session_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
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
            let confirmed = terminate_session_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
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
                #[cfg(unix)]
                host_group,
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
        #[cfg(unix)]
        let mut host_group = if self.inner.config.host.is_some() {
            match child.process_id().and_then(|pid| {
                crate::host_process::OwnedProcessGroup::new(
                    pid,
                    self.inner.host_bounds.cleanup_step,
                )
                .ok()
            }) {
                Some(group) => Some(group),
                None => {
                    let _ = child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await;
                    return self
                        .record_launch_cleanup(
                            handle,
                            false,
                            "host PTY ownership could not be established".into(),
                        )
                        .await;
                }
            }
        } else {
            None
        };
        let projection = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(std::io::Error::other("environment launch cancelled")),
            _ = wait_for_launch_cancellation(&handle) => Err(std::io::Error::other("environment launch cancelled")),
            result = prepared.project_spawned(child.process_id()) => result,
        };
        if projection.is_err() {
            #[cfg(target_os = "macos")]
            drop(pair.master);
            let confirmed = terminate_session_pty_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
            return self
                .record_launch_cleanup(
                    handle,
                    confirmed,
                    launch_failure_status(prepared.launch_committed()).into(),
                )
                .await;
        }

        #[cfg(unix)]
        if host_group.is_some()
            && let Err(error) = set_host_pty_nonblocking(&*pair.master)
        {
            #[cfg(target_os = "macos")]
            drop(pair.master);
            let confirmed = terminate_session_pty_launch(&mut child, host_group.as_mut()).await;
            return self
                .record_launch_cleanup(handle, confirmed, format!("prepare host PTY: {error}"))
                .await;
        }

        let reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(error) => {
                #[cfg(target_os = "macos")]
                drop(pair.master);
                let confirmed = terminate_session_pty_launch(
                    &mut child,
                    #[cfg(unix)]
                    host_group.as_mut(),
                )
                .await;
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
                #[cfg(target_os = "macos")]
                drop((reader, pair.master));
                let confirmed = terminate_session_pty_launch(
                    &mut child,
                    #[cfg(unix)]
                    host_group.as_mut(),
                )
                .await;
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
            #[cfg(target_os = "macos")]
            drop((reader, writer, pair.master));
            let confirmed = terminate_session_pty_launch(
                &mut child,
                #[cfg(unix)]
                host_group.as_mut(),
            )
            .await;
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

        #[cfg(unix)]
        if let Some(group) = host_group {
            let io_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (output_tx, output_rx) = mpsc::channel(32);
            let reader_cancel = io_cancel.clone();
            let reader_thread = tokio::task::spawn_blocking(move || {
                copy_host_pty_output(reader, output_tx, reader_cancel)
            });
            let output_task = tokio::spawn(capture_pty_output(
                self.inner.root.clone(),
                handle.clone(),
                output_rx,
                reader_thread,
            ));
            let (pty_control_tx, pty_control_rx) = std_mpsc::channel();
            let control_cancel = io_cancel.clone();
            let control_thread = std::thread::spawn(move || {
                host_pty_control_loop(pair.master, writer, pty_control_rx, control_cancel)
            });
            let (control_tx, control_rx) = mpsc::channel(32);
            let (start_tx, start_rx) = oneshot::channel();
            let token = Uuid::new_v4();
            let monitor = HostPtyProcessMonitor {
                inner: Arc::downgrade(&self.inner),
                session_id: snapshot.session_id.clone(),
                token,
                handle: monitor_handle,
                group,
                child,
                control: control_rx,
                pty_control: pty_control_tx,
                control_thread,
                output_task,
                io_cancel,
            };
            let task = tokio::spawn(async move {
                let _ = start_rx.await;
                monitor_host_pty_process(monitor).await;
            });
            lock(&self.inner.active).insert(
                snapshot.session_id,
                ActiveSession {
                    token,
                    control: control_tx,
                    task,
                },
            );
            return self.complete_handoff(handle, start_tx, record).await;
        }

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
        _record: v1::SessionRecord,
    ) -> Result<v1::SessionRecord, SessionError> {
        // The active monitor now owns the child. Caller loss must not stop it.
        let result = {
            let mut metadata = handle.metadata.lock().await;
            metadata.cleanup_unknown = false;
            metadata.cleanup_confirmed = false;
            persist_metadata(&self.inner.root, &metadata)
                .await
                .map(|()| metadata.to_record())
        };
        let _ = start.send(());
        result
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
        self.config
            .validate_host()
            .map_err(|error| SessionError::FailedPrecondition(error.to_string()))?;
        if self.config.host.is_some()
            && tokio::fs::symlink_metadata(&self.root)
                .await
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(SessionError::FailedPrecondition(
                "host session root must not be a symlink".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        let platform_tree = if crate::platform_managed::Service::available(&self.config) {
            Some(
                crate::platform_managed::Tree::open(&self.root, true).map_err(|_| {
                    SessionError::FailedPrecondition(crate::platform_managed::tree_refusal(
                        &self.root,
                    ))
                })?,
            )
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let platform_tree: Option<()> = None;
        if platform_tree.is_none() {
            tokio::fs::create_dir_all(&self.root)
                .await
                .map_err(|error| {
                    SessionError::Internal(format!(
                        "create session store {}: {error}",
                        self.root.display()
                    ))
                })?;
            set_private_directory_permissions(&self.root).await?;
        }
        if let Some(host) = &self.config.host {
            set_private_directory_permissions(&host.state_root).await?;
        }
        if platform_tree.is_none() {
            drain_retired_records(&self.root).await?;
        }

        let mut entries = tokio::fs::read_dir(&self.root).await.map_err(|error| {
            SessionError::Internal(format!(
                "read session store {}: {error}",
                self.root.display()
            ))
        })?;
        let mut loaded = BTreeMap::new();
        // A workload store skips a record it cannot read, decode or reconcile
        // instead of refusing every session request; the record stays on
        // disk. Host and platform stores keep refusing: their records carry
        // process-cleanup and admission obligations.
        let tolerate_damage = self.config.host.is_none() && platform_tree.is_none();
        let mut damaged = std::collections::BTreeSet::new();
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
                if platform_tree.is_some() {
                    return Err(SessionError::FailedPrecondition(
                        "platform retired record requires identified cleanup".into(),
                    ));
                }
                tokio::fs::remove_dir_all(entry.path())
                    .await
                    .map_err(|error| {
                        SessionError::Internal(format!("clean retired session record: {error}"))
                    })?;
                continue;
            }
            validate_session_id(&session_id)?;
            if self.config.host.is_some() {
                for name in [
                    METADATA_FILE,
                    OUTPUT_FILE,
                    METADATA_TEMP_FILE,
                    OUTPUT_TEMP_FILE,
                    crate::stop_evidence::STOP_INTENT_FILE,
                ] {
                    if let Ok(metadata) = tokio::fs::symlink_metadata(entry.path().join(name)).await
                        && !metadata.is_file()
                    {
                        return Err(SessionError::FailedPrecondition(
                            "host session state must contain only regular files".into(),
                        ));
                    }
                }
            }
            let path = entry.path().join(METADATA_FILE);
            #[cfg(target_os = "linux")]
            let private_bytes = if platform_tree.is_some() {
                let tree =
                    crate::platform_managed::Tree::open(&entry.path(), false).map_err(|_| {
                        SessionError::FailedPrecondition(crate::platform_managed::tree_refusal(
                            &entry.path(),
                        ))
                    })?;
                let refused = |name: &str, bound: usize| {
                    SessionError::FailedPrecondition(crate::platform_managed::leaf_refusal(
                        &entry.path().join(name),
                        bound,
                    ))
                };
                let bytes = tree
                    .read(METADATA_FILE, 128 * 1024)
                    .map_err(|_| refused(METADATA_FILE, 128 * 1024))?
                    .ok_or_else(|| refused(METADATA_FILE, 128 * 1024))?;
                // Admission precedes the existing bounded output-index scan.
                // No new recovery process or credential projection is started.
                let output = (2 * RETAINED_OUTPUT_BYTES
                    + 2 * RETAINED_OUTPUT_FRAMES as u64 * OUTPUT_FRAME_HEADER_SIZE as u64
                    + OUTPUT_BUFFER_SIZE as u64) as usize;
                tree.read(OUTPUT_FILE, output)
                    .map_err(|_| refused(OUTPUT_FILE, output))?
                    .ok_or_else(|| refused(OUTPUT_FILE, output))?;
                Some(bytes)
            } else {
                None
            };
            #[cfg(not(target_os = "linux"))]
            let private_bytes: Option<Vec<u8>> = None;
            let decoded = match private_bytes {
                Some(bytes) => Ok(bytes),
                None => tokio::fs::read(&path).await.map_err(|error| {
                    SessionError::Internal(format!(
                        "read session metadata {}: {error}",
                        path.display()
                    ))
                }),
            }
            .and_then(|bytes| {
                serde_json::from_slice::<PersistedSession>(&bytes).map_err(|error| {
                    // The category and position only: serde's own text can
                    // quote a record's values, such as its environment.
                    SessionError::Internal(format!(
                        "decode session metadata {}: {} at line {} column {}",
                        path.display(),
                        match error.classify() {
                            serde_json::error::Category::Io => "unreadable",
                            serde_json::error::Category::Syntax => "malformed JSON",
                            serde_json::error::Category::Data => "an unexpected field or value",
                            serde_json::error::Category::Eof => "truncated JSON",
                        },
                        error.line(),
                        error.column()
                    ))
                })
            })
            .and_then(|metadata| {
                if metadata.session_id != session_id {
                    return Err(SessionError::Internal(format!(
                        "session metadata identity mismatch in {}",
                        path.display()
                    )));
                }
                Ok(metadata)
            });
            let mut metadata = match decoded {
                Ok(metadata) => metadata,
                Err(error) if tolerate_damage => {
                    skip_damaged_session(&mut damaged, session_id, &error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            #[cfg(target_os = "linux")]
            if let Some(origin) = &metadata.control_origin {
                origin.validate().map_err(|_| {
                    SessionError::Internal("controlled session origin is invalid".into())
                })?;
                if self.config.host.is_none()
                    || format!("session-{}", origin.request_id) != session_id
                {
                    return Err(SessionError::Internal(
                        "controlled session origin identity is invalid".into(),
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(check) =
                platform_managed::retained_record_fault(&metadata, self.config.host.is_some())
            {
                return Err(SessionError::FailedPrecondition(format!(
                    "platform record {session_id}: {check}"
                )));
            }
            let legacy_projection = !metadata.env.is_empty();
            if legacy_projection {
                metadata.environment_projection_required = true;
                metadata.env.clear();
            }
            validate_session_name(&metadata.name)?;
            if let Some(parent) = &metadata.parent_session_id {
                validate_session_id(parent)?;
            }
            let (mut metadata_changed, output_index) =
                match reconcile_output_cursor(&self.root, &mut metadata).await {
                    Ok(reconciled) => reconciled,
                    Err(error) if tolerate_damage => {
                        skip_damaged_session(&mut damaged, session_id, &error);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            metadata_changed |= legacy_projection;
            if is_live_state(metadata.state) {
                metadata.state = v1::SessionLifecycleState::Interrupted as i32;
                metadata.finished_at = Some(PersistedTimestamp::now());
                metadata.exit_code = None;
                metadata.status_message =
                    "session interrupted because the environment daemon restarted".into();
                if self.config.host.is_some() || platform_tree.is_some() {
                    // Persisted PIDs can never establish ownership after restart.
                    metadata.cleanup_unknown = true;
                    metadata.cleanup_confirmed = false;
                    metadata.status_message = "host session interrupted; process cleanup is unknown; restart is unavailable".into();
                }
                metadata_changed = true;
            }
            if metadata_changed {
                persist_metadata(&self.root, &metadata).await?;
            }
            let handle = SessionHandle::new(metadata, output_index);
            compact_output(&self.root, &handle, &mut *handle.metadata.lock().await).await?;
            loaded.insert(session_id, handle);
        }
        let mut names = std::collections::BTreeSet::new();
        for handle in loaded.values() {
            let mut metadata = handle.metadata.lock().await;
            // A child keeps running history when its parent record is damaged.
            if metadata
                .parent_session_id
                .as_ref()
                .is_some_and(|id| damaged.contains(id))
            {
                metadata.parent_session_id = None;
            }
            if !metadata.name.is_empty() && !names.insert(metadata.name.clone()) {
                return Err(SessionError::Internal(
                    "duplicate retained session name".into(),
                ));
            }
            if metadata
                .parent_session_id
                .as_ref()
                .is_some_and(|id| !loaded.contains_key(id) || id == &metadata.session_id)
            {
                return Err(SessionError::Internal(
                    "retained session parent is missing or invalid".into(),
                ));
            }
        }
        *lock(&self.sessions) = loaded;
        // Grandfather unresolved records from older unbounded stores rather
        // than deleting a possible live process's recovery obligation. New
        // admission remains blocked until enough safe records are available.
        let result = prune_session_records(self, MAX_SESSION_RECORDS, false).await;
        #[cfg(target_os = "linux")]
        if let Some(tree) = platform_tree {
            tree.check().map_err(|_| {
                SessionError::FailedPrecondition("platform session store changed".into())
            })?;
        }
        result
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
    prune_session_records_preserving(inner, maximum, require_room, None).await
}

async fn prune_session_records_preserving(
    inner: &SessionEngineInner,
    maximum: usize,
    require_room: bool,
    parent: Option<&str>,
) -> Result<(), SessionError> {
    let handles = lock(&inner.sessions).values().cloned().collect::<Vec<_>>();
    let needed = handles.len().saturating_sub(maximum);
    if needed == 0 {
        return Ok(());
    }
    let mut candidates = Vec::new();
    // Keep identity-addressed parents while a retained child refers to them.
    // Admission also pins its proposed parent before pruning makes room.
    let mut referenced = std::collections::BTreeSet::new();
    if let Some(parent) = parent {
        referenced.insert(parent.to_owned());
    }
    for handle in &handles {
        if let Some(parent) = &handle.metadata.lock().await.parent_session_id {
            referenced.insert(parent.clone());
        }
    }
    for handle in handles {
        let metadata = handle.metadata.lock().await;
        let state = lifecycle_state(metadata.state);
        if (matches!(
            state,
            v1::SessionLifecycleState::Exited | v1::SessionLifecycleState::Stopped
        ) || (state == v1::SessionLifecycleState::Failed && metadata.cleanup_confirmed))
            && !metadata.cleanup_unknown
            && !referenced.contains(&metadata.session_id)
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
        #[cfg(target_os = "linux")]
        retire_managed_before_prune(inner, &session_id, &handle).await;
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

/// One pipe session's process. Every session is prepared the same way, a
/// managed agent's driver included, because a managed agent works in the
/// user's environment: the one shared builder (the Git route, the SSH signer
/// socket, the provider routes), then the launch projection when this daemon
/// has one, with its own authority check for this launch. The driver, its
/// guardian and the provider inherit the result, and the guardian adds only
/// the managed login lockdown. Nothing resolved is kept: the values exist in
/// the launcher and the processes it becomes, never in the session record.
/// `daemon_environment` is this daemon's own environment, from which the
/// builder drops the daemon's internal configuration.
fn prepare_pipe_process(
    config: &Config,
    bridge: &CredentialBridge,
    snapshot: &PersistedSession,
    daemon_environment: impl IntoIterator<Item = (String, String)>,
) -> Result<PreparedProcess, String> {
    let environment =
        build_process_env_in(config, &snapshot.env, &snapshot.term, daemon_environment)
            .map_err(|error| format!("prepare session environment: {error}"))?;
    PreparedProcess::prepare_configured(
        (config, bridge),
        &snapshot.command,
        &snapshot.working_dir,
        &environment,
        false,
        0,
        0,
    )
    .map_err(|error| format!("prepare session process: {error}"))
}

/// The environment and driver IDs of a host owner's own managed
/// conversation: the only kind of session whose run can pause or resume. A
/// member's or the platform's conversation, a terminal and every other
/// command are none.
#[cfg(target_os = "linux")]
fn owner_conversation(
    config: &crate::Config,
    metadata: &PersistedSession,
) -> Option<(String, String)> {
    let environment = config.host.as_ref()?.state_root.file_name()?.to_str()?;
    let driver_id = metadata.command.get(5)?;
    (!metadata.pty
        && metadata.platform_managed_origin.is_none()
        && metadata.control_origin.is_none()
        && crate::host_control::canonical_uuid(environment).is_ok()
        && crate::host_control::canonical_uuid(driver_id).is_ok()
        && crate::host_control::managed::driver_command_shape(
            &metadata.command,
            environment,
            driver_id,
        ))
    .then(|| (environment.to_owned(), driver_id.clone()))
}

/// Before retention removes a stopped managed conversation's session record
/// on a trusted host, asks its record helper to resolve what can then never
/// resume: a message that the environment's takedown paused ends unknown and
/// its parent hears of it once, so none stays paused with no conversation
/// behind it. The daemon cannot tell an agent's kind from a session, so each
/// such record costs one bounded helper run; a member's conversation never
/// pauses and costs none. A refusal or timeout is logged and the record is
/// removed all the same.
#[cfg(target_os = "linux")]
async fn retire_managed_before_prune(
    inner: &SessionEngineInner,
    session_id: &str,
    handle: &SessionHandle,
) {
    use crate::host_control::managed;
    let Some((environment, driver_id)) =
        owner_conversation(&inner.config, &*handle.metadata.lock().await)
    else {
        return;
    };
    #[cfg(test)]
    inner
        .prune_retire_checks
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match managed::helper_within(
        &inner.config,
        &environment,
        managed::retire_before_prune(&driver_id, session_id),
        managed::RESOLVE_PAUSED_BOUND,
    )
    .await
    {
        Ok(reply) => {
            if reply["resolved"]
                .as_array()
                .is_some_and(|resolved| !resolved.is_empty())
            {
                tracing::info!(
                    session_id,
                    driver_id = driver_id.as_str(),
                    resolved = %reply["resolved"],
                    "resolved paused messages before removing their conversation's session record"
                );
            }
        }
        Err(_) => tracing::warn!(
            session_id,
            driver_id = driver_id.as_str(),
            "could not check for paused messages before removing a conversation's session record"
        ),
    }
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
    crate::confirm::check_within(LAUNCH_CLEANUP_TIMEOUT, || match child.try_wait() {
        Ok(Some(_)) => Some(true),
        Err(_) => Some(false),
        Ok(None) => None,
    })
    .await
    .unwrap_or(false)
}

async fn terminate_session_launch(
    child: &mut Child,
    #[cfg(unix)] group: Option<&mut crate::host_process::OwnedProcessGroup>,
) -> bool {
    #[cfg(unix)]
    if let Some(group) = group {
        let signals = group.terminate().await;
        let reaped =
            crate::confirm::await_within(group.cleanup_bound(), &mut std::pin::pin!(child.wait()))
                .await;
        return signals.is_ok() && matches!(reaped, Some(Ok(_)));
    }
    terminate_native_launch(child).await
}

/// On macOS a session leader's exit waits for its terminal output to drain,
/// so launch cleanup closes every PTY master handle before waiting to reap.
async fn terminate_session_pty_launch(
    child: &mut crate::execution::PtyLaunchGuard,
    #[cfg(unix)] group: Option<&mut crate::host_process::OwnedProcessGroup>,
) -> bool {
    #[cfg(unix)]
    if let Some(group) = group {
        let signals = group.terminate().await;
        return child.terminate_confirmed(group.cleanup_bound()).await && signals.is_ok();
    }
    child.terminate_confirmed(LAUNCH_CLEANUP_TIMEOUT).await
}

async fn monitor_process(monitor: ProcessMonitor) {
    #[cfg(unix)]
    if monitor.host_group.is_some() {
        monitor_host_process(monitor).await;
        return;
    }
    let ProcessMonitor {
        inner,
        session_id,
        token,
        handle,
        #[cfg(unix)]
            host_group: _,
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
                Some(SessionControl::Stop { reply, reason }) => {
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
                        reason,
                    };
                }
                Some(SessionControl::Input { data, reply }) => {
                    let result = match stdin.as_mut() {
                        Some(stdin) => write_session_input(stdin, &data).await,
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

async fn write_session_input(stdin: &mut ChildStdin, data: &[u8]) -> Result<(), String> {
    tokio::time::timeout(SESSION_INPUT_TIMEOUT, async {
        stdin.write_all(data).await?;
        stdin.flush().await
    })
    .await
    .map_err(|_| {
        "session input write timed out; outcome is ambiguous; do not retry automatically"
            .to_string()
    })?
    .map_err(|error| format!("write session input: {error}"))
}

#[cfg(unix)]
async fn monitor_host_process(monitor: ProcessMonitor) {
    let ProcessMonitor {
        inner,
        session_id,
        token,
        handle,
        host_group,
        mut child,
        mut stdin,
        mut control,
        stdout_task,
        stderr_task,
    } = monitor;
    // Declare the group after Child: cancellation signals while Child is owned.
    let mut group = host_group.expect("host process group is owned");
    let completion = loop {
        tokio::select! {
            result = group.wait_for_exit() => {
                let signals = group.terminate().await;
                let status = crate::confirm::await_within(group.cleanup_bound(), &mut std::pin::pin!(child.wait())).await;
                break ProcessCompletion::Exited(result.map(|_| ()).and(signals)
                    .and_then(|()| status.ok_or_else(|| std::io::Error::other("host child reap timed out"))?)
                    .map(|status| status.code().unwrap_or(1)).map_err(|error| error.to_string()));
            }
            command = control.recv() => match command {
                Some(SessionControl::Stop { reply, reason }) => {
                    let result = terminate_session_launch(&mut child, Some(&mut group)).await;
                    break ProcessCompletion::Stopped { result: if result { Ok(()) } else { Err("host process cleanup could not be confirmed".into()) }, reply, reason };
                }
                Some(SessionControl::Input { data, reply }) => {
                    if reply.is_closed() { continue; }
                    let result = match stdin.as_mut() { Some(stdin) => write_session_input(stdin, &data).await,
                        None => Err("host session stdin is closed".into()) };
                    let _ = reply.send(result);
                }
                Some(SessionControl::Resize { reply, .. }) => { let _ = reply.send(Err("session is not a PTY session".into())); }
                None => {
                    let confirmed = terminate_session_launch(&mut child, Some(&mut group)).await;
                    break ProcessCompletion::Exited(if confirmed { Ok(1) } else { Err("host process cleanup could not be confirmed".into()) });
                }
            }
        }
    };
    drop(stdin);
    let bound = group.cleanup_bound();
    let (stdout, stderr) = tokio::join!(
        bounded_output_join(stdout_task, bound),
        bounded_output_join(stderr_task, bound)
    );
    finish_process(
        inner,
        session_id,
        token,
        handle,
        completion,
        stdout.or(stderr),
    )
    .await;
}

#[cfg(unix)]
async fn bounded_output_join(
    mut task: JoinHandle<Result<(), SessionError>>,
    bound: Duration,
) -> Option<String> {
    match crate::confirm::await_within(bound, &mut task).await {
        Some(Ok(Ok(()))) => None,
        Some(Ok(Err(error))) => Some(error.to_string()),
        Some(Err(error)) => Some(format!("host output task failed: {error}")),
        None => {
            task.abort();
            let _ = task.await;
            Some("host output drain timed out; cleanup is unknown".into())
        }
    }
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
                Some(SessionControl::Stop { reply, reason }) => {
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
                    break ProcessCompletion::Stopped { result, reply, reason };
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

#[cfg(unix)]
async fn monitor_host_pty_process(monitor: HostPtyProcessMonitor) {
    use std::sync::atomic::Ordering;
    let HostPtyProcessMonitor {
        inner,
        session_id,
        token,
        handle,
        group,
        mut child,
        mut control,
        pty_control,
        control_thread,
        output_task,
        io_cancel,
    } = monitor;
    // Keep the guard live until group signaling completes; never wait/reap first.
    let mut group = group;
    let completion = loop {
        tokio::select! {
            result = group.wait_for_exit() => {
                let signals = group.terminate().await;
                // WNOWAIT proved exit and kept identity reserved through signals.
                let status = child.terminate_confirmed(group.cleanup_bound()).await;
                break ProcessCompletion::Exited(if signals.is_ok() && status { result.map_err(|error| error.to_string()) }
                    else { Err("host PTY cleanup could not be confirmed".into()) });
            }
            command = control.recv() => match command {
                Some(SessionControl::Stop { reply, reason }) => {
                    io_cancel.store(true, Ordering::Release);
                    let confirmed = terminate_session_pty_launch(&mut child, Some(&mut group)).await;
                    break ProcessCompletion::Stopped { result: if confirmed { Ok(()) } else { Err("host PTY cleanup could not be confirmed".into()) }, reply, reason };
                }
                Some(SessionControl::Input { data, reply }) => {
                    if reply.is_closed() { continue; }
                    if let Err(error) = pty_control.send(PtyRuntimeControl::Input { data, reply })
                        && let PtyRuntimeControl::Input { reply, .. } = error.0 { let _ = reply.send(Err("host PTY input is closed".into())); }
                }
                Some(SessionControl::Resize { width, height, reply }) => {
                    if let Err(error) = pty_control.send(PtyRuntimeControl::Resize { width, height, reply })
                        && let PtyRuntimeControl::Resize { reply, .. } = error.0 { let _ = reply.send(Err("host PTY control is closed".into())); }
                }
                None => {
                    io_cancel.store(true, Ordering::Release);
                    let confirmed = terminate_session_pty_launch(&mut child, Some(&mut group)).await;
                    break ProcessCompletion::Exited(if confirmed { Ok(1) } else { Err("host PTY cleanup could not be confirmed".into()) });
                }
            }
        }
    };
    io_cancel.store(true, Ordering::Release);
    drop(pty_control);
    let mut join = tokio::task::spawn_blocking(move || control_thread.join());
    let control_error = match crate::confirm::await_within(group.cleanup_bound(), &mut join).await {
        Some(Ok(Ok(()))) => None,
        _ => Some("host PTY control join could not be confirmed".into()),
    };
    let output_error = bounded_output_join(output_task, group.cleanup_bound()).await;
    finish_process(
        inner,
        session_id,
        token,
        handle,
        completion,
        control_error.or(output_error),
    )
    .await;
}

#[cfg(unix)]
fn set_host_pty_nonblocking(master: &dyn portable_pty::MasterPty) -> std::io::Result<()> {
    let fd = master
        .as_raw_fd()
        .ok_or_else(|| std::io::Error::other("host PTY descriptor unavailable"))?;
    // SAFETY: the descriptor remains owned by master, and only host clones use it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn copy_host_pty_output(
    mut reader: Box<dyn Read + Send>,
    output: mpsc::Sender<Vec<u8>>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
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
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if cancel.load(std::sync::atomic::Ordering::Acquire) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(()),
            Err(error) => return Err(format!("read host PTY output: {error}")),
        }
    }
}

#[cfg(unix)]
fn host_pty_control_loop(
    master: Box<dyn portable_pty::MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    control: std_mpsc::Receiver<PtyRuntimeControl>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    while !cancel.load(Ordering::Acquire) {
        let command = match control.recv_timeout(Duration::from_millis(10)) {
            Ok(command) => command,
            Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
        };
        match command {
            PtyRuntimeControl::Input { data, reply } => {
                if reply.is_closed() {
                    continue;
                }
                let deadline = std::time::Instant::now() + SESSION_INPUT_TIMEOUT;
                let mut remaining = data.as_slice();
                let result = loop {
                    if cancel.load(Ordering::Acquire)
                        || reply.is_closed()
                        || std::time::Instant::now() >= deadline
                    {
                        break Err("host PTY input interrupted; outcome is ambiguous; do not retry automatically".into());
                    }
                    match writer.write(remaining) {
                        Ok(0) => break Err("host PTY input is closed".into()),
                        Ok(size) => {
                            remaining = &remaining[size..];
                            if remaining.is_empty() {
                                break writer.flush().map_err(|error| error.to_string());
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(error) => break Err(format!("write host PTY input: {error}")),
                    }
                };
                let _ = reply.send(result);
            }
            PtyRuntimeControl::Resize {
                width,
                height,
                reply,
            } => {
                let _ = reply.send(
                    master
                        .resize(pty_size(width, height))
                        .map_err(|error| error.to_string()),
                );
            }
        }
    }
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
            if inner.config.host.is_some() {
                metadata.cleanup_unknown =
                    completion_result(&completion).is_err() || output_error.is_some();
                metadata.cleanup_confirmed = !metadata.cleanup_unknown;
            }
            let stopped_because = match &completion {
                ProcessCompletion::Stopped { reason, .. } => reason.clone(),
                ProcessCompletion::Exited(_) => None,
            };
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
                    metadata.status_message =
                        stopped_because.unwrap_or_else(|| "session stopped".into());
                }
                (Err(error), None) => {
                    metadata.state = v1::SessionLifecycleState::Failed as i32;
                    metadata.exit_code = None;
                    metadata.status_message = error;
                }
            }
            if inner.config.host.is_some() && metadata.cleanup_unknown {
                metadata.state = v1::SessionLifecycleState::Interrupted as i32;
                metadata.status_message =
                    "host process cleanup could not be confirmed; restart is unavailable".into();
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
    // Tokio writes in the background and reports a failed write only on the
    // next write or flush; sync alone would not see it.
    file.flush()
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
    handle.output_end.send_replace(metadata.output_end_offset);
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
        .flush()
        .await
        .map_err(|error| SessionError::Internal(format!("write retained output: {error}")))?;
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

fn skip_damaged_session(
    damaged: &mut std::collections::BTreeSet<String>,
    session_id: String,
    error: &SessionError,
) {
    tracing::warn!(
        session_id = %session_id,
        error = %error,
        "workspace daemon: skipping a damaged session record"
    );
    damaged.insert(session_id);
}

async fn persist_metadata(root: &Path, metadata: &PersistedSession) -> Result<(), SessionError> {
    validate_session_id(&metadata.session_id)?;
    let directory = session_directory(root, &metadata.session_id)?;
    let path = directory.join(METADATA_FILE);
    let temporary = directory.join(METADATA_TEMP_FILE);
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|error| SessionError::Internal(format!("encode session metadata: {error}")))?;
    #[cfg(target_os = "linux")]
    if metadata.platform_managed_origin.is_some() {
        let tree = crate::platform_managed::Tree::open(&directory, false).map_err(|_| {
            SessionError::FailedPrecondition("platform session directory refused".into())
        })?;
        tree.read(METADATA_FILE, 128 * 1024)
            .map_err(|_| {
                SessionError::FailedPrecondition("platform session metadata refused".into())
            })?
            .ok_or_else(|| {
                SessionError::FailedPrecondition("platform session metadata missing".into())
            })?;
        return tree.write(METADATA_FILE, &bytes, true).map_err(|_| {
            SessionError::Internal("platform session publication outcome unknown".into())
        });
    }
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
    // A failed background write (for example ENOSPC) surfaces only here; a
    // record that is not complete must never replace the published one.
    file.flush().await.map_err(|error| {
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
    let written = file
        .metadata()
        .await
        .map_err(|error| {
            SessionError::Internal(format!(
                "inspect session metadata {}: {error}",
                temporary.display()
            ))
        })?
        .len();
    if written != bytes.len() as u64 {
        return Err(SessionError::Internal(format!(
            "session metadata {} is incomplete ({written} of {} bytes)",
            temporary.display(),
            bytes.len()
        )));
    }
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
    let id = Uuid::parse_str(raw_id).map_err(|_| {
        SessionError::InvalidArgument(format!("invalid session identifier: {session_id}"))
    })?;
    if id.to_string() != raw_id {
        return Err(SessionError::InvalidArgument(
            "session identifier must be canonical".into(),
        ));
    }
    Ok(())
}

fn validate_session_name(name: &str) -> Result<(), SessionError> {
    if !codewire_daemon_proto::valid_session_name(name) {
        return Err(SessionError::InvalidArgument("session name must be 1..64 ASCII bytes, alphanumeric first, then alphanumeric, dot, underscore or hyphen".into()));
    }
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

/// Hosted only: where a session launched without a working directory starts.
/// That is the environment's declared directory, or the workspace root while
/// the declared one does not exist (for example after a failed clone). Local
/// and host daemons return None and keep their own defaults.
async fn hosted_default_working_dir(config: &Config) -> Option<String> {
    let declared = config.session_working_dir.as_ref()?;
    let declared = declared.to_string_lossy().into_owned();
    Some(if path_is_directory(&declared).await {
        declared
    } else {
        config.workspace_root.to_string_lossy().into_owned()
    })
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
            launch_generation: self.launch_generation,
            name: self.name.clone(),
            parent_session_id: self.parent_session_id.clone(),
            cleanup_unknown: self.cleanup_unknown,
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
            end_after_detached_seconds: self.end_after_detached_seconds,
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
        SessionError::AlreadyExists(message) => Status::already_exists(message),
        SessionError::DeadlineExceeded(message) => Status::deadline_exceeded(message),
        SessionError::InvalidArgument(message) => Status::invalid_argument(message),
        SessionError::NotFound(message) => Status::not_found(message),
        SessionError::FailedPrecondition(message) => Status::failed_precondition(message),
        SessionError::ResourceExhausted(message) => Status::resource_exhausted(message),
        SessionError::Internal(message) => Status::internal(message),
        // A code no other session refusal uses: orchestration reports it as a
        // known precondition, never as an ambiguous launch or restart outcome.
        SessionError::StoreRefused(_) => Status::data_loss(error.to_string()),
        SessionError::NeverRestarts(reason, message) => reason.status(message),
    }
}

/// Prepare a host launch between fork and exec: it owns a fresh session and
/// group, and on Darwin inherits no descriptor beyond stdio.
#[cfg(unix)]
fn prepare_host_child() -> std::io::Result<()> {
    // SAFETY: setsid takes no arguments.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "macos")]
    mark_inherited_descriptors_close_on_exec();
    Ok(())
}

/// Darwin creates pipes and sockets close-on-exec only in a second call, so a
/// descriptor another thread is creating can reach a child spawned in between:
/// another session's pipe, for example, which then stays open until this
/// child exits. Between fork and exec, mark every descriptor beyond stdio
/// close-on-exec, as Linux's atomic close-on-exec flags already ensure.
#[cfg(target_os = "macos")]
fn mark_inherited_descriptors_close_on_exec() {
    // SAFETY: getdtablesize and fcntl take only scalar arguments. A number
    // that is not an open descriptor fails with EBADF and is skipped.
    unsafe {
        for descriptor in 3..libc::getdtablesize() {
            libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Bounds a wait on an event, so a hang fails instead of stalling the
    /// run. It is never the expected duration: the condition is the event,
    /// and a slow CI slot can stall a process for seconds (#3277).
    pub(super) const HANG: Duration = Duration::from_secs(60);

    #[test]
    fn slow_control_records_each_phase_in_order() {
        let mut timing = SlowControl::new("resize", "session-test");
        timing.phase("operation_lock");
        std::thread::sleep(Duration::from_millis(5));
        timing.phase("persist");
        let names: Vec<_> = timing.phases.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["operation_lock", "persist"]);
        assert!(timing.phases[1].1 >= 5);
        assert!(timing.started.elapsed() < SLOW_SESSION_CONTROL);
    }

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
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        engine.ensure_initialized().await.unwrap();
        (temp, engine)
    }

    /// An engine whose home and workspace roots are distinct directories under
    /// one temporary root. `declared` names the hosted session directory
    /// relative to that root; None is a local or host daemon.
    async fn working_dir_engine(declared: Option<&str>) -> (tempfile::TempDir, SessionEngine) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("home")).unwrap();
        std::fs::create_dir_all(temp.path().join("workspace")).unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().join("workspace"),
            home_root: temp.path().join("home"),
            auth_token: crate::DaemonAuthToken::new("synthetic-working-dir-test").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: declared.map(|relative| temp.path().join(relative)),
        };
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        engine.ensure_initialized().await.unwrap();
        (temp, engine)
    }

    fn true_request(working_dir: &Path) -> v1::LaunchSessionRequest {
        v1::LaunchSessionRequest {
            command: vec!["/bin/true".into()],
            working_dir: working_dir.to_string_lossy().into_owned(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn an_unlisted_session_starts_in_the_hosted_default_directory() {
        let unlisted = Path::new("");
        // Local and host daemons keep the home directory.
        let (temp, engine) = working_dir_engine(None).await;
        let record = engine.launch(true_request(unlisted)).await.unwrap();
        assert_eq!(Path::new(&record.working_dir), temp.path().join("home"));

        // A hosted daemon starts in the declared directory when it exists.
        let (temp, engine) = working_dir_engine(Some("workspace/app")).await;
        std::fs::create_dir(temp.path().join("workspace/app")).unwrap();
        let record = engine.launch(true_request(unlisted)).await.unwrap();
        assert_eq!(
            Path::new(&record.working_dir),
            temp.path().join("workspace/app")
        );

        // ... and in the workspace root while it does not, for example after
        // a failed clone.
        let (temp, engine) = working_dir_engine(Some("workspace/missing")).await;
        let record = engine.launch(true_request(unlisted)).await.unwrap();
        assert_eq!(
            Path::new(&record.working_dir),
            temp.path().join("workspace")
        );

        // An explicit directory is used as given and still must exist.
        let (temp, engine) = working_dir_engine(Some("workspace")).await;
        let record = engine
            .launch(true_request(&temp.path().join("home")))
            .await
            .unwrap();
        assert_eq!(Path::new(&record.working_dir), temp.path().join("home"));
        assert!(matches!(
            engine
                .launch(true_request(&temp.path().join("absent")))
                .await,
            Err(SessionError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn the_hosted_default_is_only_for_hosted_daemons() {
        let (temp, engine) = working_dir_engine(None).await;
        assert_eq!(hosted_default_working_dir(&engine.inner.config).await, None);
        drop(temp);
        let (temp, engine) = working_dir_engine(Some("workspace/missing")).await;
        assert_eq!(
            hosted_default_working_dir(&engine.inner.config).await,
            Some(temp.path().join("workspace").to_string_lossy().into_owned())
        );
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

    pub(super) async fn pending_handle(
        engine: &SessionEngine,
        marker: &Path,
    ) -> Arc<SessionHandle> {
        let session_id = engine.create_session_id().await.unwrap();
        let metadata = PersistedSession {
            session_id: session_id.clone(),
            #[cfg(target_os = "linux")]
            control_origin: None,
            #[cfg(target_os = "linux")]
            platform_managed_origin: None,
            launch_generation: 1,
            name: String::new(),
            parent_session_id: None,
            state: v1::SessionLifecycleState::Starting as i32,
            command: marker_request(marker).command,
            working_dir: engine.inner.config.home_root.to_string_lossy().into_owned(),
            env: Vec::new(),
            environment_projection_required: false,
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
            end_after_detached_seconds: 0,
        };
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
        let handle = SessionHandle::new(metadata, Vec::new());
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
        tokio::time::timeout(HANG, settled_rx)
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
            Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                _
            ))
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
            Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                _
            ))
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
        let stopped = tokio::time::timeout(HANG, stopping)
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
            let Some(SessionControl::Stop { reply, .. }) = commands.recv().await else {
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
        tokio::time::timeout(HANG, dispatched)
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
        let next = tokio::time::timeout(HANG, second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(next.session_id, id);
        tokio::time::timeout(HANG, async {
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
            Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                _
            ))
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
        let record = tokio::time::timeout(HANG, observed).await.unwrap().unwrap();
        caller.abort();
        let _ = caller.await;
        tokio::time::timeout(HANG, finished).await.unwrap().unwrap();
        assert_eq!(
            engine.get(&record.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Running as i32
        );
        engine
            .input(&record.session_id, b"still-alive\n".to_vec())
            .await
            .unwrap();
        tokio::time::timeout(HANG, async {
            while !std::fs::read_to_string(&marker).is_ok_and(|value| value == "still-alive") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        engine.stop(&record.session_id).await.unwrap();
        engine.shutdown().await.unwrap();
    }

    /// Output capture holds a session's metadata lock across its write,
    /// fsync and metadata persist, which take seconds on a loaded disk. Input
    /// must not wait for it: an attach gives each input 5 s, then ends the
    /// browser terminal (#2829).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn input_reaches_the_pty_while_output_capture_holds_the_metadata_lock() {
        let (temp, engine) = cancellation_engine().await;
        let marker = temp.path().join("typed");
        let record = engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "IFS= read -r line; printf '%s' \"$line\" > \"$1\"; exec sleep 30".into(),
                    "sh".into(),
                    marker.to_string_lossy().into_owned(),
                ],
                pty: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let handle = engine.handle(&record.session_id).unwrap();
        let capture = handle.metadata.lock().await;
        tokio::time::timeout(HANG, engine.input(&record.session_id, b"typed\n".to_vec()))
            .await
            .expect("input waited for output capture's metadata lock")
            .unwrap();
        tokio::time::timeout(HANG, async {
            while !std::fs::read_to_string(&marker).is_ok_and(|value| value == "typed") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the shell read the typed line");
        drop(capture);
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
            Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                _
            ))
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
            host: None,
            launch_projection: Some(crate::LaunchProjectionConfig {
                selection_sha256: [4; 32],
                native: Some(crate::NativeLaunchProjectionConfig {
                    helper_path: temp.path().join("must-not-inspect-helper"),
                    process_directory: temp.path().join("must-not-inspect-processes"),
                }),
            }),
            session_working_dir: None,
        };
        let bridge = CredentialBridge::new(config.credential_bridge.clone());
        let engine = SessionEngine::new(&config, bridge);
        let record = engine
            .launch(v1::LaunchSessionRequest {
                name: String::new(),
                parent_session_id: None,
                end_after_detached_seconds: 0,
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
            #[cfg(target_os = "linux")]
            control_origin: None,
            #[cfg(target_os = "linux")]
            platform_managed_origin: None,
            launch_generation: 1,
            name: String::new(),
            parent_session_id: None,
            state: v1::SessionLifecycleState::Running as i32,
            command: vec!["sh".into()],
            working_dir: root.to_string_lossy().into_owned(),
            env: Vec::new(),
            environment_projection_required: false,
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
            end_after_detached_seconds: 0,
        };
        persist_metadata(root, &metadata).await.unwrap();
        SessionHandle {
            #[cfg(target_os = "linux")]
            platform_managed: std::sync::atomic::AtomicBool::new(
                metadata.platform_managed_origin.is_some(),
            ),
            output_end: watch::channel(metadata.output_end_offset).0,
            metadata: AsyncMutex::new(metadata),
            output_index: Mutex::new(index),
            operation: AsyncMutex::new(()),
            launch_cancellation: watch::channel(false).0,
            presence: Mutex::new(unattended::Presence::default()),
            end_after_detached: None,
        }
    }

    pub(super) fn test_engine(root: &Path) -> SessionEngine {
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: root.join("workspace"),
            home_root: root.join("home"),
            auth_token: crate::DaemonAuthToken::new("synthetic-retention-test").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
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
    async fn startup_skips_damaged_records_instead_of_refusing_every_request() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let empty = record_fixture(&engine, 2, v1::SessionLifecycleState::Exited).await;
        let truncated = record_fixture(&engine, 3, v1::SessionLifecycleState::Exited).await;
        let parent = record_fixture(&engine, 4, v1::SessionLifecycleState::Exited).await;
        let child = record_fixture(&engine, 5, v1::SessionLifecycleState::Exited).await;
        let retained = record_fixture(&engine, 6, v1::SessionLifecycleState::Stopped).await;
        {
            let handle = engine.handle(&child).unwrap();
            let mut metadata = handle.metadata.lock().await;
            metadata.parent_session_id = Some(parent.clone());
            persist_metadata(&engine.inner.root, &metadata)
                .await
                .unwrap();
        }
        let root = engine.inner.root.clone();
        // What a full disk left behind before writes were verified: an empty
        // record, and a record cut short.
        tokio::fs::write(root.join(&empty).join(METADATA_FILE), b"")
            .await
            .unwrap();
        for damaged in [&truncated, &parent] {
            let path = root.join(damaged).join(METADATA_FILE);
            let bytes = tokio::fs::read(&path).await.unwrap();
            tokio::fs::write(&path, &bytes[..bytes.len() / 2])
                .await
                .unwrap();
        }

        let recovered = test_engine(temp.path());
        let mut sessions = recovered
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|session| session.session_id)
            .collect::<Vec<_>>();
        sessions.sort();
        assert_eq!(sessions, [child.clone(), retained]);
        assert!(
            recovered
                .handle(&child)
                .unwrap()
                .metadata
                .lock()
                .await
                .parent_session_id
                .is_none()
        );
        // Damaged records are left for diagnosis, never deleted.
        for damaged in [&empty, &truncated, &parent] {
            assert!(root.join(damaged).join(OUTPUT_FILE).exists());
            assert!(matches!(
                recovered.handle(damaged),
                Err(SessionError::NotFound(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_failed_metadata_write_never_replaces_the_published_record() {
        let temp = tempfile::tempdir().unwrap();
        let engine = test_engine(temp.path());
        let session_id = record_fixture(&engine, 7, v1::SessionLifecycleState::Exited).await;
        let directory = engine.inner.root.join(&session_id);
        let published = tokio::fs::read(directory.join(METADATA_FILE))
            .await
            .unwrap();
        // Every write to the temporary record fails as on a full disk.
        std::os::unix::fs::symlink("/dev/full", directory.join(METADATA_TEMP_FILE)).unwrap();
        let handle = engine.handle(&session_id).unwrap();
        let mut metadata = handle.metadata.lock().await;
        metadata.status_message = "changed while the disk is full".into();
        assert!(
            persist_metadata(&engine.inner.root, &metadata)
                .await
                .is_err()
        );
        assert_eq!(
            tokio::fs::read(directory.join(METADATA_FILE))
                .await
                .unwrap(),
            published
        );
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

    #[test]
    fn a_restart_that_is_never_admitted_carries_its_reason_beside_the_same_code_and_message() {
        for (reason, code) in [
            (NeverRestarts::NoSession, tonic::Code::NotFound),
            (
                NeverRestarts::ProjectionLost,
                tonic::Code::FailedPrecondition,
            ),
            (
                NeverRestarts::CleanupUnconfirmed,
                tonic::Code::FailedPrecondition,
            ),
            (
                NeverRestarts::GenerationExhausted,
                tonic::Code::ResourceExhausted,
            ),
        ] {
            let status =
                status_from_session_error(SessionError::NeverRestarts(reason, "refused".into()));
            assert_eq!((status.code(), status.message()), (code, "refused"));
            assert_eq!(NeverRestarts::of(&status), Some(reason));
            assert!(NeverRestarts::ALL.contains(&reason));
        }
        // No other refusal carries a reason, whatever its code and words.
        for other in [
            SessionError::NotFound("session not found".into()),
            SessionError::FailedPrecondition(
                "session launch cleanup is unconfirmed; restart is unavailable".into(),
            ),
            SessionError::ResourceExhausted(
                "session launch generation is exhausted; launch a new session".into(),
            ),
        ] {
            assert_eq!(NeverRestarts::of(&status_from_session_error(other)), None);
        }
        // A reason this build does not know decides nothing.
        let mut unknown = Status::failed_precondition("refused");
        unknown.metadata_mut().insert(
            NeverRestarts::METADATA_KEY,
            tonic::metadata::MetadataValue::from_static("a-later-reason"),
        );
        assert_eq!(NeverRestarts::of(&unknown), None);
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
            Err(SessionError::NeverRestarts(NeverRestarts::NoSession, _))
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
            #[cfg(target_os = "linux")]
            control_origin: None,
            #[cfg(target_os = "linux")]
            platform_managed_origin: None,
            launch_generation: 1,
            name: String::new(),
            parent_session_id: None,
            state: v1::SessionLifecycleState::Exited as i32,
            command: vec!["true".into()],
            working_dir: root.to_string_lossy().into_owned(),
            env: Vec::new(),
            environment_projection_required: false,
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
            end_after_detached_seconds: 0,
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

    #[cfg(target_os = "macos")]
    #[test]
    fn host_launch_inherits_no_descriptor_beyond_stdio() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        use std::os::unix::process::CommandExt as _;
        // An inheritable pipe end stands in for a pipe another session's
        // launch has created but not yet marked close-on-exec.
        let mut ends = [0; 2];
        // SAFETY: a two-element output array.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: both are fresh descriptors that only this test owns.
        let (read, _write) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // SAFETY: a scalar fcntl on an owned descriptor.
        assert_eq!(
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let inherited = |prepare: bool| {
            let mut command = std::process::Command::new("/bin/test");
            command
                .arg("-e")
                .arg(format!("/dev/fd/{}", read.as_raw_fd()));
            if prepare {
                // SAFETY: as in the host launch.
                unsafe {
                    command.pre_exec(prepare_host_child);
                }
            }
            command.status().unwrap().success()
        };
        assert!(
            inherited(false),
            "control: an inheritable descriptor reaches the child"
        );
        assert!(!inherited(true));
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "durable_session/host_tests.rs"]
mod host_tests;

#[path = "durable_session/unattended.rs"]
mod unattended;

#[cfg(target_os = "linux")]
#[path = "durable_session/platform_managed.rs"]
mod platform_managed;
#[cfg(target_os = "linux")]
use platform_managed::{platform_managed_bypass_refused, refuse_platform_managed_bypass};
