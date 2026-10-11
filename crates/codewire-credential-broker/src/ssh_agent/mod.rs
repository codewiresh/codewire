//! Isolated selected-key OpenSSH agent ownership and a finite protocol bridge.
//!
//! This is not a credential authority. Callers admit the selected protected
//! input, retain the original environment/profile/material lease and recheck
//! it before dispatch AND before releasing a signature. No raw agent socket is
//! exposed. An SSH agent signs for its caller; it does not enforce remote
//! commands/repository paths or revoke established SSH connections.
//!
//! Dropping a pending/ready handle cancels its owned worker. Await its drain
//! handle or owner shutdown before ending the runtime: only those prove child
//! drain and private tmpfs cleanup. Process death cannot guarantee cleanup.
//! Unproven drain retains the private directory rather than removing state
//! beneath a possible writer.

mod one_shot;
mod protocol;
pub use one_shot::sign_once;
#[cfg(all(test, target_os = "macos"))]
mod darwin_tests;
#[cfg(all(test, target_os = "linux"))]
mod tests;

use std::future::Future;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use crate::provider_enrollment::validate_private_directory;
#[cfg(target_os = "linux")]
use crate::provider_enrollment::validate_private_tmpfs_runtime;
use crate::provider_enrollment::{PrivateProviderHome, validate_executable};
use protocol::{FAILURE, MAX_FRAME_BYTES, REQUEST_IDENTITIES};
pub use protocol::{SshKeyAlgorithm, SshPublicIdentity};

const MAX_AGENTS: usize = 8;
const MAX_CONNECTIONS: usize = 8;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const ASKPASS_HELPER: &[u8] = include_bytes!("askpass.sh");
/// `sockaddr_un.sun_path` capacity, including the terminating NUL.
#[cfg(target_os = "linux")]
const SOCKET_PATH_BYTES: usize = 108;
#[cfg(target_os = "macos")]
const SOCKET_PATH_BYTES: usize = 104;

/// Exact public helper bytes for trusted packaging/composition. This script
/// reads only the authority-selected private FIFO; it contains no credentials.
pub fn askpass_script() -> &'static [u8] {
    ASKPASS_HELPER
}

/// Closed failures; raw tool output, key bytes and OS errors are never retained.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SshAgentError {
    #[error("SSH agent configuration is unavailable")]
    Configuration,
    #[error("SSH agent is unavailable")]
    Unavailable,
    #[error("SSH agent operation is not permitted")]
    Denied,
    #[error("SSH agent key is invalid or unsupported")]
    InvalidKey,
    #[error("SSH agent operation failed")]
    Failed,
    #[error("SSH agent operation was cancelled")]
    Cancelled,
    #[error("SSH agent operation expired")]
    Expired,
    #[error("SSH agent cleanup could not be completed")]
    Cleanup,
}

/// Administrator-owned tool paths, never paths accepted from a material RPC.
pub struct SshAgentConfig {
    runtime: PathBuf,
    agent: PathBuf,
    add: PathBuf,
    askpass: PathBuf,
    #[cfg(target_os = "macos")]
    darwin: DarwinProcessPrimitives,
    #[cfg(all(test, target_os = "linux"))]
    phase_probe: Option<Arc<tests::PhaseProbe>>,
}

/// Darwin process primitives the trusted composer supplies, because this
/// crate forbids unsafe code. Darwin creates some descriptors without an
/// atomic close-on-exec flag, so every OpenSSH child must start holding only
/// its standard descriptors; rustix offers no Apple `mkfifo`.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub struct DarwinProcessPrimitives {
    /// Arrange for the spawned child to mark every inherited descriptor above
    /// stderr close-on-exec before it executes.
    pub prepare_child: fn(&mut Command),
    /// Create an owner-only (0600) FIFO at exactly this new path.
    pub make_fifo: fn(&std::path::Path) -> std::io::Result<()>,
}

impl SshAgentConfig {
    /// Validate trusted OpenSSH executables and the installed fixed askpass
    /// helper. The helper must be executable outside a noexec tmpfs, use the
    /// checked-in script, and receive only the private FIFO path in its env.
    #[cfg(target_os = "linux")]
    pub fn new(
        runtime: PathBuf,
        agent: PathBuf,
        add: PathBuf,
        askpass: PathBuf,
    ) -> Result<Self, SshAgentError> {
        validate_private_tmpfs_runtime(&runtime).map_err(|_| SshAgentError::Configuration)?;
        Ok(Self {
            runtime,
            agent: validate_executable(&agent).map_err(|_| SshAgentError::Configuration)?,
            add: validate_executable(&add).map_err(|_| SshAgentError::Configuration)?,
            askpass: validate_askpass_helper(&askpass)?,
            #[cfg(test)]
            phase_probe: None,
        })
    }

    /// As on Linux, but macOS has no per-user tmpfs: `runtime` must be a
    /// private directory, and the staging inside it receives only the agent
    /// socket and the passphrase FIFO (see
    /// `PrivateProviderHome::create_signer_staging_in`).
    #[cfg(target_os = "macos")]
    pub fn new(
        runtime: PathBuf,
        agent: PathBuf,
        add: PathBuf,
        askpass: PathBuf,
        darwin: DarwinProcessPrimitives,
    ) -> Result<Self, SshAgentError> {
        validate_private_directory(&runtime).map_err(|_| SshAgentError::Configuration)?;
        Ok(Self {
            runtime,
            agent: validate_executable(&agent).map_err(|_| SshAgentError::Configuration)?,
            add: validate_executable(&add).map_err(|_| SshAgentError::Configuration)?,
            askpass: validate_askpass_helper(&askpass)?,
            darwin,
        })
    }
}

fn validate_askpass_helper(path: &std::path::Path) -> Result<PathBuf, SshAgentError> {
    let invalid = || SshAgentError::Configuration;
    if !path.is_absolute() || std::fs::canonicalize(path).map_err(|_| invalid())? != path {
        return Err(invalid());
    }
    let uid = rustix::process::geteuid().as_raw();
    // A different user must not be able to replace a containing directory.
    // Root-owned sticky /tmp-style ancestors do not permit that replacement.
    for parent in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| invalid())?;
        if !metadata.is_dir()
            || !matches!(metadata.uid(), owner if owner == 0 || owner == uid)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
        {
            return Err(invalid());
        }
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| invalid())?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file()
        || !matches!(metadata.uid(), owner if owner == 0 || owner == uid)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() != 1
        || metadata.len() != ASKPASS_HELPER.len() as u64
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(ASKPASS_HELPER.len());
    file.take(ASKPASS_HELPER.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes != ASKPASS_HELPER {
        return Err(invalid());
    }
    Ok(path.to_owned())
}

/// Finite process-local owner. Shutdown observes workers even when the caller
/// abandoned the start/ready future or dropped the selected key handle.
pub struct SshAgentOwner {
    config: Arc<SshAgentConfig>,
    accepting: Arc<Mutex<bool>>,
    workers: TaskTracker,
    cancellation: CancellationToken,
    capacity: Arc<Semaphore>,
    cleanup_failed: Arc<AtomicBool>,
}

impl SshAgentOwner {
    pub fn new(config: SshAgentConfig) -> Self {
        Self {
            config: Arc::new(config),
            accepting: Arc::new(Mutex::new(true)),
            workers: TaskTracker::new(),
            cancellation: CancellationToken::new(),
            capacity: Arc::new(Semaphore::new(MAX_AGENTS)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Consume exactly one explicit OpenSSH private key and optional protected
    /// passphrase. Nothing is loaded from ambient HOME, files or ssh-agent.
    /// The caller's original deadline bounds the entire worker, including start.
    pub fn start(
        &self,
        key: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
        deadline: Instant,
    ) -> Result<PendingSshAgent, SshAgentError> {
        validate_material(&key, passphrase.as_deref().map(Vec::as_slice))?;
        let now = Instant::now();
        if deadline <= now || deadline > now + MAX_LIFETIME {
            return Err(SshAgentError::Expired);
        }
        let accepting = self
            .accepting
            .lock()
            .map_err(|_| SshAgentError::Unavailable)?;
        if !*accepting || self.cleanup_failed.load(Ordering::Acquire) {
            return Err(SshAgentError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| SshAgentError::Unavailable)?;
        let cancel = self.cancellation.child_token();
        let (completion, completed) = watch::channel(None);
        let (ready, receiver) = oneshot::channel();
        let (requests, input) = mpsc::channel(MAX_CONNECTIONS);
        let config = self.config.clone();
        let worker_cancel = cancel.clone();
        let cleanup_failed = self.cleanup_failed.clone();
        let worker_accepting = Arc::clone(&self.accepting);
        self.workers.spawn(async move {
            // Track the result, not just task completion. An unexpected unwind
            // during cleanup must never become a successful owner shutdown.
            let worker = tokio::spawn(run_worker(
                config,
                key,
                passphrase,
                deadline,
                worker_cancel,
                ready,
                input,
            ));
            let result = worker.await.unwrap_or(Err(SshAgentError::Cleanup));
            // A per-worker acknowledgement permits a replacement immediately.
            // Release shared capacity only after worker cleanup has completed,
            // but before publishing that durable acknowledgement.
            if result.is_err() {
                // Serialize failure publication with start admission, before
                // returning capacity. A failed worker must not create a slot
                // in which a concurrent start can enter an unhealthy owner.
                if let Ok(mut accepting) = worker_accepting.lock() {
                    *accepting = false;
                    cleanup_failed.store(true, Ordering::Release);
                } else {
                    // Poisoned admission also fails closed in start/shutdown.
                    cleanup_failed.store(true, Ordering::Release);
                }
            }
            drop(permit);
            let _ = completion.send(Some(result));
        });
        Ok(PendingSshAgent {
            ready: Some(receiver),
            requests: Some(requests),
            drain: Some(SshAgentDrain { cancel, completed }),
            deadline,
        })
    }

    /// Stop accepting, cancel every owned worker, and prove child drain before
    /// reporting success. Abnormal worker exit also latches a cleanup failure.
    /// Repeated shutdown does not renew any signal authority.
    pub async fn shutdown(&self) -> Result<(), SshAgentError> {
        *self.accepting.lock().map_err(|_| SshAgentError::Cleanup)? = false;
        self.cancellation.cancel();
        self.workers.close();
        self.workers.wait().await;
        if self.cleanup_failed.load(Ordering::Acquire) {
            Err(SshAgentError::Cleanup)
        } else {
            Ok(())
        }
    }
}

impl Drop for SshAgentOwner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Cloneable, material-free authority to cancel and observe one owned worker.
///
/// Completion is durable and reports only drain proof: `Ok(())` means every
/// child was reaped, private staging was removed, and shared capacity was
/// released. Dropping or cancelling a waiter neither consumes that result nor
/// takes cleanup ownership away from [`SshAgentOwner`].
#[derive(Clone)]
pub struct SshAgentDrain {
    cancel: CancellationToken,
    completed: watch::Receiver<Option<Result<(), SshAgentError>>>,
}

impl SshAgentDrain {
    pub async fn cancel_and_drain(&self) -> Result<(), SshAgentError> {
        self.cancel.cancel();
        let mut completed = self.completed.clone();
        loop {
            if let Some(result) = *completed.borrow() {
                return result;
            }
            completed
                .changed()
                .await
                .map_err(|_| SshAgentError::Cleanup)?;
        }
    }
}

/// Cancellation-owning startup handle. Drop also cancels while `ready` awaits.
pub struct PendingSshAgent {
    ready: Option<oneshot::Receiver<Result<SshPublicIdentity, SshAgentError>>>,
    requests: Option<mpsc::Sender<AgentOperation>>,
    drain: Option<SshAgentDrain>,
    deadline: Instant,
}

impl PendingSshAgent {
    /// Retain per-worker cancellation and drain proof even if `ready` is moved
    /// into an abandoned task.
    pub fn drain_handle(&self) -> SshAgentDrain {
        self.drain
            .as_ref()
            .expect("pending SSH agent always owns its drain handle")
            .clone()
    }

    pub async fn cancel_and_drain(&self) -> Result<(), SshAgentError> {
        self.drain_handle().cancel_and_drain().await
    }

    pub async fn ready(mut self) -> Result<SelectedSshAgent, SshAgentError> {
        let identity = self
            .ready
            .take()
            .ok_or(SshAgentError::Unavailable)?
            .await
            .map_err(|_| SshAgentError::Unavailable)??;
        Ok(SelectedSshAgent {
            identity,
            requests: self.requests.take().ok_or(SshAgentError::Unavailable)?,
            drain: self.drain.take().ok_or(SshAgentError::Unavailable)?,
            deadline: self.deadline,
            connections: Semaphore::new(MAX_CONNECTIONS),
        })
    }
}

impl Drop for PendingSshAgent {
    fn drop(&mut self) {
        if let Some(drain) = &self.drain {
            drain.cancel.cancel();
        }
    }
}

/// One selected public identity and bounded operations. The private OpenSSH
/// socket remains inside the owner and is never returned to an untrusted peer.
pub struct SelectedSshAgent {
    identity: SshPublicIdentity,
    requests: mpsc::Sender<AgentOperation>,
    drain: SshAgentDrain,
    deadline: Instant,
    connections: Semaphore,
}

impl SelectedSshAgent {
    pub fn public_identity(&self) -> &SshPublicIdentity {
        &self.identity
    }

    pub fn drain_handle(&self) -> SshAgentDrain {
        self.drain.clone()
    }

    pub async fn cancel_and_drain(&self) -> Result<(), SshAgentError> {
        self.drain.cancel_and_drain().await
    }

    /// Broker-internal request payload, excluding the four-byte length prefix.
    /// A returned signature is not authorized for release until the caller has
    /// rechecked its environment/profile/material lease after this await.
    pub async fn request(&self, payload: &[u8]) -> Result<Vec<u8>, SshAgentError> {
        self.identity.admit_request(payload)?;
        let deadline = self.deadline.min(Instant::now() + OPERATION_TIMEOUT);
        let (response, receiver) = oneshot::channel();
        let operation = AgentOperation {
            payload: Zeroizing::new(payload.to_vec()),
            response,
            deadline,
        };
        tokio::select! {
            biased;
            _ = self.drain.cancel.cancelled() => Err(SshAgentError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(SshAgentError::Expired),
            result = async {
                self.requests.try_send(operation).map_err(|_| SshAgentError::Unavailable)?;
                receiver.await.map_err(|_| SshAgentError::Unavailable)?
            } => result,
        }
    }

    /// Serve an already authenticated, placement-bound byte stream. The owner
    /// does not bind a public listener. `authorize` must rederive the original
    /// grant; it runs before dispatch AND immediately before response release.
    pub async fn serve_connection<S, F, A>(
        &self,
        mut stream: S,
        cancellation: CancellationToken,
        authorize: F,
    ) -> Result<(), SshAgentError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: Fn() -> A,
        A: Future<Output = Result<(), SshAgentError>>,
    {
        let _permit = self
            .connections
            .try_acquire()
            .map_err(|_| SshAgentError::Unavailable)?;
        let work = async {
            loop {
                let deadline = self.deadline.min(Instant::now() + CONNECTION_IDLE_TIMEOUT);
                let payload = match tokio::time::timeout_at(deadline, read_frame(&mut stream)).await
                {
                    Ok(Ok(Some(payload))) => payload,
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(SshAgentError::Expired),
                };
                let deadline = self.deadline.min(Instant::now() + OPERATION_TIMEOUT);
                let response = tokio::time::timeout_at(deadline, async {
                    authorize().await?;
                    let response = self.request(&payload).await?;
                    authorize().await?;
                    Ok::<_, SshAgentError>(response)
                })
                .await
                .unwrap_or(Err(SshAgentError::Expired));
                let response = response.unwrap_or_else(|_| vec![FAILURE]);
                tokio::time::timeout_at(deadline, write_frame(&mut stream, &response))
                    .await
                    .map_err(|_| SshAgentError::Expired)??;
            }
        };
        tokio::select! {
            biased;
            _ = self.drain.cancel.cancelled() => Err(SshAgentError::Cancelled),
            _ = cancellation.cancelled() => Err(SshAgentError::Cancelled),
            result = work => result,
        }
    }
}

impl Drop for SelectedSshAgent {
    fn drop(&mut self) {
        self.drain.cancel.cancel();
    }
}

struct AgentOperation {
    payload: Zeroizing<Vec<u8>>,
    response: oneshot::Sender<Result<Vec<u8>, SshAgentError>>,
    deadline: Instant,
}

fn validate_material(key: &[u8], passphrase: Option<&[u8]>) -> Result<(), SshAgentError> {
    if key.is_empty() || key.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(SshAgentError::InvalidKey);
    }
    let text = std::str::from_utf8(key)
        .map_err(|_| SshAgentError::InvalidKey)?
        .trim();
    const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const END: &str = "-----END OPENSSH PRIVATE KEY-----";
    if !text.starts_with(BEGIN)
        || !text.ends_with(END)
        || text.matches(BEGIN).count() != 1
        || text.matches(END).count() != 1
    {
        return Err(SshAgentError::InvalidKey);
    }
    if passphrase.is_some_and(|value| {
        value.len() > MAX_PASSPHRASE_BYTES
            || value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    }) {
        return Err(SshAgentError::InvalidKey);
    }
    Ok(())
}

struct WorkerState {
    home: Option<PrivateProviderHome>,
    agent: Option<GroupChild>,
    add: Option<GroupChild>,
}

impl Drop for WorkerState {
    fn drop(&mut self) {
        // This path includes an unwind in cleanup itself. GroupChild drop can
        // signal, but cannot prove drain: never let PrivateProviderHome's
        // ordinary drop remove staging while a child might still be writing.
        if let Some(home) = self.home.take() {
            home.retain();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_worker(
    config: Arc<SshAgentConfig>,
    mut key: Zeroizing<Vec<u8>>,
    mut passphrase: Option<Zeroizing<Vec<u8>>>,
    deadline: Instant,
    cancel: CancellationToken,
    ready: oneshot::Sender<Result<SshPublicIdentity, SshAgentError>>,
    mut requests: mpsc::Receiver<AgentOperation>,
) -> Result<(), SshAgentError> {
    #[cfg(target_os = "linux")]
    let home = PrivateProviderHome::create_in(&config.runtime);
    #[cfg(target_os = "macos")]
    let home = PrivateProviderHome::create_signer_staging_in(&config.runtime);
    let home = match home {
        Ok(home) => home,
        Err(_) => {
            let _ = ready.send(Err(SshAgentError::Configuration));
            return Ok(());
        }
    };
    let mut ready = Some(ready);
    let mut state = WorkerState {
        home: Some(home),
        agent: None,
        add: None,
    };
    // Only operation state unwinds. Child/home ownership stays outside this
    // boundary and is used solely for cleanup after an unexpected panic.
    let result = AssertUnwindSafe(async { tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(SshAgentError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(SshAgentError::Expired),
        result = async {
            let home = state.home.as_ref().ok_or(SshAgentError::Cleanup)?;
            let started = tokio::time::timeout_at(deadline.min(Instant::now() + START_TIMEOUT), start_agent(&config, home, &mut key, &mut passphrase, &mut state.agent, &mut state.add)).await.map_err(|_| SshAgentError::Expired)?;
            let (identity, mut socket) = started?;
            #[cfg(all(test, target_os = "linux"))]
            config.reach_phase(tests::Phase::Ready, home, state.agent.as_ref(), None).await;
            let sender = ready.take().ok_or(SshAgentError::Unavailable)?;
            sender.send(Ok(identity.clone())).map_err(|_| SshAgentError::Cancelled)?;
            while let Some(operation) = requests.recv().await {
                if operation.response.is_closed() { continue; }
                if Instant::now() >= operation.deadline {
                    let _ = operation.response.send(Err(SshAgentError::Expired));
                    continue;
                }
                let response = tokio::time::timeout_at(operation.deadline, async {
                    match identity.admit_request(&operation.payload)? {
                        None => Ok(identity.identities_response()),
                        Some(algorithm) => {
                            write_frame(&mut socket, &operation.payload).await?;
                            #[cfg(all(test, target_os = "linux"))]
                            config.reach_phase(tests::Phase::SignDispatched, home, state.agent.as_ref(), None).await;
                            let response = read_frame(&mut socket).await?.ok_or(SshAgentError::Failed)?;
                            identity.validate_signature(&response, algorithm)?;
                            Ok(response.to_vec())
                        }
                    }
                }).await.unwrap_or(Err(SshAgentError::Expired));
                // A timeout or invalid upstream frame poisons this byte stream;
                // never let a late signature satisfy the next request.
                let failed = response.is_err();
                let _ = operation.response.send(response);
                if failed { return Err(SshAgentError::Failed); }
            }
            Ok(())
        } => result,
    }}).catch_unwind().await;
    let (result, operation_panicked) = match result {
        Ok(result) => (result, false),
        Err(_) => (Err(SshAgentError::Failed), true),
    };
    key.zeroize();
    passphrase.zeroize();
    cancel.cancel();
    requests.close();
    #[cfg(all(test, target_os = "linux"))]
    if let Some(home) = state.home.as_ref() {
        config
            .reach_phase(
                tests::Phase::BeforeCleanup,
                home,
                state.agent.as_ref(),
                state.add.as_ref(),
            )
            .await;
    }
    let add_clean = match state.add.as_mut() {
        Some(child) => child.stop_and_drain().await.is_ok(),
        None => true,
    };
    let agent_clean = match state.agent.as_mut() {
        Some(child) => child.stop_and_drain().await.is_ok(),
        None => true,
    };
    let clean = if add_clean && agent_clean && result != Err(SshAgentError::Cleanup) {
        state.home.take().is_some_and(|home| home.remove().is_ok())
    } else {
        false
    };
    if let Some(ready) = ready {
        let _ = ready.send(Err(if clean {
            result.err().unwrap_or(SshAgentError::Failed)
        } else {
            SshAgentError::Cleanup
        }));
    }
    if clean && !operation_panicked {
        Ok(())
    } else {
        Err(SshAgentError::Cleanup)
    }
}

async fn start_agent(
    config: &SshAgentConfig,
    home: &PrivateProviderHome,
    key: &mut Zeroizing<Vec<u8>>,
    passphrase: &mut Option<Zeroizing<Vec<u8>>>,
    agent: &mut Option<GroupChild>,
    add: &mut Option<GroupChild>,
) -> Result<(SshPublicIdentity, UnixStream), SshAgentError> {
    // Configuration can outlive deployment changes. Check the exact trusted
    // helper again immediately before starting the material-bearing tools.
    validate_askpass_helper(&config.askpass)?;
    let path = home.path().join("a");
    // sockaddr_un has a short, fixed path bound. Do not truncate names.
    if path.as_os_str().as_encoded_bytes().len() >= SOCKET_PATH_BYTES {
        return Err(SshAgentError::Configuration);
    }
    let mut command = isolated_command(config, &config.agent, home);
    command.args(["-D", "-a"]).arg(&path).args(["-P", ""]);
    *agent = Some(GroupChild::spawn(&mut command)?);
    let mut socket = loop {
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(SshAgentError::Configuration);
            }
            if let Ok(socket) = UnixStream::connect(&path).await {
                break socket;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    // Fresh process, and no inherited agent: importing must yield exactly one
    // supported identity. No ssh-add -D against any ambient socket is needed.
    let fifo = home.path().join("askpass.fifo");
    #[cfg(target_os = "linux")]
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .map_err(|_| SshAgentError::Configuration)?;
    #[cfg(target_os = "macos")]
    (config.darwin.make_fifo)(&fifo).map_err(|_| SshAgentError::Configuration)?;
    let mut command = isolated_command(config, &config.add, home);
    command
        .args(["-q", "-"])
        .stdin(Stdio::piped())
        .env("SSH_AUTH_SOCK", &path)
        .env("SSH_ASKPASS", &config.askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "codewire:0")
        .env("CODEWIRE_SSH_ASKPASS_FIFO", &fifo);
    *add = Some(GroupChild::spawn(&mut command)?);
    #[cfg(all(test, target_os = "linux"))]
    config
        .reach_phase(
            tests::Phase::ImportSpawned,
            home,
            agent.as_ref(),
            add.as_ref(),
        )
        .await;
    let child = add.as_mut().ok_or(SshAgentError::Failed)?;
    let mut stdin = child.child.stdin.take().ok_or(SshAgentError::Failed)?;
    stdin
        .write_all(key)
        .await
        .map_err(|_| SshAgentError::Failed)?;
    drop(stdin);
    key.zeroize();
    let success = {
        let deliver_passphrase = async {
            let mut sender = loop {
                match tokio::net::unix::pipe::OpenOptions::new().open_sender(&fifo) {
                    Ok(sender) => break sender,
                    Err(error)
                        if error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error()) =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(_) => return Err(SshAgentError::Failed),
                }
            };
            #[cfg(all(test, target_os = "linux"))]
            config
                .reach_phase(
                    tests::Phase::FifoConnected,
                    home,
                    agent.as_ref(),
                    Some(child),
                )
                .await;
            if let Some(passphrase) = passphrase.as_mut() {
                sender
                    .write_all(passphrase)
                    .await
                    .map_err(|_| SshAgentError::Failed)?;
                passphrase.zeroize();
            }
            // Empty/no passphrase still returns EOF instead of prompting on a TTY.
            drop(sender);
            Ok::<_, SshAgentError>(())
        };
        tokio::pin!(deliver_passphrase);
        tokio::select! {
            result = child.wait_without_reaping() => result?,
            result = &mut deliver_passphrase => { result?; child.wait_without_reaping().await? }
        }
    };
    passphrase.zeroize();
    if !success {
        return Err(SshAgentError::InvalidKey);
    }
    child.stop_and_drain().await?;
    *add = None;
    write_frame(&mut socket, &[REQUEST_IDENTITIES]).await?;
    let response = read_frame(&mut socket)
        .await?
        .ok_or(SshAgentError::Failed)?;
    let identity = SshPublicIdentity::from_agent_response(&response)?;
    Ok((identity, socket))
}

fn isolated_command(
    config: &SshAgentConfig,
    executable: &std::path::Path,
    home: &PrivateProviderHome,
) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("HOME", home.path())
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    #[cfg(target_os = "macos")]
    (config.darwin.prepare_child)(&mut command);
    #[cfg(target_os = "linux")]
    let _ = config;
    command
}

struct GroupChild {
    child: Child,
    pid: Option<Pid>,
    stdout: Option<JoinHandle<Result<(), SshAgentError>>>,
    stderr: Option<JoinHandle<Result<(), SshAgentError>>>,
    cleanup_failed: bool,
}

impl GroupChild {
    fn spawn(command: &mut Command) -> Result<Self, SshAgentError> {
        let mut child = command.spawn().map_err(|_| SshAgentError::Failed)?;
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw)
            .filter(|pid| pid.as_raw_pid() > 1)
            .ok_or(SshAgentError::Failed)?;
        let stdout = child.stdout.take().ok_or(SshAgentError::Failed)?;
        let stderr = child.stderr.take().ok_or(SshAgentError::Failed)?;
        Ok(Self {
            child,
            pid: Some(pid),
            stdout: Some(tokio::spawn(discard(stdout))),
            stderr: Some(tokio::spawn(discard(stderr))),
            cleanup_failed: false,
        })
    }
    async fn wait_without_reaping(&self) -> Result<bool, SshAgentError> {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .map_err(|_| SshAgentError::Failed)?;
        loop {
            let status = rustix::process::waitid(
                WaitId::Pid(self.pid.ok_or(SshAgentError::Failed)?),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| SshAgentError::Failed)?;
            if let Some(status) = status {
                return Ok(status.exited() && status.exit_status() == Some(0));
            }
            if signal.recv().await.is_none() {
                return Err(SshAgentError::Failed);
            }
        }
    }
    async fn stop_and_drain(&mut self) -> Result<(), SshAgentError> {
        if let Some(pid) = self.pid.take() {
            // Signal before reaping; the unreaped leader reserves the group ID.
            // Clear signal authority before any wait, including error paths.
            match rustix::process::kill_process_group(pid, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                // Darwin refuses to signal a group whose members have all
                // exited (an unreaped leader is a zombie). The drain below
                // still proves that every member exited.
                #[cfg(target_os = "macos")]
                Err(rustix::io::Errno::PERM) => {}
                Err(_) => self.cleanup_failed = true,
            }
        }
        let result = tokio::time::timeout(CLEANUP_TIMEOUT, async {
            let (child, stdout, stderr) = tokio::join!(
                self.child.wait(),
                observe_output(&mut self.stdout),
                observe_output(&mut self.stderr)
            );
            child.map_err(|_| SshAgentError::Cleanup)?;
            stdout?;
            stderr?;
            Ok(())
        })
        .await
        .unwrap_or(Err(SshAgentError::Cleanup));
        self.cleanup_failed |= result.is_err();
        if self.cleanup_failed {
            Err(SshAgentError::Cleanup)
        } else {
            Ok(())
        }
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }
}

async fn observe_output(
    task: &mut Option<JoinHandle<Result<(), SshAgentError>>>,
) -> Result<(), SshAgentError> {
    let Some(handle) = task.as_mut() else {
        return Ok(());
    };
    let result = handle.await;
    // Cleanup may be retried after cancellation/timeout. A completed join
    // handle must not be polled twice; failure remains latched on GroupChild.
    *task = None;
    result.map_err(|_| SshAgentError::Cleanup)?
}

async fn discard(mut input: impl AsyncRead + Unpin) -> Result<(), SshAgentError> {
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        let count = input
            .read(&mut *buffer)
            .await
            .map_err(|_| SshAgentError::Cleanup)?;
        buffer.zeroize();
        if count == 0 {
            return Ok(());
        }
    }
}

async fn read_frame(
    input: &mut (impl AsyncRead + Unpin),
) -> Result<Option<Zeroizing<Vec<u8>>>, SshAgentError> {
    let mut header = [0; 4];
    let count = input
        .read(&mut header[..1])
        .await
        .map_err(|_| SshAgentError::Failed)?;
    if count == 0 {
        return Ok(None);
    }
    input
        .read_exact(&mut header[1..])
        .await
        .map_err(|_| SshAgentError::Failed)?;
    let count = u32::from_be_bytes(header) as usize;
    if count == 0 || count > MAX_FRAME_BYTES {
        return Err(SshAgentError::Denied);
    }
    let mut frame = Zeroizing::new(vec![0; count]);
    input
        .read_exact(&mut frame)
        .await
        .map_err(|_| SshAgentError::Failed)?;
    Ok(Some(frame))
}

async fn write_frame(
    output: &mut (impl AsyncWrite + Unpin),
    frame: &[u8],
) -> Result<(), SshAgentError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(SshAgentError::Denied);
    }
    output
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .map_err(|_| SshAgentError::Failed)?;
    output
        .write_all(frame)
        .await
        .map_err(|_| SshAgentError::Failed)?;
    output.flush().await.map_err(|_| SshAgentError::Failed)
}
