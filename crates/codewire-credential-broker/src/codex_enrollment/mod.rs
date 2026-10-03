//! Explicit isolated enrollment through the pinned official Codex CLI.
//!
//! This is a process-local owner, not a public material transport or enrollment
//! endpoint. The caller authenticates the owner and publishes the imported
//! bundle into that owner's placement store. No ambient provider state is read.
//!
//! The original fifteen-minute deadline includes startup, the device exchange
//! and completion disposition. Cancellation owns and drains the dedicated child
//! process group before removing tmpfs staging. Shutdown must be awaited before
//! terminating the Tokio runtime. Process/runtime death cannot guarantee remote
//! revocation or cleanup; an unprovable drain retains the private tmpfs directory.

mod parser;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zeroize::{Zeroize, Zeroizing};

use crate::provider_enrollment::{
    PrivateProviderHome, read_private_file, validate_executable, validate_private_tmpfs_runtime,
};
use crate::{CodexOAuthImport, import_codex_auth_json};
use parser::ChallengeParser;

const ENROLLMENT_LIFETIME: Duration = Duration::from_secs(15 * 60);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STDERR_BYTES: usize = 64 * 1024;
// Same strict input ceiling as the existing canonical Codex importer.
const MAX_AUTH_FILE_BYTES: usize = 1024 * 1024;
const MAX_ENROLLMENTS: usize = 8;

/// Closed, value-blind enrollment failures. Raw child output and OS/parser
/// diagnostics are never retained as error sources.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CodexEnrollmentError {
    /// Trusted executable or private tmpfs configuration is invalid.
    #[error("Codex enrollment configuration is unavailable")]
    Configuration,
    /// The owner is shutting down or its finite worker limit is occupied.
    #[error("Codex enrollment is unavailable")]
    Unavailable,
    /// The caller or process owner cancelled this enrollment.
    #[error("Codex enrollment was cancelled")]
    Cancelled,
    /// The immutable original enrollment deadline elapsed.
    #[error("Codex enrollment expired")]
    Expired,
    /// The pinned official CLI prompt was not accepted.
    #[error("Codex enrollment output is invalid or unsupported")]
    InvalidOutput,
    /// This extraction supports only reviewed Codex 0.149.0/0.153.4/0.157.0 prompts.
    #[error("Codex enrollment executable version is unsupported")]
    UnsupportedVersion,
    /// The isolated process could not finish successfully.
    #[error("Codex enrollment did not complete")]
    Failed,
    /// The isolated file was not a valid private ChatGPT OAuth result.
    #[error("Codex enrollment result is invalid")]
    InvalidResult,
    /// Child drain or private staging removal could not be established.
    #[error("Codex enrollment cleanup could not be completed")]
    Cleanup,
}

/// The only child-output data permitted outside this process-local boundary.
/// Debug deliberately omits the one-time code.
pub struct CodexDeviceChallenge {
    user_code: Zeroizing<String>,
    expires_at_unix: u64,
}

impl CodexDeviceChallenge {
    /// Exact pinned provider challenge URL, never parsed into an arbitrary URL.
    pub fn verification_url(&self) -> &'static str {
        "https://auth.openai.com/codex/device"
    }

    /// Accepted bounded one-time code, never a provider access or refresh token.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// Conservative original wall-clock deadline, fixed before child startup.
    /// The worker enforces its corresponding immutable monotonic deadline.
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl std::fmt::Debug for CodexDeviceChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodexDeviceChallenge")
            .field("user_code", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

/// Trusted process configuration. This is not accepted from an enrollment RPC.
pub struct CodexEnrollmentConfig {
    executable: PathBuf,
    private_tmpfs_root: PathBuf,
    child_path: OsString,
}

impl CodexEnrollmentConfig {
    /// Validate the administrator/CLI-selected executable, private tmpfs root
    /// and explicit child PATH required by the official npm wrapper's node
    /// launcher. No ambient environment or arbitrary environment map is copied.
    pub fn new(
        executable: PathBuf,
        private_tmpfs_root: PathBuf,
        child_path: OsString,
    ) -> Result<Self, CodexEnrollmentError> {
        let executable =
            validate_executable(&executable).map_err(|_| CodexEnrollmentError::Configuration)?;
        validate_private_tmpfs_runtime(&private_tmpfs_root)
            .map_err(|_| CodexEnrollmentError::Configuration)?;
        if child_path.is_empty()
            || std::env::split_paths(&child_path).any(|path| !path.is_absolute())
        {
            return Err(CodexEnrollmentError::Configuration);
        }
        Ok(Self {
            executable,
            private_tmpfs_root,
            child_path,
        })
    }
}

/// One bounded owner for all isolated enrollment workers in a CLI/service.
/// Dropping requests signals cancellation; only awaiting shutdown proves drain.
pub struct CodexEnrollmentOwner {
    config: Arc<CodexEnrollmentConfig>,
    accepting: Mutex<bool>,
    workers: TaskTracker,
    shutdown: CancellationToken,
    capacity: Arc<Semaphore>,
    cleanup_failed: Arc<AtomicBool>,
}

impl CodexEnrollmentOwner {
    /// Construct an owner from already-validated trusted configuration.
    pub fn new(config: CodexEnrollmentConfig) -> Self {
        Self {
            config: Arc::new(config),
            accepting: Mutex::new(true),
            workers: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            capacity: Arc::new(Semaphore::new(MAX_ENROLLMENTS)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start one owned worker. Its deadline cannot be renewed by challenge
    /// reads, retries, a detached caller, or publication acknowledgement.
    pub fn start(&self) -> Result<PendingCodexEnrollment, CodexEnrollmentError> {
        let lifetime = ENROLLMENT_LIFETIME;
        let started = Instant::now();
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CodexEnrollmentError::Unavailable)?
            .as_secs()
            .checked_add(lifetime.as_secs())
            .ok_or(CodexEnrollmentError::Unavailable)?;
        let accepting = self
            .accepting
            .lock()
            .map_err(|_| CodexEnrollmentError::Unavailable)?;
        if !*accepting {
            return Err(CodexEnrollmentError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| CodexEnrollmentError::Unavailable)?;
        let cancellation = self.shutdown.child_token();
        let (challenge_tx, challenge_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let config = self.config.clone();
        let worker_cancel = cancellation.clone();
        let cleanup_failed = self.cleanup_failed.clone();
        self.workers.spawn(async move {
            let _permit = permit;
            enrollment_worker(
                config,
                worker_cancel,
                started + lifetime,
                expires_at_unix,
                challenge_tx,
                result_tx,
                cleanup_failed,
            )
            .await;
        });
        drop(accepting);
        Ok(PendingCodexEnrollment {
            cancellation: Some(cancellation),
            challenge: Some(challenge_rx),
            result: Some(result_rx),
        })
    }

    /// Close admission, signal every pending/completed worker and await owned
    /// process drain and staging cleanup. No worker is aborted mid-cleanup.
    pub async fn shutdown(&self) -> Result<(), CodexEnrollmentError> {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *accepting = false;
            self.workers.close();
            self.shutdown.cancel();
        }
        self.workers.wait().await;
        if self.cleanup_failed.load(Ordering::Acquire) {
            Err(CodexEnrollmentError::Cleanup)
        } else {
            Ok(())
        }
    }
}

impl Drop for CodexEnrollmentOwner {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.workers.close();
    }
}

/// Pending enrollment; dropping it cancels, but does not abort its worker.
pub struct PendingCodexEnrollment {
    cancellation: Option<CancellationToken>,
    challenge: Option<oneshot::Receiver<Result<CodexDeviceChallenge, CodexEnrollmentError>>>,
    result: Option<oneshot::Receiver<Result<CompletedCodexEnrollment, CodexEnrollmentError>>>,
}

impl PendingCodexEnrollment {
    /// Receive exactly one safe challenge. Waiting does not extend its deadline.
    pub async fn challenge(&mut self) -> Result<CodexDeviceChallenge, CodexEnrollmentError> {
        self.challenge
            .take()
            .ok_or(CodexEnrollmentError::Unavailable)?
            .await
            .map_err(|_| CodexEnrollmentError::Unavailable)?
    }

    /// Wait for strict import after successful child exit and process-group
    /// drain. The result is process-local protected material, never an RPC DTO.
    pub async fn complete(mut self) -> Result<CompletedCodexEnrollment, CodexEnrollmentError> {
        let result = self
            .result
            .take()
            .ok_or(CodexEnrollmentError::Unavailable)?
            .await
            .map_err(|_| CodexEnrollmentError::Unavailable)?;
        self.cancellation = None;
        result
    }

    /// Cancel and await child drain/cleanup rather than merely dropping a future.
    pub async fn cancel(mut self) -> Result<(), CodexEnrollmentError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        match self
            .result
            .take()
            .ok_or(CodexEnrollmentError::Unavailable)?
            .await
        {
            Ok(Err(CodexEnrollmentError::Cancelled)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Ok(Ok(completed)) => completed.finish(CodexPublicationOutcome::Unknown).await,
            Err(_) => Err(CodexEnrollmentError::Unavailable),
        }
    }
}

impl Drop for PendingCodexEnrollment {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}

/// Explicit placement outcome. An uncertain acknowledgement is never evidence
/// that a refresh token was not stored, so it must never trigger logout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexPublicationOutcome {
    /// The exact placement publication was acknowledged: cleanup, no logout.
    Published,
    /// Publication definitely did not occur: attempt bounded best-effort logout.
    NotPublished,
    /// The commit acknowledgement is unknown: cleanup, no automatic logout.
    Unknown,
}

/// A completed login plus its still-owned staging cleanup. No Debug, Clone or
/// serialization implementation can accidentally expose the imported bundle.
pub struct CompletedCodexEnrollment {
    imported: Option<CodexOAuthImport>,
    disposition: Option<oneshot::Sender<CodexPublicationOutcome>>,
    cleanup: Option<oneshot::Receiver<Result<(), CodexEnrollmentError>>>,
    deadline: Instant,
    cancellation: CancellationToken,
}

impl CompletedCodexEnrollment {
    /// Check the existing cancellation state and original enrollment deadline.
    /// A placement must repeat this immediately before issuing COMMIT; this
    /// check neither renews the login nor acknowledges a storage outcome.
    pub fn check_active(&self) -> Result<(), CodexEnrollmentError> {
        if self.cancellation.is_cancelled() {
            return Err(CodexEnrollmentError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(CodexEnrollmentError::Expired);
        }
        Ok(())
    }

    /// Move the one imported bundle into owner-fenced placement storage exactly
    /// once. The placement owns its own commit/acknowledgement semantics.
    pub fn take_import(&mut self) -> Result<CodexOAuthImport, CodexEnrollmentError> {
        self.check_active()?;
        self.imported
            .take()
            .ok_or(CodexEnrollmentError::Unavailable)
    }

    /// Await a placement acknowledgement within the original enrollment
    /// deadline. This does not cancel an already-issued store mutation: on
    /// expiry, cancellation or a transport error the caller must resolve an
    /// uncertain publication as Unknown, never NotPublished.
    pub async fn wait_for_publication<T>(
        &self,
        publication: impl std::future::Future<Output = T>,
    ) -> Result<T, CodexEnrollmentError> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(CodexEnrollmentError::Cancelled),
            _ = tokio::time::sleep_until(self.deadline) => Err(CodexEnrollmentError::Expired),
            result = publication => Ok(result),
        }
    }

    /// Resolve the actual store outcome and await cleanup. Dropping this value
    /// before sending an explicit disposition implies Unknown, never
    /// NotPublished. Once sent, a definite rejection remains definite even if
    /// its caller stops awaiting cleanup.
    pub async fn finish(
        mut self,
        outcome: CodexPublicationOutcome,
    ) -> Result<(), CodexEnrollmentError> {
        self.imported = None;
        if let Some(disposition) = self.disposition.take() {
            let _ = disposition.send(outcome);
        }
        self.cleanup
            .take()
            .ok_or(CodexEnrollmentError::Unavailable)?
            .await
            .map_err(|_| CodexEnrollmentError::Unavailable)?
    }
}

async fn enrollment_worker(
    config: Arc<CodexEnrollmentConfig>,
    cancellation: CancellationToken,
    deadline: Instant,
    expires_at_unix: u64,
    challenge_tx: oneshot::Sender<Result<CodexDeviceChallenge, CodexEnrollmentError>>,
    result_tx: oneshot::Sender<Result<CompletedCodexEnrollment, CodexEnrollmentError>>,
    cleanup_failed: Arc<AtomicBool>,
) {
    let mut challenge_tx = Some(challenge_tx);
    let home = match PrivateProviderHome::create_in(&config.private_tmpfs_root) {
        Ok(home) => home,
        Err(_) => {
            if let Some(sender) = challenge_tx.take() {
                let _ = sender.send(Err(CodexEnrollmentError::Configuration));
            }
            let _ = result_tx.send(Err(CodexEnrollmentError::Configuration));
            return;
        }
    };
    let result = run_login(
        &config,
        &home,
        &cancellation,
        deadline,
        expires_at_unix,
        &mut challenge_tx,
    )
    .await;
    let imported = match result {
        Ok(imported) => imported,
        Err(error) => {
            let cleanup = if error == CodexEnrollmentError::Cleanup {
                home.retain();
                Err(CodexEnrollmentError::Cleanup)
            } else {
                let logout = logout_if_valid(&config, &home, deadline).await;
                if logout == Err(CodexEnrollmentError::Cleanup) {
                    home.retain();
                    logout
                } else {
                    home.remove().map_err(|_| CodexEnrollmentError::Cleanup)
                }
            };
            let error = cleanup.err().unwrap_or(error);
            if error == CodexEnrollmentError::Cleanup {
                cleanup_failed.store(true, Ordering::Release);
            }
            if let Some(sender) = challenge_tx.take() {
                let _ = sender.send(Err(error));
            }
            let _ = result_tx.send(Err(error));
            return;
        }
    };
    let (disposition_tx, disposition_rx) = oneshot::channel();
    let (cleanup_tx, cleanup_rx) = oneshot::channel();
    let completed = CompletedCodexEnrollment {
        imported: Some(imported),
        disposition: Some(disposition_tx),
        cleanup: Some(cleanup_rx),
        deadline,
        cancellation: cancellation.clone(),
    };
    // Failure to deliver, or a subsequently dropped result, closes disposition
    // and therefore takes the Unknown/no-logout branch.
    let _ = result_tx.send(Ok(completed));
    let outcome = tokio::select! {
        biased;
        _ = cancellation.cancelled() => CodexPublicationOutcome::Unknown,
        _ = tokio::time::sleep_until(deadline) => CodexPublicationOutcome::Unknown,
        outcome = disposition_rx => outcome.unwrap_or(CodexPublicationOutcome::Unknown),
    };
    let cleanup = if outcome == CodexPublicationOutcome::NotPublished
        && logout_if_valid(&config, &home, deadline).await == Err(CodexEnrollmentError::Cleanup)
    {
        home.retain();
        Err(CodexEnrollmentError::Cleanup)
    } else {
        home.remove().map_err(|_| CodexEnrollmentError::Cleanup)
    };
    if cleanup.is_err() {
        cleanup_failed.store(true, Ordering::Release);
    }
    let _ = cleanup_tx.send(cleanup);
}

fn isolated_command(config: &CodexEnrollmentConfig, home: &PrivateProviderHome) -> Command {
    let mut command = Command::new(&config.executable);
    command
        .env_clear()
        .env("PATH", &config.child_path)
        .env("HOME", home.path())
        .env("CODEX_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("TMPDIR", home.path())
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    command
}

async fn run_login(
    config: &CodexEnrollmentConfig,
    home: &PrivateProviderHome,
    cancellation: &CancellationToken,
    deadline: Instant,
    expires_at_unix: u64,
    challenge_tx: &mut Option<oneshot::Sender<Result<CodexDeviceChallenge, CodexEnrollmentError>>>,
) -> Result<CodexOAuthImport, CodexEnrollmentError> {
    if cancellation.is_cancelled() {
        return Err(CodexEnrollmentError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(CodexEnrollmentError::Expired);
    }
    let mut command = isolated_command(config, home);
    command.args([
        "login",
        "--device-auth",
        "-c",
        "cli_auth_credentials_store=\"file\"",
    ]);
    let mut group = GroupChild::spawn(&mut command)?;
    let mut stdout = group.child.stdout.take().expect("isolated stdout is piped");
    let mut stderr = group.child.stderr.take().expect("isolated stderr is piped");
    let mut parser = ChallengeParser::new(expires_at_unix);
    let mut stdout_buffer = Zeroizing::new([0_u8; 4096]);
    let mut stderr_buffer = Zeroizing::new([0_u8; 4096]);
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stderr_bytes = 0_usize;
    let mut leader_result = None;
    let outcome = loop {
        if stdout_done
            && stderr_done
            && let Some(success) = leader_result
        {
            break if success {
                parser.finish()
            } else {
                Err(CodexEnrollmentError::Failed)
            };
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Err(CodexEnrollmentError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => break Err(CodexEnrollmentError::Expired),
            read = stdout.read(&mut *stdout_buffer), if !stdout_done => {
                match read {
                    Ok(0) => stdout_done = true,
                    Ok(count) => match parser.push(&stdout_buffer[..count]) {
                        Ok(Some(challenge)) => {
                            if let Some(sender) = challenge_tx.take() {
                                let _ = sender.send(Ok(challenge));
                            }
                        }
                        Ok(None) => {}
                        Err(error) => break Err(error),
                    },
                    Err(_) => break Err(CodexEnrollmentError::Failed),
                }
                stdout_buffer.zeroize();
            }
            read = stderr.read(&mut *stderr_buffer), if !stderr_done => {
                match read {
                    Ok(0) => stderr_done = true,
                    Ok(count) => {
                        stderr_bytes = stderr_bytes.saturating_add(count);
                        if stderr_bytes > MAX_STDERR_BYTES { break Err(CodexEnrollmentError::InvalidOutput); }
                    }
                    Err(_) => break Err(CodexEnrollmentError::Failed),
                }
                stderr_buffer.zeroize();
            }
            result = group.wait_without_reaping(), if leader_result.is_none() => {
                match result {
                    Ok(success) => {
                        leader_result = Some(success);
                        if let Err(error) = group.terminate() { break Err(error); }
                    }
                    Err(error) => break Err(error),
                }
            }
        }
    };
    group.stop_and_drain(&mut stdout, &mut stderr).await?;
    outcome?;
    if cancellation.is_cancelled() {
        return Err(CodexEnrollmentError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(CodexEnrollmentError::Expired);
    }
    let source = read_private_file(home, "auth.json", MAX_AUTH_FILE_BYTES)
        .map_err(|_| CodexEnrollmentError::InvalidResult)?;
    import_codex_auth_json(&source).map_err(|_| CodexEnrollmentError::InvalidResult)
}

async fn logout_if_valid(
    config: &CodexEnrollmentConfig,
    home: &PrivateProviderHome,
    deadline: Instant,
) -> Result<(), CodexEnrollmentError> {
    if Instant::now() >= deadline {
        return Ok(());
    }
    let Ok(source) = read_private_file(home, "auth.json", MAX_AUTH_FILE_BYTES) else {
        return Ok(());
    };
    if import_codex_auth_json(&source).is_err() {
        return Ok(());
    }
    drop(source);
    let mut command = isolated_command(config, home);
    command.args(["logout", "-c", "cli_auth_credentials_store=\"file\""]);
    let mut group = GroupChild::spawn(&mut command)?;
    let mut stdout = group.child.stdout.take().expect("isolated stdout is piped");
    let mut stderr = group.child.stderr.take().expect("isolated stderr is piped");
    let logout_deadline = deadline.min(Instant::now() + LOGOUT_TIMEOUT);
    let _ = tokio::time::timeout_at(logout_deadline, async {
        tokio::try_join!(discard(&mut stdout), discard(&mut stderr), async {
            group.wait_without_reaping().await.map(|_| ())
        })
    })
    .await;
    group.stop_and_drain(&mut stdout, &mut stderr).await
}

// A dedicated group is required because the pinned npm executable is a wrapper
// which spawns the native child. Killing only the direct child is insufficient.
// Also used by the isolated GitHub enrollment: one implementation owns the
// unreaped process-group identity, termination and both output EOF barriers.
pub(crate) struct GroupChild {
    pub(crate) child: Child,
    pid: Option<Pid>,
}

impl GroupChild {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self, CodexEnrollmentError> {
        let child = command.spawn().map_err(|_| CodexEnrollmentError::Failed)?;
        let pid = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
            .filter(|pid| pid.as_raw_pid() > 1)
            .expect("new child has a positive non-init PID");
        Ok(Self {
            child,
            pid: Some(pid),
        })
    }

    pub(crate) async fn wait_without_reaping(&self) -> Result<bool, CodexEnrollmentError> {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .map_err(|_| CodexEnrollmentError::Failed)?;
        loop {
            let status = rustix::process::waitid(
                WaitId::Pid(self.pid.ok_or(CodexEnrollmentError::Failed)?),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| CodexEnrollmentError::Failed)?;
            if let Some(status) = status {
                return Ok(status.exited() && status.exit_status() == Some(0));
            }
            if signal.recv().await.is_none() {
                return Err(CodexEnrollmentError::Failed);
            }
        }
    }

    pub(crate) async fn stop_and_drain(
        &mut self,
        stdout: &mut (impl AsyncRead + Unpin),
        stderr: &mut (impl AsyncRead + Unpin),
    ) -> Result<(), CodexEnrollmentError> {
        self.stop_and_drain_with_timeout(stdout, stderr, CLEANUP_TIMEOUT)
            .await
    }

    async fn stop_and_drain_with_timeout(
        &mut self,
        stdout: &mut (impl AsyncRead + Unpin),
        stderr: &mut (impl AsyncRead + Unpin),
        timeout: Duration,
    ) -> Result<(), CodexEnrollmentError> {
        self.terminate()?;
        let result = tokio::time::timeout(timeout, async {
            tokio::try_join!(discard(stdout), discard(stderr), async {
                self.child
                    .wait()
                    .await
                    .map(|_| ())
                    .map_err(|_| CodexEnrollmentError::Cleanup)
            })
        })
        .await
        .map_err(|_| CodexEnrollmentError::Cleanup)?;
        result.map(|_| ())
    }

    pub(crate) fn terminate(&mut self) -> Result<(), CodexEnrollmentError> {
        if let Some(pid) = self.pid {
            // The unreaped leader reserves the process-group ID until after
            // this signal. Clear the signal authority before any child wait:
            // timeout/error cleanup must never signal a subsequently reused ID.
            rustix::process::kill_process_group(pid, Signal::KILL)
                .map_err(|_| CodexEnrollmentError::Cleanup)?;
            self.pid = None;
        }
        Ok(())
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }
}

async fn discard(reader: &mut (impl AsyncRead + Unpin)) -> Result<(), CodexEnrollmentError> {
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        let count = reader
            .read(&mut *buffer)
            .await
            .map_err(|_| CodexEnrollmentError::Cleanup)?;
        buffer.zeroize();
        if count == 0 {
            return Ok(());
        }
    }
}
