//! Explicit isolated enrollment through the official GitHub CLI 2.97.0.
//!
//! The owner retains each process group and private tmpfs home through drain
//! and publication disposition. Only the fixed device challenge and verified
//! login hint can leave this process-local boundary. No ambient login, token,
//! keyring, proxy or browser is used. This is not a public material transport.
//!
//! Import accepts only the pinned CLI's ordinary `gho_` token/config shape.
//! Persisted refresh/expiry fields are rejected, never discarded. The upstream
//! CLI itself exposes only a token and username, however: this importer cannot
//! inspect OAuth HTTP fields discarded inside gh and promises no provider-token
//! lifetime or refresh support. Codewire's hard credential expiry is separate.

mod parser;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::FutureExt as _;
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use tokio::sync::{Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zeroize::{Zeroize, Zeroizing};

use crate::codex_enrollment::{CodexEnrollmentError, GroupChild};
use crate::provider_enrollment::{
    PrivateProviderHome, read_private_file, validate_executable, validate_private_tmpfs_runtime,
};
use parser::{ChallengeParser, import_hosts, validate_version};

const ENROLLMENT_LIFETIME: Duration = Duration::from_secs(15 * 60);
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENROLLMENTS: usize = 8;
const MAX_VERSION_BYTES: usize = 4096;
const MAX_HOSTS_BYTES: usize = 16 * 1024;

/// Closed failures: never retain provider output, private paths or OS sources.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum GitHubEnrollmentError {
    /// Trusted executable or private staging is invalid.
    #[error("GitHub enrollment configuration is unavailable")]
    Configuration,
    /// Admission is closed, full or already consumed.
    #[error("GitHub enrollment is unavailable")]
    Unavailable,
    /// The requesting operation or owner was cancelled.
    #[error("GitHub enrollment was cancelled")]
    Cancelled,
    /// The immutable original deadline elapsed.
    #[error("GitHub enrollment expired")]
    Expired,
    /// Output did not match the fixed device flow.
    #[error("GitHub enrollment output is invalid or unsupported")]
    InvalidOutput,
    /// Only the pinned official CLI version is admitted.
    #[error("GitHub enrollment executable version is unsupported")]
    UnsupportedVersion,
    /// The isolated provider process failed.
    #[error("GitHub enrollment did not complete")]
    Failed,
    /// Private result was not the supported GitHub OAuth representation.
    #[error("GitHub enrollment result is invalid or unsupported")]
    InvalidResult,
    /// Group drain or staging removal could not be proved.
    #[error("GitHub enrollment cleanup could not be completed")]
    Cleanup,
}

/// Only the one-time code is user-visible; Debug always redacts it.
pub struct GitHubDeviceChallenge {
    user_code: Zeroizing<String>,
    expires_at_unix: u64,
}

impl GitHubDeviceChallenge {
    /// Never derived from an arbitrary child-provided URL.
    pub fn verification_url(&self) -> &'static str {
        "https://github.com/login/device"
    }

    /// Fixed-format one-time user code, not a provider token.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// Original conservative operation expiry, not a renewable challenge TTL.
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl std::fmt::Debug for GitHubDeviceChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubDeviceChallenge")
            .field("user_code", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// One process-local raw-token result; intentionally no Debug/Clone/serde.
pub struct GitHubOAuthImport {
    token: Zeroizing<Vec<u8>>,
    login: String,
}

impl GitHubOAuthImport {
    /// Move protected material and the bounded verified account hint once.
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, Option<String>) {
        (self.token, Some(self.login))
    }
}

/// Trusted owner configuration, never RPC-supplied executable/path inputs.
pub struct GitHubEnrollmentConfig {
    executable: PathBuf,
    private_tmpfs_root: PathBuf,
    child_path: OsString,
}

impl GitHubEnrollmentConfig {
    /// Validate fixed executable and canonical private tmpfs before admission.
    /// Runtime version is checked in the same owned, bounded process group.
    pub fn new(
        executable: PathBuf,
        private_tmpfs_root: PathBuf,
        child_path: OsString,
    ) -> Result<Self, GitHubEnrollmentError> {
        let executable =
            validate_executable(&executable).map_err(|_| GitHubEnrollmentError::Configuration)?;
        validate_private_tmpfs_runtime(&private_tmpfs_root)
            .map_err(|_| GitHubEnrollmentError::Configuration)?;
        if child_path.is_empty()
            || std::env::split_paths(&child_path).any(|path| !path.is_absolute())
        {
            return Err(GitHubEnrollmentError::Configuration);
        }
        Ok(Self {
            executable,
            private_tmpfs_root,
            child_path,
        })
    }
}

/// Bounded retained enrollment workers; shutdown must be awaited before exit.
pub struct GitHubEnrollmentOwner {
    config: Arc<GitHubEnrollmentConfig>,
    accepting: Mutex<bool>,
    workers: TaskTracker,
    shutdown: CancellationToken,
    capacity: Arc<Semaphore>,
    cleanup_failed: Arc<AtomicBool>,
}

impl GitHubEnrollmentOwner {
    /// Construct from already-validated trusted configuration.
    pub fn new(config: GitHubEnrollmentConfig) -> Self {
        Self {
            config: Arc::new(config),
            accepting: Mutex::new(true),
            workers: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            capacity: Arc::new(Semaphore::new(MAX_ENROLLMENTS)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Admit one worker before any provider activity; no waiting capacity queue.
    pub fn start(&self) -> Result<PendingGitHubEnrollment, GitHubEnrollmentError> {
        self.start_with_lifetime(ENROLLMENT_LIFETIME)
    }

    fn start_with_lifetime(
        &self,
        lifetime: Duration,
    ) -> Result<PendingGitHubEnrollment, GitHubEnrollmentError> {
        let started = Instant::now();
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GitHubEnrollmentError::Unavailable)?
            .as_secs()
            .checked_add(lifetime.as_secs())
            .ok_or(GitHubEnrollmentError::Unavailable)?;
        let accepting = self
            .accepting
            .lock()
            .map_err(|_| GitHubEnrollmentError::Unavailable)?;
        if !*accepting || self.cleanup_failed.load(Ordering::Acquire) {
            return Err(GitHubEnrollmentError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| GitHubEnrollmentError::Unavailable)?;
        let cancellation = self.shutdown.child_token();
        let (challenge_tx, challenge_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let config = self.config.clone();
        let worker_cancel = cancellation.clone();
        let cleanup_failed = self.cleanup_failed.clone();
        self.workers.spawn(async move {
            let _permit = permit;
            if AssertUnwindSafe(enrollment_worker(
                config,
                worker_cancel,
                started + lifetime,
                expires_at_unix,
                challenge_tx,
                result_tx,
                &cleanup_failed,
            ))
            .catch_unwind()
            .await
            .is_err()
            {
                // Staging's unwind guard retains it; a panic is never drain proof.
                cleanup_failed.store(true, Ordering::Release);
            }
        });
        drop(accepting);
        Ok(PendingGitHubEnrollment {
            cancellation: Some(cancellation),
            challenge: Some(challenge_rx),
            result: Some(result_rx),
        })
    }

    /// Close admission, cancel and await all retained drain/cleanup owners.
    pub async fn shutdown(&self) -> Result<(), GitHubEnrollmentError> {
        {
            let mut accepting = self.accepting.lock().unwrap_or_else(|p| p.into_inner());
            *accepting = false;
            self.workers.close();
            self.shutdown.cancel();
        }
        self.workers.wait().await;
        if self.cleanup_failed.load(Ordering::Acquire) {
            Err(GitHubEnrollmentError::Cleanup)
        } else {
            Ok(())
        }
    }
}

impl Drop for GitHubEnrollmentOwner {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.workers.close();
    }
}

/// Dropping a waiter signals cancellation, never aborts the owned worker.
pub struct PendingGitHubEnrollment {
    cancellation: Option<CancellationToken>,
    challenge: Option<oneshot::Receiver<Result<GitHubDeviceChallenge, GitHubEnrollmentError>>>,
    result: Option<oneshot::Receiver<Result<CompletedGitHubEnrollment, GitHubEnrollmentError>>>,
}

impl PendingGitHubEnrollment {
    /// Receive one bounded challenge under the original deadline.
    pub async fn challenge(&mut self) -> Result<GitHubDeviceChallenge, GitHubEnrollmentError> {
        self.challenge
            .take()
            .ok_or(GitHubEnrollmentError::Unavailable)?
            .await
            .map_err(|_| GitHubEnrollmentError::Unavailable)?
    }

    /// Receive validated material only after successful leader exit and drain.
    pub async fn complete(mut self) -> Result<CompletedGitHubEnrollment, GitHubEnrollmentError> {
        let result = self
            .result
            .take()
            .ok_or(GitHubEnrollmentError::Unavailable)?
            .await
            .map_err(|_| GitHubEnrollmentError::Unavailable)?;
        self.cancellation = None;
        result
    }

    /// Cancel and await actual terminal worker cleanup.
    pub async fn cancel(mut self) -> Result<(), GitHubEnrollmentError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        match self
            .result
            .take()
            .ok_or(GitHubEnrollmentError::Unavailable)?
            .await
        {
            Ok(Err(GitHubEnrollmentError::Cancelled)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Ok(Ok(completed)) => completed.finish(GitHubPublicationOutcome::Unknown).await,
            Err(_) => Err(GitHubEnrollmentError::Unavailable),
        }
    }
}

impl Drop for PendingGitHubEnrollment {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}

/// Storage disposition never implies remote GitHub token revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitHubPublicationOutcome {
    /// Storage acknowledged publication.
    Published,
    /// Storage definitely did not publish.
    NotPublished,
    /// Storage acknowledgement was lost or caller disappeared.
    Unknown,
}

/// Completed material plus still-owned private staging. No raw-token Debug.
pub struct CompletedGitHubEnrollment {
    imported: Option<GitHubOAuthImport>,
    disposition: Option<oneshot::Sender<GitHubPublicationOutcome>>,
    cleanup: Option<oneshot::Receiver<Result<(), GitHubEnrollmentError>>>,
    deadline: Instant,
    cancellation: CancellationToken,
}

impl CompletedGitHubEnrollment {
    /// Repeat immediately before issuing the caller-owned COMMIT.
    pub fn check_active(&self) -> Result<(), GitHubEnrollmentError> {
        check_active(&self.cancellation, self.deadline)
    }

    /// Move the imported token once into owner-fenced protected storage.
    pub fn take_import(&mut self) -> Result<GitHubOAuthImport, GitHubEnrollmentError> {
        self.check_active()?;
        self.imported
            .take()
            .ok_or(GitHubEnrollmentError::Unavailable)
    }

    /// Bound the caller wait; this cannot undo an already-issued publication.
    pub async fn wait_for_publication<T>(
        &self,
        publication: impl std::future::Future<Output = T>,
    ) -> Result<T, GitHubEnrollmentError> {
        self.check_active()?;
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(GitHubEnrollmentError::Cancelled),
            _ = tokio::time::sleep_until(self.deadline) => Err(GitHubEnrollmentError::Expired),
            result = publication => { self.check_active()?; Ok(result) }
        }
    }

    /// Await private cleanup. No outcome invokes gh logout or provider revoke.
    pub async fn finish(
        mut self,
        outcome: GitHubPublicationOutcome,
    ) -> Result<(), GitHubEnrollmentError> {
        self.imported = None;
        if let Some(disposition) = self.disposition.take() {
            let _ = disposition.send(outcome);
        }
        self.cleanup
            .take()
            .ok_or(GitHubEnrollmentError::Unavailable)?
            .await
            .map_err(|_| GitHubEnrollmentError::Unavailable)?
    }
}

// Unwind/drop is not group drain; only explicit completion authorizes deletion.
struct Staging(Option<PrivateProviderHome>);
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(home) = self.0.take() {
            home.retain();
        }
    }
}

async fn enrollment_worker(
    config: Arc<GitHubEnrollmentConfig>,
    cancellation: CancellationToken,
    deadline: Instant,
    expires_at_unix: u64,
    challenge_tx: oneshot::Sender<Result<GitHubDeviceChallenge, GitHubEnrollmentError>>,
    result_tx: oneshot::Sender<Result<CompletedGitHubEnrollment, GitHubEnrollmentError>>,
    cleanup_failed: &AtomicBool,
) {
    let mut challenge_tx = Some(challenge_tx);
    let home = match PrivateProviderHome::create_in(&config.private_tmpfs_root) {
        Ok(home) => home,
        Err(_) => {
            let _ = challenge_tx
                .take()
                .unwrap()
                .send(Err(GitHubEnrollmentError::Configuration));
            let _ = result_tx.send(Err(GitHubEnrollmentError::Configuration));
            return;
        }
    };
    let mut staging = Staging(Some(home));
    let home = staging.0.as_ref().expect("retained staging");
    let imported = run_login(
        &config,
        home,
        &cancellation,
        deadline,
        expires_at_unix,
        &mut challenge_tx,
    )
    .await;
    let imported = match imported {
        Ok(imported) => imported,
        Err(mut error) => {
            if error != GitHubEnrollmentError::Cleanup {
                let home = staging.0.take().expect("retained staging");
                if home.remove().is_err() {
                    error = GitHubEnrollmentError::Cleanup;
                }
            }
            if error == GitHubEnrollmentError::Cleanup {
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
    let _ = result_tx.send(Ok(CompletedGitHubEnrollment {
        imported: Some(imported),
        disposition: Some(disposition_tx),
        cleanup: Some(cleanup_rx),
        deadline,
        cancellation: cancellation.clone(),
    }));
    // Closed disposition means Unknown. Nothing here logs out/revokes a token.
    let _outcome = tokio::select! {
        biased;
        _ = cancellation.cancelled() => GitHubPublicationOutcome::Unknown,
        _ = tokio::time::sleep_until(deadline) => GitHubPublicationOutcome::Unknown,
        outcome = disposition_rx => outcome.unwrap_or(GitHubPublicationOutcome::Unknown),
    };
    let cleanup = staging
        .0
        .take()
        .expect("retained staging")
        .remove()
        .map_err(|_| GitHubEnrollmentError::Cleanup);
    if cleanup.is_err() {
        cleanup_failed.store(true, Ordering::Release);
    }
    let _ = cleanup_tx.send(cleanup);
}

fn isolated_command(config: &GitHubEnrollmentConfig, home: &PrivateProviderHome) -> Command {
    let mut command = Command::new(&config.executable);
    command
        .env_clear()
        .env("PATH", &config.child_path)
        .env("HOME", home.path())
        .env("GH_CONFIG_DIR", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_STATE_HOME", home.path())
        .env("TMPDIR", home.path())
        // gh activateUser invokes keyring even with --insecure-storage. Never
        // discover the real user's Linux session bus or autolaunch one.
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!(
                "unix:path={}",
                home.path().join("no-keyring.sock").display()
            ),
        )
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("TERM", "dumb")
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    command
}

fn check_active(
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<(), GitHubEnrollmentError> {
    if cancel.is_cancelled() {
        Err(GitHubEnrollmentError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(GitHubEnrollmentError::Expired)
    } else {
        Ok(())
    }
}

fn process_error(error: CodexEnrollmentError) -> GitHubEnrollmentError {
    if error == CodexEnrollmentError::Cleanup {
        GitHubEnrollmentError::Cleanup
    } else {
        GitHubEnrollmentError::Failed
    }
}

async fn run_login(
    config: &GitHubEnrollmentConfig,
    home: &PrivateProviderHome,
    cancel: &CancellationToken,
    deadline: Instant,
    expires_at_unix: u64,
    challenge_tx: &mut Option<
        oneshot::Sender<Result<GitHubDeviceChallenge, GitHubEnrollmentError>>,
    >,
) -> Result<GitHubOAuthImport, GitHubEnrollmentError> {
    let mut version = isolated_command(config, home);
    version.arg("--version");
    let mut version_output = Zeroizing::new(Vec::new());
    run_child(
        &mut version,
        cancel,
        deadline.min(Instant::now() + VERSION_TIMEOUT),
        |stderr, bytes| {
            if stderr || version_output.len().saturating_add(bytes.len()) > MAX_VERSION_BYTES {
                return Err(GitHubEnrollmentError::InvalidOutput);
            }
            version_output.extend_from_slice(bytes);
            Ok(())
        },
    )
    .await?;
    validate_version(&version_output)?;
    drop(version_output);
    let mut command = isolated_command(config, home);
    command.args([
        "auth",
        "login",
        "--hostname",
        "github.com",
        "--git-protocol",
        "https",
        "--web",
        "--insecure-storage",
        "--skip-ssh-key",
    ]);
    let mut parser = ChallengeParser::new(expires_at_unix);
    run_child(&mut command, cancel, deadline, |stderr, bytes| {
        if !stderr {
            return Err(GitHubEnrollmentError::InvalidOutput);
        }
        if let Some(challenge) = parser.push(bytes)?
            && let Some(sender) = challenge_tx.take()
        {
            sender
                .send(Ok(challenge))
                .map_err(|_| GitHubEnrollmentError::Cancelled)?;
        }
        Ok(())
    })
    .await?;
    let login = parser.finish()?;
    check_active(cancel, deadline)?;
    let source = read_private_file(home, "hosts.yml", MAX_HOSTS_BYTES)
        .map_err(|_| GitHubEnrollmentError::InvalidResult)?;
    let imported = import_hosts(&source, &login)?;
    check_active(cancel, deadline)?;
    Ok(imported)
}

// Output handling is provider-specific; process identity/kill/reap/EOF is the
// exact Codex-owned GroupChild primitive, never a second child runner.
async fn run_child(
    command: &mut Command,
    cancel: &CancellationToken,
    deadline: Instant,
    mut output: impl FnMut(bool, &[u8]) -> Result<(), GitHubEnrollmentError>,
) -> Result<(), GitHubEnrollmentError> {
    check_active(cancel, deadline)?;
    let mut group = GroupChild::spawn(command).map_err(process_error)?;
    let mut stdout = group.child.stdout.take().expect("owned stdout pipe");
    let mut stderr = group.child.stderr.take().expect("owned stderr pipe");
    let mut stdout_buffer = Zeroizing::new([0_u8; 4096]);
    let mut stderr_buffer = Zeroizing::new([0_u8; 4096]);
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut leader_result = None;
    let outcome = loop {
        if let Err(error) = check_active(cancel, deadline) {
            break Err(error);
        }
        if stdout_done
            && stderr_done
            && let Some(success) = leader_result
        {
            break if success {
                Ok(())
            } else {
                Err(GitHubEnrollmentError::Failed)
            };
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Err(GitHubEnrollmentError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => break Err(GitHubEnrollmentError::Expired),
            read = stdout.read(&mut *stdout_buffer), if !stdout_done => {
                match read {
                    Ok(0) => stdout_done = true,
                    Ok(count) => if let Err(error) = output(false, &stdout_buffer[..count]) { break Err(error); },
                    Err(_) => break Err(GitHubEnrollmentError::Failed),
                }
                stdout_buffer.zeroize();
            }
            read = stderr.read(&mut *stderr_buffer), if !stderr_done => {
                match read {
                    Ok(0) => stderr_done = true,
                    Ok(count) => if let Err(error) = output(true, &stderr_buffer[..count]) { break Err(error); },
                    Err(_) => break Err(GitHubEnrollmentError::Failed),
                }
                stderr_buffer.zeroize();
            }
            result = group.wait_without_reaping(), if leader_result.is_none() => {
                match result {
                    Ok(success) => {
                        leader_result = Some(success);
                        if let Err(error) = group.terminate() { break Err(process_error(error)); }
                    }
                    Err(error) => break Err(process_error(error)),
                }
            }
        }
    };
    group
        .stop_and_drain(&mut stdout, &mut stderr)
        .await
        .map_err(process_error)?;
    outcome?;
    check_active(cancel, deadline)
}
