//! Authority-retained repository jobs. An RPC waiter can cancel a preparation,
//! but cannot drop its child, lease channel or staging cleanup out from under it.

use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{fs, io};

use codewire_protected_store::ProtectedStore;
use futures::FutureExt as _;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStderr};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tonic::Status;

use super::run_blocking;
use crate::repository::{
    LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner, LocalRepositoryTransport,
    PlatformRepositoryConnection, PreparedRepositoryMetadata, REPOSITORY_SSH_RUNTIME_PREFIX,
    RepositoryExecutorError, RepositoryLeaseChannelError, create_repository_staging,
    prepared_bundle_path, read_prepared_repository, remove_repository_staging,
    serve_repository_lease_channel_with_ready, validate_repository_lease_request,
    validate_repository_ssh_runtime_path,
};
use crate::transport::AuthorityRuntimeError;
use crate::{LocalCredentialAuthority, RepositoryCredentialLeaseRequest};

const MAX_REPOSITORY_JOBS: u32 = 8;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(310);
const CHANNEL_CLOSE_GRACE: Duration = Duration::from_secs(1);
const PROCESS_GROUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct RepositoryProcessManager<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
    authority_root: PathBuf,
    jobs: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    failed: Arc<AtomicBool>,
    ssh_runtime: Arc<crate::broker_channel::LocalSshOperationRuntime>,
    platform_connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
}

impl<S: ProtectedStore + 'static> RepositoryProcessManager<S> {
    pub(super) fn new(
        authority: Arc<LocalCredentialAuthority<S>>,
        spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
        authority_root: PathBuf,
        ssh_runtime: Arc<crate::broker_channel::LocalSshOperationRuntime>,
        platform_connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
    ) -> Self {
        Self {
            authority,
            spawner,
            authority_root,
            jobs: Arc::new(Semaphore::new(MAX_REPOSITORY_JOBS as usize)),
            shutdown: watch::channel(false).0,
            failed: Arc::new(AtomicBool::new(false)),
            ssh_runtime,
            platform_connector,
        }
    }

    fn ensure_running(&self) -> Result<(), Status> {
        if *self.shutdown.borrow()
            || self.failed.load(Ordering::Acquire)
            || self.ssh_runtime.is_unhealthy()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) async fn prepare(
        self: &Arc<Self>,
        authorization: RepositoryCredentialLeaseRequest,
        platform: Option<crate::RepositoryPlatformAccess>,
    ) -> Result<PreparedRepository, Status> {
        validate_repository_lease_request(&authorization)
            .map_err(|_| Status::invalid_argument("invalid repository preparation request"))?;
        if let Some(platform) = &platform {
            platform.validate(&authorization)?;
        }
        self.ensure_running()?;
        let permit = Arc::clone(&self.jobs)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("local repository workers are busy"))?;
        // Shutdown publishes its durable signal before acquiring all permits.
        // A late acquirer therefore either already blocks drain or fails here.
        self.ensure_running()?;
        let (cancel_request, request) = watch::channel(false);
        let _waiter = RequestCancellation(cancel_request);
        let mut cancellation = JobCancellation {
            shutdown: self.shutdown.subscribe(),
            request,
            deadline: tokio::time::Instant::now() + START_TIMEOUT + EXECUTION_TIMEOUT,
        };
        let deadline = cancellation.deadline;
        let manager = Arc::clone(self);
        let (sender, receiver) = oneshot::channel();
        // The job owns its permit and manager through cleanup even if the
        // request future disappears. No RPC owns/aborts this JoinHandle.
        tokio::spawn(async move {
            let mut completion = JobCompletion {
                permit: Some(permit),
                failed: Arc::clone(&manager.failed),
                complete: false,
            };
            let result = manager
                .prepare_owned(authorization, platform, &mut cancellation)
                .await;
            let result = match cancellation.ensure_live() {
                Ok(()) => result,
                Err(error) => Err(error),
            };
            // A disconnected waiter drops any completed bundle here, after
            // process/channel drain, rather than unwinding cleanup early.
            match result {
                Ok(mut prepared) => {
                    completion.complete = true;
                    // The same permit also bounds queued/stalled bundles and
                    // remains owned until their staging cleanup has run.
                    prepared._completion = Some(completion);
                    let _ = sender.send(Ok(prepared));
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    completion.complete = true;
                }
            }
        });
        let mut shutdown = self.shutdown.subscribe();
        let prepared = tokio::select! {
            biased;
            () = wait_for_shutdown(&mut shutdown) => return Err(cancelled()),
            () = tokio::time::sleep_until(deadline) => return Err(cancelled()),
            result = receiver => result.map_err(|_| unavailable())??,
        };
        self.ensure_running()?;
        if tokio::time::Instant::now() >= deadline {
            return Err(cancelled());
        }
        Ok(prepared)
    }

    pub(super) fn cancel_all(&self) {
        self.shutdown.send_replace(true);
    }

    pub(super) fn shutdown_on_drop(&self) -> RepositoryShutdownGuard {
        RepositoryShutdownGuard(self.shutdown.clone())
    }

    pub(super) async fn shutdown_all(&self) -> Result<(), AuthorityRuntimeError> {
        self.cancel_all();
        let drained = Arc::clone(&self.jobs)
            .acquire_many_owned(MAX_REPOSITORY_JOBS)
            .await
            .map_err(|_| AuthorityRuntimeError::Serve)?;
        let failed = self.failed.load(Ordering::Acquire) || self.ssh_runtime.is_unhealthy();
        drop(drained);
        if failed {
            Err(AuthorityRuntimeError::Serve)
        } else {
            Ok(())
        }
    }

    async fn prepare_owned(
        &self,
        authorization: RepositoryCredentialLeaseRequest,
        platform: Option<crate::RepositoryPlatformAccess>,
        cancellation: &mut JobCancellation,
    ) -> Result<PreparedRepository, Status> {
        let mut connection = match platform {
            Some(access) => {
                let connector = self
                    .platform_connector
                    .as_ref()
                    .cloned()
                    .ok_or_else(unavailable)?;
                let deadline = cancellation.deadline;
                Some(tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(cancelled()),
                    connection = PlatformRepositoryConnection::connect(access, connector, deadline) => connection?,
                })
            }
            None => None,
        };
        // Keep transport/ingress owners outside both cancellation and panic
        // boundaries. Every path joins local cleanup before releasing the job.
        let outcome = AssertUnwindSafe(self.prepare_execution(
            authorization,
            connection.as_mut(),
            cancellation,
        ))
        .catch_unwind()
        .await;
        let closed = match connection.as_mut() {
            Some(connection) => connection.close().await,
            None => Ok(()),
        };
        let result = outcome.map_err(|_| {
            self.failed.store(true, Ordering::Release);
            unavailable()
        })?;
        closed?;
        result
    }

    async fn prepare_execution(
        &self,
        authorization: RepositoryCredentialLeaseRequest,
        platform: Option<&mut PlatformRepositoryConnection>,
        cancellation: &mut JobCancellation,
    ) -> Result<PreparedRepository, Status> {
        cancellation.ensure_live()?;
        let transport =
            validate_repository_lease_request(&authorization).map_err(|_| unavailable())?;
        let admitted = if platform.is_none() {
            let authority = Arc::clone(&self.authority);
            let preflight = authorization.clone();
            Some(
                run_blocking(move || authority.admit_repository_credential_operation(&preflight))
                    .await?,
            )
        } else {
            None
        };
        let platform_checkout = match platform {
            Some(platform) => {
                let deadline = cancellation.deadline;
                Some(tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(cancelled()),
                    result = platform.prepare_checkout(&authorization, deadline) => result?,
                })
            }
            None => None,
        };
        cancellation.ensure_live()?;
        let spawner = self.spawner.as_ref().cloned().ok_or_else(unavailable)?;
        let staging =
            create_repository_staging(&self.authority_root).map_err(repository_executor_status)?;
        let mut cleanup = RepositoryStagingGuard {
            path: Some(staging.clone()),
            failed: Arc::clone(&self.failed),
        };
        let mut ssh_cleanup = match transport {
            LocalRepositoryTransport::GitHubOAuth => None,
            LocalRepositoryTransport::Ssh => Some(create_repository_ssh_runtime(
                &self.authority_root,
                Arc::clone(&self.failed),
            )?),
        };
        let config = LocalRepositoryProcessConfig {
            request_id: authorization.request_id,
            staging_directory: staging.clone(),
            transport,
            platform_delegated: platform_checkout.is_some(),
            ssh_runtime_directory: ssh_cleanup
                .as_ref()
                .and_then(|cleanup| cleanup.path.clone()),
        };
        config.validate().map_err(|_| unavailable())?;
        let (authority_stream, executor_stream) =
            std::os::unix::net::UnixStream::pair().map_err(|_| unavailable())?;
        authority_stream
            .set_nonblocking(true)
            .map_err(|_| unavailable())?;
        let authority_stream = UnixStream::from_std(authority_stream).map_err(|_| unavailable())?;
        cancellation.ensure_live()?;
        let child = spawner
            .spawn(&config, executor_stream)
            .map_err(|_| unavailable())?;
        let mut child = RepositoryChild::new(child, config.transport);
        if !child.construction_valid() {
            self.failed.store(true, Ordering::Release);
            cleanup.path.take();
            if let Some(ssh_cleanup) = ssh_cleanup.as_mut() {
                ssh_cleanup.path.take();
            }
            let _ = child.stop_and_drain(false).await;
            return Err(unavailable());
        }
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let (lease_shutdown, shutdown_rx) = watch::channel(false);
        let mut lease_task = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&self.authority),
            authority_stream,
            authorization.clone(),
            Arc::clone(&self.ssh_runtime),
            platform_checkout,
            ready_tx,
            shutdown_rx,
        ));
        let mut lease_result = None;
        // The process and lease handles live OUTSIDE the caught operation.
        // Even a panic must take the same explicit kill/reap/channel drain.
        let outcome = AssertUnwindSafe(wait_for_executor(
            &mut child,
            &mut lease_task,
            &mut lease_result,
            &mut ready_rx,
            cancellation,
        ))
        .catch_unwind()
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => {
                self.failed.store(true, Ordering::Release);
                Err(unavailable())
            }
        };
        // Stop admission before awaiting child termination. Never abort the
        // lease task: its return also includes any retained blocking workers.
        lease_shutdown.send_replace(true);
        let child_drained = child.stop_and_drain(outcome.is_ok()).await;
        let lease_drained = match lease_result {
            Some(result) => result,
            None => lease_task.await,
        };
        if !child_drained || !matches!(lease_drained, Ok(Ok(()))) {
            self.failed.store(true, Ordering::Release);
            // No destructive staging cleanup when a process/channel drain
            // could not be proven. Startup reconciliation owns this exact
            // authority-created directory after the process lifetime ends.
            cleanup.path.take();
            if let Some(ssh_cleanup) = ssh_cleanup.as_mut() {
                ssh_cleanup.path.take();
            }
            return Err(unavailable());
        }
        drop(ssh_cleanup);
        let success = outcome?;
        if !success {
            return Err(unavailable());
        }
        cancellation.ensure_live()?;
        if let Some(admitted) = admitted {
            let authority = Arc::clone(&self.authority);
            let current = run_blocking(move || {
                authority.admit_repository_credential_operation(&authorization)
            })
            .await?;
            if current != admitted {
                return Err(Status::permission_denied(
                    "repository authorization changed",
                ));
            }
        }
        cancellation.ensure_live()?;
        self.ensure_running()?;
        let metadata = read_prepared_repository(&staging).map_err(repository_executor_status)?;
        let bundle = tokio::fs::File::open(prepared_bundle_path(&staging))
            .await
            .map_err(|_| unavailable())?;
        cancellation.ensure_live()?;
        Ok(PreparedRepository {
            metadata,
            bundle: Some(bundle),
            shutdown: self.shutdown.subscribe(),
            deadline: cancellation.deadline,
            _cleanup: cleanup,
            _completion: None,
        })
    }
}

fn create_repository_ssh_runtime(
    authority_root: &std::path::Path,
    failed: Arc<AtomicBool>,
) -> Result<RepositorySshRuntimeGuard, Status> {
    let path = authority_root.join(format!(
        "{REPOSITORY_SSH_RUNTIME_PREFIX}{}",
        uuid::Uuid::new_v4()
    ));
    validate_repository_ssh_runtime_path(&path).map_err(|_| unavailable())?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| unavailable())?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        let _ = fs::remove_dir(&path);
        return Err(unavailable());
    }
    Ok(RepositorySshRuntimeGuard {
        path: Some(path),
        identity: RepositorySshRuntimeIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        failed,
    })
}

fn remove_repository_ssh_runtime(
    path: &std::path::Path,
    expected: RepositorySshRuntimeIdentity,
) -> io::Result<()> {
    validate_repository_ssh_runtime_path(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid SSH runtime path"))?;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o700 =>
        {
            if metadata.dev() != expected.device || metadata.ino() != expected.inode {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SSH runtime identity changed",
                ));
            }
            fs::remove_dir_all(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SSH runtime ownership",
        )),
    }
}

pub(super) fn cleanup_repository_ssh_runtimes(
    authority_root: &std::path::Path,
) -> Result<(), AuthorityRuntimeError> {
    for entry in fs::read_dir(authority_root).map_err(|_| AuthorityRuntimeError::Serve)? {
        let entry = entry.map_err(|_| AuthorityRuntimeError::Serve)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_prefix(REPOSITORY_SSH_RUNTIME_PREFIX) else {
            continue;
        };
        if uuid::Uuid::parse_str(id)
            .is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == id)
        {
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| AuthorityRuntimeError::Serve)?;
            remove_repository_ssh_runtime(
                &entry.path(),
                RepositorySshRuntimeIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            )
            .map_err(|_| AuthorityRuntimeError::Serve)?;
        }
    }
    Ok(())
}

struct RepositorySshRuntimeGuard {
    path: Option<PathBuf>,
    identity: RepositorySshRuntimeIdentity,
    failed: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
struct RepositorySshRuntimeIdentity {
    device: u64,
    inode: u64,
}

impl Drop for RepositorySshRuntimeGuard {
    fn drop(&mut self) {
        if std::thread::panicking()
            || self
                .path
                .take()
                .is_some_and(|path| remove_repository_ssh_runtime(&path, self.identity).is_err())
        {
            self.failed.store(true, Ordering::Release);
        }
    }
}

type LeaseResult = Result<Result<(), RepositoryLeaseChannelError>, tokio::task::JoinError>;

async fn wait_for_executor(
    child: &mut RepositoryChild,
    lease_task: &mut tokio::task::JoinHandle<Result<(), RepositoryLeaseChannelError>>,
    lease_result: &mut Option<LeaseResult>,
    ready_rx: &mut oneshot::Receiver<()>,
    cancellation: &mut JobCancellation,
) -> Result<bool, Status> {
    let ready = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(cancelled()),
        ready = ready_rx => ready.is_ok(),
        _ = child.wait() => false,
        result = &mut *lease_task => { *lease_result = Some(result); false },
        () = tokio::time::sleep(START_TIMEOUT) => false,
    };
    if !ready {
        return Err(unavailable());
    }
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(cancelled()),
        status = child.wait() => status,
        () = tokio::time::sleep(EXECUTION_TIMEOUT) => {
            Err(Status::deadline_exceeded("local repository preparation timed out"))
        }
        result = lease_task => {
            *lease_result = Some(result);
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Err(cancelled()),
                status = tokio::time::timeout(CHANNEL_CLOSE_GRACE, child.wait()) => {
                    status.ok().and_then(Result::ok).ok_or_else(unavailable)
                }
            }
        }
    }
}

enum RepositoryChild {
    Single(Child),
    Group(GroupRepositoryChild),
}

impl RepositoryChild {
    fn new(mut child: Child, transport: LocalRepositoryTransport) -> Self {
        // Darwin has no parent-death signal for Git and its helpers, so a
        // macOS executor of either transport leads its own process group,
        // pipes stderr, and is stopped and drained like an SSH executor.
        let group = cfg!(target_os = "macos") || transport == LocalRepositoryTransport::Ssh;
        if !group {
            return Self::Single(child);
        }
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw)
            .filter(|pid| pid.as_raw_pid() > 1);
        let stderr = child
            .stderr
            .take()
            .map(|stderr| tokio::spawn(discard_stderr(stderr)));
        Self::Group(GroupRepositoryChild {
            child,
            pid,
            stderr,
            cleanup_failed: false,
        })
    }

    fn construction_valid(&self) -> bool {
        match self {
            Self::Single(_) => true,
            Self::Group(child) => child.pid.is_some() && child.stderr.is_some(),
        }
    }

    async fn wait(&mut self) -> Result<bool, Status> {
        match self {
            Self::Single(child) => child
                .wait()
                .await
                .map(|status| status.success())
                .map_err(|_| unavailable()),
            Self::Group(child) => child.wait_without_reaping().await,
        }
    }

    async fn stop_and_drain(&mut self, already_waited: bool) -> bool {
        match self {
            Self::Single(_) if already_waited => true,
            Self::Single(child) => {
                let _ = child.start_kill();
                child.wait().await.is_ok()
            }
            Self::Group(child) => child.stop_and_drain().await.is_ok(),
        }
    }
}

struct GroupRepositoryChild {
    child: Child,
    pid: Option<Pid>,
    stderr: Option<tokio::task::JoinHandle<Result<(), Status>>>,
    cleanup_failed: bool,
}

impl GroupRepositoryChild {
    async fn wait_without_reaping(&self) -> Result<bool, Status> {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .map_err(|_| unavailable())?;
        loop {
            let status = rustix::process::waitid(
                WaitId::Pid(self.pid.ok_or_else(unavailable)?),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| unavailable())?;
            if let Some(status) = status {
                return Ok(status.exited() && status.exit_status() == Some(0));
            }
            if signal.recv().await.is_none() {
                return Err(unavailable());
            }
        }
    }

    async fn stop_and_drain(&mut self) -> Result<(), Status> {
        if let Some(pid) = self.pid.take() {
            match rustix::process::kill_process_group(pid, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                // Darwin refuses to signal a group whose members have all
                // exited (the unreaped executor is a zombie). The stderr EOF
                // and reap below still prove that every member exited.
                #[cfg(target_os = "macos")]
                Err(rustix::io::Errno::PERM) => {}
                Err(_) => self.cleanup_failed = true,
            }
        } else {
            self.cleanup_failed = true;
            let _ = self.child.start_kill();
        }
        let result = tokio::time::timeout(PROCESS_GROUP_CLEANUP_TIMEOUT, async {
            let (child, stderr) = tokio::join!(self.child.wait(), observe_stderr(&mut self.stderr));
            child.map_err(|_| unavailable())?;
            stderr?;
            Ok::<_, Status>(())
        })
        .await
        .unwrap_or_else(|_| Err(unavailable()));
        self.cleanup_failed |= result.is_err();
        if result.is_err()
            && let Some(stderr) = self.stderr.take()
        {
            stderr.abort();
            let _ = stderr.await;
        }
        if self.cleanup_failed {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
}

impl Drop for GroupRepositoryChild {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }
}

async fn discard_stderr(mut stderr: ChildStderr) -> Result<(), Status> {
    use zeroize::Zeroize as _;

    let mut buffer = [0u8; 8192];
    loop {
        let read = stderr.read(&mut buffer).await.map_err(|_| unavailable())?;
        buffer.zeroize();
        if read == 0 {
            return Ok(());
        }
    }
}

async fn observe_stderr(
    task: &mut Option<tokio::task::JoinHandle<Result<(), Status>>>,
) -> Result<(), Status> {
    let Some(handle) = task.as_mut() else {
        return Err(unavailable());
    };
    let result = handle.await;
    *task = None;
    result.map_err(|_| unavailable())?
}

struct JobCancellation {
    shutdown: watch::Receiver<bool>,
    request: watch::Receiver<bool>,
    deadline: tokio::time::Instant,
}

impl JobCancellation {
    fn ensure_live(&self) -> Result<(), Status> {
        if *self.shutdown.borrow()
            || *self.request.borrow()
            || tokio::time::Instant::now() >= self.deadline
        {
            Err(cancelled())
        } else {
            Ok(())
        }
    }

    async fn cancelled(&mut self) {
        loop {
            if self.ensure_live().is_err() {
                return;
            }
            tokio::select! {
                result = self.shutdown.changed() => if result.is_err() { return },
                result = self.request.changed() => if result.is_err() { return },
                () = tokio::time::sleep_until(self.deadline) => return,
            }
        }
    }
}

struct RequestCancellation(watch::Sender<bool>);

pub(super) struct RepositoryShutdownGuard(watch::Sender<bool>);

impl Drop for RepositoryShutdownGuard {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

struct JobCompletion {
    permit: Option<OwnedSemaphorePermit>,
    failed: Arc<AtomicBool>,
    complete: bool,
}

impl Drop for JobCompletion {
    fn drop(&mut self) {
        if !self.complete || std::thread::panicking() {
            // Failure is visible before a released permit can wake drain or
            // admit another job. An unwind is never successful cleanup proof.
            self.failed.store(true, Ordering::Release);
        }
        drop(self.permit.take());
    }
}

pub(super) struct PreparedRepository {
    pub(super) metadata: PreparedRepositoryMetadata,
    pub(super) bundle: Option<tokio::fs::File>,
    pub(super) shutdown: watch::Receiver<bool>,
    pub(super) deadline: tokio::time::Instant,
    // Fields drop in declaration order: close bundle, remove staging/latch
    // failure, and only then release the manager's retained capacity.
    _cleanup: RepositoryStagingGuard,
    _completion: Option<JobCompletion>,
}

impl PreparedRepository {
    pub(super) fn latch_failure(&self) {
        self._cleanup.failed.store(true, Ordering::Release);
    }

    pub(super) async fn drain_bundle(&mut self) {
        if let Some(bundle) = self.bundle.take() {
            // A cancelled tokio File read may still own a blocking worker.
            // into_std waits for that worker; dropping File alone does not.
            drop(bundle.into_std().await);
        }
    }
}

pub(super) async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

struct RepositoryStagingGuard {
    path: Option<PathBuf>,
    failed: Arc<AtomicBool>,
}

impl Drop for RepositoryStagingGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Preserve for authority-owned startup reconciliation, never
            // remove a possibly live executor's files during an unwind.
            self.failed.store(true, Ordering::Release);
        } else if let Some(path) = self.path.take()
            && remove_repository_staging(&path).is_err()
        {
            self.failed.store(true, Ordering::Release);
        }
    }
}

fn repository_executor_status(_: RepositoryExecutorError) -> Status {
    unavailable()
}
fn unavailable() -> Status {
    Status::unavailable("local repository preparation failed")
}
fn cancelled() -> Status {
    Status::cancelled("local repository preparation was cancelled")
}

#[cfg(test)]
mod process_tests;

#[cfg(test)]
mod tests;
