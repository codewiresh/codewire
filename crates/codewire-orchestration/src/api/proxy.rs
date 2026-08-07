//! Shared sandbox exec and file service logic.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, mark_organization_mutation_resolution_required,
    release_organization_mutation_lease,
};
use codewire_server_core::{AppError, AppResult};
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ApiState;
use super::environments::require_environment_access;
use crate::confidential_storage::require_interactive_access;
use crate::sandbox::client::SandboxClient;
use crate::sandbox::exec::WorkspaceExecResult;

/// Mirrors `sandboxTarget`.
pub(crate) struct SandboxTarget {
    pub environment_id: String,
    pub namespace: String,
    pub pod_name: String,
}

/// Resolves a running sandbox target or returns its typed gate failure.
pub(crate) async fn resolve_running_sandbox_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    resolve_running_sandbox_target_for_role(state, user, org_id, env_id, "operator").await
}

pub(crate) async fn resolve_running_sandbox_target_for_role(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    required_role: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    if user_org_role(&state.pool, user, org_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "organization not found"));
    }
    if require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        required_role,
        "access denied",
    )
    .await
    .is_err()
    {
        return Err((StatusCode::FORBIDDEN, "access denied"));
    }

    // The environments read row carries state + type; resolve via the
    // same query the read surface uses, scoped to the org.
    let row = sqlx::query(
        "SELECT id, state, type, isolation_tier FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "environment not found"));
    };
    let id: String = row.get("id");
    let st: String = row.get("state");
    let env_type: String = row.get("type");
    let isolation_tier: String = row.get("isolation_tier");
    if let Err(error) =
        require_interactive_access(state.confidential_storage_flags, user, &isolation_tier)
    {
        return match error {
            AppError::Coded { status, .. } => Err((
                status,
                if status == StatusCode::SERVICE_UNAVAILABLE {
                    "confidential persistent storage is disabled"
                } else {
                    "global administrator user credential required"
                },
            )),
            _ => Err((StatusCode::FORBIDDEN, "access denied")),
        };
    }
    if st != "running" {
        return Err((StatusCode::BAD_REQUEST, "environment must be running"));
    }
    if env_type != "sandbox" {
        return Err((
            StatusCode::BAD_REQUEST,
            "only supported for sandbox environments",
        ));
    }

    let backend = sqlx::query(
        "SELECT namespace, COALESCE(pod_name, '') AS pod_name FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let namespace: String = backend
        .as_ref()
        .map(|r| r.get::<String, _>("namespace"))
        .unwrap_or_default();
    if namespace.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "sandbox backend not found"));
    }
    let pod_name: String = backend
        .map(|r| r.get::<String, _>("pod_name"))
        .unwrap_or_default();

    Ok(SandboxTarget {
        environment_id: id,
        namespace,
        pod_name,
    })
}

/// Maps sandbox gate failures into application errors for Connect handlers.
pub(crate) fn huma_error(status: StatusCode, msg: &'static str) -> AppError {
    match status {
        StatusCode::UNAUTHORIZED => AppError::Coded {
            status,
            code: "",
            detail: std::borrow::Cow::Borrowed(msg),
        },
        StatusCode::NOT_FOUND => AppError::NotFound(std::borrow::Cow::Borrowed(msg)),
        StatusCode::BAD_REQUEST => AppError::BadRequest(std::borrow::Cow::Borrowed(msg)),
        StatusCode::FORBIDDEN => AppError::Coded {
            status,
            code: "",
            detail: std::borrow::Cow::Borrowed(msg),
        },
        StatusCode::SERVICE_UNAVAILABLE => {
            AppError::ServiceUnavailable(std::borrow::Cow::Borrowed(msg))
        }
        _ => AppError::InternalMsg(std::borrow::Cow::Borrowed(msg)),
    }
}

fn sandbox_client(state: &ApiState, namespace: &str) -> Option<SandboxClient> {
    state
        .kube
        .as_ref()
        .map(|c| SandboxClient::new(c.clone(), namespace))
}

pub(crate) const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone)]
pub(crate) struct ExecInput {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: BTreeMap<String, String>,
    pub timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecStreamInput {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: BTreeMap<String, String>,
}

/// Output stays as bytes until the Connect renderer deliberately chooses its
/// wire shape.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExecStreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    UpstreamError(String),
}

/// Shared unary exec source: gate, command, timeout, Kubernetes attachment,
/// raw output bytes, and exit status.
pub(crate) async fn exec_in_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    input: ExecInput,
) -> AppResult<WorkspaceExecResult> {
    if state.kube.is_none() {
        return Err(AppError::ServiceUnavailable(
            "sandbox client not configured".into(),
        ));
    }

    let target = resolve_running_sandbox_target(state, user, org_id, env_id)
        .await
        .map_err(|(status, msg)| huma_error(status, msg))?;

    if input.command.is_empty() {
        return Err(AppError::BadRequest("command is required".into()));
    }

    let sb = sandbox_client(state, &target.namespace)
        .ok_or_else(|| AppError::ServiceUnavailable("sandbox client not configured".into()))?;

    let pod_name = if target.pod_name.trim().is_empty() {
        sb.get_pod_name(&target.environment_id)
            .await
            .map_err(|error| {
                AppError::ServiceUnavailable(format!("sandbox pod not found: {error}").into())
            })?
    } else {
        target.pod_name
    };
    let lease =
        acquire_environment_runtime_mutation_lease(&state.pool, org_id, &target.environment_id)
            .await?;
    let deadline = tokio::time::Instant::now() + input.timeout;
    let handle = match tokio::time::timeout_at(
        deadline,
        sb.start_workspace_exec_on_pod(&pod_name, &input.command, &input.working_dir, &input.env),
    )
    .await
    {
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            mark_organization_mutation_resolution_required(
                &state.pool,
                &lease.id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await?;
            return Err(AppError::Upstream(
                format!("workspace exec failed: {error}").into(),
            ));
        }
        Err(_) => {
            mark_organization_mutation_resolution_required(
                &state.pool,
                &lease.id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await?;
            return Err(AppError::Upstream(
                "workspace exec failed: timed out".into(),
            ));
        }
    };
    release_organization_mutation_lease(&state.pool, &lease.id).await?;

    match tokio::time::timeout_at(deadline, handle.wait()).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(AppError::Upstream(
            format!("workspace exec failed: {error}").into(),
        )),
        Err(_) => Err(AppError::Upstream(
            "workspace exec failed: timed out".into(),
        )),
    }
}

/// Shared streaming exec source with one gate, attachment, and byte lifecycle.
pub(crate) async fn exec_stream_in_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    input: ExecStreamInput,
) -> AppResult<tokio::sync::mpsc::UnboundedReceiver<ExecStreamEvent>> {
    if state.kube.is_none() {
        return Err(AppError::ServiceUnavailable(
            "sandbox client not configured".into(),
        ));
    }
    if input.command.is_empty() {
        return Err(AppError::BadRequest("command is required".into()));
    }

    let target = resolve_running_sandbox_target(state, user, org_id, env_id)
        .await
        .map_err(|(status, msg)| huma_error(status, msg))?;
    let sb = sandbox_client(state, &target.namespace)
        .ok_or_else(|| AppError::ServiceUnavailable("sandbox client not configured".into()))?;

    let pod_name = if target.pod_name.trim().is_empty() {
        sb.get_pod_name(&target.environment_id)
            .await
            .map_err(|error| {
                AppError::ServiceUnavailable(format!("sandbox pod not found: {error}").into())
            })?
    } else {
        target.pod_name
    };

    let lease =
        acquire_environment_runtime_mutation_lease(&state.pool, org_id, &target.environment_id)
            .await?;
    let handle = match sb
        .start_workspace_exec_on_pod(&pod_name, &input.command, &input.working_dir, &input.env)
        .await
    {
        Ok(handle) => handle,
        Err(error) => {
            mark_organization_mutation_resolution_required(
                &state.pool,
                &lease.id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await?;
            return Err(AppError::Upstream(
                format!("workspace exec failed: {error}").into(),
            ));
        }
    };
    release_organization_mutation_lease(&state.pool, &lease.id).await?;

    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::unbounded_channel::<(bool, Vec<u8>)>();
        let exec_fut = handle.stream(chunk_tx);
        tokio::pin!(exec_fut);

        let mut exec_done: Option<anyhow::Result<i32>> = None;
        loop {
            tokio::select! {
                chunk = chunk_rx.recv() => {
                    match chunk {
                        Some((is_stderr, bytes)) => {
                            let event = if is_stderr {
                                ExecStreamEvent::Stderr(bytes)
                            } else {
                                ExecStreamEvent::Stdout(bytes)
                            };
                            if event_tx.send(event).is_err() {
                                return;
                            }
                        }
                        None => {
                            if exec_done.is_none() {
                                exec_done = Some((&mut exec_fut).await);
                            }
                            break;
                        }
                    }
                }
                result = &mut exec_fut, if exec_done.is_none() => {
                    exec_done = Some(result);
                    // Drain chunks already queued before the sender closes.
                }
            }
        }

        let terminal = match exec_done {
            Some(Ok(exit_code)) => ExecStreamEvent::Exit(exit_code),
            Some(Err(error)) => ExecStreamEvent::UpstreamError(error.to_string()),
            None => return,
        };
        let _ = event_tx.send(terminal);
    });

    Ok(event_rx)
}
// ── file operations over SFTP ─────────────────────────────────────────────

const SFTP_CONNECT_ATTEMPTS: usize = 3;
const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
const FILE_CAT_TIMEOUT_SECS: u64 = 120;
pub(crate) const CONNECT_SFTP_REQUEST_TIMEOUT_SECS: u64 = 30;
pub(crate) const FILE_STREAM_CHUNK_SIZE: usize = 64 * 1024;
/// File metadata used by the Connect service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceFileEntry {
    pub name: String,
    pub size: i64,
    pub is_dir: bool,
    pub mode: u32,
    pub mod_time: Option<u32>,
}

struct WorkspaceFileTarget {
    environment_id: String,
    pod_name: String,
    sandbox: SandboxClient,
}

/// Semantic download failures consumed by the Connect service.
#[derive(Debug)]
pub(crate) enum WorkspaceFileReadError {
    App(AppError),
    Missing { detail: String },
    Directory,
    CommandFailed(String),
}

impl From<AppError> for WorkspaceFileReadError {
    fn from(error: AppError) -> Self {
        Self::App(error)
    }
}

enum WorkspaceFileDownloadSource {
    Buffered {
        data: Vec<u8>,
        offset: usize,
    },
    Sftp {
        file: russh_sftp::client::fs::File,
        _connection: Box<crate::sandbox::sidecar::SidecarSftp>,
    },
}

/// A prepared incremental download.
pub(crate) struct WorkspaceFileDownload {
    pub entry: WorkspaceFileEntry,
    source: WorkspaceFileDownloadSource,
}

impl WorkspaceFileDownload {
    pub(crate) async fn next_chunk(&mut self) -> AppResult<Option<Vec<u8>>> {
        match &mut self.source {
            WorkspaceFileDownloadSource::Buffered { data, offset } => {
                if *offset == data.len() {
                    return Ok(None);
                }
                let end = (*offset + FILE_STREAM_CHUNK_SIZE).min(data.len());
                let chunk = data[*offset..end].to_vec();
                *offset = end;
                Ok(Some(chunk))
            }
            WorkspaceFileDownloadSource::Sftp { file, .. } => {
                let mut chunk = vec![0_u8; FILE_STREAM_CHUNK_SIZE];
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(CONNECT_SFTP_REQUEST_TIMEOUT_SECS),
                    file.read(&mut chunk),
                )
                .await
                .map_err(|_| AppError::Upstream("workspace file open failed: timed out".into()))?
                .map_err(|error| {
                    AppError::Upstream(format!("workspace file open failed: {error}").into())
                })?;
                if read == 0 {
                    return Ok(None);
                }
                chunk.truncate(read);
                Ok(Some(chunk))
            }
        }
    }
}

pub(crate) struct WorkspaceFileUpload {
    file: russh_sftp::client::fs::File,
    connection: crate::sandbox::sidecar::SidecarSftp,
    path: String,
    size: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceFileUploadResult {
    pub path: String,
    pub size: i64,
}

impl WorkspaceFileUpload {
    pub(crate) async fn write_chunk(&mut self, chunk: &[u8]) -> AppResult<()> {
        self.file.write_all(chunk).await.map_err(|error| {
            AppError::Upstream(format!("workspace file upload failed: {error}").into())
        })?;
        self.size = self.size.checked_add(chunk.len() as i64).ok_or_else(|| {
            AppError::BadRequest("uploaded file exceeds the supported size".into())
        })?;
        Ok(())
    }

    pub(crate) async fn finish(&mut self) -> AppResult<WorkspaceFileUploadResult> {
        self.file.shutdown().await.map_err(|error| {
            AppError::Upstream(format!("workspace file upload failed: {error}").into())
        })?;
        Ok(WorkspaceFileUploadResult {
            path: self.path.clone(),
            size: self.size,
        })
    }

    /// Best-effort removal of a partial file after a broken or invalid client
    /// stream. The original protocol/transfer error remains authoritative.
    pub(crate) async fn abort(mut self) {
        let _ = self.file.shutdown().await;
        let _ = self.connection.session().remove_file(self.path).await;
    }
}

/// Mirrors `connectEnvironmentSFTPWithRetry`: up to 3 attempts with
/// linear backoff (the same flaky-sidecar guard the Go file routes use).
async fn connect_env_sftp(
    sb: &SandboxClient,
    env_id: &str,
) -> anyhow::Result<crate::sandbox::sidecar::SidecarSftp> {
    let mut last_err = None;
    for attempt in 0..SFTP_CONNECT_ATTEMPTS {
        match sb
            .connect_sidecar_sftp(env_id, crate::sandbox::sidecar::DEFAULT_GATEWAY_SSH_PORT)
            .await
        {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < SFTP_CONNECT_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_secs((attempt + 1) as u64)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("sftp connect failed")))
}

async fn resolve_workspace_file_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<WorkspaceFileTarget> {
    if state.kube.is_none() {
        return Err(AppError::ServiceUnavailable(
            "sandbox client not configured".into(),
        ));
    }
    let target = resolve_running_sandbox_target(state, user, org_id, env_id)
        .await
        .map_err(|(status, message)| huma_error(status, message))?;
    let sandbox = sandbox_client(state, &target.namespace)
        .ok_or_else(|| AppError::ServiceUnavailable("sandbox client not configured".into()))?;
    Ok(WorkspaceFileTarget {
        environment_id: target.environment_id,
        pod_name: target.pod_name,
        sandbox,
    })
}

async fn connect_workspace_sftp(
    target: &WorkspaceFileTarget,
    request_timeout_secs: Option<u64>,
) -> AppResult<crate::sandbox::sidecar::SidecarSftp> {
    let connection = connect_env_sftp(&target.sandbox, &target.environment_id)
        .await
        .map_err(|error| {
            AppError::Upstream(format!("workspace file connection failed: {error}").into())
        })?;
    if let Some(timeout) = request_timeout_secs {
        connection.session().set_timeout(timeout);
    }
    Ok(connection)
}

fn workspace_file_entry(
    name: String,
    metadata: &russh_sftp::client::fs::Metadata,
) -> WorkspaceFileEntry {
    WorkspaceFileEntry {
        name,
        size: metadata.size.unwrap_or(0).min(i64::MAX as u64) as i64,
        is_dir: metadata.is_dir(),
        mode: metadata.permissions.unwrap_or(0),
        mod_time: metadata.mtime,
    }
}

fn remote_file_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn sftp_missing(error: &russh_sftp::client::error::Error) -> bool {
    matches!(
        error,
        russh_sftp::client::error::Error::Status(status)
            if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile
    )
}

pub(crate) async fn list_workspace_files(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    path: &str,
    request_timeout_secs: Option<u64>,
) -> AppResult<Vec<WorkspaceFileEntry>> {
    let target = resolve_workspace_file_target(state, user, org_id, env_id).await?;
    let connection = connect_workspace_sftp(&target, request_timeout_secs).await?;
    let remote_path = if path.trim().is_empty() {
        DEFAULT_WORKSPACE_ROOT.to_string()
    } else {
        path.trim().to_string()
    };
    let entries = connection
        .session()
        .read_dir(remote_path)
        .await
        .map_err(|error| {
            AppError::Upstream(format!("workspace file list failed: {error}").into())
        })?;
    Ok(entries
        .map(|entry| workspace_file_entry(entry.file_name(), &entry.metadata()))
        .collect())
}

pub(crate) async fn begin_workspace_file_upload(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    path: &str,
    request_timeout_secs: Option<u64>,
) -> AppResult<WorkspaceFileUpload> {
    let remote_path = path.trim().to_string();
    if remote_path.is_empty() {
        return Err(AppError::BadRequest("path parameter is required".into()));
    }
    let target = resolve_workspace_file_target(state, user, org_id, env_id).await?;
    let connection = connect_workspace_sftp(&target, request_timeout_secs).await?;
    let parent = parent_dir(&remote_path);
    if parent != "." && parent != "/" {
        sftp_mkdir_all(connection.session(), &parent).await;
    }
    let file = connection
        .session()
        .create(remote_path.clone())
        .await
        .map_err(|error| {
            AppError::Upstream(format!("workspace file upload failed: {error}").into())
        })?;
    Ok(WorkspaceFileUpload {
        file,
        connection,
        path: remote_path,
        size: 0,
    })
}

async fn prepare_exec_file_download(
    target: &WorkspaceFileTarget,
    remote_path: &str,
) -> Result<WorkspaceFileDownload, WorkspaceFileReadError> {
    let command = vec!["cat".to_string(), remote_path.to_string()];
    let environment = BTreeMap::new();
    let exec = async {
        if target.pod_name.trim().is_empty() {
            target
                .sandbox
                .exec_workspace_result(&target.environment_id, &command, "", &environment)
                .await
        } else {
            target
                .sandbox
                .exec_workspace_result_on_pod(&target.pod_name, &command, "", &environment)
                .await
        }
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(FILE_CAT_TIMEOUT_SECS), exec)
        .await
        .map_err(|_| {
            WorkspaceFileReadError::App(AppError::Upstream("file read failed: timed out".into()))
        })?
        .map_err(|error| {
            WorkspaceFileReadError::App(AppError::Upstream(
                format!("file read failed: {error}").into(),
            ))
        })?;
    if result.exit_code != 0 {
        return Err(WorkspaceFileReadError::CommandFailed(
            String::from_utf8_lossy(&result.stderr).trim().to_string(),
        ));
    }

    Ok(WorkspaceFileDownload {
        entry: WorkspaceFileEntry {
            name: remote_file_name(remote_path),
            size: result.stdout.len().min(i64::MAX as usize) as i64,
            is_dir: false,
            mode: 0,
            mod_time: None,
        },
        source: WorkspaceFileDownloadSource::Buffered {
            data: result.stdout,
            offset: 0,
        },
    })
}

async fn prepare_sftp_file_download(
    target: &WorkspaceFileTarget,
    remote_path: &str,
    request_timeout_secs: Option<u64>,
) -> Result<WorkspaceFileDownload, WorkspaceFileReadError> {
    let connection = connect_workspace_sftp(target, request_timeout_secs)
        .await
        .map_err(WorkspaceFileReadError::App)?;
    let metadata = match connection.session().metadata(remote_path.to_string()).await {
        Ok(metadata) => metadata,
        Err(error) if sftp_missing(&error) => {
            return Err(WorkspaceFileReadError::Missing {
                detail: error.to_string(),
            });
        }
        Err(error) => {
            return Err(WorkspaceFileReadError::App(AppError::Upstream(
                format!("workspace file stat failed: {error}").into(),
            )));
        }
    };
    if metadata.is_dir() {
        return Err(WorkspaceFileReadError::Directory);
    }
    let file = match connection.session().open(remote_path.to_string()).await {
        Ok(file) => file,
        Err(error) if sftp_missing(&error) => {
            return Err(WorkspaceFileReadError::Missing {
                detail: error.to_string(),
            });
        }
        Err(error) => {
            return Err(WorkspaceFileReadError::App(AppError::Upstream(
                format!("workspace file open failed: {error}").into(),
            )));
        }
    };
    Ok(WorkspaceFileDownload {
        entry: workspace_file_entry(remote_file_name(remote_path), &metadata),
        source: WorkspaceFileDownloadSource::Sftp {
            file,
            _connection: Box::new(connection),
        },
    })
}

/// Connect's consolidated backend selector: exec-cat is authoritative when
/// it reaches the workspace; only an exec transport/setup failure falls back
/// to the SFTP sidecar. This keeps missing/directory results from being
/// misreported merely because the alternate backend behaves differently.
pub(crate) async fn prepare_workspace_file_download(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    path: &str,
) -> Result<WorkspaceFileDownload, WorkspaceFileReadError> {
    let remote_path = path.trim();
    if remote_path.is_empty() {
        return Err(WorkspaceFileReadError::App(AppError::BadRequest(
            "path parameter is required".into(),
        )));
    }
    let target = resolve_workspace_file_target(state, user, org_id, env_id).await?;
    match prepare_exec_file_download(&target, remote_path).await {
        Ok(download) => Ok(download),
        Err(WorkspaceFileReadError::App(AppError::Upstream(_))) => {
            prepare_sftp_file_download(
                &target,
                remote_path,
                Some(CONNECT_SFTP_REQUEST_TIMEOUT_SECS),
            )
            .await
        }
        Err(WorkspaceFileReadError::CommandFailed(detail)) => {
            if detail.to_ascii_lowercase().contains("is a directory") {
                Err(WorkspaceFileReadError::Directory)
            } else {
                Err(WorkspaceFileReadError::Missing { detail })
            }
        }
        Err(error) => Err(error),
    }
}

/// Mirrors `sftpClient.MkdirAll(parent)`: create each path level,
/// ignoring already-exists at each step.
async fn sftp_mkdir_all(session: &russh_sftp::client::SftpSession, dir: &str) {
    let mut cur = String::new();
    for comp in dir.split('/') {
        if comp.is_empty() {
            continue;
        }
        cur.push('/');
        cur.push_str(comp);
        let _ = session.create_dir(cur.clone()).await;
    }
}

/// `pathpkg.Dir`-style parent of a slash path.
fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => ".".to_string(),
    }
}
