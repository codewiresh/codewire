//! Sandbox exec proxy (#38 slice 6a) — port of the `execInEnvironment`
//! huma handler in `environment_proxy.go` plus the shared
//! `resolveRunningSandboxTarget` gate (reused by the file/stream
//! handlers in slice 6b).
//!
//! Verification note: the happy path proxies to a live sandbox pod over the
//! kube exec transport, so contract tests cover every gate error path (shared
//! by all proxy routes) and kind e2e covers the live path.
//!
//! The Go `humaError` helper includes the same status mapping used
//! here, including 403 for the shared access gate. Raw stream/file
//! handlers still keep their non-huma JSON error envelope.

use std::collections::BTreeMap;
use std::convert::Infallible;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, mark_organization_mutation_resolution_required,
    release_organization_mutation_lease,
};
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ApiState;
use super::environments::require_environment_access;
use super::prepare::json_response;
use crate::sandbox::client::SandboxClient;
use crate::sandbox::exec::WorkspaceExecResult;

fn safe_attachment_filename(remote_path: &str) -> String {
    let candidate = remote_path.rsplit(['/', '\\']).next().unwrap_or_default();
    let sanitized: String = candidate
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '.' | '-' | '_' | '(' | ')')
            {
                character
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "download".to_string()
    } else {
        sanitized.to_string()
    }
}

/// Mirrors `sandboxTarget`.
pub(crate) struct SandboxTarget {
    pub environment_id: String,
    pub namespace: String,
    pub pod_name: String,
}

/// Mirrors `resolveRunningSandboxTarget`: returns the target or a
/// `(status, message)` pair. Each handler maps the raw gate status to
/// the envelope it uses.
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
    let row = sqlx::query("SELECT id, state, type FROM environments WHERE id = $1 AND org_id = $2")
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

/// Mirrors `humaError`: plain huma errors keyed by status.
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

// ── exec (POST .../exec) ────────────────────────────────────────────────

/// Mirrors `api.ExecBody`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct ExecBody {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout: i64,
}

/// Mirrors `api.ExecResult`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub(crate) const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 600;

fn exec_timeout(timeout_seconds: i64) -> std::time::Duration {
    if timeout_seconds <= 0 {
        std::time::Duration::from_secs(DEFAULT_EXEC_TIMEOUT_SECS)
    } else {
        std::time::Duration::from_secs(timeout_seconds as u64)
    }
}

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

impl From<ExecBody> for ExecStreamInput {
    fn from(body: ExecBody) -> Self {
        Self {
            command: body.command,
            working_dir: body.working_dir,
            env: body.env,
        }
    }
}

/// Raw event feed shared by the legacy SSE renderer and StreamExec. Output
/// stays as bytes until a renderer deliberately chooses its wire shape.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExecStreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    UpstreamError(String),
}

impl From<ExecBody> for ExecInput {
    fn from(body: ExecBody) -> Self {
        Self {
            command: body.command,
            working_dir: body.working_dir,
            env: body.env,
            timeout: exec_timeout(body.timeout),
        }
    }
}

/// Shared unary exec source. REST and Connect render the same gate, command,
/// timeout, Kubernetes attachment, raw output bytes, and exit status.
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

/// Shared streaming exec source. Both the SSE and Connect handlers use this
/// gate, pod resolution, Kubernetes attachment, chunk channel, and terminal
/// status so the dual-served routes cannot diverge.
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

/// `POST /api/v1/organizations/{org_id}/environments/{env_id}/exec` —
/// mirrors `execInEnvironment`.
pub async fn exec_in_environment(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<ExecBody>,
) -> AppResult<Json<ExecResult>> {
    let result = exec_in_environment_core(&state, &user, &org_id, &env_id, body.into()).await?;

    Ok(Json(ExecResult {
        exit_code: result.exit_code,
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
    }))
}

// ── file cat (GET .../files/cat) — exec `cat`, raw handler ───────────────

/// `writeProxyJSONError` / `writeExecStreamJSONError` parity:
/// application/json, status, `{"error": msg}` + trailing newline.
fn proxy_json_error(status: StatusCode, msg: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": msg }))
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

/// `GET .../environments/{env_id}/files/cat` — mirrors
/// `downloadFileExecHandler` (reads a file via k8s exec `cat`, more
/// reliable than SFTP on isol8 sandboxes). Middleware-authed raw
/// handler: gate keeps raw status codes (403 stays 403).
pub async fn download_file_exec(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
) -> Response {
    if state.kube.is_none() {
        return proxy_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox client not configured",
        );
    }
    let remote_path = q.path.trim();
    if remote_path.is_empty() {
        return proxy_json_error(StatusCode::BAD_REQUEST, "path parameter is required");
    }
    let target = match resolve_workspace_file_target(&state, &user, &org_id, &env_id).await {
        Ok(target) => target,
        Err(error) => return exec_stream_json_error(error),
    };
    let mut download = match prepare_exec_file_download(&target, remote_path).await {
        Ok(download) => download,
        Err(WorkspaceFileReadError::CommandFailed(detail)) => {
            return proxy_json_error(StatusCode::NOT_FOUND, &detail);
        }
        Err(WorkspaceFileReadError::App(error)) => return exec_stream_json_error(error),
        Err(WorkspaceFileReadError::Missing { detail, .. }) => {
            return proxy_json_error(StatusCode::NOT_FOUND, &detail);
        }
        Err(WorkspaceFileReadError::Directory) => {
            return proxy_json_error(StatusCode::NOT_FOUND, "path is a directory");
        }
    };
    let mut data = Vec::with_capacity(download.entry.size.max(0) as usize);
    loop {
        match download.next_chunk().await {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(error) => return exec_stream_json_error(error),
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, data.len())
        .body(Body::from(data))
        .expect("octet-stream response")
}

// ── exec stream (POST .../exec/stream) — SSE, raw handler ────────────────

/// Mirrors `execStreamFrame` (omitempty data/exit_code/error).
#[derive(Debug, Serialize)]
struct ExecStreamFrame<'a> {
    #[serde(rename = "type")]
    typ: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    data: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "str::is_empty")]
    error: &'a str,
}

fn sse_frame(event: &str, frame: &ExecStreamFrame) -> String {
    let payload = serde_json::to_string(frame).unwrap_or_default();
    format!("event: {event}\ndata: {payload}\n\n")
}

/// `POST .../environments/{env_id}/exec/stream` — mirrors
/// `environmentExecStreamHandler` (SSE stdout/stderr/exit frames).
pub async fn exec_stream(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    body_bytes: axum::body::Bytes,
) -> Response {
    // Preserve the legacy SSE setup-error ordering while the route dual-serves:
    // an unavailable Kubernetes client wins even when the request body is bad.
    if state.kube.is_none() {
        return proxy_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox client not configured",
        );
    }

    let body: ExecBody = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => return proxy_json_error(StatusCode::BAD_REQUEST, "invalid JSON body"),
    };
    let events =
        match exec_stream_in_environment_core(&state, &user, &org_id, &env_id, body.into()).await {
            Ok(events) => events,
            Err(error) => return exec_stream_json_error(error),
        };

    let stream = futures::stream::unfold(events, |mut events| async move {
        let event = events.recv().await?;
        let frame = match event {
            ExecStreamEvent::Stdout(bytes) => {
                let data = String::from_utf8_lossy(&bytes);
                sse_frame(
                    "stdout",
                    &ExecStreamFrame {
                        typ: "stdout",
                        data: &data,
                        exit_code: None,
                        error: "",
                    },
                )
            }
            ExecStreamEvent::Stderr(bytes) => {
                let data = String::from_utf8_lossy(&bytes);
                sse_frame(
                    "stderr",
                    &ExecStreamFrame {
                        typ: "stderr",
                        data: &data,
                        exit_code: None,
                        error: "",
                    },
                )
            }
            ExecStreamEvent::Exit(exit_code) => sse_frame(
                "exit",
                &ExecStreamFrame {
                    typ: "exit",
                    data: "",
                    exit_code: Some(exit_code),
                    error: "",
                },
            ),
            ExecStreamEvent::UpstreamError(error) => sse_frame(
                "error",
                &ExecStreamFrame {
                    typ: "error",
                    data: "",
                    exit_code: None,
                    error: &error,
                },
            ),
        };
        Some((Ok::<_, Infallible>(frame), events))
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .expect("sse response")
}

fn exec_stream_json_error(error: AppError) -> Response {
    let (status, detail) = match error {
        AppError::NotFound(detail) => (StatusCode::NOT_FOUND, detail),
        AppError::BadRequest(detail) | AppError::Precondition(detail) => {
            (StatusCode::BAD_REQUEST, detail)
        }
        AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
        AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
        AppError::Conflict(detail) => (StatusCode::CONFLICT, detail),
        AppError::Validation { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "validation failed".into())
        }
        AppError::Upstream(detail) => (StatusCode::BAD_GATEWAY, detail),
        AppError::ServiceUnavailable(detail) => (StatusCode::SERVICE_UNAVAILABLE, detail),
        AppError::InternalMsg(detail) => (StatusCode::INTERNAL_SERVER_ERROR, detail),
        AppError::Coded { status, detail, .. } => (status, detail),
        AppError::Internal(error) => {
            tracing::error!(error = ?error, "exec stream setup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
        }
    };
    proxy_json_error(status, &detail)
}

// ── file ops over SFTP (#38 slice 6b-2) ──────────────────────────────────
//
// Port of listFiles (huma) + uploadFileHandler / downloadFileHandler
// (raw) in environment_proxy.go. The connection path mirrors Go's
// connectEnvironmentSFTPWithRetry → ConnectSidecarSFTP (port-forward to
// the gateway sidecar's SSH, none-auth, sftp subsystem). Contract tests cover
// the gate/disabled error paths; the live transfer is covered by the kind SFTP
// smoke. For Kata sandboxes,
// `SandboxClient` uses direct pod-IP TCP first because kubelet
// port-forward cannot reach listeners inside the guest VM loopback.

const SFTP_CONNECT_ATTEMPTS: usize = 3;
const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
const FILE_CAT_TIMEOUT_SECS: u64 = 120;
pub(crate) const CONNECT_SFTP_REQUEST_TIMEOUT_SECS: u64 = 30;
pub(crate) const FILE_STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Mirrors `api.FileEntry`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FileEntry {
    pub name: String,
    pub size: i64,
    pub is_dir: bool,
    pub mode: String,
    pub mod_time: String,
}

/// Transport-neutral file metadata shared by the REST and Connect renderers.
/// `mode` deliberately retains the raw SFTP permission bits; REST formats the
/// low permission bits as its historical four-digit octal string.
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

/// Semantic download failures. Both public transports consume the same
/// backend result, then retain their documented renderer differences while
/// REST dual-serves: Connect normalizes missing files and directories, while
/// REST keeps the existing raw status/body shapes.
#[derive(Debug)]
pub(crate) enum WorkspaceFileReadError {
    App(AppError),
    Missing {
        operation: &'static str,
        detail: String,
    },
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

/// A prepared download. The source stays incremental even though the legacy
/// REST renderer still joins chunks to preserve its content-length response.
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
                operation: "stat",
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
                operation: "open",
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
                Err(WorkspaceFileReadError::Missing {
                    operation: "cat",
                    detail,
                })
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

/// Mirrors `modeString`: 4-digit octal of the permission bits.
fn mode_string(perms: u32) -> String {
    format!("{:04o}", perms & 0o777)
}

/// `time.RFC3339` in UTC (Go: `ModTime().UTC().Format(time.RFC3339)`).
fn mod_time_rfc3339(mtime: Option<u32>) -> String {
    mtime
        .and_then(|s| chrono::DateTime::<chrono::Utc>::from_timestamp(s as i64, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// `GET .../environments/{env_id}/files` — mirrors `listFiles` (huma
/// envelope, 502 on connect/list failures).
pub async fn list_files(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
) -> AppResult<Json<Vec<FileEntry>>> {
    let entries = list_workspace_files(&state, &user, &org_id, &env_id, &q.path, None).await?;
    Ok(Json(
        entries
            .into_iter()
            .map(|entry| FileEntry {
                name: entry.name,
                size: entry.size,
                is_dir: entry.is_dir,
                mode: mode_string(entry.mode),
                mod_time: mod_time_rfc3339(entry.mod_time),
            })
            .collect(),
    ))
}

/// `POST .../environments/{env_id}/files/upload?path=` — mirrors
/// `uploadFileHandler` (raw: gate keeps raw codes, 502 on transfer
/// failures, `{path,size}` JSON on success).
pub async fn upload_file(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
    body: axum::body::Bytes,
) -> Response {
    if state.kube.is_none() {
        return proxy_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox client not configured",
        );
    }
    let mut upload =
        match begin_workspace_file_upload(&state, &user, &org_id, &env_id, &q.path, None).await {
            Ok(upload) => upload,
            Err(error) => return exec_stream_json_error(error),
        };
    if let Err(error) = upload.write_chunk(body.as_ref()).await {
        upload.abort().await;
        return exec_stream_json_error(error);
    }
    let result = match upload.finish().await {
        Ok(result) => result,
        Err(error) => {
            upload.abort().await;
            return exec_stream_json_error(error);
        }
    };
    json_response(
        StatusCode::OK,
        &serde_json::json!({ "path": result.path, "size": result.size }),
    )
}

/// `GET .../environments/{env_id}/files/download?path=` — mirrors
/// `downloadFileHandler` (raw: 400 on a directory, octet-stream body).
pub async fn download_file(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    Query(q): Query<PathQuery>,
) -> Response {
    if state.kube.is_none() {
        return proxy_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox client not configured",
        );
    }
    let remote_path = q.path.trim().to_string();
    if remote_path.is_empty() {
        return proxy_json_error(StatusCode::BAD_REQUEST, "path parameter is required");
    }
    let target = match resolve_workspace_file_target(&state, &user, &org_id, &env_id).await {
        Ok(target) => target,
        Err(error) => return exec_stream_json_error(error),
    };
    let mut download = match prepare_sftp_file_download(&target, &remote_path, None).await {
        Ok(download) => download,
        Err(WorkspaceFileReadError::Missing { operation, detail }) => {
            return proxy_json_error(
                StatusCode::BAD_GATEWAY,
                &format!("workspace file {operation} failed: {detail}"),
            );
        }
        Err(WorkspaceFileReadError::Directory) => {
            return proxy_json_error(StatusCode::BAD_REQUEST, "path is a directory");
        }
        Err(WorkspaceFileReadError::App(error)) => return exec_stream_json_error(error),
        Err(WorkspaceFileReadError::CommandFailed(detail)) => {
            return proxy_json_error(StatusCode::BAD_GATEWAY, &detail);
        }
    };
    let mut data = Vec::new();
    loop {
        match download.next_chunk().await {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(error) => return exec_stream_json_error(error),
        }
    }

    let filename = safe_attachment_filename(&remote_path);
    let disposition = match HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        Ok(value) => value,
        Err(_) => {
            return proxy_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build file response",
            );
        }
    };
    match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, data.len())
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(data))
    {
        Ok(response) => response,
        Err(_) => proxy_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to build file response",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn exec_stream_frames_match_go_shapes() {
        let f = ExecStreamFrame {
            typ: "stdout",
            data: "hello",
            exit_code: None,
            error: "",
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"stdout","data":"hello"}"#
        );
        let f = ExecStreamFrame {
            typ: "exit",
            data: "",
            exit_code: Some(0),
            error: "",
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"exit","exit_code":0}"#
        );
        let f = ExecStreamFrame {
            typ: "error",
            data: "",
            exit_code: None,
            error: "boom",
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"error","error":"boom"}"#
        );
        assert_eq!(
            sse_frame(
                "stdout",
                &ExecStreamFrame {
                    typ: "stdout",
                    data: "x",
                    exit_code: None,
                    error: ""
                }
            ),
            "event: stdout\ndata: {\"type\":\"stdout\",\"data\":\"x\"}\n\n"
        );
    }

    #[test]
    fn exec_timeout_defaults_to_ten_minutes() {
        assert_eq!(exec_timeout(0).as_secs(), 600);
        assert_eq!(exec_timeout(-5).as_secs(), 600);
        assert_eq!(exec_timeout(30).as_secs(), 30);
    }

    #[test]
    fn exec_body_schema_has_no_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(ExecBody)).unwrap();

        assert!(
            schema.get("required").is_none(),
            "Go/huma exec body keeps command required as handler-level validation"
        );
    }

    #[test]
    fn exec_body_validation_accepts_empty_body() {
        let parsed = validate_value::<ExecBody>(serde_json::json!({})).expect("empty body");

        assert!(parsed.command.is_empty());
        assert_eq!(parsed.working_dir, "");
        assert!(parsed.env.is_empty());
        assert_eq!(parsed.timeout, 0);
    }

    #[test]
    fn exec_body_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) = validate_value::<ExecBody>(serde_json::json!({
            "command": "echo hi"
        })) else {
            panic!("expected type-invalid command to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/command");
        assert!(errors[0].message.contains("array"));
    }

    #[tokio::test]
    async fn huma_error_mirrors_go_status_mapping() {
        // Plain mappings.
        let cases = [
            (
                StatusCode::NOT_FOUND,
                "organization not found",
                StatusCode::NOT_FOUND,
            ),
            (
                StatusCode::BAD_REQUEST,
                "environment must be running",
                StatusCode::BAD_REQUEST,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "sandbox backend not found",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                StatusCode::FORBIDDEN,
                "access denied",
                StatusCode::FORBIDDEN,
            ),
        ];
        for (gate, msg, want) in cases {
            let resp = huma_error(gate, msg).into_response();
            assert_eq!(resp.status(), want, "gate {gate} msg {msg}");
        }
    }

    #[test]
    fn mode_string_is_four_digit_octal_perms() {
        assert_eq!(mode_string(0o644), "0644");
        assert_eq!(mode_string(0o755), "0755");
        // Type/setuid bits above 0o777 are masked off, like Go's
        // FileMode.Perm().
        assert_eq!(mode_string(0o100644), "0644");
        assert_eq!(mode_string(0o040755), "0755");
    }

    #[test]
    fn parent_dir_mirrors_path_dir() {
        assert_eq!(parent_dir("/workspace/a/b.txt"), "/workspace/a");
        assert_eq!(parent_dir("/file"), "/");
        assert_eq!(parent_dir("file"), ".");
    }

    #[test]
    fn attachment_filename_is_ascii_header_safe() {
        assert_eq!(
            safe_attachment_filename("/workspace/release notes (final).txt"),
            "release notes (final).txt"
        );
        assert_eq!(
            safe_attachment_filename("/workspace/report\r\nInjected: value\".txt"),
            "report__Injected_ value_.txt"
        );
        assert_eq!(
            safe_attachment_filename("/workspace/naïve.txt"),
            "na_ve.txt"
        );
        assert_eq!(
            safe_attachment_filename("/workspace/path\\escape.txt"),
            "escape.txt"
        );
        assert_eq!(safe_attachment_filename("/workspace/"), "download");
        assert_eq!(safe_attachment_filename(".."), "download");

        for path in [
            "/workspace/report\r\nInjected: value\".txt",
            "/workspace/naïve.txt",
            "/workspace/path\\escape.txt",
        ] {
            let value = format!(
                "attachment; filename=\"{}\"",
                safe_attachment_filename(path)
            );
            HeaderValue::from_str(&value).expect("sanitized filename must be a valid header");
        }
    }

    #[test]
    fn mod_time_is_rfc3339_utc_z() {
        // 2021-01-01T00:00:00Z = 1609459200.
        assert_eq!(
            mod_time_rfc3339(Some(1_609_459_200)),
            "2021-01-01T00:00:00Z"
        );
        assert_eq!(mod_time_rfc3339(None), "");
    }

    #[test]
    fn file_entry_serializes_with_go_field_names() {
        let e = FileEntry {
            name: "x.txt".into(),
            size: 12,
            is_dir: false,
            mode: "0644".into(),
            mod_time: "2021-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["name"], "x.txt");
        assert_eq!(v["size"], 12);
        assert_eq!(v["is_dir"], false);
        assert_eq!(v["mode"], "0644");
        assert_eq!(v["mod_time"], "2021-01-01T00:00:00Z");
    }
}
