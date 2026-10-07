//! Durable platform environment resize admission and operation reads.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use chrono::NaiveDateTime;
use codewire_daemon_proto::daemon::v1::SessionLifecycleState;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::{Row, Transaction};

use super::ApiState;
use super::environment_daemon::list_environment_daemon_sessions_core;
use super::environments::{
    Environment, fetch_env_summary, get_environment_core, get_org_quota,
    require_environment_access, require_org_member, trigger_environment,
};
use crate::confidential_storage::require_interactive_access;
use crate::resize_metrics::{self, RequestOutcome};
use crate::sandbox::client::WorkspacePodResizeState;
use crate::sandbox::client::{SandboxClient, WorkspacePvcAnchor};
use crate::sandbox::template::{RUNTIME_CLASS_COMMODITY, RUNTIME_CLASS_RUNC};

const ACTIVE_OPERATION_STATES: [&str; 3] = ["pending", "applying", "restarting"];

/// Runtime classes whose Kata VM is sized once, when the Pod sandbox starts.
///
/// `commodity` runs the `kata-clh` handler: Kata runtime-rs with the upstream
/// Cloud Hypervisor configuration, which sets
/// `static_sandbox_resource_mgmt = true`. Kata derives the VM's vCPUs and
/// memory from the Pod's container limits at sandbox creation. A later Pod
/// `/resize` changes only the in-guest cgroup limits, so a larger memory limit
/// is not backed by guest RAM, and CPU above the boot vCPU count is not backed
/// by vCPUs (#2266).
///
/// The boot vCPU count also depends on the node's Kata defaults and sizing
/// formula, which orchestration cannot read, and a Pod resized in place before
/// #2266 no longer shows its boot limits. Codewire therefore cannot prove CPU
/// headroom from the Pod spec: every CPU or memory increase replaces the Pod,
/// and only CPU decreases stay live.
const STATIC_VM_RUNTIME_CLASSES: [&str; 2] = [RUNTIME_CLASS_COMMODITY, "kata-clh"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EnvironmentResources {
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentResizeDisruptionPolicy {
    LiveOnly,
    AllowRestart,
}

impl EnvironmentResizeDisruptionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveOnly => "live_only",
            Self::AllowRestart => "allow_restart",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentResizeExecutionMode {
    Noop,
    ApplyOnStart,
    InPlace,
    Restart,
}

impl EnvironmentResizeExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::ApplyOnStart => "apply_on_start",
            Self::InPlace => "in_place",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentResizePlan {
    pub previous_resources: EnvironmentResources,
    pub desired_resources: EnvironmentResources,
    pub execution_mode: EnvironmentResizeExecutionMode,
    pub active_session_count: i32,
    pub active_sessions_will_be_terminated: bool,
    pub reason: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentResizeFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentResizeOperation {
    pub id: String,
    pub org_id: String,
    pub environment_id: String,
    pub request_id: String,
    pub previous_resources: EnvironmentResources,
    pub desired_resources: EnvironmentResources,
    pub last_applied_resources: EnvironmentResources,
    pub previous_state: String,
    pub previous_desired_state: String,
    pub state: String,
    pub force: bool,
    pub disruption_policy: EnvironmentResizeDisruptionPolicy,
    pub planned_mode: EnvironmentResizeExecutionMode,
    pub applied_mode: Option<EnvironmentResizeExecutionMode>,
    pub pod_replaced: bool,
    pub reserved_cpu_millicores: i32,
    pub reserved_memory_mb: i32,
    pub failure: Option<EnvironmentResizeFailure>,
    pub previous_pod_uid: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub completed_at: Option<NaiveDateTime>,
}

impl EnvironmentResizeOperation {
    pub fn is_active(&self) -> bool {
        ACTIVE_OPERATION_STATES.contains(&self.state.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ResizeEnvironmentParams {
    pub org_id: String,
    pub environment_id: String,
    pub desired_resources: EnvironmentResources,
    pub request_id: String,
    pub force: bool,
    pub disruption_policy: EnvironmentResizeDisruptionPolicy,
}

#[derive(Debug, Clone)]
pub struct PlanEnvironmentResizeParams {
    pub org_id: String,
    pub environment_id: String,
    pub desired_resources: EnvironmentResources,
}

#[derive(Debug, Clone)]
pub struct PlanEnvironmentResizeResult {
    pub plan: EnvironmentResizePlan,
    pub environment: Environment,
}

#[derive(Debug, Clone)]
pub struct ResizeEnvironmentResult {
    pub operation: EnvironmentResizeOperation,
    pub environment: Environment,
}

#[derive(Debug)]
struct LockedEnvironment {
    state: String,
    desired_state: String,
    env_type: String,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
}

fn coded(status: StatusCode, code: &'static str, detail: impl Into<Cow<'static, str>>) -> AppError {
    AppError::Coded {
        status,
        code,
        detail: detail.into(),
    }
}

/// Setup progress as recorded on the backend row. The schema keeps the owner
/// tuple all-or-nothing, so its status alone says whether a lease is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
struct SetupProgress {
    setup_complete: bool,
    setup_failed: bool,
    owner_present: bool,
}

macro_rules! setup_progress_sql {
    () => {
        "SELECT setup_complete,
                COALESCE(btrim(setup_error), '') <> '' AS setup_failed,
                setup_owner_status IS NOT NULL AS owner_present
           FROM sandbox_environment_backend
          WHERE environment_id = $1"
    };
}
const SETUP_PROGRESS_SQL: &str = setup_progress_sql!();
const SETUP_PROGRESS_FOR_UPDATE_SQL: &str = concat!(setup_progress_sql!(), " FOR UPDATE");

/// Setup owns a running runtime from create until it completes or records its
/// failure, and for as long as any setup lease tuple (including `reaping`)
/// remains. Admitting a resize there replaces the `started` intent that the
/// lease is fenced on: setup then treats the change as authority loss, scales
/// the Sandbox to zero to fence its attached process, and cannot resume it
/// (#2328). Source restart and session launch refuse the same window.
fn setup_owns_running_runtime(state: &str, setup: Option<SetupProgress>) -> bool {
    state == "running"
        && setup.is_some_and(|setup| {
            setup.owner_present || (!setup.setup_complete && !setup.setup_failed)
        })
}

fn setup_in_progress() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "invalid_state",
        "environment setup is still in progress; try again when it finishes",
    )
}

fn validate_request(params: &ResizeEnvironmentParams) -> AppResult<()> {
    if params.org_id.trim().is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "org_id is required",
        ));
    }
    if params.environment_id.trim().is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "environment_id is required",
        ));
    }
    let request_id = params.request_id.trim();
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "request_id must contain 1 to 128 characters",
        ));
    }
    validate_resources(params.desired_resources)
}

fn validate_resources(desired: EnvironmentResources) -> AppResult<()> {
    if desired.cpu_millicores <= 0 || desired.memory_mb <= 0 || desired.disk_gb <= 0 {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "cpu_millicores, memory_mb, and disk_gb must be greater than zero",
        ));
    }
    Ok(())
}

fn active_daemon_session(state: i32) -> bool {
    matches!(
        SessionLifecycleState::try_from(state).unwrap_or(SessionLifecycleState::Unspecified),
        SessionLifecycleState::Starting | SessionLifecycleState::Running
    )
}

pub(crate) fn classify_execution_mode(
    environment_state: &str,
    previous: EnvironmentResources,
    desired: EnvironmentResources,
    pod: Option<&WorkspacePodResizeState>,
) -> AppResult<(EnvironmentResizeExecutionMode, String)> {
    if desired == previous {
        return Ok((
            EnvironmentResizeExecutionMode::Noop,
            "resources are unchanged".into(),
        ));
    }
    if environment_state == "stopped" {
        return Ok((
            EnvironmentResizeExecutionMode::ApplyOnStart,
            "resources will be applied when the environment next starts".into(),
        ));
    }

    let compute_changed = desired.cpu_millicores != previous.cpu_millicores
        || desired.memory_mb != previous.memory_mb;
    if !compute_changed {
        return Ok((
            EnvironmentResizeExecutionMode::InPlace,
            "persistent storage will be expanded without replacing the workspace Pod".into(),
        ));
    }
    if desired.memory_mb < previous.memory_mb {
        return Ok((
            EnvironmentResizeExecutionMode::Restart,
            "memory shrink requires replacement so guest memory is actually reclaimed".into(),
        ));
    }

    let pod = pod.ok_or_else(|| {
        coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "workspace Pod is unavailable for a running environment",
        )
    })?;
    if !pod.live_resize_compatible {
        return Ok((
            EnvironmentResizeExecutionMode::Restart,
            pod.incompatibility_reason
                .clone()
                .unwrap_or_else(|| "workspace container resize policy requires restart".into()),
        ));
    }
    let runtime_class = pod.runtime_class_name.as_str();
    if STATIC_VM_RUNTIME_CLASSES.contains(&runtime_class) {
        // Memory shrink already returned above, so memory is equal or larger.
        if desired.memory_mb > previous.memory_mb {
            return Ok((
                EnvironmentResizeExecutionMode::Restart,
                format!(
                    "runtime class {runtime_class} sizes the workspace VM when the Pod starts; \
                     memory growth needs a replacement Pod to reach the guest"
                ),
            ));
        }
        if desired.cpu_millicores > previous.cpu_millicores {
            return Ok((
                EnvironmentResizeExecutionMode::Restart,
                format!(
                    "runtime class {runtime_class} fixes the workspace VM's vCPUs when the Pod \
                     starts; a CPU increase needs a replacement Pod to reach the guest"
                ),
            ));
        }
        return Ok((
            EnvironmentResizeExecutionMode::InPlace,
            "the CPU reduction will be applied through the Kubernetes Pod /resize subresource"
                .into(),
        ));
    }
    if !matches!(runtime_class, "" | RUNTIME_CLASS_RUNC) {
        return Ok((
            EnvironmentResizeExecutionMode::Restart,
            format!("runtime class {runtime_class} does not provide verified live compute resize"),
        ));
    }
    Ok((
        EnvironmentResizeExecutionMode::InPlace,
        "CPU and memory will be applied through the Kubernetes Pod /resize subresource".into(),
    ))
}

/// state, type, namespace, cpu, memory, disk, claim name, claim UID, PVC UID.
type ResizePlanRow = (
    String,
    String,
    Option<String>,
    i32,
    i32,
    i32,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn build_resize_plan(
    state: &ApiState,
    user: &AuthUser,
    params: &PlanEnvironmentResizeParams,
) -> AppResult<EnvironmentResizePlan> {
    let row: Option<ResizePlanRow> = sqlx::query_as(
        "SELECT state, type, b.namespace, e.cpu_millicores, e.memory_mb, e.disk_gb,
                b.sandbox_claim_name, b.sandbox_claim_uid, b.workspace_pvc_uid
           FROM environments e
           LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
          WHERE e.id = $1 AND e.org_id = $2",
    )
    .bind(&params.environment_id)
    .bind(&params.org_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((
        environment_state,
        env_type,
        namespace,
        cpu_millicores,
        memory_mb,
        disk_gb,
        claim_name,
        claim_uid,
        recorded_pvc_uid,
    )) = row
    else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        ));
    };
    if env_type != "sandbox" {
        return Err(coded(
            StatusCode::PRECONDITION_FAILED,
            "resize_unsupported",
            "environment type does not support resize",
        ));
    }
    if !matches!(environment_state.as_str(), "running" | "stopped") {
        return Err(coded(
            StatusCode::CONFLICT,
            "invalid_state",
            format!("environment cannot be resized while {environment_state}"),
        ));
    }
    // Review refuses early so the plan never offers an Apply that admission
    // must reject; admission rechecks under the environment row lock.
    if environment_state == "running" {
        let setup = sqlx::query_as::<_, SetupProgress>(SETUP_PROGRESS_SQL)
            .bind(&params.environment_id)
            .fetch_optional(&state.pool)
            .await?;
        if setup_owns_running_runtime(&environment_state, setup) {
            return Err(setup_in_progress());
        }
    }
    let previous = EnvironmentResources {
        cpu_millicores,
        memory_mb,
        disk_gb,
    };
    if params.desired_resources.disk_gb < previous.disk_gb {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "storage_shrink_forbidden",
            format!(
                "persistent storage cannot shrink from {} Gi to {} Gi",
                previous.disk_gb, params.desired_resources.disk_gb
            ),
        ));
    }

    let compute_changed = params.desired_resources.cpu_millicores != previous.cpu_millicores
        || params.desired_resources.memory_mb != previous.memory_mb;
    let needs_runtime = params.desired_resources.disk_gb > previous.disk_gb
        || (environment_state == "running" && compute_changed);
    let client = if needs_runtime {
        let kube = state.kube.clone().ok_or_else(|| {
            coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_unavailable",
                "sandbox runtime is unavailable",
            )
        })?;
        let namespace = namespace.as_deref().unwrap_or_default();
        if namespace.trim().is_empty() {
            return Err(coded(
                StatusCode::PRECONDITION_FAILED,
                "resize_unsupported",
                "environment has no sandbox runtime",
            ));
        }
        Some(SandboxClient::new(kube, namespace))
    } else {
        None
    };

    let storage = if params.desired_resources.disk_gb > previous.disk_gb {
        // The shared resolver: the recorded Claim and PVC UIDs, never a name.
        let anchor = WorkspacePvcAnchor {
            claim_name: claim_name.unwrap_or_default(),
            claim_uid: claim_uid.unwrap_or_default(),
            recorded_pvc_uid,
        };
        Some(
            client
                .as_ref()
                .expect("runtime client required for disk growth")
                .require_workspace_storage_resize(&anchor, params.desired_resources.disk_gb)
                .await
                .map_err(|error| {
                    coded(
                        StatusCode::PRECONDITION_FAILED,
                        "storage_expansion_unsupported",
                        error.to_string(),
                    )
                })?,
        )
    } else {
        None
    };

    let pod = if environment_state == "running" && compute_changed {
        Some(
            client
                .as_ref()
                .expect("runtime client required for running environment")
                .workspace_pod_resize_state(&params.environment_id)
                .await
                .map_err(|error| {
                    coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "runtime_unavailable",
                        error.to_string(),
                    )
                })?,
        )
    } else {
        None
    };
    let (mut execution_mode, mut reason) = classify_execution_mode(
        &environment_state,
        previous,
        params.desired_resources,
        pod.as_ref(),
    )?;
    if environment_state == "running"
        && storage
            .as_ref()
            .is_some_and(|storage| storage.filesystem_resize_pending)
    {
        execution_mode = EnvironmentResizeExecutionMode::Restart;
        reason =
            "Kubernetes requires workspace Pod replacement to finish filesystem expansion".into();
    }

    let active_session_count = if execution_mode == EnvironmentResizeExecutionMode::Restart {
        let sessions = list_environment_daemon_sessions_core(
            state,
            user,
            &params.org_id,
            &params.environment_id,
        )
        .await?;
        sessions
            .iter()
            .filter(|session| active_daemon_session(session.state))
            .count() as i32
    } else {
        0
    };
    let mut warnings = Vec::new();
    if execution_mode == EnvironmentResizeExecutionMode::Restart {
        warnings.push(
            "Codewire will delete and recreate the workspace Pod; the environment and PVC remain"
                .into(),
        );
    }
    if execution_mode == EnvironmentResizeExecutionMode::InPlace {
        warnings.push("The live path will not replace or restart the workspace container".into());
    }
    if params.desired_resources.disk_gb > previous.disk_gb {
        warnings.push("Persistent storage growth cannot be reversed".into());
    }
    if execution_mode == EnvironmentResizeExecutionMode::Restart && active_session_count > 0 {
        warnings.push(format!(
            "{active_session_count} active session(s) must be terminated before restart"
        ));
    }
    Ok(EnvironmentResizePlan {
        previous_resources: previous,
        desired_resources: params.desired_resources,
        execution_mode,
        active_session_count,
        active_sessions_will_be_terminated: execution_mode
            == EnvironmentResizeExecutionMode::Restart
            && active_session_count > 0,
        reason,
        warnings,
    })
}

pub async fn plan_environment_resize_core(
    state: &ApiState,
    user: &AuthUser,
    params: PlanEnvironmentResizeParams,
) -> AppResult<PlanEnvironmentResizeResult> {
    if params.org_id.trim().is_empty() || params.environment_id.trim().is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "org_id and environment_id are required",
        ));
    }
    validate_resources(params.desired_resources)?;
    require_org_member(&state.pool, user, &params.org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        &params.environment_id,
        &params.org_id,
        "owner",
        "only environment owners can plan environment resize",
    )
    .await?;
    let environment =
        fetch_env_summary(&state.pool, &params.org_id, &params.environment_id).await?;
    require_interactive_access(
        state.confidential_storage_flags,
        user,
        &environment.isolation_tier,
    )?;
    let plan = build_resize_plan(state, user, &params).await?;
    let environment =
        get_environment_core(state, user, &params.org_id, &params.environment_id).await?;
    Ok(PlanEnvironmentResizeResult { plan, environment })
}

pub async fn resize_environment_core(
    state: &ApiState,
    user: &AuthUser,
    params: ResizeEnvironmentParams,
) -> AppResult<ResizeEnvironmentResult> {
    let result = resize_environment_core_inner(state, user, params).await;
    match &result {
        Ok((result, outcome)) => {
            resize_metrics::record_request(*outcome);
            if *outcome == RequestOutcome::Accepted {
                if result.operation.state == "completed" {
                    resize_metrics::record_terminal_after_commit(
                        "completed",
                        result
                            .operation
                            .applied_mode
                            .unwrap_or(result.operation.planned_mode),
                        result
                            .operation
                            .completed_at
                            .map(|completed_at| (result.operation.created_at, completed_at)),
                    );
                }
                resize_metrics::refresh_active_best_effort(&state.pool).await;
            }
        }
        Err(_) => resize_metrics::record_request(RequestOutcome::Rejected),
    }
    result.map(|(result, _)| result)
}

async fn resize_environment_core_inner(
    state: &ApiState,
    user: &AuthUser,
    mut params: ResizeEnvironmentParams,
) -> AppResult<(ResizeEnvironmentResult, RequestOutcome)> {
    params.request_id = params.request_id.trim().to_string();
    validate_request(&params)?;
    require_org_member(&state.pool, user, &params.org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        &params.environment_id,
        &params.org_id,
        "owner",
        "only environment owners can resize environments",
    )
    .await?;
    let environment =
        fetch_env_summary(&state.pool, &params.org_id, &params.environment_id).await?;
    require_interactive_access(
        state.confidential_storage_flags,
        user,
        &environment.isolation_tier,
    )?;

    if let Some(operation) = find_existing_operation(state, &params).await? {
        if operation.desired_resources != params.desired_resources
            || operation.force != params.force
            || operation.disruption_policy != params.disruption_policy
        {
            return Err(coded(
                StatusCode::CONFLICT,
                "request_id_conflict",
                "request_id was already used with different resize resources or consent",
            ));
        }
        if operation.is_active() {
            trigger_environment(state, &params.environment_id, "resize")
                .await
                .map_err(|_| {
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "resize_dispatch_failed",
                        "failed to redispatch environment resize",
                    )
                })?;
        }
        return Ok((
            ResizeEnvironmentResult {
                operation,
                environment: get_environment_core(
                    state,
                    user,
                    &params.org_id,
                    &params.environment_id,
                )
                .await?,
            },
            RequestOutcome::Idempotent,
        ));
    }
    if active_operation_exists(state, &params.environment_id).await? {
        return Err(coded(
            StatusCode::CONFLICT,
            "resize_in_progress",
            "another resize operation is active for this environment",
        ));
    }
    let plan = build_resize_plan(
        state,
        user,
        &PlanEnvironmentResizeParams {
            org_id: params.org_id.clone(),
            environment_id: params.environment_id.clone(),
            desired_resources: params.desired_resources,
        },
    )
    .await?;
    if plan.execution_mode == EnvironmentResizeExecutionMode::Restart
        && params.disruption_policy != EnvironmentResizeDisruptionPolicy::AllowRestart
    {
        return Err(coded(
            StatusCode::PRECONDITION_FAILED,
            "restart_consent_required",
            format!(
                "resize requires workspace Pod replacement: {}; retry with allow-restart consent",
                plan.reason
            ),
        ));
    }
    if plan.execution_mode == EnvironmentResizeExecutionMode::Restart
        && plan.active_session_count > 0
        && !params.force
    {
        return Err(coded(
            StatusCode::PRECONDITION_FAILED,
            "active_sessions",
            format!(
                "environment has {} active session(s); restart requires force=true to terminate them",
                plan.active_session_count
            ),
        ));
    }

    let quota = get_org_quota(&state.pool, &params.org_id).await;
    let dispatch_ambiguous = AtomicBool::new(false);
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    let owned_params = params.clone();
    let operation = run_environment_runtime_mutation(
        &state.pool,
        &params.org_id,
        &params.environment_id,
        async move {
            let state = &owned_state;
            let params = owned_params;
            let result: AppResult<(EnvironmentResizeOperation, bool)> = async {
                let (operation, admitted) = begin_resize_operation(
                    &state.pool,
                    &params,
                    &plan,
                    quota.max_cpu_millicores,
                    quota.max_memory_mb,
                )
                .await?;
                if operation.is_active()
                    && trigger_environment(state, &params.environment_id, "resize")
                        .await
                        .is_err()
                {
                    dispatch_ambiguous.store(true, Ordering::Release);
                    return Err(coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "resize_dispatch_failed",
                        "failed to dispatch environment resize",
                    ));
                }
                Ok((operation, admitted))
            }
            .await;
            match result {
                Ok(operation) => Ok(operation),
                Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                    Err(OrganizationRuntimeMutationError::ambiguous(error))
                }
                Err(error) => Err(error.into()),
            }
        },
    )
    .await?;

    let (operation, admitted) = operation;
    let environment =
        get_environment_core(state, user, &params.org_id, &params.environment_id).await?;
    Ok((
        ResizeEnvironmentResult {
            operation,
            environment,
        },
        if admitted {
            RequestOutcome::Accepted
        } else {
            RequestOutcome::Idempotent
        },
    ))
}

async fn find_existing_operation(
    state: &ApiState,
    params: &ResizeEnvironmentParams,
) -> AppResult<Option<EnvironmentResizeOperation>> {
    let row = sqlx::query(
        "SELECT * FROM environment_resize_operations
          WHERE org_id = $1 AND environment_id = $2 AND request_id = $3",
    )
    .bind(&params.org_id)
    .bind(&params.environment_id)
    .bind(&params.request_id)
    .fetch_optional(&state.pool)
    .await?;
    row.as_ref().map(scan_operation).transpose()
}

async fn active_operation_exists(state: &ApiState, environment_id: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM environment_resize_operations
              WHERE environment_id = $1
                AND state IN ('pending', 'applying', 'restarting')
         )",
    )
    .bind(environment_id)
    .fetch_one(&state.pool)
    .await?)
}

async fn begin_resize_operation(
    pool: &sqlx::PgPool,
    params: &ResizeEnvironmentParams,
    plan: &EnvironmentResizePlan,
    max_cpu_millicores: i32,
    max_memory_mb: i32,
) -> AppResult<(EnvironmentResizeOperation, bool)> {
    let mut tx = pool.begin().await?;
    let org_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(&params.org_id)
            .fetch_optional(&mut *tx)
            .await?;
    if org_exists.is_none() {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    }

    if let Some(existing) =
        find_operation_by_request(&mut tx, &params.environment_id, &params.request_id).await?
    {
        if existing.desired_resources != params.desired_resources
            || existing.force != params.force
            || existing.disruption_policy != params.disruption_policy
        {
            return Err(coded(
                StatusCode::CONFLICT,
                "request_id_conflict",
                "request_id was already used with different resize resources or consent",
            ));
        }
        tx.commit().await?;
        return Ok((existing, false));
    }

    let row = sqlx::query(
        "SELECT state, desired_state, type, cpu_millicores, memory_mb, disk_gb
           FROM environments
          WHERE id = $1 AND org_id = $2
          FOR UPDATE",
    )
    .bind(&params.environment_id)
    .bind(&params.org_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })?;
    let env = LockedEnvironment {
        state: row.try_get("state")?,
        desired_state: row.try_get("desired_state")?,
        env_type: row.try_get("type")?,
        cpu_millicores: row.try_get("cpu_millicores")?,
        memory_mb: row.try_get("memory_mb")?,
        disk_gb: row.try_get("disk_gb")?,
    };
    let active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM environment_resize_operations
          WHERE environment_id = $1 AND state = ANY($2)
          LIMIT 1",
    )
    .bind(&params.environment_id)
    .bind(&ACTIVE_OPERATION_STATES[..])
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_some() {
        return Err(coded(
            StatusCode::CONFLICT,
            "resize_in_progress",
            "another resize operation is active for this environment",
        ));
    }
    if env.env_type != "sandbox" || !matches!(env.state.as_str(), "running" | "stopped") {
        return Err(coded(
            StatusCode::CONFLICT,
            "invalid_state",
            "environment state changed before resize admission",
        ));
    }
    if env.state == "running" {
        // Setup lease transitions lock the environment row, then the backend
        // row. Holding both until the intent update commits excludes a new
        // setup owner between this check and `state = 'resizing'`.
        let setup = sqlx::query_as::<_, SetupProgress>(SETUP_PROGRESS_FOR_UPDATE_SQL)
            .bind(&params.environment_id)
            .fetch_optional(&mut *tx)
            .await?;
        if setup_owns_running_runtime(&env.state, setup) {
            return Err(setup_in_progress());
        }
    }

    let desired = params.desired_resources;
    let previous = EnvironmentResources {
        cpu_millicores: env.cpu_millicores,
        memory_mb: env.memory_mb,
        disk_gb: env.disk_gb,
    };
    if previous != plan.previous_resources || desired != plan.desired_resources {
        return Err(coded(
            StatusCode::CONFLICT,
            "resize_plan_stale",
            "environment resources changed after resize planning",
        ));
    }
    if desired.disk_gb < previous.disk_gb {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "storage_shrink_forbidden",
            "persistent storage cannot shrink",
        ));
    }
    let reserved_cpu = (desired.cpu_millicores - previous.cpu_millicores).max(0);
    let reserved_memory = (desired.memory_mb - previous.memory_mb).max(0);
    let (used_cpu, used_memory): (i64, i64) = sqlx::query_as(
        "SELECT
             COALESCE((SELECT SUM(cpu_millicores)::bigint FROM environments
                        WHERE org_id = $1
                          AND state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')), 0)
               + COALESCE((SELECT SUM(reserved_cpu_millicores)::bigint
                             FROM environment_resize_operations
                            WHERE org_id = $1 AND state = ANY($2)), 0),
             COALESCE((SELECT SUM(memory_mb)::bigint FROM environments
                        WHERE org_id = $1
                          AND state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')), 0)
               + COALESCE((SELECT SUM(reserved_memory_mb)::bigint
                             FROM environment_resize_operations
                            WHERE org_id = $1 AND state = ANY($2)), 0)",
    )
    .bind(&params.org_id)
    .bind(&ACTIVE_OPERATION_STATES[..])
    .fetch_one(&mut *tx)
    .await?;
    if max_cpu_millicores != -1
        && used_cpu + i64::from(reserved_cpu) > i64::from(max_cpu_millicores)
    {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "CPU limit would be exceeded ({}+{} > {} millicores)",
                used_cpu, reserved_cpu, max_cpu_millicores
            ),
        ));
    }
    if max_memory_mb != -1 && used_memory + i64::from(reserved_memory) > i64::from(max_memory_mb) {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "memory limit would be exceeded ({}+{} > {} MB)",
                used_memory, reserved_memory, max_memory_mb
            ),
        ));
    }

    let id = uuid::Uuid::new_v4().simple().to_string();
    let no_change = desired == previous;
    if no_change && plan.execution_mode != EnvironmentResizeExecutionMode::Noop {
        return Err(coded(
            StatusCode::CONFLICT,
            "resize_plan_stale",
            "environment resources changed after resize planning",
        ));
    }
    let operation_state = if no_change { "completed" } else { "pending" };
    let row = sqlx::query(
        "INSERT INTO environment_resize_operations (
             id, org_id, environment_id, request_id,
             previous_cpu_millicores, previous_memory_mb, previous_disk_gb,
             desired_cpu_millicores, desired_memory_mb, desired_disk_gb,
             last_applied_cpu_millicores, last_applied_memory_mb, last_applied_disk_gb,
             previous_state, previous_desired_state, state, force,
             disruption_policy, planned_mode, applied_mode,
             reserved_cpu_millicores, reserved_memory_mb, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $5, $6, $7,
                 $11, $12, $13, $14, $15, $16,
                 CASE WHEN $13 = 'completed' THEN $16 ELSE NULL END,
                 $17, $18,
                 CASE WHEN $13 = 'completed' THEN NOW() ELSE NULL END)
         RETURNING *",
    )
    .bind(&id)
    .bind(&params.org_id)
    .bind(&params.environment_id)
    .bind(&params.request_id)
    .bind(previous.cpu_millicores)
    .bind(previous.memory_mb)
    .bind(previous.disk_gb)
    .bind(desired.cpu_millicores)
    .bind(desired.memory_mb)
    .bind(desired.disk_gb)
    .bind(&env.state)
    .bind(&env.desired_state)
    .bind(operation_state)
    .bind(params.force)
    .bind(params.disruption_policy.as_str())
    .bind(plan.execution_mode.as_str())
    .bind(reserved_cpu)
    .bind(reserved_memory)
    .fetch_one(&mut *tx)
    .await?;

    if !no_change {
        sqlx::query(
            "UPDATE environments
                SET state = 'resizing', desired_state = 'resized', state_changed_at = NOW(),
                    error_reason = NULL
              WHERE id = $1",
        )
        .bind(&params.environment_id)
        .execute(&mut *tx)
        .await?;
    }
    let operation = scan_operation(&row)?;
    tx.commit().await?;
    Ok((operation, true))
}

pub async fn get_resize_operation_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    operation_id: &str,
) -> AppResult<ResizeEnvironmentResult> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        environment_id,
        org_id,
        "owner",
        "only environment owners can read resize operations",
    )
    .await?;
    let row = sqlx::query(
        "SELECT * FROM environment_resize_operations
          WHERE id = $1 AND environment_id = $2 AND org_id = $3",
    )
    .bind(operation_id)
    .bind(environment_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "resize_operation_not_found",
            "environment resize operation not found",
        )
    })?;
    Ok(ResizeEnvironmentResult {
        operation: scan_operation(&row)?,
        environment: get_environment_core(state, user, org_id, environment_id).await?,
    })
}

async fn find_operation_by_request(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    environment_id: &str,
    request_id: &str,
) -> AppResult<Option<EnvironmentResizeOperation>> {
    sqlx::query(
        "SELECT * FROM environment_resize_operations
          WHERE environment_id = $1 AND request_id = $2",
    )
    .bind(environment_id)
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(scan_operation)
    .transpose()
}

pub(crate) fn scan_operation(row: &PgRow) -> AppResult<EnvironmentResizeOperation> {
    let failure_code: Option<String> = row.try_get("failure_code")?;
    let failure_message: Option<String> = row.try_get("failure_message")?;
    Ok(EnvironmentResizeOperation {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        environment_id: row.try_get("environment_id")?,
        request_id: row.try_get("request_id")?,
        previous_resources: EnvironmentResources {
            cpu_millicores: row.try_get("previous_cpu_millicores")?,
            memory_mb: row.try_get("previous_memory_mb")?,
            disk_gb: row.try_get("previous_disk_gb")?,
        },
        desired_resources: EnvironmentResources {
            cpu_millicores: row.try_get("desired_cpu_millicores")?,
            memory_mb: row.try_get("desired_memory_mb")?,
            disk_gb: row.try_get("desired_disk_gb")?,
        },
        last_applied_resources: EnvironmentResources {
            cpu_millicores: row.try_get("last_applied_cpu_millicores")?,
            memory_mb: row.try_get("last_applied_memory_mb")?,
            disk_gb: row.try_get("last_applied_disk_gb")?,
        },
        previous_state: row.try_get("previous_state")?,
        previous_desired_state: row.try_get("previous_desired_state")?,
        state: row.try_get("state")?,
        force: row.try_get("force")?,
        disruption_policy: parse_disruption_policy(
            &row.try_get::<String, _>("disruption_policy")?,
        )?,
        planned_mode: parse_execution_mode(&row.try_get::<String, _>("planned_mode")?)?,
        applied_mode: row
            .try_get::<Option<String>, _>("applied_mode")?
            .as_deref()
            .map(parse_execution_mode)
            .transpose()?,
        pod_replaced: row.try_get("pod_replaced")?,
        reserved_cpu_millicores: row.try_get("reserved_cpu_millicores")?,
        reserved_memory_mb: row.try_get("reserved_memory_mb")?,
        failure: match (failure_code, failure_message) {
            (Some(code), Some(message)) => Some(EnvironmentResizeFailure { code, message }),
            _ => None,
        },
        previous_pod_uid: row.try_get("previous_pod_uid")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        completed_at: row.try_get("completed_at")?,
    })
}

fn parse_disruption_policy(value: &str) -> AppResult<EnvironmentResizeDisruptionPolicy> {
    match value {
        "live_only" => Ok(EnvironmentResizeDisruptionPolicy::LiveOnly),
        "allow_restart" => Ok(EnvironmentResizeDisruptionPolicy::AllowRestart),
        unexpected => Err(coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_stored_value",
            format!("invalid environment resize disruption policy {unexpected:?}"),
        )),
    }
}

fn parse_execution_mode(value: &str) -> AppResult<EnvironmentResizeExecutionMode> {
    match value {
        "noop" => Ok(EnvironmentResizeExecutionMode::Noop),
        "apply_on_start" => Ok(EnvironmentResizeExecutionMode::ApplyOnStart),
        "in_place" => Ok(EnvironmentResizeExecutionMode::InPlace),
        "restart" => Ok(EnvironmentResizeExecutionMode::Restart),
        unexpected => Err(coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_stored_value",
            format!("invalid environment resize execution mode {unexpected:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    fn params() -> ResizeEnvironmentParams {
        ResizeEnvironmentParams {
            org_id: "org-1".into(),
            environment_id: "env-1".into(),
            desired_resources: EnvironmentResources {
                cpu_millicores: 2_000,
                memory_mb: 4_096,
                disk_gb: 20,
            },
            request_id: "request-1".into(),
            force: false,
            disruption_policy: EnvironmentResizeDisruptionPolicy::LiveOnly,
        }
    }

    #[test]
    fn request_validation_requires_stable_identity_and_positive_resources() {
        assert!(validate_request(&params()).is_ok());
        let mut invalid = params();
        invalid.request_id.clear();
        assert!(validate_request(&invalid).is_err());
        invalid = params();
        invalid.desired_resources.memory_mb = 0;
        assert!(validate_request(&invalid).is_err());
    }

    #[test]
    fn only_starting_and_running_daemon_sessions_block_resize() {
        assert!(active_daemon_session(
            SessionLifecycleState::Starting as i32
        ));
        assert!(active_daemon_session(SessionLifecycleState::Running as i32));
        assert!(!active_daemon_session(
            SessionLifecycleState::Stopped as i32
        ));
        assert!(!active_daemon_session(SessionLifecycleState::Exited as i32));
    }

    #[test]
    fn execution_plan_prefers_live_resize_and_never_hides_restart() {
        let previous = EnvironmentResources {
            cpu_millicores: 1_000,
            memory_mb: 2_048,
            disk_gb: 10,
        };
        let compatible = pod_with_runtime_class("runc");
        let desired = EnvironmentResources {
            cpu_millicores: 2_000,
            ..previous
        };
        assert_eq!(
            classify_execution_mode("running", previous, desired, Some(&compatible))
                .unwrap()
                .0,
            EnvironmentResizeExecutionMode::InPlace
        );

        let default_runtime = pod_with_runtime_class("");
        assert_eq!(
            classify_execution_mode("running", previous, desired, Some(&default_runtime))
                .unwrap()
                .0,
            EnvironmentResizeExecutionMode::InPlace
        );

        let kata_snp = WorkspacePodResizeState {
            runtime_class_name: "kata-qemu-snp".into(),
            ..compatible.clone()
        };
        assert_eq!(
            classify_execution_mode("running", previous, desired, Some(&kata_snp))
                .unwrap()
                .0,
            EnvironmentResizeExecutionMode::Restart
        );

        let incompatible_policy = WorkspacePodResizeState {
            live_resize_compatible: false,
            incompatibility_reason: Some("memory uses restartPolicy RestartContainer".into()),
            ..compatible
        };
        assert_eq!(
            classify_execution_mode("running", previous, desired, Some(&incompatible_policy))
                .unwrap()
                .0,
            EnvironmentResizeExecutionMode::Restart
        );
        assert_eq!(
            classify_execution_mode("stopped", previous, desired, None)
                .unwrap()
                .0,
            EnvironmentResizeExecutionMode::ApplyOnStart
        );
    }

    fn pod_with_runtime_class(runtime_class_name: &str) -> WorkspacePodResizeState {
        WorkspacePodResizeState {
            identity: crate::sandbox::client::WorkspacePodIdentity {
                name: "workspace".into(),
                uid: "uid-1".into(),
            },
            runtime_class_name: runtime_class_name.into(),
            restart_count: 0,
            live_resize_compatible: true,
            incompatibility_reason: None,
        }
    }

    /// #2266: on Dev, kata-clh reported a live 1 CPU / 2 GiB -> 2 CPU / 4 GiB
    /// resize while guest `nproc` and `MemTotal` stayed at their boot values.
    #[test]
    fn static_vm_runtime_classes_replace_the_pod_for_any_compute_growth() {
        let previous = EnvironmentResources {
            cpu_millicores: 1_000,
            memory_mb: 2_048,
            disk_gb: 10,
        };
        let with = |cpu_millicores, memory_mb| EnvironmentResources {
            cpu_millicores,
            memory_mb,
            ..previous
        };
        for runtime_class in ["commodity", "kata-clh"] {
            let pod = pod_with_runtime_class(runtime_class);
            let classify = |desired| {
                classify_execution_mode("running", previous, desired, Some(&pod)).unwrap()
            };

            // The measured defect: CPU and memory growth together.
            let (mode, reason) = classify(with(2_000, 4_096));
            assert_eq!(mode, EnvironmentResizeExecutionMode::Restart);
            assert!(reason.contains("memory growth"), "{reason}");
            assert!(reason.contains(runtime_class), "{reason}");

            let (mode, reason) = classify(with(1_000, 3_072));
            assert_eq!(mode, EnvironmentResizeExecutionMode::Restart);
            assert!(reason.contains("memory growth"), "{reason}");

            // Kata's boot vCPU count is not provable from the Pod spec, so even
            // a fractional CPU increase replaces the Pod.
            for cpu_millicores in [1_001, 1_500, 2_000] {
                let (mode, reason) = classify(with(cpu_millicores, 2_048));
                assert_eq!(mode, EnvironmentResizeExecutionMode::Restart);
                assert!(reason.contains("CPU increase"), "{reason}");
            }

            // Lowering the in-guest CPU quota is real, so it stays live.
            let (mode, _) = classify(with(500, 2_048));
            assert_eq!(mode, EnvironmentResizeExecutionMode::InPlace);

            // Memory shrink keeps its existing all-runtime restart reason.
            let (mode, reason) = classify(with(500, 1_024));
            assert_eq!(mode, EnvironmentResizeExecutionMode::Restart);
            assert!(reason.contains("memory shrink"), "{reason}");

            // Stopped environments boot a new VM at the desired size.
            assert_eq!(
                classify_execution_mode("stopped", previous, with(2_000, 4_096), None)
                    .unwrap()
                    .0,
                EnvironmentResizeExecutionMode::ApplyOnStart
            );

            // Storage-only growth never touches the VM's compute size.
            assert_eq!(
                classify(EnvironmentResources {
                    disk_gb: 20,
                    ..previous
                })
                .0,
                EnvironmentResizeExecutionMode::InPlace
            );
        }

        // runc (Kind) keeps live CPU and memory growth.
        for runtime_class in ["runc", ""] {
            let pod = pod_with_runtime_class(runtime_class);
            assert_eq!(
                classify_execution_mode("running", previous, with(2_000, 4_096), Some(&pod))
                    .unwrap()
                    .0,
                EnvironmentResizeExecutionMode::InPlace
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn db_resize_admission_is_idempotent_serialized_and_releases_failed_reservations() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL is required for resize DB flow");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect environment resize test database");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("usr_resize_{suffix}");
        let org_id = format!("org_resize_{suffix}");
        let preset_id = format!("preset_resize_{suffix}");
        let env_id = format!("env_resize_{suffix}");
        let other_env_id = format!("env_resize_other_{suffix}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("resize-{suffix}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by)
             VALUES ($1, 'Resize test', $2, $3)",
        )
        .bind(&org_id)
        .bind(format!("resize-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
               VALUES ($1, $2, 'Resize test', $3,
                       '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&preset_id)
        .bind(&org_id)
        .bind(format!("resize-preset-{suffix}"))
        .execute(&pool)
        .await
        .unwrap();
        for (id, cpu) in [(&env_id, 1_000), (&other_env_id, 2_000)] {
            sqlx::query(
                r#"INSERT INTO environments
                    (id, org_id, created_by, preset_id, type, state, desired_state,
                     cpu_millicores, memory_mb, disk_gb, project_spec)
                 VALUES ($1, $2, $3, $4, 'sandbox', 'running', 'started', $5, 1024, 10,
                         '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
            )
            .bind(id)
            .bind(&org_id)
            .bind(&user_id)
            .bind(&preset_id)
            .bind(cpu)
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut params = ResizeEnvironmentParams {
            org_id: org_id.clone(),
            environment_id: env_id.clone(),
            desired_resources: EnvironmentResources {
                cpu_millicores: 1_600,
                memory_mb: 1_024,
                disk_gb: 10,
            },
            request_id: "over-quota".into(),
            force: false,
            disruption_policy: EnvironmentResizeDisruptionPolicy::LiveOnly,
        };
        let plan_for = |params: &ResizeEnvironmentParams| EnvironmentResizePlan {
            previous_resources: EnvironmentResources {
                cpu_millicores: 1_000,
                memory_mb: 1_024,
                disk_gb: 10,
            },
            desired_resources: params.desired_resources,
            execution_mode: EnvironmentResizeExecutionMode::InPlace,
            active_session_count: 0,
            active_sessions_will_be_terminated: false,
            reason: "test".into(),
            warnings: Vec::new(),
        };
        let error = begin_resize_operation(&pool, &params, &plan_for(&params), 3_500, -1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("CPU limit would be exceeded"));

        params.desired_resources.cpu_millicores = 1_500;
        params.request_id = "stable-request".into();
        let (admitted, newly_admitted) =
            begin_resize_operation(&pool, &params, &plan_for(&params), 3_500, -1)
                .await
                .unwrap();
        assert!(newly_admitted);
        assert_eq!(admitted.reserved_cpu_millicores, 500);
        let (repeated, newly_admitted) =
            begin_resize_operation(&pool, &params, &plan_for(&params), 3_500, -1)
                .await
                .unwrap();
        assert!(!newly_admitted);
        assert_eq!(repeated.id, admitted.id);

        let mut concurrent = params.clone();
        concurrent.request_id = "concurrent-request".into();
        concurrent.desired_resources.cpu_millicores = 1_400;
        assert!(
            begin_resize_operation(&pool, &concurrent, &plan_for(&concurrent), 3_500, -1)
                .await
                .unwrap_err()
                .to_string()
                .contains("another resize operation")
        );

        sqlx::query(
            "UPDATE environment_resize_operations
                SET state = 'failed', failure_code = 'test_failure',
                    failure_message = 'test failure', completed_at = NOW()
              WHERE id = $1",
        )
        .bind(&admitted.id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE environments SET state = 'running', desired_state = 'started' WHERE id = $1",
        )
        .bind(&env_id)
        .execute(&pool)
        .await
        .unwrap();
        let (after_failure, newly_admitted) =
            begin_resize_operation(&pool, &concurrent, &plan_for(&concurrent), 3_500, -1)
                .await
                .unwrap();
        assert!(newly_admitted);
        assert_eq!(after_failure.reserved_cpu_millicores, 400);

        sqlx::query("DELETE FROM environments WHERE org_id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn setup_owns_a_running_runtime_until_it_completes_or_records_failure() {
        let progress = |setup_complete, setup_failed, owner_present| SetupProgress {
            setup_complete,
            setup_failed,
            owner_present,
        };
        // Published but not yet claimed, between phases, and every lease
        // status, including a `reaping` tuple left after authority loss.
        for setup in [
            progress(false, false, false),
            progress(false, false, true),
            progress(false, true, true),
            progress(true, false, true),
        ] {
            assert!(
                setup_owns_running_runtime("running", Some(setup)),
                "{setup:?}"
            );
        }
        // Completed or recorded failure with no lease leaves nothing to fence.
        for setup in [progress(true, false, false), progress(false, true, false)] {
            assert!(
                !setup_owns_running_runtime("running", Some(setup)),
                "{setup:?}"
            );
        }
        assert!(!setup_owns_running_runtime("running", None));
        // A stopped Sandbox applies the change on its next start.
        assert!(!setup_owns_running_runtime(
            "stopped",
            Some(progress(false, false, true))
        ));
        assert_setup_in_progress(&setup_in_progress(), "constructor");
    }

    fn assert_setup_in_progress(error: &AppError, label: &str) {
        let AppError::Coded {
            status,
            code,
            detail,
        } = error
        else {
            panic!("{label}: expected a coded rejection, got {error}");
        };
        // A known, non-ambiguous lifecycle rejection: Connect renders
        // `invalid_state` as failed_precondition with its state hint.
        assert_eq!(*status, StatusCode::CONFLICT, "{label}");
        assert_eq!(*code, "invalid_state", "{label}");
        assert!(
            detail.contains("setup is still in progress"),
            "{label}: {detail}"
        );
    }

    /// #2328: a resize admitted 128 ms after setup started replaced the
    /// `started` intent its lease is fenced on, so setup suspended the Sandbox
    /// and never resumed it. Admission must wait for setup to release it.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn db_resize_admission_waits_for_setup_to_release_the_running_runtime() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL is required for resize DB flow");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect environment resize test database");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("usr_resize_setup_{suffix}");
        let org_id = format!("org_resize_setup_{suffix}");
        let preset_id = format!("preset_resize_setup_{suffix}");
        let env_id = format!("env_resize_setup_{suffix}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("resize-setup-{suffix}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by)
             VALUES ($1, 'Resize setup test', $2, $3)",
        )
        .bind(&org_id)
        .bind(format!("resize-setup-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
               VALUES ($1, $2, 'Resize setup test', $3,
                       '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&preset_id)
        .bind(&org_id)
        .bind(format!("resize-setup-preset-{suffix}"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO environments
                (id, org_id, created_by, preset_id, type, state, desired_state,
                 cpu_millicores, memory_mb, disk_gb, project_spec)
             VALUES ($1, $2, $3, $4, 'sandbox', 'running', 'started', 1000, 1024, 10,
                     '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&env_id)
        .bind(&org_id)
        .bind(&user_id)
        .bind(&preset_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sandbox_environment_backend (environment_id, namespace)
             VALUES ($1, 'resize-setup-test')",
        )
        .bind(&env_id)
        .execute(&pool)
        .await
        .unwrap();

        let set_setup =
            |complete: bool,
             error: Option<&'static str>,
             owner: Option<(&'static str, Option<&'static str>)>| {
                let pool = pool.clone();
                let env_id = env_id.clone();
                async move {
                    let (status, pod_uid) = owner.unzip();
                    sqlx::query(
                    "UPDATE sandbox_environment_backend
                        SET setup_complete = $2, setup_error = $3,
                            setup_owner_generation = CASE WHEN $4::text IS NULL THEN NULL ELSE 1 END,
                            setup_owner_activity_id = CASE WHEN $4::text IS NULL THEN NULL ELSE '3' END,
                            setup_owner_attempt = CASE WHEN $4::text IS NULL THEN NULL ELSE 1 END,
                            setup_owner_phase = CASE WHEN $4::text IS NULL THEN NULL ELSE 1 END,
                            setup_owner_status = $4, setup_owner_pod_uid = $5
                      WHERE environment_id = $1",
                )
                .bind(&env_id)
                .bind(complete)
                .bind(error)
                .bind(status)
                .bind(pod_uid.flatten())
                .execute(&pool)
                .await
                .unwrap();
                }
            };
        let params = |request_id: &str| ResizeEnvironmentParams {
            org_id: org_id.clone(),
            environment_id: env_id.clone(),
            desired_resources: EnvironmentResources {
                cpu_millicores: 1_500,
                memory_mb: 1_024,
                disk_gb: 10,
            },
            request_id: request_id.into(),
            force: false,
            disruption_policy: EnvironmentResizeDisruptionPolicy::LiveOnly,
        };
        let plan = |execution_mode| EnvironmentResizePlan {
            previous_resources: EnvironmentResources {
                cpu_millicores: 1_000,
                memory_mb: 1_024,
                disk_gb: 10,
            },
            desired_resources: params("plan").desired_resources,
            execution_mode,
            active_session_count: 0,
            active_sessions_will_be_terminated: false,
            reason: "test".into(),
            warnings: Vec::new(),
        };
        let lifecycle = || async {
            sqlx::query_as::<_, (String, String, i64)>(
                "SELECT e.state, e.desired_state,
                        (SELECT COUNT(*) FROM environment_resize_operations o
                          WHERE o.environment_id = e.id)
                   FROM environments e WHERE e.id = $1",
            )
            .bind(&env_id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };

        let mut operations = 0;
        for (label, complete, error, owner) in [
            ("published, not yet claimed", false, None, None),
            ("claimed", false, None, Some(("claimed", None))),
            (
                "process attached",
                false,
                None,
                Some(("running", Some("pod-a"))),
            ),
            (
                "reaping after authority loss",
                false,
                None,
                Some(("reaping", Some("pod-a"))),
            ),
            (
                "post-start mutation",
                true,
                None,
                Some(("running", Some("pod-a"))),
            ),
            (
                "retry after a recorded failure",
                false,
                Some("install failed"),
                Some(("claimed", None)),
            ),
        ] {
            set_setup(complete, error, owner).await;
            let refused = begin_resize_operation(
                &pool,
                &params(label),
                &plan(EnvironmentResizeExecutionMode::InPlace),
                -1,
                -1,
            )
            .await
            .expect_err(label);
            assert_setup_in_progress(&refused, label);
            assert_eq!(
                lifecycle().await,
                ("running".into(), "started".into(), operations),
                "{label} must leave setup's intent untouched"
            );
        }
        // Review reads the same facts without taking the admission locks.
        let progress = sqlx::query_as::<_, SetupProgress>(SETUP_PROGRESS_SQL)
            .bind(&env_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            progress,
            SetupProgress {
                setup_complete: false,
                setup_failed: true,
                owner_present: true,
            }
        );

        for (label, complete, error) in [
            ("setup complete", true, None),
            ("setup failure recorded", false, Some("install failed")),
        ] {
            set_setup(complete, error, None).await;
            let (operation, newly_admitted) = begin_resize_operation(
                &pool,
                &params(label),
                &plan(EnvironmentResizeExecutionMode::InPlace),
                -1,
                -1,
            )
            .await
            .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert!(newly_admitted, "{label}");
            operations += 1;
            assert_eq!(
                lifecycle().await,
                ("resizing".into(), "resized".into(), operations),
                "{label}"
            );
            sqlx::query(
                "UPDATE environment_resize_operations
                    SET state = 'failed', failure_code = 'test_failure',
                        failure_message = 'test failure', completed_at = NOW()
                  WHERE id = $1",
            )
            .bind(&operation.id)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE environments SET state = 'running', desired_state = 'started'
                  WHERE id = $1",
            )
            .bind(&env_id)
            .execute(&pool)
            .await
            .unwrap();
        }

        // A stopped Sandbox has no setup runtime to fence; it applies on start.
        set_setup(false, None, Some(("reaping", Some("pod-a")))).await;
        sqlx::query(
            "UPDATE environments SET state = 'stopped', desired_state = 'stopped' WHERE id = $1",
        )
        .bind(&env_id)
        .execute(&pool)
        .await
        .unwrap();
        let (_, newly_admitted) = begin_resize_operation(
            &pool,
            &params("stopped"),
            &plan(EnvironmentResizeExecutionMode::ApplyOnStart),
            -1,
            -1,
        )
        .await
        .unwrap();
        assert!(newly_admitted);

        sqlx::query("DELETE FROM environments WHERE org_id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
