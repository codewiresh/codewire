//! The `environment.setup` job, resumable setup runner, and worker-side
//! environment configuration operations.
//!
//! Final Rust semantics:
//! - ordinary setup failures record the error and leave the environment
//!   usable, while cancellation and recovery ambiguity remain retryable;
//! - phases are resumable via `sandbox_environment_backend.setup_phase`;
//! - startup-script and mesh-node failures are warnings, not errors;
//! - with no sandbox backend configured the health check passes and
//!   workspace execs fail (warn-only where Go warns).

use std::collections::BTreeMap;
use std::time::Duration;

use temporalio_sdk::activities::ActivityContext;

use super::activity_authority::{ActivityAuthority, is_authority_lost};
use super::agents::agent_definition;
use super::env_data::{BackendRow, EnvironmentRow, load_backend_row, load_environment};
#[cfg(feature = "kind-e2e")]
use super::fencing_evidence::{FencingEvidence as SetupFencingEvidence, emit};
use super::scripts::build_workspace_env_script;
use super::setup_lease::{
    PhaseAcquire, PhasePreparation, SetupActivityIdentity, SetupLeaseRecord, SetupPhaseAuthority,
};
use super::{JobPayload, WorkerContext};
use crate::repository_mount::{canonical_repository_mount, validate_repository_mounts};
use crate::sandbox::client::{ProbeResult, SandboxClient};
use crate::sandbox::exec::WorkspaceExecResult;
use crate::sandbox::sidecar::DEFAULT_GATEWAY_SSH_PORT;

const DEFAULT_SIDECAR_READY_TIMEOUT: Duration = Duration::from_secs(180);
const SIDECAR_READY_TIMEOUT_ENV: &str = "SIDECAR_READY_TIMEOUT_SECS";
const SIDECAR_READY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const SIDECAR_READY_POLL_INTERVAL: Duration = Duration::from_secs(2);
const SETUP_EXEC_ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
const SETUP_EXEC_QUIESCENCE: Duration = Duration::from_secs(6);
const SETUP_POD_RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const SETUP_POD_RECOVERY_POLL: Duration = Duration::from_millis(500);
const SETUP_MUTATION_STATES: &[&str] = &["running"];
// Every chain now launches through the shared projection/provider channel.
// Leave room beneath its unchanged 16-request bound for provider traffic.
const SETUP_REPOSITORY_CONCURRENCY: usize = 4;

mod github_checkout;
mod ssh_checkout;

async fn observe_repository_chains<F: std::future::Future>(
    chains: impl IntoIterator<Item = F>,
) -> Vec<F::Output> {
    use futures::StreamExt as _;

    // Preserve input/error ordering and observe every started sibling. A
    // failure must not short-circuit and drop attached workspace operations;
    // existing per-chain authority/reaping checks fence queued launches.
    futures::stream::iter(chains)
        .buffered(SETUP_REPOSITORY_CONCURRENCY)
        .collect()
        .await
}

macro_rules! setup_fencing_evidence {
    ($event:expr) => {{
        #[cfg(feature = "kind-e2e")]
        emit($event);
    }};
}

#[derive(Debug)]
pub struct SetupActivityCancelled;

impl std::fmt::Display for SetupActivityCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("environment setup activity cancelled")
    }
}

impl std::error::Error for SetupActivityCancelled {}

#[derive(Debug)]
pub struct SetupRecoveryFailed {
    message: String,
}

impl std::fmt::Display for SetupRecoveryFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "environment setup recovery failed: {}", self.message)
    }
}

impl std::error::Error for SetupRecoveryFailed {}

pub fn is_setup_activity_cancelled(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<SetupActivityCancelled>())
}

pub fn is_setup_recovery_failed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<SetupRecoveryFailed>())
}

fn classify_setup_recovery_error(error: anyhow::Error) -> anyhow::Error {
    if is_setup_control_flow(&error) {
        error
    } else {
        SetupRecoveryFailed {
            message: format!("{error:#}"),
        }
        .into()
    }
}

fn is_setup_control_flow(error: &anyhow::Error) -> bool {
    is_authority_lost(error)
        || is_setup_activity_cancelled(error)
        || is_setup_recovery_failed(error)
}

async fn await_setup_or_cancel<T, F>(activity_ctx: &ActivityContext, future: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    tokio::select! {
        result = future => result,
        _ = activity_ctx.cancelled() => Err(SetupActivityCancelled.into()),
    }
}

fn setup_command_cancelled(state: &str, desired_state: &str) -> bool {
    desired_state != "started" || matches!(state, "destroying" | "destroyed")
}

// ── Runner engine (port of internal/environmentsetup/runner.go) ────────

/// Mirrors `environmentsetup.Repo`.
#[derive(Debug, Clone, Default)]
pub struct Repo {
    pub url: String,
    pub revision: String,
    pub branch: String,
    pub mount_path: String,
    pub known_hosts: Vec<String>,
}

/// Mirrors `environmentsetup.Inputs`.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub environment_id: String,
    pub namespace: String,
    pub pod_name: String,
    pub desired_state: String,
    pub setup_phase: i32,
    pub setup_complete: bool,
    pub ttl_seconds: Option<i32>,
    pub has_setup: bool,
    pub repos: Vec<Repo>,
    pub working_directory: String,
    pub install_command: String,
    pub startup_script: String,
    pub agents: Vec<String>,
    pub app_ports: Vec<(i32, String, String)>, // (port, label, access)
}

/// Mirrors `environmentsetup.Store`.
pub struct PhaseCompletion<'a> {
    pub phase: i32,
    pub next_phase: i32,
    pub step: &'a str,
    pub status: &'a str,
    pub message: &'a str,
    pub data: Option<serde_json::Value>,
}

pub trait SetupStore {
    fn complete_phase(
        &self,
        env_id: &str,
        completion: PhaseCompletion<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn complete_setup(
        &self,
        env_id: &str,
        phase: i32,
        ttl_seconds: Option<i32>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn set_error(
        &self,
        env_id: &str,
        phase: i32,
        err_msg: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

/// Mirrors `environmentsetup.Ops`.
pub trait SetupOps {
    fn prepare_phase(
        &mut self,
        input: &Inputs,
        phase: i32,
    ) -> impl std::future::Future<Output = anyhow::Result<PhaseAcquire>> + Send;
    fn emit_log(
        &self,
        env_id: &str,
        phase_number: i32,
        step: &str,
        status: &str,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn ensure_can_commit(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn health_check(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn configure_environment(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn clone_repos(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn run_install(
        &mut self,
        input: &Inputs,
        work_dir: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn run_startup_script(
        &mut self,
        input: &Inputs,
        work_dir: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn validate_agents(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn register_ports(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

fn duration_ms_meta(started: std::time::Instant) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "duration_ms": started.elapsed().as_millis() as i64 }))
}

/// Mirrors `environmentsetup.Runner`.
pub struct Runner<S, O> {
    pub store: S,
    pub ops: O,
}

impl<S: SetupStore, O: SetupOps> Runner<S, O> {
    pub async fn run(&mut self, input: &mut Inputs) -> anyhow::Result<()> {
        if input.setup_complete {
            return Ok(());
        }
        let env_id = input.environment_id.clone();

        if input.setup_phase <= 0 {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            let started = std::time::Instant::now();
            self.ops
                .emit_log(&env_id, phase, "health_check", "started", "", None)
                .await?;
            if let Err(e) = self.ops.health_check(input).await {
                if is_setup_control_flow(&e) {
                    return Err(e);
                }
                self.ops
                    .emit_log(
                        &env_id,
                        phase,
                        "health_check",
                        "failed",
                        &format!("{e:#}"),
                        duration_ms_meta(started),
                    )
                    .await?;
                return Err(anyhow::anyhow!("health check: {e:#}"));
            }
            self.finish_phase(
                input,
                phase,
                1,
                "health_check",
                "completed",
                "",
                duration_ms_meta(started),
            )
            .await?;
        }

        if input.setup_phase <= 1 {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops
                .emit_log(&env_id, phase, "configure_environment", "started", "", None)
                .await?;
            self.ops.configure_environment(input).await?;
            self.finish_phase(
                input,
                phase,
                2,
                "configure_environment",
                "completed",
                "",
                None,
            )
            .await?;
        }

        if !input.has_setup {
            return self.complete(input).await;
        }

        let work_dir = input.working_directory.clone();

        if input.setup_phase <= 2 && !input.repos.is_empty() {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops
                .emit_log(&env_id, phase, "git_clone", "started", "", None)
                .await?;
            if let Err(e) = self.ops.clone_repos(input).await {
                if is_setup_control_flow(&e) {
                    return Err(e);
                }
                self.ops
                    .emit_log(
                        &env_id,
                        phase,
                        "git_clone",
                        "failed",
                        &format!("{e:#}"),
                        None,
                    )
                    .await?;
                return Err(anyhow::anyhow!("git clone: {e:#}"));
            }
            self.finish_phase(input, phase, 3, "git_clone", "completed", "", None)
                .await?;
        }

        if input.setup_phase <= 3 && !input.install_command.is_empty() {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops
                .emit_log(&env_id, phase, "install", "started", "", None)
                .await?;
            if let Err(e) = self.ops.run_install(input, &work_dir).await {
                if is_setup_control_flow(&e) {
                    return Err(e);
                }
                self.ops
                    .emit_log(&env_id, phase, "install", "failed", &format!("{e:#}"), None)
                    .await?;
                return Err(anyhow::anyhow!("install: {e:#}"));
            }
            self.finish_phase(input, phase, 4, "install", "completed", "", None)
                .await?;
        }

        if input.setup_phase <= 4 && !input.startup_script.is_empty() {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops
                .emit_log(&env_id, phase, "startup_script", "started", "", None)
                .await?;
            match self.ops.run_startup_script(input, &work_dir).await {
                Err(e) => {
                    if is_setup_control_flow(&e) {
                        return Err(e);
                    }
                    self.finish_phase(
                        input,
                        phase,
                        5,
                        "startup_script",
                        "warning",
                        &format!("{e:#}"),
                        None,
                    )
                    .await?;
                }
                Ok(()) => {
                    self.finish_phase(input, phase, 5, "startup_script", "completed", "", None)
                        .await?;
                }
            }
        }

        if input.setup_phase <= 5 && !input.agents.is_empty() {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops
                .emit_log(&env_id, phase, "agent_validation", "started", "", None)
                .await?;
            if let Err(e) = self.ops.validate_agents(input).await {
                if is_setup_control_flow(&e) {
                    return Err(e);
                }
                self.ops
                    .emit_log(
                        &env_id,
                        phase,
                        "agent_validation",
                        "failed",
                        &format!("{e:#}"),
                        Some(serde_json::json!({ "count": input.agents.len() })),
                    )
                    .await?;
                return Err(anyhow::anyhow!("agent validation: {e:#}"));
            }
            self.finish_phase(
                input,
                phase,
                6,
                "agent_validation",
                "completed",
                "",
                Some(serde_json::json!({ "count": input.agents.len() })),
            )
            .await?;
        }

        if input.setup_phase <= 6 && !input.app_ports.is_empty() {
            let phase = input.setup_phase;
            if !self.begin_phase(input, phase).await? {
                return Ok(());
            }
            self.ops.register_ports(input).await?;
            self.finish_phase(input, phase, 7, "register_ports", "completed", "", None)
                .await?;
        }

        self.complete(input).await
    }

    pub async fn record_error(
        &self,
        env_id: &str,
        phase: i32,
        err: &anyhow::Error,
    ) -> anyhow::Result<()> {
        self.store
            .set_error(env_id, phase, &format!("{err:#}"))
            .await
    }

    async fn begin_phase(&mut self, input: &mut Inputs, phase: i32) -> anyhow::Result<bool> {
        match self.ops.prepare_phase(input, phase).await? {
            PhaseAcquire::Acquired => Ok(true),
            PhaseAcquire::AlreadyComplete(actual_phase) => {
                input.setup_phase = actual_phase;
                Ok(false)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_phase(
        &mut self,
        input: &mut Inputs,
        phase: i32,
        next_phase: i32,
        step: &str,
        status: &str,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        self.ops.ensure_can_commit().await?;
        self.store
            .complete_phase(
                &input.environment_id,
                PhaseCompletion {
                    phase,
                    next_phase,
                    step,
                    status,
                    message,
                    data,
                },
            )
            .await?;
        input.setup_phase = next_phase;
        Ok(())
    }

    async fn complete(&mut self, input: &mut Inputs) -> anyhow::Result<()> {
        let phase = input.setup_phase;
        if !self.begin_phase(input, phase).await? {
            return Ok(());
        }
        self.ops.ensure_can_commit().await?;
        self.store
            .complete_setup(&input.environment_id, phase, input.ttl_seconds)
            .await?;
        input.setup_complete = true;
        Ok(())
    }
}

// ── Postgres store (port of environmentsetup/pgstore.go) ───────────────

pub struct PgSetupStore {
    pub phase_authority: SetupPhaseAuthority,
}

impl SetupStore for PgSetupStore {
    async fn complete_phase(
        &self,
        _env_id: &str,
        completion: PhaseCompletion<'_>,
    ) -> anyhow::Result<()> {
        self.phase_authority
            .complete_phase(
                completion.phase,
                completion.next_phase,
                completion.step,
                completion.status,
                completion.message,
                completion.data,
            )
            .await
    }

    async fn complete_setup(
        &self,
        _env_id: &str,
        phase: i32,
        ttl_seconds: Option<i32>,
    ) -> anyhow::Result<()> {
        self.phase_authority
            .complete_setup(phase, ttl_seconds)
            .await
    }

    async fn set_error(&self, _env_id: &str, phase: i32, err_msg: &str) -> anyhow::Result<()> {
        self.phase_authority.set_error(phase, err_msg).await
    }
}

// ── Worker ops (port of worker/environment_setup.go + helpers) ─────────

/// Mirrors `toSetupInputs`.
pub fn to_setup_inputs(env: &EnvironmentRow, backend: &BackendRow) -> Inputs {
    let spec = &env.project_spec;
    let mut input = Inputs {
        environment_id: env.id.clone(),
        namespace: backend.namespace.clone(),
        pod_name: backend.pod_name.clone(),
        desired_state: env.desired_state.clone(),
        setup_phase: backend.setup_phase,
        setup_complete: backend.setup_complete,
        ttl_seconds: env.ttl_seconds,
        has_setup: !spec.repositories.is_empty()
            || !spec.install_command.is_empty()
            || !spec.startup_script.is_empty()
            || !spec.environment.is_empty()
            || !spec.agents.is_empty()
            || !spec.application_ports.is_empty(),
        working_directory: spec.working_directory.clone(),
        install_command: spec.install_command.clone(),
        startup_script: spec.startup_script.clone(),
        agents: spec.agents.tools.clone(),
        app_ports: spec
            .application_ports
            .iter()
            .map(|port| {
                (
                    i32::from(port.port),
                    port.label.clone(),
                    port.access.clone(),
                )
            })
            .collect(),
        ..Default::default()
    };
    for repository in &spec.repositories {
        input.repos.push(Repo {
            url: repository.source.clone(),
            revision: repository.revision.clone(),
            branch: repository.branch.clone(),
            mount_path: repository.destination.clone(),
            known_hosts: repository.known_hosts.clone(),
        });
    }
    input
}

fn require_workspace_exec_success(result: &WorkspaceExecResult) -> anyhow::Result<()> {
    if result.exit_code != 0 {
        anyhow::bail!("workspace exec exited {}", result.exit_code);
    }
    Ok(())
}

fn replacement_runtime_is_current(
    expected_pod_name: &str,
    old_pod_uid: &str,
    probe: &ProbeResult,
) -> bool {
    probe.claim_exists
        && probe.claim_ready
        && probe.replicas == 1
        && probe.pod_exists
        && probe.pod_phase == "Running"
        && probe.pod_name == expected_pod_name
        && !probe.pod_uid.is_empty()
        && probe.pod_uid != old_pod_uid
        && !probe.pod_ip.is_empty()
}

pub struct WorkerSetupOps<'a> {
    pub ctx: &'a WorkerContext,
    pub env: EnvironmentRow,
    pub authority: &'a ActivityAuthority,
    pub phase_authority: SetupPhaseAuthority,
    pub activity_ctx: ActivityContext,
    pub active_phase: i32,
    pub recovery_lock: std::sync::Arc<tokio::sync::Mutex<bool>>,
    pub launch_group_active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub launch_group_reaping: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WorkerSetupOps<'_> {
    fn setup_env_vars(&self) -> BTreeMap<String, String> {
        self.env.project_spec.environment.clone()
    }

    fn sandbox_client(&self, namespace: &str) -> anyhow::Result<SandboxClient> {
        self.ctx
            .kube
            .clone()
            .map(|client| SandboxClient::new(client, namespace))
            .ok_or_else(|| anyhow::anyhow!("workspace setup: sandbox backend not configured"))
    }

    fn cancellation_requested(&self) -> bool {
        self.activity_ctx.is_cancelled()
    }

    fn mark_launch_group_reaping(&self) {
        if self
            .launch_group_active
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.launch_group_reaping
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// A definite failure from one parallel clone cannot leave sibling execs
    /// attached. Recycle the one owned Pod before the group returns; the
    /// shared recovery lock makes concurrent sibling failures join this same
    /// path rather than scaling the replacement Pod a second time.
    async fn fence_failed_launch_group(
        &self,
        input: &Inputs,
        error: anyhow::Error,
    ) -> anyhow::Error {
        if is_setup_control_flow(&error) {
            return error;
        }
        self.mark_launch_group_reaping();
        match self
            .recover_current_exec(input, self.active_phase, true)
            .await
        {
            Ok(()) => error,
            Err(recovery_error) => recovery_error,
        }
    }

    async fn wait_for_no_workspace_pod(
        &self,
        sandbox: &SandboxClient,
        pod_name: &str,
        old_uid: &str,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + SETUP_POD_RECOVERY_TIMEOUT;
        loop {
            let named = sandbox.get_workspace_pod_identity_by_name(pod_name).await?;
            let all = sandbox
                .list_workspace_pod_identities(self.phase_authority.environment_id())
                .await?;
            let old_uid_present = named.as_ref().is_some_and(|pod| pod.uid == old_uid)
                || all.iter().any(|pod| pod.uid == old_uid);
            let any_workspace_pod = named.is_some() || !all.is_empty();
            if !old_uid_present && !any_workspace_pod {
                setup_fencing_evidence!(SetupFencingEvidence::NoPodObserved {
                    environment_id: self.phase_authority.environment_id().to_string(),
                    pod_uid: old_uid.to_string(),
                });
                break;
            }
            if let Some(identity) = named.as_ref().filter(|pod| pod.uid != old_uid) {
                tracing::warn!(
                    environment_id = self.phase_authority.environment_id(),
                    pod_name,
                    old_uid,
                    observed_uid = identity.uid,
                    "setup recovery waiting for workspace Pod absence"
                );
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "setup recovery timed out waiting for Pod {pod_name} ({old_uid}) to be absent"
                );
            }
            tokio::time::sleep(SETUP_POD_RECOVERY_POLL).await;
        }
        tokio::time::sleep(SETUP_EXEC_QUIESCENCE).await;
        setup_fencing_evidence!(SetupFencingEvidence::QuiescenceComplete {
            environment_id: self.phase_authority.environment_id().to_string(),
            pod_uid: old_uid.to_string(),
            wait_ms: SETUP_EXEC_QUIESCENCE.as_millis() as u64,
        });
        Ok(())
    }

    async fn suspend_and_observe(
        &self,
        input: &Inputs,
        old_owner: &SetupLeaseRecord,
    ) -> anyhow::Result<()> {
        let old_uid = old_owner
            .pod_uid
            .as_deref()
            .filter(|uid| !uid.trim().is_empty())
            .ok_or_else(|| anyhow::Error::new(super::activity_authority::AuthorityLost))?;
        let sandbox = self.sandbox_client(&input.namespace)?;
        let pod_name = if input.pod_name.trim().is_empty() {
            sandbox.get_pod_name(&input.environment_id).await?
        } else {
            input.pod_name.clone()
        };
        let guard = self.phase_authority.begin_reap(old_owner).await?;
        let suspend_result = tokio::time::timeout(
            Duration::from_secs(30),
            sandbox.set_replicas(&input.environment_id, 0),
        )
        .await;
        guard.commit().await?;
        self.wait_for_no_workspace_pod(&sandbox, &pod_name, old_uid)
            .await?;
        match suspend_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(
                    environment_id = input.environment_id,
                    error = %error,
                    "setup recovery suspend request failed after Pod absence was observed"
                );
                Ok(())
            }
            Err(_) => {
                tracing::warn!(
                    environment_id = input.environment_id,
                    "setup recovery suspend request timed out after Pod absence was observed"
                );
                Ok(())
            }
        }
    }

    async fn wait_for_replacement_runtime(
        &self,
        sandbox: &SandboxClient,
        input: &Inputs,
        old_uid: &str,
    ) -> anyhow::Result<ProbeResult> {
        let pod_name = if input.pod_name.trim().is_empty() {
            sandbox.get_pod_name(&input.environment_id).await?
        } else {
            input.pod_name.clone()
        };
        let deadline = tokio::time::Instant::now() + SETUP_POD_RECOVERY_TIMEOUT;
        loop {
            if self.cancellation_requested() {
                return Err(SetupActivityCancelled.into());
            }
            // Sandbox, Pod, and Claim status converge independently after a
            // resume. A newly allocated UID is not yet a usable replacement;
            // retain the strict identity boundary and wait through ordinary
            // Pending/not-Ready observations within the one recovery bound.
            let probe = sandbox.probe_environment(&input.environment_id).await?;
            if replacement_runtime_is_current(&pod_name, old_uid, &probe) {
                let replacement_uid = probe.pod_uid.clone();
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    anyhow::bail!(
                        "setup recovery timed out waiting for replacement Pod {pod_name} readiness"
                    );
                }
                let ready = tokio::time::timeout(
                    remaining,
                    wait_for_sidecar(self.ctx, &input.namespace, &input.environment_id),
                );
                await_setup_or_cancel(&self.activity_ctx, async {
                    ready.await.map_err(|_| {
                        anyhow::anyhow!(
                            "setup recovery timed out waiting for replacement Pod {pod_name} readiness"
                        )
                    })??;
                    Ok(())
                })
                .await?;
                let final_probe = sandbox.probe_environment(&input.environment_id).await?;
                if final_probe.pod_uid == replacement_uid
                    && replacement_runtime_is_current(&pod_name, old_uid, &final_probe)
                {
                    return Ok(final_probe);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "setup recovery timed out waiting for current replacement Pod {pod_name}"
                );
            }
            tokio::time::sleep(SETUP_POD_RECOVERY_POLL).await;
        }
    }

    async fn settle_failed_recovery(
        &self,
        input: &Inputs,
        old_owner: &SetupLeaseRecord,
        error: anyhow::Error,
    ) -> anyhow::Result<()> {
        self.suspend_and_observe(input, old_owner).await?;
        if is_setup_activity_cancelled(&error) || self.cancellation_requested() {
            return Err(SetupActivityCancelled.into());
        }
        // Keep the exact old tuple in `reaping`. A later Temporal attempt must
        // observe that durable recovery obligation and retry the guarded
        // scale-up; transferring it to `claimed` here would lose the fact that
        // the workspace is deliberately down.
        Err(error)
    }

    async fn recover_setup_phase(
        &self,
        input: &Inputs,
        old_owner: &SetupLeaseRecord,
    ) -> anyhow::Result<()> {
        let old_uid = old_owner
            .pod_uid
            .as_deref()
            .filter(|uid| !uid.trim().is_empty())
            .ok_or_else(|| anyhow::Error::new(super::activity_authority::AuthorityLost))?;
        self.suspend_and_observe(input, old_owner).await?;
        if self.cancellation_requested() {
            return Err(SetupActivityCancelled.into());
        }

        let Some(resume_guard) = self.phase_authority.begin_resume(old_owner).await? else {
            return Err(super::activity_authority::AuthorityLost.into());
        };
        let sandbox = self.sandbox_client(&input.namespace)?;
        let resume_result = tokio::time::timeout(
            Duration::from_secs(30),
            sandbox.set_replicas(&input.environment_id, 1),
        )
        .await;
        resume_guard.commit().await?;
        match resume_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return self.settle_failed_recovery(input, old_owner, error).await;
            }
            Err(_) => {
                return self
                    .settle_failed_recovery(
                        input,
                        old_owner,
                        anyhow::anyhow!("setup recovery resume request timed out"),
                    )
                    .await;
            }
        }

        let replacement_probe = match await_setup_or_cancel(&self.activity_ctx, async {
            tokio::time::timeout(
                SETUP_POD_RECOVERY_TIMEOUT,
                self.authority.run_while_authoritative_for_states(
                    SETUP_MUTATION_STATES,
                    self.wait_for_replacement_runtime(&sandbox, input, old_uid),
                ),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "setup recovery exceeded the replacement runtime deadline for {}",
                    input.environment_id
                )
            })?
        })
        .await
        {
            Ok(probe) => probe,
            Err(error) => {
                return self.settle_failed_recovery(input, old_owner, error).await;
            }
        };
        let backend_update = self
            .authority
            .execute_for_states(
                SETUP_MUTATION_STATES,
                sqlx::query(
                    "UPDATE sandbox_environment_backend SET pod_name = $1, pod_ip = $2 \
                     WHERE environment_id = $3",
                )
                .bind(&replacement_probe.pod_name)
                .bind(&replacement_probe.pod_ip)
                .bind(&input.environment_id),
            )
            .await;
        if !matches!(backend_update, Ok(ref result) if result.rows_affected() == 1) {
            return self
                .settle_failed_recovery(
                    input,
                    old_owner,
                    anyhow::anyhow!("setup recovery backend update did not converge"),
                )
                .await;
        }
        setup_fencing_evidence!(SetupFencingEvidence::ReplacementReady {
            environment_id: self.phase_authority.environment_id().to_string(),
            old_pod_uid: old_uid.to_string(),
            new_pod_uid: replacement_probe.pod_uid.clone(),
        });
        if let Err(error) = self.phase_authority.finish_recovery(old_owner).await {
            match self.suspend_and_observe(input, old_owner).await {
                Ok(()) => {}
                Err(cleanup_error) if is_authority_lost(&cleanup_error) => {}
                Err(cleanup_error) => return Err(cleanup_error),
            }
            return Err(error);
        }
        setup_fencing_evidence!(SetupFencingEvidence::RecoveryComplete {
            environment_id: self.phase_authority.environment_id().to_string(),
            phase: old_owner.phase,
            old_pod_uid: old_uid.to_string(),
        });
        Ok(())
    }

    async fn recover_current_exec_inner(
        &self,
        input: &Inputs,
        phase: i32,
        resume: bool,
    ) -> anyhow::Result<()> {
        let mut recovery_complete = self.recovery_lock.lock().await;
        let launch_group_active = self
            .launch_group_active
            .load(std::sync::atomic::Ordering::Acquire);
        if launch_group_active && *recovery_complete {
            return Ok(());
        }
        let owner = match self.phase_authority.mark_current_reaping(phase).await {
            Ok(owner) => owner,
            Err(error) if self.cancellation_requested() && is_authority_lost(&error) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let Some(owner) = owner else {
            // A sibling in the same owned launch group already completed the
            // single recycle path and restored this activity's claimed lease.
            return Ok(());
        };
        setup_fencing_evidence!(SetupFencingEvidence::RecoveryStarted {
            environment_id: self.phase_authority.environment_id().to_string(),
            phase,
            pod_uid: owner.pod_uid.clone().unwrap_or_default(),
        });
        if resume && !self.cancellation_requested() {
            self.recover_setup_phase(input, &owner).await?;
        } else {
            self.suspend_and_observe(input, &owner).await?;
        }
        if launch_group_active {
            *recovery_complete = true;
        }
        Ok(())
    }

    async fn recover_current_exec(
        &self,
        input: &Inputs,
        phase: i32,
        resume: bool,
    ) -> anyhow::Result<()> {
        self.recover_current_exec_inner(input, phase, resume)
            .await
            .map_err(classify_setup_recovery_error)
    }

    async fn workspace_exec(
        &self,
        namespace: &str,
        env_id: &str,
        cmd: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<()> {
        if self.cancellation_requested() {
            return Err(SetupActivityCancelled.into());
        }
        let launch_group_active = self
            .launch_group_active
            .load(std::sync::atomic::Ordering::Acquire);
        if launch_group_active
            && self
                .launch_group_reaping
                .load(std::sync::atomic::Ordering::Acquire)
        {
            anyhow::bail!("workspace setup launch group is reaping");
        }
        if !launch_group_active {
            *self.recovery_lock.lock().await = false;
        }
        let sandbox = self.sandbox_client(namespace)?;
        let mut recovered_uid_mismatch = false;
        let pod = loop {
            let pod = sandbox
                .get_workspace_pod_identity(env_id)
                .await?
                .filter(|identity| !identity.uid.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("workspace setup: workspace Pod is not present"))?;
            match self
                .phase_authority
                .mark_running(self.active_phase, &pod.uid)
                .await
            {
                Ok(()) => break pod,
                Err(error) if is_authority_lost(&error) && !recovered_uid_mismatch => {
                    self.mark_launch_group_reaping();
                    self.recover_current_exec(
                        &Inputs {
                            environment_id: env_id.to_string(),
                            namespace: namespace.to_string(),
                            pod_name: pod.name,
                            ..Default::default()
                        },
                        self.active_phase,
                        true,
                    )
                    .await?;
                    if launch_group_active {
                        return Err(error);
                    }
                    recovered_uid_mismatch = true;
                }
                Err(error) => return Err(error),
            }
        };
        let guard = self
            .phase_authority
            .begin_exec(self.active_phase, &pod.uid)
            .await?;
        let attach = tokio::time::timeout(
            SETUP_EXEC_ATTACH_TIMEOUT,
            sandbox.start_workspace_exec_on_pod(&pod.name, cmd, work_dir, env),
        )
        .await;
        let pod_still_exact = if matches!(&attach, Ok(Ok(_))) {
            match tokio::time::timeout(
                SETUP_EXEC_ATTACH_TIMEOUT,
                sandbox.get_workspace_pod_identity_by_name(&pod.name),
            )
            .await
            {
                Ok(Ok(Some(identity))) => Ok(identity.uid == pod.uid),
                Ok(Ok(None)) => Ok(false),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(anyhow::anyhow!(
                    "workspace exec post-attach Pod identity check timed out"
                )),
            }
        } else {
            Ok(true)
        };
        if let Err(error) = guard.commit().await {
            // Attachment may already have dispatched the daemon command. A
            // failed lock/transaction release is not proof of non-execution.
            // Drop the transport and retain the existing exact-Pod recovery
            // obligation, including when the database is temporarily unavailable.
            drop(attach);
            self.mark_launch_group_reaping();
            self.recover_current_exec(
                &Inputs {
                    environment_id: env_id.to_string(),
                    namespace: namespace.to_string(),
                    pod_name: pod.name.clone(),
                    ..Default::default()
                },
                self.active_phase,
                true,
            )
            .await?;
            return Err(classify_setup_recovery_error(error));
        }
        let handle = match attach {
            Ok(Ok(handle)) if pod_still_exact.as_ref().is_ok_and(|exact| *exact) => handle,
            Ok(Ok(_handle)) => {
                self.mark_launch_group_reaping();
                self.recover_current_exec(
                    &Inputs {
                        environment_id: env_id.to_string(),
                        namespace: namespace.to_string(),
                        pod_name: pod.name.clone(),
                        ..Default::default()
                    },
                    self.active_phase,
                    true,
                )
                .await?;
                return Err(classify_setup_recovery_error(
                    pod_still_exact.err().unwrap_or_else(|| {
                        anyhow::anyhow!("workspace Pod changed during exec attachment")
                    }),
                ));
            }
            Ok(Err(error)) => {
                self.mark_launch_group_reaping();
                self.recover_current_exec(
                    &Inputs {
                        environment_id: env_id.to_string(),
                        namespace: namespace.to_string(),
                        pod_name: pod.name.clone(),
                        ..Default::default()
                    },
                    self.active_phase,
                    true,
                )
                .await?;
                return Err(classify_setup_recovery_error(error));
            }
            Err(_) => {
                self.mark_launch_group_reaping();
                self.recover_current_exec(
                    &Inputs {
                        environment_id: env_id.to_string(),
                        namespace: namespace.to_string(),
                        pod_name: pod.name.clone(),
                        ..Default::default()
                    },
                    self.active_phase,
                    true,
                )
                .await?;
                return Err(classify_setup_recovery_error(anyhow::anyhow!(
                    "workspace exec attachment timed out"
                )));
            }
        };
        setup_fencing_evidence!(SetupFencingEvidence::ExecAttached {
            environment_id: env_id.to_string(),
            phase: self.active_phase,
            pod_uid: pod.uid.clone(),
        });

        let mut authority_tick = tokio::time::interval(Duration::from_millis(500));
        authority_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let wait = handle.wait();
        tokio::pin!(wait);
        let exec_result = loop {
            tokio::select! {
                result = &mut wait => break result,
                _ = authority_tick.tick() => {
                    if let Err(error) = self.phase_authority.ensure_active(self.active_phase).await {
                        self.mark_launch_group_reaping();
                        self.recover_current_exec(
                            &Inputs {
                                environment_id: env_id.to_string(),
                                namespace: namespace.to_string(),
                                pod_name: pod.name.clone(),
                                ..Default::default()
                            },
                            self.active_phase,
                            false,
                        ).await?;
                        if self.cancellation_requested() {
                            return Err(SetupActivityCancelled.into());
                        }
                        return Err(error);
                    }
                }
                _ = self.activity_ctx.cancelled() => {
                    self.mark_launch_group_reaping();
                    self.recover_current_exec(
                        &Inputs {
                            environment_id: env_id.to_string(),
                            namespace: namespace.to_string(),
                            pod_name: pod.name.clone(),
                            ..Default::default()
                        },
                        self.active_phase,
                        false,
                    ).await?;
                    return Err(SetupActivityCancelled.into());
                }
            }
        };
        let exec_result = match exec_result {
            Ok(result) => result,
            Err(error) => {
                setup_fencing_evidence!(SetupFencingEvidence::ExecWaitFailed {
                    environment_id: env_id.to_string(),
                    phase: self.active_phase,
                    pod_uid: pod.uid.clone(),
                    error: super::fencing_evidence::safe_exec_wait_error(&error),
                });
                self.mark_launch_group_reaping();
                // Once attachment succeeded, a transport/read/join failure is
                // ambiguous process exit. Recycle the exact Pod before the
                // phase can report the ordinary failure.
                self.recover_current_exec(
                    &Inputs {
                        environment_id: env_id.to_string(),
                        namespace: namespace.to_string(),
                        pod_name: pod.name.clone(),
                        ..Default::default()
                    },
                    self.active_phase,
                    true,
                )
                .await?;
                return Err(classify_setup_recovery_error(error));
            }
        };
        require_workspace_exec_success(&exec_result)?;
        #[cfg(feature = "kind-e2e")]
        if super::fencing_evidence::fail_once_after_exec(env_id, self.active_phase, &pod.uid) {
            return Err(SetupRecoveryFailed {
                message: "injected fail-once after workspace exec".to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Publish the complete ordinary defaults before clone/install, including an
    /// empty map after clearing values. Resolved application secrets never enter
    /// this file; the first write gets canonical defaults as explicit overrides.
    async fn sync_workspace_env(&self, namespace: &str) -> anyhow::Result<()> {
        let script = build_workspace_env_script(&self.env.project_spec.environment);
        let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        self.workspace_exec(
            namespace,
            &self.env.id,
            &cmd,
            "",
            &self.env.project_spec.environment,
        )
        .await
    }

    /// Applies non-secret Git author metadata through the fenced setup executor.
    async fn configure_git_identity(&self, namespace: &str) -> anyhow::Result<()> {
        let env_id = &self.env.id;
        let created_by: Option<(String,)> =
            sqlx::query_as("SELECT created_by FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(&self.ctx.pool)
                .await
                .unwrap_or(None);
        let Some((created_by,)) = created_by else {
            tracing::warn!(
                environment_id = env_id,
                "git-identity: could not resolve creator"
            );
            return Ok(());
        };

        let user_row: Option<GitIdentityRow> =
            sqlx::query_as("SELECT git_name, git_email, name, email FROM users WHERE id = $1")
                .bind(&created_by)
                .fetch_optional(&self.ctx.pool)
                .await
                .unwrap_or(None);
        let Some((git_name, git_email, name, email)) = user_row else {
            tracing::warn!(user_id = created_by, "git-identity: could not load user");
            return Ok(());
        };

        let resolved_name = resolve_git_field(git_name.as_deref(), name.as_deref(), &email);
        let resolved_email = match git_email.as_deref() {
            Some(email) if !email.is_empty() => email.to_string(),
            _ => email,
        };
        let git_config_result: anyhow::Result<()> = async {
            self.workspace_exec(
                namespace,
                env_id,
                &[
                    "git".to_string(),
                    "config".to_string(),
                    "--global".to_string(),
                    "user.email".to_string(),
                    resolved_email.clone(),
                ],
                "",
                &BTreeMap::new(),
            )
            .await?;
            self.workspace_exec(
                namespace,
                env_id,
                &[
                    "git".to_string(),
                    "config".to_string(),
                    "--global".to_string(),
                    "user.name".to_string(),
                    resolved_name.clone(),
                ],
                "",
                &BTreeMap::new(),
            )
            .await
        }
        .await;
        match git_config_result {
            Err(error) if is_setup_control_flow(&error) => {
                return Err(error);
            }
            Err(error) => tracing::warn!(
                environment_id = env_id,
                error = %error,
                "git-identity: failed to set Git identity"
            ),
            Ok(()) => tracing::info!(
                environment_id = env_id,
                name = resolved_name,
                email = resolved_email,
                "git-identity: configured"
            ),
        }

        Ok(())
    }
}

/// Row shape for the git-identity lookup: (git_name, git_email, name, email).
type GitIdentityRow = (Option<String>, Option<String>, Option<String>, String);

impl SetupOps for WorkerSetupOps<'_> {
    async fn prepare_phase(&mut self, input: &Inputs, phase: i32) -> anyhow::Result<PhaseAcquire> {
        self.active_phase = phase;
        match self.phase_authority.prepare_phase(phase).await? {
            PhasePreparation::Ready(result) => Ok(result),
            PhasePreparation::Recover(owner) => {
                self.recover_setup_phase(input, &owner)
                    .await
                    .map_err(classify_setup_recovery_error)?;
                Ok(PhaseAcquire::Acquired)
            }
        }
    }

    async fn emit_log(
        &self,
        _env_id: &str,
        phase_number: i32,
        step: &str,
        status: &str,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        self.phase_authority
            .emit_log(phase_number, step, status, message, data)
            .await
    }

    async fn ensure_can_commit(&self) -> anyhow::Result<()> {
        if self.cancellation_requested() {
            return Err(SetupActivityCancelled.into());
        }
        self.authority.ensure_for_states(&["running"]).await
    }

    async fn health_check(&mut self, input: &Inputs) -> anyhow::Result<()> {
        await_setup_or_cancel(
            &self.activity_ctx,
            self.authority.run_while_authoritative(wait_for_sidecar(
                self.ctx,
                &input.namespace,
                &input.environment_id,
            )),
        )
        .await
    }

    async fn configure_environment(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        self.sync_workspace_env(&input.namespace).await?;
        self.configure_git_identity(&input.namespace).await?;
        Ok(())
    }

    async fn clone_repos(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        validate_repository_mounts(
            input
                .repos
                .iter()
                .map(|repo| (repo.url.as_str(), repo.mount_path.as_str())),
        )?;
        // Validate every trust/selection input before even the first checkout
        // removal. Missing metadata must never select an ambient SSH agent or
        // silently downgrade a potentially protected GitHub checkout.
        let ssh_commands = ssh_checkout::commands(
            &input.repos,
            self.env.managed_credential_clients.as_ref().ok().copied(),
        )?;
        let github_commands = github_checkout::commands(
            &input.repos,
            self.env.managed_credential_clients.as_ref().ok().copied(),
        )?;
        // Observe every launched sibling before returning an error. Dropping a
        // sibling future could otherwise detach an unobserved workspace exec.
        *self.recovery_lock.lock().await = false;
        self.launch_group_reaping
            .store(false, std::sync::atomic::Ordering::Release);
        self.launch_group_active
            .store(true, std::sync::atomic::Ordering::Release);
        let this: &WorkerSetupOps<'_> = self;
        // Materialize the unpolled futures before crossing the async-trait
        // boundary; only observe_repository_chains admits them for execution.
        let clones: Vec<_> = input
            .repos
            .iter()
            .zip(ssh_commands)
            .zip(github_commands)
            .map(|((repo, ssh_command), github_command)| {
                let repo = repo.clone();
                let namespace = input.namespace.clone();
                let env_id = input.environment_id.clone();
                async move {
                    this.phase_authority
                        .ensure_active(this.active_phase)
                        .await?;
                    let dir = canonical_repository_mount(&repo.url, &repo.mount_path)?;
                    let rm: Vec<String> = vec!["rm".into(), "-rf".into(), dir.clone()];
                    if let Err(error) = this
                        .workspace_exec(&namespace, &env_id, &rm, "", &BTreeMap::new())
                        .await
                        && is_setup_control_flow(&error)
                    {
                        return Err(error);
                    }
                    this.phase_authority
                        .ensure_active(this.active_phase)
                        .await?;
                    #[cfg(feature = "kind-e2e")]
                    let clone = super::fencing_evidence::clone_fixture_command(&repo.url)
                        .unwrap_or_else(|| {
                            vec!["git".into(), "clone".into(), repo.url.clone(), dir.clone()]
                        });
                    #[cfg(not(feature = "kind-e2e"))]
                    let clone: Vec<String> =
                        vec!["git".into(), "clone".into(), repo.url.clone(), dir.clone()];
                    let clone = ssh_command
                        .or_else(|| {
                            github_command
                                .as_ref()
                                .map(|commands| commands.clone.clone())
                        })
                        .unwrap_or(clone);
                    if let Err(e) = this
                        .workspace_exec(&namespace, &env_id, &clone, "", &BTreeMap::new())
                        .await
                    {
                        if is_setup_control_flow(&e) {
                            return Err(e);
                        }
                        let error = e.context(format!("git clone {}", repo.url));
                        return Err(this.fence_failed_launch_group(input, error).await);
                    }
                    let selector = if repo.revision.is_empty() {
                        &repo.branch
                    } else {
                        &repo.revision
                    };
                    if !selector.is_empty() {
                        let mut checkout: Vec<String> = vec!["git".into(), "checkout".into()];
                        if !repo.revision.is_empty() {
                            checkout.push("--detach".into());
                        }
                        checkout.push(selector.clone());
                        let checkout = github_command
                            .as_ref()
                            .and_then(|commands| commands.checkout.clone())
                            .unwrap_or(checkout);
                        if let Err(e) = this
                            .workspace_exec(&namespace, &env_id, &checkout, &dir, &BTreeMap::new())
                            .await
                        {
                            if is_setup_control_flow(&e) {
                                return Err(e);
                            }
                            let error =
                                e.context(format!("git checkout {} for {}", selector, repo.url));
                            return Err(this.fence_failed_launch_group(input, error).await);
                        }
                    }
                    Ok(())
                }
            })
            .collect();
        let results = observe_repository_chains(clones).await;
        setup_fencing_evidence!(SetupFencingEvidence::CloneGroupJoined {
            environment_id: input.environment_id.clone(),
            launched: results.len(),
            observed: results.len(),
        });
        self.launch_group_active
            .store(false, std::sync::atomic::Ordering::Release);
        if self.cancellation_requested() {
            return Err(SetupActivityCancelled.into());
        }
        if let Some(error) = results.into_iter().find_map(Result::err) {
            return Err(error);
        }
        Ok(())
    }

    async fn run_install(&mut self, input: &Inputs, work_dir: &str) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            input.install_command.clone(),
        ];
        self.workspace_exec(
            &input.namespace,
            &input.environment_id,
            &cmd,
            work_dir,
            &self.setup_env_vars(),
        )
        .await
    }

    async fn run_startup_script(&mut self, input: &Inputs, work_dir: &str) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            input.startup_script.clone(),
        ];
        self.workspace_exec(
            &input.namespace,
            &input.environment_id,
            &cmd,
            work_dir,
            &self.setup_env_vars(),
        )
        .await
    }

    async fn validate_agents(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        for agent_type in &input.agents {
            if self.cancellation_requested() {
                return Err(SetupActivityCancelled.into());
            }
            self.phase_authority
                .ensure_active(self.active_phase)
                .await?;
            let agent = agent_definition(agent_type)
                .ok_or_else(|| anyhow::anyhow!("unsupported configured agent: {agent_type}"))?;
            let command = vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("command -v {} >/dev/null 2>&1", agent.command),
            ];
            self.workspace_exec(
                &input.namespace,
                &input.environment_id,
                &command,
                "",
                &BTreeMap::new(),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "selected agent `{}` is unavailable in the workspace image; recreate this environment with a canonical agent-ready image. No runtime installation was attempted: {error:#}",
                    agent.id,
                )
            })?;
        }
        Ok(())
    }

    async fn register_ports(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        // Mirrors autoRegisterPorts: per-port warn-only inserts.
        for (port, label, access) in &input.app_ports {
            if self.cancellation_requested() {
                return Err(SetupActivityCancelled.into());
            }
            let access = if access.is_empty() { "creator" } else { access };
            let res = self
                .phase_authority
                .insert_port(self.active_phase, *port, label, access)
                .await;
            if let Err(e) = res {
                if is_setup_control_flow(&e) {
                    return Err(e);
                }
                tracing::warn!(environment_id = input.environment_id, port, error = %e, "auto-register port failed");
            }
        }
        if !input.app_ports.is_empty() {
            tracing::info!(
                environment_id = input.environment_id,
                count = input.app_ports.len(),
                "post-boot: auto-registered ports"
            );
        }
        Ok(())
    }
}

/// Mirrors `resolveGitField`.
fn resolve_git_field(git_name: Option<&str>, account_name: Option<&str>, email: &str) -> String {
    if let Some(n) = git_name
        && !n.is_empty()
    {
        return n.to_string();
    }
    if let Some(n) = account_name
        && !n.is_empty()
    {
        return n.to_string();
    }
    if let Some(idx) = email.find('@')
        && idx > 0
    {
        return email[..idx].to_string();
    }
    email.to_string()
}

/// Mirrors `waitForSidecar`: no backend → pass; otherwise poll the
/// SSH/SFTP readiness check with ~2s jittered intervals.
pub(crate) async fn wait_for_sidecar(
    ctx: &WorkerContext,
    namespace: &str,
    env_id: &str,
) -> anyhow::Result<()> {
    let Some(kube) = &ctx.kube else {
        return Ok(());
    };
    let client = SandboxClient::new(kube.clone(), namespace);
    let timeout = sidecar_ready_timeout();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempt = 0u32;
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        attempt += 1;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = remaining.min(SIDECAR_READY_ATTEMPT_TIMEOUT);
        match tokio::time::timeout(
            attempt_timeout,
            client.check_sidecar_ready(env_id, DEFAULT_GATEWAY_SSH_PORT),
        )
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => {
                tracing::debug!(attempt, error = %e, "sidecar readiness attempt failed");
                last_err = Some(e);
            }
            Err(_) => {
                tracing::debug!(attempt, "sidecar readiness attempt timed out");
                last_err = Some(anyhow::anyhow!(
                    "attempt timed out after {}ms",
                    attempt_timeout.as_millis()
                ));
            }
        }
        let sleep = jittered_duration(SIDECAR_READY_POLL_INTERVAL);
        if tokio::time::Instant::now() + sleep >= deadline {
            tokio::time::sleep_until(deadline).await;
            break;
        }
        tokio::time::sleep(sleep).await;
    }
    let last = last_err
        .map(|e| format!("{e:#}"))
        .unwrap_or_else(|| "deadline exceeded".to_string());
    anyhow::bail!(
        "sidecar readiness failed after {}s: {last}",
        timeout.as_secs()
    )
}

fn sidecar_ready_timeout() -> Duration {
    std::env::var(SIDECAR_READY_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_SIDECAR_READY_TIMEOUT)
}

/// Mirrors `jitteredDuration`: base + random(0, base/2).
pub(crate) fn jittered_duration(base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let half = (base.as_millis() / 2).max(1) as u64;
    let entropy = uuid::Uuid::new_v4().as_u128() as u64;
    base + Duration::from_millis(entropy % half)
}

// ── Handler (port of HandleEnvironmentSetup) ────────────────────────────

pub async fn handle_environment_setup(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.setup received");

    let env = load_environment(&ctx.pool, env_id).await?;
    if setup_command_cancelled(&env.state, &env.desired_state) {
        tracing::info!(
            env = env_id,
            state = env.state,
            desired = env.desired_state,
            "setup cancelled: desired state changed"
        );
        return Ok(());
    }

    let backend = match load_backend_row(&ctx.pool, env_id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(env = env_id, error = %e, "setup: no backend row");
            return Err(e);
        }
    };

    if backend.setup_complete {
        if super::create::requires_running_runtime_identity(&env.state, &env.desired_state) {
            super::create::reconcile_runtime_identity(ctx, &env, &backend, authority, &["running"])
                .await?;
        }
        return Ok(());
    }

    let mut input = to_setup_inputs(&env, &backend);
    let phase_authority = SetupPhaseAuthority::new(authority.clone(), setup_identity)?;
    let mut runner = Runner {
        store: PgSetupStore {
            phase_authority: phase_authority.clone(),
        },
        ops: WorkerSetupOps {
            ctx,
            env,
            authority,
            phase_authority,
            activity_ctx,
            active_phase: input.setup_phase,
            recovery_lock: std::sync::Arc::new(tokio::sync::Mutex::new(false)),
            launch_group_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            launch_group_reaping: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    };
    if let Err(err) = runner.run(&mut input).await {
        if is_authority_lost(&err)
            || is_setup_activity_cancelled(&err)
            || is_setup_recovery_failed(&err)
        {
            return Err(err);
        }
        if let Err(record_error) = runner.record_error(env_id, input.setup_phase, &err).await {
            if is_authority_lost(&record_error) {
                return Err(record_error);
            }
            tracing::warn!(env = env_id, error = %record_error, "setup: failed to record setup error");
        }
        tracing::error!(env = env_id, error = %err, "setup failed");
        return Ok(()); // environment is still usable — don't retry
    }

    let environment = load_environment(&ctx.pool, env_id).await?;
    let backend = load_backend_row(&ctx.pool, env_id).await?;
    super::create::reconcile_runtime_identity(ctx, &environment, &backend, authority, &["running"])
        .await?;
    tracing::info!(environment_id = env_id, "environment.setup completed");
    Ok(())
}

/// Reapply Git author metadata and run the current startup script after a
/// stop→start Pod replacement under the same durable process lease used by setup.
pub async fn handle_post_start_configuration(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    let env = load_environment(&ctx.pool, &payload.environment_id).await?;
    let backend = load_backend_row(&ctx.pool, &payload.environment_id).await?;
    let input = to_setup_inputs(&env, &backend);
    let phase = input.setup_phase;
    let phase_authority = SetupPhaseAuthority::new(authority.clone(), setup_identity)?;
    let mut ops = WorkerSetupOps {
        ctx,
        env,
        authority,
        phase_authority: phase_authority.clone(),
        activity_ctx,
        active_phase: phase,
        recovery_lock: std::sync::Arc::new(tokio::sync::Mutex::new(false)),
        launch_group_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        launch_group_reaping: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    match phase_authority.prepare_post_start_mutation(phase).await? {
        PhasePreparation::Ready(PhaseAcquire::Acquired) => {}
        PhasePreparation::Ready(PhaseAcquire::AlreadyComplete(_)) => {
            return Err(super::activity_authority::AuthorityLost.into());
        }
        PhasePreparation::Recover(owner) => ops
            .recover_setup_phase(&input, &owner)
            .await
            .map_err(classify_setup_recovery_error)?,
    }

    ops.configure_git_identity(&input.namespace).await?;
    run_post_start_script(&mut ops, &input).await?;
    ops.ensure_can_commit().await?;
    phase_authority.complete_post_start_mutation(phase).await?;
    Ok(())
}

/// Startup runs on every start, independently of completed install/clone phases.
/// The caller owns the post-start lease and releases it only after this succeeds.
async fn run_post_start_script(ops: &mut impl SetupOps, input: &Inputs) -> anyhow::Result<()> {
    if input.startup_script.is_empty() {
        return Ok(());
    }
    ops.emit_log(
        &input.environment_id,
        input.setup_phase,
        "startup_script",
        "started",
        "",
        None,
    )
    .await?;
    let (status, message) = match ops
        .run_startup_script(input, &input.working_directory)
        .await
    {
        Ok(()) => ("completed", String::new()),
        Err(error) if is_setup_control_flow(&error) => return Err(error),
        Err(error) => ("warning", format!("{error:#}")),
    };
    ops.ensure_can_commit().await?;
    ops.emit_log(
        &input.environment_id,
        input.setup_phase,
        "startup_script",
        status,
        &message,
        None,
    )
    .await
}

#[cfg(test)]
mod repository_schedule_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct MockState {
        calls: Vec<String>,
        phases: Vec<i32>,
        complete: bool,
        error: Option<(i32, String)>,
        shutdown_ttl: Option<i32>,
        startup_launches: Vec<(String, String)>,
        fail_step: Option<&'static str>,
        authority_loss_step: Option<&'static str>,
        recovery_failure_step: Option<&'static str>,
        cancellation_step: Option<&'static str>,
        cancel_before_commit: bool,
    }

    #[derive(Clone)]
    struct Mock(Arc<Mutex<MockState>>);

    impl Mock {
        fn new() -> Self {
            Mock(Arc::new(Mutex::new(MockState::default())))
        }
        fn failing(step: &'static str) -> Self {
            let m = Self::new();
            m.0.lock().unwrap().fail_step = Some(step);
            m
        }
        fn losing_authority(step: &'static str) -> Self {
            let m = Self::new();
            m.0.lock().unwrap().authority_loss_step = Some(step);
            m
        }
        fn failing_recovery(step: &'static str) -> Self {
            let m = Self::new();
            m.0.lock().unwrap().recovery_failure_step = Some(step);
            m
        }
        fn cancelling_before_commit() -> Self {
            let m = Self::new();
            m.0.lock().unwrap().cancel_before_commit = true;
            m
        }
        fn call(&self, name: &str) -> anyhow::Result<()> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(name.to_string());
            if s.authority_loss_step == Some(name) {
                return Err(super::super::activity_authority::AuthorityLost.into());
            }
            if s.cancellation_step == Some(name) {
                return Err(SetupActivityCancelled.into());
            }
            if s.recovery_failure_step == Some(name) {
                return Err(SetupRecoveryFailed {
                    message: format!("{name} recovery boom"),
                }
                .into());
            }
            if s.fail_step == Some(name) {
                anyhow::bail!("{name} boom");
            }
            Ok(())
        }
        fn state(&self) -> MockState {
            self.0.lock().unwrap().clone()
        }
    }

    impl SetupStore for Mock {
        async fn complete_phase(
            &self,
            _env_id: &str,
            completion: PhaseCompletion<'_>,
        ) -> anyhow::Result<()> {
            let mut state = self.0.lock().unwrap();
            state
                .calls
                .push(format!("log:{}:{}", completion.step, completion.status));
            state.phases.push(completion.next_phase);
            Ok(())
        }
        async fn complete_setup(
            &self,
            _env_id: &str,
            _phase: i32,
            ttl_seconds: Option<i32>,
        ) -> anyhow::Result<()> {
            let mut state = self.0.lock().unwrap();
            state.complete = true;
            state.shutdown_ttl = ttl_seconds.filter(|ttl| *ttl > 0);
            state.calls.push("log:complete:completed".to_string());
            Ok(())
        }
        async fn set_error(&self, _env_id: &str, phase: i32, msg: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().error = Some((phase, msg.to_string()));
            Ok(())
        }
    }

    impl SetupOps for Mock {
        async fn prepare_phase(
            &mut self,
            _input: &Inputs,
            _phase: i32,
        ) -> anyhow::Result<PhaseAcquire> {
            Ok(PhaseAcquire::Acquired)
        }

        async fn emit_log(
            &self,
            _env_id: &str,
            _phase_number: i32,
            step: &str,
            status: &str,
            _message: &str,
            _data: Option<serde_json::Value>,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .calls
                .push(format!("log:{step}:{status}"));
            Ok(())
        }
        async fn ensure_can_commit(&self) -> anyhow::Result<()> {
            if self.0.lock().unwrap().cancel_before_commit {
                return Err(SetupActivityCancelled.into());
            }
            Ok(())
        }
        async fn health_check(&mut self, _input: &Inputs) -> anyhow::Result<()> {
            self.call("health_check")
        }
        async fn configure_environment(&mut self, _input: &Inputs) -> anyhow::Result<()> {
            self.call("configure_environment")
        }
        async fn clone_repos(&mut self, _input: &Inputs) -> anyhow::Result<()> {
            self.call("clone_repos")
        }
        async fn run_install(&mut self, _input: &Inputs, _wd: &str) -> anyhow::Result<()> {
            self.call("run_install")
        }
        async fn run_startup_script(&mut self, input: &Inputs, wd: &str) -> anyhow::Result<()> {
            assert_eq!(wd, input.working_directory);
            self.0
                .lock()
                .unwrap()
                .startup_launches
                .push((input.startup_script.clone(), wd.to_string()));
            self.call("run_startup_script")
        }
        async fn validate_agents(&mut self, _input: &Inputs) -> anyhow::Result<()> {
            self.call("validate_agents")
        }
        async fn register_ports(&mut self, _input: &Inputs) -> anyhow::Result<()> {
            self.call("register_ports")
        }
    }

    fn full_inputs() -> Inputs {
        Inputs {
            environment_id: "env-1".into(),
            namespace: "ns".into(),
            desired_state: "started".into(),
            has_setup: true,
            repos: vec![Repo {
                url: "https://x/y/app.git".into(),
                revision: String::new(),
                branch: "".into(),
                mount_path: "/workspace/app".into(),
                known_hosts: Vec::new(),
            }],
            working_directory: "/workspace/app".into(),
            install_command: "npm ci".into(),
            startup_script: "npm start".into(),
            agents: vec!["claude-code".into()],
            app_ports: vec![(3000, "web".into(), "public".into())],
            ttl_seconds: Some(7200),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn post_start_runs_script_after_completed_setup_without_replaying_install() {
        let mut mock = Mock::new();
        let mut input = full_inputs();
        input.setup_complete = true;
        input.setup_phase = 7;
        input.startup_script = "./current-startup.sh".into();
        input.working_directory = "/workspace/current".into();
        run_post_start_script(&mut mock, &input).await.unwrap();
        let state = mock.state();
        assert_eq!(
            state.calls,
            [
                "log:startup_script:started",
                "run_startup_script",
                "log:startup_script:completed",
            ]
        );
        assert!(state.phases.is_empty());
        assert_eq!(
            state.startup_launches,
            [("./current-startup.sh".into(), "/workspace/current".into())]
        );
        assert!(!state.complete);
        assert_eq!(input.setup_phase, 7);
        assert!(input.setup_complete);
    }

    #[tokio::test]
    async fn post_start_skips_empty_script() {
        let mut mock = Mock::new();
        let mut input = full_inputs();
        input.startup_script.clear();
        run_post_start_script(&mut mock, &input).await.unwrap();
        assert!(mock.state().calls.is_empty());
    }

    #[tokio::test]
    async fn post_start_script_failure_is_warning_only() {
        let mut mock = Mock::failing("run_startup_script");
        run_post_start_script(&mut mock, &full_inputs())
            .await
            .unwrap();
        assert_eq!(
            mock.state().calls,
            [
                "log:startup_script:started",
                "run_startup_script",
                "log:startup_script:warning",
            ]
        );
        assert!(mock.state().phases.is_empty());
    }

    #[tokio::test]
    async fn post_start_propagates_control_flow_without_success_or_warning() {
        let cancelled = Mock::new();
        cancelled.0.lock().unwrap().cancellation_step = Some("run_startup_script");
        for mut mock in [
            Mock::losing_authority("run_startup_script"),
            Mock::failing_recovery("run_startup_script"),
            cancelled,
            Mock::cancelling_before_commit(),
        ] {
            let error = run_post_start_script(&mut mock, &full_inputs())
                .await
                .unwrap_err();
            assert!(is_setup_control_flow(&error), "{error:#}");
            let state = mock.state();
            assert_eq!(
                state.calls,
                ["log:startup_script:started", "run_startup_script"]
            );
            assert!(state.phases.is_empty());
            assert!(!state.complete);
        }
    }

    #[tokio::test]
    async fn run_executes_all_phases_in_order() {
        let mock = Mock::new();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        runner.run(&mut input).await.unwrap();
        let s = mock.state();
        let ops: Vec<&str> = s
            .calls
            .iter()
            .filter(|c| !c.starts_with("log:"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            ops,
            [
                "health_check",
                "configure_environment",
                "clone_repos",
                "run_install",
                "run_startup_script",
                "validate_agents",
                "register_ports"
            ]
        );
        assert_eq!(s.phases, vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(s.complete);
        assert_eq!(s.shutdown_ttl, Some(7200));
        assert!(input.setup_complete);
    }

    #[tokio::test]
    async fn run_without_setup_completes_after_configuration() {
        let mock = Mock::new();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = Inputs {
            environment_id: "env-1".into(),
            ..Default::default()
        };
        runner.run(&mut input).await.unwrap();
        let s = mock.state();
        assert_eq!(s.phases, vec![1, 2]);
        assert!(s.complete);
        assert_eq!(s.shutdown_ttl, None);
        assert!(s.calls.contains(&"log:complete:completed".to_string()));
        assert!(!s.calls.iter().any(|c| c == "clone_repos"));
    }

    #[tokio::test]
    async fn run_resumes_from_recorded_phase() {
        let mock = Mock::new();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        input.setup_phase = 3; // health/configuration/clone already done
        runner.run(&mut input).await.unwrap();
        let s = mock.state();
        let ops: Vec<&str> = s
            .calls
            .iter()
            .filter(|c| !c.starts_with("log:"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            ops,
            [
                "run_install",
                "run_startup_script",
                "validate_agents",
                "register_ports"
            ]
        );
        assert_eq!(s.phases, vec![4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn already_complete_is_a_noop() {
        let mock = Mock::new();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        input.setup_complete = true;
        runner.run(&mut input).await.unwrap();
        assert!(mock.state().calls.is_empty());
        assert!(!mock.state().complete);
    }

    #[tokio::test]
    async fn install_failure_aborts_with_wrapped_error() {
        let mock = Mock::failing("run_install");
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        let err = runner.run(&mut input).await.unwrap_err();
        assert!(format!("{err:#}").starts_with("install: "), "{err:#}");
        let s = mock.state();
        assert!(!s.complete);
        assert_eq!(s.phases, vec![1, 2, 3]); // stopped at install
        assert!(s.calls.contains(&"log:install:failed".to_string()));
    }

    #[tokio::test]
    async fn startup_script_failure_is_warning_only() {
        let mock = Mock::failing("run_startup_script");
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        runner.run(&mut input).await.unwrap();
        let s = mock.state();
        assert!(s.complete);
        assert!(s.calls.contains(&"log:startup_script:warning".to_string()));
        assert_eq!(s.phases, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn unavailable_selected_agent_fails_setup_without_a_download() {
        let mock = Mock::failing("validate_agents");
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        let error = runner.run(&mut input).await.unwrap_err();
        assert!(
            format!("{error:#}").starts_with("agent validation: validate_agents boom"),
            "{error:#}"
        );
        let state = mock.state();
        assert!(!state.complete);
        assert_eq!(state.phases, vec![1, 2, 3, 4, 5]);
        assert!(
            state
                .calls
                .contains(&"log:agent_validation:failed".to_string())
        );
        assert!(!state.calls.iter().any(|call| call == "install_agents"));
    }

    #[tokio::test]
    async fn authority_loss_escapes_every_runner_path_without_advancing() {
        for step in [
            "health_check",
            "configure_environment",
            "clone_repos",
            "run_install",
            "run_startup_script",
            "validate_agents",
            "register_ports",
        ] {
            let mock = Mock::losing_authority(step);
            let mut runner = Runner {
                store: mock.clone(),
                ops: mock.clone(),
            };
            let mut input = full_inputs();
            let error = runner.run(&mut input).await.unwrap_err();
            assert!(
                is_authority_lost(&error),
                "{step} hid authority loss: {error:#}"
            );
            let state = mock.state();
            assert!(
                !state.complete,
                "{step} completed setup after authority loss"
            );
            let log_step = match step {
                "run_startup_script" => "startup_script",
                other => other,
            };
            assert!(
                !state
                    .calls
                    .iter()
                    .any(|call| call == &format!("log:{log_step}:warning")),
                "{step} converted authority loss into a warning"
            );
        }
    }

    #[tokio::test]
    async fn recovery_failure_escapes_every_runner_path_without_advancing() {
        for step in [
            "health_check",
            "configure_environment",
            "clone_repos",
            "run_install",
            "run_startup_script",
            "validate_agents",
            "register_ports",
        ] {
            let mock = Mock::failing_recovery(step);
            let mut runner = Runner {
                store: mock.clone(),
                ops: mock.clone(),
            };
            let mut input = full_inputs();
            let error = runner.run(&mut input).await.unwrap_err();
            assert!(
                is_setup_recovery_failed(&error),
                "{step} hid retryable recovery failure: {error:#}"
            );
            let state = mock.state();
            assert!(
                !state.complete,
                "{step} completed setup after recovery failure"
            );
            let log_step = match step {
                "run_startup_script" => "startup_script",
                other => other,
            };
            assert!(
                !state
                    .calls
                    .iter()
                    .any(|call| call == &format!("log:{log_step}:warning")),
                "{step} converted retryable recovery failure into a warning"
            );
        }
    }

    #[tokio::test]
    async fn cancellation_barrier_prevents_phase_advance_after_work_returns() {
        let mock = Mock::cancelling_before_commit();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        let error = runner.run(&mut input).await.unwrap_err();
        assert!(is_setup_activity_cancelled(&error));
        let state = mock.state();
        assert!(state.phases.is_empty());
        assert!(!state.complete);
        assert!(state.calls.contains(&"health_check".to_string()));
        assert!(
            !state
                .calls
                .contains(&"log:health_check:completed".to_string())
        );
    }

    #[test]
    fn ordinary_recovery_errors_are_retryable_control_flow() {
        let recovery = classify_setup_recovery_error(anyhow::anyhow!("scale down failed"));
        assert!(is_setup_recovery_failed(&recovery));
        let authority =
            classify_setup_recovery_error(super::super::activity_authority::AuthorityLost.into());
        assert!(is_authority_lost(&authority));
        assert!(!is_setup_recovery_failed(&authority));
    }

    #[tokio::test]
    async fn record_error_writes_phase_and_message() {
        let mock = Mock::new();
        let runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        runner
            .record_error("env-1", 4, &anyhow::anyhow!("install: npm ci exploded"))
            .await
            .unwrap();
        assert_eq!(
            mock.state().error,
            Some((4, "install: npm ci exploded".to_string()))
        );
    }

    #[test]
    fn to_setup_inputs_consumes_the_canonical_project_spec() {
        let env = EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "running".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 10,
            ttl_seconds: Some(3600),
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        };
        let backend = BackendRow {
            namespace: "ns".into(),
            setup_phase: 2,
            ..Default::default()
        };
        let input = to_setup_inputs(&env, &backend);
        assert!(!input.has_setup);
        assert_eq!(input.setup_phase, 2);
        assert_eq!(input.ttl_seconds, Some(3600));

        let mut env = env;
        env.project_spec = codewire_project::ProjectSpec {
            repositories: vec![codewire_project::RepositorySpec {
                source: "https://g/o/r.git".into(),
                branch: "dev".into(),
                destination: "/workspace/r".into(),
                ..Default::default()
            }],
            working_directory: "/workspace/r".into(),
            environment: BTreeMap::from([("APP_MODE".into(), "test".into())]),
            agents: codewire_project::AgentsSpec {
                install: Some(true),
                tools: vec!["codex".into()],
            },
            application_ports: vec![codewire_project::ApplicationPort {
                port: 8080,
                label: "api".into(),
                access: String::new(),
            }],
            ..Default::default()
        };
        let input = to_setup_inputs(&env, &backend);
        assert!(input.has_setup);
        assert_eq!(input.repos.len(), 1);
        assert_eq!(input.repos[0].branch, "dev");
        assert_eq!(input.repos[0].mount_path, "/workspace/r");
        assert_eq!(input.working_directory, "/workspace/r");
        assert_eq!(input.agents, vec!["codex".to_string()]);
        assert_eq!(
            input.app_ports,
            vec![(8080, "api".to_string(), String::new())]
        );
        env.project_spec.repositories[0].source = "git@example.com:org/app.git".into();
        env.project_spec.repositories[0].known_hosts =
            vec!["example.com ssh-ed25519 QUJDRA== public-pin".into()];
        let input = to_setup_inputs(&env, &backend);
        assert_eq!(
            input.repos[0].known_hosts,
            env.project_spec.repositories[0].known_hosts
        );
    }

    #[test]
    fn stale_setup_commands_do_not_run_after_delete() {
        assert!(setup_command_cancelled("pending", "destroyed"));
        assert!(setup_command_cancelled("running", "destroyed"));
        assert!(setup_command_cancelled("destroying", "destroyed"));
        assert!(setup_command_cancelled("destroyed", "destroyed"));
        assert!(setup_command_cancelled("destroying", "started"));
        assert!(!setup_command_cancelled("running", "started"));
    }

    #[test]
    fn removed_agent_env_is_rejected() {
        assert!(
            serde_json::from_str::<codewire_project::ProjectSpec>(
                r#"{"agent_env":{"CLAUDE_CODE_OAUTH_TOKEN":"synthetic"}}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_git_field_mirrors_go() {
        assert_eq!(
            resolve_git_field(Some("Git Name"), Some("Acct"), "a@b.c"),
            "Git Name"
        );
        assert_eq!(resolve_git_field(Some(""), Some("Acct"), "a@b.c"), "Acct");
        assert_eq!(resolve_git_field(None, None, "user@b.c"), "user");
        assert_eq!(resolve_git_field(None, None, "@b.c"), "@b.c");
    }

    #[test]
    fn workspace_exec_failure_never_retains_child_output() {
        let marker = "synthetic-secret-output-must-not-persist";
        let result = WorkspaceExecResult {
            stdout: marker.as_bytes().to_vec(),
            stderr: marker.as_bytes().to_vec(),
            exit_code: 23,
        };
        let error = require_workspace_exec_success(&result).unwrap_err();
        assert_eq!(error.to_string(), "workspace exec exited 23");
        assert!(!format!("{error:?}").contains(marker));
    }

    fn current_replacement_probe() -> ProbeResult {
        ProbeResult {
            claim_exists: true,
            claim_ready: true,
            replicas: 1,
            pod_exists: true,
            pod_phase: "Running".into(),
            pod_name: "workspace-current".into(),
            pod_uid: "uid-new".into(),
            pod_ip: "10.0.0.9".into(),
            ..Default::default()
        }
    }

    #[test]
    fn replacement_runtime_requires_exact_ready_incarnation() {
        let current = current_replacement_probe();
        assert!(replacement_runtime_is_current(
            "workspace-current",
            "uid-old",
            &current
        ));

        let mut cases = Vec::new();
        let mut probe = current.clone();
        probe.claim_exists = false;
        cases.push(probe);
        let mut probe = current.clone();
        probe.claim_ready = false;
        cases.push(probe);
        let mut probe = current.clone();
        probe.replicas = 0;
        cases.push(probe);
        let mut probe = current.clone();
        probe.pod_exists = false;
        cases.push(probe);
        let mut probe = current.clone();
        probe.pod_phase = "Pending".into();
        cases.push(probe);
        let mut probe = current.clone();
        probe.pod_name = "workspace-other".into();
        cases.push(probe);
        let mut probe = current.clone();
        probe.pod_uid.clear();
        cases.push(probe);
        let mut probe = current.clone();
        probe.pod_uid = "uid-old".into();
        cases.push(probe);
        let mut probe = current;
        probe.pod_ip.clear();
        cases.push(probe);

        for probe in cases {
            assert!(!replacement_runtime_is_current(
                "workspace-current",
                "uid-old",
                &probe
            ));
        }
    }
}
