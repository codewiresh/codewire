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
use super::create::{CreateHandover, ReconciledRuntime};
use super::env_data::{BackendRow, EnvironmentRow, load_backend_row, load_environment};
#[cfg(feature = "kind-e2e")]
use super::fencing_evidence::{FencingEvidence as SetupFencingEvidence, emit};
use super::scripts::{
    GIT_IDENTITY_FAILED_EXIT, build_configure_environment_command, build_git_identity_command,
    build_user_setup_command,
};
use super::setup_lease::{
    PhaseAcquire, PhasePreparation, SetupActivityIdentity, SetupLeaseRecord, SetupPhaseAuthority,
};
use super::start_timing::{record_create_milestone, start_profile};
use super::workspace_binding::{BindRefused, bind_replacement_runtime};
use super::{JobPayload, WorkerContext};
use crate::repository_mount::{canonical_repository_mount, validate_repository_mounts};
use crate::runtime::{MemberRef, Placement, RuntimeDriver};
use crate::sandbox::client::ProbeResult;
use crate::sandbox::exec::{StderrTap, WorkspaceExecResult};
use crate::sandbox::host_keys::RecordedHostKeys;
use crate::start_metrics::{CreateMilestone, StartPath};

const DEFAULT_SIDECAR_READY_TIMEOUT: Duration = Duration::from_secs(180);
const SIDECAR_READY_TIMEOUT_ENV: &str = "SIDECAR_READY_TIMEOUT_SECS";
const SIDECAR_READY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const SIDECAR_READY_POLL_INTERVAL: Duration = Duration::from_secs(2);
const SETUP_EXEC_ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
const SETUP_EXEC_QUIESCENCE: Duration = Duration::from_secs(6);
const SETUP_POD_RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);

/// How long recovery waits for a replacement Pod to come up and bind. A
/// confidential guest attests and reopens its encrypted storage first (B2c),
/// so it gets the tier's whole ready budget.
fn replacement_runtime_timeout(input: &Inputs) -> Duration {
    if input.isolation_tier == "confidential" {
        crate::sandbox::template::CONFIDENTIAL_WORKSPACE_READY_TIMEOUT
    } else {
        SETUP_POD_RECOVERY_TIMEOUT
    }
}
const SETUP_POD_RECOVERY_POLL: Duration = Duration::from_millis(500);
const SETUP_MUTATION_STATES: &[&str] = &["running"];
// Every chain now launches through the shared projection/provider channel.
// Leave room beneath its unchanged 16-request bound for provider traffic.
const SETUP_REPOSITORY_CONCURRENCY: usize = 4;
/// Stderr chunks buffered between one clone and its progress parser. A full
/// buffer drops chunks, which only coarsens the reported progress.
const CLONE_PROGRESS_CHUNKS: usize = 64;

/// A clone without managed credentials. `--progress` makes Git write its
/// meters to stderr even though the exec has no terminal.
fn plain_clone_command(url: &str, destination: &str) -> Vec<String> {
    vec![
        "git".into(),
        "clone".into(),
        "--progress".into(),
        url.into(),
        destination.into(),
    ]
}

mod clone_progress;
mod github_checkout;
mod ssh_checkout;

/// Runs the clone chains depth by depth: every repository before the
/// repositories inside it (#4024), each depth through
/// [`observe_repository_chains`]. A depth with a failure stops the run; the
/// deeper chains were never polled, so they did nothing.
async fn observe_repository_levels<F, T>(chains: Vec<F>, depths: &[usize]) -> Vec<anyhow::Result<T>>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let deepest = depths.iter().copied().max().unwrap_or(0);
    let mut chains = chains.into_iter().map(Some).collect::<Vec<_>>();
    let mut results = Vec::with_capacity(chains.len());
    for depth in 0..=deepest {
        let level = chains
            .iter_mut()
            .zip(depths)
            .filter(|(_, chain_depth)| **chain_depth == depth)
            .filter_map(|(chain, _)| chain.take())
            .collect::<Vec<_>>();
        let level_results = observe_repository_chains(level).await;
        let failed = level_results.iter().any(Result::is_err);
        results.extend(level_results);
        if failed {
            break;
        }
    }
    results
}

/// Exit status of [`NESTED_CHECKOUT_GUARD`] when the parent tracks the path.
const NESTED_CHECKOUT_TRACKED_EXIT: i32 = 3;

/// Before a nested repository's checkout is removed and cloned: the parent's
/// commit must track neither the path nor a file on the way to it, so the
/// removal can never delete the parent's files. The path then goes into the
/// parent's `.git/info/exclude`, which a clone with an empty template lacks.
const NESTED_CHECKOUT_GUARD: &str = r#"set -eu
parent=$1 relative=$2
git -C "$parent" rev-parse --verify --quiet HEAD >/dev/null
if [ -n "$(git -C "$parent" ls-tree -r --name-only HEAD -- "$relative")" ]; then exit 3; fi
prefix=
saved_ifs=$IFS
IFS=/
for part in $relative; do
  prefix=${prefix:+$prefix/}$part
  kind=$(git -C "$parent" cat-file -t "HEAD:$prefix" 2>/dev/null || :)
  if [ -n "$kind" ] && [ "$kind" != tree ]; then exit 3; fi
done
IFS=$saved_ifs
mkdir -p "$parent/.git/info"
printf '/%s/
' "$relative" >> "$parent/.git/info/exclude"
"#;

fn nested_checkout_guard(parent: &str, relative: &str) -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        NESTED_CHECKOUT_GUARD.into(),
        "sh".into(),
        parent.into(),
        relative.into(),
    ]
}

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
    /// `standard` or `confidential`; only recovery budgets read it.
    pub isolation_tier: String,
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

/// The workspace daemon's own status, read by setup in-cluster beside its
/// health check (#3684): `state` is the CLI's token for it (`ready`,
/// `starting`, `upgrade_required`, `unsupported`, `unhealthy`,
/// `unspecified`). `cw create` applies its usual readiness rule to it from the
/// `daemon_ready` row instead of asking the API after setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonReadiness {
    pub state: &'static str,
    pub message: String,
    /// The binding generation the daemon reports having written the saved
    /// project defaults and Git author for (`workspace_defaults`), when that
    /// write succeeded.
    pub defaults_generation: Option<i64>,
}

/// How long setup waits for the daemon's status beside the health check. A
/// slower or failed read writes no row, and `cw create` asks as before.
const DAEMON_STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// The `daemon_ready` row's message and metadata for `daemon`, written by
/// setup or, after create's full access proof, by create (#3684).
pub(super) fn daemon_ready_log(daemon: &DaemonReadiness) -> (String, serde_json::Value) {
    let message = match daemon.state {
        "ready" => String::new(),
        state => format!("Workspace daemon {state}: {}", daemon.message),
    };
    (
        message,
        serde_json::json!({ "state": daemon.state, "message": daemon.message }),
    )
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
    /// The daemon's SSH and SFTP proof. It also returns the daemon's own
    /// status when it could be read alongside, for the `daemon_ready` row.
    fn health_check(
        &mut self,
        input: &Inputs,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<DaemonReadiness>>> + Send;
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
            let daemon = match self.ops.health_check(input).await {
                Ok(daemon) => daemon,
                Err(e) => {
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
            };
            if let Some(daemon) = daemon {
                let (message, metadata) = daemon_ready_log(&daemon);
                self.ops
                    .emit_log(
                        &env_id,
                        phase,
                        "daemon_ready",
                        "completed",
                        &message,
                        Some(metadata),
                    )
                    .await?;
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
    /// Set when this store committed setup: how long after the API accepted
    /// the create that was (Program #2238's `setup_complete` milestone).
    pub completed_since_accepted: std::sync::OnceLock<Duration>,
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
        if let Some(since) = self
            .phase_authority
            .complete_setup(phase, ttl_seconds)
            .await?
        {
            let _ = self.completed_since_accepted.set(since);
        }
        Ok(())
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
        isolation_tier: env.isolation_tier.clone(),
        namespace: backend.namespace.clone(),
        pod_name: backend.pod_name.clone(),
        desired_state: env.desired_state.clone(),
        setup_phase: backend.setup_phase,
        setup_complete: backend.setup_complete,
        ttl_seconds: env.ttl_seconds,
        // Work after `configure_environment`. The saved environment isn't:
        // that phase writes it, and a later phase uses it only with its own
        // work (#3684).
        has_setup: !spec.repositories.is_empty()
            || !spec.install_command.is_empty()
            || !spec.startup_script.is_empty()
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

/// A workspace command that ran and exited non-zero. Only its status is kept:
/// child output never enters an error that may be logged or persisted.
#[derive(Debug)]
struct WorkspaceExecExited(i32);

impl std::fmt::Display for WorkspaceExecExited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workspace exec exited {}", self.0)
    }
}

impl std::error::Error for WorkspaceExecExited {}

fn require_workspace_exec_success(result: &WorkspaceExecResult) -> anyhow::Result<()> {
    if result.exit_code != 0 {
        return Err(WorkspaceExecExited(result.exit_code).into());
    }
    Ok(())
}

/// Whether `error` is a workspace command that ran to completion and exited
/// with exactly `code`.
fn exited_with(error: &anyhow::Error, code: i32) -> bool {
    error
        .downcast_ref::<WorkspaceExecExited>()
        .is_some_and(|exited| exited.0 == code)
}

/// The visible note when a GitHub repository was cloned over HTTPS because
/// GitHub refused the selected SSH key or the repository over SSH.
const SSH_FALLBACK_WARNING: &str = "SSH key not accepted by GitHub; cloned over HTTPS";

/// How one repository was cloned, for a failure that names the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloneTransport {
    /// The selected SSH key. `refused`: the server did not accept it.
    Ssh { refused: bool },
    /// The selected GitHub connection, through the managed bridge.
    GitHub,
    /// The user's HTTPS URL after GitHub refused the SSH key.
    HttpsAfterSshRefused { github: bool },
    /// No credential. `github`: a canonical GitHub source.
    Anonymous { github: bool },
}

fn clone_failure_context(url: &str, transport: CloneTransport) -> String {
    let detail = match transport {
        CloneTransport::Ssh { refused: false } => " over SSH",
        CloneTransport::Ssh { refused: true } => {
            " over SSH: the server did not accept the SSH key in the Sandbox's credential profile"
        }
        CloneTransport::GitHub => " through the GitHub connection",
        CloneTransport::HttpsAfterSshRefused { github: true } => {
            " through the GitHub connection after GitHub did not accept the SSH key"
        }
        CloneTransport::HttpsAfterSshRefused { github: false } => {
            " over HTTPS after GitHub did not accept the SSH key; no GitHub connection is selected"
        }
        CloneTransport::Anonymous { github: true } => {
            " (no SSH key or GitHub connection is selected; a private repository needs one)"
        }
        CloneTransport::Anonymous { github: false } => "",
    };
    format!("git clone {url}{detail}")
}

/// One repository's first clone and, for a GitHub HTTPS source cloned with the
/// selected SSH key, the HTTPS clone to run if GitHub refuses that key.
#[derive(Debug, PartialEq, Eq)]
struct ClonePlan {
    clone: Vec<String>,
    transport: CloneTransport,
    https_fallback: Option<(Vec<String>, CloneTransport)>,
}

/// SSH first when its command exists, then the GitHub connection, then an
/// anonymous clone. Only a GitHub HTTPS source cloned over SSH has a fallback:
/// the user's own HTTPS URL, through the bridge when GitHub is selected.
fn clone_plan(
    ssh: Option<&ssh_checkout::Command>,
    github: Option<&github_checkout::Commands>,
    plain: Vec<String>,
    github_source: bool,
) -> ClonePlan {
    let (https, https_transport) = match github {
        Some(commands) => (commands.clone.clone(), CloneTransport::GitHub),
        None => (
            plain,
            CloneTransport::Anonymous {
                github: github_source,
            },
        ),
    };
    match ssh {
        Some(ssh) => ClonePlan {
            clone: ssh.argv.clone(),
            transport: CloneTransport::Ssh { refused: false },
            https_fallback: ssh.https_fallback.then(|| {
                (
                    https,
                    CloneTransport::HttpsAfterSshRefused {
                        github: github.is_some(),
                    },
                )
            }),
        },
        None => ClonePlan {
            clone: https,
            transport: https_transport,
            https_fallback: None,
        },
    }
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

/// How far one replacement attempt of setup recovery got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplacementAccess {
    /// Bound, and its access wait succeeded.
    Ready,
    /// Its chain has not converged on the replacement yet; observe again.
    NotYetBindable,
}

/// Design §10: an identity-free daemon serves SSH and records its host key
/// only once bound, so a replacement Pod binds before its access wait, as a
/// daemon repair's does. A refusal that clears while the replacement's chain
/// converges asks the caller to observe again; any other refusal fails, and
/// the access wait never starts for an unbound Pod.
async fn bind_replacement_then_await_access(
    bind: impl std::future::Future<Output = anyhow::Result<()>>,
    access: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<ReplacementAccess> {
    match bind.await {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.downcast_ref::<BindRefused>(),
                Some(
                    BindRefused::NotConverged
                        | BindRefused::PodChanged
                        | BindRefused::ChainUnverified
                )
            ) =>
        {
            return Ok(ReplacementAccess::NotYetBindable);
        }
        Err(error) => return Err(error),
    }
    access.await?;
    Ok(ReplacementAccess::Ready)
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
    /// Create's full access proof reached the Pod this setup runs on, inside
    /// the same activity (#3684), so the health check would repeat it.
    pub health_proven: bool,
    /// That Pod's daemon reports having written the saved project defaults
    /// and Git author for its live binding (#3684), so setup's exec would
    /// repeat it.
    pub defaults_written: bool,
}

impl WorkerSetupOps<'_> {
    fn setup_env_vars(&self) -> BTreeMap<String, String> {
        self.env.project_spec.environment.clone()
    }

    fn runtime(&self) -> anyhow::Result<&dyn RuntimeDriver> {
        self.ctx
            .runtime
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("workspace setup: sandbox backend not configured"))
    }

    /// The support image a recovery resume re-pins the daemon to: the one
    /// create renders.
    fn support_image(&self) -> &str {
        self.ctx.sandbox_cfg.support_image()
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
        let runtime = self.runtime()?;
        let placement = Placement::new(&input.namespace);
        let pod_name = if input.pod_name.trim().is_empty() {
            runtime
                .member_name(&placement, &input.environment_id)
                .await?
        } else {
            input.pod_name.clone()
        };
        let guard = self.phase_authority.begin_reap(old_owner).await?;
        let suspend_result = tokio::time::timeout(
            Duration::from_secs(30),
            runtime.suspend_current(&placement, &input.environment_id),
        )
        .await;
        guard.commit().await?;
        wait_for_no_workspace_pod(
            runtime,
            &placement,
            self.phase_authority.environment_id(),
            &pod_name,
            old_uid,
        )
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
        input: &Inputs,
        old_uid: &str,
    ) -> anyhow::Result<ProbeResult> {
        let runtime = self.runtime()?;
        let placement = Placement::new(&input.namespace);
        let pod_name = if input.pod_name.trim().is_empty() {
            runtime
                .member_name(&placement, &input.environment_id)
                .await?
        } else {
            input.pod_name.clone()
        };
        let deadline = tokio::time::Instant::now() + replacement_runtime_timeout(input);
        loop {
            if self.cancellation_requested() {
                return Err(SetupActivityCancelled.into());
            }
            // Sandbox, Pod, and Claim status converge independently after a
            // resume. A newly allocated UID is not yet a usable replacement;
            // retain the strict identity boundary and wait through ordinary
            // Pending/not-Ready observations within the one recovery bound.
            let probe = runtime.probe(&placement, &input.environment_id).await?;
            if replacement_runtime_is_current(&pod_name, old_uid, &probe) {
                let replacement = MemberRef {
                    name: probe.pod_name.clone(),
                    uid: probe.pod_uid.clone(),
                };
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    anyhow::bail!(
                        "setup recovery timed out waiting for replacement Pod {pod_name} readiness"
                    );
                }
                let runtime = self.ctx.runtime.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("workspace setup: sandbox backend not configured")
                })?;
                // Boxed: the bind and access futures are large, and inline
                // they would grow every setup activity's future, not only a
                // recovery's.
                let attempt = tokio::time::timeout(
                    remaining,
                    Box::pin(bind_replacement_then_await_access(
                        bind_replacement_runtime(
                            runtime,
                            self.authority,
                            SETUP_MUTATION_STATES,
                            &replacement,
                            remaining,
                        ),
                        wait_for_sidecar(self.ctx, &input.namespace, &input.environment_id),
                    )),
                );
                let reached = await_setup_or_cancel(&self.activity_ctx, async {
                    attempt.await.map_err(|_| {
                        anyhow::anyhow!(
                            "setup recovery timed out waiting for replacement Pod {pod_name} readiness"
                        )
                    })?
                })
                .await?;
                if reached == ReplacementAccess::Ready {
                    let final_probe = runtime.probe(&placement, &input.environment_id).await?;
                    if final_probe.pod_uid == replacement.uid
                        && replacement_runtime_is_current(&pod_name, old_uid, &final_probe)
                    {
                        return Ok(final_probe);
                    }
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
        let resume_result = tokio::time::timeout(
            Duration::from_secs(30),
            self.runtime()?.resume_current(
                &Placement::new(&input.namespace),
                &input.environment_id,
                self.support_image(),
            ),
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
                replacement_runtime_timeout(input),
                self.authority.run_while_authoritative_for_states(
                    SETUP_MUTATION_STATES,
                    self.wait_for_replacement_runtime(input, old_uid),
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
        self.workspace_exec_tapped(namespace, env_id, cmd, work_dir, env, None)
            .await
    }

    /// [`Self::workspace_exec`], also copying the command's stderr chunks to
    /// `stderr_tap` while it runs. Fencing, recovery and the result are
    /// unchanged, and a full tap never delays the command.
    async fn workspace_exec_tapped(
        &self,
        namespace: &str,
        env_id: &str,
        cmd: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
        stderr_tap: Option<StderrTap>,
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
        let runtime = self.runtime()?;
        let placement = Placement::new(namespace);
        let mut recovered_uid_mismatch = false;
        let pod = loop {
            let pod = runtime
                .current_member(&placement, env_id)
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
            runtime.start_exec(&placement, &pod.name, cmd, work_dir, env),
        )
        .await;
        let pod_still_exact = if matches!(&attach, Ok(Ok(_))) {
            match tokio::time::timeout(
                SETUP_EXEC_ATTACH_TIMEOUT,
                runtime.member_named(&placement, &pod.name),
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
        let wait = handle.wait_tapping_stderr(stderr_tap);
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

    /// Runs one repository's clone while turning Git's stderr meters into
    /// `git_clone` `progress` rows (A5a contract v1). Only stage tokens and
    /// percentages leave the parser; the stderr copies stay in this process
    /// and are zeroed when dropped. Progress is telemetry: a dropped chunk or
    /// an unwritten row never changes the clone's outcome.
    async fn clone_with_progress(
        &self,
        namespace: &str,
        env_id: &str,
        clone: &[String],
        env: &BTreeMap<String, String>,
        repo_index: usize,
        repo_count: usize,
    ) -> anyhow::Result<()> {
        let (tap, mut chunks) = tokio::sync::mpsc::channel(CLONE_PROGRESS_CHUNKS);
        let exec = self.workspace_exec_tapped(namespace, env_id, clone, "", env, Some(tap));
        let report = async {
            let mut parser = clone_progress::CloneProgressParser::default();
            let mut throttle =
                clone_progress::ProgressThrottle::new(clone_progress::PROGRESS_ROW_INTERVAL);
            // The tap closes when the command's stderr ends.
            while let Some(chunk) = chunks.recv().await {
                for progress in parser.feed(&chunk) {
                    if throttle.admit(progress, std::time::Instant::now()) {
                        self.emit_clone_row(
                            "progress",
                            "",
                            clone_progress::progress_metadata(repo_index, repo_count, progress),
                        )
                        .await;
                    }
                }
            }
        };
        let (result, ()) = tokio::join!(exec, report);
        result
    }

    /// Writes one A5a `git_clone` row under the active setup phase. These rows
    /// are best effort: a lost authority is reported by the clone's own fence.
    async fn emit_clone_row(&self, status: &str, message: &str, metadata: serde_json::Value) {
        if let Err(error) = self
            .phase_authority
            .emit_log(
                self.active_phase,
                "git_clone",
                status,
                message,
                Some(metadata),
            )
            .await
        {
            tracing::debug!(
                environment_id = %self.env.id,
                status,
                error = %error,
                "setup: clone progress row not written"
            );
        }
    }

    /// Publish the complete ordinary defaults before clone/install, including an
    /// empty map after clearing values, then set the creator's Git author, in
    /// one workspace exec: each exec costs about 0.2 s of attachment on the
    /// create critical path. Resolved application secrets never enter the
    /// defaults file; the first write gets canonical defaults as explicit
    /// overrides. A failed publication fails the phase; a failed author is a
    /// warning, as when it was its own exec.
    async fn publish_defaults_and_git_identity(&self, namespace: &str) -> anyhow::Result<()> {
        let identity = self.resolve_git_identity().await;
        let cmd = build_configure_environment_command(
            &self.env.project_spec.environment,
            identity
                .as_ref()
                .map(|(email, name)| (email.as_str(), name.as_str())),
        );
        let result = self
            .workspace_exec(
                namespace,
                &self.env.id,
                &cmd,
                "",
                &self.env.project_spec.environment,
            )
            .await;
        match configure_environment_outcome(result, identity.is_some())? {
            GitIdentityOutcome::Unresolved => {}
            GitIdentityOutcome::Configured => {
                if let Some((email, name)) = &identity {
                    log_git_identity_configured(&self.env.id, email, name);
                }
            }
            GitIdentityOutcome::Failed(error) => log_git_identity_failed(&self.env.id, &error),
        }
        Ok(())
    }

    /// The creator's Git author as (email, name), or `None` with a warning
    /// when the creator or their user row cannot be read.
    async fn resolve_git_identity(&self) -> Option<(String, String)> {
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
            return None;
        };

        let user_row: Option<GitIdentityRow> =
            sqlx::query_as("SELECT git_name, git_email, name, email FROM users WHERE id = $1")
                .bind(&created_by)
                .fetch_optional(&self.ctx.pool)
                .await
                .unwrap_or(None);
        let Some((git_name, git_email, name, email)) = user_row else {
            tracing::warn!(user_id = created_by, "git-identity: could not load user");
            return None;
        };

        let resolved_name = resolve_git_field(git_name.as_deref(), name.as_deref(), &email);
        let resolved_email = match git_email.as_deref() {
            Some(email) if !email.is_empty() => email.to_string(),
            _ => email,
        };
        Some((resolved_email, resolved_name))
    }

    /// Applies non-secret Git author metadata through the fenced setup
    /// executor: restart's post-start configuration, after a Pod replacement.
    async fn configure_git_identity(&self, namespace: &str) -> anyhow::Result<()> {
        let env_id = &self.env.id;
        let Some((resolved_email, resolved_name)) = self.resolve_git_identity().await else {
            return Ok(());
        };
        // One workspace exec sets both fields: each exec costs about 0.2 s of
        // attachment on the create and restart critical paths.
        let git_config_result = self
            .workspace_exec(
                namespace,
                env_id,
                &build_git_identity_command(&resolved_email, &resolved_name),
                "",
                &BTreeMap::new(),
            )
            .await;
        match git_config_result {
            Err(error) if is_setup_control_flow(&error) => {
                return Err(error);
            }
            Err(error) => log_git_identity_failed(env_id, &error),
            Ok(()) => log_git_identity_configured(env_id, &resolved_email, &resolved_name),
        }

        Ok(())
    }
}

/// What the configure-environment exec did with the Git author.
#[derive(Debug)]
enum GitIdentityOutcome {
    /// No author was resolved, so the exec only published the defaults.
    Unresolved,
    Configured,
    /// The defaults were published; only the author failed.
    Failed(anyhow::Error),
}

/// Attribute the configure-environment exec's result: any failure but the
/// author's own status is the defaults publication's (or control flow) and
/// fails the phase; the author's status is a warning.
fn configure_environment_outcome(
    result: anyhow::Result<()>,
    identity_resolved: bool,
) -> anyhow::Result<GitIdentityOutcome> {
    match result {
        Ok(()) if identity_resolved => Ok(GitIdentityOutcome::Configured),
        Ok(()) => Ok(GitIdentityOutcome::Unresolved),
        Err(error)
            if identity_resolved
                && !is_setup_control_flow(&error)
                && exited_with(&error, GIT_IDENTITY_FAILED_EXIT) =>
        {
            Ok(GitIdentityOutcome::Failed(error))
        }
        Err(error) => Err(error),
    }
}

fn log_git_identity_failed(environment_id: &str, error: &anyhow::Error) {
    tracing::warn!(
        environment_id,
        error = %error,
        "git-identity: failed to set Git identity"
    );
}

fn log_git_identity_configured(environment_id: &str, email: &str, name: &str) {
    tracing::info!(environment_id, name, email, "git-identity: configured");
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

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
    async fn health_check(&mut self, input: &Inputs) -> anyhow::Result<Option<DaemonReadiness>> {
        if self.health_proven {
            // Create's full access proof covered this exact Pod moments ago,
            // and wrote the daemon's status (#3684).
            tracing::info!(
                environment_id = input.environment_id,
                "setup: health check proven by create's access proof"
            );
            return Ok(None);
        }
        let proof = await_setup_or_cancel(
            &self.activity_ctx,
            self.authority.run_while_authoritative(wait_for_sidecar(
                self.ctx,
                &input.namespace,
                &input.environment_id,
            )),
        );
        // The status read runs beside the proof and is dropped when the proof
        // fails or is cancelled; after a proof it is waited for, bounded.
        let daemon = daemon_readiness(self.ctx, &input.namespace, &input.environment_id);
        tokio::pin!(proof);
        tokio::pin!(daemon);
        let mut status = None;
        let mut read = false;
        loop {
            tokio::select! {
                result = &mut proof => {
                    result?;
                    break;
                }
                observed = &mut daemon, if !read => {
                    status = observed;
                    read = true;
                }
            }
        }
        if !read {
            status = daemon.await;
        }
        Ok(status)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
    async fn configure_environment(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        if self.defaults_written {
            tracing::info!(
                environment_id = input.environment_id,
                "setup: the daemon wrote the project defaults and Git author at its bind"
            );
            return Ok(());
        }
        self.publish_defaults_and_git_identity(&input.namespace)
            .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
    async fn clone_repos(&mut self, input: &Inputs) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        let destinations = validate_repository_mounts(
            input
                .repos
                .iter()
                .map(|repo| (repo.url.as_str(), repo.mount_path.as_str())),
        )?;
        let parents = codewire_project::destination_parents(&destinations);
        let depths = codewire_project::destination_depths(&destinations);
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
        let repo_count = input.repos.len();
        let clones: Vec<_> = input
            .repos
            .iter()
            .zip(ssh_commands)
            .zip(github_commands)
            .enumerate()
            .map(|(position, ((repo, ssh_command), github_command))| {
                let repo = repo.clone();
                let nested_in = parents[position].map(|parent| {
                    let parent = destinations[parent].clone();
                    let relative = destinations[position][parent.len() + 1..].to_owned();
                    (parent, relative)
                });
                let namespace = input.namespace.clone();
                let env_id = input.environment_id.clone();
                let repo_index = position + 1;
                async move {
                    this.phase_authority
                        .ensure_active(this.active_phase)
                        .await?;
                    if repo_count > 1 {
                        this.emit_clone_row(
                            "started",
                            &format!("Cloning repository {repo_index} of {repo_count}"),
                            clone_progress::repository_metadata(repo_index, repo_count),
                        )
                        .await;
                    }
                    let dir = canonical_repository_mount(&repo.url, &repo.mount_path)?;
                    if let Some((parent, relative)) = &nested_in {
                        let guard = nested_checkout_guard(parent, relative);
                        if let Err(error) = this
                            .workspace_exec(&namespace, &env_id, &guard, "", &BTreeMap::new())
                            .await
                        {
                            if is_setup_control_flow(&error) {
                                return Err(error);
                            }
                            let context = if exited_with(&error, NESTED_CHECKOUT_TRACKED_EXIT) {
                                format!(
                                    "repository destination {dir} is a path the repository at {parent} tracks"
                                )
                            } else {
                                format!("prepare repository destination {dir} inside {parent}")
                            };
                            return Err(this
                                .fence_failed_launch_group(input, error.context(context))
                                .await);
                        }
                    }
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
                    let plain = super::fencing_evidence::clone_fixture_command(&repo.url)
                        .unwrap_or_else(|| plain_clone_command(&repo.url, &dir));
                    #[cfg(not(feature = "kind-e2e"))]
                    let plain = plain_clone_command(&repo.url, &dir);
                    let plan = clone_plan(
                        ssh_command.as_ref(),
                        github_command.as_ref(),
                        plain,
                        codewire_project::github_ssh_source(&repo.url).is_some(),
                    );
                    // Git's meters are English only under the C locale, which
                    // the managed SSH and GitHub commands already select.
                    let clone_env = BTreeMap::from([("LC_ALL".to_string(), "C".to_string())]);
                    let mut transport = plan.transport;
                    let mut cloned = this
                        .clone_with_progress(
                            &namespace,
                            &env_id,
                            &plan.clone,
                            &clone_env,
                            repo_index,
                            repo_count,
                        )
                        .await;
                    let refused = matches!(transport, CloneTransport::Ssh { .. })
                        && cloned.as_ref().err().is_some_and(|error| {
                            exited_with(error, ssh_checkout::SSH_REFUSED_EXIT)
                        });
                    if refused {
                        transport = CloneTransport::Ssh { refused: true };
                    }
                    if let Some((https, https_transport)) = plan.https_fallback.filter(|_| refused)
                    {
                        // Git removed its partial checkout; make the empty
                        // destination exact before the HTTPS attempt.
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
                        transport = https_transport;
                        cloned = this
                            .clone_with_progress(
                                &namespace, &env_id, &https, &clone_env, repo_index, repo_count,
                            )
                            .await;
                        if cloned.is_ok() {
                            this.emit_clone_row(
                                "warning",
                                SSH_FALLBACK_WARNING,
                                clone_progress::repository_metadata(repo_index, repo_count),
                            )
                            .await;
                        }
                    }
                    if let Err(e) = cloned {
                        if is_setup_control_flow(&e) {
                            return Err(e);
                        }
                        let error = e.context(clone_failure_context(&repo.url, transport));
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
                    if repo_count > 1 {
                        this.emit_clone_row(
                            "completed",
                            &format!("Cloned repository {repo_index} of {repo_count}"),
                            clone_progress::repository_metadata(repo_index, repo_count),
                        )
                        .await;
                    }
                    Ok(())
                }
            })
            .collect();
        let results = observe_repository_levels(clones, &depths).await;
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

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
    async fn run_install(&mut self, input: &Inputs, work_dir: &str) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        // Docker may still be starting: the command waits for it, bounded.
        let cmd = build_user_setup_command(&input.install_command);
        self.workspace_exec(
            &input.namespace,
            &input.environment_id,
            &cmd,
            work_dir,
            &self.setup_env_vars(),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
    async fn run_startup_script(&mut self, input: &Inputs, work_dir: &str) -> anyhow::Result<()> {
        self.phase_authority
            .ensure_active(self.active_phase)
            .await?;
        // Docker may still be starting: the command waits for it, bounded.
        let cmd = build_user_setup_command(&input.startup_script);
        self.workspace_exec(
            &input.namespace,
            &input.environment_id,
            &cmd,
            work_dir,
            &self.setup_env_vars(),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
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

    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %input.environment_id))]
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
            // The bound daemon serves these on its tailnet address (#2460).
            crate::api::environment_daemon::push_environment_app_ports(
                &self.ctx.pool,
                self.ctx.runtime.as_deref(),
                &self.ctx.sandbox_cfg.session_secret,
                None,
                &input.environment_id,
            )
            .await;
        }
        Ok(())
    }
}

/// Mirrors `resolveGitField`.
pub(crate) fn resolve_git_field(
    git_name: Option<&str>,
    account_name: Option<&str>,
    email: &str,
) -> String {
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

/// Wait until the environment has no member at all, under any name, then for
/// any exec still attached to the old incarnation to have ended.
async fn wait_for_no_workspace_pod(
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    environment_id: &str,
    pod_name: &str,
    old_uid: &str,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + SETUP_POD_RECOVERY_TIMEOUT;
    loop {
        let members = runtime.members(placement, environment_id, pod_name).await?;
        if members.is_empty() {
            setup_fencing_evidence!(SetupFencingEvidence::NoPodObserved {
                environment_id: environment_id.to_string(),
                pod_uid: old_uid.to_string(),
            });
            break;
        }
        if let Some(identity) = members
            .iter()
            .find(|member| member.name == pod_name && member.uid != old_uid)
        {
            tracing::warn!(
                environment_id,
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
        environment_id: environment_id.to_string(),
        pod_uid: old_uid.to_string(),
        wait_ms: SETUP_EXEC_QUIESCENCE.as_millis() as u64,
    });
    Ok(())
}

/// Mirrors `waitForSidecar`: no backend → pass; otherwise poll the
/// SSH/SFTP readiness check with ~2s jittered intervals.
#[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
pub(crate) async fn wait_for_sidecar(
    ctx: &WorkerContext,
    namespace: &str,
    env_id: &str,
) -> anyhow::Result<()> {
    let Some(runtime) = ctx.runtime.as_deref() else {
        return Ok(());
    };
    let placement = Placement::new(namespace);
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
            runtime.ssh_ready(&placement, env_id, &RecordedHostKeys(&ctx.pool)),
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

/// The daemon's status over its control channel, as `GetEnvironmentDaemonStatus`
/// reads it, or `None` when it can't be read within [`DAEMON_STATUS_TIMEOUT`].
async fn daemon_readiness(
    ctx: &WorkerContext,
    namespace: &str,
    env_id: &str,
) -> Option<DaemonReadiness> {
    read_daemon_readiness(
        ctx.pool.clone(),
        ctx.runtime.clone(),
        ctx.sandbox_cfg.session_secret.clone(),
        namespace.to_owned(),
        env_id.to_owned(),
    )
    .await
}

/// The binding generation the daemon says it wrote the defaults for: only a
/// healthy report counts, so a failed write leaves them to setup's exec.
fn reported_defaults_generation(
    diagnostics: &[crate::api::environment_daemon::EnvironmentDaemonDiagnostic],
) -> Option<i64> {
    diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.healthy
                && diagnostic.name == codewire_daemon_proto::WORKSPACE_DEFAULTS_DIAGNOSTIC
        })
        .and_then(|diagnostic| {
            codewire_daemon_proto::workspace_defaults_generation(&diagnostic.message)
        })
}

/// [`daemon_readiness`] from owned parts, for a task that outlives the
/// caller's borrow: create's read beside its own tail (#3684).
pub(super) async fn read_daemon_readiness(
    pool: sqlx::PgPool,
    runtime: Option<std::sync::Arc<dyn crate::runtime::RuntimeDriver>>,
    session_secret: String,
    namespace: String,
    env_id: String,
) -> Option<DaemonReadiness> {
    let env_id = env_id.as_str();
    runtime.as_ref()?;
    let status = tokio::time::timeout(
        DAEMON_STATUS_TIMEOUT,
        crate::api::environment_daemon::environment_daemon_status_for_worker(
            &pool,
            runtime.as_deref(),
            &session_secret,
            &namespace,
            env_id,
        ),
    )
    .await;
    match status {
        Ok(Ok(status)) => Some(DaemonReadiness {
            state: crate::api::environment_daemon::daemon_state_token(status.state),
            defaults_generation: reported_defaults_generation(&status.diagnostics),
            message: status.message,
        }),
        Ok(Err(error)) => {
            tracing::debug!(environment_id = env_id, error = %error, "setup: daemon status unavailable");
            None
        }
        Err(_) => {
            tracing::debug!(environment_id = env_id, "setup: daemon status timed out");
            None
        }
    }
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

#[tracing::instrument(level = "debug", skip_all, fields(environment_id = %payload.environment_id))]
pub async fn handle_environment_setup(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    run_setup(ctx, payload, authority, setup_identity, activity_ctx, None)
        .await
        .map(|_| ())
}

/// What [`handle_environment_setup_after_create`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SetupAfterCreate {
    /// Nothing: the environment has setup work, so the workflow's separate
    /// setup activity runs it as before. Also what an activity that lost its
    /// authority reports, so that activity decides as it always has.
    #[default]
    Deferred,
    /// Setup ran in the create activity, to completion or to its recorded
    /// error, exactly as the separate setup activity would have.
    Ran,
}

/// Setup in the create activity, straight after its `publish_setup` (#3684),
/// for an environment with no setup work: the health check and
/// `configure_environment`, then the final runtime reconcile. `confirmed` is
/// the runtime the create attempt reconciled for that last ready action. When
/// the observation after setup is exactly that runtime, with the backend still
/// naming its Pod as bound, the final reconcile is skipped: it would repeat,
/// in the same activity and with only setup's own steps in between, what the
/// create pass just did ([`ReconciledRuntime`]'s rule, #3637). What that equality
/// does not cover is the gap #3637 accepted within one activity: the preset's
/// template configuration, the worker configuration, the Claim's labels, and
/// the Services and policies the access stack re-applies. Any other
/// observation runs the full reconcile. The health check, the one proof of
/// the SSH login, a session and the SFTP subsystem, is skipped only when
/// create's `access_ready` already made that proof on this runtime's Pod, in
/// the same activity ([`CreateHandover::proved_its_runtime`]).
#[tracing::instrument(level = "debug", skip_all, fields(environment_id = %payload.environment_id))]
pub async fn handle_environment_setup_after_create(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
    handover: &CreateHandover,
) -> anyhow::Result<SetupAfterCreate> {
    let outcome = run_setup(
        ctx,
        payload,
        authority,
        setup_identity,
        activity_ctx,
        Some(handover),
    )
    .await;
    // After setup committed, so the user never waits on them (#3684).
    handover.record_pod_start_marks(ctx, authority).await;
    outcome
}

async fn run_setup(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
    after_create: Option<&CreateHandover>,
) -> anyhow::Result<SetupAfterCreate> {
    let env_id = &payload.environment_id;
    let handover = after_create;
    let health_proven = handover.is_some_and(CreateHandover::proved_its_runtime);
    let after_create = handover.map(CreateHandover::runtime);
    tracing::info!(environment_id = env_id, "environment.setup received");

    let env = load_environment(&ctx.pool, env_id).await?;
    if setup_command_cancelled(&env.state, &env.desired_state) {
        tracing::info!(
            env = env_id,
            state = env.state,
            desired = env.desired_state,
            "setup cancelled: desired state changed"
        );
        return Ok(SetupAfterCreate::Ran);
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
        return Ok(SetupAfterCreate::Ran);
    }

    let mut input = to_setup_inputs(&env, &backend);
    if after_create.is_some() && input.has_setup {
        return Ok(SetupAfterCreate::Deferred);
    }
    // A database error here only costs the shortcut: setup's exec writes them.
    let defaults_written = match handover {
        Some(handover) => {
            let binding = super::workspace_binding::live_environment_binding(&ctx.pool, env_id)
                .await
                .ok()
                .flatten();
            handover.daemon_wrote_defaults(
                binding
                    .as_ref()
                    .map(|binding| (binding.pod_uid.as_str(), binding.operation_generation)),
            )
        }
        None => false,
    };
    let phase_authority = SetupPhaseAuthority::new(authority.clone(), setup_identity)?;
    let mut runner = Runner {
        store: PgSetupStore {
            phase_authority: phase_authority.clone(),
            completed_since_accepted: std::sync::OnceLock::new(),
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
            health_proven,
            defaults_written,
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
        return Ok(SetupAfterCreate::Ran); // environment is still usable — don't retry
    }
    let since = runner.store.completed_since_accepted.get().copied();
    // One read of the runtime after setup serves both the milestone and the
    // final reconcile's check; a setup that completed earlier and is not
    // checking create's runtime reads nothing, as before.
    let probe = if since.is_some() || after_create.is_some() {
        probe_after_setup(ctx, &input.namespace, env_id).await
    } else {
        None
    };
    if let Some(since) = since {
        record_setup_complete(ctx, &runner.ops.env, probe.as_ref(), since);
    }

    let environment = load_environment(&ctx.pool, env_id).await?;
    let backend = load_backend_row(&ctx.pool, env_id).await?;
    if final_reconcile_needed(after_create, &environment, &backend, probe.as_ref()) {
        super::create::reconcile_runtime_identity(
            ctx,
            &environment,
            &backend,
            authority,
            &["running"],
        )
        .await?;
    } else {
        tracing::info!(
            environment_id = env_id,
            "setup: the runtime is the one create just reconciled; no final reconcile"
        );
    }
    tracing::info!(environment_id = env_id, "environment.setup completed");
    Ok(SetupAfterCreate::Ran)
}

/// Whether setup's last step, the runtime reconcile, has to run: always,
/// unless setup runs in the create activity and the observation after it is
/// exactly the runtime that create reconciled
/// ([`handle_environment_setup_after_create`]).
fn final_reconcile_needed(
    after_create: Option<&ReconciledRuntime>,
    environment: &EnvironmentRow,
    backend: &BackendRow,
    probe: Option<&ProbeResult>,
) -> bool {
    match (after_create, probe) {
        (Some(confirmed), Some(probe)) => !confirmed.unchanged(environment, backend, probe),
        _ => true,
    }
}

async fn probe_after_setup(
    ctx: &WorkerContext,
    namespace: &str,
    env_id: &str,
) -> Option<ProbeResult> {
    let runtime = ctx.runtime.as_deref()?;
    match runtime.probe(&Placement::new(namespace), env_id).await {
        Ok(probe) => Some(probe),
        Err(error) => {
            tracing::warn!(
                environment_id = env_id,
                error = %error,
                "setup: the Sandbox read after setup failed"
            );
            None
        }
    }
}

/// Observe the `setup_complete` create milestone after its row committed.
/// Setup completes once per environment, as the last step of its create. It
/// does not know the start path, so it reads the Sandbox's launch type as
/// `access_ready` does; without that read the observation is skipped rather
/// than guessed.
fn record_setup_complete(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    probe: Option<&ProbeResult>,
    since_accepted: Duration,
) {
    // Timing is observational; the row still carries the time.
    let Some(probe) = probe else {
        return;
    };
    record_create_milestone(
        &env.id,
        CreateMilestone::SetupComplete,
        StartPath::from_launch_type(Some(probe.launch_type.as_str())),
        start_profile(&ctx.sandbox_cfg, &env.isolation_tier),
        since_accepted,
    );
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
        health_proven: false,
        defaults_written: false,
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
mod nested_checkout_tests;
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
        daemon: Option<DaemonReadiness>,
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
        async fn health_check(
            &mut self,
            _input: &Inputs,
        ) -> anyhow::Result<Option<DaemonReadiness>> {
            self.call("health_check")?;
            Ok(self.0.lock().unwrap().daemon.clone())
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

    /// #3684: the daemon status read beside the health check becomes a
    /// `daemon_ready` row inside phase 0, before setup completes; with no
    /// status read, no row is written and `cw create` asks the API as before.
    #[tokio::test]
    async fn the_daemon_status_read_beside_the_health_check_is_logged_before_complete() {
        let mock = Mock::new();
        mock.0.lock().unwrap().daemon = Some(DaemonReadiness {
            state: "ready",
            message: String::new(),
            defaults_generation: None,
        });
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        runner.run(&mut input).await.unwrap();
        let calls = mock.state().calls;
        let at = |entry: &str| calls.iter().position(|call| call == entry);
        let daemon = at("log:daemon_ready:completed").expect("a daemon_ready row");
        assert!(at("health_check").is_some_and(|check| check < daemon));
        assert!(
            calls[daemon..]
                .iter()
                .any(|call| call == "log:git_clone:started"),
            "the row is written in phase 0, before the later phases"
        );
        assert!(mock.state().complete);

        let mock = Mock::new();
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        runner.run(&mut input).await.unwrap();
        assert!(
            !mock
                .state()
                .calls
                .iter()
                .any(|call| call.starts_with("log:daemon_ready")),
            "no status read, no row"
        );
    }

    fn member(name: &str, uid: &str) -> MemberRef {
        MemberRef {
            name: name.into(),
            uid: uid.into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_waits_until_no_member_is_left_under_any_name() {
        let runtime = crate::runtime::fake::FakeRuntimeDriver::default();
        *runtime.member_reads.lock().unwrap() = [
            vec![member("workspace-old", "uid-old")],
            // A replacement under the old name, then one under another name,
            // are still members: neither proves the environment is empty.
            vec![member("workspace-old", "uid-new")],
            vec![member("workspace-other", "uid-other")],
            vec![],
        ]
        .into();
        let began = tokio::time::Instant::now();

        wait_for_no_workspace_pod(
            &runtime,
            &Placement::new("dev-sandboxes"),
            "env-1",
            "workspace-old",
            "uid-old",
        )
        .await
        .unwrap();

        assert_eq!(runtime.member_reads.lock().unwrap().len(), 1);
        assert_eq!(
            began.elapsed(),
            SETUP_POD_RECOVERY_POLL * 3 + SETUP_EXEC_QUIESCENCE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_gives_up_at_its_bound_while_a_member_remains() {
        let runtime = crate::runtime::fake::FakeRuntimeDriver::default();
        *runtime.member_reads.lock().unwrap() =
            [vec![member("workspace-other", "uid-other")]].into();
        let began = tokio::time::Instant::now();

        let error = wait_for_no_workspace_pod(
            &runtime,
            &Placement::new("dev-sandboxes"),
            "env-1",
            "workspace-old",
            "uid-old",
        )
        .await
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "setup recovery timed out waiting for Pod workspace-old (uid-old) to be absent"
        );
        assert_eq!(began.elapsed(), SETUP_POD_RECOVERY_TIMEOUT);
    }

    /// Setup recovery binds the replacement Pod before its access wait: an
    /// identity-free daemon serves SSH only once bound (design §10).
    #[tokio::test]
    async fn recovery_binds_the_replacement_before_its_access_wait() {
        let steps = Arc::new(Mutex::new(Vec::new()));
        let step = |name: &'static str, result: anyhow::Result<()>| {
            let steps = Arc::clone(&steps);
            async move {
                steps.lock().unwrap().push(name);
                result
            }
        };

        let reached =
            bind_replacement_then_await_access(step("bind", Ok(())), step("access", Ok(())))
                .await
                .unwrap();
        assert_eq!(reached, ReplacementAccess::Ready);
        assert_eq!(*steps.lock().unwrap(), ["bind", "access"]);

        for refusal in [
            BindRefused::NotConverged,
            BindRefused::PodChanged,
            BindRefused::ChainUnverified,
        ] {
            steps.lock().unwrap().clear();
            let reached = bind_replacement_then_await_access(
                step("bind", Err(refusal.into())),
                step("access", Ok(())),
            )
            .await
            .unwrap();
            assert_eq!(reached, ReplacementAccess::NotYetBindable);
            assert_eq!(*steps.lock().unwrap(), ["bind"], "{refusal:?}");
        }

        for failure in [
            anyhow::Error::from(BindRefused::BoundElsewhere),
            anyhow::Error::from(BindRefused::Denied("released binding")),
            anyhow::Error::from(super::super::activity_authority::AuthorityLost),
        ] {
            steps.lock().unwrap().clear();
            assert!(
                bind_replacement_then_await_access(
                    step("bind", Err(failure)),
                    step("access", Ok(())),
                )
                .await
                .is_err()
            );
            assert_eq!(*steps.lock().unwrap(), ["bind"]);
        }

        steps.lock().unwrap().clear();
        assert!(
            bind_replacement_then_await_access(
                step("bind", Ok(())),
                step("access", Err(anyhow::anyhow!("access timed out"))),
            )
            .await
            .is_err()
        );
        assert_eq!(*steps.lock().unwrap(), ["bind", "access"]);
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
            dedicated_cpu: false,
            never_ran: false,
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 10,
            source_snapshot_id: None,
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

        // #3684: saved variables alone are written by `configure_environment`,
        // which runs either way, so they leave no work for a later phase.
        let mut env = env;
        env.project_spec.environment = BTreeMap::from([("APP_MODE".into(), "test".into())]);
        assert!(!to_setup_inputs(&env, &backend).has_setup);

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

    #[test]
    fn only_a_typed_exit_status_matches_exactly() {
        let refused = WorkspaceExecResult {
            exit_code: ssh_checkout::SSH_REFUSED_EXIT,
            ..Default::default()
        };
        let error = require_workspace_exec_success(&refused)
            .unwrap_err()
            .context("git clone https://github.com/org/app.git over SSH");
        assert!(exited_with(&error, ssh_checkout::SSH_REFUSED_EXIT));
        assert!(!exited_with(&error, 128));
        // Text alone, such as a transport error, is never an exit status.
        assert!(!exited_with(
            &anyhow::anyhow!("workspace exec exited 77"),
            ssh_checkout::SSH_REFUSED_EXIT
        ));
    }

    fn exited(code: i32) -> anyhow::Error {
        require_workspace_exec_success(&WorkspaceExecResult {
            exit_code: code,
            ..Default::default()
        })
        .unwrap_err()
    }

    #[test]
    fn only_a_healthy_defaults_report_names_a_generation() {
        let diagnostic = |name: &str, healthy, message: &str| {
            crate::api::environment_daemon::EnvironmentDaemonDiagnostic {
                name: name.to_owned(),
                healthy,
                message: message.to_owned(),
            }
        };
        let written = codewire_daemon_proto::workspace_defaults_message(7);
        let name = codewire_daemon_proto::WORKSPACE_DEFAULTS_DIAGNOSTIC;
        assert_eq!(
            reported_defaults_generation(&[
                diagnostic("session-store", true, "fine"),
                diagnostic(name, true, &written),
            ]),
            Some(7)
        );
        for refused in [
            vec![],
            vec![diagnostic(name, false, &written)],
            vec![diagnostic(name, false, "project defaults failed")],
            vec![diagnostic(name, true, "something else")],
            vec![diagnostic("session-store", true, &written)],
        ] {
            assert_eq!(reported_defaults_generation(&refused), None, "{refused:?}");
        }
    }

    #[test]
    fn configure_environment_fails_only_for_the_defaults_and_warns_for_the_author() {
        assert!(matches!(
            configure_environment_outcome(Ok(()), true).unwrap(),
            GitIdentityOutcome::Configured
        ));
        assert!(matches!(
            configure_environment_outcome(Ok(()), false).unwrap(),
            GitIdentityOutcome::Unresolved
        ));
        // Only the author's own status, with an author resolved, is a warning.
        assert!(matches!(
            configure_environment_outcome(Err(exited(GIT_IDENTITY_FAILED_EXIT)), true).unwrap(),
            GitIdentityOutcome::Failed(_)
        ));
        for (error, resolved) in [
            (exited(1), true),
            (exited(GIT_IDENTITY_FAILED_EXIT), false),
            (anyhow::anyhow!("workspace exec exited 78"), true),
            (SetupActivityCancelled.into(), true),
            (
                anyhow::Error::new(super::super::activity_authority::AuthorityLost),
                true,
            ),
        ] {
            let message = format!("{error:#}");
            let failed = configure_environment_outcome(Err(error), resolved).unwrap_err();
            assert_eq!(format!("{failed:#}"), message);
        }
    }

    const GITHUB_HTTPS: &str = "https://github.com/org/app.git";

    fn plan_for(repo: Repo, slots: &[&str]) -> ClonePlan {
        let clients = Some(
            codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
                .unwrap(),
        );
        let repos = std::slice::from_ref(&repo);
        let ssh = ssh_checkout::commands(repos, clients).unwrap().remove(0);
        let github = github_checkout::commands(repos, clients).unwrap().remove(0);
        clone_plan(
            ssh.as_ref(),
            github.as_ref(),
            plain_clone_command(&repo.url, &repo.mount_path),
            codewire_project::github_ssh_source(&repo.url).is_some(),
        )
    }

    fn https_repo(url: &str) -> Repo {
        Repo {
            url: url.into(),
            mount_path: "/workspace/app".into(),
            ..Default::default()
        }
    }

    fn bridge(plan: &[String]) -> bool {
        plan.iter()
            .any(|argument| argument.contains("/_codewire/github/"))
    }

    #[test]
    fn a_selected_ssh_key_is_preferred_and_https_is_its_fallback() {
        let plain = plain_clone_command(GITHUB_HTTPS, "/workspace/app");
        // SSH only: SSH first, then the anonymous HTTPS URL.
        let plan = plan_for(https_repo(GITHUB_HTTPS), &["ssh"]);
        assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
        assert_eq!(plan.clone[4], "git@github.com:org/app.git");
        assert_eq!(
            plan.https_fallback,
            Some((
                plain.clone(),
                CloneTransport::HttpsAfterSshRefused { github: false }
            ))
        );
        // Both: SSH first, then the GitHub connection.
        let plan = plan_for(https_repo(GITHUB_HTTPS), &["github", "ssh"]);
        assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
        assert_eq!(plan.clone[4], "git@github.com:org/app.git");
        let (fallback, transport) = plan.https_fallback.unwrap();
        assert!(bridge(&fallback));
        assert_eq!(fallback.last().unwrap(), "/workspace/app");
        assert_eq!(
            transport,
            CloneTransport::HttpsAfterSshRefused { github: true }
        );
        // GitHub only: the bridge, with nothing to fall back to.
        let plan = plan_for(https_repo(GITHUB_HTTPS), &["github"]);
        assert_eq!(plan.transport, CloneTransport::GitHub);
        assert!(bridge(&plan.clone));
        assert_eq!(plan.https_fallback, None);
        // Neither: anonymous, which still clones a public repository.
        let plan = plan_for(https_repo(GITHUB_HTTPS), &[]);
        assert_eq!(plan.transport, CloneTransport::Anonymous { github: true });
        assert_eq!(plan.clone, plain);
        assert_eq!(plan.https_fallback, None);
    }

    /// A github.com source in SSH form: the key when selected (never falling
    /// back), otherwise the GitHub connection's bridge, the origin as written.
    #[test]
    fn a_github_ssh_source_uses_the_key_first_then_the_github_connection() {
        for source in [
            "git@github.com:org/app.git",
            "ssh://git@github.com/org/app.git",
        ] {
            let repo = Repo {
                url: source.into(),
                mount_path: "/workspace/app".into(),
                known_hosts: codewire_project::GITHUB_SSH_KNOWN_HOSTS
                    .map(str::to_owned)
                    .to_vec(),
                ..Default::default()
            };
            for slots in [&["ssh"][..], &["github", "ssh"]] {
                let plan = plan_for(repo.clone(), slots);
                assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
                assert_eq!(plan.clone[4], source);
                assert_eq!(plan.https_fallback, None);
            }
            let plan = plan_for(repo, &["github"]);
            assert_eq!(plan.transport, CloneTransport::GitHub);
            assert!(bridge(&plan.clone));
            assert!(plan.clone.contains(&format!(
                "url.http://127.0.0.1:38081/_codewire/github/org/app.git.insteadOf={source}"
            )));
            assert_eq!(
                &plan.clone[plan.clone.len() - 2..],
                &[source, "/workspace/app"]
            );
            assert_eq!(plan.https_fallback, None);
        }
        // `git://` is served like HTTPS.
        let plan = plan_for(https_repo("git://github.com/org/app.git"), &["github"]);
        assert_eq!(plan.transport, CloneTransport::GitHub);
        assert!(bridge(&plan.clone));
        let plan = plan_for(
            https_repo("git://github.com/org/app.git"),
            &["github", "ssh"],
        );
        assert_eq!(plan.clone[4], "git@github.com:org/app.git");
        assert!(bridge(&plan.https_fallback.unwrap().0));
    }

    #[test]
    fn ssh_and_other_https_sources_never_fall_back() {
        let source = "git@example.com:org/app.git";
        let repo = Repo {
            url: source.into(),
            mount_path: "/workspace/app".into(),
            known_hosts: vec![
                "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx"
                    .into(),
            ],
            ..Default::default()
        };
        let plan = plan_for(repo, &["github", "ssh"]);
        assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
        assert_eq!(plan.clone[4], source);
        assert_eq!(plan.https_fallback, None);
        let plan = plan_for(https_repo("https://gitlab.com/org/app.git"), &["ssh"]);
        assert_eq!(plan.transport, CloneTransport::Anonymous { github: false });
        assert_eq!(plan.https_fallback, None);
    }

    #[test]
    fn clone_failures_name_the_credential_that_was_used_or_missing() {
        for (transport, expected) in [
            (CloneTransport::Ssh { refused: false }, " over SSH"),
            (
                CloneTransport::Ssh { refused: true },
                " over SSH: the server did not accept the SSH key in the Sandbox's credential profile",
            ),
            (CloneTransport::GitHub, " through the GitHub connection"),
            (
                CloneTransport::HttpsAfterSshRefused { github: true },
                " through the GitHub connection after GitHub did not accept the SSH key",
            ),
            (
                CloneTransport::HttpsAfterSshRefused { github: false },
                " over HTTPS after GitHub did not accept the SSH key; no GitHub connection is selected",
            ),
            (
                CloneTransport::Anonymous { github: true },
                " (no SSH key or GitHub connection is selected; a private repository needs one)",
            ),
            (CloneTransport::Anonymous { github: false }, ""),
        ] {
            assert_eq!(
                clone_failure_context(GITHUB_HTTPS, transport),
                format!("git clone {GITHUB_HTTPS}{expected}")
            );
        }
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

    fn running_environment() -> EnvironmentRow {
        EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "running".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            dedicated_cpu: false,
            never_ran: false,
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 80,
            source_snapshot_id: None,
            ttl_seconds: Some(1800),
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        }
    }

    /// #3684: setup in the create activity skips its final reconcile only
    /// when the runtime after setup is exactly the one create reconciled, and
    /// the backend still names its Pod as bound. Every change since then, and
    /// every setup that has no such runtime or could not read one, reconciles.
    #[test]
    fn the_final_reconcile_is_skipped_only_for_the_runtime_create_reconciled() {
        let env = running_environment();
        let backend = BackendRow {
            namespace: "ns".into(),
            claim_name: "sandbox-env-1".into(),
            claim_uid: "claim-1".into(),
            pod_uid: Some("pod-1".into()),
            ..Default::default()
        };
        let probe = ProbeResult {
            pod_name: "cw-pool-member".into(),
            pod_uid: "pod-1".into(),
            pod_ip: "10.0.0.1".into(),
            ..Default::default()
        };
        let confirmed = ReconciledRuntime::observe(&env, &backend, &probe);
        assert!(!final_reconcile_needed(
            Some(&confirmed),
            &env,
            &backend,
            Some(&probe)
        ));
        assert!(final_reconcile_needed(None, &env, &backend, Some(&probe)));
        assert!(final_reconcile_needed(
            Some(&confirmed),
            &env,
            &backend,
            None
        ));

        let mut republished = env.clone();
        republished.projection_selection =
            Ok(Some(codewire_project::PlatformProjectionSelection {
                creator: "usr-1".into(),
                organization: "org-1".into(),
                organization_selected: true,
                project_id: None,
                user_selected: false,
                profile: None,
                ordinary_keys: ["API_URL".to_string()].into(),
                reserved_keys: Default::default(),
            }));
        let mut regenerated = env.clone();
        regenerated.operation_generation = 8;
        let mut failed = env.clone();
        failed.state = "error".into();
        for (case, changed) in [
            ("a republished projection selection", republished),
            ("a new generation", regenerated),
            ("another state", failed),
        ] {
            assert!(
                final_reconcile_needed(Some(&confirmed), &changed, &backend, Some(&probe)),
                "{case}"
            );
        }

        let released = BackendRow {
            pod_uid: None,
            ..backend.clone()
        };
        let reclaimed = BackendRow {
            claim_uid: "claim-2".into(),
            ..backend.clone()
        };
        for (case, changed) in [
            ("a released binding", released),
            ("another Claim", reclaimed),
        ] {
            assert!(
                final_reconcile_needed(Some(&confirmed), &env, &changed, Some(&probe)),
                "{case}"
            );
        }

        let replaced = ProbeResult {
            pod_uid: "pod-2".into(),
            ..probe.clone()
        };
        let readdressed = ProbeResult {
            pod_ip: "10.0.0.2".into(),
            ..probe.clone()
        };
        for (case, changed) in [
            ("a replaced Pod", replaced),
            ("a new Pod address", readdressed),
        ] {
            assert!(
                final_reconcile_needed(Some(&confirmed), &env, &backend, Some(&changed)),
                "{case}"
            );
        }
    }
}
