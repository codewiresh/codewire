//! Rust-owned Temporal environment orchestration (#36 Stage D1, #916).
//!
//! The launch protocol has no Go compatibility path or pre-activation history:
//!
//! - workflow type `EnvironmentWorkflow`, ID `environment/{env_id}`
//! - signal `environment.command`, Rust-native JSON payload
//! - one required operation generation per workflow run
//! - activity names `Environment*Activity`, StartToClose 30m,
//!   HeartbeatTimeout 15s, retry 2s ×2 → 30s cap, 3 attempts
//! - task queue `codewire-lifecycle` (TEMPORAL_TASK_QUEUE)
//!
//! Activity bodies are generation-fenced, cancellation-aware, and
//! journal-checkpointed. Setup additionally owns the workspace process boundary
//! with a durable activity-attempt lease.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use codewire_server_core::obs::TraceContext;
use serde::{Deserialize, Serialize};
use temporalio_client::{Client, ClientOptions, Connection, ConnectionOptions};
use temporalio_common::protos::coresdk::workflow_commands::ActivityCancellationType;
use temporalio_common::protos::temporal::api::common::v1::RetryPolicy;
use temporalio_macros::{activities, workflow, workflow_methods};
use temporalio_sdk::activities::{ActivityContext, ActivityError};
use temporalio_sdk::{
    ActivityOptions, SyncWorkflowContext, Worker, WorkerOptions, WorkflowContext,
    WorkflowContextView, WorkflowResult,
};
use temporalio_sdk_core::{CoreRuntime, RuntimeOptions};
use tracing::Instrument as _;

use crate::worker::activity_authority::{ActivityAuthority, AuthorityLost, is_authority_lost};
use crate::worker::lifecycle::ReconcileOutcome;
use crate::worker::organization_deletion::{
    self, OrganizationDeletionActivityResult, OrganizationDeletionFailureInput,
    OrganizationDeletionWorkflowInput,
};
use crate::worker::setup_lease::SetupActivityIdentity;
use crate::worker::{JobPayload, WorkerContext, create, lifecycle, resize, setup};

pub const DEFAULT_TASK_QUEUE: &str = "codewire-lifecycle";

/// Task queue the billing service's `OrgTeardownWorkflow` runs on (#38).
/// Cross-service: org deletion here starts that workflow by name so the
/// billing worker (which owns the Stripe client) cancels the org's
/// subscription.
pub const BILLING_TASK_QUEUE: &str = "codewire-billing";

/// Input for the billing `OrgTeardownWorkflow`. Both sides are Rust, so
/// the field is plain snake_case — it must serde-match billing's
/// `OrgTeardownInput`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgTeardownInput {
    pub org_id: String,
}

pub fn environment_workflow_id(env_id: &str) -> String {
    format!("environment/{env_id}")
}

pub fn organization_deletion_workflow_id(organization_id: &str, generation: i64) -> String {
    format!("organization-deletion/{organization_id}/{generation}")
}

/// Rust-owned signal payload. Activity authority never comes from a signal.
///
/// `trace_context` is the sender's W3C trace context, so the activities the
/// command runs join the sender's trace. It is never authority, it is absent
/// from the payload unless trace export is on, and the workflow copies it
/// only into the activity inputs below.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCommand {
    pub action: String,
    pub environment_id: String,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentClaimInput {
    pub environment_id: String,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

/// A create's first activity when no generation is claimed yet (#3630): it
/// claims authority exactly as [`EnvironmentActivities::claim_authority`]
/// does, from its own scheduling, then runs the create under that
/// generation, saving one activity dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentClaimAndCreateInput {
    pub environment_id: String,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

/// The workflow patch under which a first create claims inside its own
/// activity. Histories recorded before it replay the separate claim.
const CLAIM_WITH_CREATE_PATCH: &str = "claim-authority-with-create-3630";

/// Internal activity payload created only after the workflow claims authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentActivityCommand {
    pub environment_id: String,
    pub requested_by: String,
    pub operation_generation: i64,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

impl EnvironmentActivityCommand {
    fn from_signal(cmd: &EnvironmentCommand, operation_generation: i64) -> anyhow::Result<Self> {
        Self::claimed(
            &cmd.environment_id,
            &cmd.requested_by,
            &cmd.trace_context,
            operation_generation,
        )
    }

    fn claimed(
        environment_id: &str,
        requested_by: &str,
        trace_context: &TraceContext,
        operation_generation: i64,
    ) -> anyhow::Result<Self> {
        if environment_id.trim().is_empty() || operation_generation <= 0 {
            return Err(AuthorityLost.into());
        }
        Ok(Self {
            environment_id: environment_id.to_owned(),
            requested_by: requested_by.to_owned(),
            operation_generation,
            trace_context: trace_context.clone(),
        })
    }
}

/// The span an environment activity runs in: a child of the trace that sent
/// its command (see [`EnvironmentCommand::trace_context`]). It records the
/// environment id and attempt only.
fn activity_span(
    activity: &'static str,
    environment_id: &str,
    trace_context: &TraceContext,
    ctx: &ActivityContext,
) -> tracing::Span {
    let span = tracing::debug_span!(
        "temporal.activity",
        otel.name = activity,
        otel.kind = "consumer",
        environment_id = %environment_id,
        temporal.attempt = ctx.info().attempt,
    );
    trace_context.attach_to(&span);
    span
}

fn job_payload(cmd: &EnvironmentActivityCommand, action: &str) -> JobPayload {
    JobPayload {
        environment_id: cmd.environment_id.clone(),
        action: action.to_string(),
        ..Default::default()
    }
}

/// Mirrors `environmentActivities` (temporal_worker.go): each activity
/// delegates to the ported job handler.
pub struct EnvironmentActivities {
    pub wctx: Arc<WorkerContext>,
}

async fn required_authority(
    wctx: &WorkerContext,
    cmd: &EnvironmentActivityCommand,
    desired_state: &str,
) -> Result<Option<ActivityAuthority>, ActivityError> {
    match ActivityAuthority::capture_required(
        &wctx.pool,
        &cmd.environment_id,
        desired_state,
        cmd.operation_generation,
    )
    .await
    {
        Ok(authority) => Ok(Some(authority)),
        Err(error) if is_authority_lost(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn run_environment_activity<T, F>(ctx: ActivityContext, future: F) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let cancel_ctx = ctx.clone();
    let heartbeat_ctx = ctx;
    heartbeat_ctx.record_heartbeat(Vec::new());
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = cancel_ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => heartbeat_ctx.record_heartbeat(Vec::new()),
            result = &mut future => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(error) if is_authority_lost(&error) => Ok(T::default()),
                    Err(error) => Err(error.into()),
                };
            }
        }
    }
}

async fn run_claim_activity<F>(ctx: ActivityContext, future: F) -> Result<i64, ActivityError>
where
    F: std::future::Future<Output = anyhow::Result<i64>>,
{
    ctx.record_heartbeat(Vec::new());
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => ctx.record_heartbeat(Vec::new()),
            result = &mut future => return result.map_err(Into::into),
        }
    }
}

/// Setup cancellation must be acknowledged by the setup handler only after it
/// has fenced any ambiguously attached workspace process by observing the Pod
/// absent. Keep heartbeating while that cleanup runs; unlike the ordinary
/// activity wrapper, do not drop the handler future when cancellation arrives.
async fn run_cleanup_aware_environment_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    ctx.record_heartbeat(Vec::new());
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // On the heap: an activity's state machine is large, and this one is
    // otherwise held inside the activity future that the SDK moves.
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = heartbeat.tick() => ctx.record_heartbeat(Vec::new()),
            result = &mut future => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(error) if setup::is_setup_activity_cancelled(&error) => {
                        Err(ActivityError::cancelled())
                    }
                    Err(error) if setup::is_setup_recovery_failed(&error) => {
                        Err(error.into())
                    }
                    Err(error) if is_authority_lost(&error) => Ok(T::default()),
                    Err(error) => Err(error.into()),
                };
            }
        }
    }
}

fn claim_authority_metadata(ctx: &ActivityContext) -> anyhow::Result<(String, i64)> {
    let info = ctx.info();
    let workflow_run_id = info
        .workflow_execution
        .as_ref()
        .map(|execution| execution.run_id.trim())
        .filter(|run_id| !run_id.is_empty())
        .ok_or(AuthorityLost)?
        .to_string();
    let scheduled_at_unix_nanos = info
        .scheduled_time
        .ok_or(AuthorityLost)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthorityLost)?
        .as_nanos()
        .try_into()
        .map_err(|_| AuthorityLost)?;
    Ok((workflow_run_id, scheduled_at_unix_nanos))
}

fn setup_activity_identity(
    ctx: &ActivityContext,
    cmd: &EnvironmentActivityCommand,
) -> anyhow::Result<SetupActivityIdentity> {
    let info = ctx.info();
    SetupActivityIdentity::new(
        cmd.operation_generation,
        info.activity_id.clone(),
        info.attempt,
    )
}

#[activities]
impl EnvironmentActivities {
    #[activity(name = "EnvironmentClaimAuthorityActivity")]
    pub async fn claim_authority(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: EnvironmentClaimInput,
    ) -> Result<i64, ActivityError> {
        let span = activity_span(
            "EnvironmentClaimAuthorityActivity",
            &input.environment_id,
            &input.trace_context,
            &ctx,
        );
        async move {
            let (workflow_run_id, scheduled_at_unix_nanos) = claim_authority_metadata(&ctx)?;
            run_claim_activity(
                ctx,
                ActivityAuthority::claim(
                    &self.wctx.pool,
                    &input.environment_id,
                    &workflow_run_id,
                    scheduled_at_unix_nanos,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    /// #3630: claim, then create, in one activity. A retry claims again with
    /// the same run and scheduled time, which returns the same generation, as
    /// a retried claim activity does; a create that lost authority is a no-op,
    /// as in [`Self::create`], and the generation still goes back to the
    /// workflow for setup.
    #[activity(name = "EnvironmentClaimAndCreateActivity")]
    pub async fn claim_and_create(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: EnvironmentClaimAndCreateInput,
    ) -> Result<i64, ActivityError> {
        let span = activity_span(
            "EnvironmentClaimAndCreateActivity",
            &input.environment_id,
            &input.trace_context,
            &ctx,
        );
        async move {
            let (workflow_run_id, scheduled_at_unix_nanos) = claim_authority_metadata(&ctx)?;
            let generation = run_claim_activity(
                ctx.clone(),
                ActivityAuthority::claim(
                    &self.wctx.pool,
                    &input.environment_id,
                    &workflow_run_id,
                    scheduled_at_unix_nanos,
                ),
            )
            .await?;
            let cmd = EnvironmentActivityCommand::claimed(
                &input.environment_id,
                &input.requested_by,
                &input.trace_context,
                generation,
            )?;
            if let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? {
                run_environment_activity(
                    ctx,
                    create::handle_environment_create_without_setup_publish(
                        &self.wctx,
                        &job_payload(&cmd, "environment.create"),
                        &authority,
                    ),
                )
                .await?;
            }
            Ok(generation)
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentCreateActivity")]
    pub async fn create(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentCreateActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? else {
                return Ok(());
            };
            run_environment_activity(
                ctx,
                create::handle_environment_create_without_setup_publish(
                    &self.wctx,
                    &job_payload(&cmd, "environment.create"),
                    &authority,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentSetupActivity")]
    pub async fn setup(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentSetupActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let setup_identity = setup_activity_identity(&ctx, &cmd)?;
            let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? else {
                return Ok(());
            };
            run_cleanup_aware_environment_activity(
                ctx.clone(),
                setup::handle_environment_setup(
                    &self.wctx,
                    &job_payload(&cmd, "environment.setup"),
                    &authority,
                    setup_identity,
                    ctx,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentStartActivity")]
    pub async fn start(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentStartActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let setup_identity = setup_activity_identity(&ctx, &cmd)?;
            let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? else {
                return Ok(());
            };
            run_cleanup_aware_environment_activity(
                ctx.clone(),
                lifecycle::handle_environment_start(
                    &self.wctx,
                    &job_payload(&cmd, "environment.start"),
                    &authority,
                    setup_identity,
                    ctx,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentStopActivity")]
    pub async fn stop(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentStopActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let Some(authority) = required_authority(&self.wctx, &cmd, "stopped").await? else {
                return Ok(());
            };
            run_environment_activity(
                ctx,
                lifecycle::handle_environment_stop(
                    &self.wctx,
                    &job_payload(&cmd, "environment.stop"),
                    &authority,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentRestartSourcesActivity")]
    pub async fn restart_sources(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentRestartSourcesActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let setup_identity = setup_activity_identity(&ctx, &cmd)?;
            let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? else {
                return Ok(());
            };
            run_cleanup_aware_environment_activity(
                ctx.clone(),
                lifecycle::handle_environment_restart_sources(
                    &self.wctx,
                    &job_payload(&cmd, "environment.restart_sources"),
                    &authority,
                    setup_identity,
                    ctx,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentDestroyActivity")]
    pub async fn destroy(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentDestroyActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let Some(authority) = required_authority(&self.wctx, &cmd, "destroyed").await? else {
                return Ok(());
            };
            run_environment_activity(
                ctx,
                lifecycle::handle_environment_destroy(
                    &self.wctx,
                    &job_payload(&cmd, "environment.destroy"),
                    &authority,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentResizeActivity")]
    pub async fn resize(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<(), ActivityError> {
        let span = activity_span(
            "EnvironmentResizeActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let attempt = ctx.info().attempt;
            let Some(authority) = required_authority(&self.wctx, &cmd, "resized").await? else {
                return Ok(());
            };
            run_environment_activity(
                ctx,
                resize::run_environment_resize(
                    &self.wctx,
                    &cmd.environment_id,
                    &authority,
                    attempt >= 3,
                ),
            )
            .await
        }
        .instrument(span)
        .await
    }

    #[activity(name = "EnvironmentReconcileActivity")]
    pub async fn reconcile(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: EnvironmentActivityCommand,
    ) -> Result<ReconcileOutcome, ActivityError> {
        let span = activity_span(
            "EnvironmentReconcileActivity",
            &cmd.environment_id,
            &cmd.trace_context,
            &ctx,
        );
        async move {
            let authority = match ActivityAuthority::capture(
                &self.wctx.pool,
                &cmd.environment_id,
                cmd.operation_generation,
            )
            .await
            {
                Ok(authority) => authority,
                Err(error) if is_authority_lost(&error) => return Ok(ReconcileOutcome::Continue),
                Err(error) => return Err(error.into()),
            };
            let setup_identity = setup_activity_identity(&ctx, &cmd)?;
            run_cleanup_aware_environment_activity(ctx.clone(), async {
                lifecycle::handle_environment_reconcile(
                    &self.wctx,
                    &job_payload(&cmd, "environment.reconcile"),
                    &authority,
                    setup_identity,
                    ctx,
                )
                .await
            })
            .await
        }
        .instrument(span)
        .await
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        initial_interval: Duration::from_secs(2).try_into().ok(),
        backoff_coefficient: 2.0,
        maximum_interval: Duration::from_secs(30).try_into().ok(),
        maximum_attempts: 3,
        ..Default::default()
    }
}

fn environment_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .heartbeat_timeout(Duration::from_secs(15))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry_policy())
        .build()
}

fn short_activity_opts() -> ActivityOptions {
    let mut opts = ActivityOptions::start_to_close_timeout(Duration::from_secs(30 * 60));
    opts.retry_policy = Some(retry_policy());
    opts
}

fn known_environment_action(action: &str) -> bool {
    matches!(
        action,
        "create" | "start" | "stop" | "destroy" | "resize" | "restart_sources" | "reconcile"
    )
}

fn ensure_workflow_environment(
    expected: &mut Option<String>,
    command: &EnvironmentCommand,
) -> anyhow::Result<()> {
    if command.environment_id.trim().is_empty() {
        return Err(AuthorityLost.into());
    }
    match expected {
        Some(environment_id) if environment_id != &command.environment_id => {
            Err(AuthorityLost.into())
        }
        Some(_) => Ok(()),
        slot @ None => {
            *slot = Some(command.environment_id.clone());
            Ok(())
        }
    }
}

/// Mirrors `orchestration.EnvironmentWorkflow`: a signal-driven
/// command queue; `destroy` completes the workflow; unknown actions
/// are logged and ignored.
#[workflow(name = "EnvironmentWorkflow")]
#[derive(Default)]
pub struct EnvironmentWorkflow {
    queue: VecDeque<EnvironmentCommand>,
}

#[workflow_methods]
impl EnvironmentWorkflow {
    #[init]
    pub fn new(_ctx: &WorkflowContextView, initial: EnvironmentCommand) -> Self {
        let mut queue = VecDeque::new();
        if !initial.action.is_empty() {
            queue.push_back(initial);
        }
        Self { queue }
    }

    #[run]
    pub async fn run(ctx: &mut WorkflowContext<Self>) -> WorkflowResult<()> {
        let mut operation_generation = None;
        let mut environment_id = None;
        loop {
            ctx.wait_condition(|s| !s.queue.is_empty()).await;
            let cmd = ctx
                .state_mut(|s| s.queue.pop_front())
                .expect("queue checked non-empty");

            if !known_environment_action(&cmd.action) {
                tracing::warn!(
                    environment_id = cmd.environment_id,
                    action = cmd.action,
                    "ignoring unknown environment workflow command"
                );
                continue;
            }

            ensure_workflow_environment(&mut environment_id, &cmd)?;
            // Whether this command's create already ran with its claim.
            let mut created = false;
            let generation = match operation_generation {
                Some(generation) => generation,
                None if cmd.action == "create" && ctx.patched(CLAIM_WITH_CREATE_PATCH) => {
                    let generation = ctx
                        .start_activity(
                            EnvironmentActivities::claim_and_create,
                            EnvironmentClaimAndCreateInput {
                                environment_id: cmd.environment_id.clone(),
                                requested_by: cmd.requested_by.clone(),
                                trace_context: cmd.trace_context.clone(),
                            },
                            environment_activity_opts(),
                        )
                        .await?;
                    operation_generation = Some(generation);
                    created = true;
                    generation
                }
                None => {
                    let generation = ctx
                        .start_activity(
                            EnvironmentActivities::claim_authority,
                            EnvironmentClaimInput {
                                environment_id: cmd.environment_id.clone(),
                                trace_context: cmd.trace_context.clone(),
                            },
                            environment_activity_opts(),
                        )
                        .await?;
                    operation_generation = Some(generation);
                    generation
                }
            };
            let activity_cmd = EnvironmentActivityCommand::from_signal(&cmd, generation)?;

            match cmd.action.as_str() {
                "create" => {
                    if !created {
                        ctx.start_activity(
                            EnvironmentActivities::create,
                            activity_cmd.clone(),
                            environment_activity_opts(),
                        )
                        .await?;
                    }
                    ctx.start_activity(
                        EnvironmentActivities::setup,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "start" => {
                    ctx.start_activity(
                        EnvironmentActivities::start,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "stop" => {
                    ctx.start_activity(
                        EnvironmentActivities::stop,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "restart_sources" => {
                    ctx.start_activity(
                        EnvironmentActivities::restart_sources,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "destroy" => {
                    ctx.start_activity(
                        EnvironmentActivities::destroy,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                    return Ok(());
                }
                "resize" => {
                    ctx.start_activity(
                        EnvironmentActivities::resize,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "reconcile" => {
                    let outcome = ctx
                        .start_activity(
                            EnvironmentActivities::reconcile,
                            activity_cmd,
                            environment_activity_opts(),
                        )
                        .await?;
                    if outcome == ReconcileOutcome::Destroyed {
                        return Ok(());
                    }
                }
                _ => unreachable!("known environment action checked above"),
            }
        }
    }

    #[signal(name = "environment.command")]
    pub fn command(&mut self, _ctx: &mut SyncWorkflowContext<Self>, cmd: EnvironmentCommand) {
        self.queue.push_back(cmd);
    }
}

/// Public marker type for clients that retain a typed handle to this workflow.
pub type EnvironmentWorkflowRun = environment_workflow::Run;

/// Port-DNS command for the PortDnsWorkflow (D3: the misc NATS queue
/// is retired; the capability lives on as a short-lived workflow).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortDnsCommand {
    #[serde(rename = "Action", default)]
    pub action: String,
    #[serde(rename = "EnvironmentID", default)]
    pub environment_id: String,
    #[serde(rename = "PortID", default)]
    pub port_id: String,
}

pub struct PortDnsActivities {
    pub wctx: Arc<WorkerContext>,
}

/// Local activity handlers for the dark, generation-bound organization
/// deletion workflow. The billing phase is deliberately not registered here:
/// that activity is owned by the billing worker and scheduled onto its queue.
pub struct OrganizationDeletionActivities {
    pub wctx: Arc<WorkerContext>,
}

async fn run_organization_deletion_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    F: std::future::Future<Output = Result<T, codewire_server_core::AppError>>,
{
    ctx.record_heartbeat(Vec::new());
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(future);

    loop {
        tokio::select! {
            _ = ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => ctx.record_heartbeat(Vec::new()),
            result = &mut future => return result.map_err(|error| {
                ActivityError::from(anyhow::anyhow!(
                    "organization deletion activity failed: {error}"
                ))
            }),
        }
    }
}

#[activities]
impl OrganizationDeletionActivities {
    #[activity(name = "DestroyOrganizationEnvironmentsActivity")]
    pub async fn destroy_environments(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::destroy_organization_environments(&self.wctx, &input),
        )
        .await
    }

    #[activity(name = "RecordOrganizationBillingFinalizedActivity")]
    pub async fn record_billing_finalized(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::record_billing_finalized(&self.wctx.pool, &input),
        )
        .await
    }

    #[activity(name = "TeardownOrganizationTenantSecretsActivity")]
    pub async fn teardown_tenant_secrets(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::teardown_tenant_secrets(&self.wctx, &input),
        )
        .await
    }

    #[activity(name = "ReconcileOrganizationControlPlaneActivity")]
    pub async fn reconcile_control_plane(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::reconcile_control_plane_mutations(&self.wctx.pool, &input),
        )
        .await
    }

    #[activity(name = "FinalizeOrganizationDatabaseActivity")]
    pub async fn finalize_database(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::finalize_database(&self.wctx.pool, &input),
        )
        .await
    }

    #[activity(name = "FailOrganizationDeletionActivity")]
    pub async fn fail(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: OrganizationDeletionFailureInput,
    ) -> Result<OrganizationDeletionActivityResult, ActivityError> {
        run_organization_deletion_activity(
            ctx,
            organization_deletion::record_failure(&self.wctx.pool, &input),
        )
        .await
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationBillingTeardownResult {
    pub state: String,
    pub terminal_subscription_count: u32,
}

/// Name-only declaration for the activity implemented by codewire-billing.
/// Temporal routes it to `codewire-billing`; this implementation is never
/// registered by the orchestration worker.
pub struct ExternalOrganizationBillingActivities;

#[activities]
impl ExternalOrganizationBillingActivities {
    #[activity(name = "FinalizeOrganizationBillingActivity")]
    pub async fn finalize_billing(
        self: Arc<Self>,
        _ctx: ActivityContext,
        _input: OrganizationDeletionWorkflowInput,
    ) -> Result<OrganizationBillingTeardownResult, ActivityError> {
        unreachable!("external billing activity is not registered locally")
    }
}

fn organization_deletion_activity_opts() -> ActivityOptions {
    environment_activity_opts()
}

fn organization_deletion_failure_opts() -> ActivityOptions {
    let mut retry = retry_policy();
    // The destructive phase has already stopped. Keep retrying only the
    // idempotent terminal-state write so a database outage cannot strand a
    // started operation behind a completed Temporal workflow.
    retry.maximum_attempts = 0;
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .heartbeat_timeout(Duration::from_secs(15))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry)
        .build()
}

fn organization_billing_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .task_queue(BILLING_TASK_QUEUE)
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry_policy())
        .build()
}

fn organization_deletion_failure(
    operation: &OrganizationDeletionWorkflowInput,
    failure_code: &str,
) -> OrganizationDeletionFailureInput {
    OrganizationDeletionFailureInput {
        operation: operation.clone(),
        failure_code: failure_code.to_string(),
    }
}

/// Dark WI-5 workflow. It is started only from the durable outbox reconciler;
/// the customer DELETE endpoint remains on its inherited path until WI-7.
#[workflow(name = "OrganizationDeletionWorkflow")]
#[derive(Default)]
pub struct OrganizationDeletionWorkflow {}

#[workflow_methods]
impl OrganizationDeletionWorkflow {
    #[run]
    pub async fn run(
        ctx: &mut WorkflowContext<Self>,
        input: OrganizationDeletionWorkflowInput,
    ) -> WorkflowResult<()> {
        if ctx
            .start_activity(
                OrganizationDeletionActivities::destroy_environments,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "environment_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .start_activity(
                ExternalOrganizationBillingActivities::finalize_billing,
                input.clone(),
                organization_billing_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "billing_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .start_activity(
                OrganizationDeletionActivities::record_billing_finalized,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "billing_reconciliation_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .start_activity(
                OrganizationDeletionActivities::teardown_tenant_secrets,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "tenant_secret_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .start_activity(
                OrganizationDeletionActivities::reconcile_control_plane,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "control_plane_reconciliation_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .start_activity(
                OrganizationDeletionActivities::finalize_database,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.start_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "database_finalization_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
        }
        Ok(())
    }
}

#[activities]
impl PortDnsActivities {
    #[activity(name = "PortDnsCreateActivity")]
    pub async fn create(
        self: Arc<Self>,
        _ctx: ActivityContext,
        cmd: PortDnsCommand,
    ) -> Result<(), ActivityError> {
        let payload = JobPayload {
            environment_id: cmd.environment_id.clone(),
            port_id: cmd.port_id.clone(),
            action: "port.dns.create".to_string(),
            ..Default::default()
        };
        crate::worker::port_dns::handle_port_dns_create(&self.wctx, &payload).await?;
        Ok(())
    }

    #[activity(name = "PortDnsDeleteActivity")]
    pub async fn delete(
        self: Arc<Self>,
        _ctx: ActivityContext,
        cmd: PortDnsCommand,
    ) -> Result<(), ActivityError> {
        let payload = JobPayload {
            environment_id: cmd.environment_id.clone(),
            port_id: cmd.port_id.clone(),
            action: "port.dns.delete".to_string(),
            ..Default::default()
        };
        crate::worker::port_dns::handle_port_dns_delete(&self.wctx, &payload).await?;
        Ok(())
    }
}

/// Single-shot workflow: one port-DNS action with Temporal's retry
/// policy, then complete. Workflow ID convention:
/// `port-dns/{action}/{port_id or environment_id}`.
#[workflow(name = "PortDnsWorkflow")]
#[derive(Default)]
pub struct PortDnsWorkflow {}

#[workflow_methods]
impl PortDnsWorkflow {
    #[run]
    pub async fn run(ctx: &mut WorkflowContext<Self>, cmd: PortDnsCommand) -> WorkflowResult<()> {
        match cmd.action.as_str() {
            "create" => {
                ctx.start_activity(
                    PortDnsActivities::create,
                    cmd.clone(),
                    short_activity_opts(),
                )
                .await?;
            }
            "delete" => {
                ctx.start_activity(
                    PortDnsActivities::delete,
                    cmd.clone(),
                    short_activity_opts(),
                )
                .await?;
            }
            other => {
                tracing::warn!(action = other, "ignoring unknown port-dns workflow command");
            }
        }
        Ok(())
    }
}

/// The D2 trigger client — mirrors `TemporalOrchestrator.TriggerEnvironment`
/// (temporal.go): atomic SignalWithStart of the environment workflow.
/// Used by the reconciler's enqueues (and, after #38, the API) when
/// `ENVIRONMENT_ORCHESTRATOR=temporal-primary`.
pub struct TemporalTrigger {
    client: Client,
    task_queue: String,
}

impl TemporalTrigger {
    pub async fn connect(
        host_port: &str,
        namespace: &str,
        task_queue: &str,
    ) -> anyhow::Result<Self> {
        let target = if host_port.contains("://") {
            host_port.to_string()
        } else {
            format!("http://{host_port}")
        };
        let conn_opts = ConnectionOptions::new(url::Url::parse(&target)?)
            // One frontend Service address, connected now. DNS load
            // balancing would open connections lazily inside the first
            // request, whose span the connection then holds (#3581).
            .dns_load_balancing(None)
            .build();
        let connection = Connection::connect(conn_opts).await?;
        let client = Client::new(
            connection,
            ClientOptions::new(namespace.to_string()).build(),
        )
        .map_err(|e| anyhow::anyhow!("temporal trigger client: {e}"))?;
        Ok(Self {
            client,
            task_queue: task_queue.to_string(),
        })
    }

    /// Mirrors `TriggerEnvironment`: SignalWithStart with an empty
    /// initial command and the real command as the signal. The signal carries
    /// the caller's trace context, so the command's activities join its trace.
    #[tracing::instrument(
        level = "debug",
        name = "temporal.signal_with_start",
        skip_all,
        fields(
            environment_id = %env_id,
            action = %action,
            otel.kind = "producer",
            otel.name = "SignalWithStartWorkflow:EnvironmentWorkflow",
        )
    )]
    pub async fn trigger_environment(&self, env_id: &str, action: &str) -> anyhow::Result<()> {
        use temporalio_client::{WorkflowStartOptions, WorkflowStartSignal};
        let workflow_id = environment_workflow_id(env_id);
        let cmd = EnvironmentCommand {
            action: action.to_string(),
            environment_id: env_id.to_string(),
            requested_by: String::new(),
            trace_context: TraceContext::current(),
        };
        let signal_input = temporalio_common::data_converters::DataConverter::default()
            .to_payloads(
                &temporalio_common::data_converters::SerializationContextData::Workflow,
                &cmd,
            )
            .await
            .map_err(|e| anyhow::anyhow!("serialize environment command: {e}"))?;
        use temporalio_common::protos::coresdk::IntoPayloadsExt;
        let options = WorkflowStartOptions::new(self.task_queue.as_str(), workflow_id.as_str())
            .start_signal(
                WorkflowStartSignal::new("environment.command".to_string())
                    .input(signal_input.into_payloads().unwrap_or_default())
                    .build(),
            )
            .build();
        // The RPC runs span-free: Temporal's frontend closes connections at
        // their maximum age, and the SDK's channel reopens one lazily inside
        // the next call, through an executor that keeps the caller's span for
        // the connection's life (#3581). The signal carries the trace context
        // itself, so the workflow's activities still join this trace.
        let client = self.client.clone();
        codewire_server_core::span_free::detached(async move {
            client
                .start_workflow(
                    EnvironmentWorkflow::run,
                    EnvironmentCommand::default(),
                    options,
                )
                .await
                .map(|_| ())
        })
        .await
        .map_err(|e| anyhow::anyhow!("signal/start environment workflow: {e}"))?;
        Ok(())
    }

    /// Starts the billing `OrgTeardownWorkflow` BY NAME (untyped) on the
    /// `codewire-billing` task queue (#38). The workflow's
    /// subscription-cancel activity runs in the billing service; this
    /// side only needs the workflow type name and the JSON input.
    pub async fn trigger_org_teardown(&self, org_id: &str) -> anyhow::Result<()> {
        use temporalio_client::{UntypedWorkflow, WorkflowHandle, WorkflowStartOptions};
        use temporalio_common::data_converters::{PayloadConverter, RawValue};

        let workflow_id = format!("org-teardown/{org_id}");
        let converter = PayloadConverter::default();
        let input = RawValue::from_value(
            &OrgTeardownInput {
                org_id: org_id.to_string(),
            },
            &converter,
        );
        let options = WorkflowStartOptions::new(BILLING_TASK_QUEUE, workflow_id.as_str()).build();
        let _handle: WorkflowHandle<_, UntypedWorkflow> = self
            .client
            .start_workflow(UntypedWorkflow::new("OrgTeardownWorkflow"), input, options)
            .await
            .map_err(|e| anyhow::anyhow!("start org-teardown workflow: {e}"))?;
        Ok(())
    }

    /// Start or recover the one durable workflow for this organization
    /// deletion generation. `UseExisting` turns a crash after Temporal
    /// accepted the start but before the database acknowledgement into an
    /// idempotent recovery, never a second deletion execution.
    pub async fn trigger_organization_deletion(
        &self,
        input: OrganizationDeletionWorkflowInput,
    ) -> anyhow::Result<()> {
        use temporalio_client::WorkflowStartOptions;
        use temporalio_common::protos::temporal::api::enums::v1::WorkflowIdConflictPolicy;

        if input.operation_id.trim().is_empty()
            || input.organization_id.trim().is_empty()
            || input.generation <= 0
        {
            anyhow::bail!("organization deletion workflow identity is invalid");
        }
        let workflow_id =
            organization_deletion_workflow_id(&input.organization_id, input.generation);
        if input.operation_id != workflow_id {
            anyhow::bail!("organization deletion workflow identity does not match its operation");
        }
        let options = WorkflowStartOptions::new(self.task_queue.as_str(), workflow_id)
            .id_conflict_policy(WorkflowIdConflictPolicy::UseExisting)
            .build();
        self.client
            .start_workflow(OrganizationDeletionWorkflow::run, input, options)
            .await
            .map_err(|error| anyhow::anyhow!("start organization deletion workflow: {error}"))?;
        Ok(())
    }
}

/// The Temporal worker thread's stack. Every activity is polled on this one
/// thread, nested inside the SDK's own futures. In an unoptimised build the
/// create activity's poll frames alone take about 1.75 MiB (the create loop's
/// frame is 1.1 MiB), and its first Kubernetes call overflowed a spawned
/// thread's 2 MiB default (main run 22671); it ran in 3 MiB. A stack is
/// address space, committed only as it is touched.
const TEMPORAL_WORKER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Spawns the Temporal worker on a dedicated thread with its own
/// runtime — `Worker::run`'s future is !Send, so it cannot ride the
/// main multi-threaded runtime via `tokio::spawn`. Retries with
/// backoff forever (server restarts, network partitions).
pub fn spawn_temporal_worker(
    wctx: Arc<WorkerContext>,
    host_port: String,
    namespace: String,
    task_queue: String,
) {
    std::thread::Builder::new()
        .name("temporal-worker".into())
        .stack_size(TEMPORAL_WORKER_STACK_BYTES)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("temporal worker runtime");
            rt.block_on(async move {
                let mut backoff = Duration::from_secs(2);
                loop {
                    match run_temporal_worker(wctx.clone(), &host_port, &namespace, &task_queue)
                        .await
                    {
                        Ok(()) => break,
                        Err(e) => {
                            tracing::error!(error = %e, backoff = ?backoff, "temporal worker failed; retrying");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(60));
                        }
                    }
                }
            });
        })
        .expect("spawn temporal worker thread");
}

/// Connects and runs the Temporal worker until failure. The caller
/// owns retry/backoff.
pub async fn run_temporal_worker(
    wctx: Arc<WorkerContext>,
    host_port: &str,
    namespace: &str,
    task_queue: &str,
) -> anyhow::Result<()> {
    let runtime_opts = RuntimeOptions::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("temporal runtime options: {e}"))?;
    let runtime = CoreRuntime::new_assume_tokio(runtime_opts)?;

    let target = if host_port.contains("://") {
        host_port.to_string()
    } else {
        format!("http://{host_port}")
    };
    let conn_opts = ConnectionOptions::new(url::Url::parse(&target)?)
        // One frontend Service address, connected now. DNS load
        // balancing would open connections lazily inside the first
        // request, whose span the connection then holds (#3581).
        .dns_load_balancing(None)
        .build();
    let connection = Connection::connect(conn_opts).await?;
    let client = Client::new(
        connection,
        ClientOptions::new(namespace.to_string()).build(),
    )
    .map_err(|e| anyhow::anyhow!("temporal client: {e}"))?;

    let worker_options = WorkerOptions::new(task_queue.to_string())
        .register_workflow::<EnvironmentWorkflow>()?
        .register_workflow::<PortDnsWorkflow>()?
        .register_workflow::<OrganizationDeletionWorkflow>()?
        .register_activities(EnvironmentActivities { wctx: wctx.clone() })
        .register_activities(PortDnsActivities { wctx: wctx.clone() })
        .register_activities(OrganizationDeletionActivities { wctx })
        .build();

    let mut worker = Worker::new(&runtime, client, worker_options)
        .map_err(|e| anyhow::anyhow!("temporal worker init: {e}"))?;
    tracing::info!(task_queue, namespace, "temporal worker started");
    worker
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("temporal worker run: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_id_is_stable() {
        assert_eq!(environment_workflow_id("env-1"), "environment/env-1");
        assert_eq!(
            organization_deletion_workflow_id("org-1", 7),
            "organization-deletion/org-1/7"
        );
    }

    #[test]
    fn organization_deletion_payload_matches_external_billing_contract() {
        let input = OrganizationDeletionWorkflowInput {
            operation_id: "op-1".into(),
            organization_id: "org-1".into(),
            generation: 7,
        };
        assert_eq!(
            serde_json::to_string(&input).unwrap(),
            r#"{"operation_id":"op-1","organization_id":"org-1","generation":7}"#
        );
        assert!(
            serde_json::from_str::<OrganizationDeletionWorkflowInput>(
                r#"{"operation_id":"op-1","org_id":"org-1","generation":7}"#
            )
            .is_err()
        );
    }

    #[test]
    fn organization_billing_activity_uses_only_the_billing_queue() {
        let opts = organization_billing_activity_opts();
        assert_eq!(opts.task_queue.as_deref(), Some(BILLING_TASK_QUEUE));
        assert_eq!(opts.heartbeat_timeout, None);
        assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts, 3);
    }

    #[test]
    fn organization_deletion_failure_write_retries_until_durable() {
        let opts = organization_deletion_failure_opts();
        assert_eq!(opts.heartbeat_timeout, Some(Duration::from_secs(15)));
        assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts, 0);
    }

    #[test]
    fn signal_payload_is_rust_native_and_rejects_go_aliases() {
        let json = r#"{"action":"create","environment_id":"env-1","requested_by":"usr-1"}"#;
        let cmd: EnvironmentCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.action, "create");
        assert_eq!(cmd.environment_id, "env-1");
        assert_eq!(cmd.requested_by, "usr-1");
        assert_eq!(serde_json::to_string(&cmd).unwrap(), json);
        assert!(
            serde_json::from_str::<EnvironmentCommand>(
                r#"{"Action":"create","EnvironmentID":"env-1","RequestedBy":"usr-1"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<EnvironmentCommand>(
                r#"{"action":"create","environment_id":"env-1"}"#
            )
            .is_err()
        );

        let empty: EnvironmentCommand =
            serde_json::from_str(r#"{"action":"","environment_id":"","requested_by":""}"#).unwrap();
        assert!(empty.action.is_empty());
    }

    #[test]
    fn activity_payload_requires_positive_generation() {
        let cmd: EnvironmentActivityCommand = serde_json::from_str(
            r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#,
        )
        .unwrap();
        assert_eq!(cmd.operation_generation, 7);
        assert!(
            serde_json::from_str::<EnvironmentActivityCommand>(
                r#"{"environment_id":"env-1","requested_by":""}"#
            )
            .is_err()
        );
        let signal = EnvironmentCommand {
            action: "setup".into(),
            environment_id: "env-1".into(),
            requested_by: String::new(),
            ..Default::default()
        };
        assert!(EnvironmentActivityCommand::from_signal(&signal, 0).is_err());
    }

    /// #3630: the merged first create's input carries no generation, since
    /// the activity claims it, and refuses unknown fields like every other
    /// workflow payload; the command it builds keeps the claim's checks.
    #[test]
    fn claim_and_create_input_carries_no_authority() {
        let input: EnvironmentClaimAndCreateInput =
            serde_json::from_str(r#"{"environment_id":"env-1","requested_by":"alice"}"#).unwrap();
        assert_eq!(input.environment_id, "env-1");
        assert!(
            serde_json::from_str::<EnvironmentClaimAndCreateInput>(
                r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#
            )
            .is_err()
        );
        let cmd = EnvironmentActivityCommand::claimed(
            &input.environment_id,
            &input.requested_by,
            &input.trace_context,
            7,
        )
        .unwrap();
        assert_eq!(
            (
                cmd.environment_id.as_str(),
                cmd.requested_by.as_str(),
                cmd.operation_generation
            ),
            ("env-1", "alice", 7)
        );
        assert!(
            EnvironmentActivityCommand::claimed("env-1", "alice", &TraceContext::default(), 0)
                .is_err()
        );
        assert!(
            EnvironmentActivityCommand::claimed(" ", "alice", &TraceContext::default(), 7).is_err()
        );
    }

    #[test]
    fn final_workflow_activates_heartbeat_and_cancellation_completion() {
        let opts = environment_activity_opts();
        assert_eq!(
            opts.close_timeouts,
            temporalio_sdk::ActivityCloseTimeouts::StartToClose(Duration::from_secs(30 * 60))
        );
        assert_eq!(opts.heartbeat_timeout, Some(Duration::from_secs(15)));
        assert_eq!(
            opts.cancellation_type,
            ActivityCancellationType::WaitCancellationCompleted
        );
        assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts, 3);
        assert!(known_environment_action("resize"));
        assert!(known_environment_action("restart_sources"));
    }

    #[test]
    fn reconcile_outcome_is_directly_typed() {
        let json = serde_json::to_string(&ReconcileOutcome::Destroyed).unwrap();
        assert_eq!(
            serde_json::from_str::<ReconcileOutcome>(&json).unwrap(),
            ReconcileOutcome::Destroyed
        );
        assert_ne!(json, "null");
    }

    /// A create's trace context rides the signal through the Temporal data
    /// converter into the claim and activity inputs, and a command sent while
    /// trace export is off keeps its exact pre-tracing payload.
    #[tokio::test]
    async fn trace_context_rides_from_the_signal_into_activity_inputs() {
        use temporalio_common::data_converters::{DataConverter, SerializationContextData};

        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let converter = DataConverter::default();
        let signal = EnvironmentCommand {
            action: "create".into(),
            environment_id: "env-1".into(),
            requested_by: String::new(),
            trace_context: TraceContext {
                traceparent: Some(traceparent.into()),
                tracestate: Some("codewire=dev".into()),
            },
        };
        let payloads = converter
            .to_payloads(&SerializationContextData::Workflow, &signal)
            .await
            .unwrap();
        let received: EnvironmentCommand = converter
            .from_payloads(&SerializationContextData::Workflow, payloads)
            .await
            .unwrap();
        assert_eq!(received.trace_context, signal.trace_context);

        let claim = EnvironmentClaimInput {
            environment_id: received.environment_id.clone(),
            trace_context: received.trace_context.clone(),
        };
        let claim_payloads = converter
            .to_payloads(&SerializationContextData::Activity, &claim)
            .await
            .unwrap();
        let claim: EnvironmentClaimInput = converter
            .from_payloads(&SerializationContextData::Activity, claim_payloads)
            .await
            .unwrap();
        assert_eq!(
            claim.trace_context.traceparent.as_deref(),
            Some(traceparent)
        );

        let activity = EnvironmentActivityCommand::from_signal(&received, 7).unwrap();
        let activity_payloads = converter
            .to_payloads(&SerializationContextData::Activity, &activity)
            .await
            .unwrap();
        let activity: EnvironmentActivityCommand = converter
            .from_payloads(&SerializationContextData::Activity, activity_payloads)
            .await
            .unwrap();
        assert_eq!(activity.operation_generation, 7);
        assert_eq!(
            activity.trace_context.traceparent.as_deref(),
            Some(traceparent)
        );
        assert_eq!(
            activity.trace_context.tracestate.as_deref(),
            Some("codewire=dev")
        );

        let untraced = EnvironmentActivityCommand::from_signal(
            &EnvironmentCommand {
                action: "create".into(),
                environment_id: "env-1".into(),
                ..Default::default()
            },
            7,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&untraced).unwrap(),
            r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#
        );
        assert!(
            serde_json::from_str::<EnvironmentActivityCommand>(
                r#"{"environment_id":"env-1","requested_by":"","operation_generation":7,"trace_context":{"traceparent":"x","authority":"y"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn workflow_rejects_cross_environment_signals() {
        let mut expected = None;
        let first = EnvironmentCommand {
            action: "create".into(),
            environment_id: "env-1".into(),
            requested_by: String::new(),
            ..Default::default()
        };
        let other = EnvironmentCommand {
            action: "destroy".into(),
            environment_id: "env-2".into(),
            requested_by: String::new(),
            ..Default::default()
        };
        ensure_workflow_environment(&mut expected, &first).unwrap();
        assert!(ensure_workflow_environment(&mut expected, &other).is_err());
    }
}
