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

use codewire_server_core::account_deletion::{self, AccountDeletionWorkflowInput};
use codewire_server_core::obs::TraceContext;
use serde::{Deserialize, Serialize};
use temporalio_client::{Client, ClientOptions, Connection, ConnectionOptions};
use temporalio_common::protos::temporal::api::common::v1::RetryPolicy;
use temporalio_macros::{activities, workflow, workflow_methods};
use temporalio_sdk::activities::{ActivityContext, ActivityError};
use temporalio_sdk::{
    ActivityCancellationType, ActivityOptions, ApplicationFailure, SyncWorkflowContext,
    WorkflowContext, WorkflowContextView, WorkflowResult,
};
use tracing::Instrument as _;

use crate::worker::activity_authority::{ActivityAuthority, AuthorityLost, is_authority_lost};
use crate::worker::host_lifecycle::Change;
use crate::worker::lifecycle::ReconcileOutcome;
use crate::worker::organization_deletion::{
    self, OrganizationDeletionActivityResult, OrganizationDeletionFailureInput,
    OrganizationDeletionWorkflowInput,
};
use crate::worker::setup_lease::SetupActivityIdentity;
use crate::worker::{JobPayload, WorkerContext, create, lifecycle, resize, setup};
use options::*;

mod activity_run;
mod commands;
mod continuation;
mod host;
mod options;
mod snapshot;
mod worker;

use activity_run::{
    claim_authority_metadata, record_heartbeat, required_authority, run_claim_activity,
    run_cleanup_aware_environment_activity, run_environment_activity, setup_activity_identity,
};
use commands::{ensure_workflow_environment, known_environment_action};
pub use snapshot::{
    SnapshotAbandonment, SnapshotActivities, SnapshotCaptureWorkflow, SnapshotCommand,
    SnapshotDeleteWorkflow, snapshot_capture_workflow_id, snapshot_delete_workflow_id,
};
pub use worker::{run_temporal_worker, spawn_temporal_worker};

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
/// Retry setup (#4767). A worker from before it ignored `retry_setup` as an
/// unknown command, before any claim; `run` skips an unpatched one at that
/// same check, so a history it recorded replays the command as skipped. Deprecate it (`deprecate_patch`) once no open
/// `EnvironmentWorkflow` holds a `retry_setup` signal without the marker:
/// every workflow open during the rollout has closed, or a scan of open
/// histories finds none. Remove it once that release runs everywhere.
const RETRY_SETUP_PATCH: &str = "retry-setup-4767";

/// What [`EnvironmentActivities::claim_and_create`] returns. Histories
/// recorded before #3684 hold the bare generation, which decodes as
/// [`Self::Generation`]: setup still to run, as those workflows expect. No
/// patch is needed, since the workflow reads the recorded result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimAndCreateResult {
    Generation(i64),
    Outcome {
        operation_generation: i64,
        /// Setup ran in the same activity, so the workflow skips its own.
        setup_completed: bool,
    },
}

impl ClaimAndCreateResult {
    fn operation_generation(self) -> i64 {
        match self {
            Self::Generation(generation)
            | Self::Outcome {
                operation_generation: generation,
                ..
            } => generation,
        }
    }

    fn setup_completed(self) -> bool {
        matches!(
            self,
            Self::Outcome {
                setup_completed: true,
                ..
            }
        )
    }
}

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
    ///
    /// #3684: when the create hands over to setup and the environment has no
    /// setup work, setup runs here too, after the create and under its own
    /// wrapper, as the reconcile recovery path composes them: the create's
    /// readiness waits stop when the activity is cancelled, and setup fences
    /// its workspace processes before it acknowledges a cancellation. Its
    /// lease is this activity's identity, which a retry takes over.
    #[activity(name = "EnvironmentClaimAndCreateActivity")]
    pub async fn claim_and_create(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: EnvironmentClaimAndCreateInput,
    ) -> Result<ClaimAndCreateResult, ActivityError> {
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
            let mut setup_completed = false;
            if let Some(authority) = required_authority(&self.wctx, &cmd, "started").await? {
                if host::ran(&self.wctx, &ctx, &authority, host::Step::Create).await? {
                    return Ok(ClaimAndCreateResult::Outcome {
                        operation_generation: generation,
                        setup_completed: false,
                    });
                }
                let confirmed = run_environment_activity(
                    ctx.clone(),
                    create::handle_environment_create_before_setup(
                        &self.wctx,
                        &job_payload(&cmd, "environment.create"),
                        &authority,
                    ),
                )
                .await?;
                if let Some(confirmed) = confirmed {
                    let setup_identity = setup_activity_identity(&ctx, &cmd)?;
                    let setup = run_cleanup_aware_environment_activity(
                        ctx.clone(),
                        Box::pin(setup::handle_environment_setup_after_create(
                            &self.wctx,
                            &job_payload(&cmd, "environment.setup"),
                            &authority,
                            setup_identity,
                            ctx,
                            &confirmed,
                        )),
                    )
                    .await?;
                    setup_completed = setup == setup::SetupAfterCreate::Ran;
                }
            }
            Ok(ClaimAndCreateResult::Outcome {
                operation_generation: generation,
                setup_completed,
            })
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
            if host::ran(&self.wctx, &ctx, &authority, host::Step::Create).await? {
                return Ok(());
            }
            run_environment_activity(
                ctx,
                create::handle_environment_create_without_setup_publish(
                    &self.wctx,
                    &job_payload(&cmd, "environment.create"),
                    &authority,
                ),
            )
            .await
            .map(|_| ())
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
            if host::ran(&self.wctx, &ctx, &authority, host::Step::Nothing).await? {
                return Ok(());
            }
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
            if host::ran(
                &self.wctx,
                &ctx,
                &authority,
                host::Step::Change(Change::Start),
            )
            .await?
            {
                return Ok(());
            }
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
            if host::ran(
                &self.wctx,
                &ctx,
                &authority,
                host::Step::Change(Change::Stop),
            )
            .await?
            {
                return Ok(());
            }
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
            if host::ran(&self.wctx, &ctx, &authority, host::Step::Nothing).await? {
                return Ok(());
            }
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
            if host::ran(
                &self.wctx,
                &ctx,
                &authority,
                host::Step::Change(Change::Destroy),
            )
            .await?
            {
                return Ok(());
            }
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
            if host::ran(
                &self.wctx,
                &ctx,
                &authority,
                host::Step::Unsupported("Resize"),
            )
            .await?
            {
                return Ok(());
            }
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
            if host::ran(&self.wctx, &ctx, &authority, host::Step::Nothing).await? {
                return Ok(ReconcileOutcome::Continue);
            }
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

/// Mirrors `orchestration.EnvironmentWorkflow`: a signal-driven
/// command queue; `destroy` completes the workflow; unknown actions
/// are logged and ignored.
#[workflow]
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

    #[run(name = "EnvironmentWorkflow")]
    pub async fn run(ctx: &mut WorkflowContext<Self>) -> WorkflowResult<()> {
        let mut operation_generation = None;
        let mut environment_id = None;
        loop {
            continuation::continue_when_due(ctx)?;
            ctx.wait_condition(|s| !s.queue.is_empty()).await?;
            let cmd = ctx
                .state_mut(|s| s.queue.pop_front())
                .expect("queue checked non-empty");

            if !known_environment_action(&cmd.action)
                || (cmd.action == "retry_setup" && !ctx.patched(RETRY_SETUP_PATCH))
            {
                tracing::warn!(
                    environment_id = cmd.environment_id,
                    action = cmd.action,
                    "ignoring unknown environment workflow command"
                );
                continue;
            }

            ensure_workflow_environment(&mut environment_id, &cmd)
                .map_err(ApplicationFailure::from)?;
            // Whether this command's create already ran with its claim, and
            // its setup with it (#3684).
            let mut created = false;
            let mut setup_completed = false;
            let generation = match operation_generation {
                Some(generation) => generation,
                None if cmd.action == "create" && ctx.patched(CLAIM_WITH_CREATE_PATCH) => {
                    let result = ctx
                        .execute_activity(
                            EnvironmentActivities::claim_and_create,
                            EnvironmentClaimAndCreateInput {
                                environment_id: cmd.environment_id.clone(),
                                requested_by: cmd.requested_by.clone(),
                                trace_context: cmd.trace_context.clone(),
                            },
                            environment_activity_opts(),
                        )
                        .await?;
                    let generation = result.operation_generation();
                    operation_generation = Some(generation);
                    created = true;
                    setup_completed = result.setup_completed();
                    generation
                }
                None => {
                    let generation = ctx
                        .execute_activity(
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
            let activity_cmd = EnvironmentActivityCommand::from_signal(&cmd, generation)
                .map_err(ApplicationFailure::from)?;

            match cmd.action.as_str() {
                "create" => {
                    if !created {
                        ctx.execute_activity(
                            EnvironmentActivities::create,
                            activity_cmd.clone(),
                            environment_activity_opts(),
                        )
                        .await?;
                    }
                    if !setup_completed {
                        ctx.execute_activity(
                            EnvironmentActivities::setup,
                            activity_cmd,
                            environment_activity_opts(),
                        )
                        .await?;
                    }
                }
                "start" => {
                    ctx.execute_activity(
                        EnvironmentActivities::start,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "stop" => {
                    ctx.execute_activity(
                        EnvironmentActivities::stop,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                // Setup resumes from its recorded checkpoint; the activity
                // is the one a create runs after its handover.
                "retry_setup" => {
                    ctx.execute_activity(
                        EnvironmentActivities::setup,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "restart_sources" => {
                    ctx.execute_activity(
                        EnvironmentActivities::restart_sources,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "destroy" => {
                    ctx.execute_activity(
                        EnvironmentActivities::destroy,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                    return Ok(());
                }
                "resize" => {
                    ctx.execute_activity(
                        EnvironmentActivities::resize,
                        activity_cmd,
                        environment_activity_opts(),
                    )
                    .await?;
                }
                "reconcile" => {
                    let outcome = ctx
                        .execute_activity(
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
    record_heartbeat(&ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(future);

    loop {
        tokio::select! {
            _ = ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => record_heartbeat(&ctx).await,
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
#[workflow]
#[derive(Default)]
pub struct OrganizationDeletionWorkflow {}

#[workflow_methods]
impl OrganizationDeletionWorkflow {
    #[run(name = "OrganizationDeletionWorkflow")]
    pub async fn run(
        ctx: &mut WorkflowContext<Self>,
        input: OrganizationDeletionWorkflowInput,
    ) -> WorkflowResult<()> {
        if ctx
            .execute_activity(
                OrganizationDeletionActivities::destroy_environments,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "environment_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .execute_activity(
                ExternalOrganizationBillingActivities::finalize_billing,
                input.clone(),
                organization_billing_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "billing_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .execute_activity(
                OrganizationDeletionActivities::record_billing_finalized,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "billing_reconciliation_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .execute_activity(
                OrganizationDeletionActivities::teardown_tenant_secrets,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "tenant_secret_cleanup_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .execute_activity(
                OrganizationDeletionActivities::reconcile_control_plane,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "control_plane_reconciliation_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
            return Ok(());
        }

        if ctx
            .execute_activity(
                OrganizationDeletionActivities::finalize_database,
                input.clone(),
                organization_deletion_activity_opts(),
            )
            .await
            .is_err()
        {
            ctx.execute_activity(
                OrganizationDeletionActivities::fail,
                organization_deletion_failure(&input, "database_finalization_failed"),
                organization_deletion_failure_opts(),
            )
            .await?;
        }
        Ok(())
    }
}

/// Local activities of the account deletion workflow (#3679). The Stripe and
/// mail phases are owned by the billing worker and scheduled onto its queue.
pub struct AccountDeletionActivities {
    pub wctx: Arc<WorkerContext>,
}

fn account_deletion_activity_error(error: codewire_server_core::AppError) -> ActivityError {
    ActivityError::from(anyhow::anyhow!("account deletion activity failed: {error}"))
}

#[activities]
impl AccountDeletionActivities {
    /// Fails, and so is retried, until every personal organization's own
    /// deletion has completed.
    #[activity(name = "AwaitAccountOrganizationsDeletedActivity")]
    pub async fn await_organizations(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        account_deletion::mark_account_deletion_started(&self.wctx.pool, &input.operation_id)
            .await
            .map_err(account_deletion_activity_error)?;
        let done =
            account_deletion::advance_personal_organizations(&self.wctx.pool, &input.operation_id)
                .await
                .map_err(account_deletion_activity_error)?;
        if !done {
            return Err(ActivityError::from(anyhow::anyhow!(
                "personal organizations are still being deleted"
            )));
        }
        Ok(())
    }

    #[activity(name = "FinalizeAccountDatabaseActivity")]
    pub async fn finalize_database(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        account_deletion::finalize_account_deletion_database(&self.wctx.pool, &input.operation_id)
            .await
            .map_err(account_deletion_activity_error)?;
        Ok(())
    }
}

/// Name-only declarations for the activities implemented by codewire-billing.
/// Temporal routes them to `codewire-billing`; this implementation is never
/// registered by the orchestration worker.
pub struct ExternalAccountDeletionBillingActivities;

#[activities]
impl ExternalAccountDeletionBillingActivities {
    #[activity(name = "DeleteAccountStripeCustomersActivity")]
    pub async fn delete_stripe_customers(
        self: Arc<Self>,
        _ctx: ActivityContext,
        _input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        unreachable!("external billing activity is not registered locally")
    }

    #[activity(name = "SendAccountDeletedMailActivity")]
    pub async fn send_deleted_mail(
        self: Arc<Self>,
        _ctx: ActivityContext,
        _input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        unreachable!("external billing activity is not registered locally")
    }
}

/// Deletes an account after its request disabled it (#3679). Started only
/// from the durable outbox reconciler; each activity resumes from the phase
/// the operation records.
#[workflow]
#[derive(Default)]
pub struct AccountDeletionWorkflow {}

#[workflow_methods]
impl AccountDeletionWorkflow {
    #[run(name = "AccountDeletionWorkflow")]
    pub async fn run(
        ctx: &mut WorkflowContext<Self>,
        input: AccountDeletionWorkflowInput,
    ) -> WorkflowResult<()> {
        ctx.execute_activity(
            AccountDeletionActivities::await_organizations,
            input.clone(),
            account_deletion_activity_opts(),
        )
        .await?;
        ctx.execute_activity(
            ExternalAccountDeletionBillingActivities::delete_stripe_customers,
            input.clone(),
            account_deletion_billing_activity_opts(),
        )
        .await?;
        ctx.execute_activity(
            AccountDeletionActivities::finalize_database,
            input.clone(),
            account_deletion_activity_opts(),
        )
        .await?;
        ctx.execute_activity(
            ExternalAccountDeletionBillingActivities::send_deleted_mail,
            input,
            account_deletion_billing_activity_opts(),
        )
        .await?;
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
#[workflow]
#[derive(Default)]
pub struct PortDnsWorkflow {}

#[workflow_methods]
impl PortDnsWorkflow {
    #[run(name = "PortDnsWorkflow")]
    pub async fn run(ctx: &mut WorkflowContext<Self>, cmd: PortDnsCommand) -> WorkflowResult<()> {
        match cmd.action.as_str() {
            "create" => {
                ctx.execute_activity(
                    PortDnsActivities::create,
                    cmd.clone(),
                    short_activity_opts(),
                )
                .await?;
            }
            "delete" => {
                ctx.execute_activity(
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
        use temporalio_client::WorkflowStartOptions;
        let workflow_id = environment_workflow_id(env_id);
        let cmd = EnvironmentCommand {
            action: action.to_string(),
            environment_id: env_id.to_string(),
            requested_by: String::new(),
            trace_context: TraceContext::current(),
        };
        let options =
            WorkflowStartOptions::new(self.task_queue.as_str(), workflow_id.as_str()).build();
        // The RPC runs span-free: Temporal's frontend closes connections at
        // their maximum age, and the SDK's channel reopens one lazily inside
        // the next call, through an executor that keeps the caller's span for
        // the connection's life (#3581). The signal carries the trace context
        // itself, so the workflow's activities still join this trace.
        let client = self.client.clone();
        codewire_server_core::span_free::detached(async move {
            client
                .signal_with_start_workflow(
                    EnvironmentWorkflow::run,
                    EnvironmentCommand::default(),
                    EnvironmentWorkflow::command,
                    cmd,
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
        use temporalio_client::WorkflowIdConflictPolicy;
        use temporalio_client::WorkflowStartOptions;

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

impl TemporalTrigger {
    /// Start or recover the one durable workflow for an account deletion.
    /// `UseExisting` makes a start repeated after a crash a recovery, never
    /// a second execution.
    pub async fn trigger_account_deletion(
        &self,
        input: AccountDeletionWorkflowInput,
    ) -> anyhow::Result<()> {
        use temporalio_client::WorkflowIdConflictPolicy;
        use temporalio_client::WorkflowStartOptions;

        if !input.operation_id.starts_with("account-deletion/") {
            anyhow::bail!("account deletion workflow identity is invalid");
        }
        let options =
            WorkflowStartOptions::new(self.task_queue.as_str(), input.operation_id.clone())
                .id_conflict_policy(WorkflowIdConflictPolicy::UseExisting)
                .build();
        self.client
            .start_workflow(AccountDeletionWorkflow::run, input, options)
            .await
            .map_err(|error| anyhow::anyhow!("start account deletion workflow: {error}"))?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod replay_tests;
