//! How a lifecycle activity runs: the authority it must hold, its heartbeat
//! while the work is in flight, and what its context says about the command.

use super::*;
use temporalio_common::protos::temporal::api::enums::v1::WorkflowExecutionStatus;
use temporalio_common::protos::temporal::api::workflowservice::v1::DescribeWorkflowExecutionResponse;

impl EnvironmentActivities {
    /// The authority of an activity in this run: the command's generation,
    /// whose claim row must name this activity's own run (#6103).
    pub(super) async fn run_authority(
        &self,
        ctx: &ActivityContext,
        cmd: &EnvironmentActivityCommand,
    ) -> anyhow::Result<ActivityAuthority> {
        ActivityAuthority::capture_for_run(
            &self.wctx.pool,
            &cmd.environment_id,
            cmd.operation_generation,
            &activity_run_id(ctx)?,
        )
        .await
    }

    /// [`Self::run_authority`], when the command still matches its required
    /// lifecycle intent; `None` when it is stale.
    pub(super) async fn required_authority(
        &self,
        ctx: &ActivityContext,
        cmd: &EnvironmentActivityCommand,
        desired_state: &str,
    ) -> Result<Option<ActivityAuthority>, ActivityError> {
        match self.run_authority(ctx, cmd).await {
            Ok(authority) if authority.desired_state() == desired_state => Ok(Some(authority)),
            Ok(_) => Ok(None),
            Err(error) if is_authority_lost(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// Records an empty heartbeat. The SDK encodes it before handing it to the
/// worker, which throttles and sends it; encoding `()` cannot fail, and a
/// heartbeat that cannot be sent is never a reason to fail the activity.
pub(super) async fn record_heartbeat(ctx: &ActivityContext) {
    if let Err(error) = ctx.record_heartbeat(()).await {
        tracing::warn!(%error, "activity heartbeat could not be encoded");
    }
}

pub(super) async fn run_environment_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let cancel_ctx = ctx.clone();
    let heartbeat_ctx = ctx;
    record_heartbeat(&heartbeat_ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = cancel_ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => record_heartbeat(&heartbeat_ctx).await,
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

pub(super) async fn run_claim_activity<F>(
    ctx: ActivityContext,
    future: F,
) -> Result<i64, ActivityError>
where
    F: std::future::Future<Output = anyhow::Result<i64>>,
{
    record_heartbeat(&ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => record_heartbeat(&ctx).await,
            result = &mut future => return result.map_err(Into::into),
        }
    }
}

/// Setup cancellation must be acknowledged by the setup handler only after it
/// has fenced any ambiguously attached workspace process by observing the Pod
/// absent. Keep heartbeating while that cleanup runs; unlike the ordinary
/// activity wrapper, do not drop the handler future when cancellation arrives.
pub(super) async fn run_cleanup_aware_environment_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    record_heartbeat(&ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // On the heap: an activity's state machine is large, and this one is
    // otherwise held inside the activity future that the SDK moves.
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = heartbeat.tick() => record_heartbeat(&ctx).await,
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

/// The run this activity belongs to, as Temporal reports it.
fn activity_run_id(ctx: &ActivityContext) -> anyhow::Result<String> {
    Ok(ctx
        .info()
        .workflow_run_id
        .as_deref()
        .map(str::trim)
        .filter(|run_id| !run_id.is_empty())
        .ok_or(AuthorityLost)?
        .to_string())
}

pub(super) fn claim_authority_metadata(ctx: &ActivityContext) -> anyhow::Result<(String, i64)> {
    let info = ctx.info();
    let workflow_run_id = activity_run_id(ctx)?;
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

pub(super) fn setup_activity_identity(
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

/// What a claim activity knows about the run making it.
pub(super) struct ClaimRun {
    workflow_run_id: String,
    scheduled_at_unix_nanos: i64,
}

impl ClaimRun {
    pub(super) fn of(ctx: &ActivityContext) -> anyhow::Result<Self> {
        let (workflow_run_id, scheduled_at_unix_nanos) = claim_authority_metadata(ctx)?;
        Ok(Self {
            workflow_run_id,
            scheduled_at_unix_nanos,
        })
    }
}

/// The generation this run's claim holds: the current one, when Temporal
/// describes the run holding it as closed (#5950, #6103);
/// otherwise, as for any new run, the next one. A failed Temporal read claims
/// nothing: the claim activity retries, and a run whose attempts run out
/// fails and leaves the generation where it was.
pub(super) async fn claim_for_run(
    wctx: &WorkerContext,
    environment_id: &str,
    claim: &ClaimRun,
) -> anyhow::Result<i64> {
    let trigger = &wctx.temporal_trigger;
    ActivityAuthority::claim_after_holder(
        &wctx.pool,
        environment_id,
        &claim.workflow_run_id,
        claim.scheduled_at_unix_nanos,
        |holder| async move { trigger.run_status(environment_id, &holder).await },
    )
    .await
}

impl TemporalTrigger {
    /// How Temporal describes run `workflow_run_id` of the environment's
    /// workflow. `Ok(None)` is Temporal's answer that it has no such run; a
    /// read that failed is an error.
    pub(crate) async fn run_status(
        &self,
        environment_id: &str,
        workflow_run_id: &str,
    ) -> anyhow::Result<Option<WorkflowExecutionStatus>> {
        let read = self.read_run_status(environment_workflow_id(environment_id), workflow_run_id);
        codewire_server_core::span_free::detached(read).await
    }

    fn read_run_status(
        &self,
        workflow_id: String,
        workflow_run_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<WorkflowExecutionStatus>>>
    + Send
    + 'static {
        use temporalio_client::NamespacedClient;
        use temporalio_client::grpc::WorkflowService;
        use temporalio_common::protos::temporal::api::common::v1::WorkflowExecution;
        use temporalio_common::protos::temporal::api::workflowservice::v1::DescribeWorkflowExecutionRequest;
        let mut client = self.client.clone();
        let run_id = workflow_run_id.to_owned();
        async move {
            let namespace = client.namespace();
            let described = WorkflowService::describe_workflow_execution(
                &mut client,
                tonic::Request::new(DescribeWorkflowExecutionRequest {
                    namespace,
                    execution: Some(WorkflowExecution {
                        workflow_id,
                        run_id,
                    }),
                }),
            )
            .await;
            described_status(described.map(tonic::Response::into_inner))
        }
    }
}

/// Temporal's answer for one run: its status, or `None` when Temporal has no
/// record of it (`NotFound`, as once its retention has passed) or reports no
/// status it knows. Any other error is a failed read.
fn described_status(
    described: Result<DescribeWorkflowExecutionResponse, tonic::Status>,
) -> anyhow::Result<Option<WorkflowExecutionStatus>> {
    match described {
        Ok(response) => Ok(response
            .workflow_execution_info
            .and_then(|info| WorkflowExecutionStatus::try_from(info.status).ok())),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(status.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::described_status;
    use temporalio_common::protos::temporal::api::enums::v1::WorkflowExecutionStatus;
    use temporalio_common::protos::temporal::api::workflow::v1::WorkflowExecutionInfo;
    use temporalio_common::protos::temporal::api::workflowservice::v1::DescribeWorkflowExecutionResponse;

    fn described(status: i32) -> Result<DescribeWorkflowExecutionResponse, tonic::Status> {
        Ok(DescribeWorkflowExecutionResponse {
            workflow_execution_info: Some(WorkflowExecutionInfo {
                status,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// #6103: a read that failed is an error, whatever the failure, so the
    /// claim returns it and retries instead of claiming a new generation;
    /// the old last-attempt fallback to a new generation is gone. Only
    /// Temporal's own answer that it has no such run reads as no status.
    #[test]
    fn a_failed_holder_read_is_an_error_never_a_status() {
        for code in [
            tonic::Code::Unavailable,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Cancelled,
            tonic::Code::Internal,
            tonic::Code::Unknown,
            tonic::Code::ResourceExhausted,
            tonic::Code::PermissionDenied,
            tonic::Code::Unauthenticated,
        ] {
            assert!(
                described_status(Err(tonic::Status::new(code, "temporal unavailable"))).is_err(),
                "{code:?}"
            );
        }
        assert_eq!(
            described_status(Err(tonic::Status::not_found("no such run"))).unwrap(),
            None
        );
    }

    #[test]
    fn a_described_run_reads_as_its_status() {
        for status in [
            WorkflowExecutionStatus::Running,
            WorkflowExecutionStatus::ContinuedAsNew,
            WorkflowExecutionStatus::Completed,
            WorkflowExecutionStatus::Failed,
            WorkflowExecutionStatus::Terminated,
            WorkflowExecutionStatus::TimedOut,
            WorkflowExecutionStatus::Canceled,
        ] {
            assert_eq!(
                described_status(described(status as i32)).unwrap(),
                Some(status),
                "{status:?}"
            );
        }
        assert_eq!(described_status(described(i32::MAX)).unwrap(), None);
        assert_eq!(
            described_status(Ok(DescribeWorkflowExecutionResponse::default())).unwrap(),
            None
        );
    }
}
