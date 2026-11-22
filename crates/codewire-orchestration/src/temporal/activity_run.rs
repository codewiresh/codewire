//! How a lifecycle activity runs: the authority it must hold, its heartbeat
//! while the work is in flight, and what its context says about the command.

use super::*;

pub(super) async fn required_authority(
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

pub(super) fn claim_authority_metadata(ctx: &ActivityContext) -> anyhow::Result<(String, i64)> {
    let info = ctx.info();
    let workflow_run_id = info
        .workflow_run_id
        .as_deref()
        .map(str::trim)
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

/// What a claim activity knows about the run and attempt making it.
pub(super) struct ClaimRun {
    workflow_run_id: String,
    scheduled_at_unix_nanos: i64,
    attempt: u32,
}

impl ClaimRun {
    pub(super) fn of(ctx: &ActivityContext) -> anyhow::Result<Self> {
        let (workflow_run_id, scheduled_at_unix_nanos) = claim_authority_metadata(ctx)?;
        Ok(Self {
            workflow_run_id,
            scheduled_at_unix_nanos,
            attempt: ctx.info().attempt,
        })
    }
}

/// The generation this run's claim holds: its predecessor's, when Temporal
/// reports that this run continued as new from it (#5950); otherwise, as for
/// any new run, the next one.
pub(super) async fn claim_for_run(
    wctx: &WorkerContext,
    environment_id: &str,
    claim: &ClaimRun,
) -> anyhow::Result<i64> {
    let read = wctx
        .temporal_trigger
        .continued_from(environment_id, &claim.workflow_run_id)
        .await;
    let continued_from = predecessor_or_retry(read, claim.attempt, environment_id)?;
    ActivityAuthority::claim_continued(
        &wctx.pool,
        environment_id,
        &claim.workflow_run_id,
        claim.scheduled_at_unix_nanos,
        continued_from.as_deref(),
    )
    .await
}

/// A Temporal read that failed is retried with the claim activity, which
/// holds no claim yet, so nothing waits on it: claiming a new generation on a
/// blip would restart a credentialed Sandbox (#5950). On the activity's last
/// attempt the claim goes on as a new run's, once, rather than failing the
/// command.
fn predecessor_or_retry(
    read: anyhow::Result<Option<String>>,
    attempt: u32,
    environment_id: &str,
) -> anyhow::Result<Option<String>> {
    let last_attempt = u32::try_from(super::options::retry_policy().maximum_attempts).unwrap_or(1);
    match read {
        Ok(predecessor) => Ok(predecessor),
        Err(error) if attempt < last_attempt => {
            Err(error.context("read the run this run continued from"))
        }
        Err(error) => {
            tracing::warn!(
                environment_id,
                attempt,
                error = %error,
                "continued run: its predecessor could not be read on the claim's last attempt; claiming a new generation"
            );
            Ok(None)
        }
    }
}

impl TemporalTrigger {
    /// The run `workflow_run_id` continued from, read from Temporal: the
    /// `continued_execution_run_id` of its own start event, and only when
    /// Temporal reports that run as continued-as-new. `Ok(None)` is
    /// Temporal's answer that there is none; a read that failed is an error.
    pub(crate) async fn continued_from(
        &self,
        environment_id: &str,
        workflow_run_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let read =
            self.read_continued_from(environment_workflow_id(environment_id), workflow_run_id);
        codewire_server_core::span_free::detached(read).await
    }

    fn read_continued_from(
        &self,
        workflow_id: String,
        workflow_run_id: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<String>>> + Send + 'static {
        use temporalio_client::NamespacedClient;
        use temporalio_client::grpc::WorkflowService;
        use temporalio_common::protos::temporal::api::common::v1::WorkflowExecution;
        use temporalio_common::protos::temporal::api::history::v1::history_event::Attributes;
        use temporalio_common::protos::temporal::api::workflowservice::v1::{
            DescribeWorkflowExecutionRequest, GetWorkflowExecutionHistoryRequest,
        };
        let mut client = self.client.clone();
        let run_id = workflow_run_id.to_owned();
        async move {
            let namespace = client.namespace();
            let started = WorkflowService::get_workflow_execution_history(
                &mut client,
                tonic::Request::new(GetWorkflowExecutionHistoryRequest {
                    namespace: namespace.clone(),
                    execution: Some(WorkflowExecution {
                        workflow_id: workflow_id.clone(),
                        run_id,
                    }),
                    maximum_page_size: 1,
                    ..Default::default()
                }),
            )
            .await?
            .into_inner();
            let predecessor = started
                .history
                .and_then(|history| history.events.into_iter().next())
                .and_then(|event| match event.attributes {
                    Some(Attributes::WorkflowExecutionStartedEventAttributes(started)) => {
                        Some(started.continued_execution_run_id)
                    }
                    _ => None,
                })
                .unwrap_or_default();
            if predecessor.is_empty() {
                return Ok(None);
            }
            let described = WorkflowService::describe_workflow_execution(
                &mut client,
                tonic::Request::new(DescribeWorkflowExecutionRequest {
                    namespace,
                    execution: Some(WorkflowExecution {
                        workflow_id,
                        run_id: predecessor.clone(),
                    }),
                }),
            )
            .await?
            .into_inner();
            Ok(continued_predecessor(
                predecessor,
                described.workflow_execution_info.map(|info| info.status),
            ))
        }
    }
}

/// A predecessor counts only when Temporal reports it continued as new: a
/// run still going, failed, terminated, timed out, completed or reset does
/// not hand its generation on.
pub(super) fn continued_predecessor(predecessor: String, status: Option<i32>) -> Option<String> {
    use temporalio_common::protos::temporal::api::enums::v1::WorkflowExecutionStatus;
    (!predecessor.is_empty() && status == Some(WorkflowExecutionStatus::ContinuedAsNew as i32))
        .then_some(predecessor)
}

#[cfg(test)]
mod tests {
    use super::{continued_predecessor, predecessor_or_retry};
    use temporalio_common::protos::temporal::api::enums::v1::WorkflowExecutionStatus;

    /// An answer passes through; a failed read retries while the claim has
    /// attempts left, and claims as a new run on its last (#5950).
    #[test]
    fn a_failed_predecessor_read_retries_then_claims_as_a_new_run() {
        let failed = || Err(anyhow::anyhow!("temporal unavailable"));
        assert_eq!(
            predecessor_or_retry(Ok(Some("run-a".into())), 1, "env").unwrap(),
            Some("run-a".to_owned())
        );
        assert_eq!(predecessor_or_retry(Ok(None), 1, "env").unwrap(), None);
        let last = u32::try_from(super::super::options::retry_policy().maximum_attempts).unwrap();
        assert!(last > 1, "the claim activity retries");
        for attempt in 1..last {
            assert!(
                predecessor_or_retry(failed(), attempt, "env").is_err(),
                "{attempt}"
            );
        }
        assert_eq!(predecessor_or_retry(failed(), last, "env").unwrap(), None);
    }

    #[test]
    fn only_a_predecessor_that_continued_as_new_hands_its_generation_on() {
        let run = || "run-a".to_owned();
        assert_eq!(
            continued_predecessor(run(), Some(WorkflowExecutionStatus::ContinuedAsNew as i32)),
            Some(run())
        );
        for status in [
            WorkflowExecutionStatus::Running,
            WorkflowExecutionStatus::Completed,
            WorkflowExecutionStatus::Failed,
            WorkflowExecutionStatus::Canceled,
            WorkflowExecutionStatus::Terminated,
            WorkflowExecutionStatus::TimedOut,
            WorkflowExecutionStatus::Unspecified,
        ] {
            assert_eq!(
                continued_predecessor(run(), Some(status as i32)),
                None,
                "{status:?}"
            );
        }
        assert_eq!(continued_predecessor(run(), None), None);
        assert_eq!(
            continued_predecessor(
                String::new(),
                Some(WorkflowExecutionStatus::ContinuedAsNew as i32)
            ),
            None
        );
    }
}
