//! Hosted disk snapshots' workflows (#3046 H1): a capture (raw, clear, keep,
//! or the abandonment that deletes what it made) and a deletion. They stand
//! apart from the rest of the module so that file, past the size at which a
//! file stops growing, loses a concern instead of gaining lines.

use super::*;

/// One hosted snapshot's workflow input. The row holds everything else.
///
/// `trace_context` is the starter's W3C trace context, as in
/// [`EnvironmentCommand::trace_context`]. A worker accepts it before any
/// starter sends it, because a worker from the release before refuses an
/// unknown field; until then it is empty and absent from the payload
/// (docs/CONFIGURATION.md, "Tracing").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCommand {
    pub snapshot_id: String,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

/// What [`SnapshotActivities::abandon`] records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAbandonment {
    pub snapshot_id: String,
    pub failure_code: String,
    #[serde(default, skip_serializing_if = "TraceContext::is_empty")]
    pub trace_context: TraceContext,
}

pub fn snapshot_capture_workflow_id(snapshot_id: &str) -> String {
    format!("snapshot/capture/{snapshot_id}")
}

pub fn snapshot_delete_workflow_id(snapshot_id: &str) -> String {
    format!("snapshot/delete/{snapshot_id}")
}

/// The span a snapshot activity runs in: a child of the trace that started its
/// workflow, when the input carries one. It records the snapshot id and
/// attempt only.
fn snapshot_activity_span(
    activity: &'static str,
    snapshot_id: &str,
    trace_context: &TraceContext,
    ctx: &ActivityContext,
) -> tracing::Span {
    let span = tracing::debug_span!(
        "temporal.activity",
        otel.name = activity,
        otel.kind = "consumer",
        snapshot_id = %snapshot_id,
        temporal.attempt = ctx.info().attempt,
    );
    trace_context.attach_to(&span);
    span
}

/// Hosted disk snapshot activities (#3046 H1); the bodies are
/// [`crate::worker::snapshots`]. Each returns a failure code when the capture
/// can't go on, which no retry would change.
pub struct SnapshotActivities {
    pub wctx: Arc<WorkerContext>,
}

#[activities]
impl SnapshotActivities {
    #[activity(name = "SnapshotCaptureRawActivity")]
    pub async fn capture_raw(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: SnapshotCommand,
    ) -> Result<Option<String>, ActivityError> {
        let span = snapshot_activity_span(
            "SnapshotCaptureRawActivity",
            &cmd.snapshot_id,
            &cmd.trace_context,
            &ctx,
        );
        run_environment_activity(
            ctx,
            crate::worker::snapshots::capture_raw(&self.wctx, &cmd.snapshot_id),
        )
        .instrument(span)
        .await
    }

    #[activity(name = "SnapshotClearActivity")]
    pub async fn clear(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: SnapshotCommand,
    ) -> Result<Option<String>, ActivityError> {
        let span = snapshot_activity_span(
            "SnapshotClearActivity",
            &cmd.snapshot_id,
            &cmd.trace_context,
            &ctx,
        );
        run_environment_activity(
            ctx,
            crate::worker::snapshots::run_clearing(&self.wctx, &cmd.snapshot_id),
        )
        .instrument(span)
        .await
    }

    #[activity(name = "SnapshotKeepActivity")]
    pub async fn keep(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: SnapshotCommand,
    ) -> Result<(), ActivityError> {
        let span = snapshot_activity_span(
            "SnapshotKeepActivity",
            &cmd.snapshot_id,
            &cmd.trace_context,
            &ctx,
        );
        run_environment_activity(
            ctx,
            crate::worker::snapshots::keep_and_finish(&self.wctx, &cmd.snapshot_id),
        )
        .instrument(span)
        .await
    }

    #[activity(name = "SnapshotAbandonActivity")]
    pub async fn abandon(
        self: Arc<Self>,
        ctx: ActivityContext,
        input: SnapshotAbandonment,
    ) -> Result<(), ActivityError> {
        let span = snapshot_activity_span(
            "SnapshotAbandonActivity",
            &input.snapshot_id,
            &input.trace_context,
            &ctx,
        );
        run_environment_activity(
            ctx,
            crate::worker::snapshots::abandon_capture(
                &self.wctx,
                &input.snapshot_id,
                &input.failure_code,
            ),
        )
        .instrument(span)
        .await
    }

    #[activity(name = "SnapshotDeleteActivity")]
    pub async fn delete(
        self: Arc<Self>,
        ctx: ActivityContext,
        cmd: SnapshotCommand,
    ) -> Result<(), ActivityError> {
        let span = snapshot_activity_span(
            "SnapshotDeleteActivity",
            &cmd.snapshot_id,
            &cmd.trace_context,
            &ctx,
        );
        run_environment_activity(
            ctx,
            crate::worker::snapshots::delete_snapshot(&self.wctx, &cmd.snapshot_id),
        )
        .instrument(span)
        .await
    }
}

/// Retries until it succeeds: the raw snapshot holds sign-ins whole, so nothing
/// may give up on deleting it.
fn snapshot_cleanup_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .heartbeat_timeout(Duration::from_secs(15))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(RetryPolicy {
            initial_interval: Duration::from_secs(2).try_into().ok(),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(60).try_into().ok(),
            maximum_attempts: 0,
            ..Default::default()
        })
        .build()
}

/// One hosted snapshot's capture: raw, clear, keep. Any failure, retries
/// exhausted included, ends in the abandonment that deletes what it made.
#[workflow]
#[derive(Default)]
pub struct SnapshotCaptureWorkflow {}

#[workflow_methods]
impl SnapshotCaptureWorkflow {
    #[run(name = "SnapshotCaptureWorkflow")]
    pub async fn run(ctx: &mut WorkflowContext<Self>, cmd: SnapshotCommand) -> WorkflowResult<()> {
        let raw = ctx
            .execute_activity(
                SnapshotActivities::capture_raw,
                cmd.clone(),
                environment_activity_opts(),
            )
            .await;
        let failure = match raw {
            Ok(Some(code)) => Some(code),
            Err(_) => Some(crate::worker::snapshots::FAILURE_CAPTURE.to_owned()),
            Ok(None) => {
                let cleared = ctx
                    .execute_activity(
                        SnapshotActivities::clear,
                        cmd.clone(),
                        environment_activity_opts(),
                    )
                    .await;
                match cleared {
                    Ok(Some(code)) => Some(code),
                    Err(_) => Some(crate::worker::snapshots::FAILURE_CAPTURE.to_owned()),
                    Ok(None) => ctx
                        .execute_activity(
                            SnapshotActivities::keep,
                            cmd.clone(),
                            environment_activity_opts(),
                        )
                        .await
                        .err()
                        .map(|_| crate::worker::snapshots::FAILURE_CAPTURE.to_owned()),
                }
            }
        };
        if let Some(failure_code) = failure {
            ctx.execute_activity(
                SnapshotActivities::abandon,
                SnapshotAbandonment {
                    snapshot_id: cmd.snapshot_id,
                    failure_code,
                    trace_context: cmd.trace_context,
                },
                snapshot_cleanup_activity_opts(),
            )
            .await?;
        }
        Ok(())
    }
}

/// One hosted snapshot's deletion: its objects, then its row.
#[workflow]
#[derive(Default)]
pub struct SnapshotDeleteWorkflow {}

#[workflow_methods]
impl SnapshotDeleteWorkflow {
    #[run(name = "SnapshotDeleteWorkflow")]
    pub async fn run(ctx: &mut WorkflowContext<Self>, cmd: SnapshotCommand) -> WorkflowResult<()> {
        ctx.execute_activity(
            SnapshotActivities::delete,
            cmd,
            snapshot_cleanup_activity_opts(),
        )
        .await?;
        Ok(())
    }
}

impl TemporalTrigger {
    /// Start a snapshot's capture workflow. `UseExisting` makes a restart of a
    /// running capture change nothing.
    #[tracing::instrument(
        level = "debug",
        name = "temporal.start_workflow",
        skip_all,
        fields(
            snapshot_id = %snapshot_id,
            otel.kind = "producer",
            otel.name = "StartWorkflow:SnapshotCaptureWorkflow",
        )
    )]
    pub async fn trigger_snapshot_capture(&self, snapshot_id: &str) -> anyhow::Result<()> {
        use temporalio_client::WorkflowIdConflictPolicy;
        use temporalio_client::WorkflowStartOptions;
        let options = WorkflowStartOptions::new(
            self.task_queue.as_str(),
            snapshot_capture_workflow_id(snapshot_id),
        )
        .id_conflict_policy(WorkflowIdConflictPolicy::UseExisting)
        .build();
        // No trace context yet: see `SnapshotCommand::trace_context`.
        let input = SnapshotCommand {
            snapshot_id: snapshot_id.to_owned(),
            trace_context: TraceContext::default(),
        };
        let client = self.client.clone();
        codewire_server_core::span_free::detached(async move {
            client
                .start_workflow(SnapshotCaptureWorkflow::run, input, options)
                .await
                .map(|_| ())
        })
        .await
        .map_err(|error| anyhow::anyhow!("start snapshot capture workflow: {error}"))
    }

    /// Start a snapshot's delete workflow, as above.
    #[tracing::instrument(
        level = "debug",
        name = "temporal.start_workflow",
        skip_all,
        fields(
            snapshot_id = %snapshot_id,
            otel.kind = "producer",
            otel.name = "StartWorkflow:SnapshotDeleteWorkflow",
        )
    )]
    pub async fn trigger_snapshot_delete(&self, snapshot_id: &str) -> anyhow::Result<()> {
        use temporalio_client::WorkflowIdConflictPolicy;
        use temporalio_client::WorkflowStartOptions;
        let options = WorkflowStartOptions::new(
            self.task_queue.as_str(),
            snapshot_delete_workflow_id(snapshot_id),
        )
        .id_conflict_policy(WorkflowIdConflictPolicy::UseExisting)
        .build();
        // No trace context yet: see `SnapshotCommand::trace_context`.
        let input = SnapshotCommand {
            snapshot_id: snapshot_id.to_owned(),
            trace_context: TraceContext::default(),
        };
        let client = self.client.clone();
        codewire_server_core::span_free::detached(async move {
            client
                .start_workflow(SnapshotDeleteWorkflow::run, input, options)
                .await
                .map(|_| ())
        })
        .await
        .map_err(|error| anyhow::anyhow!("start snapshot delete workflow: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An input with no trace context is byte for byte what the release before
    /// sent, so a worker from either release reads it, and an input from the
    /// release before reads as untraced.
    #[test]
    fn an_untraced_snapshot_input_is_the_payload_the_release_before_read() {
        let command = SnapshotCommand {
            snapshot_id: "snap-1".into(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&command).unwrap(),
            r#"{"snapshot_id":"snap-1"}"#
        );
        let abandonment = SnapshotAbandonment {
            snapshot_id: "snap-1".into(),
            failure_code: "capture_failed".into(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&abandonment).unwrap(),
            r#"{"snapshot_id":"snap-1","failure_code":"capture_failed"}"#
        );
        let earlier: SnapshotCommand = serde_json::from_str(r#"{"snapshot_id":"snap-1"}"#).unwrap();
        assert!(earlier.trace_context.is_empty());
    }

    /// A worker reads a starter's trace context and still refuses any other
    /// field, in the input or in the context.
    #[test]
    fn a_traced_snapshot_input_carries_its_context_and_nothing_else() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let traced: SnapshotCommand = serde_json::from_str(&format!(
            r#"{{"snapshot_id":"snap-1","trace_context":{{"traceparent":"{traceparent}"}}}}"#
        ))
        .unwrap();
        assert_eq!(
            traced.trace_context.traceparent.as_deref(),
            Some(traceparent)
        );
        for refused in [
            r#"{"snapshot_id":"snap-1","trace_context":{"traceparent":"x","authority":"y"}}"#,
            r#"{"snapshot_id":"snap-1","requested_by":"u"}"#,
        ] {
            assert!(
                serde_json::from_str::<SnapshotCommand>(refused).is_err(),
                "{refused}"
            );
        }
    }
}
