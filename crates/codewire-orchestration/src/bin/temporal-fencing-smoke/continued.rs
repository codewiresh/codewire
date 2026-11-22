//! #5950's Kind proof: a credentialed running Sandbox whose workflow run
//! continues as new keeps its Pod, its binding and its generation.

use super::*;

impl Driver {
    /// #5950: a credentialed running Sandbox whose workflow run continues
    /// as new keeps its Pod, its binding and its generation. The
    /// continued run's first claim takes over its predecessor's, so the
    /// bootstrap check that follows finds the binding current and replaces
    /// nothing.
    pub(super) async fn continued_generation(&self) -> anyhow::Result<()> {
        let scenario = "continued-generation";
        let env_id = uuid::Uuid::new_v4().to_string();
        let queue = format!(
            "wif-continued-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let evidence = self.scenario_path(scenario, "evidence.jsonl");
        // Organization secrets alone make a credential selection, so the
        // binding captures a projection digest and the generation counts.
        self.seed_environment(
            &env_id,
            Some(json!({
                "schema_version": 1,
                "working_directory": "/workspace",
                "secrets": {"organization": true}
            })),
        )
        .await?;
        let worker = self.spawn_selected_worker(&queue, &evidence)?;
        let handle = self.start_create(&env_id, &queue).await?;
        self.wait_setup_complete(&env_id, &handle, &evidence)
            .await?;
        let pod = self
            .sandbox
            .get_workspace_pod_identity(&env_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{env_id} has no workspace Pod after setup"))?;
        self.assert_access_ready(&env_id, &pod.uid).await?;
        let before = self.continued_binding(&env_id).await?;
        anyhow::ensure!(
            before.digest_selected
                && before.pod_uid == pod.uid
                && before.binding == before.environment,
            "{env_id} is not a credentialed Sandbox bound at its generation: {before:?}"
        );

        // Ignored commands add history without work, until the run is
        // past its bound and, idle, continues as new.
        let first_run = handle.run_id().unwrap_or_default().to_string();
        let latest = self
            .temporal
            .get_workflow_handle::<EnvironmentWorkflowRun>(environment_workflow_id(&env_id));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        let continued_run = loop {
            let run = latest
                .describe(temporalio_client::WorkflowDescribeOptions::default())
                .await?
                .run_id()
                .to_string();
            if run != first_run {
                break run;
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "{env_id}'s run did not continue as new"
            );
            for _ in 0..50 {
                latest
                    .signal(
                        EnvironmentWorkflow::command,
                        EnvironmentCommand {
                            action: "kind-continuation-padding".into(),
                            environment_id: env_id.clone(),
                            requested_by: "temporal-fencing-smoke".into(),
                            ..Default::default()
                        },
                        WorkflowSignalOptions::default(),
                    )
                    .await?;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        // The continued run's first command, as the sweep sends it.
        latest
            .signal(
                EnvironmentWorkflow::command,
                EnvironmentCommand {
                    action: "reconcile".into(),
                    environment_id: env_id.clone(),
                    requested_by: "temporal-fencing-smoke".into(),
                    ..Default::default()
                },
                WorkflowSignalOptions::default(),
            )
            .await?;
        wait_evidence(&evidence, &env_id, "claim_attempt_started", |event| {
            event["workflow_run_id"] == continued_run.as_str()
        })
        .await?;
        wait_activity_completed(&latest, "EnvironmentReconcileActivity").await?;

        let after = self.continued_binding(&env_id).await?;
        let claims: Vec<(String, i64)> = sqlx::query_as(
            "SELECT workflow_run_id, generation FROM environment_operation_generation_claims
                  WHERE environment_id = $1",
        )
        .bind(&env_id)
        .fetch_all(&self.pool)
        .await?;
        let pod_after = self
            .sandbox
            .get_workspace_pod_identity(&env_id)
            .await?
            .map(|pod| pod.uid);
        anyhow::ensure!(
            claims == vec![(continued_run.clone(), before.environment)],
            "{env_id}'s continued run did not take over generation {}: {claims:?}",
            before.environment
        );
        anyhow::ensure!(
            after == before && pod_after.as_deref() == Some(pod.uid.as_str()),
            "{env_id} changed across the continuation: before {before:?}, after {after:?}, \
                 Pod {} then {pod_after:?}",
            pod.uid
        );
        self.destroy_and_wait(&env_id, &latest).await?;
        worker.stop().await?;
        println!("temporal-fencing-smoke: continued generation PASS");
        Ok(())
    }

    /// An environment's generation and its live binding's.
    async fn continued_binding(&self, env_id: &str) -> anyhow::Result<ContinuedBinding> {
        let row: (i64, i64, bool, String) = sqlx::query_as(
            "SELECT e.environment_operation_generation, w.operation_generation,
                        w.projection_selection_sha256 IS NOT NULL, w.pod_uid
                   FROM environments e
                   JOIN sandbox_workspace_bindings w
                     ON w.environment_id = e.id AND w.released_at IS NULL
                  WHERE e.id = $1",
        )
        .bind(env_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(ContinuedBinding {
            environment: row.0,
            binding: row.1,
            digest_selected: row.2,
            pod_uid: row.3,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ContinuedBinding {
    environment: i64,
    binding: i64,
    digest_selected: bool,
    pod_uid: String,
}

/// Waits until the latest run's history holds a completed `activity_name`.
async fn wait_activity_completed<W>(
    handle: &temporalio_client::WorkflowHandle<Client, W>,
    activity_name: &str,
) -> anyhow::Result<()>
where
    W: temporalio_common::HasWorkflowDefinition,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
    loop {
        let history = handle
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .into_events()
            .await?;
        let scheduled: Vec<i64> = history
            .iter()
            .filter_map(|event| match event.attributes.as_ref() {
                Some(Attributes::ActivityTaskScheduledEventAttributes(attributes))
                    if attributes
                        .activity_type
                        .as_ref()
                        .is_some_and(|kind| kind.name == activity_name) =>
                {
                    Some(event.event_id)
                }
                _ => None,
            })
            .collect();
        let completed = history.iter().any(|event| {
            matches!(
                event.attributes.as_ref(),
                Some(Attributes::ActivityTaskCompletedEventAttributes(done))
                    if scheduled.contains(&done.scheduled_event_id)
            )
        });
        if completed {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "{activity_name} did not complete within 240 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
