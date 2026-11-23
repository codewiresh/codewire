//! The fencing smoke's cross-run scenario: a replacement run's claim waits
//! behind the old run's activity, and the old run writes nothing after it.

use super::*;

impl Driver {
    pub(super) async fn cross_run_serialization(&self) -> anyhow::Result<()> {
        let scenario = "cross-run";
        // The daemon binds only canonical environment UUIDs.
        let env_id = uuid::Uuid::new_v4().to_string();
        let queue = format!(
            "wif-cross-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let evidence = self.scenario_path(scenario, "evidence.jsonl");
        let release = self.scenario_path(scenario, "release");
        self.seed_environment(&env_id, None).await?;
        let worker = self.spawn_worker(&queue, &evidence, Some(&release), None)?;
        let old = self.start_create(&env_id, &queue).await?;
        let old_run = old.run_id().unwrap_or_default().to_string();
        let expected_claim_name = codewire_orchestration::sandbox::claim_name(&env_id);
        wait_evidence(&evidence, &env_id, "claim_row_lock_held", |event| {
            event["claim_name"].as_str() == Some(expected_claim_name.as_str())
                && event["claim_uid"]
                    .as_str()
                    .is_some_and(|uid| !uid.is_empty())
        })
        .await?;

        let update_pool = self.pool.clone();
        let update_env = env_id.clone();
        let desired_update = tokio::spawn(async move {
            sqlx::query(
                "UPDATE environments SET desired_state = 'destroyed'
                   WHERE id = $1 /* codewire_wif_intent_wait */",
            )
            .bind(update_env)
            .execute(&update_pool)
            .await
        });
        wait_lock_waiters(&self.pool, 1).await?;

        old.terminate(
            WorkflowTerminateOptions::builder()
                .reason("cross-run fencing replacement")
                .build(),
        )
        .await?;

        let replacement = self
            .temporal
            .start_workflow(
                EnvironmentWorkflow::run,
                EnvironmentCommand {
                    action: "destroy".into(),
                    environment_id: env_id.clone(),
                    requested_by: "temporal-fencing-smoke".into(),
                    ..Default::default()
                },
                WorkflowStartOptions::new(&queue, environment_workflow_id(&env_id)).build(),
            )
            .await?;
        let replacement_run = replacement.run_id().unwrap_or_default().to_string();
        anyhow::ensure!(
            replacement_run != old_run,
            "replacement reused the old run ID"
        );
        wait_evidence(&evidence, &env_id, "claim_attempt_started", |event| {
            event["workflow_run_id"].as_str() == Some(&replacement_run)
        })
        .await?;
        wait_lock_waiters(&self.pool, 2).await?;
        let generation_before_release: i64 = sqlx::query_scalar(
            "SELECT environment_operation_generation FROM environments WHERE id = $1",
        )
        .bind(&env_id)
        .fetch_one(&self.pool)
        .await?;
        anyhow::ensure!(generation_before_release == 1);
        anyhow::ensure!(
            claim_activity_pending(&replacement).await?,
            "replacement claim was not visibly pending behind the row lock"
        );

        std::fs::write(&release, b"release")?;
        desired_update.await??;
        tokio::time::timeout(
            Duration::from_secs(180),
            replacement.get_result(WorkflowGetResultOptions::default()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("replacement destroy timed out"))??;
        self.wait_environment_state(&env_id, "destroyed", Duration::from_secs(30))
            .await?;
        anyhow::ensure!(
            self.sandbox.get_sandbox_claim(&env_id).await?.is_none(),
            "replacement did not delete the old activity's live SandboxClaim"
        );
        // The old run was terminated, so the replacement takes its claim row
        // over and keeps generation one (#6103); the old activity is fenced
        // by the row's run id, which the snapshot below proves.
        let holder: Option<String> = sqlx::query_scalar(
            "SELECT c.workflow_run_id
               FROM environments e
               JOIN environment_operation_generation_claims c
                 ON c.environment_id = e.id AND c.generation = e.environment_operation_generation
              WHERE e.id = $1 AND e.environment_operation_generation = 1",
        )
        .bind(&env_id)
        .fetch_optional(&self.pool)
        .await?;
        anyhow::ensure!(
            holder.as_deref() == Some(replacement_run.as_str()),
            "replacement did not take over generation one: {holder:?}"
        );
        let before = mutation_snapshot(&self.pool, &env_id).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let after = mutation_snapshot(&self.pool, &env_id).await?;
        anyhow::ensure!(
            before == after,
            "stale generation wrote after replacement: {before:?} -> {after:?}"
        );
        worker.stop().await?;
        println!("temporal-fencing-smoke: cross-run serialization PASS");
        Ok(())
    }
}
