//! Completing a destroy once its external resources are proven gone (moved
//! from `mod.rs`, which is past the file-size limit).

use super::*;

impl PgLifecycleStore {
    pub(super) async fn complete_external_cleanup_now(
        &self,
        env_id: &str,
        already_destroyed: bool,
        proof: RuntimeAbsenceProof,
    ) -> anyhow::Result<()> {
        let (phase, message, metadata) = if already_destroyed {
            (
                "lifecycle_checkpoint",
                "historical destroyed environment external cleanup verified",
                serde_json::json!({ "kind": "external_cleanup_complete" }),
            )
        } else {
            (
                "lifecycle_transition",
                "external cleanup verified and environment destroyed",
                serde_json::json!({
                    "kind": "external_cleanup_complete",
                    "from": "destroying",
                    "to": "destroyed",
                }),
            )
        };
        let mut tx = self.pool.begin().await?;
        let organization_id: Option<String> =
            sqlx::query_scalar("SELECT org_id FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(&mut *tx)
                .await?;
        let organization_id = organization_id
            .ok_or_else(|| anyhow::anyhow!("environment external cleanup target not found"))?;
        let organization_locked: Option<String> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(&organization_id)
                .fetch_optional(&mut *tx)
                .await?;
        if organization_locked.is_none() {
            return Err(anyhow::anyhow!(
                "environment external cleanup organization not found"
            ));
        }
        if let Some(authority) = &self.authority {
            authority.lock_transaction(&mut tx).await?;
        }
        // The organization row lock above orders this statement after every
        // committed runtime admission; a later admission sees the marker and
        // releases itself. Only dispatches that may target this environment
        // (its own, and organization-wide ones such as creation or leases
        // admitted before leases recorded their environment) can block it:
        // - an active one may still be acting;
        // - an ambiguous one that settled after `proof` began may have acted
        //   while the proof ran, so the next attempt must prove absence again.
        // This environment's ambiguous dispatches that settled before `proof`
        // began are resolved here, in the same statement as the marker: the
        // proof covers every runtime effect they could have left. An
        // organization-wide one may concern another environment, so it stays
        // for organization deletion to resolve after every environment's
        // proof. A live workspace binding also blocks the marker: destroy
        // releases it once its Pod is observed absent (design §10).
        let tag = sqlx::query(
            r#"WITH target AS (
                       SELECT id, org_id
                       FROM environments
                       WHERE id = $1
                         AND desired_state = 'destroyed'
                         AND state = CASE WHEN $2 THEN 'destroyed' ELSE 'destroying' END
                         AND external_cleanup_completed_at IS NULL
                         AND NOT EXISTS (
                             SELECT 1
                             FROM organization_mutation_leases lease
                             WHERE lease.organization_id = environments.org_id
                               AND lease.mutation_class = 'environment_runtime_dispatch'
                               AND (lease.environment_id = environments.id
                                    OR lease.environment_id IS NULL)
                               AND (lease.state = 'active'
                                    OR (lease.state = 'resolution_required'
                                        AND lease.resolution_required_at >= $3))
                         )
                         AND NOT EXISTS (
                             SELECT 1
                             FROM environment_ports port
                             WHERE port.environment_id = environments.id
                         )
                         AND NOT EXISTS (
                             SELECT 1
                             FROM sandbox_workspace_bindings binding
                             WHERE binding.environment_id = environments.id
                               AND binding.released_at IS NULL
                         )
                       FOR UPDATE
                   ), resolved_dispatches AS (
                       UPDATE organization_mutation_leases lease
                       SET state = 'resolved', resolved_at = NOW(), updated_at = NOW()
                       FROM target
                       WHERE lease.organization_id = target.org_id
                         AND lease.mutation_class = 'environment_runtime_dispatch'
                         AND lease.environment_id = target.id
                         AND lease.state = 'resolution_required'
                         AND lease.resolution_required_at < $3
                       RETURNING lease.id
                   ), closed_sessions AS (
                       UPDATE sandbox_running_sessions session
                       SET ended_at = COALESCE(session.ended_at, session.last_observed_at), -- not NOW(): #5675
                           end_reason = COALESCE(session.end_reason, 'environment_destroyed'),
                           updated_at = CASE
                               WHEN session.ended_at IS NULL THEN NOW()
                               ELSE session.updated_at
                           END
                       FROM target
                       WHERE session.environment_id = target.id
                         AND session.ended_at IS NULL
                       RETURNING session.id
                   ), removed_backend AS (
                       DELETE FROM sandbox_environment_backend backend
                       USING target
                       WHERE backend.environment_id = target.id
                       RETURNING backend.environment_id
                   ), removed_access_binding AS (
                       DELETE FROM platform_environment_access_bindings binding
                       USING target
                       WHERE binding.environment_id = target.id
                       RETURNING binding.environment_id
                   ), removed_network_policy AS (
                       -- A destroyed environment no longer holds its policy (#4000).
                       DELETE FROM platform_environment_network_policies selection
                       USING target
                       WHERE selection.environment_id = target.id
                       RETURNING selection.environment_id
                   ), removed_placeholder_key AS (
                       -- A destroyed environment's placeholder key serves
                       -- nothing, so it goes with the destroy (#4001).
                       DELETE FROM platform_placeholder_keys placeholder_key
                       USING target
                       WHERE placeholder_key.environment_id = target.id
                       RETURNING placeholder_key.environment_id
                   )
                   UPDATE environments env
                   SET state = 'destroyed',
                       state_changed_at = CASE
                           WHEN env.state = 'destroying' THEN NOW()
                           ELSE env.state_changed_at
                       END,
                       destroyed_at = COALESCE(env.destroyed_at, NOW()),
                       external_cleanup_completed_at = NOW()
                   FROM target
                   WHERE env.id = target.id"#,
        )
        .bind(env_id)
        .bind(already_destroyed)
        .bind(proof.started_at)
        .execute(&mut *tx)
        .await?;
        if tag.rows_affected() == 1 {
            Self::append_log_and_journal(
                &mut tx,
                env_id,
                LogEntry {
                    phase,
                    status: "completed",
                    message: message.into(),
                    metadata,
                },
            )
            .await?;
        }
        tx.commit().await?;
        if tag.rows_affected() == 1 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "external cleanup preconditions are not satisfied"
            ))
        }
    }
}
