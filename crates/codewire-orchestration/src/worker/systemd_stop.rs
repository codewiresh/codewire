//! A systemd workspace's Pod comes up only while every check holds
//! (docs/dev/SYSTEMD-WORKSPACE.md, "Where it is checked"). The worker refuses
//! to render one that fails them. This stops a systemd workspace whose
//! bring-up is under way when a check fails, with `systemd_refused` as its
//! stop reason: a create or start the worker refused, or a Pod orchestration
//! did not ask for, which liveness marks `starting` when it first sees it. A
//! running systemd workspace is left running until its next bring-up.

use sqlx::PgPool;

use super::WorkerContext;
use crate::lifecycle::{PgLifecycleStore, Service, StopReason};
use crate::sandbox::runtime_images::RuntimeImages;
use crate::sandbox::systemd_workspace::{bring_up_refusal, existing_profile};

/// The systemd workspaces to stop: being brought up, and refused now on the
/// profile each renders on, by the deployment or, where that profile needs
/// it, by their organization's opt-in.
pub async fn refused_environment_ids(
    pool: &PgPool,
    images: &RuntimeImages,
    deployment_profile: &str,
) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String, String, String, Option<String>, bool)> = sqlx::query_as(
        r#"SELECT e.id, COALESCE(e.project_spec->>'image', ''), e.isolation_tier,
                  e.systemd_runtime_profile, o.systemd_environments_enabled
             FROM environments e
             JOIN organizations o ON o.id = e.org_id
            WHERE e.systemd_workspace
              AND e.desired_state = 'started'
              AND e.state IN ('pending', 'creating', 'starting')
            ORDER BY e.id"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, image, isolation_tier, recorded, opted_in)| {
            let profile = existing_profile(deployment_profile, recorded.as_deref());
            bring_up_refusal(images, image, isolation_tier, profile, *opted_in).is_some()
        })
        .map(|(id, ..)| id)
        .collect())
}

pub(super) async fn stop_refused_systemd_workspaces(ctx: &WorkerContext) {
    let ids = match refused_environment_ids(
        &ctx.pool,
        crate::sandbox::runtime_images::configured(),
        &ctx.sandbox_cfg.runtime_profile,
    )
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "reconciler: query refused systemd workspaces");
            return;
        }
    };
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    for id in ids {
        tracing::info!(
            environment_id = id,
            "reconciler: stopping a systemd workspace its bring-up checks refused"
        );
        if let Err(e) = svc.request_stop(&id, StopReason::SystemdRefused).await {
            tracing::error!(environment_id = id, error = %e, "reconciler: set desired_state=stopped for a refused systemd workspace");
            continue;
        }
        if let Err(e) =
            super::loops::enqueue_environment_reconcile(ctx, &id, false, "systemd refused").await
        {
            tracing::error!(environment_id = id, error = %e, "reconciler: failed to enqueue reconcile for a refused systemd workspace");
        }
    }
}
