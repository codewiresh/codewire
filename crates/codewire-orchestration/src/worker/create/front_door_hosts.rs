//! A create's or a start's readiness wait ends at once, naming the hosts,
//! when its Pod's first bind was refused because the Pod's front door doesn't
//! serve every host the environment's selection needs (#6290). More waiting
//! can't make that door serve them, and the bind is never let through with
//! interception quietly off.

use super::*;

/// How often the wait reads whether the current Pod's first bind was refused.
const UNSERVED_POLL: Duration = Duration::from_secs(2);

/// The Pod's first bind was refused: its front door has no route for these
/// hosts of the creator's own selection. They are fixed public provider names
/// the creator chose; nothing else of the front door is said.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "this Sandbox's credential front door does not serve {}, which its credentials need",
    .hosts.join(", ")
)]
pub struct FrontDoorHostsUnserved {
    pub hosts: Vec<String>,
}

/// The runtime's readiness wait for `env_id`, which create and start run,
/// ended early with [`FrontDoorHostsUnserved`] once the environment's current
/// Pod has a recorded first-bind refusal.
pub(in crate::worker) async fn wait_ready(
    ctx: &WorkerContext,
    placement: &Placement,
    env_id: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let runtime = ctx.require_runtime()?;
    tokio::select! {
        result = runtime.wait_ready(placement, env_id, timeout) => result,
        refusal = refused(runtime, &ctx.pool, placement, env_id) => Err(refusal.into()),
    }
}

/// Ends once the Pod the environment's claim names now has a recorded
/// refusal, and never otherwise. A read that fails is tried again; only the
/// current Pod's own record counts, never an earlier Pod's.
async fn refused(
    runtime: &dyn crate::runtime::RuntimeDriver,
    pool: &PgPool,
    placement: &Placement,
    env_id: &str,
) -> FrontDoorHostsUnserved {
    loop {
        if let Ok(Some(pod)) = runtime.current_member(placement, env_id).await
            && let Ok(Some(hosts)) = crate::egress::front_door_hosts::unserved(pool, &pod.uid).await
        {
            return FrontDoorHostsUnserved { hosts };
        }
        tokio::time::sleep(UNSERVED_POLL).await;
    }
}

/// The refusal, when a readiness wait ended for it.
pub(in crate::worker) fn front_door_hosts_unserved(
    error: &anyhow::Error,
) -> Option<&FrontDoorHostsUnserved> {
    error.downcast_ref::<FrontDoorHostsUnserved>().or_else(|| {
        error
            .downcast_ref::<ReadinessWaitFailed>()
            .and_then(|failed| failed.0.downcast_ref::<FrontDoorHostsUnserved>())
    })
}

/// End a create whose Pod's front door can't serve its selection, in place of
/// an error that would retry into the same refusal: this activity finishes,
/// and the reconcile it queues does the normal destroy.
pub(in crate::worker) async fn fail_create_for_front_door_hosts(
    ctx: &WorkerContext,
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    refusal: &FrontDoorHostsUnserved,
) -> anyhow::Result<()> {
    authority.ensure().await?;
    if !svc
        .fail_create_for_front_door_hosts(env_id, &refusal.to_string(), CREATE_MUTATION_STATES)
        .await?
    {
        return Ok(());
    }
    tracing::warn!(
        environment_id = env_id,
        missing = ?refusal.hosts,
        reason = "front_door_hosts_unserved",
        "create ended: the Pod's front door does not serve every host its selection needs"
    );
    ctx.temporal_trigger
        .trigger_environment(env_id, "reconcile")
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_names_only_the_missing_hosts() {
        let refusal = FrontDoorHostsUnserved {
            hosts: vec!["api.github.com".into(), "github.com".into()],
        };
        assert_eq!(
            refusal.to_string(),
            "this Sandbox's credential front door does not serve api.github.com, github.com, \
             which its credentials need"
        );
        let wrapped: anyhow::Error = ReadinessWaitFailed(refusal.clone().into()).into();
        assert_eq!(front_door_hosts_unserved(&wrapped), Some(&refusal));
        assert_eq!(front_door_hosts_unserved(&anyhow::anyhow!("timeout")), None);
    }
}
