//! A create's or a start's readiness wait ends at once, naming the hosts,
//! when its Pod's first bind was refused because the Pod's front door doesn't
//! serve every host the environment's selection needs (#6290), or because the
//! hosts of its selected bound secrets don't hold together (#4003). More
//! waiting can't change either, and the bind is never let through with
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

/// The Pod's first bind was refused for its selected bound secrets (#4003):
/// `end` carries the code, and the sentence names the hosts and the keys.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct BoundSecretsRefused {
    pub end: crate::lifecycle::FailedCreate,
    pub reason: String,
}

/// Runs `wait` until it completes or the environment's current Pod records a
/// first-bind refusal ([`FrontDoorHostsUnserved`] or [`BoundSecretsRefused`]).
async fn race_refusal<T>(
    ctx: &WorkerContext,
    placement: &Placement,
    env_id: &str,
    wait: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let runtime = ctx.require_runtime()?;
    race_refusal_with(wait, refused(runtime, &ctx.pool, placement, env_id)).await
}

async fn race_refusal_with<T>(
    wait: impl std::future::Future<Output = anyhow::Result<T>>,
    refusal: impl std::future::Future<Output = anyhow::Error>,
) -> anyhow::Result<T> {
    tokio::select! {
        result = wait => result,
        refusal = refusal => Err(refusal),
    }
}

/// The runtime's readiness wait for `env_id`, which create and start run,
/// ended early with [`FrontDoorHostsUnserved`] or [`BoundSecretsRefused`] once
/// the environment's current Pod has a recorded first-bind refusal.
pub(in crate::worker) async fn wait_ready(
    ctx: &WorkerContext,
    placement: &Placement,
    env_id: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let runtime = ctx.require_runtime()?;
    race_refusal(
        ctx,
        placement,
        env_id,
        runtime.wait_ready(placement, env_id, timeout),
    )
    .await
}

/// The runtime's access-proof wait for `env_id` (`access_ready` during create),
/// ended early with [`FrontDoorHostsUnserved`] or [`BoundSecretsRefused`] once
/// the environment's current Pod has a recorded first-bind refusal.
pub(in crate::worker) async fn prove_access(
    ctx: &WorkerContext,
    placement: &Placement,
    env_id: &str,
    timeout: Duration,
    host_keys: &dyn crate::sandbox::host_keys::HostKeyStore,
) -> anyhow::Result<String> {
    let runtime = ctx.require_runtime()?;
    race_refusal(
        ctx,
        placement,
        env_id,
        runtime.prove_access(placement, env_id, timeout, host_keys),
    )
    .await
}

/// The runtime's access-readiness wait for `env_id`, ended early with
/// [`FrontDoorHostsUnserved`] or [`BoundSecretsRefused`] once the environment's
/// current Pod has a recorded first-bind refusal.
pub(in crate::worker) async fn wait_access_ready(
    ctx: &WorkerContext,
    placement: &Placement,
    env_id: &str,
    timeout: Duration,
    host_keys: &dyn crate::sandbox::host_keys::HostKeyStore,
) -> anyhow::Result<()> {
    let runtime = ctx.require_runtime()?;
    race_refusal(
        ctx,
        placement,
        env_id,
        runtime.wait_access_ready(placement, env_id, timeout, host_keys),
    )
    .await
}

/// Ends once the Pod the environment's claim names now has a recorded
/// refusal, and never otherwise. A read that fails is tried again; only the
/// current Pod's own record counts, never an earlier Pod's.
async fn refused(
    runtime: &dyn crate::runtime::RuntimeDriver,
    pool: &PgPool,
    placement: &Placement,
    env_id: &str,
) -> anyhow::Error {
    loop {
        if let Ok(Some(pod)) = runtime.current_member(placement, env_id).await {
            if let Ok(Some(hosts)) = crate::egress::front_door_hosts::unserved(pool, &pod.uid).await
            {
                return FrontDoorHostsUnserved { hosts }.into();
            }
            if let Ok(Some(refusal)) =
                crate::egress::front_door_hosts::refusal(pool, &pod.uid).await
                && let Some(refused) = bound_secrets_refused_from(refusal)
            {
                return refused.into();
            }
        }
        tokio::time::sleep(UNSERVED_POLL).await;
    }
}

/// The refusal a Pod's row keeps, by its code; `None` for a code this
/// build doesn't know, which the wait then doesn't end for.
fn bound_secrets_refused_from(
    refusal: crate::egress::front_door_hosts::RecordedRefusal,
) -> Option<BoundSecretsRefused> {
    use crate::lifecycle::{
        BOUND_HOST_CONFLICT_ERROR_CODE, BOUND_HOST_RESERVED_ERROR_CODE, FailedCreate,
        TOO_MANY_BOUND_HOSTS_ERROR_CODE,
    };
    let end = match refusal.code.as_str() {
        BOUND_HOST_RESERVED_ERROR_CODE => FailedCreate::BoundHostReserved,
        BOUND_HOST_CONFLICT_ERROR_CODE => FailedCreate::BoundHostConflict,
        TOO_MANY_BOUND_HOSTS_ERROR_CODE => FailedCreate::TooManyBoundHosts,
        _ => return None,
    };
    Some(BoundSecretsRefused {
        end,
        reason: refusal.reason,
    })
}

/// The bound-secret refusal, when a readiness wait ended for it.
pub(in crate::worker) fn bound_secrets_refused(
    error: &anyhow::Error,
) -> Option<&BoundSecretsRefused> {
    error.downcast_ref::<BoundSecretsRefused>().or_else(|| {
        error
            .downcast_ref::<ReadinessWaitFailed>()
            .and_then(|failed| failed.0.downcast_ref::<BoundSecretsRefused>())
    })
}

/// End a create whose Pod's first bind was refused for its bound secrets, as
/// [`fail_create_for_front_door_hosts`] ends one for its front door.
pub(in crate::worker) async fn fail_create_for_bound_secrets(
    ctx: &WorkerContext,
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    refusal: &BoundSecretsRefused,
) -> anyhow::Result<()> {
    authority.ensure().await?;
    if !svc
        .fail_create_for_bound_secrets(env_id, refusal.end, &refusal.reason, CREATE_MUTATION_STATES)
        .await?
    {
        return Ok(());
    }
    tracing::warn!(
        environment_id = env_id,
        reason = refusal.end.code(),
        "create ended: the Pod's selected bound secrets were refused at its first bind"
    );
    ctx.temporal_trigger
        .trigger_environment(env_id, "reconcile")
        .await
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

    /// A Pod's kept bound-secret refusal ends the wait with its code and its
    /// sentence; a code this build doesn't know doesn't end it.
    #[test]
    fn a_kept_bound_secret_refusal_ends_the_wait_with_its_code() {
        use crate::egress::front_door_hosts::RecordedRefusal;
        use crate::lifecycle::FailedCreate;
        for (code, end) in [
            ("bound_host_reserved", FailedCreate::BoundHostReserved),
            ("bound_host_conflict", FailedCreate::BoundHostConflict),
            ("too_many_bound_hosts", FailedCreate::TooManyBoundHosts),
        ] {
            let refused = bound_secrets_refused_from(RecordedRefusal {
                code: code.into(),
                reason: "a sentence naming hosts and keys".into(),
            })
            .unwrap();
            assert_eq!(refused.end, end);
            assert_eq!(refused.end.code(), code);
            assert_eq!(refused.to_string(), "a sentence naming hosts and keys");
            let wrapped: anyhow::Error = ReadinessWaitFailed(refused.clone().into()).into();
            assert_eq!(bound_secrets_refused(&wrapped), Some(&refused));
        }
        assert_eq!(
            bound_secrets_refused_from(RecordedRefusal {
                code: "front_door_hosts_unserved".into(),
                reason: "a sentence".into(),
            }),
            None
        );
        assert_eq!(bound_secrets_refused(&anyhow::anyhow!("timeout")), None);
    }

    #[tokio::test]
    async fn a_recorded_refusal_ends_a_pending_access_wait_immediately() {
        let unserved = FrontDoorHostsUnserved {
            hosts: vec!["api.example.com".into()],
        };
        let err = race_refusal_with(
            std::future::pending::<anyhow::Result<String>>(),
            std::future::ready(unserved.clone().into()),
        )
        .await
        .unwrap_err();
        assert_eq!(front_door_hosts_unserved(&err), Some(&unserved));

        let bound = BoundSecretsRefused {
            end: crate::lifecycle::FailedCreate::BoundHostConflict,
            reason: "conflict".into(),
        };
        let err = race_refusal_with(
            std::future::pending::<anyhow::Result<String>>(),
            std::future::ready(bound.clone().into()),
        )
        .await
        .unwrap_err();
        assert_eq!(bound_secrets_refused(&err), Some(&bound));

        let ok = race_refusal_with(
            std::future::ready(Ok::<_, anyhow::Error>("pod-uid".to_owned())),
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(ok, "pod-uid");
    }
}
