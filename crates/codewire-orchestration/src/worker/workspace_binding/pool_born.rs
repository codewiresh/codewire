//! The first bind of a pool-born Sandbox (Program #2238 C3): the Claim names
//! this environment's own pool, the Sandbox's spec is exactly that pool's
//! rendering, and the Pod booted from that pool revision, read from its
//! immutable spec (review M1), so a stale, foreign or altered member never
//! binds. The member is judged in its own egress mode, read from its Sandbox
//! object, never the switch (#6070): the broker additions (the TUN init and
//! its volume, and the egress token) are admitted only on a whole broker
//! member of a pool whose template at that revision was broker. A broker
//! member claimed before the switch went off and bound after it is judged by
//! its own pool revision and binds. With the switch on a create ends up
//! broker, so a direct member is refused and deleted, and the create claimed
//! again cold, as is a broker member without the broker settings: neither has
//! ever served, so the cold claim is a new create, which the switch decides.

use super::checks::pool_member_isolated;
use super::{DENIED_POOL_RENDERING, SandboxWorkerCfg};
use crate::egress::own_mode::SandboxMode;
use crate::runtime::kubernetes::rendering::KubernetesRenderConfig;
use crate::runtime::{MemberFacts, Placement, RuntimeDriver, RuntimeObservation, WantedPool};
use crate::worker::env_data::EnvironmentRow;

/// The expected pool of a pool-born environment (Program #2238 C3): the
/// identity-free pool of its exact shape on this replica, whose template
/// carries the pool revision marker, and the options it renders from, which
/// the member's isolation is checked against, in `member`'s own egress mode.
/// Routing sends an environment to a pool only when its own rendering equals
/// this one's, less the marker.
pub(super) fn pool_born_rendering(
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    member: &SandboxMode,
) -> anyhow::Result<(WantedPool, crate::sandbox::template::TemplateOpts)> {
    anyhow::ensure!(
        env.isolation_tier == "standard",
        "only standard environments are pool-born"
    );
    let shape = crate::sandbox::warm_pool::WorkspaceShape {
        cpu_millicores: i64::from(env.cpu_millicores),
        memory_mib: i64::from(env.memory_mb),
        disk_gib: i64::from(env.disk_gb),
    };
    let config = KubernetesRenderConfig::from(cfg);
    // With the switch on, a pool a create claims from is broker.
    anyhow::ensure!(
        member.broker || config.pool(shape)?.hosted_egress.is_none(),
        "a member that is not whole broker never binds while hosted egress is on"
    );
    let rendering = config.pool_of(shape, member)?;
    Ok((
        WantedPool {
            configured: crate::sandbox::warm_pool::ConfiguredShape { shape, members: 0 },
            allow_unpinned_images: cfg.allow_diagnostic_runtime,
        },
        rendering,
    ))
}

/// Whether a never-bound pool-born member was born of this environment's
/// pool. `Err` is the refusal's reason and whether it is definitive about the
/// member. Without the configuration to render the pool, it is refused
/// without deleting. The driver renders the pool, so only it can say whether
/// this runtime was born of it; the decision stays here. The member's own
/// isolation is checked here too, over its Pod spec, whatever the driver says
/// (#3628 PR 5c, cw-confidential's condition 3).
pub(super) async fn born_of_its_pool(
    runtime: &dyn RuntimeDriver,
    cfg: Option<&SandboxWorkerCfg>,
    env: &EnvironmentRow,
    placement: &Placement,
    observation: &RuntimeObservation,
    member: &MemberFacts,
) -> Result<(), (&'static str, bool)> {
    let Some(cfg) = cfg else {
        return Err(("pool rendering unverified", false));
    };
    let sandbox = SandboxMode::of(
        observation.runtime.name.as_deref().unwrap_or_default(),
        &observation.runtime.json,
    );
    let matched = match pool_born_rendering(cfg, env, &sandbox) {
        Ok((wanted, rendering)) => match pool_member_isolated(&member.spec_json, &rendering) {
            Ok(()) => runtime.pool_birth(placement, &wanted, observation).await,
            Err(path) => Err(format!("isolation {path}")),
        },
        Err(error) => Err(format!("{error:#}")),
    };
    matched.map_err(|path| {
        tracing::warn!(env = %env.id, %path, "pool-born Sandbox differs from the expected rendering");
        (DENIED_POOL_RENDERING, true)
    })
}
