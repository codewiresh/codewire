//! The warm-member bridge (Program #2238 C6, #2434).
//!
//! A claim relabels its adopted warm-pool member with the environment ID, and
//! Cilium drops the gateway's traffic until the relabelled Pod has a new
//! security identity, which took 5–20 s on Dev. Once the warm binding is
//! committed, two bridge policies select the member by the Sandbox UID its
//! binding recorded (`agents.x-k8s.io/sandbox-uid`, stamped by the fork at the
//! Pod's birth) and admit exactly what the environment's own policies admit.
//!
//! The bridge is applied only here, only for a binding this activity just
//! recorded on the warm path, and only inside the generation fence while that
//! binding is the environment's live one, so an unbound member is never
//! selected and a cold create never gets one. Stop, destroy and a cold
//! re-claim remove it with the gateway stack.

use super::{ActivityAuthority, EnvironmentRow, WorkerContext, await_external_mutation};
use crate::sandbox::client::SandboxClient;
use crate::start_metrics::StartPath;
use crate::worker::activity_authority::{AuthorityLost, is_authority_lost};
use crate::worker::workspace_binding::{RecordedBind, live_binding_sandbox};

/// The namespace and Sandbox UID to bridge: present only when `recorded` is a
/// warm bind and the environment's live binding, read inside the fence, names
/// that same Sandbox. A cold bind, no live binding, or a live binding of
/// another Sandbox bridges nothing.
pub(super) fn warm_bridge_target(
    recorded: &RecordedBind,
    live: Option<(String, String)>,
) -> Option<(String, String)> {
    if recorded.path != StartPath::Warm || recorded.sandbox_uid.is_empty() {
        return None;
    }
    live.filter(|(namespace, sandbox_uid)| {
        !namespace.is_empty() && *sandbox_uid == recorded.sandbox_uid
    })
}

/// Apply the bridge for `recorded`, a binding this activity just recorded.
///
/// The bridge only shortens the wait for the relabelled member's identity,
/// so a Kubernetes or database failure is logged and the environment's own
/// policies keep admitting the gateway once Cilium converges. Losing
/// authority still fails the caller.
pub(super) async fn bridge_warm_member(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    authority: &ActivityAuthority,
    states: &[&str],
    recorded: &RecordedBind,
) -> anyhow::Result<()> {
    if recorded.path != StartPath::Warm {
        return Ok(());
    }
    let Some(kube) = ctx.kube.as_ref() else {
        return Ok(());
    };
    let result = async {
        anyhow::ensure!(env.id == authority.environment_id(), AuthorityLost);
        let opts =
            super::load_environment_template_opts(ctx, env, authority.operation_generation())
                .await?;
        let mut guard = authority.begin_external_mutation(states).await?;
        let bridged = await_external_mutation(async {
            let live = live_binding_sandbox(&mut **guard.transaction(), &env.id).await?;
            let Some((namespace, sandbox_uid)) = warm_bridge_target(recorded, live) else {
                return Ok(false);
            };
            SandboxClient::new(kube.clone(), &namespace)
                .ensure_warm_member_bridge(&opts, &sandbox_uid)
                .await?;
            Ok(true)
        })
        .await?;
        guard.commit().await?;
        Ok(bridged)
    }
    .await;
    match result {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(env = %env.id, "warm member bridge: the recorded warm binding is not live; nothing bridged");
            Ok(())
        }
        Err(error) if is_authority_lost(&error) => Err(error),
        Err(error) => {
            tracing::warn!(
                env = %env.id,
                error = %format!("{error:#}"),
                "warm member bridge: not applied; the environment policies admit the gateway once the relabel converges"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const NAMESPACE: &str = "dev-sandboxes";
    const SANDBOX: &str = "0b6f4a52-5d1e-4c2a-9a4e-3f1d2c7b8e90";
    const OTHER_SANDBOX: &str = "7c3e9d10-2b4a-4f6e-8d1c-5a9b0e2f4c61";

    fn recorded(path: StartPath, sandbox_uid: &str) -> RecordedBind {
        RecordedBind {
            elapsed: Duration::from_millis(80),
            path,
            sandbox_uid: sandbox_uid.into(),
        }
    }

    fn live(namespace: &str, sandbox_uid: &str) -> Option<(String, String)> {
        Some((namespace.into(), sandbox_uid.into()))
    }

    /// No bridge without a recorded warm binding that is still the live one.
    #[test]
    fn only_a_live_recorded_warm_binding_is_bridged() {
        assert_eq!(
            warm_bridge_target(
                &recorded(StartPath::Warm, SANDBOX),
                live(NAMESPACE, SANDBOX)
            ),
            live(NAMESPACE, SANDBOX)
        );
        // A cold create, or a restart of a Sandbox some binding already
        // recorded, never bridges, even with a matching live binding.
        assert_eq!(
            warm_bridge_target(
                &recorded(StartPath::Cold, SANDBOX),
                live(NAMESPACE, SANDBOX)
            ),
            None
        );
        // No committed binding (not yet written, rolled back or released).
        assert_eq!(
            warm_bridge_target(&recorded(StartPath::Warm, SANDBOX), None),
            None
        );
        // The live binding names another Sandbox: a replacement bound since.
        assert_eq!(
            warm_bridge_target(
                &recorded(StartPath::Warm, SANDBOX),
                live(NAMESPACE, OTHER_SANDBOX)
            ),
            None
        );
        // Nothing recorded, or no namespace to bridge in.
        assert_eq!(
            warm_bridge_target(&recorded(StartPath::Warm, ""), live(NAMESPACE, "")),
            None
        );
        assert_eq!(
            warm_bridge_target(&recorded(StartPath::Warm, SANDBOX), live("", SANDBOX)),
            None
        );
    }
}
