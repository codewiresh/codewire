//! What the driver reads of an environment's Sandbox before it writes to it:
//! the Sandbox's own egress mode, which every write to an existing
//! environment renders in (#6070, `egress::own_mode`), and whether it was
//! made before hosted egress (#4000).

use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};

use super::{KubernetesDriver, check_authorized};
use crate::egress::own_mode::SandboxMode;
use crate::egress::reapply::PolicyReapply;
use crate::runtime::{Placement, RenderingIntent};
use crate::sandbox::client::claim_bound_sandbox_name;
use crate::sandbox::template::TemplateOpts;
use crate::sandbox::{CRD_VERSION, SANDBOX_GROUP};

impl KubernetesDriver {
    fn sandboxes(&self, placement: &Placement) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
        Api::namespaced_with(
            self.client.clone(),
            &placement.namespace,
            &ApiResource::from_gvk_with_plural(&gvk, "sandboxes"),
        )
    }

    /// The egress mode of the Sandbox the environment's Claim is bound to,
    /// from the Sandbox object; `None` while there is none to read: no Claim,
    /// a Claim that names no Sandbox yet, as on a create before it binds, or
    /// a Sandbox that is gone.
    async fn bound_sandbox_mode(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<SandboxMode>> {
        let Some(claim) = self
            .sandbox_client(placement)
            .get_sandbox_claim(environment_id)
            .await?
        else {
            return Ok(None);
        };
        let Some(name) = claim_bound_sandbox_name(&claim) else {
            return Ok(None);
        };
        let sandbox = self
            .sandboxes(placement)
            .get_opt(name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {name}: {error}"))?;
        Ok(sandbox.map(|sandbox| SandboxMode::of(name, &sandbox.data)))
    }

    /// The options a write to an existing environment renders from: in its
    /// bound Sandbox's own egress mode, never the switch, so a broker
    /// Sandbox keeps its broker rules and a direct one its direct rules
    /// (#6070). With no Sandbox bound yet it is a create, and renders as one.
    pub(super) async fn render_existing(
        &self,
        placement: &Placement,
        intent: &RenderingIntent,
    ) -> anyhow::Result<TemplateOpts> {
        let sandbox = self
            .bound_sandbox_mode(placement, &intent.identity.environment_id)
            .await?;
        self.rendering.existing(intent, sandbox.as_ref())
    }

    /// The startup re-apply of one environment's policy (#6070,
    /// `egress::reapply`): rendered in its bound Sandbox's own mode, by the
    /// access stack's own writer, only for a whole broker Sandbox.
    pub(super) async fn reapply_policy(
        &self,
        placement: &Placement,
        intent: &RenderingIntent,
    ) -> anyhow::Result<PolicyReapply> {
        let sandbox = self
            .bound_sandbox_mode(placement, &intent.identity.environment_id)
            .await?;
        if !sandbox.as_ref().is_some_and(|sandbox| sandbox.broker) {
            return Ok(PolicyReapply::NotBroker);
        }
        let opts = self.rendering.existing(intent, sandbox.as_ref())?;
        self.sandbox_client(placement)
            .reapply_workspace_network_policy(&opts)
            .await
    }

    /// The options a start's bootstrap refresh renders from, held to the
    /// init data confidential storage `authorized` ([`check_authorized`]).
    /// With the switch on they are create's, so a start moves a Sandbox made
    /// before it (`sandbox::client`'s `egress_migration`) and a broker one
    /// keeps its mode; with it off they are the Sandbox's own, so a start
    /// never moves a broker Sandbox back to direct. Create's are checked
    /// first, so a measured runtime whose configuration changed is refused
    /// before anything is read.
    pub(super) async fn render_start(
        &self,
        placement: &Placement,
        intent: &RenderingIntent,
        authorized: Option<&[u8; 32]>,
    ) -> anyhow::Result<TemplateOpts> {
        let create = self.render(intent)?;
        check_authorized(&create, authorized)?;
        if self.rendering.hosted_egress.enabled {
            return Ok(create);
        }
        let own = self.render_existing(placement, intent).await?;
        check_authorized(&own, authorized)?;
        Ok(own)
    }

    /// Refuses, before anything is patched, a resume, repair or replacement
    /// whose next Pod hosted egress would leave direct: the bound Sandbox was
    /// made before the switch and no start has moved it yet
    /// ([`crate::egress::pre_switch`], #4000). A start's bootstrap refresh
    /// moves it first, so its resume passes.
    pub(super) async fn check_made_before_hosted_egress(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        if !self.rendering.hosted_egress.enabled {
            return Ok(());
        }
        let name = self
            .sandbox_client(placement)
            .bound_sandbox_name(environment_id)
            .await?;
        let sandbox = self
            .sandboxes(placement)
            .get(&name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {name}: {error}"))?;
        crate::egress::pre_switch::check_sandbox(true, &name, &sandbox.data).inspect_err(|_| {
            tracing::warn!(
                environment_id,
                sandbox = name,
                "refused a Sandbox made before hosted egress"
            );
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
