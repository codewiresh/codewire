//! Hosted egress as orchestration starts (#4000, #6070): read once and only
//! here. With the switch on, every template a create renders on a VM runtime
//! is broker-mode, and a missing or malformed setting stops startup. The
//! broker settings are read whenever they are configured, so the broker
//! Sandboxes a deployment already has are served with the switch off too.

use anyhow::Context;

use super::own_mode::HostedEgress;
use super::settings::EgressSettings;
use crate::sandbox::template::{
    RUNTIME_PROFILE_STANDARD, STANDARD_IMAGE_DISK_ENV, STANDARD_RUNTIME_IMAGE_ENV, StandardRuntime,
};
use crate::worker::create::SandboxWorkerCfg;

/// Read hosted egress and the standard runtime into `cfg`, start the gateway
/// check while the broker settings are read, and count the broker Sandboxes
/// that can't be served without them. Returns the switches the services read.
pub async fn configure(
    cfg: &mut SandboxWorkerCfg,
    kube: Option<&kube::Client>,
) -> anyhow::Result<EgressSettings> {
    let startup =
        super::settings::startup(&cfg.derp_host).context("read the hosted egress settings")?;
    cfg.hosted_egress = HostedEgress {
        enabled: startup.settings.enabled,
        broker: startup.template,
    };
    // The standard runtime profile (#5602) runs only with its runtime, its
    // image disk and hosted egress, its VM's only network.
    cfg.standard_runtime = StandardRuntime::from_env()
        .map_err(anyhow::Error::msg)
        .context("read the standard runtime settings")?;
    if cfg.runtime_profile.trim() == RUNTIME_PROFILE_STANDARD {
        anyhow::ensure!(
            cfg.standard_runtime.is_some() && cfg.hosted_egress.create().is_some(),
            "the standard runtime profile needs {STANDARD_RUNTIME_IMAGE_ENV} and \
             {STANDARD_IMAGE_DISK_ENV}, and hosted egress on; see docs/CONFIGURATION.md",
        );
    }
    // While the broker settings are read, the gateway address they render is
    // held to the gateway Service's ClusterIP; a broker-mode render refuses
    // until it is.
    if let Some(gateway) = startup.gateway {
        match kube {
            Some(kube) => super::gateway_check::start(kube.clone(), gateway)
                .await
                .context("start the gateway check")?,
            None => {
                tracing::warn!("hosted egress is on without a cluster; broker-mode renders refuse")
            }
        }
    }
    // Without the broker settings, the broker Sandboxes this deployment
    // already has can't be served: counted and logged, never silent.
    if cfg.hosted_egress.broker.is_none()
        && let Some(kube) = kube.cloned()
    {
        let namespace = cfg.sandbox_namespace.clone();
        tokio::spawn(async move { super::own_mode::report_stranded(kube, &namespace).await });
    }
    Ok(startup.settings)
}
