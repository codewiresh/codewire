//! A Sandbox keeps its own egress mode whatever the switch reads (#6070;
//! SPEC "Target, not shipped (#6070)").
//!
//! The switch (`settings::SWITCH`) decides what a create renders, and whether
//! a start moves a Sandbox made before it (`pre_switch`). The broker
//! settings are read whenever they are configured, so a broker Sandbox is
//! rendered and served from them with the switch on or off. Everything that
//! writes or checks an existing Sandbox's egress decides from the whole
//! broker shape of the Sandbox object orchestration wrote
//! (`pre_switch::template_whole_broker`), never from the switch, the Pod, its
//! status or anything the guest can influence. A Sandbox with the broker
//! label alone is direct.
//!
//! Removing the broker settings is the emergency stop for broker egress: each
//! broker Sandbox is then refused with [`BrokerSettingsAbsent`] before
//! anything is written, never given direct rules, and startup counts them
//! ([`report_stranded`]).

use std::sync::OnceLock;

use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams};
use prometheus::{IntGauge, register_int_gauge};
use serde_json::Value;

use super::pre_switch::template_whole_broker;
use crate::sandbox::template::HostedEgressTemplate;
use crate::sandbox::{CRD_VERSION, SANDBOX_GROUP};

/// Hosted egress as a deployment has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostedEgress {
    /// The switch: what a create renders, and whether a start moves a
    /// Sandbox made before it.
    pub enabled: bool,
    /// What every broker Sandbox renders from, read whenever it is configured
    /// (`settings::startup`). Always set while the switch is on.
    pub broker: Option<HostedEgressTemplate>,
}

impl HostedEgress {
    /// The switch on, rendering from `broker`.
    pub fn on(broker: HostedEgressTemplate) -> Self {
        Self {
            enabled: true,
            broker: Some(broker),
        }
    }

    /// What a create renders on a VM runtime: broker mode while the switch is
    /// on, direct while it is off.
    pub fn create(&self) -> Option<&HostedEgressTemplate> {
        self.broker.as_ref().filter(|_| self.enabled)
    }

    /// What `sandbox` renders: broker mode from the settings when its own
    /// shape is whole broker, whatever the switch says, and direct when it is
    /// not. A broker Sandbox without the settings is refused, never rendered
    /// direct.
    pub fn existing(
        &self,
        sandbox: &SandboxMode,
    ) -> Result<Option<&HostedEgressTemplate>, BrokerSettingsAbsent> {
        if !sandbox.broker {
            return Ok(None);
        }
        self.broker.as_ref().map(Some).ok_or_else(|| {
            tracing::warn!(
                sandbox = %sandbox.name,
                "refused a broker-mode Sandbox: the hosted egress broker settings are absent"
            );
            BrokerSettingsAbsent {
                sandbox: sandbox.name.clone(),
            }
        })
    }
}

/// A Sandbox's own egress mode, from the pod template orchestration wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxMode {
    pub name: String,
    /// The whole broker shape; the label alone is not.
    pub broker: bool,
}

impl SandboxMode {
    /// The mode of the Sandbox `name`, from its object as read.
    pub fn of(name: &str, sandbox: &Value) -> Self {
        Self {
            name: name.to_owned(),
            broker: template_whole_broker(sandbox.pointer("/spec/podTemplate")),
        }
    }
}

/// A broker-mode Sandbox refused because this deployment has no broker
/// settings. Nothing was written. `sandbox` is for the operator log; the
/// message is what the user reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "this environment uses hosted egress, which this deployment has stopped serving: it can't run until hosted egress is restored"
)]
pub struct BrokerSettingsAbsent {
    pub sandbox: String,
}

static STRANDED: OnceLock<IntGauge> = OnceLock::new();

fn stranded_metric() -> &'static IntGauge {
    STRANDED.get_or_init(|| {
        register_int_gauge!(
            "codewire_egress_stranded_broker_sandboxes",
            "Broker-mode Sandboxes this orchestration can't serve because its hosted egress broker settings are absent, counted at startup."
        )
        .expect("stranded broker metric registration must be unique")
    })
}

/// How many of `sandboxes` have the whole broker shape.
pub fn broker_sandboxes(sandboxes: &[DynamicObject]) -> usize {
    sandboxes
        .iter()
        .filter(|sandbox| template_whole_broker(sandbox.data.pointer("/spec/podTemplate")))
        .count()
}

/// With the broker settings absent, count and log the broker-mode Sandboxes
/// in `namespace` that can't be served, so the stop is never silent. A failed
/// read is logged and counts nothing.
pub async fn report_stranded(client: kube::Client, namespace: &str) {
    let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
    let sandboxes: Api<DynamicObject> = Api::namespaced_with(
        client,
        namespace,
        &ApiResource::from_gvk_with_plural(&gvk, "sandboxes"),
    );
    match sandboxes.list(&ListParams::default()).await {
        Ok(list) => {
            let stranded = broker_sandboxes(&list.items);
            stranded_metric().set(i64::try_from(stranded).unwrap_or(i64::MAX));
            if stranded > 0 {
                tracing::warn!(
                    stranded,
                    namespace,
                    "broker-mode Sandboxes can't be served: the hosted egress broker settings are absent"
                );
            }
        }
        Err(error) => tracing::warn!(
            %error,
            namespace,
            "could not count the broker-mode Sandboxes the absent hosted egress broker settings strand"
        ),
    }
}

/// The count [`report_stranded`] last set.
#[cfg(test)]
pub(crate) fn stranded() -> i64 {
    stranded_metric().get()
}

#[cfg(test)]
mod tests;
