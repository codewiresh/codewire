//! The runner's control channel to its egress broker (#2614, #2537): the
//! host address updates, each policy replacement, and the broker's refusal
//! reports, which the runner keeps for this run of the VM (#5058).

use std::sync::Arc;

use codewire_egress_policy::CompiledPolicy;
use codewire_egress_policy::host_addresses::HostAddressSet;

use crate::broker_control::RunnerRefusalLog;
use crate::control::v1;

use super::{EgressBrokerProcess, HostAddressTask, RunnerError, RunningVm};
use crate::host_addresses::{
    HostAddressMonitor, INTERFACE_POLL, PUBLIC_RELEARN, SystemHostAddressSource,
};

impl EgressBrokerProcess {
    /// One task owns the control socket: the monitor's host address updates,
    /// each policy replacement (#2537) and the broker's refusal reports,
    /// filed in this broker's own log (#5058). When any ends, the socket
    /// closes and the broker fails closed.
    pub(super) fn serve_control(
        &mut self,
        monitor: HostAddressMonitor<SystemHostAddressSource>,
        host_addresses: HostAddressSet,
        control: tokio::net::UnixStream,
    ) {
        let (address_updates, addresses) = tokio::sync::mpsc::channel(1);
        let (replace, replacements) = tokio::sync::mpsc::channel(1);
        let refusals = Arc::new(RunnerRefusalLog::new(crate::broker_control::now_unix_ms()));
        self.refusals = Some(Arc::clone(&refusals));
        self.host_addresses = Some(HostAddressTask(tokio::spawn(async move {
            tokio::select! {
                _ = monitor.run(address_updates, host_addresses, INTERFACE_POLL, PUBLIC_RELEARN) => {}
                _ = crate::broker_control::serve_runner_control(
                    control,
                    addresses,
                    replacements,
                    crate::broker_control::POLICY_ACK_TIMEOUT,
                    refusals,
                ) => {}
            }
        })));
        self.policy_control = Some(replace);
    }
}

impl RunningVm {
    /// Enforce `policy` on this generation's egress broker from now on
    /// (#2537). It returns the digest the broker acknowledged, once every
    /// flow the policy refuses has ended. A failure closes the broker's
    /// control channel, so the broker fails closed.
    ///
    /// The refusal log names the policy by `label` from before it is sent,
    /// so no refusal under it goes unnamed.
    pub async fn replace_network_policy(
        &mut self,
        policy: CompiledPolicy,
        label: Option<&v1::NetworkPolicyLabel>,
    ) -> Result<codewire_egress_policy::PolicyDigest, RunnerError> {
        let control = self
            .network_worker
            .as_ref()
            .and_then(|worker| worker.broker.as_ref())
            .and_then(|broker| broker.policy_control.clone())
            .ok_or(RunnerError::EgressPolicyControl)?;
        self.label_policy(&policy, label);
        let (reply, acknowledged) = tokio::sync::oneshot::channel();
        control
            .send(crate::broker_control::PolicyReplacementRequest {
                policy: policy.clone(),
                reply,
            })
            .await
            .map_err(|_| RunnerError::EgressPolicyControl)?;
        let enforced = acknowledged
            .await
            .map_err(|_| RunnerError::EgressPolicyControl)?;
        self.request.network_policy = policy;
        Ok(enforced)
    }

    /// This run's refusal log, while its egress broker runs.
    pub(crate) fn egress_refusals(&self) -> Option<&Arc<RunnerRefusalLog>> {
        self.network_worker
            .as_ref()
            .and_then(|worker| worker.broker.as_ref())
            .and_then(|broker| broker.refusals.as_ref())
    }

    /// Names in its refusal log the policy this boot started with, and the
    /// policy of the allowed hosts the supervisor sends its credential
    /// authority.
    pub(crate) fn label_policies(
        &self,
        network_policy: Option<v1::NetworkPolicyLabel>,
        credential_policy: Option<v1::NetworkPolicyLabel>,
    ) {
        self.label_policy(&self.request.network_policy, network_policy.as_ref());
        self.label_intercepted(credential_policy.as_ref());
    }

    /// Names the policy of the allowed hosts the supervisor sends the
    /// credential authority: the only label an intercepted host's refusal by
    /// the network policy takes from now on (#5058). Never from the front
    /// door.
    pub(crate) fn label_intercepted(&self, label: Option<&v1::NetworkPolicyLabel>) {
        if let (Some(log), Some(label)) = (self.egress_refusals(), label) {
            log.label_intercepted(label.name.clone(), u64::from(label.revision));
        }
    }

    fn label_policy(&self, policy: &CompiledPolicy, label: Option<&v1::NetworkPolicyLabel>) {
        if let (Some(log), Some(label)) = (self.egress_refusals(), label) {
            log.label(
                policy.digest(),
                label.name.clone(),
                u64::from(label.revision),
            );
        }
    }
}
