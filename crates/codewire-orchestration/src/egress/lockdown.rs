//! The out-of-band half of the egress self-check (#4000 P6). The guest
//! probes from inside that its lockdown holds; orchestration checks from
//! outside, before it admits a bound guest's stream, that the NetworkPolicy
//! the cluster holds for the guest's environment is exactly the one
//! orchestration renders for it. infra#1806 showed a NetworkPolicy can stop
//! enforcing without anyone noticing; this check and the guest's probes
//! together are what notice.
//!
//! What it proves: nobody removed, replaced or widened the environment's
//! policy, and the Pod carries the labels that policy selects by. Which
//! environment that is comes from orchestration's live binding, never from
//! the Pod's labels, so a Pod cannot leave the check by dropping a label.
//!
//! What it does not prove: that the rendered policy itself confines egress to
//! the broker. That is the broker-mode policy of #4000 P5, and checking its
//! rules is a done-when of P5 before the hosted-egress flag is turned on.
//!
//! A refusal means the sandbox fails closed, the same outcome as a failed
//! guest probe (`FAILED_CLOSED`, `self_check_failed`). The guest's own result
//! is not an input: a guest that reports its probes passed is still refused
//! here.
//!
//! When it runs: at Admit for a guest that is already bound, and on its
//! assignment watch before the first bound assignment for a member admitted
//! unbound, which is how a warm-pool member is claimed. A policy changed
//! later under an already bound sandbox is not checked again yet.
//!
//! Not compared yet: the NetworkPolicy the sandbox controller makes from a
//! warm pool's template, which selects the same Pod. Policies add up, so a
//! template made before hosted egress was turned on can stay wider while
//! this check passes. Its name and spec are the controller's, not rendered
//! here, so comparing it needs a read and a rendering this check does not
//! have; warm templates are made again before the flag goes on, and the
//! comparison of every policy that selects the Pod is #4964.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};

use crate::runtime::{MemberFacts, NetworkPolicyFacts};
use crate::sandbox::LABEL_ENV_ID;
use crate::sandbox::template::workspace_daemon_network_policy_name;

use super::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};

#[derive(Debug, PartialEq, Eq)]
pub enum LockdownRefusal {
    NotBrokerMode,
    /// The Pod's environment label is absent, or names another environment
    /// than the one its live binding records.
    NotLabelledForItsBinding,
    /// This deployment leaves workspace NetworkPolicies to someone else, so
    /// orchestration has no rendering to hold the cluster to.
    PolicyUnmanaged,
    /// The environment's NetworkPolicy does not exist.
    PolicyMissing,
    /// It exists but is not the policy orchestration renders: a rule was
    /// added, removed or widened, or its selector or types changed.
    PolicyDiffers,
    /// It is the rendered policy but does not select this Pod.
    PolicyDoesNotSelect,
}

impl LockdownRefusal {
    /// The refusal as a metric label and a log field: a closed set, never a
    /// Pod's or an environment's identifier.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NotBrokerMode => "not_broker_mode",
            Self::NotLabelledForItsBinding => "not_labelled_for_its_binding",
            Self::PolicyUnmanaged => "policy_unmanaged",
            Self::PolicyMissing => "policy_missing",
            Self::PolicyDiffers => "policy_differs",
            Self::PolicyDoesNotSelect => "policy_does_not_select",
        }
    }
}

static FAILED_CLOSED: OnceLock<IntCounterVec> = OnceLock::new();

fn failed_closed_metric() -> &'static IntCounterVec {
    FAILED_CLOSED.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_egress_lockdown_failed_closed_total",
                "Sandboxes failed closed because their egress lockdown was not applied, by reason."
            ),
            &["reason"]
        )
        .expect("egress lockdown metric registration must be unique")
    })
}

/// Count one sandbox failed closed for `refusal`. Recording `FAILED_CLOSED`
/// in the sandbox's own status follows with enforcement storage; until then
/// this counter is what an alert reads.
pub fn count_failed_closed(refusal: &LockdownRefusal) {
    failed_closed_metric()
        .with_label_values(&[refusal.reason()])
        .inc();
}

/// How many sandboxes failed closed for `refusal` since this process started.
#[cfg(test)]
pub(super) fn failed_closed(refusal: &LockdownRefusal) -> u64 {
    failed_closed_metric()
        .with_label_values(&[refusal.reason()])
        .get()
}

/// The NetworkPolicy the Pod bound to `environment_id` must be selected by.
pub fn policy_name(environment_id: &str) -> String {
    workspace_daemon_network_policy_name(environment_id)
}

/// Whether the lockdown orchestration renders is applied to `guest`, which
/// the live binding says is bound to `environment_id`. `rendered` is what
/// orchestration renders for that environment and `live` what the cluster
/// holds under [`policy_name`].
pub fn lockdown_applied(
    guest: &MemberFacts,
    environment_id: &str,
    rendered: Option<&NetworkPolicyFacts>,
    live: Option<&NetworkPolicyFacts>,
) -> Result<(), LockdownRefusal> {
    if guest.labels.get(EGRESS_MODE_LABEL).map(String::as_str) != Some(EGRESS_MODE_BROKER) {
        return Err(LockdownRefusal::NotBrokerMode);
    }
    if guest.labels.get(LABEL_ENV_ID).map(String::as_str) != Some(environment_id) {
        return Err(LockdownRefusal::NotLabelledForItsBinding);
    }
    let rendered = rendered.ok_or(LockdownRefusal::PolicyUnmanaged)?;
    let live = live.ok_or(LockdownRefusal::PolicyMissing)?;
    if live != rendered {
        return Err(LockdownRefusal::PolicyDiffers);
    }
    if !selects(rendered, guest) {
        return Err(LockdownRefusal::PolicyDoesNotSelect);
    }
    Ok(())
}

/// Whether `policy` selects `guest` by labels alone. A selector with no
/// labels, or with expressions, is not one orchestration renders for a
/// workspace, and is never taken as selecting it.
fn selects(policy: &NetworkPolicyFacts, guest: &MemberFacts) -> bool {
    let selector = &policy.spec["podSelector"];
    selector.get("matchExpressions").is_none()
        && selector["matchLabels"].as_object().is_some_and(|labels| {
            !labels.is_empty()
                && labels
                    .iter()
                    .all(|(key, value)| guest.labels.get(key).map(String::as_str) == value.as_str())
        })
}

#[cfg(test)]
mod tests;
