//! The out-of-band half of the egress self-check (#4000 P6). The guest
//! probes from inside that its lockdown holds; orchestration checks from
//! outside, before it admits a bound guest's stream, that the NetworkPolicy
//! the cluster holds for the guest's environment is exactly the one
//! orchestration renders for it. infra#1806 showed a NetworkPolicy can stop
//! enforcing without anyone noticing; this check and the guest's probes
//! together are what notice.
//!
//! What it proves: nobody removed, replaced or widened the environment's
//! policy, the Pod carries the labels that policy selects by, and no other
//! NetworkPolicy in the namespace adds to what the Pod may reach (#4964).
//! Kubernetes adds together every policy that selects a Pod, so each one that
//! selects it must be the environment's, the policy the sandbox controller
//! makes from the Pod's template exactly as orchestration renders that
//! template, a claimed warm member's bridge (#2434) exactly as orchestration
//! renders it for the Sandbox the binding recorded, or a policy with no rules
//! at all, which allows nothing. The bridge grants only the environment
//! policy's own ingress, so accepting it adds nothing the environment's
//! policy does not already allow. Which environment the Pod is bound to
//! comes from orchestration's live binding, never from the Pod's labels, so a
//! Pod cannot leave the check by dropping a label.
//!
//! It reads Kubernetes NetworkPolicies only. A Cilium policy can allow
//! traffic too and is not seen here; only infra's reviewed GitOps creates
//! those (infra#1822).
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
//! The guest's Sandbox must have the whole broker shape too, read from the
//! Sandbox object its binding recorded, and the policies it expects are the
//! broker ones from the broker settings, whatever the switch says (#6070).
//!
//! When it runs: at Admit for a guest that is already bound, and on its
//! assignment watch before the first bound assignment for a member admitted
//! unbound, which is how a warm-pool member is claimed. A policy changed
//! later under an already bound sandbox is not checked again yet.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};

use crate::runtime::{MemberFacts, NamedNetworkPolicy, NetworkPolicyFacts};
use crate::sandbox::LABEL_ENV_ID;
use crate::sandbox::template::{
    warm_member_daemon_bridge_name, workspace_daemon_network_policy_name,
};
use crate::sandbox::warm_pool::TEMPLATE_REF_HASH_LABEL;

use super::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};

#[derive(Debug, PartialEq, Eq)]
pub enum LockdownRefusal {
    /// The Pod has no broker label, or the Sandbox its binding recorded is
    /// not whole broker as orchestration wrote it (#6070).
    NotBrokerMode,
    /// The Pod's environment label is absent, or names another environment
    /// than the one its live binding records.
    NotLabelledForItsBinding,
    /// This deployment leaves workspace NetworkPolicies to someone else, so
    /// orchestration has no rendering to hold the cluster to.
    PolicyUnmanaged,
    /// The environment's NetworkPolicy does not exist.
    PolicyMissing,
    /// A policy that selects the Pod is not one orchestration renders for
    /// it: the environment's with a rule added, removed or widened, or its
    /// selector or types changed; a template's that is not the template
    /// orchestration renders, such as one made before hosted egress; or any
    /// other policy with a rule. `policy` names it for the operator's log; the
    /// stored and counted reason is the same for each.
    PolicyDiffers { policy: String },
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
            Self::PolicyDiffers { .. } => "policy_differs",
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

/// The template hash the sandbox controller selects `guest` by, if it has
/// one: the label every Sandbox made from a template carries.
pub fn template_ref_hash(guest: &MemberFacts) -> Option<&str> {
    guest
        .labels
        .get(TEMPLATE_REF_HASH_LABEL)
        .map(String::as_str)
}

/// Whether the lockdown orchestration renders is applied to `guest`, which
/// the live binding says is bound to `environment_id`. `rendered` is what
/// orchestration renders for that environment, `rendered_template` what the
/// sandbox controller makes from the guest's template as orchestration
/// renders it, `rendered_bridge` the warm-member bridge orchestration renders
/// for the Sandbox the binding recorded, and `live` every NetworkPolicy in
/// the guest's namespace.
pub fn lockdown_applied(
    guest: &MemberFacts,
    environment_id: &str,
    rendered: Option<&NetworkPolicyFacts>,
    rendered_template: Option<&NetworkPolicyFacts>,
    rendered_bridge: Option<&NetworkPolicyFacts>,
    live: &[NamedNetworkPolicy],
) -> Result<(), LockdownRefusal> {
    if guest.labels.get(EGRESS_MODE_LABEL).map(String::as_str) != Some(EGRESS_MODE_BROKER) {
        return Err(LockdownRefusal::NotBrokerMode);
    }
    if guest.labels.get(LABEL_ENV_ID).map(String::as_str) != Some(environment_id) {
        return Err(LockdownRefusal::NotLabelledForItsBinding);
    }
    let rendered = rendered.ok_or(LockdownRefusal::PolicyUnmanaged)?;
    let name = policy_name(environment_id);
    let own = live
        .iter()
        .find(|policy| policy.name == name)
        .ok_or(LockdownRefusal::PolicyMissing)?;
    if &own.facts != rendered {
        return Err(LockdownRefusal::PolicyDiffers { policy: name });
    }
    if !selects(rendered, guest) {
        return Err(LockdownRefusal::PolicyDoesNotSelect);
    }
    for policy in live.iter().filter(|policy| policy.name != name) {
        if !may_select(&policy.facts, guest)
            || allows_nothing(&policy.facts)
            || is_template_policy(policy, rendered_template)
            || is_warm_member_bridge(policy, environment_id, rendered_bridge)
        {
            continue;
        }
        return Err(LockdownRefusal::PolicyDiffers {
            policy: policy.name.clone(),
        });
    }
    Ok(())
}

/// Whether `policy` is the one the sandbox controller makes from the guest's
/// template, exactly as orchestration renders that template. The controller
/// names it `<template>-network-policy`.
fn is_template_policy(policy: &NamedNetworkPolicy, rendered: Option<&NetworkPolicyFacts>) -> bool {
    policy.name.ends_with("-network-policy") && rendered == Some(&policy.facts)
}

/// Whether `policy` is the bridge orchestration applies to the environment's
/// adopted warm member: its name, and exactly the rendered content, whose
/// selector names the Sandbox the binding recorded. Another environment's
/// bridge, or one rendered from other settings, is not.
fn is_warm_member_bridge(
    policy: &NamedNetworkPolicy,
    environment_id: &str,
    rendered: Option<&NetworkPolicyFacts>,
) -> bool {
    policy.name == warm_member_daemon_bridge_name(environment_id) && rendered == Some(&policy.facts)
}

/// Whether `policy` has no rule in either direction, whatever its types. It
/// can only isolate: a Pod's allowed traffic is the union of its policies'
/// rules. A single empty rule (`[{}]`) is a rule that allows everything.
fn allows_nothing(policy: &NetworkPolicyFacts) -> bool {
    let empty = |field: &str| {
        policy
            .spec
            .get(field)
            .is_none_or(|rules| rules.as_array().is_some_and(Vec::is_empty))
    };
    empty("ingress") && empty("egress")
}

/// Whether `policy`'s Pod selector may select `guest`, by the Kubernetes
/// label-selector rules: every `matchLabels` entry and every
/// `matchExpressions` requirement holds, and an empty selector selects every
/// Pod. A selector this cannot read, such as an unknown operator, counts as
/// selecting, so it is compared rather than skipped.
fn may_select(policy: &NetworkPolicyFacts, guest: &MemberFacts) -> bool {
    let Some(selector) = policy.spec.get("podSelector") else {
        return true;
    };
    let labels_hold = selector.get("matchLabels").is_none_or(|labels| {
        labels.as_object().is_none_or(|labels| {
            labels.iter().all(|(key, value)| {
                value
                    .as_str()
                    .is_none_or(|value| guest.labels.get(key).map(String::as_str) == Some(value))
            })
        })
    });
    let expressions_hold = selector.get("matchExpressions").is_none_or(|expressions| {
        expressions.as_array().is_none_or(|expressions| {
            expressions
                .iter()
                .all(|requirement| requirement_holds(requirement, guest))
        })
    });
    labels_hold && expressions_hold
}

/// One `matchExpressions` requirement. An operator or form this does not know
/// holds, so the policy counts as selecting.
fn requirement_holds(requirement: &serde_json::Value, guest: &MemberFacts) -> bool {
    let Some(key) = requirement.get("key").and_then(serde_json::Value::as_str) else {
        return true;
    };
    let value = guest.labels.get(key);
    let values = || {
        requirement
            .get("values")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    match requirement
        .get("operator")
        .and_then(serde_json::Value::as_str)
    {
        Some("In") => value.is_some_and(|value| values().contains(&value.as_str())),
        Some("NotIn") => value.is_none_or(|value| !values().contains(&value.as_str())),
        Some("Exists") => value.is_some(),
        Some("DoesNotExist") => value.is_none(),
        _ => true,
    }
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
