//! A Sandbox made while hosted egress was off (#4000; private-docs
//! `designs/hosted-egress.md`, "A Sandbox made before the switch").
//!
//! A start, a repair and a Pod replacement build the next Pod from the
//! Sandbox's own pod template, and nothing else renders its egress mode again.
//! So with hosted egress on, a start moves such a Sandbox to create's render
//! while it has no Pod (`sandbox::client`'s `egress_migration`), and
//! everything else that would build a Pod from it, a repair or a replacement
//! of a running one, is refused before anything changes; a Pod built from one
//! is refused its bind. A missing broker shape is never itself a reason to
//! stop or restart a running Sandbox. Only a VM runtime is broker-mode under
//! the switch, as the renderer decides; a runc Pod, or one with no runtime
//! class, never is. Neither runs in a shared sandbox namespace anyway:
//! infra's Kyverno policy `codewire-shared-sandbox-runtime-security` refuses
//! both there (its rule `enforce-shared-sandbox-runtime-class`), so the
//! exception admits nothing a hosted Sandbox can be.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use serde_json::Value;

use super::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};
use crate::sandbox::template::RUNTIME_CLASS_RUNC;

/// A repair or replacement refused because the Sandbox was made before
/// hosted egress and still runs direct. `sandbox` is for the operator log;
/// the message is what the user reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("this environment moves to hosted egress at its next start: stop it and start it again")]
pub struct MadeBeforeHostedEgress {
    pub sandbox: String,
}

/// What became of one start's move of a Sandbox made before hosted egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveOutcome {
    /// The Sandbox now has create's render.
    Moved,
    /// A precondition did not hold (a Pod, no suspension, not claimed, a
    /// measured runtime), so nothing was written.
    Refused,
    /// The patch was sent and not admitted, or did not converge.
    NotAdmitted,
}

impl MoveOutcome {
    /// The outcome as a metric label: a closed set, never an identifier.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Moved => "moved",
            Self::Refused => "refused",
            Self::NotAdmitted => "not_admitted",
        }
    }
}

static MOVES: OnceLock<IntCounterVec> = OnceLock::new();

fn moves_metric() -> &'static IntCounterVec {
    MOVES.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_egress_sandbox_moves_total",
                "Sandboxes made before hosted egress that a start moved to it, or tried to, by outcome."
            ),
            &["outcome"]
        )
        .expect("egress move metric registration must be unique")
    })
}

/// Count one start's move of a Sandbox made before hosted egress.
pub fn count_move(outcome: MoveOutcome) {
    moves_metric().with_label_values(&[outcome.label()]).inc();
}

/// How many moves ended in `outcome` since this process started.
#[cfg(test)]
pub(crate) fn moves(outcome: MoveOutcome) -> u64 {
    moves_metric().with_label_values(&[outcome.label()]).get()
}

/// Whether a Pod on `runtime_class_name` is broker-mode under the switch.
fn broker_required(runtime_class_name: &str) -> bool {
    !matches!(runtime_class_name, "" | RUNTIME_CLASS_RUNC)
}

fn made_before(enabled: bool, pod_spec: Option<&Value>, labelled: bool) -> bool {
    let class = pod_spec
        .and_then(|spec| spec.get("runtimeClassName"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    enabled && !labelled && broker_required(class)
}

/// Refuses a Sandbox, before any patch, whose next Pod would run direct
/// under a switched-on deployment: one a start moves to hosted egress first.
pub fn check_sandbox(
    enabled: bool,
    name: &str,
    sandbox: &Value,
) -> Result<(), MadeBeforeHostedEgress> {
    let labelled = sandbox
        .pointer("/spec/podTemplate/metadata/labels")
        .and_then(|labels| labels.get(EGRESS_MODE_LABEL))
        .and_then(Value::as_str)
        == Some(EGRESS_MODE_BROKER);
    if made_before(enabled, sandbox.pointer("/spec/podTemplate/spec"), labelled) {
        return Err(MadeBeforeHostedEgress {
            sandbox: name.to_owned(),
        });
    }
    Ok(())
}

/// Whether a bound Pod, with these labels and this spec, runs direct under a
/// switched-on deployment.
pub fn pod_made_before(enabled: bool, labels: &BTreeMap<String, String>, spec: &Value) -> bool {
    let labelled = labels.get(EGRESS_MODE_LABEL).map(String::as_str) == Some(EGRESS_MODE_BROKER);
    made_before(enabled, Some(spec), labelled)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sandbox(class: Option<&str>, broker: bool) -> Value {
        let mut labels = json!({"codewire.sh/type": "workspace"});
        if broker {
            labels[EGRESS_MODE_LABEL] = json!(EGRESS_MODE_BROKER);
        }
        let mut spec = json!({"containers": []});
        if let Some(class) = class {
            spec["runtimeClassName"] = json!(class);
        }
        json!({"spec": {"podTemplate": {"metadata": {"labels": labels}, "spec": spec}}})
    }

    #[test]
    fn a_direct_vm_sandbox_is_refused_only_with_the_switch_on() {
        for class in ["commodity", "commodity-32g", "confidential", "standard"] {
            let direct = sandbox(Some(class), false);
            assert_eq!(
                check_sandbox(true, "sandbox-a", &direct),
                Err(MadeBeforeHostedEgress {
                    sandbox: "sandbox-a".into()
                }),
                "{class}"
            );
            assert_eq!(
                check_sandbox(false, "sandbox-a", &direct),
                Ok(()),
                "{class}"
            );
            assert_eq!(
                check_sandbox(true, "sandbox-a", &sandbox(Some(class), true)),
                Ok(()),
                "{class}"
            );
        }
    }

    #[test]
    fn a_runtime_the_switch_never_makes_broker_mode_is_not_refused() {
        for class in [Some("runc"), None] {
            assert_eq!(check_sandbox(true, "s", &sandbox(class, false)), Ok(()));
        }
    }

    #[test]
    fn a_runtime_class_this_build_does_not_know_fails_closed() {
        assert!(check_sandbox(true, "s", &sandbox(Some("another-vm"), false)).is_err());
    }

    #[test]
    fn a_label_of_another_value_is_not_broker_mode() {
        let mut other = sandbox(Some("commodity"), false);
        other["spec"]["podTemplate"]["metadata"]["labels"][EGRESS_MODE_LABEL] = json!("direct");
        assert!(check_sandbox(true, "s", &other).is_err());
    }

    #[test]
    fn a_pod_is_judged_by_its_own_labels_and_runtime() {
        let broker =
            BTreeMap::from([(EGRESS_MODE_LABEL.to_owned(), EGRESS_MODE_BROKER.to_owned())]);
        let none = BTreeMap::new();
        let vm = json!({"runtimeClassName": "commodity"});
        assert!(pod_made_before(true, &none, &vm));
        assert!(!pod_made_before(true, &broker, &vm));
        assert!(!pod_made_before(false, &none, &vm));
        assert!(!pod_made_before(
            true,
            &none,
            &json!({"runtimeClassName": "runc"})
        ));
    }
}
