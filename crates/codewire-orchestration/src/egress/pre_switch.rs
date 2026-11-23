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
use crate::sandbox::template::{
    HOSTED_EGRESS_FENCE_REVISION_ANNOTATION, HOSTED_EGRESS_TUN_CONTAINER, RUNTIME_CLASS_RUNC,
    RUNTIME_CLASS_STANDARD,
};

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

/// Whether a pod template, or a Pod, has the whole broker shape: the broker
/// label, the fence revision annotation, and the TUN init container unless it
/// runs on a `standard` VM, which has its own. The label alone is not broker
/// mode (#6019): only a writer other than orchestration could leave it, and
/// admission refuses that (`codewire-sandbox-broker-mode`). This must match
/// `wholeBroker` in the member admission policy
/// (`deployments/k8s/orchestration/warm-pool-authz.yaml`), which
/// `sandbox::client::egress_migration`'s tests pin.
fn whole_broker(labelled: bool, fenced: bool, spec: Option<&Value>) -> bool {
    let tun = spec
        .and_then(|spec| spec.get("runtimeClassName"))
        .and_then(Value::as_str)
        == Some(RUNTIME_CLASS_STANDARD)
        || spec
            .and_then(|spec| spec.get("initContainers"))
            .and_then(Value::as_array)
            .is_some_and(|inits| {
                inits
                    .iter()
                    .any(|init| init["name"] == HOSTED_EGRESS_TUN_CONTAINER)
            });
    labelled && fenced && tun
}

/// [`whole_broker`] over a Sandbox's `spec.podTemplate`.
pub fn template_whole_broker(template: Option<&Value>) -> bool {
    let metadata = template.and_then(|template| template.get("metadata"));
    let labelled = metadata
        .and_then(|metadata| metadata.pointer("/labels"))
        .and_then(|labels| labels.get(EGRESS_MODE_LABEL))
        .and_then(Value::as_str)
        == Some(EGRESS_MODE_BROKER);
    let fenced = metadata
        .and_then(|metadata| metadata.pointer("/annotations"))
        .and_then(|annotations| annotations.get(HOSTED_EGRESS_FENCE_REVISION_ANNOTATION))
        .is_some();
    whole_broker(
        labelled,
        fenced,
        template.and_then(|template| template.get("spec")),
    )
}

fn made_before(enabled: bool, pod_spec: Option<&Value>, broker: bool) -> bool {
    let class = pod_spec
        .and_then(|spec| spec.get("runtimeClassName"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    enabled && !broker && broker_required(class)
}

/// Refuses a Sandbox, before any patch, whose next Pod would run direct
/// under a switched-on deployment: one a start moves to hosted egress first.
/// One with the broker label but not the whole shape counts as direct.
pub fn check_sandbox(
    enabled: bool,
    name: &str,
    sandbox: &Value,
) -> Result<(), MadeBeforeHostedEgress> {
    let template = sandbox.pointer("/spec/podTemplate");
    let broker = template_whole_broker(template);
    if made_before(
        enabled,
        template.and_then(|template| template.get("spec")),
        broker,
    ) {
        return Err(MadeBeforeHostedEgress {
            sandbox: name.to_owned(),
        });
    }
    Ok(())
}

/// Whether a bound Pod, with these labels, annotations and spec, runs direct
/// under a switched-on deployment. One with the broker label but not the
/// whole shape counts as direct.
pub fn pod_made_before(
    enabled: bool,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
    spec: &Value,
) -> bool {
    let broker = whole_broker(
        labels.get(EGRESS_MODE_LABEL).map(String::as_str) == Some(EGRESS_MODE_BROKER),
        annotations.contains_key(HOSTED_EGRESS_FENCE_REVISION_ANNOTATION),
        Some(spec),
    );
    made_before(enabled, Some(spec), broker)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The parts of the broker shape a pod template has.
    #[derive(Clone, Copy)]
    struct Shape {
        label: bool,
        fence: bool,
        tun: bool,
    }

    const WHOLE: Shape = Shape {
        label: true,
        fence: true,
        tun: true,
    };
    const DIRECT: Shape = Shape {
        label: false,
        fence: false,
        tun: false,
    };

    fn shaped(class: Option<&str>, shape: Shape) -> Value {
        let mut labels = json!({"codewire.sh/type": "workspace"});
        if shape.label {
            labels[EGRESS_MODE_LABEL] = json!(EGRESS_MODE_BROKER);
        }
        let mut metadata = json!({"labels": labels});
        if shape.fence {
            metadata["annotations"] = json!({HOSTED_EGRESS_FENCE_REVISION_ANNOTATION: "4"});
        }
        let mut spec = json!({"containers": []});
        if shape.tun {
            spec["initContainers"] = json!([{"name": HOSTED_EGRESS_TUN_CONTAINER}]);
        }
        if let Some(class) = class {
            spec["runtimeClassName"] = json!(class);
        }
        json!({"spec": {"podTemplate": {"metadata": metadata, "spec": spec}}})
    }

    fn sandbox(class: Option<&str>, broker: bool) -> Value {
        shaped(class, if broker { WHOLE } else { DIRECT })
    }

    /// A Pod's labels, annotations and spec, as the bind reads them.
    fn pod(
        shape: Shape,
        class: &str,
    ) -> (BTreeMap<String, String>, BTreeMap<String, String>, Value) {
        let template = shaped(Some(class), shape);
        let strings = |value: &Value| -> BTreeMap<String, String> {
            value
                .as_object()
                .into_iter()
                .flatten()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                .collect()
        };
        let metadata = &template["spec"]["podTemplate"]["metadata"];
        (
            strings(&metadata["labels"]),
            strings(&metadata["annotations"]),
            template["spec"]["podTemplate"]["spec"].clone(),
        )
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
    fn a_pod_is_judged_by_its_own_shape_and_runtime() {
        let made_before = |shape, class| {
            let (labels, annotations, spec) = pod(shape, class);
            pod_made_before(true, &labels, &annotations, &spec)
        };
        assert!(made_before(DIRECT, "commodity"));
        assert!(!made_before(WHOLE, "commodity"));
        let (labels, annotations, spec) = pod(DIRECT, "commodity");
        assert!(!pod_made_before(false, &labels, &annotations, &spec));
        assert!(!made_before(DIRECT, "runc"));
    }

    /// #6019: the broker label without the rest of the shape is direct, for
    /// a Sandbox's resume or repair and for a Pod's bind alike. A `standard`
    /// VM has its own TUN, so the label and the fence are its whole shape.
    #[test]
    fn the_label_without_the_whole_shape_is_made_before() {
        let hollow = [
            Shape {
                label: true,
                fence: false,
                tun: false,
            },
            Shape {
                label: true,
                fence: true,
                tun: false,
            },
            Shape {
                label: true,
                fence: false,
                tun: true,
            },
            Shape {
                label: false,
                fence: true,
                tun: true,
            },
        ];
        for (index, shape) in hollow.into_iter().enumerate() {
            assert_eq!(
                check_sandbox(true, "s", &shaped(Some("commodity"), shape)),
                Err(MadeBeforeHostedEgress {
                    sandbox: "s".into()
                }),
                "shape {index}"
            );
            assert!(
                format!(
                    "{}",
                    check_sandbox(true, "s", &shaped(Some("commodity"), shape)).unwrap_err()
                )
                .contains("stop it and start it again"),
                "shape {index}"
            );
            let (labels, annotations, spec) = pod(shape, "commodity");
            assert!(
                pod_made_before(true, &labels, &annotations, &spec),
                "shape {index}"
            );
            assert_eq!(
                check_sandbox(false, "s", &shaped(Some("commodity"), shape)),
                Ok(()),
                "shape {index}"
            );
        }
        let standard = Shape {
            label: true,
            fence: true,
            tun: false,
        };
        assert_eq!(
            check_sandbox(true, "s", &shaped(Some("standard"), standard)),
            Ok(())
        );
        let (labels, annotations, spec) = pod(standard, "standard");
        assert!(!pod_made_before(true, &labels, &annotations, &spec));
        let unfenced = Shape {
            label: true,
            fence: false,
            tun: false,
        };
        assert!(check_sandbox(true, "s", &shaped(Some("standard"), unfenced)).is_err());
    }
}
