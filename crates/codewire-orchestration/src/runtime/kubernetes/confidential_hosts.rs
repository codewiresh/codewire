//! How many nodes can run a confidential member now (#4281): the Ready,
//! schedulable nodes the confidential RuntimeClass schedules to. Orchestration
//! sizes its bound on concurrent confidential activations from it.

use k8s_openapi::api::core::v1::Node;
use kube::Api;
use kube::api::ListParams;

use super::warm_pools::{read_runtime_classes, selector_of};
use crate::sandbox::template::RUNTIME_CLASS_CONFIDENTIAL;

/// `None` when the count can't be known: the RuntimeClass or the nodes can't
/// be read, or the RuntimeClass names no nodes, which would count every node.
pub(super) async fn count(client: &kube::Client) -> Option<u32> {
    let (_, node_selector) = read_runtime_classes(client, &[RUNTIME_CLASS_CONFIDENTIAL])
        .await
        .map_err(|error| tracing::warn!(%error, "confidential RuntimeClass unreadable"))
        .ok()?;
    if node_selector.is_empty() {
        tracing::warn!("the confidential RuntimeClass schedules to no labelled nodes");
        return None;
    }
    let nodes = Api::<Node>::all(client.clone())
        .list(&ListParams::default().labels(&selector_of(&node_selector)))
        .await
        .map_err(|error| tracing::warn!(%error, "confidential nodes unreadable"))
        .ok()?
        .items;
    u32::try_from(nodes.iter().filter(|node| can_run_members(node)).count()).ok()
}

/// Ready and not cordoned.
fn can_run_members(node: &Node) -> bool {
    let schedulable = !node
        .spec
        .as_ref()
        .and_then(|spec| spec.unschedulable)
        .unwrap_or(false);
    let ready = node
        .status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        });
    schedulable && ready
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{NodeCondition, NodeSpec, NodeStatus};

    use super::*;

    fn node(ready: &str, unschedulable: Option<bool>) -> Node {
        Node {
            spec: Some(NodeSpec {
                unschedulable,
                ..Default::default()
            }),
            status: Some(NodeStatus {
                conditions: Some(vec![NodeCondition {
                    type_: "Ready".into(),
                    status: ready.into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn only_ready_schedulable_nodes_run_members() {
        assert!(can_run_members(&node("True", None)));
        assert!(can_run_members(&node("True", Some(false))));
        assert!(!can_run_members(&node("True", Some(true))));
        assert!(!can_run_members(&node("False", None)));
        assert!(!can_run_members(&node("Unknown", None)));
        assert!(!can_run_members(&Node::default()));
    }
}
