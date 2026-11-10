//! Whether a shared warm pool can take a claim (Program #2238 C3).

use kube::api::DynamicObject;
use serde_json::Value;

use super::super::PoolState;
use crate::sandbox::client::SandboxClient;
use crate::sandbox::warm_pool::{
    POOL_REVISION_ANNOTATION, WarmPoolObjects, has_pool_labels, pod_spec_pool_revision,
};
use crate::worker::warm_pool::{pool_observed_by_capable_controller, template_spec_current};

/// Claim only on a capable controller, a current pool and template, and
/// current members. Members are read only once the rest holds.
pub(super) async fn pool_state(
    client: &SandboxClient,
    objects: &WarmPoolObjects,
) -> anyhow::Result<PoolState> {
    let (pool, template) = client.warm_pool_objects(&objects.name).await?;
    let Some(pool) = pool else {
        return Ok(PoolState::NotCurrent);
    };
    if !pool_observed_by_capable_controller(&pool) {
        return Ok(PoolState::ControllerIncapable);
    }
    if !live_pool_current(Some(&pool), template.as_ref(), objects) {
        return Ok(PoolState::NotCurrent);
    }
    let members = client.warm_pool_members(&objects.name).await?;
    if !members_current(&members, &objects.revision) {
        return Ok(PoolState::StaleMembers);
    }
    Ok(PoolState::Claimable)
}

/// The pool and its template are Codewire's, not terminating, at this
/// replica's revision, the template's spec is this replica's rendering
/// (review L5), and the pool holds members.
pub(crate) fn live_pool_current(
    pool: Option<&DynamicObject>,
    template: Option<&DynamicObject>,
    objects: &WarmPoolObjects,
) -> bool {
    let at_revision = |object: &DynamicObject| {
        object.metadata.deletion_timestamp.is_none()
            && has_pool_labels(object.metadata.labels.as_ref())
            && object
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(POOL_REVISION_ANNOTATION))
                == Some(&objects.revision)
    };
    let (Some(pool), Some(template)) = (pool, template) else {
        return false;
    };
    at_revision(pool)
        && at_revision(template)
        && template_spec_current(template, &objects.template)
        && pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            == Some(objects.name.as_str())
        && pool
            .data
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            .is_some_and(|replicas| replicas > 0)
}

/// Every unclaimed, non-terminating member booted from `revision`: its Pod
/// spec carries exactly that marker (review M1). The controller could adopt
/// any of them.
pub(crate) fn members_current(members: &[DynamicObject], revision: &str) -> bool {
    members
        .iter()
        .filter(|member| member.metadata.deletion_timestamp.is_none())
        .all(|member| {
            member
                .data
                .pointer("/spec/podTemplate/spec")
                .and_then(pod_spec_pool_revision)
                == Some(revision)
        })
}
