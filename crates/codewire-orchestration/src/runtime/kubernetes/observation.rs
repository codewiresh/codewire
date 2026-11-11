//! Raw facts from the agent-sandbox objects, for the bind's checks (#3628 PR
//! 5a). Each is read off the object exactly as the check that consumes it read
//! it before; the checks themselves stay in orchestration.

use k8s_openapi::api::core::v1::{Container, Pod};
use kube::api::DynamicObject;

use super::super::observation::{
    ContainerFact, ControllerFact, EnvFact, MemberFacts, RuntimeFacts, RuntimeObservation,
    VerifiedChain, VolumeFact,
};
use crate::sandbox::client::BindableRuntime;
use crate::sandbox::template::SANDBOX_UID_LABEL;

fn container_fact(container: &Container) -> ContainerFact {
    ContainerFact {
        name: container.name.clone(),
        image: container.image.clone(),
        env: container
            .env
            .iter()
            .flatten()
            .map(|variable| EnvFact {
                name: variable.name.clone(),
                value: variable.value.clone(),
                from_source: variable.value_from.is_some(),
            })
            .collect(),
    }
}

pub(crate) fn member_facts(pod: &Pod) -> anyhow::Result<MemberFacts> {
    let spec = pod.spec.as_ref();
    let status = pod.status.as_ref();
    Ok(MemberFacts {
        name: pod.metadata.name.clone(),
        uid: pod.metadata.uid.clone(),
        terminating: pod.metadata.deletion_timestamp.is_some(),
        service_account: spec.and_then(|spec| spec.service_account_name.clone()),
        controllers: pod
            .metadata
            .owner_references
            .iter()
            .flatten()
            .filter(|owner| owner.controller == Some(true))
            .map(|owner| ControllerFact {
                kind: owner.kind.clone(),
                uid: owner.uid.clone(),
            })
            .collect(),
        labels: pod.metadata.labels.clone().unwrap_or_default(),
        has_spec: spec.is_some(),
        volumes: spec
            .into_iter()
            .flat_map(|spec| spec.volumes.iter().flatten())
            .map(|volume| VolumeFact {
                name: volume.name.clone(),
                token_audiences: volume
                    .projected
                    .iter()
                    .flat_map(|projected| projected.sources.iter().flatten())
                    .filter_map(|source| source.service_account_token.as_ref()?.audience.clone())
                    .collect(),
                claim_name: volume
                    .persistent_volume_claim
                    .as_ref()
                    .map(|claim| claim.claim_name.clone()),
            })
            .collect(),
        containers: spec
            .into_iter()
            .flat_map(|spec| spec.containers.iter())
            .map(container_fact)
            .collect(),
        init_containers: spec
            .into_iter()
            .flat_map(|spec| spec.init_containers.iter().flatten())
            .map(container_fact)
            .collect(),
        image_ids: status
            .into_iter()
            .flat_map(|status| {
                status
                    .container_statuses
                    .iter()
                    .flatten()
                    .chain(status.init_container_statuses.iter().flatten())
            })
            .map(|status| (status.name.clone(), status.image_id.clone()))
            .collect(),
        ip: status
            .and_then(|status| status.pod_ip.clone())
            .unwrap_or_default(),
        spec_json: serde_json::to_value(&pod.spec)?,
    })
}

pub(crate) fn runtime_facts(sandbox: &DynamicObject) -> anyhow::Result<RuntimeFacts> {
    Ok(RuntimeFacts {
        labels: sandbox.metadata.labels.clone().unwrap_or_default(),
        template_containers: sandbox
            .data
            .pointer("/spec/podTemplate/spec/containers")
            .cloned(),
        template_init_containers: sandbox
            .data
            .pointer("/spec/podTemplate/spec/initContainers")
            .cloned(),
        json: serde_json::to_value(sandbox)?,
    })
}

/// The observation of one chain read. Its chain is the read's own verified
/// one, so this is the only way an observation is built.
pub(crate) fn observation(
    claim_uid: &str,
    runtime: BindableRuntime,
) -> anyhow::Result<RuntimeObservation> {
    let member = member_facts(&runtime.pod)?;
    let birth_runtime_uid = member.labels.get(SANDBOX_UID_LABEL).cloned();
    Ok(RuntimeObservation {
        runtime: runtime_facts(&runtime.sandbox)?,
        chain: VerifiedChain::new(runtime.observation, claim_uid.to_owned(), birth_runtime_uid),
        claim_name: runtime.claim.metadata.name.clone().unwrap_or_default(),
        claim_revision: runtime
            .claim
            .metadata
            .resource_version
            .clone()
            .unwrap_or_default(),
        member_revision: runtime
            .pod
            .metadata
            .resource_version
            .clone()
            .unwrap_or_default(),
        member,
        converged: runtime.converged,
        bind_ready: runtime.bind_ready,
        pool: runtime.warm_pool_ref,
    })
}
