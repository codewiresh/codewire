//! The bind's checks as they read Kubernetes objects before #3628 PR 5a, kept
//! verbatim as the reference the fact-reading checks are proven equal to.

#![allow(dead_code)]

use std::collections::BTreeMap;

use codewire_daemon_proto::{SANDBOX_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod};
use kube::api::DynamicObject;

use super::{
    CapturedBootstrap, DAEMON_AUTH_TOKEN_ENV, GENERATION_ENV, MANAGED_CLIENTS_ENV,
    PROJECTION_SHA256_ENV, WORKSPACE_BINDING_VOLUME, WorkspaceCredentialScope,
};
use crate::sandbox::LABEL_OPERATION_GENERATION;
use crate::sandbox::client::WorkspacePvc;

/// Which credential a Pod was rendered with (design §5.5). A binding-mode Pod
/// mounts the binding token; a legacy Pod carries the environment token in its
/// `workspace` container. Both or neither is refused.
pub(crate) fn credential_scope(pod: &Pod) -> Option<WorkspaceCredentialScope> {
    let spec = pod.spec.as_ref()?;
    let binding_volume = spec.volumes.iter().flatten().any(|volume| {
        volume.name == WORKSPACE_BINDING_VOLUME
            && volume
                .projected
                .as_ref()
                .and_then(|projected| projected.sources.as_ref())
                .is_some_and(|sources| {
                    sources.iter().any(|source| {
                        source.service_account_token.as_ref().is_some_and(|token| {
                            token.audience.as_deref() == Some(WORKSPACE_BINDING_TOKEN_AUDIENCE)
                        })
                    })
                })
    });
    let environment_token = workspace_container(pod).is_some_and(|container| {
        env_entries(container, DAEMON_AUTH_TOKEN_ENV)
            .next()
            .is_some()
    });
    match (binding_volume, environment_token) {
        (true, false) => Some(WorkspaceCredentialScope::Pod),
        (false, true) => Some(WorkspaceCredentialScope::Environment),
        _ => None,
    }
}

fn workspace_container(pod: &Pod) -> Option<&Container> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .find(|container| container.name == "workspace")
}

fn env_entries<'a>(
    container: &'a Container,
    name: &'a str,
) -> impl Iterator<Item = &'a k8s_openapi::api::core::v1::EnvVar> + 'a {
    container
        .env
        .iter()
        .flatten()
        .filter(move |variable| variable.name == name)
}

/// One literal value, or absent. Duplicates and `valueFrom` are refused.
fn literal_env<'a>(container: &'a Container, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = container
        .env
        .iter()
        .flatten()
        .filter(|variable| variable.name == name);
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(variable), None) if variable.value_from.is_none() => {
            Ok(Some(variable.value.as_deref().unwrap_or_default()))
        }
        _ => Err(()),
    }
}

/// A legacy (environment-scope) Pod: what it was rendered with, so the record
/// matches what the broker reads from it today. A Pod rendered without a
/// projection carries no generation variable; its converged generation label
/// stands in.
pub(crate) fn environment_scope_capture(pod: &Pod) -> Option<CapturedBootstrap> {
    let container = workspace_container(pod)?;
    let generation = match literal_env(container, GENERATION_ENV).ok()? {
        Some(value) => value.parse::<i64>().ok()?,
        None => pod
            .metadata
            .labels
            .as_ref()?
            .get(LABEL_OPERATION_GENERATION)?
            .parse::<i64>()
            .ok()?,
    };
    let digest = literal_env(container, PROJECTION_SHA256_ENV).ok()?;
    if digest.is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return None;
    }
    let clients = match literal_env(container, MANAGED_CLIENTS_ENV).ok()? {
        Some(value) => codewire_access::ManagedCredentialClients::decode(value).ok()?,
        None => codewire_access::ManagedCredentialClients::default(),
    };
    (generation > 0).then(|| CapturedBootstrap {
        operation_generation: generation,
        projection_selection_sha256: digest.map(str::to_owned),
        managed_credential_clients: clients.encode().to_owned(),
    })
}

fn template_images(sandbox: &DynamicObject, pointer: &str) -> Option<BTreeMap<String, String>> {
    let Some(containers) = sandbox.data.pointer(pointer) else {
        return Some(BTreeMap::new());
    };
    let mut images = BTreeMap::new();
    for container in containers.as_array()? {
        let name = container.get("name")?.as_str()?.to_owned();
        let image = container.get("image")?.as_str()?.to_owned();
        if images.insert(name, image).is_some() {
            return None;
        }
    }
    Some(images)
}

fn pod_images(containers: &[Container]) -> Option<BTreeMap<String, String>> {
    let mut images = BTreeMap::new();
    for container in containers {
        if images
            .insert(container.name.clone(), container.image.clone()?)
            .is_some()
        {
            return None;
        }
    }
    Some(images)
}

fn pinned_digest(reference: &str) -> Option<&str> {
    reference
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .filter(|digest| digest.starts_with("sha256:"))
}

fn status_digest(image_id: &str) -> &str {
    image_id
        .rsplit_once('@')
        .map_or(image_id, |(_, digest)| digest)
}

/// Design §5.3: every container and init-container image equals the owning
/// Sandbox's pod template, and each digest-pinned reference matches the
/// digest the kubelet reports for that container.
pub(crate) fn images_match(sandbox: &DynamicObject, pod: &Pod) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return false;
    };
    let (Some(containers), Some(init_containers)) = (
        pod_images(&spec.containers),
        pod_images(spec.init_containers.as_deref().unwrap_or_default()),
    ) else {
        return false;
    };
    if Some(&containers) != template_images(sandbox, "/spec/podTemplate/spec/containers").as_ref()
        || Some(&init_containers)
            != template_images(sandbox, "/spec/podTemplate/spec/initContainers").as_ref()
    {
        return false;
    }
    let status = pod.status.as_ref();
    let statuses: Vec<&ContainerStatus> = status
        .into_iter()
        .flat_map(|status| {
            status
                .container_statuses
                .iter()
                .flatten()
                .chain(status.init_container_statuses.iter().flatten())
        })
        .collect();
    containers
        .iter()
        .chain(init_containers.iter())
        .all(|(name, image)| match pinned_digest(image) {
            None => true,
            Some(digest) => statuses
                .iter()
                .find(|status| &status.name == name)
                .is_some_and(|status| status_digest(&status.image_id) == digest),
        })
}

/// Design §5.2 on a re-read Pod: the observed UID, not terminating, the
/// sandbox service account, and the observed Sandbox controller.
pub(crate) fn pod_still_observed(pod: &Pod, pod_uid: &str, sandbox_uid: &str) -> bool {
    pod.metadata.uid.as_deref() == Some(pod_uid)
        && pod.metadata.deletion_timestamp.is_none()
        && pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            == Some(SANDBOX_SERVICE_ACCOUNT)
        && pod
            .metadata
            .owner_references
            .iter()
            .flatten()
            .filter(|owner| owner.controller == Some(true))
            .map(|owner| (owner.kind.as_str(), owner.uid.as_str()))
            .eq([("Sandbox", sandbox_uid)])
}

/// The PVC named by the Pod's `workspace` volume, or `None` when it has none.
fn workspace_volume_claim(pod: &Pod) -> Option<&str> {
    pod.spec
        .as_ref()?
        .volumes
        .iter()
        .flatten()
        .find(|volume| volume.name == "workspace")?
        .persistent_volume_claim
        .as_ref()
        .map(|claim| claim.claim_name.as_str())
}

/// Design §5.4: the Pod mounts exactly the resolved PVC, which is Bound, or
/// no workspace PVC at all for a volume-less environment.
pub(crate) fn pvc_matches(pod: &Pod, pvc: &WorkspacePvc) -> bool {
    match pvc {
        WorkspacePvc::VolumeLess => workspace_volume_claim(pod).is_none(),
        WorkspacePvc::Claim { name, bound, .. } => {
            *bound && workspace_volume_claim(pod) == Some(name.as_str())
        }
    }
}
