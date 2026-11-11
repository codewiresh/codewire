//! The bind's checks over what the runtime driver observed (#3628 PR 5a): the
//! same checks as before, line for line, reading raw facts instead of
//! Kubernetes objects. Each is proven equal to its object-reading form by
//! `checks_tests`.

use std::collections::BTreeMap;

use codewire_daemon_proto::{SANDBOX_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use serde_json::Value;

use super::{
    CapturedBootstrap, DAEMON_AUTH_TOKEN_ENV, GENERATION_ENV, MANAGED_CLIENTS_ENV,
    PROJECTION_SHA256_ENV, WORKSPACE_BINDING_VOLUME, WorkspaceCredentialScope,
};
use crate::runtime::{ContainerFact, MemberFacts, RuntimeFacts};
use crate::sandbox::LABEL_OPERATION_GENERATION;
use crate::sandbox::client::WorkspacePvc;

/// Which credential an incarnation was rendered with (design §5.5). A
/// binding-mode one mounts the binding token; a legacy one carries the
/// environment token in its `workspace` container. Both or neither is refused.
pub(crate) fn credential_scope(member: &MemberFacts) -> Option<WorkspaceCredentialScope> {
    if !member.has_spec {
        return None;
    }
    let binding_volume = member.volumes.iter().any(|volume| {
        volume.name == WORKSPACE_BINDING_VOLUME
            && volume
                .token_audiences
                .iter()
                .any(|audience| audience == WORKSPACE_BINDING_TOKEN_AUDIENCE)
    });
    let environment_token = workspace_container(member).is_some_and(|container| {
        container
            .env
            .iter()
            .any(|variable| variable.name == DAEMON_AUTH_TOKEN_ENV)
    });
    match (binding_volume, environment_token) {
        (true, false) => Some(WorkspaceCredentialScope::Pod),
        (false, true) => Some(WorkspaceCredentialScope::Environment),
        _ => None,
    }
}

fn workspace_container(member: &MemberFacts) -> Option<&ContainerFact> {
    member
        .containers
        .iter()
        .find(|container| container.name == "workspace")
}

/// One literal value, or absent. Duplicates and values from a source are
/// refused.
fn literal_env<'a>(container: &'a ContainerFact, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = container
        .env
        .iter()
        .filter(|variable| variable.name == name);
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(variable), None) if !variable.from_source => {
            Ok(Some(variable.value.as_deref().unwrap_or_default()))
        }
        _ => Err(()),
    }
}

/// A legacy (environment-scope) incarnation: what it was rendered with, so
/// the record matches what the broker reads from it today. One rendered
/// without a projection carries no generation variable; its converged
/// generation label stands in.
pub(crate) fn environment_scope_capture(member: &MemberFacts) -> Option<CapturedBootstrap> {
    let container = workspace_container(member)?;
    let generation = match literal_env(container, GENERATION_ENV).ok()? {
        Some(value) => value.parse::<i64>().ok()?,
        None => member
            .labels
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

fn template_images(containers: Option<&Value>) -> Option<BTreeMap<String, String>> {
    let Some(containers) = containers else {
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

fn member_images(containers: &[ContainerFact]) -> Option<BTreeMap<String, String>> {
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
/// runtime's template, and each digest-pinned reference matches the digest
/// the node reports for that container.
pub(crate) fn images_match(runtime: &RuntimeFacts, member: &MemberFacts) -> bool {
    if !member.has_spec {
        return false;
    }
    let (Some(containers), Some(init_containers)) = (
        member_images(&member.containers),
        member_images(&member.init_containers),
    ) else {
        return false;
    };
    if Some(&containers) != template_images(runtime.template_containers.as_ref()).as_ref()
        || Some(&init_containers)
            != template_images(runtime.template_init_containers.as_ref()).as_ref()
    {
        return false;
    }
    containers
        .iter()
        .chain(init_containers.iter())
        .all(|(name, image)| match pinned_digest(image) {
            None => true,
            Some(digest) => member
                .image_ids
                .iter()
                .find(|(status, _)| status == name)
                .is_some_and(|(_, image_id)| status_digest(image_id) == digest),
        })
}

/// Design §5.2 on a re-read incarnation: the observed UID, not terminating,
/// the sandbox service account, and the observed runtime as its controller.
pub(crate) fn member_still_observed(member: &MemberFacts, uid: &str, runtime_uid: &str) -> bool {
    member.uid.as_deref() == Some(uid)
        && !member.terminating
        && member.service_account.as_deref() == Some(SANDBOX_SERVICE_ACCOUNT)
        && member
            .controllers
            .iter()
            .map(|controller| (controller.kind.as_str(), controller.uid.as_str()))
            .eq([("Sandbox", runtime_uid)])
}

/// The volume claim the incarnation's `workspace` volume mounts, or `None`
/// when it has none.
fn workspace_volume_claim(member: &MemberFacts) -> Option<&str> {
    member
        .volumes
        .iter()
        .find(|volume| volume.name == "workspace")?
        .claim_name
        .as_deref()
}

/// Design §5.4: the incarnation mounts exactly the resolved volume, which is
/// bound, or no workspace volume at all for a volume-less environment.
pub(crate) fn volume_matches(member: &MemberFacts, pvc: &WorkspacePvc) -> bool {
    match pvc {
        WorkspacePvc::VolumeLess => workspace_volume_claim(member).is_none(),
        WorkspacePvc::Claim { name, bound, .. } => {
            *bound && workspace_volume_claim(member) == Some(name.as_str())
        }
    }
}
