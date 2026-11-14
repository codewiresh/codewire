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

/// The two containers the pool rendering runs privileged and as root.
const ROOT_CONTAINERS: [&str; 2] = ["dind", crate::sandbox::template::MOUNT_WORKSPACE_CONTAINER];

fn absent_or_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => items.is_empty(),
        Some(Value::Object(map)) => map.is_empty(),
        Some(_) => false,
    }
}

/// The value's one key besides `name`, or `None` when it has none or more.
fn single_source(object: &Value) -> Option<(&str, &Value)> {
    let mut sources = object
        .as_object()?
        .iter()
        .filter(|(key, _)| key.as_str() != "name");
    match (sources.next(), sources.next()) {
        (Some((key, value)), None) => Some((key.as_str(), value)),
        _ => None,
    }
}

/// Program #2238 C3, cw-confidential's #3628 PR 5c condition 3: the
/// isolation of a pool-born member, checked over its own Pod spec on its
/// first bind whatever the driver says of its pool. Every property here is
/// one the pool rendering sets and that matters for isolation; anything it
/// does not know is refused. `Err` names the first path that differs.
pub(crate) fn pool_member_isolated(
    spec: &Value,
    opts: &crate::sandbox::template::TemplateOpts,
) -> Result<(), String> {
    use codewire_daemon_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE;

    let profile = opts.runtime_profile_spec();
    // 1. The VM runtime of the pool's own profile, never a confidential one.
    if profile.profile == crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL
        || spec
            .get("runtimeClassName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            != profile.runtime_class_name
    {
        return Err("/runtimeClassName".to_owned());
    }
    // 2. The Pod's own settings.
    for (key, expected) in [
        ("automountServiceAccountToken", false),
        ("enableServiceLinks", false),
    ] {
        if spec.get(key) != Some(&Value::Bool(expected)) {
            return Err(format!("/{key}"));
        }
    }
    for key in ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"] {
        if spec
            .get(key)
            .is_some_and(|value| value != &Value::Bool(false))
        {
            return Err(format!("/{key}"));
        }
    }
    if !absent_or_empty(spec.get("ephemeralContainers")) {
        return Err("/ephemeralContainers".to_owned());
    }
    let pod_context = spec.get("securityContext");
    // Every container gets these groups, so none of them is root's.
    for key in ["runAsUser", "runAsGroup", "fsGroup"] {
        if pod_context.and_then(|context| context.get(key)) != Some(&Value::from(1000)) {
            return Err(format!("/securityContext/{key}"));
        }
    }
    for key in ["supplementalGroups", "sysctls"] {
        if !absent_or_empty(pod_context.and_then(|context| context.get(key))) {
            return Err(format!("/securityContext/{key}"));
        }
    }
    // 3. Volumes, one source each, of the kinds the rendering uses.
    let support_image = opts.effective_support_image();
    let mut token_volumes = std::collections::BTreeSet::new();
    for (index, volume) in spec
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let at = format!("/volumes/{index}");
        let name = volume.get("name").and_then(Value::as_str);
        let Some((kind, source)) = single_source(volume) else {
            return Err(at);
        };
        match kind {
            "emptyDir" | "configMap" => {}
            // The workspace claim, which `volume_matches` resolves by UID.
            "persistentVolumeClaim" if name == Some("workspace") => {}
            "image" if source.get("reference").and_then(Value::as_str) == Some(support_image) => {}
            "projected" => {
                let sources = source.get("sources").and_then(Value::as_array);
                for (position, projection) in sources.into_iter().flatten().enumerate() {
                    match single_source(projection) {
                        Some(("serviceAccountToken", token))
                            if matches!(
                                token.get("audience").and_then(Value::as_str),
                                Some(WORKSPACE_BINDING_TOKEN_AUDIENCE)
                                    | Some(CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE)
                            ) =>
                        {
                            token_volumes.extend(name);
                        }
                        Some(("configMap" | "downwardAPI", _)) => {}
                        _ => return Err(format!("{at}/projected/sources/{position}")),
                    }
                }
            }
            other => return Err(format!("{at}/{other}")),
        }
    }
    // 4. Containers: root only where the rendering grants it, with its image.
    for field in ["initContainers", "containers"] {
        for (index, container) in spec
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let at = format!("/{field}/{index}");
            let name = container
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let image = container.get("image").and_then(Value::as_str);
            let context = container.get("securityContext");
            let set = |key: &str| context.and_then(|context| context.get(key));
            let root = set("privileged") == Some(&Value::Bool(true))
                || set("runAsUser") == Some(&Value::from(0))
                || set("runAsGroup") == Some(&Value::from(0));
            let root_image = match name {
                "dind" => Some(crate::sandbox::template::dind_image(opts)),
                name if ROOT_CONTAINERS.contains(&name) => Some(support_image),
                _ => None,
            };
            if root && (root_image.is_none() || image != root_image) {
                return Err(format!("{at}/securityContext"));
            }
            if !absent_or_empty(set("capabilities").and_then(|caps| caps.get("add"))) {
                return Err(format!("{at}/securityContext/capabilities/add"));
            }
            if set("allowPrivilegeEscalation") == Some(&Value::Bool(true)) {
                return Err(format!("{at}/securityContext/allowPrivilegeEscalation"));
            }
            if set("procMount").is_some_and(|mount| mount != "Default") {
                return Err(format!("{at}/securityContext/procMount"));
            }
            for (position, port) in container
                .get("ports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                if port
                    .get("hostPort")
                    .is_some_and(|host| host != &Value::from(0))
                {
                    return Err(format!("{at}/ports/{position}/hostPort"));
                }
            }
            // (a) A token is mounted only into the workspace container.
            for (position, mount) in container
                .get("volumeMounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let volume = mount
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if token_volumes.contains(volume) && name != "workspace" {
                    return Err(format!("{at}/volumeMounts/{position}"));
                }
            }
        }
    }
    Ok(())
}
