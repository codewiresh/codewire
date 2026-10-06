use std::fmt::Debug;
use std::future::Future;

use codewire_access::{
    MANAGED_CREDENTIAL_CLIENTS_ENV, ManagedCredentialClient, ManagedCredentialClients,
};
use codewire_credential_broker::platform::PlatformRuntimeError as Error;
use codewire_server_core::pod_identity::VerifiedPodIdentity;
use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::authority::{Scope, kube_error};

const ENVIRONMENT: &str = "codewire.sh/environment-id";
const ORGANIZATION: &str = "codewire.sh/org-id";
const ROLE: &str = "codewire.sh/type";
const OPERATION_GENERATION: &str = "codewire.sh/environment-operation-generation";
const SANDBOX_API: &str = "agents.x-k8s.io/v1beta1";
const CLAIM_API: &str = "extensions.agents.x-k8s.io/v1beta1";

#[derive(PartialEq, Eq)]
pub(crate) struct Lineage {
    sandbox_uid: String,
    claim_uid: String,
    managed_github: bool,
}

impl Lineage {
    /// Whether orchestration bound the verified workspace with the managed
    /// GitHub client: the creator's recorded choice, fixed for this Pod by its
    /// binding.
    pub(crate) fn managed_github(&self) -> bool {
        self.managed_github
    }
}

/// The name one resolve read its Claim's Sandbox under: the one lineage object
/// whose name only another object's fresh read gives. An epoch keeps its
/// admission resolve's name, as a string and never as an object, so that each
/// later resolve can issue every lineage read at once. It is a read hint, not
/// authority: every object is still read fresh and checked, and a Sandbox whose
/// fresh Claim names another is read again under that name.
///
/// Backstop: Kubernetes names are immutable and UIDs unique, so a fresh name
/// that differs from the admission's always means a different UID. The
/// epoch's `lineage` equality (`same_authority`) then denies that request
/// whatever the re-read finds; the re-read only selects the error.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LineageNames {
    pub(crate) sandbox: String,
}

/// Credential scope of a claim-time binding (Program #2238 B2): the Pod
/// fetched its daemon credential from its binding.
const BINDING_SCOPE_POD: &str = "pod";
/// Credential scope of a pre-binding Pod, which still carries the environment
/// token and its rendered managed clients until it restarts.
const BINDING_SCOPE_ENVIRONMENT: &str = "environment";

/// The managed clients fixed for the bound workspace Pod: the canonical
/// selection orchestration recorded with its binding. A malformed value or an
/// unknown scope is denied. A pre-binding (`environment`) Pod must still carry
/// the same selection in its rendered environment, so both sources agree; a
/// claim-time (`pod`) Pod carries none, and its environment is not consulted.
pub(crate) fn binding_managed_clients(
    scope: &Scope,
    workspace: &Pod,
) -> Result<ManagedCredentialClients, Error> {
    let recorded = ManagedCredentialClients::decode(&scope.managed_credential_clients)
        .map_err(|_| Error::Denied)?;
    match scope.credential_scope.as_str() {
        BINDING_SCOPE_POD => Ok(recorded),
        BINDING_SCOPE_ENVIRONMENT if rendered_managed_clients(workspace)? == recorded => {
            Ok(recorded)
        }
        _ => Err(Error::Denied),
    }
}

/// The managed clients orchestration rendered into the workspace container.
/// Absent (no such container or variable) means none, which never authorizes
/// a client; a malformed or duplicated value is denied.
fn rendered_managed_clients(workspace: &Pod) -> Result<ManagedCredentialClients, Error> {
    let Some(container) = workspace.spec.as_ref().and_then(|spec| {
        spec.containers
            .iter()
            .find(|container| container.name == "workspace")
    }) else {
        return Ok(ManagedCredentialClients::default());
    };
    let mut values = container
        .env
        .iter()
        .flatten()
        .filter(|variable| variable.name == MANAGED_CREDENTIAL_CLIENTS_ENV);
    let clients = match (values.next(), values.next()) {
        (None, _) => ManagedCredentialClients::default(),
        (Some(variable), None) if variable.value_from.is_none() => variable
            .value
            .as_deref()
            .map(ManagedCredentialClients::decode)
            .ok_or(Error::Denied)?
            .map_err(|_| Error::Denied)?,
        _ => return Err(Error::Denied),
    };
    Ok(clients)
}

pub(crate) fn valid_name(value: &str, namespace: bool) -> bool {
    let max = if namespace { 63 } else { 253 };
    !value.is_empty()
        && value.len() <= max
        && (!namespace || !value.contains('.'))
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_uid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
}

pub(crate) fn verified_shape(identity: &VerifiedPodIdentity) -> Result<(), Error> {
    if !valid_name(identity.namespace(), true)
        || !valid_name(identity.pod_name(), false)
        || !valid_uid(identity.pod_uid())
    {
        return Err(Error::Denied);
    }
    Ok(())
}

fn live_metadata<'a>(
    metadata: &'a ObjectMeta,
    namespace: &str,
    name: &str,
) -> Result<&'a str, Error> {
    let uid = metadata
        .uid
        .as_deref()
        .filter(|value| valid_uid(value))
        .ok_or(Error::Denied)?;
    if !valid_name(namespace, true)
        || !valid_name(name, false)
        || metadata.namespace.as_deref() != Some(namespace)
        || metadata.name.as_deref() != Some(name)
        || metadata.deletion_timestamp.is_some()
    {
        return Err(Error::Denied);
    }
    Ok(uid)
}

pub(crate) fn live_pod(pod: &Pod, identity: &VerifiedPodIdentity) -> Result<(), Error> {
    verified_shape(identity)?;
    if live_metadata(&pod.metadata, identity.namespace(), identity.pod_name())?
        != identity.pod_uid()
        || pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            != Some(identity.purpose().service_account())
    {
        return Err(Error::Denied);
    }
    let status = pod.status.as_ref().ok_or(Error::Denied)?;
    let ready: Vec<_> = status
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|condition| condition.type_ == "Ready")
        .collect();
    if status.phase.as_deref() != Some("Running")
        || !matches!(ready.as_slice(), [condition] if condition.status == "True")
    {
        return Err(Error::Denied);
    }
    Ok(())
}

fn association(metadata: &ObjectMeta, scope: &Scope, role: &str) -> Result<(), Error> {
    let labels = metadata.labels.as_ref().ok_or(Error::Denied)?;
    let generation = scope.generation.to_string();
    for (key, expected) in [
        (ENVIRONMENT, scope.environment_id.as_str()),
        (ORGANIZATION, scope.organization.as_str()),
        (ROLE, role),
        (OPERATION_GENERATION, generation.as_str()),
    ] {
        if labels.get(key).map(String::as_str) != Some(expected) {
            return Err(Error::Denied);
        }
    }
    if scope.generation <= 0 {
        return Err(Error::Denied);
    }
    Ok(())
}

fn controller<'a>(
    metadata: &'a ObjectMeta,
    api: &str,
    kind: &str,
) -> Result<&'a OwnerReference, Error> {
    let mut owners = metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|owner| owner.controller == Some(true));
    match (owners.next(), owners.next()) {
        (Some(owner), None)
            if owner.api_version == api
                && owner.kind == kind
                && valid_name(&owner.name, false)
                && valid_uid(&owner.uid) =>
        {
            Ok(owner)
        }
        _ => Err(Error::Denied),
    }
}

fn ready(object: &DynamicObject, expected_generation: Option<i64>) -> Result<(), Error> {
    let ready: Vec<_> = object
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .ok_or(Error::Denied)?
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Ready"))
        .collect();
    let [condition] = ready.as_slice() else {
        return Err(Error::Denied);
    };
    if condition.get("status").and_then(Value::as_str) != Some("True")
        || expected_generation.is_some_and(|generation| {
            generation <= 0
                || condition.get("observedGeneration").and_then(Value::as_i64) != Some(generation)
        })
    {
        return Err(Error::Denied);
    }
    Ok(())
}

pub(crate) fn workspace_chain(
    scope: &Scope,
    claim: &DynamicObject,
    sandbox: &DynamicObject,
    pod: &Pod,
) -> Result<(String, String), Error> {
    if claim
        .types
        .as_ref()
        .is_none_or(|types| types.api_version != CLAIM_API || types.kind != "SandboxClaim")
        || sandbox
            .types
            .as_ref()
            .is_none_or(|types| types.api_version != SANDBOX_API || types.kind != "Sandbox")
    {
        return Err(Error::Denied);
    }
    let claim_uid = live_metadata(&claim.metadata, &scope.namespace, &scope.claim_name)?;
    if claim_uid != scope.claim_uid {
        return Err(Error::Denied);
    }
    association(&claim.metadata, scope, "sandbox")?;
    // Claim Ready forwards the Sandbox's observedGeneration. It is explicitly
    // NOT comparable to Claim.metadata.generation.
    ready(claim, None)?;
    let name = claim
        .data
        .pointer("/status/sandbox/name")
        .and_then(Value::as_str)
        .ok_or(Error::Denied)?;
    let sandbox_uid = live_metadata(&sandbox.metadata, &scope.namespace, name)?;
    let claim_owner = controller(&sandbox.metadata, CLAIM_API, "SandboxClaim")?;
    if claim_owner.name != scope.claim_name || claim_owner.uid != claim_uid {
        return Err(Error::Denied);
    }
    ready(
        sandbox,
        Some(sandbox.metadata.generation.ok_or(Error::Denied)?),
    )?;
    let template: ObjectMeta = serde_json::from_value(
        sandbox
            .data
            .pointer("/spec/podTemplate/metadata")
            .cloned()
            .ok_or(Error::Denied)?,
    )
    .map_err(|_| Error::Denied)?;
    association(&template, scope, "workspace")?;
    association(&pod.metadata, scope, "workspace")?;
    let pod_name = sandbox
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
        .map(String::as_str)
        .unwrap_or(name);
    if pod_name != scope.pod_name || pod.metadata.name.as_deref() != Some(pod_name) {
        return Err(Error::Denied);
    }
    let sandbox_owner = controller(&pod.metadata, SANDBOX_API, "Sandbox")?;
    if sandbox_owner.name != name || sandbox_owner.uid != sandbox_uid {
        return Err(Error::Denied);
    }
    Ok((claim_uid.into(), sandbox_uid.into()))
}

fn dynamic(
    client: Client,
    namespace: &str,
    group: &str,
    kind: &str,
    plural: &str,
) -> Api<DynamicObject> {
    let resource =
        ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(group, "v1beta1", kind), plural);
    Api::namespaced_with(client, namespace, &resource)
}

async fn read<K>(client: &Client, namespace: &str, name: &str) -> Result<K, Error>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    Api::namespaced(client.clone(), namespace)
        .get(name)
        .await
        .map_err(kube_error)
}

/// The Sandbox the Claim's status names.
fn sandbox_name(claim: &DynamicObject) -> Result<&str, Error> {
    claim
        .data
        .pointer("/status/sandbox/name")
        .and_then(Value::as_str)
        .filter(|name| valid_name(name, false))
        .ok_or(Error::Denied)
}

/// A parent object, then the object it names.
///
/// Without an `earlier` name the read follows the parent's, under the name the
/// fresh parent gives. With one, it runs at the same time as the parent's,
/// under that name, and its result, object or error, is kept unexamined until
/// the fresh parent arrives: it is used only when the parent names the same
/// object, and otherwise dropped for a read under the fresh name. So a stale
/// name costs one more read, never a decision. That re-read starts only after
/// the read under the stale name has finished, so a slow stale read delays it.
/// A failed parent read ends this at once; a failed read under the earlier
/// name fails only once the parent confirms that name.
async fn named_by<P, K, F>(
    parent: impl Future<Output = Result<P, Error>>,
    name: fn(&P) -> Result<&str, Error>,
    earlier: Option<&str>,
    read: impl Fn(String) -> F,
) -> Result<(P, K), Error>
where
    F: Future<Output = Result<K, Error>>,
{
    let Some(earlier) = earlier else {
        let parent = parent.await?;
        let object = read(name(&parent)?.to_owned()).await?;
        return Ok((parent, object));
    };
    let (parent, under_earlier) =
        tokio::try_join!(parent, async { Ok(read(earlier.to_owned()).await) })?;
    let fresh = name(&parent)?;
    let object = if fresh == earlier {
        under_earlier?
    } else {
        read(fresh.to_owned()).await?
    };
    Ok((parent, object))
}

/// The bound workspace's live Claim → Sandbox → Pod chain, checked against
/// its recorded binding by UID. `names` are the admission's read hints for a
/// later resolve in the same epoch; admission has none.
pub(crate) async fn validate_lineage(
    client: &Client,
    scope: &Scope,
    names: Option<&LineageNames>,
    workspace_identity: &VerifiedPodIdentity,
) -> Result<(Lineage, LineageNames), Error> {
    // The reviewed workspace Pod must be the one orchestration bound, by UID,
    // and the live binding must name the backend's Claim. Checked before any
    // Kubernetes read.
    if !valid_name(&scope.claim_name, false)
        || !valid_uid(&scope.claim_uid)
        || scope.pod_name != workspace_identity.pod_name()
        || scope.namespace != workspace_identity.namespace()
        || !valid_uid(&scope.pod_uid)
        || scope.pod_uid != workspace_identity.pod_uid()
        || scope.binding_claim_uid != scope.claim_uid
        || !valid_uid(&scope.binding_sandbox_uid)
    {
        return Err(Error::Denied);
    }
    let namespace = scope.namespace.as_str();
    let workspace = read::<Pod>(client, namespace, &scope.pod_name);
    let claim = async {
        dynamic(
            client.clone(),
            namespace,
            "extensions.agents.x-k8s.io",
            "SandboxClaim",
            "sandboxclaims",
        )
        .get(&scope.claim_name)
        .await
        .map_err(kube_error)
    };
    let sandbox = move |name: String| async move {
        dynamic(
            client.clone(),
            namespace,
            "agents.x-k8s.io",
            "Sandbox",
            "sandboxes",
        )
        .get(&name)
        .await
        .map_err(kube_error)
    };
    // The Claim and workspace Pod names are fixed by the scope. Only the
    // Claim's status names the Sandbox. At admission the Sandbox read follows
    // its Claim's; later in the epoch all three run at once, the Sandbox under
    // the admission's name. A failed read ends the resolve and drops the rest,
    // except that a read under an admission's name fails only once its fresh
    // Claim names the same object. No object is compared with another until all
    // are fetched.
    let ((claim, sandbox), workspace) = tokio::try_join!(
        named_by(
            claim,
            sandbox_name,
            names.map(|names| names.sandbox.as_str()),
            sandbox,
        ),
        workspace,
    )?;
    live_pod(&workspace, workspace_identity)?;
    let (claim_uid, sandbox_uid) = workspace_chain(scope, &claim, &sandbox, &workspace)?;
    // The live Claim → Sandbox → Pod chain is the recorded one, by UID. A
    // re-owned or replaced Sandbox under the same names is denied.
    if claim_uid != scope.binding_claim_uid || sandbox_uid != scope.binding_sandbox_uid {
        return Err(Error::Denied);
    }
    let managed_github =
        binding_managed_clients(scope, &workspace)?.contains(ManagedCredentialClient::GitHub);
    let names = LineageNames {
        sandbox: sandbox_name(&claim)?.to_owned(),
    };
    Ok((
        Lineage {
            sandbox_uid,
            claim_uid,
            managed_github,
        },
        names,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(environment: Value) -> Pod {
        serde_json::from_value(serde_json::json!({
            "spec": {"containers": [
                {"name": "other", "env": [
                    {"name": MANAGED_CREDENTIAL_CLIENTS_ENV, "value": "v2:10"}]},
                {"name": "workspace", "env": environment},
            ]}
        }))
        .unwrap()
    }

    #[test]
    fn only_the_workspace_containers_rendered_clients_select_github() {
        let github = ManagedCredentialClients::from_profile_slots(["github"]).unwrap();
        let rendered = workspace(serde_json::json!([
            {"name": MANAGED_CREDENTIAL_CLIENTS_ENV, "value": github.encode()}
        ]));
        assert_eq!(rendered_managed_clients(&rendered), Ok(github));
        // Absent means none, even when another container names GitHub.
        assert_eq!(
            rendered_managed_clients(&workspace(serde_json::json!([]))),
            Ok(ManagedCredentialClients::default())
        );
        for environment in [
            serde_json::json!([{"name": MANAGED_CREDENTIAL_CLIENTS_ENV, "value": "github"}]),
            serde_json::json!([{"name": MANAGED_CREDENTIAL_CLIENTS_ENV}]),
            serde_json::json!([
                {"name": MANAGED_CREDENTIAL_CLIENTS_ENV, "value": "v1:codex"},
                {"name": MANAGED_CREDENTIAL_CLIENTS_ENV, "value": github.encode()},
            ]),
            serde_json::json!([{"name": MANAGED_CREDENTIAL_CLIENTS_ENV,
                "valueFrom": {"configMapKeyRef": {"name": "clients", "key": "value"}}}]),
        ] {
            assert_eq!(
                rendered_managed_clients(&workspace(environment)),
                Err(Error::Denied)
            );
        }
        // A Pod without the workspace container carries no managed clients.
        for pod in [
            serde_json::json!({"spec": {"containers": []}}),
            serde_json::json!({}),
        ] {
            let pod: Pod = serde_json::from_value(pod).unwrap();
            assert_eq!(
                rendered_managed_clients(&pod),
                Ok(ManagedCredentialClients::default())
            );
        }
    }
}
