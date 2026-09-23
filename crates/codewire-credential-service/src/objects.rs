use codewire_access::{
    MANAGED_CREDENTIAL_CLIENTS_ENV, ManagedCredentialClient, ManagedCredentialClients,
};
use codewire_credential_broker::platform::PlatformRuntimeError as Error;
use codewire_server_core::pod_identity::VerifiedPodIdentity;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Api, Client};
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
    replica_set_uid: String,
    deployment_uid: String,
    sandbox_uid: String,
    claim_uid: String,
    managed_github: bool,
}

impl Lineage {
    /// Whether orchestration rendered the verified workspace with the managed
    /// GitHub client: the creator's recorded choice, fixed for this Pod.
    pub(crate) fn managed_github(&self) -> bool {
        self.managed_github
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

pub(crate) fn gateway_environment(pod: &Pod) -> Result<String, Error> {
    let labels = pod.metadata.labels.as_ref().ok_or(Error::Denied)?;
    let environment = labels.get(ENVIRONMENT).ok_or(Error::Denied)?;
    if !valid_uid(environment) || labels.get(ROLE).map(String::as_str) != Some("gateway") {
        return Err(Error::Denied);
    }
    Ok(environment.clone())
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

pub(crate) fn gateway_chain(
    scope: &Scope,
    pod: &Pod,
    replica_set: &ReplicaSet,
    deployment: &Deployment,
) -> Result<(String, String), Error> {
    association(&pod.metadata, scope, "gateway")?;
    let rs_owner = controller(&pod.metadata, "apps/v1", "ReplicaSet")?;
    let rs_uid = live_metadata(&replica_set.metadata, &scope.namespace, &rs_owner.name)?;
    if rs_uid != rs_owner.uid {
        return Err(Error::Denied);
    }
    association(&replica_set.metadata, scope, "gateway")?;
    let deployment_owner = controller(&replica_set.metadata, "apps/v1", "Deployment")?;
    // Environment IDs are canonical UUIDs, so this is exactly the existing
    // orchestration gateway_workload_name convention without truncation/aliasing.
    let name = format!("cw-gateway-{}", scope.environment_id);
    let deployment_uid = live_metadata(&deployment.metadata, &scope.namespace, &name)?;
    if deployment_owner.name != name || deployment_owner.uid != deployment_uid {
        return Err(Error::Denied);
    }
    association(&deployment.metadata, scope, "gateway")?;
    let template = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .ok_or(Error::Denied)?;
    association(template, scope, "gateway")?;
    let generation = deployment
        .metadata
        .generation
        .filter(|generation| *generation > 0)
        .ok_or(Error::Denied)?;
    let status = deployment.status.as_ref().ok_or(Error::Denied)?;
    let available: Vec<_> = status
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|condition| condition.type_ == "Available")
        .collect();
    if status
        .observed_generation
        .is_none_or(|observed| observed < generation)
        || status.available_replicas.unwrap_or(0) <= 0
        || !matches!(available.as_slice(), [condition] if condition.status == "True")
    {
        return Err(Error::Denied);
    }
    Ok((rs_uid.into(), deployment_uid.into()))
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

pub(crate) async fn validate_lineage(
    client: &Client,
    scope: &Scope,
    gateway: &Pod,
    workspace_identity: &VerifiedPodIdentity,
) -> Result<Lineage, Error> {
    if !valid_name(&scope.claim_name, false)
        || !valid_uid(&scope.claim_uid)
        || scope.pod_name != workspace_identity.pod_name()
        || scope.namespace != workspace_identity.namespace()
    {
        return Err(Error::Denied);
    }
    let rs_owner = controller(&gateway.metadata, "apps/v1", "ReplicaSet")?;
    let replica_set: ReplicaSet = Api::namespaced(client.clone(), &scope.namespace)
        .get(&rs_owner.name)
        .await
        .map_err(kube_error)?;
    let deployment: Deployment = Api::namespaced(client.clone(), &scope.namespace)
        .get(&format!("cw-gateway-{}", scope.environment_id))
        .await
        .map_err(kube_error)?;
    let (replica_set_uid, deployment_uid) =
        gateway_chain(scope, gateway, &replica_set, &deployment)?;
    let claim = dynamic(
        client.clone(),
        &scope.namespace,
        "extensions.agents.x-k8s.io",
        "SandboxClaim",
        "sandboxclaims",
    )
    .get(&scope.claim_name)
    .await
    .map_err(kube_error)?;
    let sandbox_name = claim
        .data
        .pointer("/status/sandbox/name")
        .and_then(Value::as_str)
        .filter(|name| valid_name(name, false))
        .ok_or(Error::Denied)?;
    let sandbox = dynamic(
        client.clone(),
        &scope.namespace,
        "agents.x-k8s.io",
        "Sandbox",
        "sandboxes",
    )
    .get(sandbox_name)
    .await
    .map_err(kube_error)?;
    let workspace: Pod = Api::namespaced(client.clone(), &scope.namespace)
        .get(&scope.pod_name)
        .await
        .map_err(kube_error)?;
    live_pod(&workspace, workspace_identity)?;
    let (claim_uid, sandbox_uid) = workspace_chain(scope, &claim, &sandbox, &workspace)?;
    let managed_github =
        rendered_managed_clients(&workspace)?.contains(ManagedCredentialClient::GitHub);
    Ok(Lineage {
        replica_set_uid,
        deployment_uid,
        sandbox_uid,
        claim_uid,
        managed_github,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(environment: Value) -> Pod {
        serde_json::from_value(serde_json::json!({
            "spec": {"containers": [
                {"name": "codewire-gateway", "env": [
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
