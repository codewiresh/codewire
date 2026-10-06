//! The one gateway ownership rule.
//!
//! Orchestration's gateway binding and daemon-credential RPCs decide here
//! whether a reviewed gateway Pod acts for an environment. Callers
//! authenticate the Pod (TokenReview, live UID, service account), read the
//! ReplicaSet and Deployment its controller references name, and read the
//! environment's organization, current operation generation and namespace,
//! then call [`authorize`]. This module performs no I/O.
//!
//! The Pod must be the live Pod of its single controlling ReplicaSet, which
//! must be the live ReplicaSet of its single controlling Deployment
//! `cw-gateway-<env>`, each matched by UID in the environment's namespace.
//! The Pod, ReplicaSet, Deployment and Pod template all carry the
//! environment, organization, `type=gateway` and the current operation
//! generation. Deployment availability is not part of the rule.

use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use uuid::Uuid;

pub const ENVIRONMENT_LABEL: &str = "codewire.sh/environment-id";
pub const ORGANIZATION_LABEL: &str = "codewire.sh/org-id";
pub const TYPE_LABEL: &str = "codewire.sh/type";
pub const OPERATION_GENERATION_LABEL: &str = "codewire.sh/environment-operation-generation";
const GATEWAY_TYPE: &str = "gateway";
const GATEWAY_DEPLOYMENT_PREFIX: &str = "cw-gateway-";

/// The environment facts a gateway chain is checked against, from one
/// database read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayEnvironment {
    pub environment_id: String,
    pub organization_id: String,
    pub operation_generation: i64,
    pub namespace: String,
}

/// Value-blind refusal: callers map it to their own denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("gateway is not authorized for this environment")]
pub struct GatewayDenied;

/// A gateway Pod's live controller chain in one namespace, matched by UID:
/// Pod → its single controlling ReplicaSet → that ReplicaSet's single
/// controlling Deployment.
#[derive(Debug)]
pub struct GatewayChain<'a> {
    namespace: &'a str,
    pod: &'a Pod,
    replica_set: &'a ReplicaSet,
    deployment: &'a Deployment,
    deployment_name: &'a str,
}

impl<'a> GatewayChain<'a> {
    /// The ReplicaSet name the Pod's controller reference gives, for the read
    /// that precedes [`GatewayChain::verify`].
    pub fn controlling_replica_set(pod: &Pod) -> Option<&str> {
        single_controller(&pod.metadata, "apps/v1", "ReplicaSet").map(|(name, _)| name)
    }

    /// The Deployment name the ReplicaSet's controller reference gives.
    pub fn controlling_deployment(replica_set: &ReplicaSet) -> Option<&str> {
        single_controller(&replica_set.metadata, "apps/v1", "Deployment").map(|(name, _)| name)
    }

    /// The chain, when every object is live in `namespace` and each controller
    /// reference names the next object's exact UID. The caller has already
    /// matched the Pod to its authenticated identity.
    pub fn verify(
        namespace: &'a str,
        pod: &'a Pod,
        replica_set: &'a ReplicaSet,
        deployment: &'a Deployment,
    ) -> Option<Self> {
        let pod_name = pod.metadata.name.as_deref()?;
        live_uid(&pod.metadata, namespace, pod_name)?;
        let (replica_set_name, replica_set_uid) =
            single_controller(&pod.metadata, "apps/v1", "ReplicaSet")?;
        (live_uid(&replica_set.metadata, namespace, replica_set_name)? == replica_set_uid)
            .then_some(())?;
        let (deployment_name, deployment_uid) =
            single_controller(&replica_set.metadata, "apps/v1", "Deployment")?;
        (live_uid(&deployment.metadata, namespace, deployment_name)? == deployment_uid)
            .then_some(())?;
        Some(Self {
            namespace,
            pod,
            replica_set,
            deployment,
            deployment_name,
        })
    }
}

/// The canonical environment label of a `type=gateway` Pod: which
/// environment to read before [`authorize`] decides.
pub fn labelled_environment(pod: &Pod) -> Option<String> {
    let labels = pod.metadata.labels.as_ref()?;
    if labels.get(TYPE_LABEL).map(String::as_str) != Some(GATEWAY_TYPE) {
        return None;
    }
    let environment = labels.get(ENVIRONMENT_LABEL)?;
    canonical_uid(environment).then(|| environment.clone())
}

/// The rule: the verified chain is `environment`'s `cw-gateway-<env>`
/// Deployment, in its namespace, with every label set current.
pub fn authorize(
    chain: &GatewayChain<'_>,
    environment: &GatewayEnvironment,
) -> Result<(), GatewayDenied> {
    let template = chain
        .deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref());
    (chain.namespace == environment.namespace
        && environment.operation_generation > 0
        && canonical_uid(&environment.environment_id)
        && chain.deployment_name
            == format!("{GATEWAY_DEPLOYMENT_PREFIX}{}", environment.environment_id)
        && associated(&chain.pod.metadata, environment)
        && associated(&chain.replica_set.metadata, environment)
        && associated(&chain.deployment.metadata, environment)
        && template.is_some_and(|template| associated(template, environment)))
    .then_some(())
    .ok_or(GatewayDenied)
}

fn associated(metadata: &ObjectMeta, environment: &GatewayEnvironment) -> bool {
    let generation = environment.operation_generation.to_string();
    metadata.labels.as_ref().is_some_and(|labels| {
        [
            (ENVIRONMENT_LABEL, environment.environment_id.as_str()),
            (ORGANIZATION_LABEL, environment.organization_id.as_str()),
            (TYPE_LABEL, GATEWAY_TYPE),
            (OPERATION_GENERATION_LABEL, generation.as_str()),
        ]
        .into_iter()
        .all(|(key, value)| labels.get(key).map(String::as_str) == Some(value))
    })
}

fn live_uid<'a>(metadata: &'a ObjectMeta, namespace: &str, name: &str) -> Option<&'a str> {
    (metadata.namespace.as_deref() == Some(namespace)
        && metadata.name.as_deref() == Some(name)
        && metadata.deletion_timestamp.is_none())
    .then_some(())
    .and(metadata.uid.as_deref())
    .filter(|uid| canonical_uid(uid))
}

fn single_controller<'a>(
    metadata: &'a ObjectMeta,
    api_version: &str,
    kind: &str,
) -> Option<(&'a str, &'a str)> {
    let mut controllers = metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|owner| owner.controller == Some(true));
    match (controllers.next(), controllers.next()) {
        (Some(owner), None)
            if owner.api_version == api_version
                && owner.kind == kind
                && !owner.name.is_empty()
                && canonical_uid(&owner.uid) =>
        {
            Some((owner.name.as_str(), owner.uid.as_str()))
        }
        _ => None,
    }
}

fn canonical_uid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
}

#[cfg(test)]
mod tests;
