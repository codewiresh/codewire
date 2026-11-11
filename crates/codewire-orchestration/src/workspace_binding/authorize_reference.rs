//! The object-reading binding checks as they were before #3628 PR 5b, kept
//! only as the reference `authorize_tests` proves the fact-reading checks
//! equal to.

use std::net::IpAddr;

use codewire_daemon_proto::SANDBOX_SERVICE_ACCOUNT;
use codewire_server_core::pod_identity::VerifiedPodIdentity;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::DynamicObject;

use super::authorize::{SandboxOwner, canonical_uid};
use super::store::LiveBinding;
use crate::sandbox::{EXTENSIONS_API_VERSION, LABEL_ENV_ID, LABEL_TYPE};

const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";

/// §4.4: the live Pod is the reviewed incarnation of a running,
/// Sandbox-controlled workspace using the sandbox service account.
pub(super) fn bindable_pod(pod: &Pod, identity: &VerifiedPodIdentity) -> Option<SandboxOwner> {
    let metadata = &pod.metadata;
    if metadata.name.as_deref() != Some(identity.pod_name())
        || metadata.namespace.as_deref() != Some(identity.namespace())
        || metadata.uid.as_deref() != Some(identity.pod_uid())
        || metadata.deletion_timestamp.is_some()
        || pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            != Some(SANDBOX_SERVICE_ACCOUNT)
        || label(metadata, LABEL_TYPE) != Some("workspace")
        || pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            != Some("Running")
    {
        return None;
    }
    let (name, uid) = single_controller(metadata, SANDBOX_API_VERSION, "Sandbox")?;
    Some(SandboxOwner { name, uid })
}

/// §4.6, Pod half: after the wait the Pod is still bindable, is still the
/// reviewed UID, carries the bound environment and is controlled by the
/// recorded Sandbox.
pub(super) fn bound_pod(
    pod: &Pod,
    identity: &VerifiedPodIdentity,
    binding: &LiveBinding,
) -> Option<SandboxOwner> {
    let owner = bindable_pod(pod, identity)?;
    (label(&pod.metadata, LABEL_ENV_ID) == Some(binding.environment_id.as_str())
        && owner.uid == binding.sandbox_uid)
        .then_some(owner)
}

/// §4.6, Sandbox half: the Sandbox the Pod names is live, has the recorded
/// UID, and its single controller is the SandboxClaim with the recorded UID.
/// Adoption rewrites Sandbox ownership, so Pod → Sandbox alone is not enough.
pub(super) fn bound_sandbox(
    sandbox: &DynamicObject,
    owner: &SandboxOwner,
    binding: &LiveBinding,
) -> bool {
    sandbox
        .types
        .as_ref()
        .is_some_and(|types| types.api_version == SANDBOX_API_VERSION && types.kind == "Sandbox")
        && sandbox.metadata.name.as_deref() == Some(owner.name.as_str())
        && sandbox.metadata.namespace.as_deref() == Some(binding.namespace.as_str())
        && sandbox.metadata.uid.as_deref() == Some(binding.sandbox_uid.as_str())
        && sandbox.metadata.deletion_timestamp.is_none()
        && single_controller(&sandbox.metadata, EXTENSIONS_API_VERSION, "SandboxClaim")
            .is_some_and(|(_, uid)| uid == binding.claim_uid)
}

fn label<'a>(metadata: &'a ObjectMeta, key: &str) -> Option<&'a str> {
    metadata.labels.as_ref()?.get(key).map(String::as_str)
}

fn single_controller(
    metadata: &ObjectMeta,
    api_version: &str,
    kind: &str,
) -> Option<(String, String)> {
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
            Some((owner.name.clone(), owner.uid.clone()))
        }
        _ => None,
    }
}

/// Whether the TCP peer is this Pod's own address (design S1).
pub(super) fn peer_is_pod(pod: &Pod, peer: IpAddr) -> bool {
    let Some(status) = pod.status.as_ref() else {
        return false;
    };
    status
        .pod_ip
        .as_deref()
        .into_iter()
        .chain(
            status
                .pod_ips
                .iter()
                .flatten()
                .map(|address| address.ip.as_str()),
        )
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .any(|ip| ip == peer || normalize(ip) == normalize(peer))
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}
