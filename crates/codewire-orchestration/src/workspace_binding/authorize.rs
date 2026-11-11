//! Live-object checks for `BindWorkspace` (design §4.4 and §4.6). Pure
//! functions over the facts the runtime driver read (#3628 PR 5b), so every
//! rule is unit tested without a cluster. A verified Pod identity is never a
//! grant by itself: the live Pod must be the reviewed incarnation of a
//! Sandbox-owned workspace, and after the wait the Pod → Sandbox →
//! SandboxClaim chain must match the recorded binding by UID.

use std::net::IpAddr;

use codewire_daemon_proto::SANDBOX_SERVICE_ACCOUNT;
use codewire_server_core::pod_identity::VerifiedPodIdentity;
use uuid::Uuid;

use super::store::LiveBinding;
use crate::runtime::{ControllerFact, MemberFacts, RuntimeFacts};
use crate::sandbox::{EXTENSIONS_API_VERSION, LABEL_ENV_ID, LABEL_TYPE};

const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";

/// A canonical, lowercase, non-nil Kubernetes UID.
pub(crate) fn canonical_uid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
}

/// The Sandbox that controls a workspace Pod, as its owner reference names it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SandboxOwner {
    pub name: String,
    pub uid: String,
}

/// §4.4: the live Pod is the reviewed incarnation of a running,
/// Sandbox-controlled workspace using the sandbox service account. The Pod
/// is read by name, so its UID must be the reviewed one: a Pod recreated
/// under the same name is another incarnation.
pub(super) fn bindable_pod(
    member: &MemberFacts,
    identity: &VerifiedPodIdentity,
) -> Option<SandboxOwner> {
    if member.name.as_deref() != Some(identity.pod_name())
        || member.namespace.as_deref() != Some(identity.namespace())
        || member.uid.as_deref() != Some(identity.pod_uid())
        || member.terminating
        || member.service_account.as_deref() != Some(SANDBOX_SERVICE_ACCOUNT)
        || label(member, LABEL_TYPE) != Some("workspace")
        || member.phase.as_deref() != Some("Running")
    {
        return None;
    }
    let (name, uid) = single_controller(&member.controllers, SANDBOX_API_VERSION, "Sandbox")?;
    Some(SandboxOwner { name, uid })
}

/// §4.6, Pod half: after the wait the Pod is still bindable, is still the
/// reviewed UID, carries the bound environment and is controlled by the
/// recorded Sandbox.
pub(super) fn bound_pod(
    member: &MemberFacts,
    identity: &VerifiedPodIdentity,
    binding: &LiveBinding,
) -> Option<SandboxOwner> {
    let owner = bindable_pod(member, identity)?;
    (label(member, LABEL_ENV_ID) == Some(binding.environment_id.as_str())
        && owner.uid == binding.sandbox_uid)
        .then_some(owner)
}

/// §4.6, Sandbox half: the Sandbox the Pod names is live, has the recorded
/// UID, and its single controller is the SandboxClaim with the recorded UID.
/// Adoption rewrites Sandbox ownership, so Pod → Sandbox alone is not enough.
pub(super) fn bound_sandbox(
    runtime: &RuntimeFacts,
    owner: &SandboxOwner,
    binding: &LiveBinding,
) -> bool {
    runtime.api_version.as_deref() == Some(SANDBOX_API_VERSION)
        && runtime.kind.as_deref() == Some("Sandbox")
        && runtime.name.as_deref() == Some(owner.name.as_str())
        && runtime.namespace.as_deref() == Some(binding.namespace.as_str())
        && runtime.uid.as_deref() == Some(binding.sandbox_uid.as_str())
        && !runtime.terminating
        && single_controller(&runtime.controllers, EXTENSIONS_API_VERSION, "SandboxClaim")
            .is_some_and(|(_, uid)| uid == binding.claim_uid)
}

/// Whether the TCP peer is one of this Pod's own addresses (design S1).
pub(super) fn peer_is_pod(member: &MemberFacts, peer: IpAddr) -> bool {
    member
        .ips
        .iter()
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

fn label<'a>(member: &'a MemberFacts, key: &str) -> Option<&'a str> {
    member.labels.get(key).map(String::as_str)
}

fn single_controller(
    controllers: &[ControllerFact],
    api_version: &str,
    kind: &str,
) -> Option<(String, String)> {
    let mut controllers = controllers.iter();
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
