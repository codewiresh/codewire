//! Whether orchestration admits a guest's egress stream for the cw-egress
//! that forwards it (#4000). Both decisions are pure functions of what the
//! service reviewed and read, so every refusal is tested without Kubernetes.
//!
//! The stream is plaintext on the Pod network and stays on its node by
//! routing; admission is what refuses a stream whose Pod is not on the
//! caller's node. `peer` is the one fact taken from cw-egress unverified: a
//! caller could misstate it only for Pods on its own node.

use std::net::IpAddr;

use codewire_daemon_proto::{EGRESS_NODE_SERVICE_ACCOUNT, SANDBOX_SERVICE_ACCOUNT};
use codewire_server_core::pod_identity::VerifiedPodIdentity;

use crate::runtime::MemberFacts;
use crate::sandbox::LABEL_TYPE;
use crate::workspace_binding::authorize::peer_is_pod;

/// The Pod label orchestration renders on every broker-mode sandbox at
/// creation. Only orchestration sets it.
pub const EGRESS_MODE_LABEL: &str = "codewire.sh/egress";
pub const EGRESS_MODE_BROKER: &str = "broker";

/// The Pod a token was reviewed for. Built only from a
/// [`VerifiedPodIdentity`], so a request field never supplies it.
#[derive(Debug, Clone, Copy)]
pub struct Reviewed<'a> {
    pub namespace: &'a str,
    pub pod_name: &'a str,
    pub pod_uid: &'a str,
}

impl<'a> From<&'a VerifiedPodIdentity> for Reviewed<'a> {
    fn from(identity: &'a VerifiedPodIdentity) -> Self {
        Self {
            namespace: identity.namespace(),
            pod_name: identity.pod_name(),
            pod_uid: identity.pod_uid(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CallerRefusal {
    /// The token is cw-egress's account in another namespace.
    WrongNamespace,
    /// The caller Pod is gone, replaced, not cw-egress or not scheduled.
    NotTheCaller,
    /// The caller Pod is terminating, and asked for a new stream.
    Draining,
}

/// What a cw-egress call is for. A terminating cw-egress is draining: it
/// takes no new stream, but keeps the streams it holds until its deadline,
/// so their calls are still served (#6483).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerUse {
    /// Admitting a new stream.
    NewStream,
    /// A call for a stream the caller already holds: its assignment watch,
    /// reports, leaves and front-door sessions.
    HeldStream,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GuestRefusal {
    WrongNamespace,
    /// The Pod the token names is gone or was replaced under its name.
    PodReplaced,
    PodTerminating,
    NotARunningWorkspace,
    /// The Pod is not on the caller's node.
    PodOnAnotherNode,
    PeerIsNotThePod,
    NotBrokerMode,
}

/// The caller's node, from its own reviewed token and live Pod: never from a
/// request field.
pub fn caller_node(
    identity: Reviewed<'_>,
    caller: &MemberFacts,
    server_namespace: &str,
    used: CallerUse,
) -> Result<String, CallerRefusal> {
    if identity.namespace != server_namespace {
        return Err(CallerRefusal::WrongNamespace);
    }
    if caller.name.as_deref() != Some(identity.pod_name)
        || caller.namespace.as_deref() != Some(identity.namespace)
        || caller.uid.as_deref() != Some(identity.pod_uid)
        || caller.service_account.as_deref() != Some(EGRESS_NODE_SERVICE_ACCOUNT)
    {
        return Err(CallerRefusal::NotTheCaller);
    }
    let node = caller
        .node_name
        .clone()
        .ok_or(CallerRefusal::NotTheCaller)?;
    if caller.terminating && used == CallerUse::NewStream {
        return Err(CallerRefusal::Draining);
    }
    Ok(node)
}

/// The guest Pod is the reviewed, running, broker-mode workspace on the
/// caller's node. Every method that names a guest Pod checks this.
pub fn guest_on_node(
    identity: Reviewed<'_>,
    guest: &MemberFacts,
    caller_node: &str,
    sandbox_namespace: &str,
) -> Result<(), GuestRefusal> {
    if identity.namespace != sandbox_namespace {
        return Err(GuestRefusal::WrongNamespace);
    }
    if guest.name.as_deref() != Some(identity.pod_name)
        || guest.namespace.as_deref() != Some(identity.namespace)
        || guest.uid.as_deref() != Some(identity.pod_uid)
    {
        return Err(GuestRefusal::PodReplaced);
    }
    if guest.terminating {
        return Err(GuestRefusal::PodTerminating);
    }
    if guest.service_account.as_deref() != Some(SANDBOX_SERVICE_ACCOUNT)
        || label(guest, LABEL_TYPE) != Some("workspace")
        || !guest.is_running()
    {
        return Err(GuestRefusal::NotARunningWorkspace);
    }
    if guest.node_name.as_deref() != Some(caller_node) {
        return Err(GuestRefusal::PodOnAnotherNode);
    }
    if label(guest, EGRESS_MODE_LABEL) != Some(EGRESS_MODE_BROKER) {
        return Err(GuestRefusal::NotBrokerMode);
    }
    Ok(())
}

/// Admits a new stream: the Pod is on the caller's node and the stream comes
/// from its address.
pub fn admit_guest(
    identity: Reviewed<'_>,
    guest: &MemberFacts,
    caller_node: &str,
    peer: IpAddr,
    sandbox_namespace: &str,
) -> Result<(), GuestRefusal> {
    guest_on_node(identity, guest, caller_node, sandbox_namespace)?;
    if !peer_is_pod(guest, peer) {
        return Err(GuestRefusal::PeerIsNotThePod);
    }
    Ok(())
}

fn label<'a>(member: &'a MemberFacts, key: &str) -> Option<&'a str> {
    member.labels.get(key).map(String::as_str)
}

#[cfg(test)]
mod tests;
