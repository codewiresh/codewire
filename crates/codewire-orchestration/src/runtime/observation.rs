//! What a driver observes of an environment's runtime for the bind (#3628 PR
//! 5a, design §5): the verified ownership chain, and raw facts about the
//! incarnation and its runtime that orchestration's checks read. The checks
//! themselves stay in orchestration; nothing here is a verdict.

use std::collections::BTreeMap;

use serde_json::Value;

use super::Incarnation;
use crate::sandbox::client::RuntimeIdentityObservation;

/// The Claim → runtime → incarnation chain, each link's controller reference
/// verified by the driver's chain read. Only that read can build one, so no
/// check can be handed an unverified chain (#2034 invariant 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    observation: RuntimeIdentityObservation,
    claim_uid: String,
    /// The incarnation's birth label naming its runtime's UID, if it has one.
    birth_runtime_uid: Option<String>,
}

impl VerifiedChain {
    /// The boundary is the `runtime` module: a driver calls this only after
    /// its own chain read has verified every link's controller reference.
    pub(in crate::runtime) fn new(
        observation: RuntimeIdentityObservation,
        claim_uid: String,
        birth_runtime_uid: Option<String>,
    ) -> Self {
        Self {
            observation,
            claim_uid,
            birth_runtime_uid,
        }
    }

    /// A chain no read verified, for tests that script a driver.
    #[cfg(test)]
    pub(crate) fn for_test(runtime_uid: &str, member_name: &str, member_uid: &str) -> Self {
        Self::new(
            RuntimeIdentityObservation::for_test(runtime_uid, member_name, member_uid),
            String::new(),
            None,
        )
    }

    pub fn claim_uid(&self) -> &str {
        &self.claim_uid
    }

    /// The runtime's UID ([`RuntimeMember::uid`](super::RuntimeMember::uid)).
    pub fn runtime_uid(&self) -> &str {
        self.observation.sandbox_uid()
    }

    pub fn member(&self) -> &Incarnation {
        self.observation.pod()
    }

    pub fn birth_runtime_uid(&self) -> Option<&str> {
        self.birth_runtime_uid.as_deref()
    }

    pub fn observation(&self) -> &RuntimeIdentityObservation {
        &self.observation
    }
}

/// One environment variable of the workspace container, as rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFact {
    pub name: String,
    pub value: Option<String>,
    /// It is set from a source rather than a literal.
    pub from_source: bool,
}

/// One container of the incarnation's spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFact {
    pub name: String,
    pub image: Option<String>,
    pub env: Vec<EnvFact>,
}

/// One volume of the incarnation's spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeFact {
    pub name: String,
    /// The audiences of the projected service-account tokens it mounts.
    pub token_audiences: Vec<String>,
    /// The volume claim it mounts, if it is one.
    pub claim_name: Option<String>,
}

/// One controller reference: an owner reference marked as the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerFact {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

/// Raw facts about one incarnation, as the driver read it.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberFacts {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub uid: Option<String>,
    pub terminating: bool,
    pub service_account: Option<String>,
    /// Owner references marked as the controller, in their order.
    pub controllers: Vec<ControllerFact>,
    pub labels: BTreeMap<String, String>,
    /// `false` when it was read without a spec; every spec fact is then empty.
    pub has_spec: bool,
    pub volumes: Vec<VolumeFact>,
    pub containers: Vec<ContainerFact>,
    pub init_containers: Vec<ContainerFact>,
    /// The image each container ran, by container name: containers first,
    /// then init containers, in their reported order.
    pub image_ids: Vec<(String, String)>,
    pub ip: String,
    /// Every address it reports: the primary one, then the list, as given.
    pub ips: Vec<String>,
    /// Its phase, if reported.
    pub phase: Option<String>,
    /// The node it was scheduled to, if any.
    pub node_name: Option<String>,
    /// The spec as a whole, for comparisons against a rendering.
    pub spec_json: Value,
}

/// Raw facts about the runtime an incarnation belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeFacts {
    /// Its API version and kind, when the read reported them.
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub uid: Option<String>,
    pub terminating: bool,
    /// Owner references marked as the controller, in their order.
    pub controllers: Vec<ControllerFact>,
    pub labels: BTreeMap<String, String>,
    /// Its template's containers and init containers, as rendered; `None`
    /// when the template has none.
    pub template_containers: Option<Value>,
    pub template_init_containers: Option<Value>,
    /// The runtime as a whole, for comparisons against a rendering.
    pub json: Value,
}

/// One read of an environment's runtime for the bind.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeObservation {
    pub chain: VerifiedChain,
    pub member: MemberFacts,
    pub runtime: RuntimeFacts,
    /// Claim and runtime ready at the current generation, the incarnation
    /// running and ready, identity labels converged.
    pub converged: bool,
    /// The bind's trigger (design §10, amended): labels converged, the
    /// runtime's status current, the incarnation running with every container
    /// started from a resolved image.
    pub bind_ready: bool,
    /// The pool the claim selects.
    pub pool: String,
    /// Opaque revisions only the driver interprets, for waiting on a change.
    pub(in crate::runtime) claim_name: String,
    pub(in crate::runtime) claim_revision: String,
    pub(in crate::runtime) member_revision: String,
}
