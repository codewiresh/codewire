//! Binding-time reads (Program #2238 B1 and B2, design §5 and §12): the live
//! Claim → Sandbox → Pod chain for the binding recorder, and the one Pod-less
//! resolver for the workspace PVC. The resolver walks the recorded Claim UID to
//! its Sandbox and that Sandbox's `workspace` volume claim template. The name is
//! only a lookup key; the UID decides. Destroy, resize, backups and restore use
//! the same resolver, because they run while a stopped environment has no Pod.

use super::*;

const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";
const WORKSPACE_VOLUME: &str = "workspace";
/// The agent-sandbox fork's PVC tracking label (`sandboxLabel` in
/// `controllers/sandbox_controller.go`). `reconcilePVCs` adopts an unowned
/// same-name PVC that carries it with the Sandbox's name hash.
pub(crate) const SANDBOX_NAME_HASH_LABEL: &str = "agents.x-k8s.io/sandbox-name-hash";

/// The fork's `NameHash`: FNV-1a 32 of the object name as 8 lowercase hex
/// digits.
pub(crate) fn sandbox_name_hash(name: &str) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in name.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

/// What the database recorded for one environment's workspace storage: the
/// exact Claim and, once resolved, the exact PVC UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePvcAnchor {
    pub claim_name: String,
    pub claim_uid: String,
    pub recorded_pvc_uid: Option<String>,
}

/// The workspace PVC the environment's Sandbox owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePvc {
    /// The Sandbox has no `workspace` volume claim template (`disk_gb = 0`).
    VolumeLess,
    Claim {
        name: String,
        uid: String,
        bound: bool,
    },
}

/// The live chain observed for one binding attempt.
pub struct BindableRuntime {
    /// The Claim as this read saw it; [`SandboxClient::wait_for_claim_change`]
    /// waits from its revision.
    pub claim: DynamicObject,
    pub sandbox: DynamicObject,
    pub pod: Pod,
    pub observation: RuntimeIdentityObservation,
    /// Claim and Sandbox Ready at the current generation, the Pod Running and
    /// Ready, and identity labels converged on Claim, Sandbox template and Pod.
    /// Claim Ready alone never counts.
    pub converged: bool,
    /// The amended record trigger (design §10): labels converged, the Sandbox
    /// status current, the Pod Running with every container started from a
    /// resolved image. Claim and Pod readiness are not required.
    pub bind_ready: bool,
    /// The SandboxWarmPool the Claim selects: an environment's zero-replica
    /// shadow, or a shared `cw-pool-` pool for a pool-born environment.
    pub warm_pool_ref: String,
}

impl RuntimeIdentityObservation {
    pub fn sandbox_uid(&self) -> &str {
        &self.sandbox_uid
    }

    #[cfg(test)]
    pub(crate) fn for_test(sandbox_uid: &str, pod_name: &str, pod_uid: &str) -> Self {
        Self {
            sandbox_uid: sandbox_uid.to_owned(),
            pod: WorkspacePodIdentity {
                name: pod_name.to_owned(),
                uid: pod_uid.to_owned(),
            },
        }
    }
}

impl SandboxClient {
    /// Read the exact Claim → Sandbox → Pod chain once, without waiting.
    pub async fn read_bindable_runtime(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<BindableRuntime> {
        let snapshot = self
            .read_claim_runtime_identity(opts, expected_claim_name, expected_claim_uid)
            .await?;
        let converged =
            runtime_identity_converged(&snapshot.claim, &snapshot.sandbox, &snapshot.pod, opts);
        let bind_ready =
            runtime_bind_ready(&snapshot.claim, &snapshot.sandbox, &snapshot.pod, opts);
        let warm_pool_ref = snapshot
            .claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(BindableRuntime {
            claim: snapshot.claim,
            sandbox: snapshot.sandbox,
            pod: snapshot.pod,
            observation: snapshot.observation,
            converged,
            bind_ready,
            warm_pool_ref,
        })
    }

    /// Returns once the observed workspace Pod changed (another revision or
    /// UID, or gone), re-reading only that Pod every `poll`, or once
    /// `fallback` elapses. A cold Pod's bind readiness turns on its own status
    /// (Running, every container started), so the early bind re-reads the
    /// whole chain as that status lands instead of on its slower cadence. A
    /// failed read counts as unchanged, so an unavailable API never turns this
    /// into a faster full re-read. Orchestration may not watch Pods.
    pub async fn wait_for_workspace_pod_revision(
        &self,
        observed: &Pod,
        poll: Duration,
        fallback: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + fallback;
        let (Some(name), Some(revision)) = (
            observed.metadata.name.as_deref(),
            observed.metadata.resource_version.as_deref(),
        ) else {
            tokio::time::sleep_until(deadline).await;
            return;
        };
        loop {
            let next = tokio::time::Instant::now() + poll;
            if next >= deadline {
                // The caller re-reads the whole chain at the deadline.
                tokio::time::sleep_until(deadline).await;
                return;
            }
            tokio::time::sleep_until(next).await;
            match self.pods().get_opt(name).await {
                Ok(Some(pod))
                    if pod.metadata.uid == observed.metadata.uid
                        && pod.metadata.resource_version.as_deref() == Some(revision) => {}
                Ok(_) => return,
                Err(_) => {}
            }
        }
    }

    /// Returns on the first change to the Claim after the observed revision,
    /// or once `fallback` elapses. A warm member's adoption ends with the
    /// Claim turning Ready within a few tens of milliseconds of the Pod's
    /// labels converging, so the early bind re-reads the chain on that change
    /// instead of on a timer (#3629). Orchestration may watch Claims, not Pods
    /// or Sandboxes. A watch that cannot open waits out `fallback`.
    pub async fn wait_for_claim_change(&self, observed: &DynamicObject, fallback: Duration) {
        let Some(name) = observed.metadata.name.as_deref() else {
            tokio::time::sleep(fallback).await;
            return;
        };
        wait_for_object_change(&self.claims, name, observed, fallback).await;
    }

    /// The workspace Pod by name, or `None` when it is gone.
    pub async fn get_workspace_pod(&self, name: &str) -> anyhow::Result<Option<Pod>> {
        self.pods()
            .get_opt(name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace Pod is unavailable"))
    }

    /// Resolve the workspace PVC with or without a Pod. When `recorded_uid` is
    /// set the PVC must carry it; otherwise this is a first resolution, which
    /// requires the Sandbox's controller reference on the PVC.
    pub async fn resolve_workspace_pvc(
        &self,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        recorded_uid: Option<&str>,
    ) -> anyhow::Result<WorkspacePvc> {
        Ok(self
            .resolve_workspace_pvc_object(expected_claim_name, expected_claim_uid, recorded_uid)
            .await?
            .map_or(WorkspacePvc::VolumeLess, |(_, pvc)| pvc))
    }

    /// The resolved PVC object with its identity, or `None` for a volume-less
    /// Sandbox. Callers that need the PVC's spec or status (resize, destroy)
    /// use this instead of computing a name.
    pub async fn resolve_workspace_pvc_object(
        &self,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        recorded_uid: Option<&str>,
    ) -> anyhow::Result<Option<(PersistentVolumeClaim, WorkspacePvc)>> {
        let claim = self
            .claims
            .get(expected_claim_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace PVC Claim is unavailable"))?;
        let sandbox_name = workspace_claim_sandbox(
            &claim,
            &self.namespace,
            expected_claim_name,
            expected_claim_uid,
        )?;
        let sandbox = self
            .sandboxes()
            .get(&sandbox_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace PVC Sandbox is unavailable"))?;
        let Some(pvc_name) = workspace_pvc_name(
            &sandbox,
            &self.namespace,
            expected_claim_name,
            expected_claim_uid,
        )?
        else {
            return Ok(None);
        };
        let pvc = self
            .persistent_volume_claims()
            .get_opt(&pvc_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace PVC is unavailable"))?
            .ok_or_else(|| anyhow::anyhow!("workspace PVC is missing"))?;
        let sandbox_uid = sandbox.metadata.uid.as_deref().unwrap_or_default();
        let identity = workspace_pvc_identity(
            &pvc,
            &self.namespace,
            &pvc_name,
            &sandbox_name,
            sandbox_uid,
            recorded_uid,
        )?;
        Ok(Some((pvc, identity)))
    }

    /// The resolver for a recorded anchor.
    pub async fn resolve_anchored_workspace_pvc(
        &self,
        anchor: &WorkspacePvcAnchor,
    ) -> anyhow::Result<Option<(PersistentVolumeClaim, WorkspacePvc)>> {
        self.resolve_workspace_pvc_object(
            &anchor.claim_name,
            &anchor.claim_uid,
            anchor.recorded_pvc_uid.as_deref(),
        )
        .await
    }
}

/// The Claim is the recorded one, live, and names its bound Sandbox.
pub(super) fn workspace_claim_sandbox(
    claim: &DynamicObject,
    namespace: &str,
    claim_name: &str,
    claim_uid: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        claim.types.as_ref().is_some_and(|types| types.api_version
            == super::super::EXTENSIONS_API_VERSION
            && types.kind == "SandboxClaim"),
        "workspace PVC Claim type does not match"
    );
    anyhow::ensure!(
        !claim_uid.is_empty()
            && runtime_object_uid(&claim.metadata, namespace, claim_name)? == claim_uid,
        "workspace PVC Claim was replaced"
    );
    claim
        .data
        .pointer("/status/sandbox/name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("workspace PVC Sandbox is not bound"))
}

/// The Sandbox is live, its single controller is the recorded Claim, and its
/// `workspace` volume claim template names the PVC `workspace-<sandbox>`.
pub(super) fn workspace_pvc_name(
    sandbox: &DynamicObject,
    namespace: &str,
    claim_name: &str,
    claim_uid: &str,
) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(
        sandbox.types.as_ref().is_some_and(
            |types| types.api_version == SANDBOX_API_VERSION && types.kind == "Sandbox"
        ),
        "workspace PVC Sandbox type does not match"
    );
    let sandbox_name = sandbox
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("workspace PVC Sandbox has no name"))?;
    runtime_object_uid(&sandbox.metadata, namespace, sandbox_name)?;
    require_runtime_controller(
        &sandbox.metadata,
        super::super::EXTENSIONS_API_VERSION,
        "SandboxClaim",
        claim_name,
        claim_uid,
    )?;
    let has_workspace = sandbox
        .data
        .pointer("/spec/volumeClaimTemplates")
        .and_then(Value::as_array)
        .is_some_and(|templates| {
            templates.iter().any(|template| {
                template.pointer("/metadata/name").and_then(Value::as_str) == Some(WORKSPACE_VOLUME)
            })
        });
    Ok(has_workspace.then(|| format!("{WORKSPACE_VOLUME}-{sandbox_name}")))
}

/// The PVC is live, controlled by the Sandbox UID, and carries the recorded
/// UID when one exists. A same-name PVC that no fenced write recorded fails.
///
/// The one exception is the window between a restore adoption and resume
/// (design §12): an unowned PVC is accepted only when it carries the fork's
/// tracking label for this Sandbox *and* the UID that
/// `adopt_restored_workspace_pvc` recorded. First resolution (no recorded UID)
/// always requires the Sandbox's controller reference.
pub(super) fn workspace_pvc_identity(
    pvc: &PersistentVolumeClaim,
    namespace: &str,
    name: &str,
    sandbox_name: &str,
    sandbox_uid: &str,
    recorded_uid: Option<&str>,
) -> anyhow::Result<WorkspacePvc> {
    let uid = runtime_object_uid(&pvc.metadata, namespace, name)?;
    let unowned = pvc
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .all(|owner| owner.controller != Some(true));
    let adoption_window = unowned
        && recorded_uid == Some(uid)
        && pvc
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SANDBOX_NAME_HASH_LABEL))
            .is_some_and(|hash| *hash == sandbox_name_hash(sandbox_name));
    if !adoption_window {
        require_runtime_controller(
            &pvc.metadata,
            SANDBOX_API_VERSION,
            "Sandbox",
            sandbox_name,
            sandbox_uid,
        )?;
    }
    anyhow::ensure!(
        recorded_uid.is_none_or(|recorded| recorded == uid),
        "workspace PVC does not carry the recorded UID"
    );
    Ok(WorkspacePvc::Claim {
        name: name.to_owned(),
        uid: uid.to_owned(),
        bound: pvc
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Bound"),
    })
}

#[cfg(test)]
#[path = "workspace_binding_tests.rs"]
mod tests;
