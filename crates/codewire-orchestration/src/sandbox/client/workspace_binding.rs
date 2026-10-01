//! Binding-time reads (Program #2238 B1, design §5 and §12): the live
//! Claim → Sandbox → Pod chain for the binding recorder, and the one Pod-less
//! resolver for the workspace PVC. The resolver walks the recorded Claim UID to
//! its Sandbox and that Sandbox's `workspace` volume claim template. The name is
//! only a lookup key; the UID decides.

use super::*;

const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";
const WORKSPACE_VOLUME: &str = "workspace";

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
    pub sandbox: DynamicObject,
    pub pod: Pod,
    pub observation: RuntimeIdentityObservation,
    /// Claim and Sandbox Ready at the current generation, the Pod Running and
    /// Ready, and identity labels converged on Claim, Sandbox template and Pod.
    /// Claim Ready alone never counts.
    pub converged: bool,
}

impl RuntimeIdentityObservation {
    pub fn sandbox_uid(&self) -> &str {
        &self.sandbox_uid
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
        Ok(BindableRuntime {
            sandbox: snapshot.sandbox,
            pod: snapshot.pod,
            observation: snapshot.observation,
            converged,
        })
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
            return Ok(WorkspacePvc::VolumeLess);
        };
        let pvc = self
            .persistent_volume_claims()
            .get_opt(&pvc_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace PVC is unavailable"))?
            .ok_or_else(|| anyhow::anyhow!("workspace PVC is missing"))?;
        let sandbox_uid = sandbox.metadata.uid.as_deref().unwrap_or_default();
        workspace_pvc_identity(
            &pvc,
            &self.namespace,
            &pvc_name,
            &sandbox_name,
            sandbox_uid,
            recorded_uid,
        )
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
pub(super) fn workspace_pvc_identity(
    pvc: &PersistentVolumeClaim,
    namespace: &str,
    name: &str,
    sandbox_name: &str,
    sandbox_uid: &str,
    recorded_uid: Option<&str>,
) -> anyhow::Result<WorkspacePvc> {
    let uid = runtime_object_uid(&pvc.metadata, namespace, name)?;
    require_runtime_controller(
        &pvc.metadata,
        SANDBOX_API_VERSION,
        "Sandbox",
        sandbox_name,
        sandbox_uid,
    )?;
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
