//! kube-rs client for agent-sandbox CRDs and Codewire-owned companion runtime objects.
//!
//! Mirror of the dynamic-client paths in `internal/sandbox/client.go`:
//! SandboxClaim create (AlreadyExists → reuse), get, finalizer removal,
//! delete. Rust now owns the live gateway/workspace split, so this client
//! also manages the gateway Deployment, gateway Service, workspace-daemon
//! Service, and their NetworkPolicies.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crc32fast::Hasher as Crc32Hasher;
use k8s_openapi::api::core::v1::{Namespace, PersistentVolume, PersistentVolumeClaim, Pod};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Client;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
    Preconditions,
};
use kube::core::GroupVersionKind;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use serde_json::Value;

use super::template::{
    CONFIDENTIAL_WORKSPACE_STORAGE_CLASS, TemplateOpts, gateway_direct_udp_service_name,
    gateway_host_key_secret_name, gateway_network_policy_name, gateway_workload_name,
    render_gateway_deployment, render_gateway_direct_udp_service, render_gateway_host_key_secret,
    render_gateway_network_policy, render_gateway_service, render_sandbox_template,
    render_sandbox_warm_pool, render_workspace_daemon_network_policy,
    render_workspace_daemon_service, workspace_daemon_network_policy_name,
    workspace_daemon_service_name,
};
use super::{
    CRD_VERSION, ClaimOpts, EXTENSIONS_GROUP, LABEL_ENV_ID, LABEL_TYPE, SANDBOX_GROUP, claim_name,
    render_sandbox_claim,
};

/// Mirrors `sandbox.ProbeResult`.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub claim_exists: bool,
    pub claim_ready: bool,
    pub claim_reason: String,
    pub replicas: i64,
    pub pod_exists: bool,
    pub pod_phase: String,
    pub node_name: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub pod_ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePodIdentity {
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePodResizeState {
    pub identity: WorkspacePodIdentity,
    pub runtime_class_name: String,
    pub restart_count: i32,
    pub live_resize_compatible: bool,
    pub incompatibility_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStorage {
    pub pvc_name: String,
    pub storage_class_name: String,
    pub requested_disk_gb: i32,
    pub applied_disk_gb: Option<i32>,
    pub filesystem_resize_pending: bool,
    pub expansion_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceStorageResizeOutcome {
    Applied,
    RequiresPodRestart,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentResidue {
    pub resources: Vec<String>,
}

impl EnvironmentResidue {
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

const DELETION_PROTECTION_FINALIZER: &str = "codewire.sh/deletion-protection";
const LONGHORN_NAMESPACE: &str = "longhorn-system";
const DEFAULT_DIRECT_UDP_LB_PORT_START: u16 = 32000;
const DEFAULT_DIRECT_UDP_LB_PORT_END: u16 = 60999;

/// Namespaced client for SandboxClaim operations.
#[derive(Clone)]
pub struct SandboxClient {
    pub(crate) client: Client,
    pub(crate) namespace: String,
    claims: Api<DynamicObject>,
}

impl SandboxClient {
    /// Builds from the ambient kube config (in-cluster or KUBECONFIG),
    /// like the Go client's rest.InClusterConfig / kubeconfig fallback.
    pub async fn from_env(namespace: &str) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self::new(client, namespace))
    }

    pub fn new(client: Client, namespace: &str) -> Self {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxClaim");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxclaims");
        Self {
            client: client.clone(),
            namespace: namespace.to_string(),
            claims: Api::namespaced_with(client, namespace, &resource),
        }
    }

    /// Ensures the shared sandbox namespace exists with the current
    /// Codewire labels and without legacy isol8-only admission labels.
    pub async fn ensure_namespace(&self) -> anyhow::Result<()> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        let name = &self.namespace;
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "codewire".to_string(),
        );
        labels.insert(
            "codewire.sh/resource-type".to_string(),
            "sandbox".to_string(),
        );
        labels.insert(
            "codewire.sh/runtime-scope".to_string(),
            "shared".to_string(),
        );

        match namespaces.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                let namespace = Namespace {
                    metadata: ObjectMeta {
                        name: Some(name.clone()),
                        labels: Some(labels),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                namespaces
                    .create(&PostParams::default(), &namespace)
                    .await
                    .map_err(|e| anyhow::anyhow!("create namespace {name}: {e}"))?;
                tracing::info!(namespace = name, "created sandbox namespace");
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("get namespace {name}: {e}")),
            Ok(_) => {
                let patch: Value = serde_json::json!({
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/managed-by": "codewire",
                            "codewire.sh/resource-type": "sandbox",
                            "codewire.sh/runtime-scope": "shared",
                            "isol8.codewire.sh/enforce-runtime-class": null,
                        },
                    },
                });
                namespaces
                    .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                    .await
                    .map_err(|e| anyhow::anyhow!("patch namespace {name}: {e}"))?;
                tracing::info!(namespace = name, "normalized sandbox namespace");
                Ok(())
            }
        }
    }

    /// Mirrors `GetPodName` → `resolveSandboxName`: the sandbox name in
    /// the claim status doubles as the pod name; an empty status falls
    /// back to the deterministic claim name.
    pub async fn get_pod_name(&self, env_id: &str) -> anyhow::Result<String> {
        let claim = self
            .get_sandbox_claim(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("resolve sandbox name: {e}"))?;
        let Some(claim) = claim else {
            anyhow::bail!("resolve sandbox name: SandboxClaim not found for env {env_id}");
        };
        let name = claim
            .data
            .pointer("/status/sandbox/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if name.is_empty() {
            return Ok(claim_name(env_id));
        }
        Ok(name.to_string())
    }

    /// Resolve the exact workspace Pod incarnation. Pod names are reused when
    /// a Sandbox is suspended and resumed, so setup fencing compares UIDs.
    pub async fn get_workspace_pod_identity(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        let pod_name = self.get_pod_name(env_id).await?;
        self.get_workspace_pod_identity_by_name(&pod_name).await
    }

    pub async fn get_workspace_pod_identity_by_name(
        &self,
        pod_name: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        match self.pods().get(pod_name).await {
            Ok(pod) => Ok(Some(WorkspacePodIdentity {
                name: pod.metadata.name.unwrap_or_else(|| pod_name.to_string()),
                uid: pod.metadata.uid.unwrap_or_default(),
            })),
            Err(kube::Error::Api(error)) if error.code == 404 => Ok(None),
            Err(error) => Err(anyhow::anyhow!("get workspace Pod {pod_name}: {error}")),
        }
    }

    /// Read the runtime facts that determine whether CPU/memory can be
    /// changed without replacing or restarting the workspace container.
    pub async fn workspace_pod_resize_state(
        &self,
        env_id: &str,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let pod_name = self.get_pod_name(env_id).await?;
        let pod = self
            .pods()
            .get(&pod_name)
            .await
            .map_err(|error| anyhow::anyhow!("get workspace Pod {pod_name}: {error}"))?;
        workspace_pod_resize_state(&pod, &pod_name)
    }

    /// Apply CPU and memory through the Kubernetes Pod `/resize` subresource
    /// and wait for the kubelet-reported resources to converge. This path
    /// never deletes the Pod and fails if its identity or restart count moves.
    pub async fn resize_workspace_pod_in_place(
        &self,
        env_id: &str,
        expected_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        if expected_uid.trim().is_empty() {
            anyhow::bail!("expected workspace Pod UID is required");
        }
        if cpu_millicores <= 0 || memory_mb <= 0 {
            anyhow::bail!("workspace CPU and memory must be greater than zero");
        }

        let before = self.workspace_pod_resize_state(env_id).await?;
        if before.identity.uid != expected_uid {
            anyhow::bail!(
                "workspace Pod identity changed before live resize: expected UID {expected_uid}, got {}",
                before.identity.uid
            );
        }
        if !before.live_resize_compatible {
            anyhow::bail!(
                "workspace container cannot be resized live: {}",
                before
                    .incompatibility_reason
                    .as_deref()
                    .unwrap_or("incompatible resize policy")
            );
        }

        let cpu = format!("{cpu_millicores}m");
        let memory = format!("{memory_mb}Mi");
        let patch = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "workspace",
                    "resources": {
                        "requests": { "cpu": cpu, "memory": memory },
                        "limits": { "cpu": cpu, "memory": memory },
                    },
                }],
            },
        });
        self.pods()
            .patch_resize(
                &before.identity.name,
                &PatchParams::default(),
                &Patch::Strategic(&patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "resize workspace Pod {} through /resize: {error}",
                    before.identity.name
                )
            })?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let pod = self
                .pods()
                .get(&before.identity.name)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "observe resized workspace Pod {}: {error}",
                        before.identity.name
                    )
                })?;
            let observed = workspace_pod_resize_state(&pod, &before.identity.name)?;
            if observed.identity.uid != expected_uid {
                anyhow::bail!(
                    "workspace Pod was replaced during live resize: expected UID {expected_uid}, got {}",
                    observed.identity.uid
                );
            }
            if observed.restart_count != before.restart_count {
                anyhow::bail!(
                    "workspace container restarted during live resize: restart count changed from {} to {}",
                    before.restart_count,
                    observed.restart_count
                );
            }
            if let Some(failure) = terminal_pod_resize_failure(&pod) {
                anyhow::bail!("workspace Pod live resize failed: {failure}");
            }
            if workspace_resources_match(&pod, &cpu, &memory) {
                return Ok(observed);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timeout waiting for workspace Pod {} live resize to converge",
                    before.identity.name
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Enumerate every Pod carrying the stable environment label. Recovery
    /// proves environment-wide absence because a replacement may use another
    /// Pod name.
    pub async fn list_workspace_pod_identities(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Vec<WorkspacePodIdentity>> {
        let selector = workspace_pod_selector(env_id);
        let pods = self
            .pods()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list workspace Pods for {env_id}: {error}"))?;
        Ok(pods
            .items
            .into_iter()
            .map(|pod| WorkspacePodIdentity {
                name: pod.metadata.name.unwrap_or_default(),
                uid: pod.metadata.uid.unwrap_or_default(),
            })
            .collect())
    }

    /// Return the exact terminal Pod incarnation that an explicit product
    /// retry must replace. A healthy or still-progressing Pod is never a
    /// replacement candidate.
    pub async fn workspace_pod_replacement_candidate(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        let selector = workspace_pod_selector(env_id);
        let mut pods = self
            .pods()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list workspace Pods before retry: {error}"))?
            .items;
        if pods.is_empty() {
            return Ok(None);
        }
        if pods.len() != 1 {
            anyhow::bail!(
                "refusing product retry with {} workspace Pods for environment {env_id}",
                pods.len()
            );
        }
        let pod = pods.pop().expect("one workspace Pod remains");
        if !pod_requires_product_replacement(&pod) {
            return Ok(None);
        }
        let name = pod
            .metadata
            .name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal workspace Pod has no name"))?;
        let uid = pod
            .metadata
            .uid
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal workspace Pod {name} has no UID"))?;
        Ok(Some(WorkspacePodIdentity { name, uid }))
    }

    /// Restart only the workspace Pod and wait for the owning Sandbox
    /// controller to replace it. The Sandbox, claim, PVCs, and environment
    /// identity are preserved.
    pub async fn restart_workspace_pod(
        &self,
        env_id: &str,
        known_pod_name: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        let pod_name = match known_pod_name.filter(|name| !name.trim().is_empty()) {
            Some(name) => name.to_string(),
            None => self.get_pod_name(env_id).await?,
        };
        let old = self
            .get_workspace_pod_identity_by_name(&pod_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("workspace Pod {pod_name} not found"))?;

        self.restart_workspace_pod_if_uid(&pod_name, &old.uid, timeout)
            .await
    }

    /// Restart the exact previously observed workspace Pod incarnation. The
    /// UID is carried from observation through the Kubernetes delete
    /// precondition so a concurrent replacement cannot be deleted.
    pub async fn restart_workspace_pod_if_uid(
        &self,
        pod_name: &str,
        previous_uid: &str,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        self.delete_workspace_pod_if_uid(pod_name, previous_uid)
            .await?;
        self.wait_for_replacement_workspace_pod(pod_name, previous_uid, timeout)
            .await
    }

    /// Delete the old workspace incarnation only when it still has the
    /// checkpointed UID. A retried resize must never delete the replacement.
    pub async fn delete_workspace_pod_if_uid(
        &self,
        pod_name: &str,
        previous_uid: &str,
    ) -> anyhow::Result<()> {
        if pod_name.trim().is_empty() {
            anyhow::bail!("workspace Pod name is required");
        }
        if previous_uid.trim().is_empty() {
            anyhow::bail!("previous workspace Pod UID is required");
        }
        let Some(current) = self.get_workspace_pod_identity_by_name(pod_name).await? else {
            return Ok(());
        };
        if current.uid != previous_uid {
            return Ok(());
        }

        let delete_params = delete_params_for_observed_uid(previous_uid);
        match self.pods().delete(&current.name, &delete_params).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            // A replacement won the race after the observation above. The
            // UID precondition prevented deleting it; the caller can now
            // observe that replacement normally.
            Err(kube::Error::Api(error)) if error.code == 409 => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "restart workspace Pod {}: {error}",
                    current.name
                ));
            }
        }
        Ok(())
    }

    /// Wait until the owning Sandbox controller has produced a ready
    /// incarnation of the same stable Pod name with a different UID. The
    /// environment label is intentionally insufficient: a private warm-pool
    /// Pod can carry the same label before it is claimed.
    pub async fn wait_for_replacement_workspace_pod(
        &self,
        pod_name: &str,
        previous_uid: &str,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.pods().get(pod_name).await {
                Ok(pod) => {
                    let name = pod.metadata.name.unwrap_or_default();
                    let uid = pod.metadata.uid.unwrap_or_default();
                    let ready = pod
                        .status
                        .as_ref()
                        .is_some_and(|status| status.phase.as_deref() == Some("Running"))
                        && pod
                            .status
                            .as_ref()
                            .and_then(|status| status.container_statuses.as_ref())
                            .is_some_and(|statuses| {
                                statuses
                                    .iter()
                                    .find(|status| status.name == "workspace")
                                    .is_some_and(|status| status.ready)
                            });
                    if !uid.is_empty() && uid != previous_uid && ready {
                        return Ok(WorkspacePodIdentity { name, uid });
                    }
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "get replacement workspace Pod {pod_name}: {error}"
                    ));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("timeout waiting for replacement workspace Pod {pod_name}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Mirrors `createSandboxClaimDynamic`: create, or reuse on
    /// AlreadyExists. Returns (name, uid).
    pub async fn create_sandbox_claim(
        &self,
        namespace: &str,
        opts: &ClaimOpts,
    ) -> anyhow::Result<(String, String)> {
        let name = claim_name(&opts.environment_id);
        let rendered = render_sandbox_claim(namespace, opts);
        let obj: DynamicObject = serde_json::from_value(rendered)?;

        match self.claims.create(&PostParams::default(), &obj).await {
            Ok(created) => {
                let uid = created.metadata.uid.unwrap_or_default();
                tracing::info!(name, namespace, env = %opts.environment_id, "created SandboxClaim");
                Ok((name, uid))
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                tracing::info!(name, namespace, env = %opts.environment_id, "SandboxClaim already exists, reusing");
                match self.claims.get(&name).await {
                    Ok(existing) => Ok((name, existing.metadata.uid.unwrap_or_default())),
                    Err(_) => Ok((name, String::new())),
                }
            }
            Err(e) => Err(anyhow::anyhow!("create SandboxClaim {name}: {e}")),
        }
    }

    /// Mirrors `GetSandboxClaim`: Ok(None) when absent.
    pub async fn get_sandbox_claim(&self, env_id: &str) -> anyhow::Result<Option<DynamicObject>> {
        let name = claim_name(env_id);
        match self.claims.get(&name).await {
            Ok(obj) => Ok(Some(obj)),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
            Err(e) => Err(anyhow::anyhow!("get SandboxClaim {name}: {e}")),
        }
    }

    /// Mirrors `RemoveDeletionProtectionFinalizer`: no-op when the claim
    /// or the finalizer is absent.
    pub async fn remove_deletion_protection_finalizer(&self, env_id: &str) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let obj = match self.claims.get(&name).await {
            Ok(obj) => obj,
            Err(kube::Error::Api(e)) if e.code == 404 => return Ok(()),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "get SandboxClaim {name} for finalizer removal: {e}"
                ));
            }
        };
        let finalizers = obj.metadata.finalizers.unwrap_or_default();
        let filtered: Vec<&String> = finalizers
            .iter()
            .filter(|f| f.as_str() != DELETION_PROTECTION_FINALIZER)
            .collect();
        if filtered.len() == finalizers.len() {
            return Ok(()); // finalizer not present
        }
        let patch: Value = serde_json::json!({ "metadata": { "finalizers": filtered } });
        self.claims
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| anyhow::anyhow!("remove finalizer from SandboxClaim {name}: {e}"))?;
        tracing::info!(name, "removed deletion-protection finalizer");
        Ok(())
    }

    /// Deletes the claim; NotFound is success, like the Go delete paths.
    pub async fn delete_sandbox_claim(&self, env_id: &str) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        match self.claims.delete(&name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxClaim {name}: {e}")),
        }
    }

    fn sandboxes(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxes");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Lists every Sandbox CR in the client's namespace.
    ///
    /// The Go billing controller drives off a shared informer over
    /// Sandboxes (`billingsessions.StartSandboxController`); the Rust
    /// orchestration substitutes a leader-gated poll for watches
    /// everywhere (see `wait_for_ready`, `sandbox_liveness_loop`), so the
    /// billing-session loop lists the same objects each tick.
    pub async fn list_sandboxes(&self) -> anyhow::Result<Vec<DynamicObject>> {
        let list = self
            .sandboxes()
            .list(&ListParams::default())
            .await
            .map_err(|e| anyhow::anyhow!("list Sandboxes: {e}"))?;
        Ok(list.items)
    }

    fn templates(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxTemplate");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxtemplates");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn warm_pools(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxWarmPool");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxwarmpools");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn persistent_volume_claims(&self) -> Api<PersistentVolumeClaim> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn persistent_volumes(&self) -> Api<PersistentVolume> {
        Api::all(self.client.clone())
    }

    fn longhorn_volumes(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("longhorn.io", "v1beta2", "Volume");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "volumes");
        Api::namespaced_with(self.client.clone(), LONGHORN_NAMESPACE, &resource)
    }

    fn storage_classes(&self) -> Api<StorageClass> {
        Api::all(self.client.clone())
    }

    /// Resolve the per-environment workspace PVC and the expansion capability
    /// advertised by its StorageClass. The Sandbox owns the volume template;
    /// Codewire never guesses a PVC from a user-supplied name.
    pub async fn workspace_storage(&self, env_id: &str) -> anyhow::Result<WorkspaceStorage> {
        let sandbox_name = self.get_pod_name(env_id).await?;
        let sandbox = self
            .sandboxes()
            .get(&sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        let has_workspace_claim = sandbox
            .data
            .pointer("/spec/volumeClaimTemplates")
            .and_then(Value::as_array)
            .is_some_and(|templates| {
                templates.iter().any(|template| {
                    template.pointer("/metadata/name").and_then(Value::as_str) == Some("workspace")
                })
            });
        if !has_workspace_claim {
            anyhow::bail!("environment {env_id} has no persistent workspace volume");
        }

        let pvc_name = format!("workspace-{sandbox_name}");
        let pvc = self
            .persistent_volume_claims()
            .get(&pvc_name)
            .await
            .map_err(|error| anyhow::anyhow!("get workspace PVC {pvc_name}: {error}"))?;
        let spec = pvc
            .spec
            .ok_or_else(|| anyhow::anyhow!("workspace PVC {pvc_name} has no spec"))?;
        let storage_class_name = spec.storage_class_name.unwrap_or_default();
        if storage_class_name.trim().is_empty() {
            anyhow::bail!("workspace PVC {pvc_name} has no explicit StorageClass");
        }
        let requested = spec
            .resources
            .and_then(|resources| resources.requests)
            .and_then(|requests| requests.get("storage").cloned())
            .ok_or_else(|| anyhow::anyhow!("workspace PVC {pvc_name} has no storage request"))?;
        let requested_disk_gb = parse_gib_quantity(&requested.0)?;
        let applied_disk_gb = pvc
            .status
            .as_ref()
            .and_then(|status| status.capacity.as_ref())
            .and_then(|capacity| capacity.get("storage"))
            .map(|quantity| parse_gib_quantity(&quantity.0))
            .transpose()?;
        let filesystem_resize_pending = pvc
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_deref())
            .is_some_and(|conditions| {
                conditions.iter().any(|condition| {
                    condition.type_ == "FileSystemResizePending" && condition.status == "True"
                })
            });
        let storage_class = self
            .storage_classes()
            .get(&storage_class_name)
            .await
            .map_err(|error| {
                anyhow::anyhow!("get StorageClass {storage_class_name} for {pvc_name}: {error}")
            })?;

        Ok(WorkspaceStorage {
            pvc_name,
            storage_class_name,
            requested_disk_gb,
            applied_disk_gb,
            filesystem_resize_pending,
            expansion_allowed: storage_class.allow_volume_expansion == Some(true),
        })
    }

    /// Verify a requested disk size before the resize operation is admitted.
    pub async fn require_workspace_storage_resize(
        &self,
        env_id: &str,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self.workspace_storage(env_id).await?;
        if desired_disk_gb < storage.requested_disk_gb {
            anyhow::bail!(
                "persistent storage cannot shrink from {} Gi to {} Gi",
                storage.requested_disk_gb,
                desired_disk_gb
            );
        }
        // The confidential direct-volume path cannot expand in place. Reject
        // here so Kubernetes never persists a larger PVC request before the
        // downstream CSI/CDH refusal.
        if desired_disk_gb > storage.requested_disk_gb
            && storage.storage_class_name == CONFIDENTIAL_WORKSPACE_STORAGE_CLASS
        {
            anyhow::bail!("confidential workspace storage expansion is not supported");
        }
        if desired_disk_gb > storage.requested_disk_gb && !storage.expansion_allowed {
            anyhow::bail!(
                "StorageClass {} does not allow volume expansion",
                storage.storage_class_name
            );
        }
        Ok(storage)
    }

    /// Persist desired compute on the current claim, its private
    /// per-environment template when present, and the already-owned Sandbox.
    /// Storage is applied to the PVC directly; the pinned Sandbox CRD makes
    /// an existing Sandbox's volumeClaimTemplates immutable.
    /// The existing agent-sandbox controller does not copy claim resource
    /// changes to an existing Sandbox, so the Sandbox patch is intentional.
    pub async fn apply_resize_desired_state(
        &self,
        env_id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        disk_gb: i32,
    ) -> anyhow::Result<()> {
        if cpu_millicores <= 0 || memory_mb <= 0 || disk_gb <= 0 {
            anyhow::bail!("resize resources must be greater than zero");
        }
        let cpu = format!("{cpu_millicores}m");
        let memory = format!("{memory_mb}Mi");
        let storage = format!("{disk_gb}Gi");

        let claim = claim_name(env_id);
        let claim_patch = serde_json::json!({
            "spec": {
                "workspaceResources": [{
                    "containerName": "workspace",
                    "resources": {
                        "requests": { "cpu": cpu, "memory": memory },
                        "limits": { "cpu": cpu, "memory": memory },
                    },
                }],
            },
        });
        self.claims
            .patch(&claim, &PatchParams::default(), &Patch::Merge(&claim_patch))
            .await
            .map_err(|error| anyhow::anyhow!("patch SandboxClaim {claim}: {error}"))?;

        let sandbox_name = self.get_pod_name(env_id).await?;
        let sandboxes = self.sandboxes();
        let mut sandbox = sandboxes
            .get(&sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        set_workspace_resources(&mut sandbox.data, &cpu, &memory)?;
        sandboxes
            .replace(&sandbox_name, &PostParams::default(), &sandbox)
            .await
            .map_err(|error| anyhow::anyhow!("update Sandbox {sandbox_name}: {error}"))?;

        if let Some(template_name) = self.claim_template_name(env_id).await?
            && template_name.ends_with(&format!("-{env_id}"))
        {
            let templates = self.templates();
            let mut template = templates
                .get(&template_name)
                .await
                .map_err(|error| anyhow::anyhow!("get SandboxTemplate {template_name}: {error}"))?;
            set_workspace_resources(&mut template.data, &cpu, &memory)?;
            set_workspace_volume_request(&mut template.data, &storage)?;
            templates
                .replace(&template_name, &PostParams::default(), &template)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("update SandboxTemplate {template_name}: {error}")
                })?;
        }

        Ok(())
    }

    async fn claim_template_name(&self, env_id: &str) -> anyhow::Result<Option<String>> {
        let Some(claim) = self.get_sandbox_claim(env_id).await? else {
            anyhow::bail!("SandboxClaim {} not found", claim_name(env_id));
        };
        let Some(warm_pool_name) = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let warm_pool = self
            .warm_pools()
            .get(warm_pool_name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxWarmPool {warm_pool_name}: {error}"))?;
        Ok(warm_pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    /// Apply only the PVC request. StorageClass capability was checked before
    /// admission and is rechecked here so a changed class fails closed.
    pub async fn apply_workspace_storage_resize(
        &self,
        env_id: &str,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self
            .require_workspace_storage_resize(env_id, desired_disk_gb)
            .await?;
        if desired_disk_gb == storage.requested_disk_gb {
            return Ok(storage);
        }
        let patch = serde_json::json!({
            "spec": {
                "resources": {
                    "requests": { "storage": format!("{desired_disk_gb}Gi") },
                },
            },
        });
        self.persistent_volume_claims()
            .patch(
                &storage.pvc_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("expand workspace PVC {}: {error}", storage.pvc_name)
            })?;
        Ok(WorkspaceStorage {
            requested_disk_gb: desired_disk_gb,
            ..storage
        })
    }

    /// Observe PVC expansion before Codewire advances durable applied resources.
    /// A filesystem resize that Kubernetes explicitly defers to Pod restart is
    /// returned to the workflow; this method never replaces the Pod itself.
    pub async fn wait_for_workspace_storage_resize(
        &self,
        env_id: &str,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspaceStorageResizeOutcome> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(env_id).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                return Ok(WorkspaceStorageResizeOutcome::Applied);
            }
            if storage.filesystem_resize_pending {
                return Ok(WorkspaceStorageResizeOutcome::RequiresPodRestart);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity before timeout",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait for the post-restart filesystem capacity, ignoring the transient
    /// FileSystemResizePending condition which is expected to clear on mount.
    pub async fn wait_for_workspace_storage_capacity(
        &self,
        env_id: &str,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(env_id).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity after Pod restart",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn deployments(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("apps", "v1", "Deployment");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "deployments");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn services(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "Service");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "services");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn secrets(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "Secret");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "secrets");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn network_policies(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "networkpolicies");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Mirrors `SetReplicas`: resolve the Sandbox name from the claim
    /// status, then update spec.operatingMode (Running/Suspended).
    pub async fn set_replicas(&self, env_id: &str, replicas: i64) -> anyhow::Result<()> {
        let name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("set replicas: {e}"))?;
        let sandboxes = self.sandboxes();
        let mut sandbox = sandboxes
            .get(&name)
            .await
            .map_err(|e| anyhow::anyhow!("get Sandbox {name}: {e}"))?;
        let mode = if replicas <= 0 {
            "Suspended"
        } else {
            "Running"
        };
        if let Some(spec) = sandbox
            .data
            .as_object_mut()
            .and_then(|o| o.get_mut("spec"))
            .and_then(Value::as_object_mut)
        {
            spec.insert("operatingMode".to_string(), Value::from(mode));
        } else {
            anyhow::bail!("set operatingMode: Sandbox {name} has no spec");
        }
        sandboxes
            .replace(&name, &PostParams::default(), &sandbox)
            .await
            .map_err(|e| anyhow::anyhow!("update Sandbox {name} operatingMode: {e}"))?;
        tracing::info!(name, replicas, mode, "set Sandbox operating mode");
        Ok(())
    }

    /// Mirrors `GetPodIP`.
    pub async fn get_pod_ip(&self, env_id: &str) -> anyhow::Result<String> {
        let name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("get pod IP: {e}"))?;
        let pod = self
            .pods()
            .get(&name)
            .await
            .map_err(|e| anyhow::anyhow!("get pod {name}: {e}"))?;
        let ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();
        if ip.is_empty() {
            anyhow::bail!("pod {name} has no IP assigned");
        }
        Ok(ip)
    }

    /// Mirrors `DeleteSandboxTemplate`: NotFound is success.
    pub async fn delete_sandbox_template(&self, name: &str) -> anyhow::Result<()> {
        match self
            .templates()
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(name, namespace = self.namespace, "deleted SandboxTemplate");
                Ok(())
            }
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxTemplate {name}: {e}")),
        }
    }

    pub async fn ensure_gateway_stack(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        if opts.environment_id.trim().is_empty() {
            anyhow::bail!("ensure gateway stack: environment_id is required");
        }
        let opts = self.resolve_gateway_direct_udp_service_opts(opts).await?;
        self.ensure_gateway_host_key_secret(&opts).await?;
        self.ensure_dynamic(
            self.services(),
            &workspace_daemon_service_name(&opts.environment_id),
            render_workspace_daemon_service(&self.namespace, &opts),
        )
        .await?;
        self.ensure_dynamic(
            self.services(),
            &super::template::gateway_service_name(&opts.environment_id),
            render_gateway_service(&self.namespace, &opts),
        )
        .await?;
        if let Some(service) = render_gateway_direct_udp_service(&self.namespace, &opts) {
            self.ensure_dynamic(
                self.services(),
                &gateway_direct_udp_service_name(&opts.environment_id),
                service,
            )
            .await?;
        } else {
            delete_dynamic(
                &self.services(),
                &gateway_direct_udp_service_name(&opts.environment_id),
            )
            .await?;
        }
        self.ensure_dynamic(
            self.deployments(),
            &gateway_workload_name(&opts.environment_id),
            render_gateway_deployment(&self.namespace, &opts),
        )
        .await?;
        if opts.network_policy_management.is_empty() || opts.network_policy_management == "Managed"
        {
            self.ensure_dynamic(
                self.network_policies(),
                &workspace_daemon_network_policy_name(&opts.environment_id),
                render_workspace_daemon_network_policy(&self.namespace, &opts),
            )
            .await?;
            self.ensure_dynamic(
                self.network_policies(),
                &gateway_network_policy_name(&opts.environment_id),
                render_gateway_network_policy(&self.namespace, &opts),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn ensure_gateway_host_key_secret(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        if opts.environment_id.trim().is_empty() {
            anyhow::bail!("ensure gateway host key secret: environment_id is required");
        }
        let name = gateway_host_key_secret_name(&opts.environment_id);
        let secrets = self.secrets();
        let host_key = generate_gateway_host_key_openssh()?;
        let obj: DynamicObject = serde_json::from_value(render_gateway_host_key_secret(
            &self.namespace,
            opts,
            &host_key,
        ))?;
        match secrets.create(&PostParams::default(), &obj).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 409 => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "create gateway host key Secret {name}: {e}"
            )),
        }
    }

    pub async fn delete_gateway_stack(&self, env_id: &str) -> anyhow::Result<()> {
        let services = self.services();
        delete_dynamic(&services, &workspace_daemon_service_name(env_id)).await?;
        delete_dynamic(&services, &super::template::gateway_service_name(env_id)).await?;
        delete_dynamic(&services, &gateway_direct_udp_service_name(env_id)).await?;
        delete_dynamic(&self.deployments(), &gateway_workload_name(env_id)).await?;
        delete_dynamic(
            &self.network_policies(),
            &workspace_daemon_network_policy_name(env_id),
        )
        .await?;
        delete_dynamic(
            &self.network_policies(),
            &gateway_network_policy_name(env_id),
        )
        .await?;
        Ok(())
    }

    pub async fn delete_gateway_host_key_secret(&self, env_id: &str) -> anyhow::Result<()> {
        delete_dynamic(&self.secrets(), &gateway_host_key_secret_name(env_id)).await
    }

    /// Remove every environment-owned runtime object and prove absence before
    /// returning. Repeated calls are safe: Kubernetes NotFound is success and
    /// the deterministic/labeled sweep catches residue left by a partially
    /// completed earlier attempt.
    pub async fn delete_environment_resources(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.delete_gateway_stack(env_id).await?;
        delete_dynamic_until_absent(
            &self.secrets(),
            &gateway_host_key_secret_name(env_id),
            timeout,
        )
        .await?;
        self.remove_deletion_protection_finalizer(env_id).await?;
        self.delete_sandbox_claim(env_id).await?;

        let selector = format!("{LABEL_ENV_ID}={env_id}");
        let mut sandboxes = self
            .sandboxes()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list Sandboxes for {env_id}: {error}"))?
            .items;
        if !known_sandbox_name.trim().is_empty()
            && !sandboxes
                .iter()
                .any(|sandbox| sandbox.metadata.name.as_deref() == Some(known_sandbox_name))
        {
            match self.sandboxes().get(known_sandbox_name).await {
                Ok(sandbox) => sandboxes.push(sandbox),
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "get known Sandbox {known_sandbox_name}: {error}"
                    ));
                }
            }
        }
        let mut sandbox_names: BTreeSet<String> = sandboxes
            .into_iter()
            .filter_map(|sandbox| sandbox.metadata.name)
            .collect();
        sandbox_names.insert(claim_name(env_id));
        if !known_sandbox_name.trim().is_empty() {
            sandbox_names.insert(known_sandbox_name.to_string());
        }
        for name in &sandbox_names {
            delete_dynamic(&self.sandboxes(), name).await?;
        }

        let mut pods = self.list_workspace_pod_identities(env_id).await?;
        for name in &sandbox_names {
            if !pods.iter().any(|pod| pod.name == *name)
                && let Some(pod) = self.get_workspace_pod_identity_by_name(name).await?
            {
                pods.push(pod);
            }
        }
        for pod in pods {
            match self
                .pods()
                .delete(&pod.name, &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "delete workspace Pod {}: {error}",
                        pod.name
                    ));
                }
            }
        }

        for pvc in self
            .environment_persistent_volume_claims(env_id, &sandbox_names)
            .await?
        {
            match self
                .persistent_volume_claims()
                .delete(&pvc, &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "delete PersistentVolumeClaim {pvc}: {error}"
                    ));
                }
            }
        }

        if let Some(template_name) = per_environment_template {
            let warm_pool_name = super::shadow_warm_pool_name(template_name);
            self.delete_warm_pool(&warm_pool_name).await?;
            self.delete_sandbox_template(template_name).await?;
        }

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let residue = self
                .environment_residue(
                    env_id,
                    known_sandbox_name,
                    per_environment_template,
                    prove_confidential_storage_absent,
                )
                .await?;
            if residue.is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() + Duration::from_millis(250) >= deadline {
                anyhow::bail!(
                    "timeout waiting for environment {env_id} resources to be deleted: {}",
                    residue.resources.join(", ")
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn environment_residue(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
    ) -> anyhow::Result<EnvironmentResidue> {
        let mut resources = Vec::new();
        if self.get_sandbox_claim(env_id).await?.is_some() {
            resources.push(format!("SandboxClaim/{}", claim_name(env_id)));
        }

        let selector = format!("{LABEL_ENV_ID}={env_id}");
        let mut sandbox_names = BTreeSet::from([claim_name(env_id)]);
        for sandbox in self
            .sandboxes()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list Sandboxes for {env_id}: {error}"))?
            .items
        {
            if let Some(name) = sandbox.metadata.name {
                sandbox_names.insert(name.clone());
                resources.push(format!("Sandbox/{name}"));
            }
        }
        if !known_sandbox_name.trim().is_empty()
            && !resources
                .iter()
                .any(|resource| resource == &format!("Sandbox/{known_sandbox_name}"))
        {
            match self.sandboxes().get(known_sandbox_name).await {
                Ok(_) => {
                    sandbox_names.insert(known_sandbox_name.to_string());
                    resources.push(format!("Sandbox/{known_sandbox_name}"));
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!("get Sandbox {known_sandbox_name}: {error}"));
                }
            }
        }
        if !known_sandbox_name.trim().is_empty() {
            sandbox_names.insert(known_sandbox_name.to_string());
        }

        let mut pod_names: BTreeSet<String> = self
            .list_workspace_pod_identities(env_id)
            .await?
            .into_iter()
            .map(|pod| pod.name)
            .collect();
        for name in &sandbox_names {
            if self
                .get_workspace_pod_identity_by_name(name)
                .await?
                .is_some()
            {
                pod_names.insert(name.clone());
            }
        }
        for name in pod_names {
            resources.push(format!("Pod/{name}"));
        }

        for pvc in self
            .environment_persistent_volume_claims(env_id, &sandbox_names)
            .await?
        {
            resources.push(format!("PersistentVolumeClaim/{pvc}"));
        }
        if prove_confidential_storage_absent {
            resources.extend(self.confidential_storage_residue(&sandbox_names).await?);
        }

        for (kind, api, name) in [
            (
                "Deployment",
                self.deployments(),
                gateway_workload_name(env_id),
            ),
            (
                "Service",
                self.services(),
                workspace_daemon_service_name(env_id),
            ),
            (
                "Service",
                self.services(),
                super::template::gateway_service_name(env_id),
            ),
            (
                "Service",
                self.services(),
                gateway_direct_udp_service_name(env_id),
            ),
            (
                "NetworkPolicy",
                self.network_policies(),
                workspace_daemon_network_policy_name(env_id),
            ),
            (
                "NetworkPolicy",
                self.network_policies(),
                gateway_network_policy_name(env_id),
            ),
        ] {
            if dynamic_exists(&api, &name).await? {
                resources.push(format!("{kind}/{name}"));
            }
        }

        if let Some(template_name) = per_environment_template {
            let warm_pool_name = super::shadow_warm_pool_name(template_name);
            if dynamic_exists(&self.warm_pools(), &warm_pool_name).await? {
                resources.push(format!("SandboxWarmPool/{warm_pool_name}"));
            }
            if dynamic_exists(&self.templates(), template_name).await? {
                resources.push(format!("SandboxTemplate/{template_name}"));
            }
        }

        resources.sort();
        resources.dedup();
        Ok(EnvironmentResidue { resources })
    }

    /// Prove that Kubernetes and Longhorn have both forgotten the workspace
    /// volume before orchestration is allowed to delete either key copy. The
    /// Longhorn KubernetesStatus fields retain the PVC identity while volume
    /// deletion is in progress, including after the PVC itself disappears.
    async fn confidential_storage_residue(
        &self,
        sandbox_names: &BTreeSet<String>,
    ) -> anyhow::Result<Vec<String>> {
        let pvc_names: BTreeSet<String> = sandbox_names
            .iter()
            .map(|sandbox_name| format!("workspace-{sandbox_name}"))
            .collect();
        let mut resources = Vec::new();
        let mut volume_handles = BTreeSet::new();

        let persistent_volumes = self
            .persistent_volumes()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list PersistentVolumes: {error}"))?;
        for volume in persistent_volumes.items {
            let Some(spec) = volume.spec.as_ref() else {
                continue;
            };
            let claim_matches = spec.claim_ref.as_ref().is_some_and(|claim| {
                claim.namespace.as_deref() == Some(self.namespace.as_str())
                    && claim
                        .name
                        .as_ref()
                        .is_some_and(|name| pvc_names.contains(name))
            });
            if !claim_matches {
                continue;
            }
            if let Some(handle) = spec
                .csi
                .as_ref()
                .map(|source| source.volume_handle.as_str())
            {
                volume_handles.insert(handle.to_string());
            }
            if let Some(name) = volume.metadata.name {
                resources.push(format!("PersistentVolume/{name}"));
            }
        }

        let longhorn_volumes = self
            .longhorn_volumes()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list Longhorn volumes: {error}"))?;
        for volume in longhorn_volumes.items {
            let name = volume.metadata.name.unwrap_or_default();
            let kubernetes_status = volume.data.pointer("/status/kubernetesStatus");
            let pvc_matches = kubernetes_status.is_some_and(|status| {
                status.get("namespace").and_then(Value::as_str) == Some(self.namespace.as_str())
                    && status
                        .get("pvcName")
                        .and_then(Value::as_str)
                        .is_some_and(|pvc_name| pvc_names.contains(pvc_name))
            });
            if pvc_matches || volume_handles.contains(&name) {
                resources.push(format!("LonghornVolume/{name}"));
            }
        }
        Ok(resources)
    }

    async fn environment_persistent_volume_claims(
        &self,
        env_id: &str,
        sandbox_names: &BTreeSet<String>,
    ) -> anyhow::Result<Vec<String>> {
        let pvcs = self
            .persistent_volume_claims()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list PersistentVolumeClaims: {error}"))?;
        Ok(pvcs
            .items
            .into_iter()
            .filter(|pvc| {
                let environment_matches = pvc
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_ENV_ID))
                    .is_some_and(|value| value == env_id);
                let owner_matches = pvc
                    .metadata
                    .owner_references
                    .as_ref()
                    .is_some_and(|owners| {
                        owners
                            .iter()
                            .any(|owner| sandbox_names.contains(&owner.name))
                    });
                environment_matches || owner_matches
            })
            .filter_map(|pvc| pvc.metadata.name)
            .collect())
    }

    async fn ensure_dynamic(
        &self,
        api: Api<DynamicObject>,
        name: &str,
        rendered: Value,
    ) -> anyhow::Result<()> {
        let is_service = rendered.get("kind").and_then(Value::as_str) == Some("Service");
        let mut obj: DynamicObject = serde_json::from_value(rendered)?;
        let mut existing = match api.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                match api.create(&PostParams::default(), &obj).await {
                    Ok(_) => return Ok(()),
                    Err(kube::Error::Api(e)) if e.code == 409 => api
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get {name}: {e}"))?,
                    Err(e) => return Err(anyhow::anyhow!("create {name}: {e}")),
                }
            }
            Err(e) => return Err(anyhow::anyhow!("get {name}: {e}")),
            Ok(existing) => existing,
        };

        for _ in 0..3 {
            obj.metadata.resource_version = existing.metadata.resource_version.clone();
            if is_service {
                preserve_service_allocated_fields(&mut obj, &existing);
            }
            match api.replace(name, &PostParams::default(), &obj).await {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(e)) if e.code == 409 => {
                    existing = api
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get {name}: {e}"))?;
                }
                Err(e) => return Err(anyhow::anyhow!("update {name}: {e}")),
            }
        }
        anyhow::bail!("update {name}: too many conflicts")
    }

    async fn resolve_gateway_direct_udp_service_opts(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<TemplateOpts> {
        let mut opts = opts.clone();
        if !opts.direct_udp_lb_enabled {
            return Ok(opts);
        }
        if opts.direct_udp_lb_ip.trim().is_empty() {
            anyhow::bail!("direct UDP LoadBalancer is enabled but no IP is configured");
        }
        if opts.direct_udp_lb_port == 0 {
            opts.direct_udp_lb_port =
                i64::from(self.allocate_gateway_direct_udp_port(&opts).await?);
        } else {
            validate_gateway_direct_udp_port(opts.direct_udp_lb_port)
                .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port: {e}"))?;
        }
        Ok(opts)
    }

    async fn allocate_gateway_direct_udp_port(&self, opts: &TemplateOpts) -> anyhow::Result<u16> {
        let services = self.services();
        let name = gateway_direct_udp_service_name(&opts.environment_id);
        match services.get(&name).await {
            Ok(existing) => {
                if let Some(port) = gateway_direct_udp_service_port(&existing) {
                    return Ok(port);
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => return Err(anyhow::anyhow!("get direct UDP Service {name}: {e}")),
        }

        let (start, end) = gateway_direct_udp_port_range(opts)?;
        let used = self.used_gateway_direct_udp_ports(opts).await?;
        let width = u32::from(end) - u32::from(start) + 1;
        let mut hasher = Crc32Hasher::new();
        hasher.update(opts.environment_id.as_bytes());
        let offset = hasher.finalize() % width;
        for step in 0..width {
            let port = u32::from(start) + ((offset + step) % width);
            let port = u16::try_from(port).expect("port range is u16");
            if !used.contains(&port) {
                return Ok(port);
            }
        }
        anyhow::bail!("no free direct UDP LoadBalancer ports in configured range {start}-{end}")
    }

    async fn used_gateway_direct_udp_ports(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<BTreeSet<u16>> {
        let ip = opts.direct_udp_lb_ip.trim();
        let list = self
            .services()
            .list(&ListParams::default().labels("codewire.sh/runtime-network=direct-udp"))
            .await
            .map_err(|e| anyhow::anyhow!("list direct UDP Services: {e}"))?;
        Ok(list
            .items
            .iter()
            .filter(|service| gateway_direct_udp_service_ip_matches(service, ip))
            .filter_map(gateway_direct_udp_service_port)
            .collect())
    }

    /// Mirrors `WaitForReady` semantics with a poll loop instead of a
    /// watch: the claim's Ready condition ends the wait; a terminal
    /// container failure on the backing pod (ImagePullBackOff & co —
    /// which the claim watcher never surfaces) fails it early with the
    /// same `pod <name>: <reason>: <message>` error the Go poller
    /// produces, so permanent-failure detection matches.
    pub async fn wait_for_ready(&self, env_id: &str, timeout: Duration) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let deadline = tokio::time::Instant::now() + timeout;
        let started = tokio::time::Instant::now();
        loop {
            let claim = self
                .claims
                .get(&name)
                .await
                .map_err(|e| anyhow::anyhow!("get SandboxClaim {name}: {e}"))?;
            if let (true, _) = claim_ready_status(&claim) {
                return Ok(());
            }
            // Pod failure check after the same 10s scheduling grace
            // period Go's pollPodFailures uses.
            if started.elapsed() >= Duration::from_secs(10)
                && let Some(err) = self.pod_terminal_failure(&name).await
            {
                tracing::warn!(claim = name, error = %err, "pod terminal failure detected");
                return Err(err);
            }
            if tokio::time::Instant::now() + Duration::from_secs(2) >= deadline {
                anyhow::bail!("timeout waiting for SandboxClaim {name} to become Ready");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Mirrors `WaitForDeleted` with a poll loop.
    pub async fn wait_for_deleted(&self, env_id: &str, timeout: Duration) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.claims.get(&name).await {
                Err(kube::Error::Api(e)) if e.code == 404 => return Ok(()),
                Err(e) => return Err(anyhow::anyhow!("get SandboxClaim {name}: {e}")),
                Ok(_) => {}
            }
            if tokio::time::Instant::now() + Duration::from_secs(2) >= deadline {
                anyhow::bail!("timeout waiting for SandboxClaim {name} to be deleted");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Mirrors `pollPodFailures`' per-tick check: resolve the pod
    /// behind the claim, then look for terminal waiting reasons.
    async fn pod_terminal_failure(&self, claim: &str) -> Option<anyhow::Error> {
        let sandbox_name = match self.claims.get(claim).await {
            Ok(c) => {
                let n = c
                    .data
                    .pointer("/status/sandbox/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if n.is_empty() {
                    claim.to_string()
                } else {
                    n.to_string()
                }
            }
            Err(_) => return None,
        };
        let pod = match self.pods().get(&sandbox_name).await {
            Ok(p) => p,
            Err(_) => return None, // pod not scheduled yet
        };
        let statuses = pod.status.as_ref()?.container_statuses.as_ref()?;
        for cs in statuses {
            if let Some(waiting) = cs.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                let reason = waiting.reason.as_deref().unwrap_or_default();
                if TERMINAL_WAITING_REASONS.contains(&reason) {
                    let msg = waiting.message.as_deref().unwrap_or_default();
                    return Some(anyhow::anyhow!(
                        "pod {}: {reason}: {msg}",
                        pod.metadata.name.as_deref().unwrap_or(&sandbox_name)
                    ));
                }
            }
        }
        None
    }
}

fn delete_params_for_observed_uid(uid: &str) -> DeleteParams {
    DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn generate_gateway_host_key_openssh() -> anyhow::Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("generate gateway host key: {e}"))?;
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
        .to_openssh(LineEnding::LF)
        .map(|key| key.to_string())
        .map_err(|e| anyhow::anyhow!("encode gateway host key: {e}"))
}

fn gateway_direct_udp_port_range(opts: &TemplateOpts) -> anyhow::Result<(u16, u16)> {
    let start = if opts.direct_udp_lb_port_start == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_START
    } else {
        validate_gateway_direct_udp_port(opts.direct_udp_lb_port_start)
            .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port start: {e}"))?
    };
    let end = if opts.direct_udp_lb_port_end == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_END
    } else {
        validate_gateway_direct_udp_port(opts.direct_udp_lb_port_end)
            .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port end: {e}"))?
    };
    if start > end {
        anyhow::bail!("direct UDP LoadBalancer port range start {start} is greater than end {end}");
    }
    Ok((start, end))
}

fn workspace_pod_selector(env_id: &str) -> String {
    format!("{LABEL_ENV_ID}={env_id},{LABEL_TYPE}=workspace")
}

fn validate_gateway_direct_udp_port(port: i64) -> Result<u16, &'static str> {
    match u16::try_from(port) {
        Ok(port) if port > 0 => Ok(port),
        _ => Err("must be a UDP port from 1 to 65535"),
    }
}

fn gateway_direct_udp_service_port(service: &DynamicObject) -> Option<u16> {
    service
        .data
        .pointer("/spec/ports")
        .and_then(Value::as_array)?
        .iter()
        .find(|port| {
            port["protocol"].as_str() == Some("UDP")
                && port["targetPort"].as_i64() == Some(super::template::GATEWAY_TAILNET_UDP_PORT)
        })
        .and_then(|port| port["port"].as_i64())
        .and_then(|port| u16::try_from(port).ok())
}

fn gateway_direct_udp_service_ip_matches(service: &DynamicObject, ip: &str) -> bool {
    service
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("lbipam.cilium.io/ips"))
        .is_some_and(|raw| {
            raw.split(',')
                .map(str::trim)
                .any(|candidate| candidate == ip)
        })
}

fn preserve_service_allocated_fields(obj: &mut DynamicObject, existing: &DynamicObject) {
    let Some(new_spec) = obj.data.get_mut("spec").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(existing_spec) = existing.data.get("spec").and_then(Value::as_object) else {
        return;
    };
    for key in ["clusterIP", "clusterIPs"] {
        if !new_spec.contains_key(key)
            && let Some(value) = existing_spec.get(key)
        {
            new_spec.insert(key.to_string(), value.clone());
        }
    }
}

async fn delete_dynamic(api: &Api<DynamicObject>, name: &str) -> anyhow::Result<()> {
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(anyhow::anyhow!("delete {name}: {e}")),
    }
}

async fn delete_dynamic_until_absent(
    api: &Api<DynamicObject>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match api.delete(name, &DeleteParams::default()).await {
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(anyhow::anyhow!("delete {name}: {error}")),
        }
        if tokio::time::Instant::now() + Duration::from_millis(250) >= deadline {
            anyhow::bail!("timeout waiting for {name} to be deleted");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn dynamic_exists(api: &Api<DynamicObject>, name: &str) -> anyhow::Result<bool> {
    match api.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) => Err(anyhow::anyhow!("get {name}: {error}")),
    }
}

impl SandboxClient {
    /// Mirrors `ensureSandboxTemplateDynamic`: create when absent,
    /// otherwise update (3 retries on resource-version conflicts).
    pub async fn ensure_sandbox_template(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        let name = &opts.name;
        let templates = self.templates();
        let rendered = render_sandbox_template(&self.namespace, opts);
        let mut template: DynamicObject = serde_json::from_value(rendered)?;

        let mut existing = match templates.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                match templates.create(&PostParams::default(), &template).await {
                    Ok(_) => {
                        tracing::info!(name, namespace = self.namespace, "created SandboxTemplate");
                        return Ok(());
                    }
                    Err(kube::Error::Api(e)) if e.code == 409 => templates
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get SandboxTemplate {name}: {e}"))?,
                    Err(e) => return Err(anyhow::anyhow!("create SandboxTemplate {name}: {e}")),
                }
            }
            Err(e) => return Err(anyhow::anyhow!("get SandboxTemplate {name}: {e}")),
            Ok(existing) => existing,
        };

        for _ in 0..3 {
            template.metadata.resource_version = existing.metadata.resource_version.clone();
            match templates
                .replace(name, &PostParams::default(), &template)
                .await
            {
                Ok(_) => {
                    tracing::info!(name, namespace = self.namespace, "updated SandboxTemplate");
                    return Ok(());
                }
                Err(kube::Error::Api(e)) if e.code == 409 => {
                    existing = templates
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get SandboxTemplate {name}: {e}"))?;
                }
                Err(e) => return Err(anyhow::anyhow!("update SandboxTemplate {name}: {e}")),
            }
        }
        anyhow::bail!("update SandboxTemplate {name}: too many conflicts")
    }

    /// Mirrors `EnsureWarmPool`'s dynamic-client path: truncate the name
    /// to 63 chars, then create when absent or update (setting the
    /// resource version) when it already exists.
    pub async fn ensure_warm_pool(
        &self,
        name: &str,
        template_ref: &str,
        replicas: i32,
    ) -> anyhow::Result<()> {
        let name = if name.len() > 63 { &name[..63] } else { name };
        let pools = self.warm_pools();
        let rendered =
            render_sandbox_warm_pool(&self.namespace, name, template_ref, i64::from(replicas));
        let mut pool: DynamicObject = serde_json::from_value(rendered)?;

        let existing = match pools.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                pools
                    .create(&PostParams::default(), &pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("create SandboxWarmPool {name}: {e}"))?;
                tracing::info!(name, replicas, "created SandboxWarmPool");
                return Ok(());
            }
            Err(e) => return Err(anyhow::anyhow!("get SandboxWarmPool {name}: {e}")),
            Ok(existing) => existing,
        };

        pool.metadata.resource_version = existing.metadata.resource_version.clone();
        pools
            .replace(name, &PostParams::default(), &pool)
            .await
            .map_err(|e| anyhow::anyhow!("update SandboxWarmPool {name}: {e}"))?;
        tracing::info!(name, replicas, "updated SandboxWarmPool");
        Ok(())
    }

    /// Mirrors `DeleteWarmPool`: NotFound is success.
    pub async fn delete_warm_pool(&self, name: &str) -> anyhow::Result<()> {
        match self
            .warm_pools()
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(
                    name,
                    namespace = self.namespace,
                    "deleted deprecated SandboxWarmPool"
                );
                Ok(())
            }
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxWarmPool {name}: {e}")),
        }
    }

    /// Mirrors `ListWarmPools`: names of all SandboxWarmPools whose name
    /// starts with `prefix`, for GC of stale revisioned pools.
    pub async fn list_warm_pools(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let list = self
            .warm_pools()
            .list(&ListParams::default())
            .await
            .map_err(|e| anyhow::anyhow!("list SandboxWarmPools: {e}"))?;
        let names = list
            .items
            .into_iter()
            .filter_map(|item| item.metadata.name)
            .filter(|n| n.starts_with(prefix))
            .collect();
        Ok(names)
    }

    /// Mirrors `GetSandboxClaimReadyStatus`: (exists, ready, reason).
    pub async fn get_sandbox_claim_ready_status(
        &self,
        env_id: &str,
    ) -> anyhow::Result<(bool, bool, String)> {
        match self.get_sandbox_claim(env_id).await? {
            None => Ok((false, false, String::new())),
            Some(claim) => {
                let (ready, reason) = claim_ready_status(&claim);
                Ok((true, ready, reason))
            }
        }
    }

    /// Mirrors `ClientBackend.ProbeEnvironment`.
    pub async fn probe_environment(&self, env_id: &str) -> anyhow::Result<ProbeResult> {
        let (exists, ready, reason) = self
            .get_sandbox_claim_ready_status(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("probe get claim status: {e}"))?;
        if !exists {
            return Ok(ProbeResult::default());
        }

        let mut result = ProbeResult {
            claim_exists: true,
            claim_ready: ready,
            claim_reason: reason,
            ..Default::default()
        };

        let claim = claim_name(env_id);
        let sandbox_name = match self.claims.get(&claim).await {
            Ok(c) => c
                .data
                .pointer("/status/sandbox/name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            Err(_) => String::new(),
        };
        if !sandbox_name.is_empty()
            && let Ok(sb) = self.sandboxes().get(&sandbox_name).await
        {
            // Like getSandboxReplicas: Suspended reads 0; any other existing
            // Sandbox is treated as one running slot.
            result.replicas = if sb
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended")
            {
                0
            } else {
                1
            };
        }

        let pod_lookup = if sandbox_name.is_empty() {
            claim.clone()
        } else {
            sandbox_name
        };
        if let Ok(pod) = self.pods().get(&pod_lookup).await {
            result.pod_exists = true;
            result.pod_uid = pod.metadata.uid.clone().unwrap_or_default();
            if let Some(status) = &pod.status {
                result.pod_phase = status.phase.clone().unwrap_or_default();
                result.pod_ip = status.pod_ip.clone().unwrap_or_default();
            }
            if let Some(spec) = &pod.spec {
                result.node_name = spec.node_name.clone().unwrap_or_default();
            }
            result.pod_name = pod.metadata.name.clone().unwrap_or_default();
        }

        if ready {
            if result.pod_ip.is_empty()
                && let Ok(ip) = self.get_pod_ip(env_id).await
            {
                result.pod_ip = ip;
            }
            if result.pod_name.is_empty()
                && let Ok(name) = self.get_pod_name(env_id).await
            {
                result.pod_name = name;
            }
        }

        Ok(result)
    }
}

/// Mirrors `terminalWaitingReasons`.
const TERMINAL_WAITING_REASONS: [&str; 6] = [
    "ImagePullBackOff",
    "ErrImagePull",
    "InvalidImageName",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
];

fn pod_requires_product_replacement(pod: &Pod) -> bool {
    if pod
        .status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
        .is_some_and(|phase| matches!(phase, "Failed" | "Succeeded"))
    {
        return true;
    }

    pod.status
        .as_ref()
        .and_then(|status| status.container_statuses.as_deref())
        .into_iter()
        .flatten()
        .filter_map(|status| status.state.as_ref()?.waiting.as_ref()?.reason.as_deref())
        .any(|reason| TERMINAL_WAITING_REASONS.contains(&reason))
}

/// Mirrors `isClaimReady`: (ready, reason).
pub fn claim_ready_status(claim: &DynamicObject) -> (bool, String) {
    let Some(conditions) = claim
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
    else {
        return (false, "no conditions".to_string());
    };
    for cond in conditions {
        if cond.get("type").and_then(Value::as_str) != Some("Ready") {
            continue;
        }
        let status = cond
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reason = cond
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return (status == "True", reason);
    }
    (false, "no Ready condition".to_string())
}

fn parse_gib_quantity(value: &str) -> anyhow::Result<i32> {
    let gib = value
        .strip_suffix("Gi")
        .ok_or_else(|| anyhow::anyhow!("unsupported workspace storage quantity {value:?}"))?
        .parse::<i32>()?;
    if gib <= 0 {
        anyhow::bail!("workspace storage quantity must be positive");
    }
    Ok(gib)
}

fn workspace_pod_resize_state(
    pod: &Pod,
    fallback_name: &str,
) -> anyhow::Result<WorkspacePodResizeState> {
    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("workspace Pod {fallback_name} has no spec"))?;
    let workspace = spec
        .containers
        .iter()
        .find(|container| container.name == "workspace")
        .ok_or_else(|| {
            anyhow::anyhow!("workspace Pod {fallback_name} has no workspace container")
        })?;
    let incompatible = workspace
        .resize_policy
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|policy| {
            matches!(policy.resource_name.as_str(), "cpu" | "memory")
                && !matches!(policy.restart_policy.as_str(), "" | "NotRequired")
        });
    let restart_count = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_deref())
        .and_then(|statuses| statuses.iter().find(|status| status.name == "workspace"))
        .map_or(0, |status| status.restart_count);
    Ok(WorkspacePodResizeState {
        identity: WorkspacePodIdentity {
            name: pod
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| fallback_name.to_string()),
            uid: pod.metadata.uid.clone().unwrap_or_default(),
        },
        runtime_class_name: spec.runtime_class_name.clone().unwrap_or_default(),
        restart_count,
        live_resize_compatible: incompatible.is_none(),
        incompatibility_reason: incompatible.map(|policy| {
            format!(
                "{} uses restartPolicy {}",
                policy.resource_name, policy.restart_policy
            )
        }),
    })
}

fn workspace_resources_match(pod: &Pod, cpu: &str, memory: &str) -> bool {
    let Some(resources) = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_deref())
        .and_then(|statuses| statuses.iter().find(|status| status.name == "workspace"))
        .and_then(|status| status.resources.as_ref())
    else {
        return false;
    };
    [resources.requests.as_ref(), resources.limits.as_ref()]
        .into_iter()
        .all(|class| {
            class.is_some_and(|values| {
                values
                    .get("cpu")
                    .is_some_and(|value| quantities_equal(&value.0, cpu))
                    && values
                        .get("memory")
                        .is_some_and(|value| quantities_equal(&value.0, memory))
            })
        })
}

/// Compare Kubernetes quantities by value rather than serialized form.
///
/// The kubelet canonicalizes equivalent requests (for example `3000m` to `3`
/// and `5120Mi` to `5Gi`). Resource convergence must accept that formatting
/// change without accepting a different value or a malformed observation.
fn quantities_equal(left: &str, right: &str) -> bool {
    let Some((left_numerator, left_denominator)) = parse_quantity_ratio(left) else {
        return false;
    };
    let Some((right_numerator, right_denominator)) = parse_quantity_ratio(right) else {
        return false;
    };
    match (
        left_numerator.checked_mul(right_denominator),
        right_numerator.checked_mul(left_denominator),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn parse_quantity_ratio(quantity: &str) -> Option<(i128, i128)> {
    let quantity = quantity.trim();
    if quantity.is_empty() {
        return None;
    }

    let (number, numerator_scale, denominator_scale) =
        if let Some(number) = quantity.strip_suffix("Ei") {
            (number, 1_i128.checked_shl(60)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Pi") {
            (number, 1_i128.checked_shl(50)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Ti") {
            (number, 1_i128.checked_shl(40)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Gi") {
            (number, 1_i128.checked_shl(30)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Mi") {
            (number, 1_i128.checked_shl(20)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Ki") {
            (number, 1_i128.checked_shl(10)?, 1)
        } else if let Some((number, exponent)) = split_decimal_exponent(quantity) {
            if exponent >= 0 {
                (number, 10_i128.checked_pow(exponent.unsigned_abs())?, 1)
            } else {
                (number, 1, 10_i128.checked_pow(exponent.unsigned_abs())?)
            }
        } else if let Some(number) = quantity.strip_suffix('E') {
            (number, 10_i128.checked_pow(18)?, 1)
        } else if let Some(number) = quantity.strip_suffix('P') {
            (number, 10_i128.checked_pow(15)?, 1)
        } else if let Some(number) = quantity.strip_suffix('T') {
            (number, 10_i128.checked_pow(12)?, 1)
        } else if let Some(number) = quantity.strip_suffix('G') {
            (number, 10_i128.checked_pow(9)?, 1)
        } else if let Some(number) = quantity.strip_suffix('M') {
            (number, 10_i128.checked_pow(6)?, 1)
        } else if let Some(number) = quantity
            .strip_suffix('k')
            .or_else(|| quantity.strip_suffix('K'))
        {
            (number, 10_i128.checked_pow(3)?, 1)
        } else if let Some(number) = quantity.strip_suffix('m') {
            (number, 1, 10_i128.checked_pow(3)?)
        } else if let Some(number) = quantity.strip_suffix('u') {
            (number, 1, 10_i128.checked_pow(6)?)
        } else if let Some(number) = quantity.strip_suffix('n') {
            (number, 1, 10_i128.checked_pow(9)?)
        } else {
            (quantity, 1, 1)
        };

    let (numerator, denominator) = parse_decimal_ratio(number)?;
    let numerator = numerator.checked_mul(numerator_scale)?;
    let denominator = denominator.checked_mul(denominator_scale)?;
    if numerator <= 0 || denominator <= 0 {
        return None;
    }
    Some((numerator, denominator))
}

fn split_decimal_exponent(quantity: &str) -> Option<(&str, i32)> {
    let index = quantity.rfind(['e', 'E'])?;
    let (number, exponent) = quantity.split_at(index);
    let exponent = exponent.get(1..)?.parse::<i32>().ok()?;
    (!number.is_empty()).then_some((number, exponent))
}

fn parse_decimal_ratio(number: &str) -> Option<(i128, i128)> {
    let number = number.trim();
    if number.is_empty() || number.starts_with('-') {
        return None;
    }
    let number = number.strip_prefix('+').unwrap_or(number);
    let mut parts = number.split('.');
    let whole = parts.next()?;
    let fractional = parts.next().unwrap_or("");
    if parts.next().is_some()
        || (whole.is_empty() && fractional.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let denominator = 10_i128.checked_pow(u32::try_from(fractional.len()).ok()?)?;
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<i128>().ok()?
    };
    let fractional = if fractional.is_empty() {
        0
    } else {
        fractional.parse::<i128>().ok()?
    };
    Some((
        whole.checked_mul(denominator)?.checked_add(fractional)?,
        denominator,
    ))
}

fn terminal_pod_resize_failure(pod: &Pod) -> Option<String> {
    pod.status
        .as_ref()?
        .conditions
        .as_deref()?
        .iter()
        .find(|condition| {
            condition.type_ == "PodResizePending"
                && condition.status == "True"
                && condition.reason.as_deref() == Some("Infeasible")
        })
        .map(|condition| {
            condition
                .message
                .clone()
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| {
                    "Kubernetes reported the requested resources as infeasible".into()
                })
        })
}

fn set_workspace_resources(data: &mut Value, cpu: &str, memory: &str) -> anyhow::Result<()> {
    let containers = data
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no PodTemplate containers"))?;
    let workspace = containers
        .iter_mut()
        .find(|container| container.get("name").and_then(Value::as_str) == Some("workspace"))
        .ok_or_else(|| anyhow::anyhow!("runtime object has no workspace container"))?;
    for class in ["requests", "limits"] {
        let resources = workspace
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace container is not an object"))?
            .entry("resources")
            .or_insert_with(|| serde_json::json!({}));
        let class_values = resources
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace resources are not an object"))?
            .entry(class)
            .or_insert_with(|| serde_json::json!({}));
        let class_values = class_values
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace resource {class} are not an object"))?;
        class_values.insert("cpu".to_string(), Value::String(cpu.to_string()));
        class_values.insert("memory".to_string(), Value::String(memory.to_string()));
    }
    Ok(())
}

fn set_workspace_volume_request(data: &mut Value, storage: &str) -> anyhow::Result<()> {
    let templates = data
        .pointer_mut("/spec/volumeClaimTemplates")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no volumeClaimTemplates"))?;
    let workspace = templates
        .iter_mut()
        .find(|template| {
            template.pointer("/metadata/name").and_then(Value::as_str) == Some("workspace")
        })
        .ok_or_else(|| anyhow::anyhow!("runtime object has no workspace volumeClaimTemplate"))?;
    let requests = workspace
        .pointer_mut("/spec/resources/requests")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("workspace volume has no resource requests"))?;
    requests.insert("storage".to_string(), Value::String(storage.to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode, header};
    use russh::keys::ssh_key::Algorithm;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[test]
    fn recovery_selector_excludes_gateway_and_companion_pods() {
        assert_eq!(
            workspace_pod_selector("env-test"),
            "codewire.sh/environment-id=env-test,codewire.sh/type=workspace"
        );
    }

    #[test]
    fn product_retry_replaces_only_terminal_workspace_pods() {
        let cases = [
            ("Running", None, false),
            ("Pending", Some("ContainerCreating"), false),
            ("Pending", Some("CreateContainerError"), true),
            ("Pending", Some("RunContainerError"), true),
            ("Failed", None, true),
            ("Succeeded", None, true),
        ];

        for (phase, waiting_reason, expected) in cases {
            let mut status = json!({"phase": phase});
            if let Some(reason) = waiting_reason {
                status["containerStatuses"] = json!([{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": reason}}
                }]);
            }
            let pod: Pod = serde_json::from_value(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "workspace", "uid": "uid-1"},
                "spec": {"containers": [{"name": "workspace", "image": "workspace:test"}]},
                "status": status
            }))
            .unwrap();

            assert_eq!(
                pod_requires_product_replacement(&pod),
                expected,
                "phase={phase} waiting_reason={waiting_reason:?}"
            );
        }
    }

    #[test]
    fn live_resize_observation_locks_uid_restart_count_and_terminal_failure() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {
                "runtimeClassName": "commodity",
                "containers": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "resizePolicy": [
                        {"resourceName": "cpu", "restartPolicy": "NotRequired"},
                        {"resourceName": "memory", "restartPolicy": "NotRequired"}
                    ]
                }]
            },
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 3,
                    "started": true,
                    "state": {"running": {"startedAt": "2026-08-02T00:00:00Z"}},
                    "resources": {
                        "requests": {"cpu": "500m", "memory": "512Mi"},
                        "limits": {"cpu": "500m", "memory": "512Mi"}
                    }
                }],
                "conditions": [{
                    "type": "PodResizePending",
                    "status": "True",
                    "reason": "Infeasible",
                    "message": "node has insufficient memory",
                    "lastTransitionTime": "2026-08-02T00:00:00Z"
                }]
            }
        }))
        .unwrap();
        let observed = workspace_pod_resize_state(&pod, "fallback").unwrap();
        assert_eq!(observed.identity.uid, "uid-1");
        assert_eq!(observed.restart_count, 3);
        assert!(observed.live_resize_compatible);
        assert!(workspace_resources_match(&pod, "500m", "512Mi"));
        assert_eq!(
            terminal_pod_resize_failure(&pod).as_deref(),
            Some("node has insufficient memory")
        );
    }

    #[test]
    fn live_resize_observation_accepts_semantically_equal_quantities() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {"containers": [{"name": "workspace"}]},
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 0,
                    "resources": {
                        "requests": {"cpu": "3", "memory": "5Gi"},
                        "limits": {"cpu": "3e0", "memory": "5242880Ki"}
                    },
                    "state": {"running": {"startedAt": "2026-08-04T00:00:00Z"}}
                }]
            }
        }))
        .unwrap();

        assert!(workspace_resources_match(&pod, "3000m", "5120Mi"));
        assert!(!workspace_resources_match(&pod, "2999m", "5120Mi"));
        assert!(!workspace_resources_match(&pod, "3000m", "5119Mi"));
        assert!(quantities_equal("1500000u", "1500m"));
        assert!(quantities_equal("1.5Gi", "1536Mi"));
        assert!(!quantities_equal("invalid", "3000m"));
        assert!(!quantities_equal("0", "0"));
    }

    #[test]
    fn live_resize_observation_fails_closed_without_reported_resources() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {"containers": [{"name": "workspace"}]},
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 0,
                    "state": {"running": {"startedAt": "2026-08-04T00:00:00Z"}}
                }]
            }
        }))
        .unwrap();

        assert!(!workspace_resources_match(&pod, "3000m", "5120Mi"));
    }

    #[test]
    fn live_resize_rejects_container_restart_policy() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {
                "containers": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "resizePolicy": [{"resourceName": "memory", "restartPolicy": "RestartContainer"}]
                }]
            }
        }))
        .unwrap();
        let observed = workspace_pod_resize_state(&pod, "fallback").unwrap();
        assert!(!observed.live_resize_compatible);
        assert_eq!(
            observed.incompatibility_reason.as_deref(),
            Some("memory uses restartPolicy RestartContainer")
        );
    }

    #[test]
    fn resize_mutates_only_workspace_resources_and_preserves_runtime_identity() {
        let mut runtime = json!({
            "metadata": {"labels": {"codewire.sh/isolation-tier": "future-tier"}},
            "spec": {
                "podTemplate": {"spec": {
                    "runtimeClassName": "kata-future",
                    "initContainers": [{"name": "daemon-inject", "image": "daemon:init"}],
                    "containers": [
                        {"name": "workspace", "image": "custom.example/workspace@sha256:abc", "ports": [{"containerPort": 8080}], "resources": {
                            "requests": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "5Gi"},
                            "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "5Gi"}
                        }},
                        {"name": "codewire-gateway", "image": "gateway:stable", "resources": {"requests": {"cpu": "250m"}}}
                    ]
                }},
                "volumeClaimTemplates": [{"metadata": {"name": "workspace"}, "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": "expandable",
                    "resources": {"requests": {"storage": "10Gi"}}
                }}]
            }
        });
        set_workspace_resources(&mut runtime, "1500m", "2048Mi").unwrap();
        set_workspace_volume_request(&mut runtime, "20Gi").unwrap();
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/0/image"),
            Some(&json!("custom.example/workspace@sha256:abc"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/0/resources/requests/cpu"),
            Some(&json!("1500m"))
        );
        assert_eq!(
            runtime.pointer(
                "/spec/podTemplate/spec/containers/0/resources/requests/ephemeral-storage"
            ),
            Some(&json!("5Gi"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/1/image"),
            Some(&json!("gateway:stable"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/runtimeClassName"),
            Some(&json!("kata-future"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/initContainers/0/image"),
            Some(&json!("daemon:init"))
        );
        assert_eq!(
            runtime.pointer("/spec/volumeClaimTemplates/0/spec/resources/requests/storage"),
            Some(&json!("20Gi"))
        );
        assert_eq!(
            runtime.pointer("/spec/volumeClaimTemplates/0/spec/storageClassName"),
            Some(&json!("expandable"))
        );
    }

    #[tokio::test]
    async fn workspace_storage_growth_requires_storage_class_expansion_and_never_shrinks() {
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        let supported = client
            .require_workspace_storage_resize("env-test", 20)
            .await
            .unwrap();
        assert_eq!(supported.requested_disk_gb, 10);
        assert_eq!(supported.applied_disk_gb, Some(10));
        assert!(!supported.filesystem_resize_pending);
        assert!(supported.expansion_allowed);

        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(false));
        assert!(
            client
                .require_workspace_storage_resize("env-test", 20)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not allow volume expansion")
        );

        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        assert!(
            client
                .require_workspace_storage_resize("env-test", 5)
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot shrink")
        );
    }

    #[tokio::test]
    async fn confidential_workspace_storage_growth_is_rejected_before_mutation() {
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses_for_class(
            CONFIDENTIAL_WORKSPACE_STORAGE_CLASS,
            true,
        ));
        let unchanged = client
            .require_workspace_storage_resize("env-test", 10)
            .await
            .unwrap();
        assert_eq!(
            unchanged.storage_class_name,
            CONFIDENTIAL_WORKSPACE_STORAGE_CLASS
        );

        let (client, requests) = sandbox_client_with_secret_responses(
            storage_lookup_responses_for_class(CONFIDENTIAL_WORKSPACE_STORAGE_CLASS, true),
        );

        let error = client
            .require_workspace_storage_resize("env-test", 20)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("confidential workspace storage expansion is not supported")
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _)| *method == Method::GET),
            "confidential resize admission must not mutate Kubernetes objects"
        );
    }

    #[test]
    fn generated_gateway_host_key_is_openssh_ed25519() {
        let key = generate_gateway_host_key_openssh().unwrap();
        assert!(key.contains("BEGIN OPENSSH PRIVATE KEY"));
        let parsed = PrivateKey::from_openssh(&key).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
    }

    #[tokio::test]
    async fn gateway_host_key_secret_fresh_create_is_one_post() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::CREATED,
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "cw-gateway-host-key-env-test",
                    "namespace": "dev-sandboxes",
                },
            }),
        )]);

        client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_secret_conflict_is_success_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::CONFLICT,
            kubernetes_status("AlreadyExists", 409),
        )]);

        client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_secret_non_conflict_failure_is_error_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::FORBIDDEN,
            kubernetes_status("Forbidden", 403),
        )]);

        let error = client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("create gateway host key Secret cw-gateway-host-key-env-test")
        );
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_delete_retries_until_not_found_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }),
            ),
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
        ]);

        delete_dynamic_until_absent(
            &client.secrets(),
            "cw-gateway-host-key-env-test",
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/secrets/cw-gateway-host-key-env-test"
                        .to_string(),
                ),
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/secrets/cw-gateway-host-key-env-test"
                        .to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_delete_failure_is_retryable_without_false_absence() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::FORBIDDEN,
            kubernetes_status("Forbidden", 403),
        )]);

        let error = delete_dynamic_until_absent(
            &client.secrets(),
            "cw-gateway-host-key-env-test",
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("delete cw-gateway-host-key-env-test")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn workspace_daemon_repair_replaces_only_the_workspace_pod() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old",
                    },
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old",
                    },
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-new",
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{
                            "image": "workspace:test",
                            "imageID": "workspace@test",
                            "name": "workspace",
                            "ready": true,
                            "restartCount": 0,
                            "started": true,
                            "state": {
                                "running": {
                                    "startedAt": "2026-07-25T00:00:00Z"
                                }
                            }
                        }]
                    }
                }),
            ),
        ]);

        let replacement = client
            .restart_workspace_pod("env-test", Some("workspace-old"), Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(
            replacement,
            WorkspacePodIdentity {
                name: "workspace-old".into(),
                uid: "uid-new".into(),
            }
        );
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn retried_resize_never_deletes_the_replacement_workspace_pod() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::OK,
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "workspace-old",
                    "namespace": "dev-sandboxes",
                    "uid": "uid-new",
                },
            }),
        )]);

        client
            .delete_workspace_pod_if_uid("workspace-old", "uid-old")
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::GET,
                "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
            )]
        );
    }

    #[test]
    fn terminal_recovery_delete_is_bound_to_the_observed_pod_uid() {
        let delete = serde_json::to_value(delete_params_for_observed_uid("uid-old")).unwrap();
        assert_eq!(
            delete.pointer("/preconditions/uid"),
            Some(&json!("uid-old"))
        );
    }

    fn gateway_host_key_opts() -> TemplateOpts {
        TemplateOpts {
            environment_id: "env-test".into(),
            ..Default::default()
        }
    }

    fn kubernetes_status(reason: &str, code: u16) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": format!("mock Kubernetes API response: {reason}"),
            "reason": reason,
            "code": code,
        })
    }

    type RecordedRequests = Arc<Mutex<Vec<(Method, String)>>>;

    fn storage_lookup_responses_for_class(
        storage_class_name: &str,
        expansion_allowed: bool,
    ) -> Vec<(StatusCode, Value)> {
        vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1alpha1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                    "status": {"sandbox": {"name": "workspace-env-test"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "agents.x-k8s.io/v1alpha1",
                    "kind": "Sandbox",
                    "metadata": {"name": "workspace-env-test", "namespace": "dev-sandboxes"},
                    "spec": {"volumeClaimTemplates": [{"metadata": {"name": "workspace"}}]}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": {"name": "workspace-workspace-env-test", "namespace": "dev-sandboxes"},
                    "spec": {
                        "storageClassName": storage_class_name,
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "10Gi"}}
                    },
                    "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": storage_class_name},
                    "provisioner": "example.test/provisioner",
                    "allowVolumeExpansion": expansion_allowed
                }),
            ),
        ]
    }

    fn storage_lookup_responses(expansion_allowed: bool) -> Vec<(StatusCode, Value)> {
        storage_lookup_responses_for_class("expandable", expansion_allowed)
    }

    fn sandbox_client_with_secret_responses(
        responses: Vec<(StatusCode, Value)>,
    ) -> (SandboxClient, RecordedRequests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let queued = responses.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let recorded = recorded.clone();
            let queued = queued.clone();
            async move {
                recorded
                    .lock()
                    .unwrap()
                    .push((request.method().clone(), request.uri().path().to_string()));
                let (status, body) = queued
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes API request");
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = Client::new(service, "default");
        (SandboxClient::new(client, "dev-sandboxes"), requests)
    }

    #[test]
    fn direct_udp_service_helpers_read_cilium_lb_ipam_shape() {
        let service: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "cw-gateway-udp-env-test",
                "annotations": {
                    "lbipam.cilium.io/ips": "192.0.2.36",
                },
            },
            "spec": {
                "ports": [
                    { "name": "tailnet-udp", "protocol": "UDP", "port": 33123, "targetPort": 31000 },
                ],
            },
        }))
        .unwrap();

        assert!(gateway_direct_udp_service_ip_matches(
            &service,
            "192.0.2.36"
        ));
        assert_eq!(gateway_direct_udp_service_port(&service), Some(33123));
    }

    #[test]
    fn direct_udp_port_range_defaults_and_validates() {
        let opts = TemplateOpts::default();
        assert_eq!(
            gateway_direct_udp_port_range(&opts).unwrap(),
            (
                DEFAULT_DIRECT_UDP_LB_PORT_START,
                DEFAULT_DIRECT_UDP_LB_PORT_END
            )
        );

        let opts = TemplateOpts {
            direct_udp_lb_port_start: 33000,
            direct_udp_lb_port_end: 33010,
            ..Default::default()
        };
        assert_eq!(
            gateway_direct_udp_port_range(&opts).unwrap(),
            (33000, 33010)
        );

        let opts = TemplateOpts {
            direct_udp_lb_port_start: 40000,
            direct_udp_lb_port_end: 33000,
            ..Default::default()
        };
        assert!(gateway_direct_udp_port_range(&opts).is_err());
    }

    #[test]
    fn service_replace_preserves_allocated_cluster_ips() {
        let mut rendered: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "cw-gateway-svc-env-test" },
            "spec": {
                "type": "ClusterIP",
                "ports": [
                    { "name": "ssh", "protocol": "TCP", "port": 2222, "targetPort": 2222 },
                ],
            },
        }))
        .unwrap();
        let existing: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "cw-gateway-svc-env-test" },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.43.12.34",
                "clusterIPs": ["10.43.12.34"],
                "ports": [
                    { "name": "ssh", "protocol": "TCP", "port": 2222, "targetPort": 2222 },
                ],
            },
        }))
        .unwrap();

        preserve_service_allocated_fields(&mut rendered, &existing);

        assert_eq!(
            rendered
                .data
                .pointer("/spec/clusterIP")
                .and_then(Value::as_str),
            Some("10.43.12.34")
        );
        assert_eq!(
            rendered
                .data
                .pointer("/spec/clusterIPs/0")
                .and_then(Value::as_str),
            Some("10.43.12.34")
        );
    }
}
