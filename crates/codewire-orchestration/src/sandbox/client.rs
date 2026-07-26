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
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Client;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
};
use kube::core::GroupVersionKind;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use serde_json::Value;

use super::template::{
    TemplateOpts, gateway_direct_udp_service_name, gateway_host_key_secret_name,
    gateway_network_policy_name, gateway_workload_name, render_gateway_deployment,
    render_gateway_direct_udp_service, render_gateway_host_key_secret,
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

        match self
            .pods()
            .delete(&old.name, &DeleteParams::default())
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "restart workspace Pod {}: {error}",
                    old.name
                ));
            }
        }

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let pods = self
                .pods()
                .list(&ListParams::default().labels(&workspace_pod_selector(env_id)))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("list replacement workspace Pods for {env_id}: {error}")
                })?;
            for pod in pods {
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
                if !uid.is_empty() && uid != old.uid && ready {
                    return Ok(WorkspacePodIdentity { name, uid });
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timeout waiting for replacement of workspace Pod {}",
                    old.name
                );
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
                .environment_residue(env_id, known_sandbox_name, per_environment_template)
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
const TERMINAL_WAITING_REASONS: [&str; 4] = [
    "ImagePullBackOff",
    "ErrImagePull",
    "InvalidImageName",
    "CreateContainerConfigError",
];

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
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "metadata": {},
                    "items": [{
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "workspace-new",
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
                    }]
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
                name: "workspace-new".into(),
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
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods".to_string(),
                ),
            ]
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
