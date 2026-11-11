//! The agent-sandbox driver: each method is one call on a [`SandboxClient`]
//! for the placement's namespace, which does no I/O to build, and reads what
//! comes back into the driver's own types.

pub(crate) mod members;
pub(crate) mod pools;
mod suspension;
pub(crate) mod warm_pools;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, LogParams};

use super::{
    CaptureStage, ClaimReadiness, ClaimRef, ClearingOpts, ClearingProgress, DesiredPool,
    FailedLiveResize, KeptSnapshot, MemberRef, MemberReplacement, Pick, Placement, PoolBornClaim,
    PoolPass, PoolState, ProbeResult, ResizeState, RuntimeAccess, RuntimeClaims, RuntimeDriver,
    RuntimeExec, RuntimeLifecycle, RuntimeMember, RuntimePools, RuntimeResize, RuntimeSnapshots,
    RuntimeStorage, RuntimeStream, RuntimeTeardown, SuspendedRuntime, VolumeGrowth, VolumeIdentity,
    VolumeMode, VolumeRef, WantedPools,
};
use crate::sandbox::client::SandboxClient;
use crate::sandbox::host_keys::HostKeyStore;
use crate::sandbox::sidecar::WORKSPACE_SSH_PORT;
use crate::sandbox::snapshots::{clearing_volume_name, kept_snapshot_name, raw_snapshot_name};
use crate::sandbox::template::{KATA_COCO_INIT_DATA_ANNOTATION_KEY, TemplateOpts};
use crate::sandbox::warm_pool::WarmPoolObjects;
use crate::sandbox::{ClaimOpts, shadow_warm_pool_name};

const WORKSPACE_DAEMON_PORT: u16 = crate::sandbox::template::WORKSPACE_DAEMON_PORT as u16;

pub struct KubernetesDriver {
    client: kube::Client,
    /// What earlier pool passes remembered, by placement.
    pool_memory: Mutex<BTreeMap<String, warm_pools::LoopState>>,
}

impl KubernetesDriver {
    pub fn shared(client: kube::Client) -> Arc<dyn RuntimeDriver> {
        Arc::new(Self {
            client,
            pool_memory: Mutex::default(),
        })
    }

    fn sandbox_client(&self, placement: &Placement) -> SandboxClient {
        SandboxClient::new(self.client.clone(), &placement.namespace)
    }
}

#[async_trait]
impl RuntimePools for KubernetesDriver {
    async fn retire_legacy_shared_pools(&self, placement: &Placement) -> anyhow::Result<usize> {
        self.sandbox_client(placement)
            .retire_legacy_shared_warm_pools()
            .await
    }

    async fn pool_state(
        &self,
        placement: &Placement,
        pool: &WarmPoolObjects,
    ) -> anyhow::Result<PoolState> {
        pools::pool_state(&self.sandbox_client(placement), pool).await
    }

    async fn keep_pools(
        &self,
        placement: &Placement,
        wanted: &WantedPools,
    ) -> anyhow::Result<PoolPass> {
        let namespace = placement.namespace.as_str();
        // Only the leader's loop keeps pools, so passes never overlap: the
        // memory is taken out for the pass and put back after it.
        let mut memory = self
            .pool_memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(namespace)
            .unwrap_or_default();
        let pass = warm_pools::reconcile_once(&self.client, namespace, wanted, &mut memory).await;
        self.pool_memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(namespace.to_owned(), memory);
        pass
    }

    fn forget_pool_memory(&self) {
        self.pool_memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn rotating_pools(
        &self,
        placement: &Placement,
        wanted: &WantedPools,
    ) -> anyhow::Result<Vec<DesiredPool>> {
        warm_pools::rotating_pools(&self.client, &placement.namespace, wanted).await
    }

    async fn warm_pools(&self, placement: &Placement, pools: &[DesiredPool]) -> anyhow::Result<()> {
        warm_pools::warm_pools(&self.client, &placement.namespace, pools).await
    }
}

#[async_trait]
impl RuntimeClaims for KubernetesDriver {
    async fn ensure_placement(&self, placement: &Placement) -> anyhow::Result<()> {
        self.sandbox_client(placement).ensure_namespace().await
    }

    async fn prepare_cold_claim(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
        claim: &ClaimOpts,
    ) -> anyhow::Result<()> {
        let client = self.sandbox_client(placement);
        let template = rendering.name.as_str();
        let shadow_pool = if claim.warm_pool_ref.is_empty() {
            shadow_warm_pool_name(template)
        } else {
            claim.warm_pool_ref.clone()
        };
        client
            .ensure_sandbox_template(rendering)
            .await
            .context("template")?;
        if let Err(error) = client
            .ensure_shadow_pool(&shadow_pool, template, &rendering.environment_id)
            .await
        {
            // The pool's error is the one that counts.
            let _ = client.delete_sandbox_template(template).await;
            return Err(error.context("shadow pool"));
        }
        Ok(())
    }

    async fn claim(
        &self,
        placement: &Placement,
        claim: &ClaimOpts,
        pick: &Pick,
    ) -> anyhow::Result<ClaimRef> {
        let mut opts = claim.clone();
        if let Pick::Pool(pool) = pick {
            // A pool Claim names only the pool, whose template is its own.
            opts.warm_pool_ref = pool.clone();
            opts.template_ref = pool.clone();
        }
        let (name, uid) = self
            .sandbox_client(placement)
            .create_sandbox_claim(&placement.namespace, &opts)
            .await?;
        Ok(ClaimRef {
            placement: placement.clone(),
            environment_id: opts.environment_id,
            organization_id: opts.org_id,
            operation_generation: opts.operation_generation,
            name,
            uid,
        })
    }

    async fn bridge_adopted_member(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
        runtime_uid: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .ensure_warm_member_bridge(rendering, runtime_uid)
            .await
    }

    async fn pool_born_claim(
        &self,
        placement: &Placement,
        environment_id: &str,
        claim_uid: &str,
    ) -> anyhow::Result<Option<PoolBornClaim>> {
        self.sandbox_client(placement)
            .pool_born_claim(environment_id, claim_uid)
            .await
    }

    async fn withdraw_pool_born_claim(
        &self,
        placement: &Placement,
        environment_id: &str,
        observed: &PoolBornClaim,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let client = self.sandbox_client(placement);
        // A never-bound member never had a warm-member bridge (#2434);
        // removing any name-addressed residue keeps a cold re-claim from
        // inheriting one.
        client.delete_warm_member_bridge(environment_id).await?;
        client
            .delete_pool_born_claim(environment_id, observed, timeout)
            .await
    }
}

#[async_trait]
impl RuntimeLifecycle for KubernetesDriver {
    async fn probe(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ProbeResult> {
        self.sandbox_client(placement)
            .probe_environment(environment_id)
            .await
    }

    async fn list_members(&self, placement: &Placement) -> anyhow::Result<Vec<RuntimeMember>> {
        let sandboxes = self.sandbox_client(placement).list_sandboxes().await?;
        Ok(sandboxes.iter().map(members::runtime_member).collect())
    }

    async fn members(
        &self,
        placement: &Placement,
        environment_id: &str,
        known_member: &str,
    ) -> anyhow::Result<Vec<MemberRef>> {
        suspension::source_restart_pods(
            &self.sandbox_client(placement),
            environment_id,
            known_member,
        )
        .await
    }

    async fn suspend(&self, claim: &ClaimRef) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .suspend_workspace(&suspension::claim_opts(claim), &claim.name, &claim.uid)
            .await
    }

    async fn wait_suspended(
        &self,
        claim: &ClaimRef,
        known_member: &str,
        previous: &[MemberRef],
        timeout: Duration,
    ) -> anyhow::Result<SuspendedRuntime> {
        suspension::wait_for_workspace_suspension(
            &self.sandbox_client(&claim.placement),
            claim,
            known_member,
            previous,
            timeout,
        )
        .await
    }

    async fn reconcile_identity(&self, claim: &ClaimRef) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .reconcile_claim_runtime_identity(
                &suspension::claim_opts(claim),
                &claim.name,
                &claim.uid,
            )
            .await
    }

    async fn resume(
        &self,
        claim: &ClaimRef,
        suspended: &SuspendedRuntime,
        support_image: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .set_replicas_for_identity(
                &suspension::claim_opts(claim),
                &claim.name,
                &claim.uid,
                suspended,
                1,
                support_image,
            )
            .await
    }

    async fn wait_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_ready(environment_id, timeout)
            .await
    }

    async fn placement_exists(&self, placement: &Placement) -> anyhow::Result<bool> {
        self.sandbox_client(placement).namespace_exists().await
    }

    async fn tear_down(
        &self,
        placement: &Placement,
        teardown: &RuntimeTeardown<'_>,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .delete_environment_resources_with_recorded_storage(
                teardown.environment_id,
                teardown.known_member,
                teardown.per_environment_template,
                teardown.prove_confidential_storage_absent,
                teardown.recorded_volume_uid,
                teardown.timeout,
            )
            .await
    }

    async fn current_member(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<MemberRef>> {
        self.sandbox_client(placement)
            .get_workspace_pod_identity(environment_id)
            .await
    }

    async fn member_name(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<String> {
        self.sandbox_client(placement)
            .get_pod_name(environment_id)
            .await
    }

    async fn member_named(
        &self,
        placement: &Placement,
        member_name: &str,
    ) -> anyhow::Result<Option<MemberRef>> {
        self.sandbox_client(placement)
            .get_workspace_pod_identity_by_name(member_name)
            .await
    }

    async fn suspend_current(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        // A suspend re-pins nothing, so it names no image.
        self.sandbox_client(placement)
            .set_replicas(environment_id, 0, "")
            .await
    }

    async fn resume_current(
        &self,
        placement: &Placement,
        environment_id: &str,
        support_image: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .set_replicas(environment_id, 1, support_image)
            .await
    }

    async fn replace_member(
        &self,
        placement: &Placement,
        environment_id: &str,
        member: &MemberRef,
        support_image: &str,
    ) -> anyhow::Result<MemberReplacement> {
        self.sandbox_client(placement)
            .replace_workspace_pod_if_uid(environment_id, &member.name, &member.uid, support_image)
            .await
    }

    async fn wait_replacement(
        &self,
        placement: &Placement,
        previous: &MemberRef,
        timeout: Duration,
    ) -> anyhow::Result<MemberRef> {
        self.sandbox_client(placement)
            .wait_for_replacement_workspace_pod(&previous.name, &previous.uid, timeout)
            .await
    }

    async fn terminal_member(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<MemberRef>> {
        self.sandbox_client(placement)
            .workspace_pod_replacement_candidate(environment_id)
            .await
    }

    async fn publish_measured_runtime(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_name: &str,
        rendering: &TemplateOpts,
    ) -> anyhow::Result<String> {
        self.sandbox_client(placement)
            .reconcile_per_environment_runtime(environment_id, member_name, rendering)
            .await
    }

    async fn wait_measured_runtime(
        &self,
        placement: &Placement,
        member: &MemberRef,
        measured: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_workspace_pod_annotation(
                &member.name,
                &member.uid,
                KATA_COCO_INIT_DATA_ANNOTATION_KEY,
                measured,
                timeout,
            )
            .await
    }

    async fn refresh_bootstrap(
        &self,
        claim: &ClaimRef,
        rendering: &TemplateOpts,
        suspended: &SuspendedRuntime,
    ) -> anyhow::Result<()> {
        self.sandbox_client(&claim.placement)
            .reconcile_workspace_bootstrap(rendering, &claim.name, &claim.uid, suspended)
            .await
    }
}

#[async_trait]
impl RuntimeResize for KubernetesDriver {
    async fn resize_state(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ResizeState> {
        self.sandbox_client(placement)
            .workspace_pod_resize_state(environment_id)
            .await
    }

    async fn set_desired_size(
        &self,
        placement: &Placement,
        environment_id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        disk_gb: i32,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .apply_resize_desired_state(environment_id, cpu_millicores, memory_mb, disk_gb)
            .await
    }

    async fn resize_in_place(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        timeout: Duration,
    ) -> anyhow::Result<ResizeState> {
        self.sandbox_client(placement)
            .resize_workspace_pod_in_place(
                environment_id,
                member_uid,
                cpu_millicores,
                memory_mb,
                timeout,
            )
            .await
    }

    async fn settle_failed_resize(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_uid: &str,
        previous: (i32, i32),
        requested: (i32, i32),
        timeout: Duration,
    ) -> FailedLiveResize {
        self.sandbox_client(placement)
            .settle_failed_live_resize(environment_id, member_uid, previous, requested, timeout)
            .await
    }
}

#[async_trait]
impl RuntimeStorage for KubernetesDriver {
    async fn volume(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
    ) -> anyhow::Result<VolumeIdentity> {
        self.sandbox_client(placement)
            .workspace_storage(volume)
            .await
    }

    async fn check_volume_growth(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
    ) -> anyhow::Result<VolumeIdentity> {
        self.sandbox_client(placement)
            .require_workspace_storage_resize(volume, disk_gb)
            .await
    }

    async fn grow_volume(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .apply_workspace_storage_resize(volume, disk_gb)
            .await
            .map(|_| ())
    }

    async fn wait_volume_growth(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<VolumeGrowth> {
        self.sandbox_client(placement)
            .wait_for_workspace_storage_resize(volume, disk_gb, timeout)
            .await
    }

    async fn wait_volume_capacity(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_workspace_storage_capacity(volume, disk_gb, timeout)
            .await
    }
}

#[async_trait]
impl RuntimeSnapshots for KubernetesDriver {
    async fn snapshot_volume(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        source: &VolumeIdentity,
        snapshot_class: &str,
    ) -> anyhow::Result<()> {
        let source_mode = if source.raw_block {
            VolumeMode::Block
        } else {
            VolumeMode::Filesystem
        };
        self.sandbox_client(placement)
            .ensure_volume_snapshot(
                &raw_snapshot_name(snapshot_id),
                snapshot_id,
                &source.pvc_name,
                snapshot_class,
                Some(source_mode),
            )
            .await
    }

    async fn keep_cleared_volume(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        snapshot_class: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .ensure_volume_snapshot(
                &kept_snapshot_name(snapshot_id),
                snapshot_id,
                &clearing_volume_name(snapshot_id),
                snapshot_class,
                None,
            )
            .await
    }

    async fn wait_snapshot(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        stage: CaptureStage,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        let name = match stage {
            CaptureStage::Raw => raw_snapshot_name(snapshot_id),
            CaptureStage::Kept => kept_snapshot_name(snapshot_id),
        };
        self.sandbox_client(placement)
            .wait_for_volume_snapshot(&name, timeout)
            .await
    }

    async fn raw_snapshot_mode(
        &self,
        placement: &Placement,
        snapshot_id: &str,
    ) -> anyhow::Result<VolumeMode> {
        self.sandbox_client(placement)
            .raw_snapshot_volume_mode(snapshot_id)
            .await
    }

    async fn start_clearing(
        &self,
        placement: &Placement,
        opts: &ClearingOpts<'_>,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .ensure_clearing_sandbox(opts)
            .await
    }

    async fn clearing_progress(
        &self,
        placement: &Placement,
        snapshot_id: &str,
    ) -> anyhow::Result<ClearingProgress> {
        self.sandbox_client(placement)
            .clearing_progress(snapshot_id)
            .await
    }

    async fn stop_clearing(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .stop_clearing_pod(snapshot_id, timeout)
            .await
    }

    async fn delete_capture(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        kept: KeptSnapshot,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .delete_capture_objects(snapshot_id, kept, timeout)
            .await
    }
}

#[async_trait]
impl RuntimeAccess for KubernetesDriver {
    async fn member_address(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<String> {
        self.sandbox_client(placement)
            .get_pod_ip(environment_id)
            .await
    }

    async fn ensure_access(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .ensure_access_stack(rendering)
            .await
    }

    async fn delete_access(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .delete_access_stack(environment_id)
            .await
    }

    async fn wait_access_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .wait_for_workspace_access_ready(environment_id, timeout, host_keys)
            .await
    }

    async fn prove_access(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<String> {
        self.sandbox_client(placement)
            .prove_workspace_access(environment_id, timeout, host_keys)
            .await
    }

    async fn ssh_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.sandbox_client(placement)
            .check_sidecar_ready(environment_id, WORKSPACE_SSH_PORT, host_keys)
            .await
    }

    async fn start_exec(
        &self,
        placement: &Placement,
        member_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<RuntimeExec> {
        self.sandbox_client(placement)
            .start_workspace_exec_on_pod(member_name, command, work_dir, env)
            .await
    }

    async fn claim_readiness(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ClaimReadiness> {
        let (exists, ready, reason) = self
            .sandbox_client(placement)
            .get_sandbox_claim_ready_status(environment_id)
            .await?;
        Ok(match (exists, ready) {
            (false, _) => ClaimReadiness::Absent,
            (true, true) => ClaimReadiness::Ready,
            (true, false) => ClaimReadiness::NotReady { reason },
        })
    }

    async fn workspace_logs(
        &self,
        placement: &Placement,
        member_name: &str,
        tail_lines: i64,
    ) -> anyhow::Result<Vec<u8>> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &placement.namespace);
        let logs = pods
            .logs(
                member_name,
                &LogParams {
                    container: Some("workspace".into()),
                    tail_lines: Some(tail_lines),
                    timestamps: true,
                    ..Default::default()
                },
            )
            .await?;
        Ok(logs.into_bytes())
    }

    async fn ssh_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        self.sandbox_client(placement)
            .workspace_ssh_stream(environment_id, WORKSPACE_SSH_PORT)
            .await
    }

    async fn daemon_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        self.sandbox_client(placement)
            .port_forward_stream(environment_id, WORKSPACE_DAEMON_PORT)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode};
    use serde_json::json;

    use super::*;

    /// A driver over an API server that has nothing, and the requests it saw.
    fn driver_over_empty_cluster() -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            async move {
                let path = request.uri().path().to_string();
                seen.lock()
                    .unwrap()
                    .push(format!("{} {path}", request.method()));
                let (status, body) = if request.uri().query().is_some() {
                    let empty_list =
                        json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": []});
                    (StatusCode::OK, empty_list)
                } else {
                    let not_found = json!({"apiVersion": "v1", "kind": "Status",
                        "status": "Failure", "reason": "NotFound", "code": 404});
                    (StatusCode::NOT_FOUND, not_found)
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), requests)
    }

    /// A driver over an API server that has this one claim.
    fn driver_with_claim(status: serde_json::Value) -> Arc<dyn RuntimeDriver> {
        let service = Router::new().fallback(move |_: Request<Body>| {
            let status = status.clone();
            async move {
                let claim = json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1alpha1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes"},
                    "status": status,
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(claim.to_string()))
                    .unwrap()
            }
        });
        KubernetesDriver::shared(kube::Client::new(service, "the-default-namespace"))
    }

    #[tokio::test]
    async fn a_missing_claim_is_absent_after_one_read_of_the_placement() {
        let (driver, requests) = driver_over_empty_cluster();

        let readiness = driver
            .claim_readiness(&Placement::new("dev-sandboxes"), "env-1")
            .await
            .unwrap();

        assert_eq!(readiness, ClaimReadiness::Absent);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxclaims/sandbox-env-1"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_claims_ready_condition_decides_its_readiness() {
        let readiness = |condition| async move {
            driver_with_claim(json!({"conditions": [condition]}))
                .claim_readiness(&Placement::new("dev-sandboxes"), "env-1")
                .await
                .unwrap()
        };

        assert_eq!(
            readiness(json!({"type": "Ready", "status": "True", "reason": "Bound"})).await,
            ClaimReadiness::Ready
        );
        assert_eq!(
            readiness(json!({"type": "Ready", "status": "False", "reason": "PodPending"})).await,
            ClaimReadiness::NotReady {
                reason: "PodPending".into()
            }
        );
    }

    #[tokio::test]
    async fn streams_refuse_an_environment_with_no_claim_and_only_read_the_placement() {
        let (driver, requests) = driver_over_empty_cluster();
        let placement = Placement::new("dev-sandboxes");

        assert!(driver.ssh_stream(&placement, "env-1").await.is_err());
        assert!(driver.daemon_stream(&placement, "env-1").await.is_err());

        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{requests:?}"
            );
        }
    }

    /// A driver over a bound environment whose Pod has no address, so a stream
    /// falls through to a port-forward, whose request is recorded with its
    /// ports. `controller_uid` is the Sandbox the Pod says controls it.
    fn driver_over_addressless_pod(
        controller_uid: &str,
    ) -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
        let namespace = "/namespaces/dev-sandboxes";
        let objects = [
            (
                format!(
                    "/apis/extensions.agents.x-k8s.io/v1beta1{namespace}/sandboxclaims/sandbox-env-1"
                ),
                json!({"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes",
                        "uid": "c0ffee00-e29b-41d4-a716-446655440000"},
                    "status": {"sandbox": {"name": "sandbox-a"}}}),
            ),
            (
                format!("/apis/agents.x-k8s.io/v1beta1{namespace}/sandboxes/sandbox-a"),
                json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                    "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes",
                        "uid": "1f4e3a52-8d2b-4c7e-9a60-5b1d2e3f4a5b", "resourceVersion": "1",
                        "annotations": {"agents.x-k8s.io/pod-name": "workspace-a"}}}),
            ),
            (
                format!("/api/v1{namespace}/pods/workspace-a"),
                json!({"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "workspace-a", "namespace": "dev-sandboxes",
                        "uid": "7e7b20f6-0bd2-4f11-8b16-9c23d4e5f607",
                        "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1",
                            "kind": "Sandbox", "name": "sandbox-a", "uid": controller_uid,
                            "controller": true}]},
                    "status": {"phase": "Running",
                        "containerStatuses": [{"name": "workspace", "ready": true,
                            "image": "", "imageID": "", "restartCount": 0}]}}),
            ),
        ];
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            let objects = objects.clone();
            async move {
                seen.lock()
                    .unwrap()
                    .push(format!("{} {}", request.method(), request.uri()));
                let path = request.uri().path();
                let (status, body) = objects.iter().find(|(known, _)| known == path).map_or(
                    (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "code": 404}),
                    ),
                    |(_, object)| (StatusCode::OK, object.clone()),
                );
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), requests)
    }

    const CONTROLLING_SANDBOX: &str = "1f4e3a52-8d2b-4c7e-9a60-5b1d2e3f4a5b";

    fn port_forwards(requests: &Mutex<Vec<String>>) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("/portforward"))
            .cloned()
            .collect()
    }

    const STUB_POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c23d4e5f607";

    #[tokio::test]
    async fn the_current_member_is_the_claims_runtime_read_from_the_placement() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let placement = Placement::new("dev-sandboxes");

        assert_eq!(
            driver.member_name(&placement, "env-1").await.unwrap(),
            "workspace-a"
        );
        let member = driver
            .current_member(&placement, "env-1")
            .await
            .unwrap()
            .expect("a member");

        assert_eq!(member.name, "workspace-a");
        assert_eq!(member.uid, STUB_POD_UID);
        for request in requests.lock().unwrap().iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{request}"
            );
        }
    }

    #[tokio::test]
    async fn workspace_logs_read_the_workspace_container_of_that_member() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);

        // The stub has no log, so the read itself fails.
        assert!(
            driver
                .workspace_logs(&Placement::new("dev-sandboxes"), "workspace-a", 200)
                .await
                .is_err()
        );

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        let request = &requests[0];
        assert!(
            request.starts_with("GET /api/v1/namespaces/dev-sandboxes/pods/workspace-a/log?")
                && request.contains("container=workspace")
                && request.contains("tailLines=200")
                && request.contains("timestamps=true"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn replacing_an_incarnation_that_is_already_gone_writes_nothing() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let gone = MemberRef {
            name: "workspace-a".into(),
            uid: "an-earlier-incarnation".into(),
        };

        let replacement = driver
            .replace_member(
                &Placement::new("dev-sandboxes"),
                "env-1",
                &gone,
                "support-image",
            )
            .await
            .unwrap();

        assert_eq!(replacement, MemberReplacement::AlreadyReplaced);
        for request in requests.lock().unwrap().iter() {
            assert!(request.starts_with("GET "), "{request}");
        }
    }

    #[tokio::test]
    async fn replacing_the_current_incarnation_deletes_it_in_the_placement() {
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let current = MemberRef {
            name: "workspace-a".into(),
            uid: STUB_POD_UID.into(),
        };

        let replacement = driver
            .replace_member(
                &Placement::new("dev-sandboxes"),
                "env-1",
                &current,
                "support-image",
            )
            .await
            .unwrap();

        assert_eq!(replacement, MemberReplacement::Replaced);
        let requests = requests.lock().unwrap();
        assert!(
            requests.iter().any(|request| request
                .starts_with("DELETE /api/v1/namespaces/dev-sandboxes/pods/workspace-a")),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_replacement_is_a_ready_member_with_another_uid() {
        let (driver, _) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        let placement = Placement::new("dev-sandboxes");
        let member = |uid: &str| MemberRef {
            name: "workspace-a".into(),
            uid: uid.into(),
        };

        let replacement = driver
            .wait_replacement(
                &placement,
                &member("an-earlier-incarnation"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(replacement.uid, STUB_POD_UID);

        // The same UID has not been replaced, however ready it is.
        assert!(
            driver
                .wait_replacement(&placement, &member(STUB_POD_UID), Duration::from_millis(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_ssh_and_daemon_streams_each_reach_their_own_port() {
        let placement = Placement::new("dev-sandboxes");

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        // The stub can't upgrade the connection, so the stream itself fails.
        assert!(driver.ssh_stream(&placement, "env-1").await.is_err());
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=2222"),
            "{forwards:?}"
        );

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        assert!(driver.daemon_stream(&placement, "env-1").await.is_err());
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=7777"),
            "{forwards:?}"
        );
    }

    #[tokio::test]
    async fn the_ssh_stream_never_reaches_a_pod_its_sandbox_does_not_control() {
        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");

        assert!(
            driver
                .ssh_stream(&Placement::new("dev-sandboxes"), "env-1")
                .await
                .is_err()
        );

        assert_eq!(port_forwards(&requests), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_named_member_is_whatever_holds_that_name_in_the_placement() {
        // The stub's Pod is controlled by another Sandbox: a name alone says
        // nothing about control.
        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");
        let placement = Placement::new("dev-sandboxes");

        let member = driver
            .member_named(&placement, "workspace-a")
            .await
            .unwrap()
            .expect("a member");
        assert_eq!(member.name, "workspace-a");
        assert_eq!(member.uid, STUB_POD_UID);

        assert_eq!(
            driver
                .member_named(&placement, "workspace-gone")
                .await
                .unwrap(),
            None
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(
            requests[0].ends_with("/namespaces/dev-sandboxes/pods/workspace-a"),
            "{requests:?}"
        );
    }

    const OLD_SUPPORT_IMAGE: &str = "registry.test/codewire/support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW_SUPPORT_IMAGE: &str = "registry.test/codewire/support@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Each patch's path and body.
    type Patches = Arc<Mutex<Vec<(String, String)>>>;

    /// A claim and its running Sandbox, answering a patch with the operating
    /// mode it asked for.
    fn driver_over_patchable_sandbox() -> (Arc<dyn RuntimeDriver>, Patches) {
        let sandbox = "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes/sandbox-a";
        let patches = Arc::new(Mutex::new(Vec::new()));
        let seen = patches.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            async move {
                let path = request.uri().path().to_owned();
                let is_patch = request.method() == axum::http::Method::PATCH;
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body = String::from_utf8(body.to_vec()).unwrap();
                let mode = if body.contains("Suspended") {
                    "Suspended"
                } else {
                    "Running"
                };
                if is_patch {
                    seen.lock().unwrap().push((path.clone(), body));
                }
                let object = if path == sandbox {
                    json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes",
                            "uid": CONTROLLING_SANDBOX, "resourceVersion": "1"},
                        "spec": {"operatingMode": mode, "podTemplate": {"spec": {"volumes": [
                            {"name": crate::sandbox::template::DAEMON_VOLUME,
                                "image": {"reference": OLD_SUPPORT_IMAGE}}]}}}})
                } else {
                    json!({"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxClaim",
                        "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes",
                            "uid": "c0ffee00-e29b-41d4-a716-446655440000"},
                        "status": {"sandbox": {"name": "sandbox-a"}}})
                };
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(object.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), patches)
    }

    #[tokio::test]
    async fn the_current_runtime_is_patched_to_the_mode_asked_for_fenced_on_its_uid() {
        let placement = Placement::new("dev-sandboxes");
        for (mode, patches) in [
            ("Suspended", {
                let (driver, patches) = driver_over_patchable_sandbox();
                driver.suspend_current(&placement, "env-1").await.unwrap();
                patches
            }),
            ("Running", {
                let (driver, patches) = driver_over_patchable_sandbox();
                driver
                    .resume_current(&placement, "env-1", NEW_SUPPORT_IMAGE)
                    .await
                    .unwrap();
                patches
            }),
        ] {
            let patches = patches.lock().unwrap();
            assert_eq!(patches.len(), 1, "{patches:?}");
            let (path, body) = &patches[0];
            assert!(
                path.ends_with("/namespaces/dev-sandboxes/sandboxes/sandbox-a"),
                "{path}"
            );
            let operations: serde_json::Value = serde_json::from_str(body).unwrap();
            let operations = operations.as_array().unwrap();
            assert_eq!(
                operations.first().unwrap(),
                &json!({"op": "test", "path": "/metadata/uid", "value": CONTROLLING_SANDBOX})
            );
            assert_eq!(
                operations.last().unwrap(),
                &json!({"op": "add", "path": "/spec/operatingMode", "value": mode})
            );
            // Only a resume re-pins the daemon.
            assert_eq!(
                body.contains(NEW_SUPPORT_IMAGE),
                mode == "Running",
                "{body}"
            );
        }
    }

    struct OneHostKey;

    #[async_trait]
    impl HostKeyStore for OneHostKey {
        async fn current_host_key(
            &self,
            _environment_id: &str,
        ) -> Result<Option<(i64, String)>, sqlx::Error> {
            Ok(Some((
                1,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                    .into(),
            )))
        }
    }

    #[tokio::test]
    async fn the_ssh_check_reaches_the_ssh_port_of_a_runtime_its_sandbox_controls() {
        let placement = Placement::new("dev-sandboxes");

        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);
        // The stub can't upgrade the connection, so the check itself fails.
        assert!(
            driver
                .ssh_ready(&placement, "env-1", &OneHostKey)
                .await
                .is_err()
        );
        let forwards = port_forwards(&requests);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        assert!(
            forwards[0].contains("/namespaces/dev-sandboxes/pods/workspace-a/portforward")
                && forwards[0].contains("ports=2222"),
            "{forwards:?}"
        );

        let (driver, requests) = driver_over_addressless_pod("another-sandbox-uid");
        assert!(
            driver
                .ssh_ready(&placement, "env-1", &OneHostKey)
                .await
                .is_err()
        );
        assert_eq!(port_forwards(&requests), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_exec_runs_in_the_workspace_container_of_that_exact_member() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, requests) = driver_over_addressless_pod(CONTROLLING_SANDBOX);

        // The stub can't upgrade the connection, so the attachment fails.
        let attached = driver
            .start_exec(
                &placement,
                "workspace-b",
                &["true".to_owned()],
                "/workspace",
                &BTreeMap::new(),
            )
            .await;

        assert!(attached.is_err());
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "no lookup, only the attach: {requests:?}"
        );
        assert!(
            requests[0].contains("/namespaces/dev-sandboxes/pods/workspace-b/exec")
                && requests[0].contains("container=workspace"),
            "{requests:?}"
        );
    }

    const CLAIM_UID: &str = "c0ffee00-e29b-41d4-a716-446655440000";
    const PVC_UID: &str = "0a0b0c0d-1111-4222-8333-444455556666";

    fn stub_volume() -> VolumeRef {
        VolumeRef {
            claim_name: "sandbox-env-1".into(),
            claim_uid: CLAIM_UID.into(),
            recorded_pvc_uid: None,
        }
    }

    /// Each write's method, path and body.
    type Writes = Arc<Mutex<Vec<(String, String, String)>>>;

    /// A claim, its Sandbox, that Sandbox's running Pod and its volume of this
    /// mode, asking for 80 GiB and with `capacity_gib` so far. A write answers
    /// with the object as it was.
    fn driver_over_sized_runtime(
        volume_mode: &str,
        capacity_gib: i32,
    ) -> (Arc<dyn RuntimeDriver>, Writes) {
        driver_over_sized_runtime_with_volume_conditions(volume_mode, capacity_gib, json!([]))
    }

    fn driver_over_sized_runtime_with_volume_conditions(
        volume_mode: &str,
        capacity_gib: i32,
        volume_conditions: serde_json::Value,
    ) -> (Arc<dyn RuntimeDriver>, Writes) {
        let namespace = "/namespaces/dev-sandboxes";
        let owned_by_sandbox = json!([{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "name": "sandbox-a", "uid": CONTROLLING_SANDBOX, "controller": true}]);
        let workspace = json!({"name": "workspace", "image": "workspace:1",
            "resources": {"requests": {"cpu": "1", "memory": "1Gi"},
                "limits": {"cpu": "1", "memory": "1Gi"}}});
        let objects = [
            (
                format!(
                    "/apis/extensions.agents.x-k8s.io/v1beta1{namespace}/sandboxclaims/sandbox-env-1"
                ),
                json!({"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-1", "namespace": "dev-sandboxes",
                        "uid": CLAIM_UID},
                    "status": {"sandbox": {"name": "sandbox-a"}}}),
            ),
            (
                format!("/apis/agents.x-k8s.io/v1beta1{namespace}/sandboxes/sandbox-a"),
                json!({"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                    "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes",
                        "uid": CONTROLLING_SANDBOX, "resourceVersion": "1",
                        "annotations": {"agents.x-k8s.io/pod-name": "workspace-a"},
                        "ownerReferences": [{"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                            "kind": "SandboxClaim", "name": "sandbox-env-1", "uid": CLAIM_UID,
                            "controller": true}]},
                    "spec": {"podTemplate": {"spec": {"containers": [workspace.clone()]}},
                        "volumeClaimTemplates": [{"metadata": {"name": "workspace"}}]}}),
            ),
            (
                format!("/api/v1{namespace}/pods/workspace-a"),
                json!({"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "workspace-a", "namespace": "dev-sandboxes",
                        "uid": STUB_POD_UID, "resourceVersion": "7",
                        "ownerReferences": owned_by_sandbox},
                    "spec": {"runtimeClassName": "kata", "containers": [workspace]},
                    "status": {"phase": "Running", "podIP": "10.0.0.7",
                        "containerStatuses": [{"name": "workspace", "ready": true,
                            "image": "", "imageID": "", "restartCount": 2}]}}),
            ),
            (
                format!("/api/v1{namespace}/persistentvolumeclaims/workspace-sandbox-a"),
                json!({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                    "metadata": {"name": "workspace-sandbox-a", "namespace": "dev-sandboxes",
                        "uid": PVC_UID, "ownerReferences": owned_by_sandbox},
                    "spec": {"storageClassName": "fast", "volumeMode": volume_mode,
                        "resources": {"requests": {"storage": "80Gi"}}},
                    "status": {"phase": "Bound", "conditions": volume_conditions,
                        "capacity": {"storage": format!("{capacity_gib}Gi")}}}),
            ),
            (
                "/apis/storage.k8s.io/v1/storageclasses/fast".to_owned(),
                json!({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
                    "metadata": {"name": "fast"}, "provisioner": "csi.test",
                    "allowVolumeExpansion": true}),
            ),
        ];
        let writes = Arc::new(Mutex::new(Vec::new()));
        let seen = writes.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            let objects = objects.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                if method != "GET" {
                    seen.lock().unwrap().push((
                        method,
                        path.clone(),
                        String::from_utf8(body.to_vec()).unwrap(),
                    ));
                }
                let object = path.strip_suffix("/resize").unwrap_or(&path);
                let (status, body) = objects.iter().find(|(known, _)| known == object).map_or(
                    (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "code": 404}),
                    ),
                    |(_, object)| (StatusCode::OK, object.clone()),
                );
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), writes)
    }

    #[tokio::test]
    async fn a_volume_carries_its_mode_and_is_found_through_its_claim() {
        let placement = Placement::new("dev-sandboxes");
        for (mode, raw_block) in [("Block", true), ("Filesystem", false)] {
            let (driver, _) = driver_over_sized_runtime(mode, 80);

            let volume = driver.volume(&placement, &stub_volume()).await.unwrap();

            assert_eq!(volume.pvc_name, "workspace-sandbox-a");
            assert_eq!(volume.pvc_uid, PVC_UID);
            assert_eq!(volume.requested_disk_gb, 80);
            assert_eq!(volume.raw_block, raw_block);
        }

        let (driver, _) = driver_over_sized_runtime("Block", 80);
        let replaced = VolumeRef {
            claim_uid: "another-claim-uid".into(),
            ..stub_volume()
        };
        assert!(driver.volume(&placement, &replaced).await.is_err());
    }

    #[tokio::test]
    async fn growing_a_volume_writes_only_when_asked_and_is_fenced_on_its_uid() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        assert_eq!(
            driver
                .check_volume_growth(&placement, &stub_volume(), 100)
                .await
                .unwrap()
                .pvc_uid,
            PVC_UID
        );
        let shrink = driver
            .check_volume_growth(&placement, &stub_volume(), 40)
            .await
            .unwrap_err();
        assert_eq!(
            shrink.to_string(),
            "persistent storage cannot shrink from 80 Gi to 40 Gi"
        );
        assert_eq!(*writes.lock().unwrap(), Vec::new());

        driver
            .grow_volume(&placement, &stub_volume(), 100)
            .await
            .unwrap();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "{writes:?}");
        let (method, path, body) = &writes[0];
        assert_eq!(method, "PATCH");
        assert!(
            path.ends_with("/namespaces/dev-sandboxes/persistentvolumeclaims/workspace-sandbox-a"),
            "{path}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            json!({"metadata": {"uid": PVC_UID},
                "spec": {"resources": {"requests": {"storage": "100Gi"}}}})
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_grown_block_volume_needs_a_new_member_and_a_filesystem_one_does_not() {
        let placement = Placement::new("dev-sandboxes");
        let timeout = Duration::from_secs(5);
        for (mode, growth) in [
            ("Block", VolumeGrowth::RequiresPodRestart),
            ("Filesystem", VolumeGrowth::Applied),
        ] {
            let (driver, _) = driver_over_sized_runtime(mode, 100);
            assert_eq!(
                driver
                    .wait_volume_growth(&placement, &stub_volume(), 100, timeout)
                    .await
                    .unwrap(),
                growth
            );
            driver
                .wait_volume_capacity(&placement, &stub_volume(), 100, timeout)
                .await
                .unwrap();
        }

        let (driver, _) = driver_over_sized_runtime("Filesystem", 80);
        assert!(
            driver
                .wait_volume_growth(&placement, &stub_volume(), 100, timeout)
                .await
                .is_err()
        );
        assert!(
            driver
                .wait_volume_capacity(&placement, &stub_volume(), 100, timeout)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_filesystem_volume_waiting_for_its_mount_needs_a_new_member_and_has_not_grown() {
        let placement = Placement::new("dev-sandboxes");
        let timeout = Duration::from_millis(50);
        let (driver, _) = driver_over_sized_runtime_with_volume_conditions(
            "Filesystem",
            80,
            json!([{"type": "FileSystemResizePending", "status": "True"}]),
        );

        assert_eq!(
            driver
                .wait_volume_growth(&placement, &stub_volume(), 100, timeout)
                .await
                .unwrap(),
            VolumeGrowth::RequiresPodRestart
        );
        // The capacity itself is what this wait reads, so the condition doesn't end it.
        assert!(
            driver
                .wait_volume_capacity(&placement, &stub_volume(), 100, timeout)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resize_state_and_address_describe_the_member_its_sandbox_controls() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        let state = driver.resize_state(&placement, "env-1").await.unwrap();

        assert_eq!(state.identity.name, "workspace-a");
        assert_eq!(state.identity.uid, STUB_POD_UID);
        assert_eq!(state.runtime_class_name, "kata");
        assert_eq!(state.restart_count, 2);
        assert_eq!(
            driver.member_address(&placement, "env-1").await.unwrap(),
            "10.0.0.7"
        );
        assert_eq!(*writes.lock().unwrap(), Vec::new());
    }

    #[tokio::test]
    async fn the_desired_size_is_written_to_the_claim_and_its_sandbox() {
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        driver
            .set_desired_size(&Placement::new("dev-sandboxes"), "env-1", 2000, 4096, 100)
            .await
            .unwrap();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 2, "{writes:?}");
        assert!(
            writes[0].1.ends_with("/sandboxclaims/sandbox-env-1"),
            "{writes:?}"
        );
        assert!(writes[1].1.ends_with("/sandboxes/sandbox-a"), "{writes:?}");
        for (_, _, body) in writes.iter() {
            assert!(body.contains("4096Mi"), "{body}");
            assert!(
                body.contains("\"cpu\":\"2\"") || body.contains("2000m"),
                "{body}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_in_place_resize_asks_this_exact_member_for_that_size() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        // The stub's Pod never changes, so the wait runs out after the request.
        assert!(
            driver
                .resize_in_place(
                    &placement,
                    "env-1",
                    STUB_POD_UID,
                    2000,
                    4096,
                    Duration::from_secs(5),
                )
                .await
                .is_err()
        );
        {
            let writes = writes.lock().unwrap();
            assert_eq!(writes.len(), 1, "{writes:?}");
            let (_, path, body) = &writes[0];
            assert!(
                path.ends_with("/namespaces/dev-sandboxes/pods/workspace-a/resize"),
                "{path}"
            );
            assert!(
                body.contains(STUB_POD_UID) && body.contains("4096Mi"),
                "{body}"
            );
        }

        let (driver, writes) = driver_over_sized_runtime("Block", 80);
        assert!(
            driver
                .resize_in_place(
                    &placement,
                    "env-1",
                    "another-uid",
                    2000,
                    4096,
                    Duration::from_secs(5),
                )
                .await
                .is_err()
        );
        assert_eq!(*writes.lock().unwrap(), Vec::new());
    }

    #[tokio::test(start_paused = true)]
    async fn settling_a_failed_resize_withdraws_it_back_to_the_previous_size() {
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        // The stub's Pod never changes, so the withdrawal doesn't settle.
        let settled = driver
            .settle_failed_resize(
                &Placement::new("dev-sandboxes"),
                "env-1",
                STUB_POD_UID,
                (3000, 8192),
                (2000, 4096),
                Duration::from_secs(5),
            )
            .await;

        assert!(
            matches!(settled, FailedLiveResize::Unknown(_)),
            "{settled:?}"
        );
        let writes = writes.lock().unwrap();
        assert!(!writes.is_empty());
        for (_, path, body) in writes.iter() {
            assert!(path.ends_with("/pods/workspace-a/resize"), "{path}");
            assert!(
                body.contains("8192Mi") && !body.contains("4096Mi"),
                "{body}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn settling_a_failed_resize_leaves_a_replaced_member_alone() {
        let (driver, writes) = driver_over_sized_runtime("Block", 80);

        let settled = driver
            .settle_failed_resize(
                &Placement::new("dev-sandboxes"),
                "env-1",
                "another-uid",
                (1000, 1024),
                (2000, 4096),
                Duration::from_secs(5),
            )
            .await;

        assert!(
            matches!(settled, FailedLiveResize::Unknown(_)),
            "{settled:?}"
        );
        assert_eq!(*writes.lock().unwrap(), Vec::new());
    }

    /// An API server where every snapshot is ready, recording what is written.
    /// Everything else is absent.
    fn driver_over_ready_snapshots(source_mode: &str) -> (Arc<dyn RuntimeDriver>, Writes) {
        let source_mode = source_mode.to_owned();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let seen = writes.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            let source_mode = source_mode.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                if method != "GET" {
                    seen.lock().unwrap().push((
                        method.clone(),
                        path.clone(),
                        String::from_utf8(body.to_vec()).unwrap(),
                    ));
                }
                let name = path.rsplit('/').next().unwrap_or_default().to_owned();
                let snapshot = json!({"apiVersion": "snapshot.storage.k8s.io/v1",
                    "kind": "VolumeSnapshot",
                    "metadata": {"name": name, "namespace": "dev-sandboxes", "labels": {
                        crate::sandbox::snapshots::LABEL_SOURCE_VOLUME_MODE: source_mode}},
                    "status": {"readyToUse": true, "restoreSize": name}});
                let found = path.contains("/volumesnapshots")
                    && (method == "POST" || path.contains("/volumesnapshots/"));
                let (status, body) = if found && method != "DELETE" {
                    (StatusCode::OK, snapshot)
                } else {
                    (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion": "v1", "kind": "Status",
                        "status": "Failure", "reason": "NotFound", "code": 404}),
                    )
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), writes)
    }

    fn stub_volume_identity(raw_block: bool) -> VolumeIdentity {
        VolumeIdentity {
            pvc_name: "workspace-sandbox-a".into(),
            pvc_uid: PVC_UID.into(),
            storage_class_name: "fast".into(),
            requested_disk_gb: 80,
            applied_disk_gb: Some(80),
            filesystem_resize_pending: false,
            expansion_allowed: true,
            raw_block,
            confidential: false,
        }
    }

    #[tokio::test]
    async fn the_raw_snapshot_is_of_the_source_volume_and_records_its_mode() {
        let placement = Placement::new("dev-sandboxes");
        for (raw_block, mode) in [(true, VolumeMode::Block), (false, VolumeMode::Filesystem)] {
            let (driver, writes) = driver_over_ready_snapshots("");

            driver
                .snapshot_volume(
                    &placement,
                    "snap-1",
                    &stub_volume_identity(raw_block),
                    "class-a",
                )
                .await
                .unwrap();

            let writes = writes.lock().unwrap();
            assert_eq!(writes.len(), 1, "{writes:?}");
            let (method, path, body) = &writes[0];
            assert_eq!(method, "POST");
            assert!(
                path.contains("/namespaces/dev-sandboxes/volumesnapshots"),
                "{path}"
            );
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                body.pointer("/metadata/name").unwrap(),
                raw_snapshot_name("snap-1").as_str()
            );
            assert_eq!(
                body.pointer("/spec/source/persistentVolumeClaimName")
                    .unwrap(),
                "workspace-sandbox-a"
            );
            assert_eq!(
                body.pointer("/spec/volumeSnapshotClassName").unwrap(),
                "class-a"
            );
            assert_eq!(
                body.pointer("/metadata/labels").unwrap()
                    [crate::sandbox::snapshots::LABEL_SOURCE_VOLUME_MODE],
                mode.as_str()
            );
        }
    }

    #[tokio::test]
    async fn the_kept_snapshot_is_of_the_cleared_volume_and_never_the_source() {
        let (driver, writes) = driver_over_ready_snapshots("");

        driver
            .keep_cleared_volume(&Placement::new("dev-sandboxes"), "snap-1", "class-a")
            .await
            .unwrap();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "{writes:?}");
        let body: serde_json::Value = serde_json::from_str(&writes[0].2).unwrap();
        assert_eq!(
            body.pointer("/metadata/name").unwrap(),
            kept_snapshot_name("snap-1").as_str()
        );
        assert_eq!(
            body.pointer("/spec/volumeSnapshotClassName").unwrap(),
            "class-a"
        );
        assert_eq!(
            body.pointer("/spec/source/persistentVolumeClaimName")
                .unwrap(),
            clearing_volume_name("snap-1").as_str()
        );
    }

    #[tokio::test]
    async fn each_stage_waits_for_its_own_snapshot_and_the_raw_one_gives_the_mode() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, _) = driver_over_ready_snapshots("Block");
        let timeout = Duration::from_secs(5);

        // The stub reports each snapshot's name as its size.
        assert_eq!(
            driver
                .wait_snapshot(&placement, "snap-1", CaptureStage::Raw, timeout)
                .await
                .unwrap(),
            raw_snapshot_name("snap-1")
        );
        assert_eq!(
            driver
                .wait_snapshot(&placement, "snap-1", CaptureStage::Kept, timeout)
                .await
                .unwrap(),
            kept_snapshot_name("snap-1")
        );
        assert_eq!(
            driver
                .raw_snapshot_mode(&placement, "snap-1")
                .await
                .unwrap(),
            VolumeMode::Block
        );
    }

    #[tokio::test]
    async fn a_clearing_that_has_not_started_is_pending_and_stopping_it_is_done() {
        let placement = Placement::new("dev-sandboxes");
        let (driver, writes) = driver_over_ready_snapshots("");

        assert_eq!(
            driver
                .clearing_progress(&placement, "snap-1")
                .await
                .unwrap(),
            ClearingProgress::Pending
        );
        driver
            .stop_clearing(&placement, "snap-1", Duration::from_secs(5))
            .await
            .unwrap();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(writes[0].0, "PATCH");
        assert!(writes[0].2.contains("Suspended"), "{writes:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn deleting_a_capture_keeps_the_kept_snapshot_only_when_asked() {
        let placement = Placement::new("dev-sandboxes");
        let deleted_kept = |writes: &Writes| {
            writes
                .lock()
                .unwrap()
                .iter()
                .any(|(_, path, _)| path.ends_with(&kept_snapshot_name("snap-1")))
        };
        for (kept, deleted) in [(KeptSnapshot::Retain, false), (KeptSnapshot::Delete, true)] {
            let (driver, writes) = driver_over_ready_snapshots("");

            // The stub keeps answering for a deleted snapshot, so the wait ends in error.
            let _ = driver
                .delete_capture(&placement, "snap-1", kept, Duration::from_secs(5))
                .await;

            assert_eq!(deleted_kept(&writes), deleted);
            assert!(
                writes
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(method, path, _)| method == "DELETE"
                        && path.ends_with(&raw_snapshot_name("snap-1"))),
                "the raw snapshot always goes"
            );
        }
    }

    #[tokio::test]
    async fn probe_reads_the_placement_and_finds_nothing_in_one_request() {
        let (driver, requests) = driver_over_empty_cluster();

        let probe = driver
            .probe(&Placement::new("dev-sandboxes"), "env-1")
            .await
            .unwrap();

        assert!(!probe.claim_exists);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].contains("/namespaces/dev-sandboxes/sandboxclaims/"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn listing_members_reads_the_placement_in_one_request() {
        let (driver, requests) = driver_over_empty_cluster();

        let members = driver
            .list_members(&Placement::new("dev-sandboxes"))
            .await
            .unwrap();

        assert!(members.is_empty());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxes"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn members_are_read_from_the_placement_with_the_known_member_rechecked() {
        let (driver, requests) = driver_over_empty_cluster();

        let members = driver
            .members(&Placement::new("dev-sandboxes"), "env-1", "known-pod")
            .await
            .unwrap();

        assert!(members.is_empty());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(
            requests[0].ends_with("/namespaces/dev-sandboxes/pods")
                && requests[1].ends_with("/namespaces/dev-sandboxes/pods/known-pod"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn suspending_acts_only_on_the_claims_placement() {
        let (driver, requests) = driver_over_empty_cluster();
        let claim = ClaimRef {
            placement: Placement::new("dev-sandboxes"),
            environment_id: "env-1".into(),
            organization_id: "org-1".into(),
            operation_generation: 3,
            name: "claim-1".into(),
            uid: "claim-uid-1".into(),
        };

        // There is no claim to own, so it refuses after reading only.
        assert!(driver.suspend(&claim).await.is_err());

        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert!(
                request.starts_with("GET ") && request.contains("/namespaces/dev-sandboxes/"),
                "{requests:?}"
            );
        }
    }

    #[tokio::test]
    async fn retiring_reads_the_placement_and_stops_when_no_pool_is_left() {
        let (driver, requests) = driver_over_empty_cluster();

        let retired = driver
            .retire_legacy_shared_pools(&Placement::new("dev-sandboxes"))
            .await
            .unwrap();

        assert_eq!(retired, 0);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("GET ")
                && requests[0].ends_with("/namespaces/dev-sandboxes/sandboxwarmpools"),
            "{requests:?}"
        );
    }

    /// An API server holding nothing, where creating a SandboxWarmPool fails
    /// if `pools_fail`, recording every write.
    fn driver_over_claimable_cluster(pools_fail: bool) -> (Arc<dyn RuntimeDriver>, Writes) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let seen = writes.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let seen = seen.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body = String::from_utf8(body.to_vec()).unwrap();
                if method != "GET" {
                    seen.lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), body.clone()));
                }
                let (status, body) = match method.as_str() {
                    "POST" if pools_fail && path.ends_with("/sandboxwarmpools") => (
                        StatusCode::FORBIDDEN,
                        json!({"apiVersion": "v1", "kind": "Status",
                            "status": "Failure", "reason": "Forbidden", "code": 403}),
                    ),
                    "POST" => {
                        let mut created: serde_json::Value = serde_json::from_str(&body).unwrap();
                        created["metadata"]["uid"] = json!("claim-uid");
                        (StatusCode::CREATED, created)
                    }
                    "DELETE" => (
                        StatusCode::OK,
                        json!({"apiVersion": "v1", "kind": "Status", "status": "Success"}),
                    ),
                    _ => (
                        StatusCode::NOT_FOUND,
                        json!({"apiVersion": "v1", "kind": "Status",
                            "status": "Failure", "reason": "NotFound", "code": 404}),
                    ),
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = kube::Client::new(service, "the-default-namespace");
        (KubernetesDriver::shared(client), writes)
    }

    fn cold_claim_opts() -> ClaimOpts {
        ClaimOpts {
            environment_id: "env-1".into(),
            org_id: "org-1".into(),
            operation_generation: 7,
            template_ref: "workspace-env-1".into(),
            warm_pool_ref: shadow_warm_pool_name("workspace-env-1"),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_pool_claim_names_only_its_pool_and_a_cold_one_the_environments_own() {
        let placement = Placement::new("dev-sandboxes");
        for (pick, pool) in [
            (Pick::Pool("cw-pool-a".into()), "cw-pool-a".to_owned()),
            (Pick::Cold, shadow_warm_pool_name("workspace-env-1")),
        ] {
            let (driver, writes) = driver_over_claimable_cluster(false);
            let claim = driver
                .claim(&placement, &cold_claim_opts(), &pick)
                .await
                .unwrap();
            assert_eq!(
                claim,
                ClaimRef {
                    placement: placement.clone(),
                    environment_id: "env-1".into(),
                    organization_id: "org-1".into(),
                    operation_generation: 7,
                    name: "sandbox-env-1".into(),
                    uid: "claim-uid".into(),
                }
            );
            let writes = writes.lock().unwrap();
            assert_eq!(writes.len(), 1, "{writes:?}");
            let (method, path, body) = &writes[0];
            assert_eq!(method, "POST");
            assert!(
                path.ends_with("/namespaces/dev-sandboxes/sandboxclaims"),
                "{path}"
            );
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                body["spec"]["warmPoolRef"]["name"],
                pool.as_str(),
                "{pick:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_cold_claim_is_prepared_with_its_template_then_its_shadow_pool() {
        let placement = Placement::new("dev-sandboxes");
        let rendering = TemplateOpts {
            name: "workspace-env-1".into(),
            environment_id: "env-1".into(),
            ..Default::default()
        };
        let (driver, writes) = driver_over_claimable_cluster(false);
        driver
            .prepare_cold_claim(&placement, &rendering, &cold_claim_opts())
            .await
            .unwrap();
        let writes_of = |writes: &Writes| -> Vec<String> {
            writes
                .lock()
                .unwrap()
                .iter()
                .map(|(method, path, _)| {
                    let resource = path.split("/namespaces/").nth(1).unwrap_or(path);
                    format!("{method} {resource}")
                })
                .collect()
        };
        assert_eq!(
            writes_of(&writes),
            [
                "POST dev-sandboxes/sandboxtemplates",
                "POST dev-sandboxes/sandboxwarmpools",
            ]
        );

        // A shadow pool that can't be made takes its template with it, and
        // says which step failed.
        let (driver, writes) = driver_over_claimable_cluster(true);
        let error = driver
            .prepare_cold_claim(&placement, &rendering, &cold_claim_opts())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").starts_with("shadow pool: "),
            "{error:#}"
        );
        assert_eq!(
            writes_of(&writes),
            [
                "POST dev-sandboxes/sandboxtemplates",
                "POST dev-sandboxes/sandboxwarmpools",
                "DELETE dev-sandboxes/sandboxtemplates/workspace-env-1",
            ]
        );
    }

    #[tokio::test]
    async fn withdrawing_a_pool_born_claim_removes_its_bridge_before_the_claim() {
        let (driver, writes) = driver_over_claimable_cluster(false);
        let observed = PoolBornClaim {
            claim_uid: "claim-uid".into(),
            pool: "cw-pool-a".into(),
            sandbox: Some(("cw-pool-a-x".into(), "sandbox-uid".into())),
        };
        driver
            .withdraw_pool_born_claim(
                &Placement::new("dev-sandboxes"),
                "env-1",
                &observed,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        let writes = writes.lock().unwrap();
        assert!(!writes.is_empty(), "{writes:?}");
        assert!(
            writes[0].1.contains("/networkpolicies"),
            "the bridge goes first: {writes:?}"
        );
        assert!(
            writes.iter().all(|(method, _, _)| method == "DELETE"),
            "{writes:?}"
        );
        // The claim is absent, so only the observed Sandbox is deleted, by UID.
        let (_, path, body) = writes.last().unwrap();
        assert!(path.ends_with("/sandboxes/cw-pool-a-x"), "{path}");
        assert!(body.contains("sandbox-uid"), "{body}");
    }

    #[tokio::test]
    async fn a_terminal_member_is_looked_for_only_in_the_placement() {
        let (driver, requests) = driver_over_empty_cluster();
        assert_eq!(
            driver
                .terminal_member(&Placement::new("dev-sandboxes"), "env-1")
                .await
                .unwrap(),
            None
        );
        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|request| request == "GET /api/v1/namespaces/dev-sandboxes/pods"),
            "{requests:?}"
        );
    }

    /// The measured runtime is seen on the exact incarnation through its
    /// confidential init-data annotation.
    #[tokio::test]
    async fn a_measured_runtime_is_waited_for_on_that_exact_incarnation() {
        let service = Router::new().fallback(move |request: Request<Body>| async move {
            let path = request.uri().path().to_owned();
            let pod = json!({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "sandbox-a", "namespace": "dev-sandboxes", "uid": "pod-uid",
                    "annotations": {KATA_COCO_INIT_DATA_ANNOTATION_KEY: "measured"}}});
            let (status, body) = if path == "/api/v1/namespaces/dev-sandboxes/pods/sandbox-a" {
                (StatusCode::OK, pod)
            } else {
                (
                    StatusCode::NOT_FOUND,
                    json!({"apiVersion": "v1", "kind": "Status",
                        "status": "Failure", "reason": "NotFound", "code": 404}),
                )
            };
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        });
        let driver = KubernetesDriver::shared(kube::Client::new(service, "the-default-namespace"));
        let placement = Placement::new("dev-sandboxes");
        let member = MemberRef {
            name: "sandbox-a".into(),
            uid: "pod-uid".into(),
        };
        driver
            .wait_measured_runtime(&placement, &member, "measured", Duration::from_secs(1))
            .await
            .unwrap();
        // Another incarnation under the name is never taken for this one.
        let replaced = MemberRef {
            name: "sandbox-a".into(),
            uid: "another-uid".into(),
        };
        assert!(
            driver
                .wait_measured_runtime(&placement, &replaced, "measured", Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(
            driver
                .wait_measured_runtime(&placement, &member, "other", Duration::from_millis(300))
                .await
                .is_err()
        );
    }
}
