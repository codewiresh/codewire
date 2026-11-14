//! A second driver, to prove the traits don't depend on Kubernetes and to
//! drive caller logic in tests. Behaviour stays proven against
//! [`KubernetesDriver`](super::kubernetes::KubernetesDriver): a fake only
//! returns what its test scripted.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::oneshot;

use super::{
    CaptureStage, ClaimReadiness, ClaimRef, ClearingOpts, ClearingProgress, FailedLiveResize,
    Incarnation, KeptSnapshot, MemberEvidence, MemberReplacement, Pick, Placement, PoolBornClaim,
    PoolPass, PoolState, RenderingIntent, ResizeState, RuntimeAccess, RuntimeClaims, RuntimeExec,
    RuntimeLifecycle, RuntimeMember, RuntimePools, RuntimeProbe, RuntimeResize, RuntimeSnapshots,
    RuntimeStorage, RuntimeStream, RuntimeTeardown, SuspendedRuntime, VolumeGrowth, VolumeIdentity,
    VolumeMode, VolumeRef, WantedPool, WantedPools,
};
use super::{
    MemberFacts, RuntimeAttestation, RuntimeFacts, RuntimeObservation, RuntimeObservations,
    VerifiedChain, WorkspaceVolume,
};
use crate::sandbox::ClaimOpts;
use crate::sandbox::host_keys::HostKeyStore;

#[derive(Default)]
pub(crate) struct FakeRuntimeDriver {
    pub probe: RuntimeProbe,
    pub members: Mutex<Vec<RuntimeMember>>,
    /// When set, listing members fails with this message.
    pub members_error: Mutex<Option<String>>,
    /// When set, `ensure_placement` refuses with this message, as a Sandbox
    /// namespace without its labels does.
    pub placement_error: Mutex<Option<String>>,
    /// Each read of an environment's members, in order; the last one repeats.
    pub member_reads: Mutex<VecDeque<Vec<Incarnation>>>,
    /// What replacing a member answers.
    pub replacement: Mutex<Option<MemberReplacement>>,
    /// Each replacement and replacement wait asked for, in order.
    pub replacement_calls: Mutex<Vec<String>>,
    /// What waiting for a replacement answers; unscripted, it fails.
    pub replaced: Mutex<Option<Incarnation>>,
    /// What publishing a measured runtime returns; unscripted, it fails. The
    /// publish and its wait are recorded with the replacement calls, in order.
    pub measured_runtime: Mutex<Option<String>>,
    /// The init data a measured runtime is measured with; unscripted, no
    /// runtime is measured.
    pub measured_init_data: Mutex<Option<String>>,
    /// The authorization each bootstrap refresh was given, in order.
    pub refreshed: Mutex<Vec<Option<[u8; 32]>>>,
    /// The claim's readiness; an error is its message.
    pub claim_readiness: Mutex<Option<Result<ClaimReadiness, String>>>,
    /// Every placement a method was asked about, in order.
    pub placements: Mutex<Vec<Placement>>,
    /// Each step of a capture's keep asked for, in order.
    pub snapshot_calls: Mutex<Vec<String>>,
    /// What waiting for the kept snapshot answers, its restore size.
    pub kept_size: Mutex<Option<String>>,
    /// When set, keeping the cleared volume says it has begun on the sender,
    /// then waits for the receiver before it returns.
    pub keep_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    /// What a pool's state answers.
    pub pool_state: Mutex<Option<PoolState>>,
    /// What `confidential_hosts` answers; unscripted, unknown.
    pub confidential_hosts: Mutex<Option<u32>>,
    /// Each pool pass's answer, in order; an error is its message.
    pub pool_passes: Mutex<VecDeque<Result<PoolPass, String>>>,
    /// How many times pool memory was forgotten.
    pub pool_memory_forgotten: Mutex<usize>,
}

#[async_trait]
impl RuntimePools for FakeRuntimeDriver {
    async fn pool_state(
        &self,
        placement: &Placement,
        _pool: &WantedPool,
        _intent: &RenderingIntent,
    ) -> anyhow::Result<PoolState> {
        self.placements.lock().unwrap().push(placement.clone());
        // Unscripted, it stands for a placement without pools: every create
        // is cold (cw-billing's #3628 PR 5c condition 1).
        Ok(self
            .pool_state
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(PoolState::NoPools))
    }

    async fn pool_birth(
        &self,
        placement: &Placement,
        _pool: &WantedPool,
        _observation: &RuntimeObservation,
    ) -> Result<(), String> {
        self.placements.lock().unwrap().push(placement.clone());
        Err("this placement has no pools".to_owned())
    }

    async fn confidential_hosts(&self, placement: &Placement) -> Option<u32> {
        self.placements.lock().unwrap().push(placement.clone());
        *self.confidential_hosts.lock().unwrap()
    }

    async fn keep_pools(
        &self,
        placement: &Placement,
        _wanted: &WantedPools,
    ) -> anyhow::Result<PoolPass> {
        self.placements.lock().unwrap().push(placement.clone());
        self.pool_passes
            .lock()
            .unwrap()
            .pop_front()
            .expect("the test scripts every pool pass")
            .map_err(anyhow::Error::msg)
    }

    fn forget_pool_memory(&self) {
        *self.pool_memory_forgotten.lock().unwrap() += 1;
    }

    async fn rotating_pools(
        &self,
        placement: &Placement,
        _wanted: &WantedPools,
    ) -> anyhow::Result<Vec<WantedPool>> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(Vec::new())
    }

    async fn warm_pools(&self, placement: &Placement, _pools: &[WantedPool]) -> anyhow::Result<()> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(())
    }
}

#[async_trait]
impl RuntimeClaims for FakeRuntimeDriver {
    async fn ensure_placement(&self, placement: &Placement) -> anyhow::Result<()> {
        if let Some(error) = self.placement_error.lock().unwrap().clone() {
            anyhow::bail!(error);
        }
        self.placements.lock().unwrap().push(placement.clone());
        Ok(())
    }

    async fn prepare_cold_claim(
        &self,
        placement: &Placement,
        _intent: &RenderingIntent,
        _claim: &ClaimOpts,
        _authorized: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(())
    }

    async fn claim(
        &self,
        placement: &Placement,
        claim: &ClaimOpts,
        _pick: &Pick,
    ) -> anyhow::Result<ClaimRef> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(ClaimRef {
            placement: placement.clone(),
            environment_id: claim.environment_id.clone(),
            organization_id: claim.org_id.clone(),
            operation_generation: claim.operation_generation,
            name: format!("claim-{}", claim.environment_id),
            uid: format!("claim-uid-{}", claim.environment_id),
        })
    }

    async fn bridge_adopted_member(
        &self,
        placement: &Placement,
        _intent: &RenderingIntent,
        _runtime_uid: &str,
    ) -> anyhow::Result<()> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(())
    }

    async fn pool_born_claim(
        &self,
        placement: &Placement,
        _environment_id: &str,
        _claim_uid: &str,
    ) -> anyhow::Result<Option<PoolBornClaim>> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(None)
    }

    async fn withdraw_pool_born_claim(
        &self,
        placement: &Placement,
        _environment_id: &str,
        _observed: &PoolBornClaim,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(())
    }
}

#[async_trait]
impl RuntimeAttestation for FakeRuntimeDriver {
    async fn review_member_credential(
        &self,
        _headers: &axum::http::HeaderMap,
    ) -> Result<
        codewire_server_core::pod_identity::VerifiedPodIdentity,
        codewire_server_core::pod_identity::PodIdentityError,
    > {
        Err(codewire_server_core::pod_identity::PodIdentityError::Unavailable)
    }

    async fn attested_member(
        &self,
        _identity: &codewire_server_core::pod_identity::VerifiedPodIdentity,
    ) -> anyhow::Result<Option<MemberFacts>> {
        anyhow::bail!("not scripted")
    }

    async fn attested_runtime(
        &self,
        placement: &Placement,
        _name: &str,
    ) -> anyhow::Result<Option<RuntimeFacts>> {
        self.placements.lock().unwrap().push(placement.clone());
        anyhow::bail!("not scripted")
    }

    async fn member_transport_zone(&self, _member: &MemberFacts) -> anyhow::Result<Option<String>> {
        anyhow::bail!("not scripted")
    }

    async fn direct_udp_endpoints(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> Vec<String> {
        self.placements.lock().unwrap().push(placement.clone());
        Vec::new()
    }
}

#[async_trait]
impl RuntimeObservations for FakeRuntimeDriver {
    async fn observe(&self, claim: &ClaimRef) -> anyhow::Result<RuntimeObservation> {
        self.placements
            .lock()
            .unwrap()
            .push(claim.placement.clone());
        anyhow::bail!("not scripted")
    }

    async fn observe_member(
        &self,
        placement: &Placement,
        _member_name: &str,
    ) -> anyhow::Result<Option<MemberFacts>> {
        self.placements.lock().unwrap().push(placement.clone());
        anyhow::bail!("not scripted")
    }

    async fn current_member_facts(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<MemberFacts> {
        self.placements.lock().unwrap().push(placement.clone());
        anyhow::bail!("not scripted")
    }

    async fn workspace_volume(
        &self,
        placement: &Placement,
        _volume: &VolumeRef,
    ) -> anyhow::Result<WorkspaceVolume> {
        self.placements.lock().unwrap().push(placement.clone());
        anyhow::bail!("not scripted")
    }

    async fn wait_member_change(
        &self,
        _placement: &Placement,
        _observation: &RuntimeObservation,
        _poll: Duration,
        _fallback: Duration,
    ) {
    }

    async fn wait_claim_change(
        &self,
        _placement: &Placement,
        _observation: &RuntimeObservation,
        _fallback: Duration,
    ) {
    }

    async fn wait_runtime_identity(
        &self,
        _claim: &ClaimRef,
        _chain: &VerifiedChain,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn repin_daemon_image(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _support_image: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn delete_refused_member(
        &self,
        _placement: &Placement,
        _member: &Incarnation,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn volume_created_at(
        &self,
        placement: &Placement,
        _probe: &RuntimeProbe,
    ) -> anyhow::Result<Option<k8s_openapi::jiff::Timestamp>> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(None)
    }
}

#[async_trait]
impl RuntimeLifecycle for FakeRuntimeDriver {
    fn check_rendering(&self, _intent: &RenderingIntent) -> anyhow::Result<()> {
        Ok(())
    }

    fn check_runtime_profile(&self, _intent: &RenderingIntent) -> Result<(), String> {
        Ok(())
    }

    fn measured_init_data(&self, _intent: &RenderingIntent) -> anyhow::Result<Option<String>> {
        Ok(self.measured_init_data.lock().unwrap().clone())
    }

    async fn probe(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<RuntimeProbe> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(self.probe.clone())
    }

    async fn list_members(&self, placement: &Placement) -> anyhow::Result<Vec<RuntimeMember>> {
        self.placements.lock().unwrap().push(placement.clone());
        if let Some(error) = self.members_error.lock().unwrap().clone() {
            anyhow::bail!(error);
        }
        Ok(self.members.lock().unwrap().clone())
    }

    async fn members(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _known_member: &str,
    ) -> anyhow::Result<Vec<Incarnation>> {
        let mut reads = self.member_reads.lock().unwrap();
        if reads.len() > 1 {
            return Ok(reads.pop_front().expect("more than one read"));
        }
        match reads.front() {
            Some(read) => Ok(read.clone()),
            None => anyhow::bail!("not scripted"),
        }
    }

    async fn suspend(&self, _claim: &ClaimRef) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn wait_suspended(
        &self,
        _claim: &ClaimRef,
        _known_member: &str,
        _previous: &[Incarnation],
        _timeout: Duration,
    ) -> anyhow::Result<SuspendedRuntime> {
        anyhow::bail!("not scripted")
    }

    async fn reconcile_identity(&self, _claim: &ClaimRef) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn resume(
        &self,
        _claim: &ClaimRef,
        _suspended: &SuspendedRuntime,
        _support_image: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn wait_ready(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn placement_exists(&self, _placement: &Placement) -> anyhow::Result<bool> {
        anyhow::bail!("not scripted")
    }

    async fn tear_down(
        &self,
        _placement: &Placement,
        _teardown: &RuntimeTeardown<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn current_member(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<Option<Incarnation>> {
        anyhow::bail!("not scripted")
    }

    async fn member_name(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<String> {
        anyhow::bail!("not scripted")
    }

    async fn member_named(
        &self,
        _placement: &Placement,
        _member_name: &str,
    ) -> anyhow::Result<Option<Incarnation>> {
        anyhow::bail!("not scripted")
    }

    async fn suspend_current(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn resume_current(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _support_image: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn replace_member(
        &self,
        _placement: &Placement,
        environment_id: &str,
        member: &Incarnation,
        support_image: &str,
    ) -> anyhow::Result<MemberReplacement> {
        self.replacement_calls.lock().unwrap().push(format!(
            "replace {environment_id} {} {} {support_image}",
            member.name, member.uid
        ));
        (*self.replacement.lock().unwrap()).ok_or_else(|| anyhow::anyhow!("not scripted"))
    }

    async fn wait_replacement(
        &self,
        _placement: &Placement,
        previous: &Incarnation,
        _timeout: Duration,
    ) -> anyhow::Result<Incarnation> {
        self.replacement_calls
            .lock()
            .unwrap()
            .push(format!("wait {} {}", previous.name, previous.uid));
        self.replaced
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("not scripted"))
    }

    async fn terminal_member(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<Option<Incarnation>> {
        self.placements.lock().unwrap().push(placement.clone());
        Ok(None)
    }

    async fn publish_measured_runtime(
        &self,
        _placement: &Placement,
        environment_id: &str,
        member_name: &str,
        _intent: &RenderingIntent,
        authorized: &[u8; 32],
    ) -> anyhow::Result<String> {
        self.replacement_calls.lock().unwrap().push(format!(
            "publish {environment_id} {member_name} {}",
            authorized[..4]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        self.measured_runtime
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("not scripted"))
    }

    async fn wait_measured_runtime(
        &self,
        _placement: &Placement,
        member: &Incarnation,
        measured: &str,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        self.replacement_calls.lock().unwrap().push(format!(
            "wait-measured {} {} {measured}",
            member.name, member.uid
        ));
        Ok(())
    }

    async fn refresh_bootstrap(
        &self,
        claim: &ClaimRef,
        _intent: &RenderingIntent,
        _suspended: &SuspendedRuntime,
        authorized: Option<&[u8; 32]>,
    ) -> anyhow::Result<()> {
        self.placements
            .lock()
            .unwrap()
            .push(claim.placement.clone());
        self.refreshed.lock().unwrap().push(authorized.copied());
        Ok(())
    }
}

#[async_trait]
impl RuntimeResize for FakeRuntimeDriver {
    async fn resize_state(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<ResizeState> {
        anyhow::bail!("not scripted")
    }

    async fn set_desired_size(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _cpu_millicores: i32,
        _memory_mb: i32,
        _disk_gb: i32,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn resize_in_place(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _member_uid: &str,
        _cpu_millicores: i32,
        _memory_mb: i32,
        _timeout: Duration,
    ) -> anyhow::Result<ResizeState> {
        anyhow::bail!("not scripted")
    }

    async fn settle_failed_resize(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _member_uid: &str,
        _previous: (i32, i32),
        _requested: (i32, i32),
        _timeout: Duration,
    ) -> FailedLiveResize {
        FailedLiveResize::Unknown("not scripted".into())
    }
}

#[async_trait]
impl RuntimeStorage for FakeRuntimeDriver {
    async fn volume(
        &self,
        _placement: &Placement,
        _volume: &VolumeRef,
    ) -> anyhow::Result<VolumeIdentity> {
        anyhow::bail!("not scripted")
    }

    async fn check_volume_growth(
        &self,
        _placement: &Placement,
        _volume: &VolumeRef,
        _disk_gb: i32,
    ) -> anyhow::Result<VolumeIdentity> {
        anyhow::bail!("not scripted")
    }

    async fn grow_volume(
        &self,
        _placement: &Placement,
        _volume: &VolumeRef,
        _disk_gb: i32,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn wait_volume_growth(
        &self,
        _placement: &Placement,
        _volume: &VolumeRef,
        _disk_gb: i32,
        _timeout: Duration,
    ) -> anyhow::Result<VolumeGrowth> {
        anyhow::bail!("not scripted")
    }

    async fn wait_volume_capacity(
        &self,
        _placement: &Placement,
        _volume: &VolumeRef,
        _disk_gb: i32,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }
}

#[async_trait]
impl RuntimeSnapshots for FakeRuntimeDriver {
    async fn snapshot_volume(
        &self,
        _placement: &Placement,
        _snapshot_id: &str,
        _source: &VolumeIdentity,
        _snapshot_class: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn keep_cleared_volume(
        &self,
        _placement: &Placement,
        snapshot_id: &str,
        snapshot_class: &str,
    ) -> anyhow::Result<()> {
        self.snapshot_calls
            .lock()
            .unwrap()
            .push(format!("keep {snapshot_id} {snapshot_class}"));
        let gate = self.keep_gate.lock().unwrap().take();
        if let Some((begun, release)) = gate {
            begun.send(()).expect("the test waits for the keep");
            release.await.expect("the test releases the keep");
        }
        Ok(())
    }

    async fn wait_snapshot(
        &self,
        _placement: &Placement,
        snapshot_id: &str,
        stage: CaptureStage,
        _timeout: Duration,
    ) -> anyhow::Result<String> {
        self.snapshot_calls
            .lock()
            .unwrap()
            .push(format!("wait {snapshot_id} {stage:?}"));
        match (stage, self.kept_size.lock().unwrap().clone()) {
            (CaptureStage::Kept, Some(size)) => Ok(size),
            _ => anyhow::bail!("not scripted"),
        }
    }

    async fn raw_snapshot_mode(
        &self,
        _placement: &Placement,
        _snapshot_id: &str,
    ) -> anyhow::Result<VolumeMode> {
        anyhow::bail!("not scripted")
    }

    async fn start_clearing(
        &self,
        _placement: &Placement,
        _opts: &ClearingOpts<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn clearing_progress(
        &self,
        _placement: &Placement,
        _snapshot_id: &str,
    ) -> anyhow::Result<ClearingProgress> {
        anyhow::bail!("not scripted")
    }

    async fn stop_clearing(
        &self,
        _placement: &Placement,
        snapshot_id: &str,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        self.snapshot_calls
            .lock()
            .unwrap()
            .push(format!("stop {snapshot_id}"));
        Ok(())
    }

    async fn delete_capture(
        &self,
        _placement: &Placement,
        snapshot_id: &str,
        kept: KeptSnapshot,
        _timeout: Duration,
    ) -> anyhow::Result<()> {
        self.snapshot_calls
            .lock()
            .unwrap()
            .push(format!("delete {snapshot_id} {kept:?}"));
        Ok(())
    }
}

#[async_trait]
impl RuntimeAccess for FakeRuntimeDriver {
    async fn member_evidence(
        &self,
        placement: &Placement,
        _member_name: &str,
    ) -> Option<MemberEvidence> {
        self.placements.lock().unwrap().push(placement.clone());
        None
    }

    async fn member_address(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<String> {
        anyhow::bail!("not scripted")
    }

    async fn ensure_access(
        &self,
        _placement: &Placement,
        _intent: &RenderingIntent,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn delete_access(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn wait_access_ready(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _timeout: Duration,
        _host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn prove_access(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _timeout: Duration,
        _host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<String> {
        anyhow::bail!("not scripted")
    }

    async fn ssh_ready(
        &self,
        _placement: &Placement,
        _environment_id: &str,
        _host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        anyhow::bail!("not scripted")
    }

    async fn start_exec(
        &self,
        _placement: &Placement,
        _member_name: &str,
        _command: &[String],
        _work_dir: &str,
        _env: &BTreeMap<String, String>,
    ) -> anyhow::Result<RuntimeExec> {
        anyhow::bail!("not scripted")
    }

    async fn claim_readiness(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<ClaimReadiness> {
        self.placements.lock().unwrap().push(placement.clone());
        match self.claim_readiness.lock().unwrap().clone() {
            Some(Ok(readiness)) => Ok(readiness),
            Some(Err(message)) => Err(anyhow::anyhow!(message)),
            None => anyhow::bail!("not scripted"),
        }
    }

    async fn workspace_logs(
        &self,
        _placement: &Placement,
        _member_name: &str,
        _tail_lines: i64,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("not scripted")
    }

    async fn ssh_stream(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        anyhow::bail!("not scripted")
    }

    async fn daemon_stream(
        &self,
        _placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<RuntimeStream> {
        anyhow::bail!("not scripted")
    }
}
