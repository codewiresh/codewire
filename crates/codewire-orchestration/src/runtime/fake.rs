//! A second driver, to prove the traits don't depend on Kubernetes and to
//! drive caller logic in tests. Behaviour stays proven against
//! [`KubernetesDriver`](super::kubernetes::KubernetesDriver): a fake only
//! returns what its test scripted.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use super::{
    ClaimReadiness, ClaimRef, FailedLiveResize, MemberRef, MemberReplacement, Placement,
    ProbeResult, ResizeState, RuntimeAccess, RuntimeExec, RuntimeLifecycle, RuntimeMember,
    RuntimePools, RuntimeResize, RuntimeStorage, RuntimeStream, RuntimeTeardown, SuspendedRuntime,
    VolumeGrowth, VolumeIdentity, VolumeRef,
};
use crate::sandbox::host_keys::HostKeyStore;
use crate::sandbox::template::TemplateOpts;

#[derive(Default)]
pub(crate) struct FakeRuntimeDriver {
    /// Each retirement's answer, in order; an error is its message.
    pub retirements: Mutex<VecDeque<Result<usize, String>>>,
    pub probe: ProbeResult,
    pub members: Mutex<Vec<RuntimeMember>>,
    /// When set, listing members fails with this message.
    pub members_error: Mutex<Option<String>>,
    /// Each read of an environment's members, in order; the last one repeats.
    pub member_reads: Mutex<VecDeque<Vec<MemberRef>>>,
    /// What replacing a member answers.
    pub replacement: Mutex<Option<MemberReplacement>>,
    /// Each replacement and replacement wait asked for, in order.
    pub replacement_calls: Mutex<Vec<String>>,
    /// The claim's readiness; an error is its message.
    pub claim_readiness: Mutex<Option<Result<ClaimReadiness, String>>>,
    /// Every placement a method was asked about, in order.
    pub placements: Mutex<Vec<Placement>>,
}

#[async_trait]
impl RuntimePools for FakeRuntimeDriver {
    async fn retire_legacy_shared_pools(&self, placement: &Placement) -> anyhow::Result<usize> {
        self.placements.lock().unwrap().push(placement.clone());
        self.retirements
            .lock()
            .unwrap()
            .pop_front()
            .expect("the test scripts every retirement")
            .map_err(anyhow::Error::msg)
    }
}

#[async_trait]
impl RuntimeLifecycle for FakeRuntimeDriver {
    async fn probe(
        &self,
        placement: &Placement,
        _environment_id: &str,
    ) -> anyhow::Result<ProbeResult> {
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
    ) -> anyhow::Result<Vec<MemberRef>> {
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
        _previous: &[MemberRef],
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
    ) -> anyhow::Result<Option<MemberRef>> {
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
    ) -> anyhow::Result<Option<MemberRef>> {
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
        member: &MemberRef,
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
        previous: &MemberRef,
        _timeout: Duration,
    ) -> anyhow::Result<MemberRef> {
        self.replacement_calls
            .lock()
            .unwrap()
            .push(format!("wait {} {}", previous.name, previous.uid));
        anyhow::bail!("not scripted")
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
impl RuntimeAccess for FakeRuntimeDriver {
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
        _rendering: &TemplateOpts,
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
