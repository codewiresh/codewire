//! A second driver, to prove the traits don't depend on Kubernetes and to
//! drive caller logic in tests. Behaviour stays proven against
//! [`KubernetesDriver`](super::kubernetes::KubernetesDriver): a fake only
//! returns what its test scripted.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use super::{
    ClaimReadiness, ClaimRef, MemberRef, MemberReplacement, Placement, ProbeResult, RuntimeAccess,
    RuntimeLifecycle, RuntimeMember, RuntimePools, RuntimeStream, RuntimeTeardown,
    SuspendedRuntime,
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
        anyhow::bail!("not scripted")
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
impl RuntimeAccess for FakeRuntimeDriver {
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
