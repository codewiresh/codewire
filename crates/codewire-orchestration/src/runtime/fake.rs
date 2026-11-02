//! A second driver, to prove the traits don't depend on Kubernetes and to
//! drive caller logic in tests. Behaviour stays proven against
//! [`KubernetesDriver`](super::kubernetes::KubernetesDriver): a fake only
//! returns what its test scripted.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use super::{Placement, ProbeResult, RuntimeLifecycle, RuntimePools};

#[derive(Default)]
pub(crate) struct FakeRuntimeDriver {
    /// Each retirement's answer, in order; an error is its message.
    pub retirements: Mutex<VecDeque<Result<usize, String>>>,
    pub probe: ProbeResult,
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
}
