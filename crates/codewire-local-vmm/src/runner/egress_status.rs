//! The network worker's late-answer reports, which reach the runner on the
//! worker's control socket while the VM runs (#4965, `super::worker_frames`):
//! what `cw info` shows as egress unavailable.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;

use super::RunningVm;
use crate::network_worker::LateStatusFrame;

/// Egress refused because the egress broker is past its deadline: how many
/// requests it refused in all, and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EgressUnavailable {
    pub(crate) late_answers: u64,
    pub(crate) since: SystemTime,
}

/// The worker's latest report, written by the ingress forwarder that reads
/// the control socket and read by the runner service's `info`.
#[derive(Clone, Debug, Default)]
pub(crate) struct EgressStatusCell(Arc<StdMutex<Option<EgressUnavailable>>>);

impl EgressStatusCell {
    pub(crate) fn unavailable(&self) -> Option<EgressUnavailable> {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Takes the worker's report `frame`: refusing since the time it gives,
    /// or answered again.
    pub(super) fn record(&self, frame: LateStatusFrame) {
        let unavailable = frame.refusing_for.map(|refusing| {
            let now = SystemTime::now();
            EgressUnavailable {
                late_answers: frame.late_answers,
                since: now.checked_sub(refusing).unwrap_or(now),
            }
        });
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = unavailable;
    }
}

impl RunningVm {
    /// Whether this VM's egress broker is past its deadline, as its network
    /// worker last reported.
    pub(crate) fn egress_unavailable(&self) -> Option<EgressUnavailable> {
        self.network_worker.as_ref()?.egress_status.unavailable()
    }
}
