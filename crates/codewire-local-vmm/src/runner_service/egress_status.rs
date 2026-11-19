//! A running VM's egress, as `info` reports it: unavailable while its egress
//! broker is past its deadline (#4965), and its interception lost once its
//! front door has ended unasked (#5216).

use std::time::UNIX_EPOCH;

use crate::control::v1;
use crate::runner::RunningVm;

impl super::RunnerState {
    /// Set from the network worker's first late-answer report until a
    /// request is answered again; never for a VM that isn't running.
    pub(super) fn egress_unavailable(&self) -> Option<v1::EgressUnavailable> {
        let unavailable = self
            .running
            .as_ref()
            .and_then(RunningVm::egress_unavailable)?;
        Some(v1::EgressUnavailable {
            late_answers: unavailable.late_answers,
            since_unix_ms: unavailable
                .since
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|since| i64::try_from(since.as_millis()).ok())
                .unwrap_or_default(),
        })
    }

    /// `lost` once the running VM's front door has ended without a stop
    /// being asked for. The boot's other states are #4912's to report; never
    /// for a VM that isn't running.
    pub(super) fn interception(&self) -> Option<v1::Interception> {
        self.running
            .as_ref()
            .and_then(RunningVm::front_door_stopped)
            .map(|_| v1::Interception {
                state: v1::InterceptionState::Lost as i32,
                reason: v1::InterceptionReason::Unspecified as i32,
            })
    }
}
