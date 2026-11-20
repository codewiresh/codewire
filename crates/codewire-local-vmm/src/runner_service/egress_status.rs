//! A runner's `info`, with its running VM's egress: unavailable while its
//! egress broker is past its deadline (#4965), and its interception, as its
//! supervisor started the boot (#4912) or lost once its front door has ended
//! unasked (#5216).

use std::time::UNIX_EPOCH;

use crate::control::v1;
use crate::runner::RunningVm;

impl super::RunnerState {
    pub(super) fn info(&self) -> v1::RunnerInfo {
        v1::RunnerInfo {
            environment_id: self.environment_id.to_string(),
            state: self.state as i32,
            generation: self.generation,
            artifact_generation: self.artifact_generation.clone(),
            error_code: self.error_code.unwrap_or_default().to_owned(),
            exit: self.reported_exit(),
            egress_unavailable: self.egress_unavailable(),
            interception: self.interception(),
            cw_runtime_catalog_generation: self
                .cw_runtime_catalog_generation()
                .unwrap_or_default()
                .to_owned(),
        }
    }

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

    /// What the running boot started with, or `lost` once its front door
    /// has ended without a stop being asked for; never for a VM that isn't
    /// running, and only `lost` when an older supervisor started it.
    fn interception(&self) -> Option<v1::Interception> {
        let running = self.running.as_ref()?;
        if running.front_door_stopped().is_some() {
            return Some(v1::Interception {
                state: v1::InterceptionState::Lost as i32,
                reason: v1::InterceptionReason::Unspecified as i32,
            });
        }
        self.interception
    }
}
