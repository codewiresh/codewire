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
        let front_door = if running.front_door_stopped().is_some() {
            FrontDoor::Ended
        } else if running.has_front_door() {
            FrontDoor::Running
        } else {
            FrontDoor::None
        };
        reported(self.interception, front_door)
    }
}

/// Where a running boot's front door stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrontDoor {
    None,
    Running,
    Ended,
}

/// What a running boot reports: `lost` once its front door has ended, and
/// `intercepted` only while it runs one, so the claim holds by itself and
/// not through the route table's defaults (#5670). A boot told to intercept
/// that bound nothing, as one whose only credential is GitHub's does
/// (#5087), reports not intercepted with nothing to intercept.
fn reported(started: Option<v1::Interception>, front_door: FrontDoor) -> Option<v1::Interception> {
    let report = |state: v1::InterceptionState, reason: v1::InterceptionReason| v1::Interception {
        state: state as i32,
        reason: reason as i32,
    };
    match front_door {
        FrontDoor::Ended => Some(report(
            v1::InterceptionState::Lost,
            v1::InterceptionReason::Unspecified,
        )),
        FrontDoor::Running => started,
        FrontDoor::None => match started {
            Some(started) if started.state == v1::InterceptionState::Intercepted as i32 => {
                Some(report(
                    v1::InterceptionState::NotIntercepted,
                    v1::InterceptionReason::NothingToIntercept,
                ))
            }
            other => other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot claims `intercepted` only while it runs a front door, is `lost`
    /// once that has ended, and otherwise reports what it started with
    /// (#5670).
    #[test]
    fn a_boot_is_intercepted_only_while_it_runs_a_front_door() {
        use v1::{InterceptionReason as Reason, InterceptionState as State};
        let started = |state: State, reason: Reason| v1::Interception {
            state: state as i32,
            reason: reason as i32,
        };
        let intercepted = started(State::Intercepted, Reason::Unspecified);
        let off = started(State::Off, Reason::Unspecified);
        let platform = started(State::NotIntercepted, Reason::PlatformCredentials);
        assert_eq!(
            reported(Some(intercepted), FrontDoor::Running),
            Some(intercepted)
        );
        assert_eq!(
            reported(Some(intercepted), FrontDoor::None),
            Some(started(State::NotIntercepted, Reason::NothingToIntercept))
        );
        for front_door in [FrontDoor::None, FrontDoor::Running, FrontDoor::Ended] {
            assert_eq!(
                reported(None, front_door).is_some(),
                front_door == FrontDoor::Ended,
                "{front_door:?}"
            );
        }
        for start in [Some(intercepted), Some(off), Some(platform), None] {
            assert_eq!(
                reported(start, FrontDoor::Ended),
                Some(started(State::Lost, Reason::Unspecified))
            );
        }
        assert_eq!(reported(Some(off), FrontDoor::None), Some(off));
        assert_eq!(reported(Some(platform), FrontDoor::None), Some(platform));
    }
}
