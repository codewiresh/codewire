//! Where a `standard` Sandbox's billing session splits between running and
//! paused (#5529, `docs/dev/BILLING.md`, "A suspended stretch";
//! `docs/dev/IDLE-STOP.md`, "Billing"), from its runtime's own pause records
//! only. This module decides; the session loop writes.

use crate::pause_records::{Logged, PauseEvent, Record, VmState};

/// A stretch of a paused Sandbox with no record longer than this is billed
/// running past the last record before it, and marked for review.
pub(crate) const GAP_LIMIT_MS: i64 = 60_000;
/// Clock slack between `sandbox_running_sessions.started_at` (database bind
/// time) and a warm-pool member's claim wake record (node wall clock).
pub(crate) const PRE_BIND_WAKE_SLACK_MS: i64 = 5_000;

pub(crate) const VM_PAUSED: &str = "vm_paused";
pub(crate) const VM_RESUMED: &str = "vm_resumed";
pub(crate) const PAUSE_RECORDS_GAP: &str = "pause_records_gap";
pub(crate) const VM_BOOT_ENDED: &str = "vm_boot_ended";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Running,
    Paused,
}

/// The last record applied: a boot and its record's sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Mark {
    pub generation: u64,
    pub sequence: u64,
}

/// The open session as the loop last left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Session {
    pub kind: Kind,
    pub mark: Option<Mark>,
    /// While paused, when the latest record said so.
    pub paused_seen_ms: Option<i64>,
    /// When this billing session opened (the binding's `bound_at`), so
    /// pre-bind pauses from an unbound warm-pool Pod are not billed onto the
    /// newly bound Sandbox (#5602).
    pub started_at_ms: Option<i64>,
}

/// Close the open session at `at_ms` with `reason`, and open one of `kind`
/// there, marked for review when `review`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Split {
    pub at_ms: i64,
    pub reason: &'static str,
    pub kind: Kind,
    pub review: bool,
}

/// Records billing has no line for: a boot's sequence numbers from `first`
/// to `last`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Missing {
    pub generation: u64,
    pub first: u64,
    pub last: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub splits: Vec<Split>,
    /// The session after the splits.
    pub session: Session,
    pub missing: Vec<Missing>,
}

/// A record's boot, sequence, state and since when.
fn view(record: &Record) -> (u64, u64, VmState, i64) {
    let (generation, sequence, state, since) = match record {
        Record::Pause(pause) => (
            pause.generation,
            pause.sequence,
            match pause.event {
                PauseEvent::Paused => VmState::Paused,
                PauseEvent::Resumed => VmState::Running,
            },
            pause.at_unix_ms,
        ),
        Record::State(state) => (
            state.generation,
            state.sequence,
            state.state,
            state.since_unix_ms,
        ),
    };
    (
        generation,
        sequence,
        state,
        i64::try_from(since).unwrap_or(i64::MAX),
    )
}

/// The splits `logged`, read in log order, makes of `session`.
pub(crate) fn plan(session: Session, logged: &[Logged]) -> Plan {
    let mut plan = Plan {
        splits: Vec::new(),
        session,
        missing: Vec::new(),
    };
    for logged in logged {
        let (generation, sequence, state, since) = view(&logged.record);
        let previous = plan.session.mark;
        // A record already applied, or an older boot's.
        if previous.is_some_and(|mark| {
            generation < mark.generation
                || (generation == mark.generation && sequence < mark.sequence)
        }) {
            continue;
        }
        // A state record repeats its pause's sequence, so one of the record
        // last applied is new only if logged after the latest seen; rereading
        // an earlier one would measure a gap already settled.
        if previous
            == Some(Mark {
                generation,
                sequence,
            })
            && plan
                .session
                .paused_seen_ms
                .is_some_and(|seen| logged.at_unix_ms <= seen)
        {
            continue;
        }
        let new_boot = previous.is_none_or(|mark| mark.generation != generation);
        // An unbound warm-pool member pauses before claim and wakes as its
        // binding commits (#5602). A pause that started before this session
        // opened belongs to that unbound warm-pool stretch, not to the bound
        // Sandbox; advance the mark past it without splitting or warning.
        if plan.session.kind == Kind::Running
            && let Some(started_at_ms) = plan.session.started_at_ms
        {
            let pre_bind_pause = state == VmState::Paused && since < started_at_ms;
            let pre_bind_wake = previous.is_none()
                && state == VmState::Running
                && since <= started_at_ms.saturating_add(PRE_BIND_WAKE_SLACK_MS);
            if pre_bind_pause || pre_bind_wake {
                plan.session.mark = Some(Mark {
                    generation,
                    sequence,
                })
                .max(previous.filter(|_| !new_boot));
                continue;
            }
        }
        let expected = match previous {
            Some(mark) if !new_boot => mark.sequence + 1,
            _ => 1,
        };
        if sequence > expected {
            plan.missing.push(Missing {
                generation,
                first: expected,
                last: sequence - 1,
            });
        }
        if new_boot && previous.is_some() && plan.session.kind == Kind::Paused {
            // The old boot ended paused: paused up to its end at most, and
            // running from the new boot's start, which ends that stretch.
            let boot_start = since.min(logged.at_unix_ms);
            settle_gap(&mut plan, boot_start);
            if plan.session.kind == Kind::Paused {
                plan.split(boot_start, VM_BOOT_ENDED, Kind::Running, false);
            }
        }
        if plan.session.kind == Kind::Paused {
            settle_gap(&mut plan, logged.at_unix_ms);
        }
        let changed = previous.is_none_or(|mark| {
            Mark {
                generation,
                sequence,
            } > mark
        });
        match (plan.session.kind, state) {
            (Kind::Running, VmState::Paused) => {
                // A new pause from its own time; after a gap, the same pause
                // again from this record.
                let at = if changed { since } else { logged.at_unix_ms };
                plan.split(at, VM_PAUSED, Kind::Paused, false);
            }
            (Kind::Paused, VmState::Running) => {
                plan.split(since, VM_RESUMED, Kind::Running, false);
            }
            _ => {}
        }
        plan.session.mark = Some(Mark {
            generation,
            sequence,
        })
        .max(previous.filter(|_| !new_boot));
        plan.session.paused_seen_ms = match plan.session.kind {
            Kind::Paused => Some(logged.at_unix_ms),
            Kind::Running => None,
        };
    }
    plan
}

/// The splits a paused session's end at `end_ms` makes, the Pod gone: the
/// stretch since the last record is a gap.
pub(crate) fn end(session: Session, end_ms: i64) -> Vec<Split> {
    let mut plan = Plan {
        splits: Vec::new(),
        session,
        missing: Vec::new(),
    };
    if plan.session.kind == Kind::Paused {
        settle_gap(&mut plan, end_ms);
    }
    plan.splits
}

/// While paused, a record `at_ms` more than [`GAP_LIMIT_MS`] after the last
/// one bills the time past that one running, marked for review.
fn settle_gap(plan: &mut Plan, at_ms: i64) {
    if let Some(seen) = plan.session.paused_seen_ms
        && at_ms.saturating_sub(seen) > GAP_LIMIT_MS
    {
        plan.split(seen, PAUSE_RECORDS_GAP, Kind::Running, true);
    }
}

impl Plan {
    fn split(&mut self, at_ms: i64, reason: &'static str, kind: Kind, review: bool) {
        // Splits never go back in time.
        let at_ms = self
            .splits
            .last()
            .map_or(at_ms, |last| at_ms.max(last.at_ms));
        self.splits.push(Split {
            at_ms,
            reason,
            kind,
            review,
        });
        self.session.kind = kind;
        if kind == Kind::Running {
            self.session.paused_seen_ms = None;
        }
    }
}

#[cfg(test)]
#[path = "pause_split/tests.rs"]
mod tests;
