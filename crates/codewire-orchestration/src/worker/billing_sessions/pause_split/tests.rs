use super::*;
use crate::pause_records::{PauseRecord, StateRecord};

const T: i64 = 1_764_000_000_000;

fn pause(event: PauseEvent, generation: u64, sequence: u64, at: i64) -> Logged {
    Logged {
        at_unix_ms: at,
        record: Record::Pause(PauseRecord {
            event,
            generation,
            sequence,
            at_unix_ms: u64::try_from(at).unwrap(),
        }),
    }
}

/// A state record logged at `logged`, of the boot's state since `since`.
fn state(state: VmState, generation: u64, sequence: u64, since: i64, logged: i64) -> Logged {
    Logged {
        at_unix_ms: logged,
        record: Record::State(StateRecord {
            generation,
            sequence,
            state,
            since_unix_ms: u64::try_from(since).unwrap(),
        }),
    }
}

fn running() -> Session {
    Session {
        kind: Kind::Running,
        mark: None,
        paused_seen_ms: None,
    }
}

fn split(at_ms: i64, reason: &'static str, kind: Kind, review: bool) -> Split {
    Split {
        at_ms,
        reason,
        kind,
        review,
    }
}

#[test]
fn a_pause_and_its_resume_split_at_their_own_times() {
    let read = [
        state(VmState::Running, 7, 0, T - 600_000, T - 30_000),
        pause(PauseEvent::Paused, 7, 1, T),
        state(VmState::Paused, 7, 1, T, T),
        state(VmState::Paused, 7, 1, T, T + 30_000),
        pause(PauseEvent::Resumed, 7, 2, T + 50_000),
        state(VmState::Running, 7, 2, T + 50_000, T + 50_000),
    ];
    let plan = plan(running(), &read);
    assert_eq!(
        plan.splits,
        [
            split(T, VM_PAUSED, Kind::Paused, false),
            split(T + 50_000, VM_RESUMED, Kind::Running, false),
        ]
    );
    assert!(plan.missing.is_empty());
    assert_eq!(
        plan.session.mark,
        Some(Mark {
            generation: 7,
            sequence: 2
        })
    );
    assert_eq!(plan.session.kind, Kind::Running);
}

#[test]
fn a_record_already_applied_is_never_applied_again() {
    let read = [
        pause(PauseEvent::Paused, 7, 1, T),
        state(VmState::Paused, 7, 1, T, T + 30_000),
    ];
    let first = plan(running(), &read);
    assert_eq!(first.splits.len(), 1);
    // The next poll's window overlaps this one's: nothing new happens.
    let again = plan(first.session, &read);
    assert!(again.splits.is_empty());
    assert_eq!(again.session, first.session);
}

/// A lost pause line is recovered from the state record, which carries its
/// sequence and time; the missing number is still reported.
#[test]
fn a_lost_line_is_recovered_from_the_state_record_and_reported() {
    let session = plan(
        running(),
        &[state(VmState::Running, 7, 0, T - 600_000, T - 30_000)],
    )
    .session;
    let read = [state(VmState::Paused, 7, 1, T, T + 10_000)];
    let plan = plan(session, &read);
    assert_eq!(plan.splits, [split(T, VM_PAUSED, Kind::Paused, false)]);
    assert!(plan.missing.is_empty(), "the state record is sequence 1");

    let read = [pause(PauseEvent::Paused, 7, 3, T + 100_000)];
    let jumped = super::plan(plan.session, &read);
    assert_eq!(
        jumped.missing,
        [Missing {
            generation: 7,
            first: 2,
            last: 2
        }]
    );
}

#[test]
fn a_gap_of_a_minute_or_less_stays_paused() {
    let read = [
        pause(PauseEvent::Paused, 7, 1, T),
        // One state record lost: 60 s between the ones seen.
        state(VmState::Paused, 7, 1, T, T + 60_000),
    ];
    let plan = plan(running(), &read);
    assert_eq!(plan.splits, [split(T, VM_PAUSED, Kind::Paused, false)]);
}

#[test]
fn a_longer_gap_bills_running_past_the_last_record_and_a_later_record_pauses_again() {
    let read = [
        pause(PauseEvent::Paused, 7, 1, T),
        state(VmState::Paused, 7, 1, T, T + 30_000),
        // Nothing for 90 s.
        state(VmState::Paused, 7, 1, T, T + 120_000),
        state(VmState::Paused, 7, 1, T, T + 150_000),
    ];
    let plan = plan(running(), &read);
    assert_eq!(
        plan.splits,
        [
            split(T, VM_PAUSED, Kind::Paused, false),
            split(T + 30_000, PAUSE_RECORDS_GAP, Kind::Running, true),
            split(T + 120_000, VM_PAUSED, Kind::Paused, false),
        ]
    );
    assert_eq!(plan.session.kind, Kind::Paused);
}

/// The next poll's window still holds the records around the gap: the
/// gap is settled once.
#[test]
fn a_gap_already_settled_is_not_settled_again() {
    let read = [
        pause(PauseEvent::Paused, 7, 1, T),
        state(VmState::Paused, 7, 1, T, T + 30_000),
        state(VmState::Paused, 7, 1, T, T + 120_000),
        state(VmState::Paused, 7, 1, T, T + 150_000),
    ];
    let first = plan(running(), &read);
    assert_eq!(first.splits.len(), 3);
    let again = plan(first.session, &read);
    assert!(again.splits.is_empty(), "{:?}", again.splits);
    assert_eq!(again.session, first.session);
}

#[test]
fn a_gap_while_running_changes_nothing() {
    let read = [
        state(VmState::Running, 7, 0, T, T),
        state(VmState::Running, 7, 0, T, T + 300_000),
    ];
    assert!(plan(running(), &read).splits.is_empty());
}

#[test]
fn a_boot_that_ends_paused_is_paused_only_to_its_end_and_the_next_runs() {
    let paused = plan(
        running(),
        &[
            pause(PauseEvent::Paused, 7, 1, T),
            state(VmState::Paused, 7, 1, T, T + 30_000),
        ],
    )
    .session;

    // The Pod ends 20 s after the last record: paused to the end.
    assert!(end(paused, T + 50_000).is_empty());
    // It ends 5 minutes after: running past the last record, for review.
    assert_eq!(
        end(paused, T + 330_000),
        [split(T + 30_000, PAUSE_RECORDS_GAP, Kind::Running, true)]
    );

    // A new Pod carries on: a new generation, starting 20 s later, turns
    // the session running at its start.
    let next = plan(
        paused,
        &[state(VmState::Running, 8, 0, T + 50_000, T + 51_000)],
    );
    assert_eq!(
        next.splits,
        [split(T + 50_000, VM_BOOT_ENDED, Kind::Running, false)]
    );
    assert_eq!(
        next.session.mark,
        Some(Mark {
            generation: 8,
            sequence: 0
        })
    );
    // Starting 5 minutes later, the stretch past the last record is a gap.
    let late = plan(
        paused,
        &[state(VmState::Running, 8, 0, T + 330_000, T + 331_000)],
    );
    assert_eq!(
        late.splits,
        [split(T + 30_000, PAUSE_RECORDS_GAP, Kind::Running, true)]
    );
}

#[test]
fn an_older_boots_records_and_a_boot_first_seen_above_one_are_handled() {
    let session = Session {
        kind: Kind::Running,
        mark: Some(Mark {
            generation: 8,
            sequence: 2,
        }),
        paused_seen_ms: None,
    };
    let old = [pause(PauseEvent::Paused, 7, 9, T)];
    assert!(plan(session, &old).splits.is_empty());

    let first_seen_late = [pause(PauseEvent::Paused, 9, 3, T)];
    let plan = plan(session, &first_seen_late);
    assert_eq!(
        plan.missing,
        [Missing {
            generation: 9,
            first: 1,
            last: 2
        }]
    );
    assert_eq!(plan.splits, [split(T, VM_PAUSED, Kind::Paused, false)]);
}
