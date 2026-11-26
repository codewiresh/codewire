use super::*;
use crate::pause_records::{PauseEvent, PauseRecord, StateRecord};

const MARK: i64 = 1_764_000_000_000;

fn pause(event: PauseEvent, sequence: u64, at: i64) -> Record {
    Record::Pause(PauseRecord {
        event,
        generation: 7,
        sequence,
        at_unix_ms: u64::try_from(at).unwrap(),
    })
}

fn state(state: VmState, sequence: u64, since: i64) -> Record {
    Record::State(StateRecord {
        generation: 7,
        sequence,
        state,
        since_unix_ms: u64::try_from(since).unwrap(),
    })
}

#[test]
fn a_pause_after_the_mark_holds_it_however_long_it_lasts() {
    let paused = [pause(PauseEvent::Paused, 1, MARK + 1_000)];
    assert_eq!(check(&paused, MARK, MARK + 2_000), MarkCheck::Paused);
    // Hours later the pause record has left the read, but the state record
    // every 30 s still says paused since then.
    let hours = MARK + 6 * 3_600_000;
    let state_only = [state(VmState::Paused, 1, MARK + 1_000)];
    assert_eq!(check(&state_only, MARK, hours), MarkCheck::Paused);
}

#[test]
fn no_pause_within_thirty_seconds_of_the_mark_clears_it() {
    // Running since boot, or no records at all (a runtime that writes none).
    for records in [vec![state(VmState::Running, 0, MARK - 600_000)], Vec::new()] {
        assert_eq!(check(&records, MARK, MARK + 29_000), MarkCheck::Waiting);
        assert_eq!(check(&records, MARK, MARK + 30_000), MarkCheck::PauseFailed);
    }
    // A pause from before the mark is not this one's.
    let earlier = [state(VmState::Paused, 3, MARK - 60_000)];
    assert_eq!(check(&earlier, MARK, MARK + 30_000), MarkCheck::PauseFailed);
}

#[test]
fn a_resume_whose_wake_isnt_reported_within_a_minute_is_an_error() {
    let resumed = [
        pause(PauseEvent::Paused, 1, MARK + 1_000),
        pause(PauseEvent::Resumed, 2, MARK + 600_000),
    ];
    assert_eq!(check(&resumed, MARK, MARK + 659_000), MarkCheck::Waiting);
    assert_eq!(
        check(&resumed, MARK, MARK + 660_000),
        MarkCheck::WakeNotReported
    );
    // The same from a state record alone.
    let state_only = [state(VmState::Running, 2, MARK + 600_000)];
    assert_eq!(
        check(&state_only, MARK, MARK + 700_000),
        MarkCheck::WakeNotReported
    );
}

#[test]
fn the_nodes_clock_may_run_a_little_behind_the_databases() {
    let paused = [pause(PauseEvent::Paused, 1, MARK - 4_000)];
    assert_eq!(check(&paused, MARK, MARK + 40_000), MarkCheck::Paused);
    let too_early = [pause(PauseEvent::Paused, 1, MARK - 6_000)];
    assert_eq!(
        check(&too_early, MARK, MARK + 40_000),
        MarkCheck::PauseFailed
    );
}
