use std::time::{Duration, Instant};

use super::*;

const SIX_HOURS: i32 = 6 * 3600;

fn at(now: chrono::DateTime<chrono::Utc>, seconds_ago: i64) -> Result<DaemonActivity, String> {
    Ok(DaemonActivity::LastActive(Some(
        now.timestamp() - seconds_ago,
    )))
}

#[test]
fn the_switch_is_off_unless_turned_on_and_a_typo_is_refused() {
    for value in [None, Some(""), Some(" "), Some("off")] {
        assert_eq!(IdleStop::parse(value), Ok(IdleStop::Off), "{value:?}");
    }
    assert_eq!(IdleStop::parse(Some(" on ")), Ok(IdleStop::On));
    assert!(
        IdleStop::parse(Some("yes"))
            .unwrap_err()
            .contains(IDLE_STOP_ENV)
    );
}

#[test]
fn a_daemon_that_saw_use_within_the_timeout_keeps_it_up() {
    let now = chrono::Utc::now();
    let instant = Instant::now();
    let seen = chrono::DateTime::from_timestamp(now.timestamp() - 60, 0).unwrap();
    assert_eq!(
        decide(SIX_HOURS, &at(now, 60), None, now, instant),
        Decision::Active(seen)
    );
    // A time in the future counts as now.
    let future = Ok(DaemonActivity::LastActive(Some(now.timestamp() + 3600)));
    assert_eq!(
        decide(SIX_HOURS, &future, None, now, instant),
        Decision::Active(now)
    );
}

#[test]
fn a_daemon_that_saw_nothing_recent_lets_it_stop() {
    let now = chrono::Utc::now();
    let instant = Instant::now();
    assert_eq!(
        decide(
            SIX_HOURS,
            &at(now, i64::from(SIX_HOURS)),
            None,
            now,
            instant
        ),
        Decision::Stop
    );
    let nothing = Ok(DaemonActivity::LastActive(None));
    assert_eq!(
        decide(SIX_HOURS, &nothing, None, now, instant),
        Decision::Stop
    );
}

#[test]
fn an_older_daemon_keeps_it_up() {
    let now = chrono::Utc::now();
    assert_eq!(
        decide(
            SIX_HOURS,
            &Ok(DaemonActivity::Unsupported),
            None,
            now,
            Instant::now()
        ),
        Decision::Active(now)
    );
}

#[test]
fn a_silent_daemon_holds_it_for_one_timeout_then_lets_it_stop() {
    let now = chrono::Utc::now();
    let instant = Instant::now() + Duration::from_secs(10 * 60);
    let failed = Err("unreachable".to_owned());
    let five_minutes = 300;
    assert_eq!(
        decide(five_minutes, &failed, Some(instant), now, instant),
        Decision::Wait
    );
    assert_eq!(
        decide(
            five_minutes,
            &failed,
            Some(instant - Duration::from_secs(299)),
            now,
            instant
        ),
        Decision::Wait
    );
    assert_eq!(
        decide(
            five_minutes,
            &failed,
            Some(instant - Duration::from_secs(300)),
            now,
            instant
        ),
        Decision::Stop
    );
}

fn candidate(id: &str) -> Candidate {
    Candidate {
        id: id.to_owned(),
        namespace: "ns".to_owned(),
        idle_stop_seconds: 300,
        last_activity_at: None,
        suspended: false,
    }
}

/// A silence is forgotten once its Sandbox stops being a candidate, so a
/// later single failure waits a whole timeout again instead of stopping it.
#[test]
fn a_silence_is_forgotten_when_its_sandbox_is_no_longer_a_candidate() {
    let now = chrono::Utc::now();
    let instant = Instant::now() + Duration::from_secs(3600);
    let mut silent = HashMap::new();
    silent.insert("busy".to_owned(), instant - Duration::from_secs(1800));
    silent.insert("still".to_owned(), instant - Duration::from_secs(1800));

    // "busy" was active, so it is not a candidate this check.
    forget_silence_of_others(&mut silent, &[candidate("still")]);
    assert!(!silent.contains_key("busy"));
    assert!(silent.contains_key("still"));

    // Idle again later, its first failure starts a new silence and waits.
    let since = *silent.entry("busy".to_owned()).or_insert(instant);
    let failed = Err("unreachable".to_owned());
    assert_eq!(
        decide(300, &failed, Some(since), now, instant),
        Decision::Wait
    );
}

#[test]
fn only_a_kata_guest_counts_its_whole_cpu() {
    for profile in ["commodity", " commodity ", "confidential"] {
        assert!(counts_guest_cpu(profile), "{profile:?}");
    }
    for profile in ["runc", "none", ""] {
        assert!(!counts_guest_cpu(profile), "{profile:?}");
    }
}
