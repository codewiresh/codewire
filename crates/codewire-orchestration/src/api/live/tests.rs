use std::collections::HashSet;
use std::time::Duration;

use super::*;

const ORG: &str = "0123456789abcdef0123456789abcdef";
const OTHER_ORG: &str = "fedcba9876543210fedcba9876543210";
const ENV: &str = "3f2a6c1e-8d4b-4e7a-9c0f-1b2d3e4f5a6b";

/// Every wait is bounded: on the paused clock the bound costs nothing, and a
/// missing event fails here instead of holding the runner.
const BOUND: Duration = Duration::from_secs(60 * 60);

async fn next<T>(events: &mut mpsc::Receiver<T>) -> Option<T> {
    tokio::time::timeout(BOUND, events.recv())
        .await
        .expect("an event within the bound")
}

fn organizations(ids: &[&str]) -> HashSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn only_notices_shaped_like_the_triggers_become_signals() {
    assert_eq!(
        LiveSignal::from_notice("environment_changes", &format!("{ORG}:{ENV}")),
        Some(LiveSignal::Sandbox {
            org: ORG.into(),
            environment: ENV.into()
        })
    );
    assert_eq!(
        LiveSignal::from_notice("resize_changes", &format!("{ORG}:{ENV}")),
        Some(LiveSignal::Resize {
            org: ORG.into(),
            environment: ENV.into()
        })
    );
    assert_eq!(
        LiveSignal::from_notice("credit_changes", ORG),
        Some(LiveSignal::Credit { org: ORG.into() })
    );
    for (channel, payload) in [
        ("environment_changes", ORG),
        ("environment_changes", ":"),
        ("environment_changes", &format!("{ORG}:{ENV}:x")),
        ("environment_changes", &format!("{ORG}:<script>")),
        ("credit_changes", &format!("{ORG}:{ENV}")),
        ("credit_changes", ""),
        ("credit_changes", &"a".repeat(65)),
        ("environment_logs", ENV),
    ] {
        assert_eq!(
            LiveSignal::from_notice(channel, payload),
            None,
            "{channel} {payload}"
        );
    }
}

#[test]
fn an_account_holds_at_most_its_limit_of_watches_and_frees_them_on_drop() {
    let notifications = LiveNotifications::new(2, MAX_WATCHES_PER_PROCESS);
    let first = notifications.acquire_watch("account").unwrap();
    let second = notifications.acquire_watch("account").unwrap();
    assert!(notifications.acquire_watch("account").is_none());
    assert!(notifications.acquire_watch("another").is_some());
    drop(first);
    assert_eq!(notifications.watches("account"), 1);
    let _third = notifications.acquire_watch("account").unwrap();
    drop(second);
    assert_eq!(notifications.watches("account"), 1);
}

#[test]
fn the_process_holds_at_most_its_limit_of_watches_across_accounts() {
    let notifications = LiveNotifications::new(2, 3);
    let first = notifications.acquire_watch("one").unwrap();
    let _second = notifications.acquire_watch("one").unwrap();
    let _third = notifications.acquire_watch("two").unwrap();
    assert!(notifications.acquire_watch("three").is_none());
    drop(first);
    assert!(notifications.acquire_watch("three").is_some());
}

#[tokio::test(start_paused = true)]
async fn a_watch_starts_with_a_resync_and_passes_on_only_its_organizations() {
    let notifications = LiveNotifications::new(4, MAX_WATCHES_PER_PROCESS);
    let permit = notifications.acquire_watch("account").unwrap();
    let mut events = start_live_watch(
        organizations(&[ORG]),
        permit,
        Duration::from_secs(600),
        Duration::from_secs(15),
        256,
    );
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
    notifications.notify("environment_changes", &format!("{OTHER_ORG}:{ENV}"));
    notifications.notify("credit_changes", OTHER_ORG);
    notifications.notify("environment_changes", &format!("{ORG}:{ENV}"));
    notifications.notify("resize_changes", &format!("{ORG}:{ENV}"));
    notifications.notify("credit_changes", ORG);
    assert_eq!(
        next(&mut events).await,
        Some(LiveEvent::Sandbox {
            org: ORG.into(),
            environment: ENV.into()
        })
    );
    assert_eq!(
        next(&mut events).await,
        Some(LiveEvent::Resize {
            org: ORG.into(),
            environment: ENV.into()
        })
    );
    assert_eq!(
        next(&mut events).await,
        Some(LiveEvent::Credit { org: ORG.into() })
    );
    // A listener reconnect reaches every watch.
    notifications.resync();
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
}

#[tokio::test(start_paused = true)]
async fn a_watch_that_fell_behind_resyncs_instead_of_losing_changes() {
    let notifications = LiveNotifications::with_capacity(4, MAX_WATCHES_PER_PROCESS, 2);
    let permit = notifications.acquire_watch("account").unwrap();
    let mut events = start_live_watch(
        organizations(&[ORG]),
        permit,
        Duration::from_secs(600),
        Duration::from_secs(15),
        256,
    );
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
    for _ in 0..5 {
        notifications.notify("credit_changes", ORG);
    }
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
}

#[tokio::test(start_paused = true)]
async fn a_watch_beats_every_interval_and_ends_after_its_lifetime() {
    let notifications = LiveNotifications::new(4, MAX_WATCHES_PER_PROCESS);
    let permit = notifications.acquire_watch("account").unwrap();
    let mut events = start_live_watch(
        organizations(&[ORG]),
        permit,
        Duration::from_secs(40),
        Duration::from_secs(15),
        256,
    );
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
    assert!(matches!(
        next(&mut events).await,
        Some(LiveEvent::Heartbeat(_))
    ));
    assert!(matches!(
        next(&mut events).await,
        Some(LiveEvent::Heartbeat(_))
    ));
    // 40 s: the watch ends, and its slot is released.
    assert_eq!(next(&mut events).await, None);
    tokio::task::yield_now().await;
    assert_eq!(notifications.watches("account"), 0);
}

/// A member removed while a watch is open keeps receiving that
/// organization's identifiers until the watch ends; a watch opened after the
/// removal no longer includes it. The identifiers alone grant nothing: every
/// re-fetch they lead to is authorized again (designs/live-updates.md).
#[tokio::test(start_paused = true)]
async fn a_removed_members_organization_leaves_their_next_watch() {
    let notifications = LiveNotifications::new(4, MAX_WATCHES_PER_PROCESS);
    let before = start_live_watch(
        organizations(&[ORG]),
        notifications.acquire_watch("account").unwrap(),
        Duration::from_secs(600),
        Duration::from_secs(15),
        256,
    );
    let after = start_live_watch(
        organizations(&[]),
        notifications.acquire_watch("account").unwrap(),
        Duration::from_secs(600),
        Duration::from_secs(15),
        256,
    );
    let (mut before, mut after) = (before, after);
    assert_eq!(next(&mut before).await, Some(LiveEvent::Resync));
    assert_eq!(next(&mut after).await, Some(LiveEvent::Resync));
    notifications.notify("credit_changes", ORG);
    assert_eq!(
        next(&mut before).await,
        Some(LiveEvent::Credit { org: ORG.into() })
    );
    // The renewed watch gets nothing from the organization; its next event
    // is the heartbeat.
    assert!(matches!(
        next(&mut after).await,
        Some(LiveEvent::Heartbeat(_))
    ));
}

/// A reader that stops reading costs a bounded queue: events past its
/// capacity are dropped, and one resync waits for the reader instead.
#[tokio::test(start_paused = true)]
async fn a_reader_that_stops_reading_gets_a_bounded_queue_and_one_resync() {
    let notifications = LiveNotifications::new(4, MAX_WATCHES_PER_PROCESS);
    let mut events = start_live_watch(
        organizations(&[ORG]),
        notifications.acquire_watch("account").unwrap(),
        Duration::from_secs(600),
        Duration::from_secs(15),
        4,
    );
    // The watch subscribes when it starts, which its first resync marks.
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
    for _ in 0..50 {
        notifications.notify("credit_changes", ORG);
    }
    // Let the watch take every notice before the reader looks.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    // The reader catches up: the four that fit, then, at the next chance to
    // send, the single resync that stands for everything dropped.
    let mut drained = Vec::new();
    while let Ok(event) = events.try_recv() {
        drained.push(event);
    }
    assert_eq!(drained, vec![LiveEvent::Credit { org: ORG.into() }; 4]);
    assert_eq!(next(&mut events).await, Some(LiveEvent::Resync));
    assert!(matches!(
        next(&mut events).await,
        Some(LiveEvent::Heartbeat(_))
    ));
}

#[test]
fn an_audit_notice_is_parsed_and_passes_only_its_audience() {
    let notice = LiveSignal::from_notice("audit_changes", &format!("{ORG}:{ENV}"))
        .expect("an audit notice parses");
    assert_eq!(
        notice,
        LiveSignal::Audit {
            org: ORG.into(),
            environment: ENV.into(),
        }
    );
    assert_eq!(LiveSignal::from_notice("audit_changes", ORG), None);

    let set = |ids: &[&str]| {
        ids.iter()
            .map(|id| (*id).to_owned())
            .collect::<HashSet<_>>()
    };
    let admin = Audience {
        organizations: set(&[ORG]),
        audit_organizations: set(&[ORG]),
        audit_environments: HashSet::new(),
    };
    let granted = Audience {
        organizations: set(&[ORG]),
        audit_organizations: HashSet::new(),
        audit_environments: set(&[ENV]),
    };
    let plain = Audience::from(set(&[ORG]));
    let elsewhere = Audience {
        organizations: set(&[OTHER_ORG]),
        audit_organizations: set(&[OTHER_ORG]),
        audit_environments: set(&[ENV]),
    };
    assert!(admin.passes(&notice));
    assert!(granted.passes(&notice));
    assert!(!plain.passes(&notice), "a member who can't open it");
    assert!(!elsewhere.passes(&notice), "another organization's caller");
    let other_sandbox = LiveSignal::Audit {
        org: ORG.into(),
        environment: "another-env".into(),
    };
    assert!(!granted.passes(&other_sandbox));
    assert!(plain.passes(&LiveSignal::Credit { org: ORG.into() }));
}
