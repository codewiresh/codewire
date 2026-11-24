//! What a carried admission may hold, and which positions a replica can check
//! it against (#3586, step 3; cw-security's bounds, 2026-11-18).

use super::*;
use crate::revocation::{Revocation, Snapshot};

fn extent(oldest: Option<i64>, newest: Option<i64>) -> LogExtent {
    LogExtent { oldest, newest }
}

#[test]
fn a_position_is_checkable_only_where_no_row_after_it_can_be_missing() {
    let log = extent(Some(40), Some(90));
    assert!(log.can_vouch_for(90), "the newest row");
    assert!(log.can_vouch_for(39), "just before the oldest row");
    assert!(!log.can_vouch_for(91), "beyond the newest row");
    assert!(
        !log.can_vouch_for(38),
        "rows after it may have been removed"
    );
    assert!(!log.can_vouch_for(-1));

    let empty = extent(None, None);
    assert!(empty.can_vouch_for(0), "a log that never held a row");
    assert!(!empty.can_vouch_for(5));
}

#[test]
fn an_id_out_of_bounds_admits_nothing() {
    let carried = |user_id: String| CarriedAdmission {
        user_id,
        credential: CarriedCredential::ApiKey {
            key_id: "key".into(),
        },
        org_id: None,
        through: 0,
    };
    assert!(carried("user".into()).admitted().is_some());
    assert!(carried(String::new()).admitted().is_none());
    assert!(carried("u".repeat(MAX_ID_LEN + 1)).admitted().is_none());
}

#[test]
fn a_carried_admission_round_trips_the_keys_it_was_made_from() {
    let fence = Fence::new();
    let admitted = Admitted::session("user", "session");
    let watch = fence.register(&admitted, Snapshot::parse("1:1:").expect("snapshot"));
    assert_eq!(fence.carry(&admitted, &watch), None, "nothing read yet");
    fence.through.store(7, std::sync::atomic::Ordering::Release);
    let carried = fence.carry(&admitted, &watch).expect("carried");
    let wire = serde_json::to_string(&carried).expect("serialize");
    let back: CarriedAdmission = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back.admitted(), Some(admitted));
    assert_eq!(back.through, 7);
}

#[test]
fn a_stream_already_ended_is_never_vouched_for() {
    let fence = Fence::new();
    let admitted = Admitted::session("user", "session");
    let watch = fence.register(&admitted, Snapshot::parse("1:1:").expect("snapshot"));
    fence.through.store(7, std::sync::atomic::Ordering::Release);
    fence.dispatch(&[super::super::LogEntry {
        key: super::super::Authority::Session("session".into()),
        revocation: Revocation::Session,
        xact: 5,
    }]);
    assert_eq!(fence.carry(&admitted, &watch), None);
}

#[test]
fn the_organization_travels_and_an_older_admission_without_it_still_reads() {
    let fence = Fence::new();
    let admitted = Admitted::session("user", "session").in_organization("org-a");
    let watch = fence.register(&admitted, Snapshot::parse("1:1:").expect("snapshot"));
    fence.through.store(7, std::sync::atomic::Ordering::Release);
    let wire = serde_json::to_string(&fence.carry(&admitted, &watch).expect("carried"))
        .expect("serialize");
    let back: CarriedAdmission = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back.admitted(), Some(admitted));

    // An older process's admission names no organization.
    let older =
        r#"{"user_id":"user","credential":{"kind":"session","session_id":"session"},"through":7}"#;
    let back: CarriedAdmission = serde_json::from_str(older).expect("deserialize");
    assert_eq!(back.admitted(), Some(Admitted::session("user", "session")));
    // And one with no organization serializes as it did.
    let plain = Admitted::session("user", "session");
    let plain_watch = fence.register(&plain, Snapshot::parse("1:1:").expect("snapshot"));
    let wire = serde_json::to_string(&fence.carry(&plain, &plain_watch).expect("carried"))
        .expect("serialize");
    assert!(!wire.contains("org_id"), "{wire}");
}
