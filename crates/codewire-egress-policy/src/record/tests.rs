use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn label(revision: u64) -> PolicyLabel {
    PolicyLabel {
        name: "web".to_owned(),
        revision,
        digest: PolicyDigest::from_bytes([u8::try_from(revision).unwrap(); 32]),
    }
}

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

fn refused(name: &str, port: u16, reason: RefusalReason) -> EgressObservation {
    EgressObservation {
        destination: Destination::Name(name.to_owned()),
        address: Some(address(1)),
        transport: Transport::Tcp { port },
        outcome: Outcome::Refused(reason),
    }
}

fn passed(name: &str) -> EgressObservation {
    EgressObservation {
        outcome: Outcome::Passed,
        ..refused(name, 443, RefusalReason::NameNotAllowed)
    }
}

#[test]
fn repeated_refusals_fold_into_one_record_with_the_latest_address_and_policy() {
    let mut log = EgressRecordLog::new(label(1));
    assert!(log.record(
        refused("example.com", 443, RefusalReason::NameNotAllowed),
        1_000
    ));
    log.set_policy(label(2));
    let mut again = refused("example.com", 443, RefusalReason::NameNotAllowed);
    again.address = Some(address(2));
    assert!(log.record(again, 5_000));

    let records = log.list(EGRESS_RECORD_LIMIT);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.count, 2);
    assert_eq!(record.first_seen_unix_ms, 1_000);
    assert_eq!(record.last_seen_unix_ms, 5_000);
    assert_eq!(record.address, Some(address(2)));
    assert_eq!(record.policy, label(2));
}

#[test]
fn a_different_port_protocol_or_reason_is_its_own_record() {
    let mut log = EgressRecordLog::new(label(1));
    log.record(
        refused("example.com", 443, RefusalReason::NameNotAllowed),
        1,
    );
    log.record(refused("example.com", 22, RefusalReason::NameNotAllowed), 2);
    log.record(
        refused("example.com", 443, RefusalReason::PortNotAllowed),
        3,
    );
    log.record(
        EgressObservation {
            destination: Destination::Name("example.com".to_owned()),
            address: None,
            transport: Transport::Dns,
            outcome: Outcome::Refused(RefusalReason::NameNotAllowed),
        },
        4,
    );
    assert_eq!(log.len(), 4);
}

#[test]
fn passes_are_recorded_only_while_learning_and_only_since_it_began() {
    let mut log = EgressRecordLog::new(label(1));
    assert!(!log.record(passed("github.com"), 1));
    assert!(log.is_empty());

    log.start_learning(10);
    assert!(log.record(passed("github.com"), 11));
    log.record(
        refused("example.com", 443, RefusalReason::NameNotAllowed),
        12,
    );
    log.stop_learning();
    assert!(!log.record(passed("crates.io"), 13));
    assert_eq!(log.learning_since_unix_ms(), None);

    log.start_learning(20);
    assert_eq!(log.learning_since_unix_ms(), Some(20));
    let records = log.list(EGRESS_RECORD_LIMIT);
    assert_eq!(
        records.len(),
        1,
        "earlier passes are dropped, refusals stay"
    );
    assert_eq!(
        records[0].outcome,
        Outcome::Refused(RefusalReason::NameNotAllowed)
    );
}

#[test]
fn a_full_log_drops_the_record_seen_least_recently() {
    let mut log = EgressRecordLog::new(label(1));
    for port in 0..EGRESS_RECORD_LIMIT {
        let port = u16::try_from(port).unwrap();
        log.record(
            refused("example.com", port, RefusalReason::NameNotAllowed),
            100 + u64::from(port),
        );
    }
    // Port 0 is the oldest; seeing it again makes port 1 the oldest.
    log.record(
        refused("example.com", 0, RefusalReason::NameNotAllowed),
        5_000,
    );
    log.record(
        refused("example.org", 443, RefusalReason::NameNotAllowed),
        5_001,
    );

    assert_eq!(log.len(), EGRESS_RECORD_LIMIT);
    let records = log.list(EGRESS_RECORD_LIMIT);
    let ports: Vec<_> = records
        .iter()
        .filter(|record| record.destination == Destination::Name("example.com".to_owned()))
        .map(|record| record.transport)
        .collect();
    assert!(ports.contains(&Transport::Tcp { port: 0 }));
    assert!(!ports.contains(&Transport::Tcp { port: 1 }));
}

#[test]
fn list_is_newest_first_and_bounded() {
    let mut log = EgressRecordLog::new(label(1));
    log.record(refused("a.example", 443, RefusalReason::NameNotAllowed), 1);
    log.record(refused("b.example", 443, RefusalReason::NameNotAllowed), 3);
    log.record(refused("c.example", 443, RefusalReason::NameNotAllowed), 2);

    let names: Vec<_> = log
        .list(2)
        .into_iter()
        .map(|record| record.destination)
        .collect();
    assert_eq!(
        names,
        [
            Destination::Name("b.example".to_owned()),
            Destination::Name("c.example".to_owned()),
        ]
    );
}

#[test]
fn the_generation_rises_on_every_change_a_reader_sees_and_only_then() {
    let mut log = EgressRecordLog::new(label(1));
    let start = log.generation();
    log.record(passed("github.com"), 1);
    assert_eq!(
        log.generation(),
        start,
        "an unrecorded pass changes nothing"
    );
    log.stop_learning();
    assert_eq!(
        log.generation(),
        start,
        "stopping when not learning changes nothing"
    );

    log.record(
        refused("example.com", 443, RefusalReason::NameNotAllowed),
        2,
    );
    let after_new = log.generation();
    assert!(after_new > start);
    log.record(
        refused("example.com", 443, RefusalReason::NameNotAllowed),
        3,
    );
    let after_fold = log.generation();
    assert!(after_fold > after_new);
    log.start_learning(4);
    assert!(log.generation() > after_fold);
}

#[test]
fn the_guest_never_sees_a_protected_reason() {
    let expected = [
        (RefusalReason::NameNotAllowed, "name_not_allowed"),
        (RefusalReason::ProtectedAnswersOnly, "name_not_allowed"),
        (RefusalReason::PortNotAllowed, "port_not_allowed"),
        (RefusalReason::AddressNotAllowed, "address_not_allowed"),
        (RefusalReason::ProtectedAddress, "address_not_allowed"),
        (RefusalReason::LeaseExpired, "lease_expired"),
        (RefusalReason::InterceptUnavailable, "unavailable"),
    ];
    assert_eq!(expected.len(), RefusalReason::ALL.len());
    for (reason, code) in expected {
        assert_eq!(GuestRefusal::from_reason(reason).code(), code, "{reason:?}");
    }
}

#[test]
fn guest_records_merge_what_only_a_protected_reason_told_apart() {
    let mut log = EgressRecordLog::new(label(1));
    log.record(
        refused("internal.example", 443, RefusalReason::NameNotAllowed),
        10,
    );
    log.record(
        refused("internal.example", 443, RefusalReason::ProtectedAnswersOnly),
        20,
    );
    log.record(
        refused("internal.example", 443, RefusalReason::ProtectedAnswersOnly),
        30,
    );
    log.record(
        refused("other.example", 443, RefusalReason::NameNotAllowed),
        25,
    );

    let guest = guest_records(&log.list(EGRESS_RECORD_LIMIT));
    assert_eq!(guest.len(), 2);
    assert_eq!(
        guest[0].destination,
        Destination::Name("internal.example".to_owned())
    );
    assert_eq!(
        guest[0].outcome,
        GuestOutcome::Refused(GuestRefusal::NameNotAllowed)
    );
    assert_eq!(guest[0].count, 3);
    assert_eq!(guest[0].first_seen_unix_ms, 10);
    assert_eq!(guest[0].last_seen_unix_ms, 30);
    assert_eq!(
        guest[1].destination,
        Destination::Name("other.example".to_owned())
    );
}

#[test]
fn the_guest_never_sees_a_protected_answer_even_when_merged() {
    let mut log = EgressRecordLog::new(label(1));
    let protected_answer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let mut answers_only_protected =
        refused("internal.example", 443, RefusalReason::ProtectedAnswersOnly);
    answers_only_protected.address = Some(protected_answer);
    log.record(answers_only_protected.clone(), 30);

    let alone = guest_records(&log.list(EGRESS_RECORD_LIMIT));
    assert_eq!(alone.len(), 1);
    assert_eq!(alone[0].address, None);

    // An older not-allowed refusal of the same name merges with it; only its
    // own address, one the guest dialled, may show.
    log.record(
        refused("internal.example", 443, RefusalReason::NameNotAllowed),
        10,
    );
    let merged = guest_records(&log.list(EGRESS_RECORD_LIMIT));
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].address, Some(address(1)));
    assert_ne!(merged[0].address, Some(protected_answer));
    assert_eq!(merged[0].last_seen_unix_ms, 30);
}

#[test]
fn guest_records_order_newest_first_whatever_the_input_order() {
    let mut log = EgressRecordLog::new(label(1));
    log.record(refused("a.example", 443, RefusalReason::NameNotAllowed), 1);
    log.record(refused("b.example", 443, RefusalReason::NameNotAllowed), 3);
    log.record(refused("c.example", 443, RefusalReason::NameNotAllowed), 2);
    let mut oldest_first = log.list(EGRESS_RECORD_LIMIT);
    oldest_first.reverse();

    let names: Vec<_> = guest_records(&oldest_first)
        .into_iter()
        .map(|record| record.destination)
        .collect();
    assert_eq!(
        names,
        [
            Destination::Name("b.example".to_owned()),
            Destination::Name("c.example".to_owned()),
            Destination::Name("a.example".to_owned()),
        ]
    );
}
