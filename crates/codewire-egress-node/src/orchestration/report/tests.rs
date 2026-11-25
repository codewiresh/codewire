use std::net::{IpAddr, Ipv4Addr};

use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::PolicyLabel;

use super::*;

fn record(destination: Destination, transport: Transport, outcome: Outcome) -> EgressRecord {
    EgressRecord {
        destination,
        address: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        transport,
        outcome,
        policy: PolicyLabel {
            name: "platform:web".into(),
            revision: 3,
            digest: PolicyDigest::from_bytes([9; 32]),
        },
        first_seen_unix_ms: 10,
        last_seen_unix_ms: 20,
        count: 4,
    }
}

#[test]
fn a_refused_name_crosses_with_its_reason_policy_and_counts() {
    let wire = wire_record(&record(
        Destination::Name("example.com".into()),
        Transport::Tcp { port: 443 },
        Outcome::Refused(RefusalReason::NameNotAllowed),
    ))
    .unwrap();
    assert_eq!(
        wire.destination,
        Some(WireDestination::Name("example.com".into()))
    );
    assert_eq!(wire.address, "203.0.113.7");
    assert_eq!(wire.transport.as_known(), Some(EgressTransport::Tcp));
    assert_eq!(wire.port, 443);
    assert_eq!(wire.refusal, RefusalReason::NameNotAllowed.code());
    assert_eq!(wire.policy_reference, "platform:web");
    assert_eq!(wire.policy_revision, 3);
    assert_eq!(wire.policy_digest, vec![9; 32]);
    assert_eq!(
        (wire.first_seen_unix_ms, wire.last_seen_unix_ms, wire.count),
        (10, 20, 4)
    );
}

#[test]
fn an_address_lookup_and_a_pass_cross_as_orchestration_reads_them() {
    let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let tcp = wire_record(&record(
        Destination::Address(address),
        Transport::Udp { port: 53 },
        Outcome::Passed,
    ))
    .unwrap();
    assert_eq!(
        tcp.destination,
        Some(WireDestination::AddressOnly("198.51.100.1".into()))
    );
    assert_eq!(tcp.transport.as_known(), Some(EgressTransport::Udp));
    assert_eq!(tcp.port, 53);
    // A pass carries no refusal code.
    assert_eq!(tcp.refusal, "");
    // A DNS record names no port.
    let dns = wire_record(&record(
        Destination::Name("example.com".into()),
        Transport::Dns,
        Outcome::Passed,
    ))
    .unwrap();
    assert_eq!(
        (dns.transport.as_known(), dns.port),
        (Some(EgressTransport::Dns), 0)
    );
}

#[test]
fn a_record_orchestration_would_refuse_is_not_sent() {
    let mut beyond = record(
        Destination::Name("example.com".into()),
        Transport::Tcp { port: 443 },
        Outcome::Passed,
    );
    beyond.policy.revision = MAX_POLICY_REVISION + 1;
    assert!(wire_record(&beyond).is_none());
    beyond.policy.revision = MAX_POLICY_REVISION;
    assert!(wire_record(&beyond).is_some());
}

/// A datagram the worker dropped crosses as a UDP refusal with its port and
/// a reason orchestration reads back (#3997).
#[test]
fn a_refused_datagram_crosses_as_udp_with_its_port_and_reason() {
    let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let wire = wire_record(&record(
        Destination::Address(address),
        Transport::Udp { port: 3478 },
        Outcome::Refused(RefusalReason::UdpNotCarried),
    ))
    .unwrap();
    assert_eq!(
        wire.destination,
        Some(WireDestination::AddressOnly("198.51.100.7".into()))
    );
    assert_eq!(wire.transport.as_known(), Some(EgressTransport::Udp));
    assert_eq!(wire.port, 3478);
    assert_eq!(wire.refusal, "udp_not_carried");
    assert_eq!(
        RefusalReason::ALL
            .into_iter()
            .find(|reason| reason.code() == wire.refusal),
        Some(RefusalReason::UdpNotCarried)
    );
}

/// SPEC.md "The host check": a name that failed the check crosses withheld,
/// with its count, and no text.
#[test]
fn a_withheld_name_crosses_as_withheld_with_its_count() {
    let wire = wire_record(&record(
        Destination::checked_name("evil\x1b[2J.example.com"),
        Transport::Dns,
        Outcome::Refused(RefusalReason::NameNotAllowed),
    ))
    .unwrap();
    assert_eq!(wire.destination, Some(WireDestination::Withheld(true)));
    assert_eq!(wire.count, 4);
}
