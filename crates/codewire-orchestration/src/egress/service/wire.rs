//! cw-egress's reports, parsed once from the wire into the store's types.
//! Anything outside what cw-egress sends is refused, not repaired.

use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::Destination as CheckedName;
use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_record::Destination;
use codewire_proto::codewire::internal::v1::{
    EgressEnforcementState, EgressRecord, EgressTransport, ReportEnforcementRequest,
};

use crate::egress::reports::{
    Enforcement, FailureCode, MAX_ADDRESS_LEN, MAX_POLICY_REVISION, MAX_REFERENCE_LEN,
    ReportedDestination, ReportedRecord, Transport,
};

pub(super) fn enforcement(request: &ReportEnforcementRequest) -> Option<Enforcement> {
    let enforcement = match request.state.as_known()? {
        EgressEnforcementState::Enforced => Enforcement::Enforced {
            revision: Some(request.revision)
                .filter(|revision| *revision <= MAX_POLICY_REVISION.unsigned_abs())?,
            digest: request.digest.as_slice().try_into().ok()?,
        },
        EgressEnforcementState::FailedClosed => Enforcement::FailedClosed {
            detail: FailureCode::parse(&request.detail)?,
        },
        EgressEnforcementState::Disconnected => Enforcement::Disconnected,
        EgressEnforcementState::Unspecified => return None,
    };
    // Only an enforced report names a revision or a digest.
    let named = request.revision != 0 || !request.digest.is_empty();
    match enforcement {
        Enforcement::Enforced { .. } => Some(enforcement),
        _ if named => None,
        _ => Some(enforcement),
    }
}

/// A well-formed record, or one whose refusal reason this orchestration
/// doesn't know: a newer cw-egress's. That one is dropped and counted, so it
/// costs only itself, never the report it came in.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Parsed {
    Record(ReportedRecord),
    UnknownReason { count: u64 },
}

/// A name passes the host check (SPEC.md "Sandbox audit log", "The host
/// check") before it is stored: one that fails is kept withheld, with its
/// count and never its text, as one cw-egress withheld already is. `None`
/// for anything cw-egress never sends.
pub(super) fn record(record: &EgressRecord) -> Option<Parsed> {
    let destination = match record.destination.as_ref()? {
        Destination::Name(name) => match CheckedName::checked_name(name) {
            CheckedName::Name(name) => ReportedDestination::Name(name),
            _ => ReportedDestination::Withheld,
        },
        Destination::AddressOnly(address)
            if !address.is_empty() && address.len() <= MAX_ADDRESS_LEN =>
        {
            ReportedDestination::Address(address.clone())
        }
        Destination::Withheld(true) => ReportedDestination::Withheld,
        Destination::AddressOnly(_) | Destination::Withheld(false) => return None,
    };
    if record.policy_reference.is_empty()
        || record.policy_reference.len() > MAX_REFERENCE_LEN
        || record.address.len() > MAX_ADDRESS_LEN
        || record.policy_revision > MAX_POLICY_REVISION.unsigned_abs()
    {
        return None;
    }
    let port = u16::try_from(record.port).ok();
    let transport = match record.transport.as_known()? {
        EgressTransport::Dns if record.port == 0 => Transport::Dns,
        EgressTransport::Tcp => Transport::Tcp {
            port: port.filter(|port| *port != 0)?,
        },
        EgressTransport::Udp => Transport::Udp {
            port: port.filter(|port| *port != 0)?,
        },
        EgressTransport::Dns | EgressTransport::Unspecified => return None,
    };
    let policy_digest = record.policy_digest.as_slice().try_into().ok()?;
    let outcome = match record.refusal.as_str() {
        "" => None,
        code => match RefusalReason::ALL
            .into_iter()
            .find(|reason| reason.code() == code)
        {
            Some(reason) => Some(reason),
            None => {
                return Some(Parsed::UnknownReason {
                    count: record.count,
                });
            }
        },
    };
    Some(Parsed::Record(ReportedRecord {
        destination,
        address: (!record.address.is_empty()).then(|| record.address.clone()),
        transport,
        outcome,
        policy_reference: record.policy_reference.clone(),
        policy_revision: record.policy_revision,
        policy_digest,
        first_seen_unix_ms: record.first_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        count: record.count,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(destination: Destination) -> EgressRecord {
        EgressRecord {
            destination: Some(destination),
            transport: EgressTransport::Dns.into(),
            refusal: "name_not_allowed".to_owned(),
            policy_reference: "walk-docs".to_owned(),
            policy_revision: 1,
            policy_digest: vec![7; 32],
            count: 3,
            ..Default::default()
        }
    }

    fn stored(parsed: Option<Parsed>) -> ReportedRecord {
        match parsed {
            Some(Parsed::Record(record)) => record,
            other => panic!("expected a record, got {other:?}"),
        }
    }

    /// A reason this orchestration doesn't know drops only its record, with
    /// its count; a reason it knows is the record's.
    #[test]
    fn a_record_with_an_unknown_reason_is_dropped_and_counted() {
        let mut newer = wire(Destination::Name("example.com".to_owned()));
        newer.refusal = "a_reason_from_a_newer_cw_egress".to_owned();
        assert_eq!(record(&newer), Some(Parsed::UnknownReason { count: 3 }));
        let known = stored(record(&wire(Destination::Name("example.com".to_owned()))));
        assert_eq!(known.outcome, Some(RefusalReason::NameNotAllowed));
    }

    /// SPEC.md "The host check": a name that fails it is kept withheld with
    /// its count, never its text, and a passing one as the check leaves it.
    #[test]
    fn a_name_that_fails_the_host_check_is_withheld_with_its_count() {
        for failing in [
            "evil\x1b[2J.example.com",
            "caf\u{e9}.example",
            &"a".repeat(254),
        ] {
            let stored = stored(record(&wire(Destination::Name(failing.to_owned()))));
            assert_eq!(
                stored.destination,
                ReportedDestination::Withheld,
                "{failing:?}"
            );
            assert_eq!(stored.count, 3);
        }
        let checked = stored(record(&wire(Destination::Name("Example.COM.".to_owned()))));
        assert_eq!(
            checked.destination,
            ReportedDestination::Name("example.com".to_owned())
        );
        let withheld = stored(record(&wire(Destination::Withheld(true))));
        assert_eq!(withheld.destination, ReportedDestination::Withheld);
        assert!(record(&wire(Destination::Withheld(false))).is_none());
        assert!(record(&wire(Destination::AddressOnly(String::new()))).is_none());
    }
}
