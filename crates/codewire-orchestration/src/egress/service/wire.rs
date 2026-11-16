//! cw-egress's reports, parsed once from the wire into the store's types.
//! Anything outside what cw-egress sends is refused, not repaired.

use codewire_egress_policy::lease::RefusalReason;
use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_record::Destination;
use codewire_proto::codewire::internal::v1::{
    EgressEnforcementState, EgressRecord, EgressTransport, ReportEnforcementRequest,
};

use crate::egress::reports::{
    Enforcement, FailureCode, MAX_ADDRESS_LEN, MAX_POLICY_REVISION, MAX_REFERENCE_LEN,
    ReportedRecord, Transport,
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

pub(super) fn record(record: &EgressRecord) -> Option<ReportedRecord> {
    let (destination, destination_is_name) = match record.destination.as_ref()? {
        Destination::Name(name) => (name.clone(), true),
        Destination::AddressOnly(address) => (address.clone(), false),
    };
    if destination.is_empty()
        || destination.len() > 253
        || record.policy_reference.is_empty()
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
    let outcome = match record.refusal.as_str() {
        "" => None,
        code => Some(
            RefusalReason::ALL
                .into_iter()
                .find(|reason| reason.code() == code)?,
        ),
    };
    Some(ReportedRecord {
        destination,
        destination_is_name,
        address: (!record.address.is_empty()).then(|| record.address.clone()),
        transport,
        outcome,
        policy_reference: record.policy_reference.clone(),
        policy_revision: record.policy_revision,
        policy_digest: record.policy_digest.as_slice().try_into().ok()?,
        first_seen_unix_ms: record.first_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        count: record.count,
    })
}
