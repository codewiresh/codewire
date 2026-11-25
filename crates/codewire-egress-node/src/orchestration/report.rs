//! cw-egress's reports to orchestration (#4000): what a Pod's pair enforces,
//! and the egress records its broker folded. Orchestration stores them per
//! Pod and reads status from the environment's current Pod.

use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::record::{Destination, EgressRecord, Outcome, Transport};
use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_record::Destination as WireDestination;
use codewire_proto::codewire::internal::v1::{
    EgressEnforcementState, EgressRecord as WireRecord, EgressTransport, ReportEnforcementRequest,
    ReportRecordsRequest,
};

use super::{CallError, Orchestration};

/// The most records one call carries; orchestration refuses a larger batch.
pub const RECORDS_PER_CALL: usize = 256;
/// The highest policy revision orchestration stores; a record above it is
/// one orchestration would refuse, so it is not sent.
const MAX_POLICY_REVISION: u64 = 10_000;

/// What one Pod's pair enforces, as orchestration stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Enforcement {
    Enforced {
        revision: u32,
        digest: PolicyDigest,
    },
    /// The pair has no egress; `detail` is a fixed failure code.
    FailedClosed {
        detail: &'static str,
    },
    Disconnected,
}

impl Orchestration {
    /// Reports what `pod_uid`'s pair enforces now.
    pub async fn report_enforcement(
        &self,
        pod_uid: &str,
        pod_name: &str,
        enforcement: &Enforcement,
    ) -> Result<(), CallError> {
        let mut request = ReportEnforcementRequest {
            pod_uid: pod_uid.to_owned(),
            pod_name: pod_name.to_owned(),
            ..Default::default()
        };
        match enforcement {
            Enforcement::Enforced { revision, digest } => {
                request.state = EgressEnforcementState::Enforced.into();
                request.revision = *revision;
                request.digest = digest.as_bytes().to_vec();
            }
            Enforcement::FailedClosed { detail } => {
                request.state = EgressEnforcementState::FailedClosed.into();
                request.detail = (*detail).to_owned();
            }
            Enforcement::Disconnected => {
                request.state = EgressEnforcementState::Disconnected.into();
            }
        }
        self.client()?
            .report_enforcement_with_options(request, self.options()?)
            .await?;
        Ok(())
    }

    /// Reports up to [`RECORDS_PER_CALL`] of `pod_uid`'s records.
    pub async fn report_records(
        &self,
        pod_uid: &str,
        pod_name: &str,
        records: Vec<WireRecord>,
    ) -> Result<(), CallError> {
        debug_assert!(records.len() <= RECORDS_PER_CALL);
        self.client()?
            .report_records_with_options(
                ReportRecordsRequest {
                    pod_uid: pod_uid.to_owned(),
                    pod_name: pod_name.to_owned(),
                    records,
                    ..Default::default()
                },
                self.options()?,
            )
            .await?;
        Ok(())
    }
}

/// One folded record as orchestration takes it, or `None` for one it would
/// refuse (a policy revision past its bound). A withheld name crosses as
/// withheld, with its count and never its text.
pub fn wire_record(record: &EgressRecord) -> Option<WireRecord> {
    let revision = u32::try_from(record.policy.revision)
        .ok()
        .filter(|revision| u64::from(*revision) <= MAX_POLICY_REVISION)?;
    let (transport, port) = match record.transport {
        Transport::Dns => (EgressTransport::Dns, 0),
        Transport::Tcp { port } => (EgressTransport::Tcp, u32::from(port)),
        Transport::Udp { port } => (EgressTransport::Udp, u32::from(port)),
    };
    let destination = match &record.destination {
        Destination::Name(name) => WireDestination::Name(name.clone()),
        Destination::Address(address) => WireDestination::AddressOnly(address.to_string()),
        Destination::Withheld => WireDestination::Withheld(true),
    };
    Some(WireRecord {
        destination: Some(destination),
        address: record
            .address
            .map(|address| address.to_string())
            .unwrap_or_default(),
        transport: transport.into(),
        port,
        refusal: match record.outcome {
            Outcome::Passed => String::new(),
            Outcome::Refused(reason) => reason.code().to_owned(),
        },
        policy_reference: record.policy.name.clone(),
        policy_revision: revision,
        policy_digest: record.policy.digest.as_bytes().to_vec(),
        first_seen_unix_ms: record.first_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        count: record.count,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests;
