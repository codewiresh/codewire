//! A reported refusal as the Sandbox audit log records it (SPEC.md "Sandbox
//! audit log", "The refusal path"): a `refused` event the Sandbox's workload
//! caused, under the environment the Pod's binding names, its count the
//! report's delta, folded per subject and hour by the log's writer. Every
//! record `ReportRecords` carries is one the Pod's broker folded, so its
//! source is the network; a front door's refusals never reach this path.
//!
//! cw-egress labels a record with the policy's reference; the log names the
//! policy, as the read words it. A built-in and `platform:NAME` name
//! themselves; `platform:id:UUID` is looked up in the event's organization,
//! and one it doesn't hold, another organization's included, is recorded
//! with no name and its revision, never the id: an id names nothing a reader
//! can act on, and another organization's must not show.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use codewire_egress_policy::reference::{
    PolicyId, PolicyReference, PolicyReferenceError, PolicyStore,
};
use sqlx::PgConnection;

use super::{ReportedDestination, ReportedRecord, Transport};
use crate::audit::{Actor, Event, Protocol, Refusal, RefusalSource, What};

/// What a reference says about its policy's name.
#[derive(Debug, PartialEq, Eq)]
enum Named {
    Name(String),
    /// A stored policy, to look up by id.
    Stored(PolicyId),
    Unnamed,
}

fn named(reference: &str) -> Named {
    match PolicyReference::parse(reference) {
        Ok(PolicyReference::Builtin(builtin))
        | Err(PolicyReferenceError::QualifiedBuiltin(builtin)) => {
            Named::Name(builtin.name().to_owned())
        }
        Ok(PolicyReference::Name { name, .. }) => Named::Name(name.as_str().to_owned()),
        Ok(PolicyReference::Id {
            store: PolicyStore::Platform,
            id,
        }) => Named::Stored(id),
        Ok(PolicyReference::Id { .. }) | Err(_) => Named::Unnamed,
    }
}

/// The policy names one report's records resolve to, each reference looked
/// up once per organization.
#[derive(Debug, Default)]
pub(super) struct PolicyNames(HashMap<(String, String), Option<String>>);

impl PolicyNames {
    /// The name `reference` gives the policy in `org_id`, on the report's
    /// own transaction.
    pub(super) async fn name(
        &mut self,
        connection: &mut PgConnection,
        org_id: &str,
        reference: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let key = (org_id.to_owned(), reference.to_owned());
        if let Some(name) = self.0.get(&key) {
            return Ok(name.clone());
        }
        let name = match named(reference) {
            Named::Name(name) => Some(name),
            Named::Stored(id) => {
                crate::api::network_policies::stored_policy_name(connection, org_id, &id).await?
            }
            Named::Unnamed => None,
        };
        self.0.insert(key, name.clone());
        Ok(name)
    }
}

/// The event `record` adds to the log under `policy`, its policy's name,
/// seen `count` times between `first` and `last`; `None` for a pass, which
/// the log never records.
pub(super) fn refused(
    org_id: &str,
    environment_id: &str,
    record: &ReportedRecord,
    policy: Option<String>,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
) -> Option<Event> {
    let reason = record.outcome?;
    let (protocol, port) = match record.transport {
        Transport::Dns => (Protocol::Dns, None),
        Transport::Tcp { port } => (Protocol::Tcp, Some(port)),
        Transport::Udp { port } => (Protocol::Udp, Some(port)),
    };
    let destination = match &record.destination {
        ReportedDestination::Name(name) => Some(name.clone()),
        ReportedDestination::Address(address) => Some(address.clone()),
        ReportedDestination::Withheld => None,
    };
    Some(Event {
        org_id: org_id.to_owned(),
        environment_id: environment_id.to_owned(),
        actor: Actor::Sandbox,
        client_ip: None,
        first,
        last,
        count: record.count,
        what: What::Refused(Refusal {
            withheld: destination.is_none(),
            destination,
            address: record.address.clone(),
            port,
            protocol,
            reason,
            source: RefusalSource::Network,
            policy,
            revision: Some(record.policy_revision),
        }),
    })
}

#[cfg(test)]
mod tests {
    use codewire_egress_policy::lease::RefusalReason;

    use super::*;

    fn record(destination: ReportedDestination, transport: Transport) -> ReportedRecord {
        ReportedRecord {
            destination,
            address: Some("192.0.2.80".to_owned()),
            transport,
            outcome: Some(RefusalReason::PortNotAllowed),
            policy_reference: "walk-docs".to_owned(),
            policy_revision: 2,
            policy_digest: [7; 32],
            first_seen_unix_ms: 1,
            last_seen_unix_ms: 2,
            count: 5,
        }
    }

    #[test]
    fn a_refusal_is_the_sandboxs_event_with_its_delta_and_labels() {
        let at = Utc::now();
        let event = refused(
            "org",
            "env",
            &record(
                ReportedDestination::Name("example.com".to_owned()),
                Transport::Tcp { port: 8080 },
            ),
            Some("walk-docs".to_owned()),
            at,
            at,
        )
        .unwrap();
        assert_eq!(event.actor, Actor::Sandbox);
        assert_eq!(event.count, 5);
        assert_eq!(event.client_ip, None);
        assert_eq!(
            event.what,
            What::Refused(Refusal {
                destination: Some("example.com".to_owned()),
                withheld: false,
                address: Some("192.0.2.80".to_owned()),
                port: Some(8080),
                protocol: Protocol::Tcp,
                reason: RefusalReason::PortNotAllowed,
                source: RefusalSource::Network,
                policy: Some("walk-docs".to_owned()),
                revision: Some(2),
            })
        );
    }

    #[test]
    fn a_withheld_name_has_no_text_a_lookup_no_port_and_a_pass_no_event() {
        let at = Utc::now();
        let event = refused(
            "org",
            "env",
            &record(ReportedDestination::Withheld, Transport::Dns),
            None,
            at,
            at,
        )
        .unwrap();
        let What::Refused(refusal) = event.what else {
            panic!("a refusal");
        };
        assert!(refusal.withheld && refusal.destination.is_none());
        assert_eq!((refusal.protocol, refusal.port), (Protocol::Dns, None));

        let pass = ReportedRecord {
            outcome: None,
            ..record(
                ReportedDestination::Name("example.com".to_owned()),
                Transport::Tcp { port: 443 },
            )
        };
        assert!(refused("org", "env", &pass, None, at, at).is_none());
    }

    /// A built-in, however a reference spells it, and `platform:NAME` name
    /// themselves; an id is looked up; nothing else names a policy.
    #[test]
    fn a_reference_names_its_policy_or_is_looked_up_by_id() {
        for (reference, name) in [
            ("open", "open"),
            ("web", "web"),
            ("locked", "locked"),
            ("platform:locked", "locked"),
            ("platform:walk-docs", "walk-docs"),
            ("walk-docs", "walk-docs"),
        ] {
            assert_eq!(
                named(reference),
                Named::Name(name.to_owned()),
                "{reference}"
            );
        }
        const ID: &str = "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a";
        assert_eq!(
            named(&format!("platform:id:{ID}")),
            Named::Stored(PolicyId::parse(ID).unwrap())
        );
        for unnamed in [&format!("local:id:{ID}"), "platform:id:not-a-uuid", ""] {
            assert_eq!(named(unnamed), Named::Unnamed, "{unnamed}");
        }
    }
}
