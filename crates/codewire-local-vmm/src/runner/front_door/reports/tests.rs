use codewire_access::RefusalCode;
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSuffix};
use codewire_egress_policy::record::{Destination, Transport};

use super::*;
use crate::broker_control::LoggedRefusal;
use crate::front_door::refusals::{FrontDoorRefusals, encode_report};

fn routes() -> InterceptSet {
    InterceptSet::with_suffixes(
        vec![
            InterceptBinding::new("api.anthropic.com", 443).unwrap(),
            InterceptBinding::new("platform.claude.com", 443).unwrap(),
        ],
        vec![InterceptSuffix::new("chatgpt.com", 443).unwrap()],
    )
    .unwrap()
}

/// A word as the front door's own fold and encoder make it.
fn word(rows: &[(&str, u16, RefusalCode)]) -> Vec<u8> {
    let refusals = FrontDoorRefusals::new();
    for (host, port, code) in rows {
        codewire_egress_front_door_bridge::RefusalSink::refused(&*refusals, host, *port, *code);
    }
    encode_report(&refusals.fold().take())
}

fn intake() -> (FrontDoorReports, Arc<RunnerRefusalLog>) {
    let log = Arc::new(RunnerRefusalLog::new(0));
    (FrontDoorReports::new(Arc::clone(&log), routes()), log)
}

/// Only a host or suffix the runner bound for this boot, on its port, is
/// kept; any other row is rejected alone and counted, and the rest of its
/// report is kept.
#[tokio::test(start_paused = true)]
async fn only_a_host_the_runner_bound_is_kept() {
    let (mut reports, log) = intake();
    assert!(reports.take(&word(&[
        ("api.anthropic.com", 443, RefusalCode::NameNotAllowed),
        ("chatgpt.com", 443, RefusalCode::PathNotServed),
        ("evil.example.org", 443, RefusalCode::NameNotAllowed),
        ("api.anthropic.com", 8443, RefusalCode::Busy),
        ("workspace-1.chatgpt.com", 443, RefusalCode::Busy),
    ])));
    let snapshot = log.snapshot();
    assert_eq!(snapshot.rejected, 3);
    let mut kept: Vec<_> = snapshot
        .records
        .iter()
        .map(|record| (record.destination.clone(), record.transport, record.outcome))
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        [
            (
                Destination::Name("api.anthropic.com".to_owned()),
                Transport::Tcp { port: 443 },
                LoggedRefusal::Intercepted(RefusalCode::NameNotAllowed)
            ),
            (
                Destination::Name("chatgpt.com".to_owned()),
                Transport::Tcp { port: 443 },
                LoggedRefusal::Intercepted(RefusalCode::PathNotServed)
            ),
        ]
    );
}

/// A malformed report is rejected whole and counted once: none of its rows
/// is kept, not even a well-formed one before the fault.
#[tokio::test(start_paused = true)]
async fn a_malformed_report_keeps_nothing() {
    let (mut reports, log) = intake();
    let mut malformed = word(&[("api.anthropic.com", 443, RefusalCode::Busy)]);
    malformed.extend_from_slice(b"trailing");
    assert!(reports.take(&malformed));
    let snapshot = log.snapshot();
    assert_eq!((snapshot.rejected, snapshot.records.len()), (1, 0));
    assert!(!reports.take(b"CWFD1 serving 2\n"));
    assert_eq!(log.snapshot().rejected, 1);
}

/// The runner's own rate: a burst of three reports, then one a second; a
/// report past it is rejected whole and counted, however the front door
/// paces itself.
#[tokio::test(start_paused = true)]
async fn reports_past_the_runners_rate_are_rejected() {
    let (mut reports, log) = intake();
    let one = word(&[("api.anthropic.com", 443, RefusalCode::Busy)]);
    for _ in 0..10 {
        assert!(reports.take(&one));
    }
    let snapshot = log.snapshot();
    assert_eq!((snapshot.refused, snapshot.rejected), (3, 7));
    tokio::time::advance(REFUSAL_REPORT_INTERVAL).await;
    assert!(reports.take(&one));
    assert!(reports.take(&one));
    let snapshot = log.snapshot();
    assert_eq!((snapshot.refused, snapshot.rejected), (4, 8));
}

/// A flood of reports keeps only the rows of the hosts the runner bound,
/// one per host and code, beside the egress broker's.
#[tokio::test(start_paused = true)]
async fn a_flood_of_reports_never_evicts_the_egress_brokers_rows() {
    let (mut reports, log) = intake();
    log.file(
        codewire_egress_broker::refusals::RefusalBatch {
            rows: vec![codewire_egress_broker::refusals::RefusedRow {
                destination: Destination::checked_name("example.org"),
                address: None,
                transport: Transport::Dns,
                reason: codewire_egress_policy::lease::RefusalReason::NameNotAllowed,
                policy_digest: codewire_egress_policy::PolicyDigest::from_bytes([1; 32]),
                count: 1,
            }],
            dropped: 0,
        },
        0,
    );
    for round in 0..40_u32 {
        let rows: Vec<_> = RefusalCode::ALL
            .into_iter()
            .flat_map(|code| {
                ["api.anthropic.com", "platform.claude.com", "chatgpt.com"]
                    .map(|host| (host, 443, code))
            })
            .collect();
        reports.take(&word(&rows));
        tokio::time::advance(REFUSAL_REPORT_INTERVAL * (round % 2 + 1)).await;
    }
    let snapshot = log.snapshot();
    assert!(
        snapshot
            .records
            .iter()
            .any(|record| matches!(record.outcome, LoggedRefusal::Network(_)))
    );
    assert_eq!(snapshot.records.len(), 1 + 3 * RefusalCode::ALL.len());
}
