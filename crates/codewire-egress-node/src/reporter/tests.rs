use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::record::{Destination, EgressRecord, Outcome, PolicyLabel, Transport};

use super::*;
use crate::admitted::FailureCode;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Enforcement(String, Enforcement),
    Records(String, usize),
}

#[derive(Default)]
struct Recorded(Mutex<Vec<Call>>);

impl Recorded {
    fn calls(&self) -> Vec<Call> {
        self.0.lock().unwrap().clone()
    }
}

impl Reports for Recorded {
    fn enforcement(
        &self,
        pod_uid: &str,
        _pod_name: &str,
        enforcement: &Enforcement,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        self.0
            .lock()
            .unwrap()
            .push(Call::Enforcement(pod_uid.to_owned(), enforcement.clone()));
        std::future::ready(Ok(()))
    }

    fn records(
        &self,
        pod_uid: &str,
        _pod_name: &str,
        records: Vec<WireRecord>,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        self.0
            .lock()
            .unwrap()
            .push(Call::Records(pod_uid.to_owned(), records.len()));
        std::future::ready(Ok(()))
    }
}

const POD: Uuid = Uuid::from_u128(0x0b8f_6a52_0f6c_4a59_9f43_1b1f_0c3a_9e01);

fn enforced(revision: u32) -> PodEvent {
    PodEvent::Enforced {
        revision,
        digest: PolicyDigest::from_bytes([u8::try_from(revision).unwrap(); 32]),
    }
}

fn reported(revision: u32) -> Call {
    Call::Enforcement(
        POD.to_string(),
        Enforcement::Enforced {
            revision,
            digest: PolicyDigest::from_bytes([u8::try_from(revision).unwrap(); 32]),
        },
    )
}

fn disconnected() -> Call {
    Call::Enforcement(POD.to_string(), Enforcement::Disconnected)
}

/// Lets the forwarding and reporting tasks run what is queued.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn one_pods_reports_go_in_order_and_an_ordinary_end_reports_it_disconnected() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let events = reporter.admit(POD, "workspace".into());
    assert!(events.send(enforced(1)).await);
    assert!(events.send(enforced(2)).await);
    assert!(events.send(PodEvent::Ended { moved: false }).await);
    settle().await;
    assert_eq!(sink.calls(), [reported(1), reported(2), disconnected()]);
}

#[tokio::test(start_paused = true)]
async fn a_failed_check_stays_the_pods_state_through_its_end() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let events = reporter.admit(POD, "workspace".into());
    assert!(
        events
            .send(PodEvent::FailedClosed(FailureCode::SelfCheckFailed))
            .await
    );
    assert!(events.send(PodEvent::Ended { moved: false }).await);
    settle().await;
    assert_eq!(
        sink.calls(),
        [Call::Enforcement(
            POD.to_string(),
            Enforcement::FailedClosed {
                detail: "self_check_failed"
            }
        )]
    );
}

#[tokio::test(start_paused = true)]
async fn a_pair_ended_for_a_move_reports_nothing_after_its_records() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let events = reporter.admit(POD, "workspace".into());
    assert!(events.send(enforced(1)).await);
    assert!(events.send(PodEvent::Ended { moved: true }).await);
    settle().await;
    assert_eq!(sink.calls(), [reported(1)]);
}

#[tokio::test(start_paused = true)]
async fn a_replaced_pairs_end_never_lands_after_its_successors_report() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let older = reporter.admit(POD, "workspace".into());
    assert!(older.send(enforced(1)).await);
    settle().await;
    let newer = reporter.admit(POD, "workspace".into());
    assert!(newer.send(enforced(2)).await);
    settle().await;
    // The older pair is torn down after its successor reported.
    assert!(older.send(PodEvent::Ended { moved: false }).await);
    assert!(older.send(enforced(9)).await);
    settle().await;
    assert_eq!(sink.calls(), [reported(1), reported(2)]);
}

#[tokio::test(start_paused = true)]
async fn an_idle_enforced_pod_is_reported_again_within_the_refresh_interval() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let events = reporter.admit(POD, "workspace".into());
    // The interval's first tick is at once; past it, only the refresh speaks.
    settle().await;
    assert!(events.send(enforced(1)).await);
    settle().await;
    assert_eq!(sink.calls(), [reported(1)]);
    tokio::time::advance(REFRESH).await;
    settle().await;
    assert_eq!(sink.calls(), [reported(1), reported(1)]);
    tokio::time::advance(REFRESH).await;
    settle().await;
    assert_eq!(sink.calls(), [reported(1), reported(1), reported(1)]);
}

fn records(count: usize) -> Vec<EgressRecord> {
    (0..count)
        .map(|index| EgressRecord {
            destination: Destination::Name(format!("h{index}.example.com")),
            address: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            transport: Transport::Tcp { port: 443 },
            outcome: Outcome::Passed,
            policy: PolicyLabel {
                name: "locked".into(),
                revision: 0,
                digest: PolicyDigest::from_bytes([1; 32]),
            },
            first_seen_unix_ms: 1,
            last_seen_unix_ms: 2,
            count: 1,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn records_go_in_batches_orchestration_takes_at_the_flush() {
    let sink = Arc::new(Recorded::default());
    let (reporter, _task) = Reporter::start(Arc::clone(&sink));
    let events = reporter.admit(POD, "workspace".into());
    settle().await;
    assert!(
        events
            .send(PodEvent::Records(records(RECORDS_PER_CALL + 44)))
            .await
    );
    settle().await;
    assert!(sink.calls().is_empty());
    tokio::time::advance(FLUSH).await;
    settle().await;
    assert_eq!(
        sink.calls(),
        [
            Call::Records(POD.to_string(), RECORDS_PER_CALL),
            Call::Records(POD.to_string(), 44),
        ]
    );
}
