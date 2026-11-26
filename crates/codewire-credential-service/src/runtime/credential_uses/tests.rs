//! The reporter: batches per binding, a failed or older orchestration costs a
//! counted drop and nothing else, and the wire carries only the allowed
//! fields.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::*;

const POD: Uuid = Uuid::from_u128(0x6189_0000_0000_4000_8000_0000_0000_0001);
const OTHER_POD: Uuid = Uuid::from_u128(0x6189_0000_0000_4000_8000_0000_0000_0002);
const KEY: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000001";

/// Answers each call with the next outcome, `Ok` once they run out, and
/// keeps what it was sent.
#[derive(Default)]
struct Orchestration {
    outcomes: Mutex<Vec<Result<(), ReportFailure>>>,
    sent: Mutex<Vec<BindingUses>>,
}

impl Orchestration {
    fn answering(outcomes: Vec<Result<(), ReportFailure>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().rev().collect()),
            sent: Mutex::default(),
        }
    }
}

#[async_trait]
impl UseReports for Orchestration {
    async fn report(&self, uses: &BindingUses) -> Result<(), ReportFailure> {
        self.sent.lock().unwrap().push(uses.clone());
        self.outcomes.lock().unwrap().pop().unwrap_or(Ok(()))
    }
}

fn used(uses: &CredentialUses, binding: Uuid, host: &str, times: usize) {
    for _ in 0..times {
        uses.record(binding, KEY, "openai", host, SystemTime::now());
    }
}

#[tokio::test]
async fn each_bindings_folds_go_in_one_report_as_deltas() {
    let uses = CredentialUses::new();
    used(&uses, POD, "api.openai.com", 3);
    used(&uses, POD, "chatgpt.com", 1);
    used(&uses, OTHER_POD, "api.openai.com", 2);
    let reporter = Reporter::new(uses.clone(), Orchestration::default());
    assert_eq!(
        reporter.flush().await,
        Flushed {
            sent: 6,
            dropped: 0
        }
    );
    let sent = reporter.client.sent.lock().unwrap().clone();
    assert_eq!(
        sent.iter()
            .map(|batch| (batch.binding, batch.uses.len(), batch.count()))
            .collect::<Vec<_>>(),
        [(POD, 2, 4), (OTHER_POD, 1, 2)]
    );
    // What was sent is never sent again: the next report is the new uses.
    used(&uses, POD, "api.openai.com", 1);
    assert_eq!(
        reporter.flush().await,
        Flushed {
            sent: 1,
            dropped: 0
        }
    );
    assert_eq!(reporter.client.sent.lock().unwrap()[2].count(), 1);
}

#[tokio::test]
async fn an_older_orchestration_is_a_quiet_counted_drop() {
    let uses = CredentialUses::new();
    used(&uses, POD, "api.openai.com", 3);
    used(&uses, OTHER_POD, "api.openai.com", 2);
    let reporter = Reporter::new(
        uses.clone(),
        Orchestration::answering(vec![Err(ReportFailure::Unimplemented)]),
    );
    // The first call answers UNIMPLEMENTED: it and the rest are dropped,
    // counted, and not sent.
    assert_eq!(
        reporter.flush().await,
        Flushed {
            sent: 0,
            dropped: 5
        }
    );
    assert_eq!(reporter.client.sent.lock().unwrap().len(), 1);
    assert_eq!(uses.dropped(), 5);
    assert!(reporter.unimplemented_logged.load(Ordering::Relaxed));
    assert!(uses.take().is_empty(), "nothing is kept to retry");
    // Recording goes on as before.
    used(&uses, POD, "api.openai.com", 1);
    assert_eq!(uses.take()[0].count(), 1);
    assert_eq!(
        failure(ErrorCode::Unimplemented),
        ReportFailure::Unimplemented
    );
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::PermissionDenied,
        ErrorCode::Unauthenticated,
        ErrorCode::InvalidArgument,
        ErrorCode::DeadlineExceeded,
    ] {
        assert_eq!(failure(code), ReportFailure::Failed);
    }
}

#[tokio::test]
async fn a_failed_report_drops_and_counts_what_it_carried() {
    let uses = CredentialUses::new();
    used(&uses, POD, "api.openai.com", 3);
    used(&uses, OTHER_POD, "api.openai.com", 2);
    let reporter = Reporter::new(
        uses.clone(),
        Orchestration::answering(vec![Ok(()), Err(ReportFailure::Failed)]),
    );
    assert_eq!(
        reporter.flush().await,
        Flushed {
            sent: 3,
            dropped: 2
        }
    );
    assert_eq!(uses.dropped(), 2);
    assert!(!reporter.unimplemented_logged.load(Ordering::Relaxed));
}

/// Never answers: a hung orchestration costs one call timeout and a drop.
struct Hung;

#[async_trait]
impl UseReports for Hung {
    async fn report(&self, _uses: &BindingUses) -> Result<(), ReportFailure> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_hung_report_ends_at_its_timeout() {
    let uses = CredentialUses::new();
    used(&uses, POD, "api.openai.com", 2);
    let reporter = Reporter::new(uses.clone(), Hung);
    let flushed = tokio::time::timeout(CALL_TIMEOUT * 2, reporter.flush())
        .await
        .expect("the flush ends at the call timeout");
    assert_eq!(
        flushed,
        Flushed {
            sent: 0,
            dropped: 2
        }
    );
}

/// The report holds the Pod UID, the credential's id and provider, a checked
/// host and counts: no value, placeholder, method, path, header or body.
#[test]
fn the_report_carries_only_its_allowed_fields() {
    let uses = CredentialUses::new();
    let now = SystemTime::now();
    uses.record(POD, KEY, "openai", "api.openai.com", now);
    uses.record(POD, KEY, "openai", "evil\u{1b}[2J.example.com", now);
    let [batch] = uses.take().try_into().unwrap();
    let wire = request(&batch);
    let json = serde_json::to_value(&wire).unwrap();
    let mut top: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
    top.sort();
    assert_eq!(top, ["podUid", "uses"]);
    let ms = u64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
    let fields = |index: usize| -> BTreeMap<String, serde_json::Value> {
        json["uses"][index]
            .as_object()
            .unwrap()
            .clone()
            .into_iter()
            .collect()
    };
    // The withheld name is sent as a count with no text.
    let withheld = fields(0);
    assert_eq!(
        withheld.keys().collect::<Vec<_>>(),
        [
            "count",
            "credentialId",
            "firstUnixMs",
            "hostWithheld",
            "lastUnixMs",
            "provider"
        ]
    );
    let named = fields(1);
    assert_eq!(
        named.keys().collect::<Vec<_>>(),
        [
            "count",
            "credentialId",
            "firstUnixMs",
            "host",
            "lastUnixMs",
            "provider"
        ]
    );
    assert_eq!(named["host"], "api.openai.com");
    assert_eq!(named["firstUnixMs"], ms.to_string());
    assert_eq!(json["podUid"], POD.to_string());
}

#[test]
fn reporting_needs_all_three_inputs_or_none() {
    let lookup = |values: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(*value))
        }
    };
    assert_eq!(config(&lookup(&[])).unwrap(), None);
    let all: &[(&str, &str)] = &[
        (
            URL,
            "https://codewire-orchestration.prod.svc.cluster.local:8088",
        ),
        (ROOTS, "/run/codewire-orchestration-internal-roots/ca.crt"),
        (TOKEN, "/var/run/secrets/codewire/credential-service/token"),
    ];
    assert!(config(&lookup(all)).unwrap().is_some());
    assert!(config(&lookup(&all[..2])).is_err());
    assert!(
        config(&lookup(&[
            (URL, "http://codewire-orchestration:8088"),
            (ROOTS, "/roots.crt"),
            (TOKEN, "/token"),
        ]))
        .is_err()
    );
    assert!(
        config(&lookup(&[
            (URL, "https://codewire-orchestration:8088"),
            (ROOTS, "relative/roots.crt"),
            (TOKEN, "/token"),
        ]))
        .is_err()
    );
}

/// A reporter that panics or returns is logged as an error, never silent;
/// the runtime's own shutdown is not.
#[tokio::test]
async fn a_reporter_that_ends_is_told_apart_from_shutdown() {
    let panicked = tokio::spawn(async { panic!("synthetic reporter fault") });
    assert_eq!(watch(panicked).await, Ended::Panicked);
    assert_eq!(watch(tokio::spawn(async {})).await, Ended::Returned);
    let pending = tokio::spawn(std::future::pending::<()>());
    pending.abort();
    assert_eq!(watch(pending).await, Ended::Cancelled);
}
