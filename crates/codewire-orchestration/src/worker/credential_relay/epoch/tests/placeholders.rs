//! The placeholders an intercepted epoch's broker admission gives the daemon
//! (#4001): read from the relay's own admission response, only for an epoch
//! it said is intercepted, and only whole; never logged.

use std::io::Write;

use codewire_access::known_answer::PLACEHOLDER;
use tonic::metadata::MetadataMap;

use super::*;

/// A well-formed placeholder other than the known answer's.
const OTHER: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn header(values: &[&str]) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for value in values {
        metadata.append(
            codewire_daemon_proto::CREDENTIAL_BRIDGE_PLACEHOLDERS_HEADER,
            value.parse().unwrap(),
        );
    }
    metadata
}

#[test]
fn only_one_whole_set_on_an_intercepted_epoch_is_taken() {
    let good = format!("anthropic={PLACEHOLDER}");
    let taken = broker_placeholders(&header(&[&good]), true).unwrap();
    assert!(
        taken
            .anthropic()
            .unwrap()
            .ct_eq(&codewire_access::CredentialPlaceholder::parse(PLACEHOLDER).unwrap())
    );
    assert!(
        broker_placeholders(&header(&[""]), true)
            .unwrap()
            .is_empty()
    );
    assert!(broker_placeholders(&header(&[]), false).unwrap().is_empty());
    // GitHub's slot travels beside Anthropic's while its hosts are bound
    // (#4001).
    let both = broker_placeholders(&header(&[&format!("{good},github={OTHER}")]), true).unwrap();
    assert_eq!(both.github().unwrap().as_str(), OTHER);
    assert!(both.anthropic().is_some());
    for (values, intercepted) in [
        // Missing on an intercepted epoch, present on one that isn't.
        (vec![], true),
        (vec![good.as_str()], false),
        (vec![""], false),
        // Repeated header values.
        (vec![good.as_str(), good.as_str()], true),
        (vec!["", ""], true),
    ] {
        assert!(
            broker_placeholders(&header(&values), intercepted).is_none(),
            "{values:?} intercepted={intercepted}"
        );
    }
    for value in [
        format!("openai={PLACEHOLDER}"),
        format!("codex={PLACEHOLDER}"),
        format!("ssh={PLACEHOLDER}"),
        format!("{good},github={OTHER},github={OTHER}"),
        format!("{good},github=not-a-placeholder"),
        format!("{good},anthropic={OTHER}"),
        format!("{good},{good}"),
        format!("{good},openai={OTHER}"),
        "anthropic=not-a-placeholder".to_owned(),
        format!("anthropic={PLACEHOLDER},"),
    ] {
        assert!(
            broker_placeholders(&header(&[&value]), true).is_none(),
            "{value}"
        );
    }
}

/// What the relay logs while a test runs on this thread.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// One fresh epoch whose broker answers with `values`: the daemon's Open,
/// or `None` when the relay left the epoch unadmitted.
async fn open_with(values: Vec<String>, intercepted: bool) -> Option<v1::CredentialBridgeOpen> {
    let mut fixture = Fixture::new().await;
    fixture.config.interception = intercepted;
    *fixture.broker_placeholders.lock().unwrap() = values;
    let (cancellation, admitted, task) = fixture.start_epoch(None, EPOCH_MAX_LIFETIME);
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall { accept, output, .. } = bounded(fixture.broker_calls.recv()).await.unwrap();
    accept.send(Ok(())).unwrap();
    let open = match bounded(daemon.input.message()).await {
        Ok(Some(v1::CredentialBridgeHostMessage {
            payload: Some(v1::credential_bridge_host_message::Payload::Open(open)),
        })) => Some(open),
        _ => None,
    };
    assert_eq!(open.is_some(), bounded(admitted).await.is_ok());
    // An unadmitted epoch ends by itself, after logging why; only an
    // admitted one is cancelled here.
    if open.is_some() {
        cancellation.cancel();
    }
    let _ = bounded(task).await;
    drop(output);
    fixture.stop().await;
    open
}

#[tokio::test]
async fn the_brokers_placeholders_reach_the_open_whole_and_never_a_log() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _logging = tracing::subscriber::set_default(subscriber);
    // A callsite another test's thread registers first can be cached as
    // never enabled, whatever this thread's subscriber says. One refused
    // epoch registers the relay's callsites, if nothing had yet; rebuilding
    // then makes them follow this subscriber for the rest of the test.
    open_with(Vec::new(), true).await;
    tracing::callsite::rebuild_interest_cache();

    let open = open_with(vec![format!("anthropic={PLACEHOLDER}")], true)
        .await
        .expect("a whole set is admitted");
    assert_eq!(open.placeholders.len(), 1);
    assert_eq!(open.placeholders[0].capability_slot, "anthropic");
    assert_eq!(open.placeholders[0].placeholder, PLACEHOLDER);
    let open = open_with(
        vec![format!("github={OTHER},anthropic={PLACEHOLDER}")],
        true,
    )
    .await
    .expect("a whole set with GitHub's slot is admitted");
    let slots: Vec<_> = open
        .placeholders
        .iter()
        .map(|entry| (entry.capability_slot.as_str(), entry.placeholder.as_str()))
        .collect();
    assert_eq!(slots, [("anthropic", PLACEHOLDER), ("github", OTHER)]);

    // An intercepted epoch with nothing to project, and one that isn't
    // intercepted, carry none.
    assert!(
        open_with(vec![String::new()], true)
            .await
            .unwrap()
            .placeholders
            .is_empty()
    );
    assert!(
        open_with(Vec::new(), false)
            .await
            .unwrap()
            .placeholders
            .is_empty()
    );

    // Anything else leaves the epoch unadmitted, named by one closed reason.
    for (values, intercepted) in [
        (Vec::new(), true),
        (vec![format!("anthropic={PLACEHOLDER}")], false),
        (vec![format!("anthropic={PLACEHOLDER}"); 2], true),
        (
            vec![format!("anthropic={PLACEHOLDER},anthropic={OTHER}")],
            true,
        ),
        (vec![format!("openai={PLACEHOLDER}")], true),
        (vec!["anthropic=not-a-placeholder".to_owned()], true),
    ] {
        assert!(
            open_with(values.clone(), intercepted).await.is_none(),
            "{values:?} intercepted={intercepted}"
        );
    }
    let logged = captured.text();
    assert!(logged.contains("broker_placeholders_invalid"), "{logged}");
    for value in [PLACEHOLDER, OTHER] {
        assert!(
            !logged.contains(value),
            "a placeholder was logged: {logged}"
        );
    }
}
