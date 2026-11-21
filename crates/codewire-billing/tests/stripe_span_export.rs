//! The payment SDK opens a span that holds each webhook's whole payload,
//! customer details included (#3263). Trace export never builds it: only
//! Codewire's and the Kubernetes client's spans are exported
//! (docs/CONFIGURATION.md, "Tracing").
//!
//! The test has this file to itself. Whether a span is opened at all is
//! cached per call site across the process, so a test beside it that reached
//! the SDK first, under no subscriber, could leave the SDK's span unopened
//! here.

use std::sync::{Arc, Mutex};

use stripe_webhook::Webhook;

// The event shape async-stripe's own tests construct.
const EVENT: &str = r#"{"id":"evt_forged","object":"event","api_version":"2017-05-25","created":1492774577,"livemode":false,"pending_webhooks":1,"data":{"object":{"object":"bank_account","country":"us","currency":"usd","id":"ba_test","last4":"6789","status":"verified"}},"type":"account.external_account.created"}"#;

/// A span as it was opened: its target, whether it holds a field named
/// `payload`, and whether trace export would build it.
type Opened = (String, bool, bool);

struct Spans(Arc<Mutex<Vec<Opened>>>);

impl tracing::Subscriber for Spans {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_span()
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let metadata = attributes.metadata();
        let mut spans = self.0.lock().expect("the span list");
        spans.push((
            metadata.target().to_owned(),
            metadata.fields().field("payload").is_some(),
            codewire_server_core::obs::exports_span(metadata),
        ));
        tracing::span::Id::from_u64(spans.len() as u64)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn the_stripe_sdk_span_that_holds_a_payload_is_never_exported() {
    let spans = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Spans(spans.clone()), || {
        let _billing =
            tracing::debug_span!(target: "codewire_billing::webhook", "delivery").entered();
        let header = Webhook::generate_test_header(EVENT, "whsec_test", None);
        Webhook::construct_event(EVENT, &header, "whsec_test").expect("a signed event parses");
    });
    let spans = spans.lock().expect("the span list");

    // The control: a span of billing's own is exported.
    assert!(
        spans
            .iter()
            .any(|(target, _, exported)| target.starts_with("codewire_billing") && *exported),
        "{spans:?}"
    );
    // The SDK still opens its payload span, and export refuses it. If the
    // first assertion fails the SDK changed: read what it opens now.
    let sdk: Vec<_> = spans
        .iter()
        .filter(|(target, _, _)| !target.starts_with("codewire"))
        .collect();
    assert!(sdk.iter().any(|(_, payload, _)| *payload), "{spans:?}");
    assert!(sdk.iter().all(|(_, _, exported)| !exported), "{spans:?}");
}
