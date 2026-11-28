//! Folding, its bounds, the host check and what a request records.

use std::time::Duration;

use super::*;

const POD: Uuid = Uuid::from_u128(0x6189_0000_0000_4000_8000_0000_0000_0001);
const OTHER_POD: Uuid = Uuid::from_u128(0x6189_0000_0000_4000_8000_0000_0000_0002);
const KEY: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000001";
const OTHER_KEY: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000002";

/// A time `seconds` into an hour that starts on an hour boundary.
fn at(hour: u64, seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 / 3600 * 3600 + hour * 3600 + seconds)
}

fn ms(time: SystemTime) -> u64 {
    u64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn folded(
    credential: &str,
    host: Option<&str>,
    first: SystemTime,
    last: SystemTime,
    count: u64,
) -> FoldedUse {
    FoldedUse {
        credential: credential.into(),
        provider: "openai".into(),
        host: host.map(Into::into),
        first_unix_ms: ms(first),
        last_unix_ms: ms(last),
        count,
    }
}

#[test]
fn a_use_folds_per_binding_credential_host_and_hour() {
    let uses = CredentialUses::new();
    uses.record(POD, KEY, "openai", "api.openai.com", at(0, 10));
    uses.record(POD, KEY, "openai", "api.openai.com", at(0, 50));
    uses.record(POD, KEY, "openai", "api.openai.com", at(0, 30));
    uses.record(POD, OTHER_KEY, "openai", "api.openai.com", at(0, 20));
    uses.record(POD, KEY, "openai", "chatgpt.com", at(0, 20));
    // The next hour is another fold: a fold never spans two hours.
    uses.record(POD, KEY, "openai", "api.openai.com", at(1, 5));
    uses.record(OTHER_POD, KEY, "openai", "api.openai.com", at(0, 40));

    let taken = uses.take();
    assert_eq!(
        taken,
        vec![
            BindingUses {
                binding: POD,
                uses: vec![
                    folded(KEY, Some("api.openai.com"), at(0, 10), at(0, 50), 3),
                    folded(KEY, Some("api.openai.com"), at(1, 5), at(1, 5), 1),
                    folded(KEY, Some("chatgpt.com"), at(0, 20), at(0, 20), 1),
                    folded(OTHER_KEY, Some("api.openai.com"), at(0, 20), at(0, 20), 1),
                ],
            },
            BindingUses {
                binding: OTHER_POD,
                uses: vec![folded(KEY, Some("api.openai.com"), at(0, 40), at(0, 40), 1)],
            },
        ]
    );
    assert_eq!(taken[0].count(), 6);
    // A take starts again from none: what was taken is never sent twice.
    assert!(uses.take().is_empty());
    assert_eq!(uses.dropped(), 0);
}

#[test]
fn a_full_binding_or_process_drops_and_counts_without_waiting() {
    let uses = CredentialUses::new();
    // Nobody takes: recording past the bounds still returns at once.
    for host in 0..MAX_BINDING_FOLDS + 3 {
        uses.record(
            POD,
            KEY,
            "openai",
            &format!("h{host}.example.com"),
            at(0, 1),
        );
    }
    assert_eq!(uses.dropped(), 3);
    // A subject already held still counts; only a new one is refused.
    uses.record(POD, KEY, "openai", "h0.example.com", at(0, 2));
    assert_eq!(uses.dropped(), 3);

    let bindings = (MAX_PENDING_FOLDS / MAX_BINDING_FOLDS) as u128;
    for pod in 1..bindings + 1 {
        for host in 0..MAX_BINDING_FOLDS {
            uses.record(
                Uuid::from_u128(pod),
                KEY,
                "openai",
                &format!("h{host}.example.com"),
                at(0, 1),
            );
        }
    }
    // The process holds MAX_PENDING_FOLDS; the last binding's all dropped.
    assert_eq!(uses.dropped(), 3 + MAX_BINDING_FOLDS as u64);
    let taken = uses.take();
    assert_eq!(
        taken
            .iter()
            .map(|binding| binding.uses.len())
            .sum::<usize>(),
        MAX_PENDING_FOLDS
    );
    assert_eq!(
        taken
            .iter()
            .find(|binding| binding.binding == POD)
            .unwrap()
            .uses[0]
            .count,
        2
    );
    // After a take there is room again.
    uses.record(POD, KEY, "openai", "later.example.com", at(0, 3));
    assert_eq!(uses.take()[0].uses.len(), 1);
}

#[test]
fn a_host_is_checked_and_a_failing_name_is_withheld_with_its_count() {
    let uses = CredentialUses::new();
    uses.record(POD, KEY, "openai", "API.OpenAI.com.", at(0, 1));
    uses.record(POD, KEY, "openai", "evil\u{1b}[2J.example.com", at(0, 2));
    uses.record(POD, KEY, "openai", &"a".repeat(254), at(0, 3));
    let taken = uses.take();
    assert_eq!(
        taken[0].uses,
        vec![
            folded(KEY, None, at(0, 2), at(0, 3), 2),
            folded(KEY, Some("api.openai.com"), at(0, 1), at(0, 1), 1),
        ]
    );
}

/// Answers nothing; only what the wrapper records matters here.
#[cfg(feature = "platform")]
#[derive(Clone, Default)]
struct Refusing;

#[cfg(feature = "platform")]
#[async_trait]
impl BrokerUpstreamTransport for Refusing {
    async fn execute(
        &self,
        _request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        Err(BrokerUpstreamError::DestinationDenied)
    }
}

#[cfg(feature = "platform")]
fn request(url: &str) -> BrokerUpstreamRequest {
    BrokerUpstreamRequest::new(
        http::Method::POST,
        Url::parse(url).unwrap(),
        http::HeaderMap::new(),
        Vec::new(),
    )
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn a_send_after_a_swap_is_one_use_at_the_host_it_went_to() {
    let uses = CredentialUses::new();
    let epoch = EpochUses::new(uses.clone(), POD);
    let transport = RecordingUses(Refusing);
    scoped(async {
        // Nothing swapped in yet: a send is no use.
        let _ = transport
            .execute(request("https://api.openai.com/v1/responses"))
            .await;
        swapped(&epoch, KEY, "openai");
        let _ = transport
            .execute(request("https://api.openai.com/v1/responses?x=1"))
            .await;
        let _ = transport
            .upgrade(request("https://api.openai.com/v1/realtime"))
            .await;
        // An untouched forward carries nothing of the broker's.
        let _ = transport
            .forward_github(request("https://github.com/o/r"))
            .await;
    })
    .await;
    // Another request starts with nothing swapped in.
    scoped(async {
        let _ = transport
            .execute(request("https://api.openai.com/v1/responses"))
            .await;
    })
    .await;
    // Outside a served request nothing is recorded.
    swapped(&epoch, KEY, "openai");
    let _ = transport
        .execute(request("https://api.openai.com/v1/responses"))
        .await;

    let taken = uses.take();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].binding, POD);
    let [only] = taken[0].uses.as_slice() else {
        panic!("one fold: {:?}", taken[0].uses);
    };
    assert_eq!(
        (
            only.credential.as_str(),
            only.provider.as_str(),
            only.host.as_deref(),
            only.count
        ),
        (KEY, "openai", Some("api.openai.com"), 2)
    );
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn send_bound_secret_forwards_to_inner_transport_without_recording_provider_use() {
    #[derive(Clone, Default)]
    struct BoundSecretEcho(Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl BrokerUpstreamTransport for BoundSecretEcho {
        async fn execute(
            &self,
            _request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            Err(BrokerUpstreamError::DestinationDenied)
        }

        async fn send_bound_secret(
            &self,
            _request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(BrokerUpstreamResponse::new(
                http::StatusCode::OK,
                http::HeaderMap::new(),
                Box::pin(futures::stream::empty()),
            ))
        }
    }

    let uses = CredentialUses::new();
    let epoch = EpochUses::new(uses.clone(), POD);
    let inner = BoundSecretEcho::default();
    let transport = RecordingUses(inner.clone());
    let response = scoped(async {
        swapped(&epoch, KEY, "openai");
        transport
            .send_bound_secret(request("https://api.example.com/v1/items"))
            .await
    })
    .await
    .expect("RecordingUses must forward send_bound_secret to the inner transport");
    assert_eq!(response.into_parts().0, http::StatusCode::OK);
    assert_eq!(inner.0.load(Ordering::SeqCst), 1);
    assert!(uses.take().is_empty());
}
