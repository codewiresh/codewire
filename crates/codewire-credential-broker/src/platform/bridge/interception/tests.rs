use std::sync::Mutex;

use tonic::Code;

use super::*;

const POD: &str = "2f6b1c9e-5d4a-4c3b-9a8e-1f2d3c4b5a69";
const OTHER_POD: &str = "7a1e9c3b-2d4f-4b6a-8c5e-9f0a1b2c3d4e";
/// Stands in for a front door's public key; the fake signer never parses it.
const KEY: &[u8] = b"synthetic-leaf-public-key-canary";

/// One leaf the service asked for.
struct Signed {
    pod_uid: String,
    environment_id: String,
    hosts: Vec<String>,
    lifetime: Duration,
}

/// Records what the service asked of the CAs, and answers as told.
#[derive(Default)]
struct Cas {
    ensured: Mutex<Vec<(String, String)>>,
    signed: Mutex<Vec<Signed>>,
    refuse: Option<fn() -> InterceptionCaError>,
}

#[async_trait]
impl InterceptionCas for Cas {
    async fn ensure(&self, pod_uid: &str, pod_name: &str) -> Result<Vec<u8>, InterceptionCaError> {
        self.ensured
            .lock()
            .unwrap()
            .push((pod_uid.to_owned(), pod_name.to_owned()));
        match self.refuse {
            Some(refusal) => Err(refusal()),
            None => Ok(b"ca-certificate".to_vec()),
        }
    }

    async fn sign(&self, request: LeafRequest<'_>) -> Result<SignedLeaf, InterceptionCaError> {
        self.signed.lock().unwrap().push(Signed {
            pod_uid: request.pod_uid.to_owned(),
            environment_id: request.environment_id.to_owned(),
            hosts: request
                .hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
            lifetime: request.lifetime,
        });
        if let Some(refusal) = self.refuse {
            return Err(refusal());
        }
        Ok(SignedLeaf {
            certificate_der: b"leaf-certificate".to_vec(),
            not_after_unix: unix_now().unwrap() + request.lifetime.as_secs(),
        })
    }
}

fn service(cas: Cas) -> (Arc<Cas>, Interception) {
    let cas = Arc::new(cas);
    let interception = Interception::new(cas.clone());
    (cas, interception)
}

fn ensure_request(pod_uid: &str) -> EnsureInterceptionCaRequest {
    EnsureInterceptionCaRequest {
        pod_uid: pod_uid.to_owned(),
        pod_name: "sandbox-0".to_owned(),
    }
}

fn leaves_for<'a>(
    hosts: &'a BTreeSet<&'static str>,
    public_key: &'a [u8],
    expires_in: u64,
) -> LeavesFor<'a> {
    LeavesFor {
        pod_uid: Uuid::parse_str(POD).unwrap(),
        environment_id: Uuid::from_u128(29),
        generation: 7,
        epoch_digest: [3; 32],
        epoch_expires_at_unix: unix_now().unwrap() + expires_in,
        public_key,
        hosts,
    }
}

fn anthropic() -> BTreeSet<&'static str> {
    BTreeSet::from(["api.anthropic.com"])
}

#[tokio::test(start_paused = true)]
async fn a_limiter_admits_ten_calls_a_minute_per_key_and_then_recovers() {
    let limiter = Limiter::new(CALLS_PER_WINDOW);
    let now = Instant::now();
    for _ in 0..CALLS_PER_WINDOW {
        assert!(limiter.admit(&1, now));
    }
    assert!(!limiter.admit(&1, now), "the eleventh call in a minute");
    assert!(limiter.admit(&2, now), "another key has its own budget");
    assert!(limiter.admit(&1, now + WINDOW), "a minute later");
}

#[tokio::test]
async fn a_limiter_full_of_live_keys_refuses_a_new_one() {
    let limiter = Limiter::new(CALLS_PER_WINDOW);
    let now = Instant::now();
    for key in 0..MAX_KEYS {
        assert!(limiter.admit(&key, now));
    }
    assert!(!limiter.admit(&MAX_KEYS, now));
    assert!(limiter.admit(&0, now), "a known key keeps its budget");
}

#[tokio::test]
async fn ensuring_a_ca_returns_only_its_certificate_for_the_named_pod() {
    let (cas, interception) = service(Cas::default());
    let response = interception
        .ensure(Uuid::from_u128(1), &ensure_request(POD))
        .await
        .unwrap();
    assert_eq!(response.ca_certificate_der, b"ca-certificate");
    assert_eq!(
        *cas.ensured.lock().unwrap(),
        [(POD.to_owned(), "sandbox-0".to_owned())]
    );
}

#[tokio::test]
async fn ensuring_is_rate_limited_per_caller_across_pods() {
    let (_, interception) = service(Cas::default());
    let caller = Uuid::from_u128(1);
    // A burst of starts across many Pods fits: only the caller's own bound
    // stops it.
    for index in 0..CALLER_CALLS_PER_WINDOW {
        let pod = Uuid::from_u128(100 + index as u128).to_string();
        interception
            .ensure(caller, &ensure_request(&pod))
            .await
            .unwrap();
    }
    let error = interception
        .ensure(caller, &ensure_request(POD))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn ensuring_is_rate_limited_per_pod_across_callers() {
    let (_, interception) = service(Cas::default());
    for caller in 0..CALLS_PER_WINDOW {
        interception
            .ensure(Uuid::from_u128(caller as u128 + 1), &ensure_request(POD))
            .await
            .unwrap();
    }
    let error = interception
        .ensure(Uuid::from_u128(99), &ensure_request(POD))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn ensuring_refuses_a_malformed_pod_before_reading_it() {
    let (cas, interception) = service(Cas::default());
    for request in [
        ensure_request("not-a-uuid"),
        ensure_request(&POD.to_uppercase()),
        ensure_request("00000000-0000-0000-0000-000000000000"),
        EnsureInterceptionCaRequest {
            pod_uid: POD.to_owned(),
            pod_name: String::new(),
        },
    ] {
        let error = interception
            .ensure(Uuid::from_u128(1), &request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
    }
    assert!(cas.ensured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_pod_the_check_refuses_is_permission_denied() {
    let (_, interception) = service(Cas {
        refuse: Some(|| InterceptionCaError::Denied),
        ..Cas::default()
    });
    let error = interception
        .ensure(Uuid::from_u128(1), &ensure_request(POD))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn leaves_name_exactly_the_sessions_hosts_for_the_authenticated_pod() {
    let (cas, interception) = service(Cas::default());
    let hosts = BTreeSet::from(["api.anthropic.com", "api.openai.com"]);
    let response = interception
        .sign(leaves_for(&hosts, KEY, 2 * 60 * 60))
        .await
        .unwrap();
    assert_eq!(response.leaves.len(), 1);
    assert_eq!(
        response.leaves[0].hosts,
        ["api.anthropic.com", "api.openai.com"]
    );
    let signed = cas.signed.lock().unwrap();
    assert_eq!(signed[0].pod_uid, POD);
    assert_eq!(signed[0].environment_id, Uuid::from_u128(29).to_string());
    assert_eq!(signed[0].hosts, ["api.anthropic.com", "api.openai.com"]);
    assert_eq!(
        signed[0].lifetime, MAX_LEAF_LIFETIME,
        "an hour, inside a longer epoch"
    );
}

#[tokio::test]
async fn a_leaf_never_outlives_its_epoch_and_renews_at_half_life() {
    let (cas, interception) = service(Cas::default());
    let hosts = anthropic();
    let before = unix_now().unwrap();
    let response = interception
        .sign(leaves_for(&hosts, KEY, 600))
        .await
        .unwrap();
    let lifetime = cas.signed.lock().unwrap()[0].lifetime;
    assert!(lifetime <= Duration::from_secs(600), "{lifetime:?}");
    let renew_at = u64::try_from(response.renew_at_unix).unwrap();
    assert!(
        (before + 299..=before + 301).contains(&renew_at),
        "{renew_at}"
    );
}

#[tokio::test]
async fn an_ended_epoch_gets_no_leaf() {
    let (cas, interception) = service(Cas::default());
    let hosts = anthropic();
    let error = interception
        .sign(leaves_for(&hosts, KEY, 0))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(cas.signed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_session_with_nothing_to_intercept_gets_no_leaf_and_signs_nothing() {
    let (cas, interception) = service(Cas::default());
    let response = interception
        .sign(leaves_for(&BTreeSet::new(), KEY, 600))
        .await
        .unwrap();
    assert!(response.leaves.is_empty());
    assert!(response.renew_at_unix > 0);
    assert!(cas.signed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_repeated_call_returns_the_same_set_and_a_new_key_or_epoch_a_new_one() {
    let (cas, interception) = service(Cas::default());
    let hosts = anthropic();
    let first = interception
        .sign(leaves_for(&hosts, KEY, 600))
        .await
        .unwrap();
    let again = interception
        .sign(leaves_for(&hosts, KEY, 600))
        .await
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(cas.signed.lock().unwrap().len(), 1);
    interception
        .sign(leaves_for(&hosts, b"another-key", 600))
        .await
        .unwrap();
    let mut next_epoch = leaves_for(&hosts, KEY, 600);
    next_epoch.epoch_digest = [4; 32];
    interception.sign(next_epoch).await.unwrap();
    assert_eq!(cas.signed.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_grant_that_changes_mid_epoch_misses_the_cache() {
    let (cas, interception) = service(Cas::default());
    let both = BTreeSet::from(["api.anthropic.com", "api.openai.com"]);
    interception
        .sign(leaves_for(&both, KEY, 600))
        .await
        .unwrap();
    // The OpenAI grant is removed: the same Pod, epoch and key get a new
    // set without that host, not the cached one.
    let anthropic = anthropic();
    let response = interception
        .sign(leaves_for(&anthropic, KEY, 600))
        .await
        .unwrap();
    assert_eq!(response.leaves[0].hosts, ["api.anthropic.com"]);
    assert_eq!(cas.signed.lock().unwrap().len(), 2);
    // And with no grant left, no leaf at all.
    let none = interception
        .sign(leaves_for(&BTreeSet::new(), KEY, 600))
        .await
        .unwrap();
    assert!(none.leaves.is_empty());
}

#[tokio::test]
async fn signing_new_leaves_is_rate_limited_per_pod() {
    let (_, interception) = service(Cas::default());
    let hosts = anthropic();
    let keys: Vec<Vec<u8>> = (0..=CALLS_PER_WINDOW)
        .map(|index| format!("key-{index}").into_bytes())
        .collect();
    for key in &keys[..CALLS_PER_WINDOW] {
        interception
            .sign(leaves_for(&hosts, key, 600))
            .await
            .unwrap();
    }
    let error = interception
        .sign(leaves_for(&hosts, &keys[CALLS_PER_WINDOW], 600))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    // Another Pod is not limited by this one.
    let mut other = leaves_for(&hosts, &keys[CALLS_PER_WINDOW], 600);
    other.pod_uid = Uuid::parse_str(OTHER_POD).unwrap();
    interception.sign(other).await.unwrap();
}

#[tokio::test]
async fn a_key_that_is_not_p256_is_an_invalid_argument() {
    let (_, interception) = service(Cas {
        refuse: Some(|| InterceptionCaError::InvalidKey),
        ..Cas::default()
    });
    let hosts = anthropic();
    let error = interception
        .sign(leaves_for(&hosts, KEY, 600))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn the_issuance_record_names_the_key_by_digest_and_never_holds_it() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    crate::timing::tests::keep_interest_peer();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let (_, interception) = service(Cas::default());
    let hosts = anthropic();
    interception
        .sign(leaves_for(&hosts, KEY, 600))
        .await
        .unwrap();
    let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("interception leaves issued"), "{logged}");
    assert!(logged.contains(POD), "{logged}");
    assert!(logged.contains(&hex(&sha256(KEY))), "{logged}");
    assert!(logged.contains("api.anthropic.com"), "{logged}");
    assert!(!logged.contains("canary"), "the key itself: {logged}");
    assert!(
        !logged.contains("leaf-certificate"),
        "the certificate: {logged}"
    );
}
