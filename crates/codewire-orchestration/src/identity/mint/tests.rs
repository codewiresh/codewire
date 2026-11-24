//! The mint decision against a fake store and either a recording signer or
//! the real transit client in front of a fake OpenBao.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::cache::{CacheKey, TokenCache};
use super::store::{MintStoreUnavailable, MintSubject, Registration};
use super::*;
use crate::identity::keys::tests::{at, key_read, key_set};
use crate::identity::transit::TransitStage;
use crate::identity::transit::tests::{client, fake_openbao_with, signature};

pub(crate) const ORG: &str = "0e3c5b7a-1f2d-4c3b-9a8e-7d6c5b4a3f2e";
const SANDBOX: &str = "7b1f2e3d-4c5b-4a69-8877-665544332211";
pub(crate) const AUDIENCE: &str = "https://k8s.walk.example";
const NOW: &str = "2026-11-21T12:00:00Z";

fn running_subject() -> MintSubject {
    MintSubject {
        org_id: ORG.into(),
        org: OrgStanding::Active,
        running: true,
        access_suspended: false,
        stopped: false,
        created_by: "user_2b8f".into(),
        name: Some("app".into()),
        groups: vec!["data-readers".into()],
        groups_version: 3,
    }
}

fn registration() -> Registration {
    Registration {
        visible_groups: None,
        lifetime_seconds: 600,
        claim_created_by: false,
        claim_environment_name: false,
        version: 1,
    }
}

pub(crate) struct FakeStore {
    environment_id: String,
    pub(crate) subject: Mutex<Option<MintSubject>>,
    registrations: Mutex<HashMap<String, Registration>>,
    subject_reads: AtomicUsize,
    records: Mutex<Vec<MintRecord>>,
    fail_record: AtomicBool,
}

impl FakeStore {
    fn new() -> Arc<Self> {
        Self::for_environment(SANDBOX)
    }

    pub(crate) fn for_environment(environment_id: &str) -> Arc<Self> {
        Arc::new(Self {
            environment_id: environment_id.to_owned(),
            subject: Mutex::new(Some(running_subject())),
            registrations: Mutex::new(HashMap::from([(AUDIENCE.to_owned(), registration())])),
            subject_reads: AtomicUsize::new(0),
            records: Mutex::new(Vec::new()),
            fail_record: AtomicBool::new(false),
        })
    }

    pub(crate) fn change(&self, change: impl FnOnce(&mut MintSubject)) {
        change(self.subject.lock().unwrap().as_mut().unwrap());
    }

    fn register(&self, change: impl FnOnce(&mut Registration)) {
        change(
            self.registrations
                .lock()
                .unwrap()
                .get_mut(AUDIENCE)
                .unwrap(),
        );
    }

    pub(crate) fn records(&self) -> Vec<MintRecord> {
        self.records.lock().unwrap().clone()
    }
}

#[async_trait]
impl MintStore for FakeStore {
    async fn subject(
        &self,
        environment_id: &str,
    ) -> Result<Option<MintSubject>, MintStoreUnavailable> {
        assert_eq!(environment_id, self.environment_id);
        self.subject_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.subject.lock().unwrap().clone())
    }

    async fn registration(
        &self,
        org_id: &str,
        audience: &str,
    ) -> Result<Option<Registration>, MintStoreUnavailable> {
        assert_eq!(org_id, ORG);
        Ok(self.registrations.lock().unwrap().get(audience).cloned())
    }

    async fn record(&self, record: &MintRecord) -> Result<(), MintStoreUnavailable> {
        if self.fail_record.load(Ordering::SeqCst) {
            return Err(MintStoreUnavailable);
        }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// Signs with a fixed signature and counts every OpenBao call.
pub(crate) struct FakeSigner {
    read: Mutex<Value>,
    pub(crate) reads: AtomicUsize,
    signs: Mutex<Vec<u32>>,
    fail: AtomicBool,
}

impl FakeSigner {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            read: Mutex::new(key_read(&[(4, "2026-11-01T00:00:00Z")], 4, 4)),
            reads: AtomicUsize::new(0),
            signs: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
        })
    }

    pub(crate) fn signs(&self) -> usize {
        self.signs.lock().unwrap().len()
    }
}

#[async_trait]
impl IdentitySigner for FakeSigner {
    async fn read_key(&self) -> Result<KeySet, TransitError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(key_set(self.read.lock().unwrap().clone())?)
    }

    async fn sign(&self, key: SigningKey, _input: &[u8]) -> Result<JwsSignature, TransitError> {
        self.signs.lock().unwrap().push(key.version());
        if self.fail.load(Ordering::SeqCst) {
            return Err(TransitError::Unavailable(TransitStage::Sign));
        }
        Ok(signature())
    }
}

pub(crate) fn minting(
    signer: Arc<dyn IdentitySigner>,
    store: Arc<FakeStore>,
    switch: MintingSwitch,
) -> IdentityMinting {
    IdentityMinting::new(
        IssuerBase::parse("https://identity.codewire.example").unwrap(),
        TrustDomain::from_public_origin("https://codewire.example").unwrap(),
        signer,
        store,
        switch,
    )
}

pub(crate) fn claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn header(token: &str) -> Value {
    let header = token.split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()
}

fn later(seconds: i64) -> DateTime<Utc> {
    at(NOW) + chrono::Duration::seconds(seconds)
}

#[tokio::test]
async fn a_mint_signs_logs_one_row_without_the_token_and_returns_it() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    let issued = minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.unwrap();

    let claims = claims(&issued.token);
    assert_eq!(claims["aud"], json!(AUDIENCE));
    assert_eq!(
        claims["iss"],
        json!(format!("https://identity.codewire.example/orgs/{ORG}"))
    );
    assert_eq!(
        claims["groups"],
        json!([format!("{ORG}:all"), format!("{ORG}:data-readers")])
    );
    assert_eq!(issued.expires_at, at(NOW).timestamp() + 600);
    assert_eq!(header(&issued.token)["kid"], json!("sandbox-identity-4"));

    let records = store.records();
    assert_eq!(
        records,
        [MintRecord {
            jti: claims["jti"].as_str().unwrap().to_owned(),
            environment_id: SANDBOX.into(),
            org_id: ORG.into(),
            audience: AUDIENCE.into(),
            kid: "sandbox-identity-4".into(),
            groups_version: 3,
            audience_version: 1,
            minted_at: at(NOW),
        }]
    );
    assert!(!format!("{records:?}").contains(issued.token.as_str()));
    assert_eq!(*signer.signs.lock().unwrap(), [4]);
}

#[tokio::test]
async fn a_repeat_within_half_the_lifetime_costs_no_signature_and_no_row() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    let first = minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.unwrap();
    let again = minting.mint(SANDBOX, AUDIENCE, later(299)).await.unwrap();
    assert_eq!(again.token, first.token);
    assert_eq!(again.expires_at, first.expires_at);
    assert_eq!((signer.signs(), store.records().len()), (1, 1));
    assert_eq!(signer.reads.load(Ordering::SeqCst), 1, "a hit reads no key");

    let renewed = minting.mint(SANDBOX, AUDIENCE, later(300)).await.unwrap();
    assert_ne!(renewed.token, first.token);
    assert_eq!((signer.signs(), store.records().len()), (2, 2));
}

#[tokio::test]
async fn a_change_to_the_groups_or_the_registration_misses_the_cache() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.unwrap();

    store.change(|sandbox| {
        sandbox.groups.clear();
        sandbox.groups_version = 4;
    });
    let issued = minting.mint(SANDBOX, AUDIENCE, later(1)).await.unwrap();
    assert_eq!(
        claims(&issued.token)["groups"],
        json!([format!("{ORG}:all")])
    );
    assert_eq!(signer.signs(), 2);

    store.register(|registration| {
        registration.claim_created_by = true;
        registration.version = 2;
    });
    let issued = minting.mint(SANDBOX, AUDIENCE, later(2)).await.unwrap();
    assert_eq!(
        claims(&issued.token)["codewire.sh"]["created_by"],
        json!("user_2b8f")
    );
    assert_eq!(signer.signs(), 3);

    // A registration removed and added again may repeat its version; its
    // different token still misses.
    store.register(|registration| registration.lifetime_seconds = 60);
    let issued = minting.mint(SANDBOX, AUDIENCE, later(3)).await.unwrap();
    assert_eq!(issued.expires_at, later(3).timestamp() + 60);
    assert_eq!(signer.signs(), 4);
    assert_eq!(store.records().len(), 4);
}

#[tokio::test]
async fn each_refusal_is_its_spec_name_and_signs_nothing() {
    type Change = fn(&mut MintSubject);
    let cases: [(Change, MintRefusal); 5] = [
        (
            |s| s.org = OrgStanding::Suspended,
            MintRefusal::IdentityStopped,
        ),
        (
            |s| s.org = OrgStanding::Deleting,
            MintRefusal::IdentityStopped,
        ),
        (|s| s.running = false, MintRefusal::NotRunning),
        (|s| s.access_suspended = true, MintRefusal::IdentityStopped),
        (|s| s.stopped = true, MintRefusal::IdentityStopped),
    ];
    for (change, refusal) in cases {
        let (signer, store) = (FakeSigner::new(), FakeStore::new());
        store.change(change);
        let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
        assert_eq!(
            minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
            Some(refusal)
        );
        assert_eq!((signer.signs(), store.records().len()), (0, 0));
    }

    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    assert_eq!(
        minting
            .mint(SANDBOX, "https://unregistered.example", at(NOW))
            .await
            .err(),
        Some(MintRefusal::InvalidTarget)
    );
    *store.subject.lock().unwrap() = None;
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
        Some(MintRefusal::NotRunning)
    );
    assert_eq!(signer.signs(), 0);

    for (refusal, code, name) in [
        (
            MintRefusal::InvalidTarget,
            connectrpc::ErrorCode::InvalidArgument,
            "invalid_target",
        ),
        (
            MintRefusal::NotRunning,
            connectrpc::ErrorCode::FailedPrecondition,
            "not_running",
        ),
        (
            MintRefusal::IdentityStopped,
            connectrpc::ErrorCode::PermissionDenied,
            "identity_stopped",
        ),
        (
            MintRefusal::ResourceExhausted,
            connectrpc::ErrorCode::ResourceExhausted,
            "resource_exhausted",
        ),
        (
            MintRefusal::IdentityUnavailable,
            connectrpc::ErrorCode::Unavailable,
            "identity_unavailable",
        ),
        (
            MintRefusal::KeyNotYetPublished,
            connectrpc::ErrorCode::Unavailable,
            "key_not_yet_published",
        ),
    ] {
        let error = refusal.connect();
        assert_eq!((error.code, error.message.as_deref()), (code, Some(name)));
    }
}

#[tokio::test]
async fn a_stopped_sandbox_gets_no_cached_token() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.unwrap();

    store.change(|sandbox| sandbox.stopped = true);
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, later(1)).await.err(),
        Some(MintRefusal::IdentityStopped)
    );
    store.change(|sandbox| {
        sandbox.stopped = false;
        sandbox.running = false;
    });
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, later(2)).await.err(),
        Some(MintRefusal::NotRunning)
    );
    store.change(|sandbox| {
        sandbox.running = true;
        sandbox.org = OrgStanding::Suspended;
    });
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, later(3)).await.err(),
        Some(MintRefusal::IdentityStopped)
    );
    // Resumed, the cached token is served again.
    store.change(|sandbox| sandbox.org = OrgStanding::Active);
    minting.mint(SANDBOX, AUDIENCE, later(4)).await.unwrap();
    assert_eq!(signer.signs(), 1);
}

#[tokio::test]
async fn the_operators_switch_refuses_before_reading_anything() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::Off);
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
        Some(MintRefusal::IdentityUnavailable)
    );
    assert_eq!(store.subject_reads.load(Ordering::SeqCst), 0);
    assert_eq!(signer.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn twenty_signing_failures_in_a_row_open_the_breaker() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    signer.fail.store(true, Ordering::SeqCst);
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    for _ in 0..TRIP_AFTER_FAILURES {
        assert_eq!(
            minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
            Some(MintRefusal::IdentityUnavailable)
        );
    }
    signer.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
        Some(MintRefusal::IdentityUnavailable)
    );
    assert_eq!(signer.signs(), 20, "the open breaker asks OpenBao nothing");
    assert!(store.records().is_empty());
}

#[tokio::test]
async fn a_mint_whose_row_cant_be_written_is_never_handed_out_or_cached() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    store.fail_record.store(true, Ordering::SeqCst);
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
        Some(MintRefusal::IdentityUnavailable)
    );
    store.fail_record.store(false, Ordering::SeqCst);
    minting.mint(SANDBOX, AUDIENCE, later(1)).await.unwrap();
    assert_eq!((signer.signs(), store.records().len()), (2, 1));
}

#[tokio::test]
async fn the_organizations_limit_counts_cache_hits_and_comes_before_the_cache() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On)
        .with_limits(MintLimits::with((1.0, 10.0), (0.0, 2.0), (1.0, 10.0), 16));
    minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.unwrap();
    minting.mint(SANDBOX, AUDIENCE, later(1)).await.unwrap();
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, later(2)).await.err(),
        Some(MintRefusal::ResourceExhausted)
    );
    assert_eq!(signer.signs(), 1);
}

#[tokio::test]
async fn a_drifted_key_signs_nothing() {
    let (signer, store) = (FakeSigner::new(), FakeStore::new());
    signer.read.lock().unwrap()["allow_plaintext_backup"] = json!(true);
    let minting = minting(signer.clone(), store.clone(), MintingSwitch::On);
    assert_eq!(
        minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
        Some(MintRefusal::IdentityUnavailable)
    );
    assert_eq!(signer.signs(), 0);
}

/// The sign request each mint sent to the fake OpenBao, as JSON.
fn sign_bodies(recorded: &crate::identity::transit::tests::Recorded) -> Vec<Value> {
    recorded
        .lock()
        .unwrap()
        .iter()
        .filter(|(call, ..)| call == "POST /v1/codewire-identity-dev/sign/sandbox-identity")
        .map(|(.., body)| serde_json::from_str(body).unwrap())
        .collect()
}

#[tokio::test]
async fn a_new_key_signs_nothing_until_it_is_24_hours_old_and_never_falls_back() {
    let created = "2026-11-21T12:00:00Z";
    let (address, recorded) =
        fake_openbao_with("cluster-dev", key_read(&[(1, created)], 1, 0)).await;
    let store = FakeStore::new();
    let minting = minting(Arc::new(client(address)), store.clone(), MintingSwitch::On);

    for offset in [0, 23 * 3_600 + 59 * 60] {
        assert_eq!(
            minting.mint(SANDBOX, AUDIENCE, later(offset)).await.err(),
            Some(MintRefusal::KeyNotYetPublished),
            "{offset} s after the key was created"
        );
    }
    let issued = minting
        .mint(SANDBOX, AUDIENCE, later(24 * 3_600))
        .await
        .unwrap();
    assert_eq!(header(&issued.token)["kid"], json!("sandbox-identity-1"));
    assert_eq!(
        sign_bodies(&recorded),
        [json!({
            "input": base64::engine::general_purpose::STANDARD
                .encode(issued.token.rsplit_once('.').unwrap().0),
            "key_version": 1,
            "marshaling_algorithm": "jws",
        })]
    );
    assert_eq!(store.records().len(), 1);
}

#[tokio::test]
async fn a_version_created_just_now_never_signs_while_an_older_one_can() {
    let now = at(NOW);
    let older = (now - chrono::Duration::hours(25)).to_rfc3339();
    let (address, recorded) = fake_openbao_with(
        "cluster-dev",
        key_read(&[(1, older.as_str()), (2, NOW)], 1, 1),
    )
    .await;
    let minting = minting(
        Arc::new(client(address)),
        FakeStore::new(),
        MintingSwitch::On,
    );
    let issued = minting.mint(SANDBOX, AUDIENCE, now).await.unwrap();
    assert_eq!(header(&issued.token)["kid"], json!("sandbox-identity-1"));
    let bodies = sign_bodies(&recorded);
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["key_version"], json!(1));
}

#[tokio::test]
async fn a_key_not_yet_published_is_not_a_signing_failure() {
    let signer = FakeSigner::new();
    *signer.read.lock().unwrap() = key_read(&[(1, NOW)], 1, 0);
    let minting = minting(signer.clone(), FakeStore::new(), MintingSwitch::On);
    for _ in 0..=TRIP_AFTER_FAILURES {
        assert_eq!(
            minting.mint(SANDBOX, AUDIENCE, at(NOW)).await.err(),
            Some(MintRefusal::KeyNotYetPublished)
        );
    }
    assert!(minting.breaker.allows(std::time::Instant::now()));
}

#[test]
fn the_cache_holds_a_bounded_number_of_tokens() {
    let issuer = IssuerBase::parse("https://identity.codewire.example").unwrap();
    let trust = TrustDomain::from_public_origin("https://codewire.example").unwrap();
    let subject = TokenSubject::new(&SubjectFacts {
        issuer_base: &issuer,
        trust_domain: &trust,
        org_id: ORG,
        environment_id: SANDBOX,
        created_by: "user_2b8f",
        environment_name: None,
        groups: &[],
        audience: AUDIENCE,
        visible_groups: None,
        lifetime_seconds: 600,
        claim_created_by: false,
        claim_environment_name: false,
    });
    let cache = TokenCache::with_capacity(2);
    let key = |audience: &str| CacheKey {
        environment_id: SANDBOX.into(),
        audience: audience.into(),
        groups_version: 0,
        audience_version: 1,
    };
    for (index, audience) in [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ]
    .into_iter()
    .enumerate()
    {
        let issued = 1_000 + i64::try_from(index).unwrap();
        cache.insert(
            key(audience),
            subject.clone(),
            Zeroizing::new(audience.into()),
            issued,
            issued + 600,
        );
    }
    assert_eq!(cache.len(), 2);
    // The one that went stale soonest went first.
    assert!(
        cache
            .get(&key("https://a.example"), &subject, 1_002)
            .is_none()
    );
    assert!(
        cache
            .get(&key("https://c.example"), &subject, 1_002)
            .is_some()
    );
    assert!(
        cache
            .get(&key("https://c.example"), &subject, 1_302)
            .is_none(),
        "half its lifetime"
    );
}
