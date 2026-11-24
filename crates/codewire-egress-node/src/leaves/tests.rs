use std::collections::VecDeque;
use std::sync::Mutex;

use super::*;

const NOW: i64 = 1_800_000_000;

/// A signer that answers from a script, and when it was asked.
#[derive(Default)]
struct Script {
    answers: Mutex<VecDeque<Result<IssuedLeaves, CallError>>>,
    asked: Mutex<Vec<Instant>>,
}

impl Script {
    fn answering(answers: impl IntoIterator<Item = Result<IssuedLeaves, CallError>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into_iter().collect()),
            asked: Mutex::default(),
        })
    }

    fn asked(&self) -> Vec<Instant> {
        self.asked.lock().unwrap().clone()
    }
}

impl LeafSigner for Script {
    async fn sign(
        &self,
        pod_uid: &str,
        _pod_name: &str,
        public_key: &[u8],
    ) -> Result<IssuedLeaves, CallError> {
        assert_eq!((pod_uid, public_key), ("pod", &b"spki"[..]));
        self.asked.lock().unwrap().push(Instant::now());
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(CallError::Unavailable("no answer".into())))
    }
}

fn leaves(name: &str, renew_in: i64) -> Result<IssuedLeaves, CallError> {
    Ok(IssuedLeaves {
        certificates: vec![name.as_bytes().to_vec()],
        renew_at_unix: NOW.saturating_add(renew_in),
    })
}

fn unavailable() -> Result<IssuedLeaves, CallError> {
    Err(CallError::Unavailable("not signed yet".into()))
}

/// A front door: what it serves, and whether it takes the next install.
#[derive(Default)]
struct Door {
    serving: Vec<Vec<u8>>,
    refuse_next: bool,
}

impl Door {
    async fn install(&mut self, leaves: &[Vec<u8>]) -> Result<(), &'static str> {
        if std::mem::take(&mut self.refuse_next) {
            return Err("refused");
        }
        self.serving = leaves.to_vec();
        Ok(())
    }
}

fn renewal(signer: &Arc<Script>) -> Renewal<Script> {
    Renewal::new(
        Arc::clone(signer),
        "pod".into(),
        "sandbox".into(),
        b"spki".to_vec(),
        NOW,
    )
}

/// One ask and its install, as a pair's session runs them.
async fn step(renewal: &mut Renewal<Script>, door: &mut Door) -> Settled<&'static str> {
    let asked = renewal.ask().await;
    renewal
        .settle(asked, async |leaves: &[Vec<u8>]| door.install(leaves).await)
        .await
}

fn after(start: Instant, seconds: u64) -> Instant {
    start + Duration::from_secs(seconds)
}

fn after_ms(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

#[tokio::test(start_paused = true)]
async fn the_first_answer_is_installed_at_once_and_renewed_at_its_renew_at() {
    let start = Instant::now();
    let signer = Script::answering([leaves("first", 600), leaves("second", 1200)]);
    let mut renewal = renewal(&signer);
    let mut door = Door::default();

    assert!(matches!(
        step(&mut renewal, &mut door).await,
        Settled::Installed(1)
    ));
    assert_eq!(door.serving, [b"first".to_vec()]);
    assert_eq!(renewal.due(), after(start, 600));

    assert!(matches!(
        step(&mut renewal, &mut door).await,
        Settled::Installed(1)
    ));
    assert_eq!(door.serving, [b"second".to_vec()]);
    assert_eq!(signer.asked(), [start, after(start, 600)]);
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_ask_is_retried_with_backoff_until_it_installs() {
    let start = Instant::now();
    let signer = Script::answering([
        unavailable(),
        unavailable(),
        unavailable(),
        leaves("first", 900),
    ]);
    let mut renewal = renewal(&signer);
    let mut door = Door::default();
    for _ in 0..3 {
        assert!(matches!(
            step(&mut renewal, &mut door).await,
            Settled::Unanswered(_)
        ));
        // Nothing to serve: the hosts fail closed meanwhile.
        assert!(door.serving.is_empty());
    }
    assert!(matches!(
        step(&mut renewal, &mut door).await,
        Settled::Installed(1)
    ));
    assert_eq!(
        signer.asked(),
        [
            start,
            after_ms(start, 500),
            after_ms(start, 1_500),
            after_ms(start, 3_500)
        ]
    );
    // Installed, it renews at the answer's renew_at, read in whole seconds
    // from an install half a second into one.
    assert_eq!(renewal.due(), after_ms(start, 900_500));
}

#[tokio::test(start_paused = true)]
async fn the_backoff_stops_doubling_at_a_minute() {
    let start = Instant::now();
    let signer = Script::answering([]);
    let mut renewal = renewal(&signer);
    let mut door = Door::default();
    for _ in 0..10 {
        step(&mut renewal, &mut door).await;
    }
    let asked = signer.asked();
    let waits: Vec<u128> = asked
        .windows(2)
        .map(|pair| (pair[1] - pair[0]).as_millis())
        .collect();
    assert_eq!(
        waits,
        [
            500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000
        ]
    );
    // Within the signer's per-Pod limit of 10 calls a minute.
    assert!(asked.iter().filter(|at| **at < after(start, 60)).count() <= 10);
    assert_eq!(asked[0], start);
}

#[tokio::test(start_paused = true)]
async fn a_refused_install_keeps_the_leaves_served_and_is_retried() {
    let start = Instant::now();
    let signer = Script::answering([
        leaves("first", 600),
        leaves("refused", 1200),
        leaves("second", 1800),
    ]);
    let mut renewal = renewal(&signer);
    let mut door = Door::default();
    step(&mut renewal, &mut door).await;
    door.refuse_next = true;
    assert!(matches!(
        step(&mut renewal, &mut door).await,
        Settled::Refused("refused")
    ));
    assert_eq!(door.serving, [b"first".to_vec()]);
    assert_eq!(renewal.due(), after_ms(start, 600_500));
    assert!(matches!(
        step(&mut renewal, &mut door).await,
        Settled::Installed(1)
    ));
    assert_eq!(door.serving, [b"second".to_vec()]);
}

/// A `renew_at` already past, or further ahead than a leaf lives, is never a
/// long sleep: the next ask comes after the backoff.
#[tokio::test(start_paused = true)]
async fn a_renew_at_out_of_range_is_asked_again_soon() {
    for renew_in in [-30, 0, 3601, i64::MAX - NOW] {
        let start = Instant::now();
        // The second is asked half a second on, within the same second, and
        // is as far out of range.
        let signer = Script::answering([leaves("first", renew_in), leaves("second", renew_in)]);
        let mut renewal = renewal(&signer);
        let mut door = Door::default();
        step(&mut renewal, &mut door).await;
        assert_eq!(renewal.due(), after_ms(start, 500), "{renew_in}");
        step(&mut renewal, &mut door).await;
        assert_eq!(renewal.due(), after_ms(start, 1_500), "{renew_in}");
    }
}

/// A leaf the node can read caps every wait at its end: a retry never
/// sleeps past the leaves being served.
#[tokio::test(start_paused = true)]
async fn no_wait_outlasts_the_installed_leaves() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["api.openai.com".to_owned()]).unwrap();
    let ends_unix = NOW + 3;
    params.not_before = time::OffsetDateTime::from_unix_timestamp(NOW - 60).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(ends_unix).unwrap();
    let leaf = params.self_signed(&key).unwrap().der().to_vec();
    let start = Instant::now();
    let signer = Script::answering([Ok(IssuedLeaves {
        certificates: vec![leaf],
        // Wrong: past the leaf's end.
        renew_at_unix: NOW + 600,
    })]);
    let mut renewal = renewal(&signer);
    let mut door = Door::default();
    step(&mut renewal, &mut door).await;
    assert_eq!(renewal.due(), after(start, 3));
}

#[test]
fn issued_leaves_never_print_their_certificates() {
    let issued = leaves("certificate-body", 600).unwrap();
    let body = format!("{:?}", issued.certificates[0]);
    assert!(!format!("{issued:?}").contains(&body));
}
