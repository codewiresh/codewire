use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    PublicKeyData, SignatureAlgorithm,
};
use time::Duration;

use super::*;

/// A signer's CA, standing in for the credential service's.
struct Signer {
    certificate: Certificate,
    key: KeyPair,
}

/// Another party's public key, given as its SPKI: all a signer sees.
struct Spki(Vec<u8>);

impl PublicKeyData for Spki {
    fn der_bytes(&self) -> &[u8] {
        // A P-256 SPKI ends with the 65-byte uncompressed point.
        &self.0[self.0.len() - 65..]
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl Signer {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "test signer");
        let certificate = params.self_signed(&key).unwrap();
        Self { certificate, key }
    }

    /// A leaf for `spki` naming `hosts`, ending `lifetime` from now.
    fn leaf(&self, spki: &[u8], hosts: &[&str], lifetime: Duration) -> Vec<u8> {
        self.leaf_from(spki, hosts, Duration::minutes(-5), lifetime)
    }

    /// A leaf starting `start` and ending `lifetime` from now.
    fn leaf_from(
        &self,
        spki: &[u8],
        hosts: &[&str],
        start: Duration,
        lifetime: Duration,
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(
            hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        params.distinguished_name = DistinguishedName::new();
        let now = OffsetDateTime::now_utc();
        params.not_before = now + start;
        params.not_after = now + lifetime;
        params
            .signed_by(&Spki(spki.to_vec()), &self.certificate, &self.key)
            .unwrap()
            .der()
            .to_vec()
    }
}

fn served(leaves: &SignedLeaves, host: &str) -> Result<String, CaError> {
    leaves.leaf(host).map(|(name, _)| name)
}

#[test]
fn a_new_front_door_serves_nothing_until_leaves_are_installed() {
    let leaves = SignedLeaves::generate().unwrap();
    assert_eq!(
        served(&leaves, "api.anthropic.com"),
        Err(CaError::UnboundHost)
    );
    assert!(!format!("{leaves:?}").contains(&format!("{:?}", leaves.spki)));
}

#[test]
fn an_installed_leaf_serves_exactly_its_hosts() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let leaf = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com", "api.openai.com"],
        Duration::hours(1),
    );
    leaves.install([&leaf]).unwrap();
    assert_eq!(
        served(&leaves, "API.Anthropic.com").as_deref(),
        Ok("api.anthropic.com")
    );
    assert_eq!(
        served(&leaves, "api.openai.com").as_deref(),
        Ok("api.openai.com")
    );
    assert_eq!(served(&leaves, "github.com"), Err(CaError::UnboundHost));
    let (_, key) = leaves.leaf("api.anthropic.com").unwrap();
    assert_eq!(
        key.cert[0].as_ref(),
        leaf.as_slice(),
        "the signer's leaf, unchanged"
    );
}

#[test]
fn a_leaf_for_another_key_or_with_no_host_installs_nothing() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let ours = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::hours(1),
    );
    leaves.install([&ours]).unwrap();

    let other = SignedLeaves::generate().unwrap();
    let theirs = signer.leaf(
        other.public_key_spki(),
        &["api.openai.com"],
        Duration::hours(1),
    );
    assert_eq!(leaves.install([&ours, &theirs]), Err(CaError::InvalidLeaf));
    assert_eq!(
        leaves.install([b"not a certificate".to_vec()]),
        Err(CaError::InvalidLeaf)
    );
    // All or nothing: the previous leaves stay.
    assert!(served(&leaves, "api.anthropic.com").is_ok());
    assert_eq!(served(&leaves, "api.openai.com"), Err(CaError::UnboundHost));
}

#[test]
fn an_expired_leaf_is_refused_and_a_leaf_that_expires_stops_serving() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let expired = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::seconds(-1),
    );
    assert_eq!(leaves.install([&expired]), Err(CaError::Expired));

    let short = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::seconds(2),
    );
    leaves.install([&short]).unwrap();
    assert!(served(&leaves, "api.anthropic.com").is_ok());
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(served(&leaves, "api.anthropic.com"), Err(CaError::Expired));
}

#[test]
fn a_wildcard_leaf_covers_exactly_one_label() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let leaf = signer.leaf(
        leaves.public_key_spki(),
        &["*.chatgpt.com"],
        Duration::hours(1),
    );
    leaves.install([&leaf]).unwrap();
    assert!(served(&leaves, "ab.chatgpt.com").is_ok());
    // Mixed case is normalised, then matched (#6195).
    assert_eq!(
        served(&leaves, "AB.ChatGPT.com"),
        Ok("ab.chatgpt.com".to_owned())
    );
    for host in [
        "chatgpt.com",
        "a.b.chatgpt.com",
        ".chatgpt.com",
        "xchatgpt.com",
        "ab.chatgpt.com.",
        "chatgpt.com.example",
        "ab.xn--chatgt-frf.com",
        "ab.chatg\u{0440}t.com",
    ] {
        assert_eq!(served(&leaves, host), Err(CaError::UnboundHost), "{host}");
    }
}

#[test]
fn clearing_fails_every_host_closed() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let leaf = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::hours(1),
    );
    leaves.install([&leaf]).unwrap();
    leaves.clear();
    assert_eq!(
        served(&leaves, "api.anthropic.com"),
        Err(CaError::UnboundHost)
    );
}

#[test]
fn a_leaf_starting_ahead_of_this_clock_is_refused_and_the_working_set_stays() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let working = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::hours(1),
    );
    leaves.install([&working]).unwrap();
    let ahead = signer.leaf_from(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::minutes(10),
        Duration::hours(1),
    );
    assert_eq!(leaves.install([&ahead]), Err(CaError::NotYetValid));
    let (_, key) = leaves.leaf("api.anthropic.com").unwrap();
    assert_eq!(
        key.cert[0].as_ref(),
        working.as_slice(),
        "the working leaf stays"
    );
    // Within the skew, a renewal installs.
    let near = signer.leaf_from(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::seconds(30),
        Duration::hours(1),
    );
    leaves.install([&near]).unwrap();
}

#[test]
fn a_current_leaf_is_served_beside_an_expired_one_for_the_same_host() {
    let signer = Signer::new();
    let leaves = SignedLeaves::generate().unwrap();
    let old = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::seconds(2),
    );
    let new = signer.leaf(
        leaves.public_key_spki(),
        &["api.anthropic.com"],
        Duration::hours(1),
    );
    leaves.install([&old, &new]).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let (_, key) = leaves.leaf("api.anthropic.com").unwrap();
    assert_eq!(key.cert[0].as_ref(), new.as_slice());
}
