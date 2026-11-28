//! The sealed input's encoding, and the seal's verification against a fake
//! transit that keeps OpenBao's key versions. Every value is synthetic.

use codewire_protected_store::secret_envelope::TestTransitHmac;

use super::*;

const ORG: &str = "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b";
/// A value the record's secret holds, which no record or seal may carry.
const CANARY: &str = "canary-value-never-sealed";

/// The spec's encoding of [`record`] for [`boot`], written out from "The
/// sealed input": the label and a zero byte; the environment's 16 bytes,
/// generation 7 and the digest; then `FANCY_TOKEN` (generation 2, bound, its
/// `binding_id`, `ft_` and its two hosts sorted, preceded by their count)
/// before `PLAIN_TOKEN` (generation 3, plain), each field a big-endian u32
/// length and its bytes.
const GOLDEN: &[&str] = &[
    "636f6465776972652e6c6f63616c2d626f756e642d736563726574732e763100",
    "000000107c9e6679742540de944be07fc1f90ae7000000080000000000000007",
    "000000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    "5a5a5a5a0000002d2f6f72672d736563726574732f3066386134633165336232",
    "6434653566386139623163326433653466356136620000000b46414e43595f54",
    "4f4b454e00000008000000000000000200000001010000001000000000000000",
    "0000000000000000070000000366745f00000004000000020000000f612e6661",
    "6e63792e6578616d706c650000000f622e66616e63792e6578616d706c650000",
    "002d2f6f72672d736563726574732f3066386134633165336232643465356638",
    "6139623163326433653466356136620000000b504c41494e5f544f4b454e0000",
    "000800000000000000030000000100",
];

fn boot() -> SealedBoot {
    SealedBoot {
        environment_id: Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap(),
        generation: 7,
        selection_sha256: [0x5a; 32],
    }
}

/// One plain and one bound secret, in the order a reader might give them:
/// unsorted, and the hosts unsorted too.
fn secrets() -> Vec<PlatformBootSecret> {
    vec![
        PlatformBootSecret {
            path: ORG.into(),
            key: "PLAIN_TOKEN".into(),
            binding_generation: 3,
            bound: None,
        },
        PlatformBootSecret {
            path: ORG.into(),
            key: "FANCY_TOKEN".into(),
            binding_generation: 2,
            bound: Some(PlatformBootBinding {
                binding_id: "00000000-0000-0000-0000-000000000007".into(),
                prefix: Some("ft_".into()),
                hosts: vec!["b.fancy.example".into(), "a.fancy.example".into()],
            }),
        },
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn sealed(seal: &BootSeal) -> PlatformBootRecord {
    PlatformBootRecord {
        seal: seal.seal(&boot(), &secrets()).await.unwrap(),
        secrets: secrets(),
    }
}

fn key() -> (Arc<TestTransitHmac>, BootSeal) {
    let key = Arc::new(TestTransitHmac::default());
    let seal = BootSeal::new(Some(key.clone()));
    (key, seal)
}

#[test]
fn the_sealed_input_is_the_specs_encoding_and_holds_no_value() {
    let input = sealed_input(&boot(), &secrets()).unwrap();
    assert_eq!(hex(&input), GOLDEN.concat());
    let text = String::from_utf8_lossy(&input);
    assert!(!text.contains(CANARY));
    assert!(!input.windows(5).any(|window| window == b"cwp1_"));
}

#[test]
fn a_record_that_cannot_be_encoded_has_no_input() {
    let mut uppercase = secrets();
    uppercase[1].bound.as_mut().unwrap().binding_id = "00000000-0000-0000-0000-00000000000A".into();
    let mut nonsense = secrets();
    nonsense[1].bound.as_mut().unwrap().binding_id = "not-a-uuid".into();
    for secrets in [uppercase, nonsense] {
        assert_eq!(sealed_input(&boot(), &secrets), None);
    }
}

#[tokio::test]
async fn a_sealed_record_verifies_for_its_boot() {
    let (_, seal) = key();
    let record = sealed(&seal).await;
    assert!(record.seal.starts_with("vault:v1:"));
    let verified = seal.verify(&boot(), record).await.unwrap();
    assert_eq!(verified.secrets(), secrets().as_slice());
    let empty = PlatformBootRecord {
        seal: seal.seal(&boot(), &[]).await.unwrap(),
        secrets: Vec::new(),
    };
    assert!(
        seal.verify(&boot(), empty)
            .await
            .unwrap()
            .secrets()
            .is_empty()
    );
}

/// One rotation leaves a running boot's seal valid; a second refuses it.
#[tokio::test]
async fn a_seal_from_the_previous_version_verifies_and_two_back_is_denied() {
    let (key, seal) = key();
    let record = sealed(&seal).await;
    key.rotate();
    assert!(seal.verify(&boot(), record.clone()).await.is_ok());
    key.rotate();
    assert_eq!(seal.verify(&boot(), record).await, Err(SealRefusal::Denied));
}

/// Every field the seal covers, changed alone, refuses the record.
#[tokio::test]
async fn a_record_changed_in_any_field_is_denied() {
    let (_, seal) = key();
    let record = sealed(&seal).await;
    let changed = |change: fn(&mut PlatformBootRecord)| {
        let mut record = record.clone();
        change(&mut record);
        record
    };
    let tampered = [
        (
            "an entry dropped",
            changed(|record| drop(record.secrets.remove(0))),
        ),
        (
            "an entry added",
            changed(|record| {
                record.secrets.push(PlatformBootSecret {
                    path: ORG.into(),
                    key: "OTHER_TOKEN".into(),
                    binding_generation: 1,
                    bound: None,
                });
            }),
        ),
        (
            "an entry made plain",
            changed(|record| record.secrets[1].bound = None),
        ),
        (
            "an entry's generation",
            changed(|record| record.secrets[0].binding_generation = 4),
        ),
        (
            "an entry's hosts",
            changed(|record| {
                record.secrets[1].bound.as_mut().unwrap().hosts = vec!["a.fancy.example".into()];
            }),
        ),
        (
            "an entry's prefix",
            changed(|record| record.secrets[1].bound.as_mut().unwrap().prefix = None),
        ),
    ];
    for (field, record) in tampered {
        assert_eq!(
            seal.verify(&boot(), record).await,
            Err(SealRefusal::Denied),
            "{field}"
        );
    }
    let boots = [
        (
            "the environment",
            SealedBoot {
                environment_id: Uuid::new_v4(),
                ..boot()
            },
        ),
        (
            "the generation",
            SealedBoot {
                generation: 8,
                ..boot()
            },
        ),
        (
            "the selection",
            SealedBoot {
                selection_sha256: [0x5b; 32],
                ..boot()
            },
        ),
    ];
    for (field, other) in boots {
        assert_eq!(
            seal.verify(&other, record.clone()).await,
            Err(SealRefusal::Denied),
            "{field}"
        );
    }
}

#[tokio::test]
async fn openbao_unavailable_is_never_a_pass_and_no_key_is_not_configured() {
    let (key, seal) = key();
    let record = sealed(&seal).await;
    key.set_unavailable(true);
    assert_eq!(
        seal.seal(&boot(), &secrets()).await,
        Err(SealRefusal::Unavailable)
    );
    assert_eq!(
        seal.verify(&boot(), record.clone()).await,
        Err(SealRefusal::Unavailable)
    );
    let none = BootSeal::default();
    assert!(!none.configured());
    assert_eq!(
        none.seal(&boot(), &secrets()).await,
        Err(SealRefusal::NotConfigured)
    );
    assert_eq!(
        none.verify(&boot(), record).await,
        Err(SealRefusal::NotConfigured)
    );
}

#[test]
fn the_record_round_trips_its_wire_form() {
    let record = PlatformBootRecord {
        secrets: secrets(),
        seal: "vault:v1:synthetic".into(),
    };
    assert_eq!(record_from_proto(record_to_proto(record.clone())), record);
}
