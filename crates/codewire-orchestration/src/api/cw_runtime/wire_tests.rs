use super::*;
use crate::api::cw_runtime::{model::RuntimePhase, service_test_support as fixture};

fn correlation() -> Correlation {
    Correlation {
        request_id: Uuid::new_v4(),
        pod_uid: Uuid::new_v4(),
        binding_sha256: "a".repeat(64),
    }
}
fn frame(correlation: Correlation, outcome: Outcome) -> Vec<u8> {
    let bytes = canonical_json(&Reply {
        schema_version: 1,
        correlation,
        outcome,
    })
    .unwrap();
    let mut result = (bytes.len() as u32).to_le_bytes().to_vec();
    result.extend(bytes);
    result
}

#[test]
fn private_receipt_requires_exact_correlation_exit_frame_and_canonical_eof() {
    let c = correlation();
    let bytes = frame(
        c.clone(),
        Outcome::Succeeded {
            result: ReplyBody::Cleaned,
        },
    );
    assert_eq!(
        reply(&bytes, &c, 0).unwrap(),
        Outcome::Succeeded {
            result: ReplyBody::Cleaned
        }
    );
    assert!(reply(&bytes, &correlation(), 0).is_err());
    assert!(reply(&bytes, &c, 3).is_err());
    assert!(reply(&bytes[..bytes.len() - 1], &c, 0).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(reply(&trailing, &c, 0).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.insert(4, b' ');
    noncanonical[..4].copy_from_slice(&((bytes.len() - 3) as u32).to_le_bytes());
    assert!(reply(&noncanonical, &c, 0).is_err());
    assert!(reply(&vec![0; MAX_FRAME + 5], &c, 0).is_err());
    let refused = frame(
        c.clone(),
        Outcome::Refused {
            code: Code::StaleSelection,
        },
    );
    assert!(matches!(
        reply(&refused, &c, 3),
        Ok(Outcome::Refused { .. })
    ));
}

#[test]
fn public_identity_and_incarnation_refuse_unknown_target_and_overflow() {
    let mut value = proto_identity(&fixture::identity('a'));
    assert_eq!(identity(&value).unwrap(), fixture::identity('a'));
    value.target = "x86_64-unknown-linux-gnu".into();
    assert!(identity(&value).is_err());
    value = proto_identity(&fixture::identity('a'));
    value.rustc = "x".repeat(129);
    assert!(identity(&value).is_err());
    let original = fixture::binding().incarnation();
    let mut value = proto_incarnation(&original).unwrap();
    assert_eq!(incarnation(&value).unwrap(), original);
    value.environment_generation = i64::MAX as u64 + 1;
    assert!(incarnation(&value).is_err());
    value = proto_incarnation(&original).unwrap();
    value.binding_generation = i64::MAX as u64 + 1;
    assert!(incarnation(&value).is_err());
    value = proto_incarnation(&original).unwrap();
    value.pod_uid = "unknown-pod".into();
    assert!(incarnation(&value).is_err());
}

#[test]
fn saved_operation_generation_and_acknowledgements_preserve_full_u64() {
    let mut request = fixture::request(RuntimeAction::Update, u64::MAX - 1);
    request.phase = RuntimePhase::Acknowledged;
    request.checkpoint = 2;
    request
        .acknowledgements
        .push(super::super::model::CheckpointAcknowledgement {
            checkpoint: 2,
            effect: RuntimeEffect::Update,
            receipt: EffectReceipt::Selected {
                sha256: request.mutation.target_identity.sha256.clone(),
                generation: u64::MAX,
                previous_sha256: request.mutation.expected_current_sha256.clone(),
                changed: true,
            },
        });
    let value = proto_operation(&request).unwrap();
    assert_eq!(
        value.expected_selection.as_option().unwrap().generation,
        u64::MAX - 1
    );
    let Some(proto::environment_cw_runtime_acknowledgement::Receipt::Selected(ack)) =
        &value.acknowledgements[0].receipt
    else {
        panic!("selected receipt")
    };
    assert_eq!(ack.generation, u64::MAX);
}

#[test]
fn status_selection_validates_previous_identity_and_pending_without_manufacturing_success() {
    let value = ObservedSelection {
        generation: 1,
        current: Some(fixture::identity('a')),
        previous: None,
        pending: true,
        consistent: false,
        retained_count: 1,
    };
    let c = correlation();
    let bytes = frame(
        c.clone(),
        Outcome::Succeeded {
            result: ReplyBody::Status {
                supported_image: true,
                bootstrap: Some(Box::new(fixture::identity('b'))),
                selection: Box::new(value.clone()),
            },
        },
    );
    assert!(reply(&bytes, &c, 0).is_ok());
    assert!(proto_selection(&value).unwrap().pending);
    let mut invalid = value;
    invalid.previous = invalid.current.clone();
    assert!(invalid.expected().is_err());
    invalid.previous = Some(fixture::identity('b'));
    invalid.previous.as_mut().unwrap().target = "x86_64-unknown-linux-gnu".into();
    assert!(invalid.expected().is_err());
}
