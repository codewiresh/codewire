use super::*;
use crate::api::cw_runtime::service_test_support as fixture;

#[test]
fn intent_fences_complete_incarnation_tuple_and_accepted_source_identity() {
    let header = fixture::header(2);
    let accepted = update_intent(&header).unwrap();
    assert_eq!(accepted.incarnation, fixture::binding().incarnation());
    let mut wrong = header.clone();
    wrong.org_id = "other-org".into();
    assert!(update_intent(&wrong).is_err());
    wrong = header.clone();
    wrong
        .expected_incarnation
        .as_option_mut()
        .unwrap()
        .claim_uid = "legacy".into();
    assert!(update_intent(&wrong).is_err());
    wrong = header.clone();
    wrong
        .expected_incarnation
        .as_option_mut()
        .unwrap()
        .environment_generation = u64::MAX;
    assert!(update_intent(&wrong).is_err());
    wrong = header.clone();
    wrong.identity.as_option_mut().unwrap().target = "x86_64-unknown-linux-gnu".into();
    assert!(update_intent(&wrong).is_err());
    wrong = header.clone();
    wrong.request_id = "00000000-0000-0000-0000-000000000000".into();
    assert!(update_intent(&wrong).is_err());
}

#[test]
fn bootstrap_requires_full_observed_original_identity_and_absent_store() {
    let header = fixture::header(0);
    let intent = update_intent(&header).unwrap();
    let selection = ObservedSelection {
        generation: 0,
        current: None,
        previous: None,
        pending: false,
        consistent: true,
        retained_count: 0,
    };
    let bootstrap = intent.mutation.bootstrap_identity.as_ref().unwrap();
    assert!(admit_observation(&intent, true, Some(bootstrap), &selection).is_ok());
    let mut wrong = bootstrap.clone();
    wrong.source_revision = "d".repeat(40);
    assert!(admit_observation(&intent, true, Some(&wrong), &selection).is_err());
    assert!(admit_observation(&intent, false, None, &selection).is_err());
    let mut pending = selection.clone();
    pending.pending = true;
    assert!(admit_observation(&intent, true, Some(bootstrap), &pending).is_err());
    let mut changed = selection;
    changed.generation = 1;
    changed.current = Some(bootstrap.clone());
    changed.retained_count = 1;
    assert!(admit_observation(&intent, true, Some(bootstrap), &changed).is_err());
}

#[test]
fn chunk_frames_refuse_duplicate_header_empty_oversized_and_unselected_payload() {
    let valid = proto::UpdateEnvironmentCwRuntimeRequest {
        payload: Some(
            proto::update_environment_cw_runtime_request::Payload::Chunk(vec![1; wire::MAX_CHUNK]),
        ),
        ..Default::default()
    };
    assert_eq!(chunk(valid).unwrap().len(), wire::MAX_CHUNK);
    for frame in [
        proto::UpdateEnvironmentCwRuntimeRequest::default(),
        proto::UpdateEnvironmentCwRuntimeRequest {
            payload: Some(
                proto::update_environment_cw_runtime_request::Payload::Header(Box::new(
                    fixture::header(1),
                )),
            ),
            ..Default::default()
        },
        proto::UpdateEnvironmentCwRuntimeRequest {
            payload: Some(proto::update_environment_cw_runtime_request::Payload::Chunk(vec![])),
            ..Default::default()
        },
        proto::UpdateEnvironmentCwRuntimeRequest {
            payload: Some(
                proto::update_environment_cw_runtime_request::Payload::Chunk(vec![
                    1;
                    wire::MAX_CHUNK
                        + 1
                ]),
            ),
            ..Default::default()
        },
    ] {
        assert!(chunk(frame).is_err());
    }
}

#[test]
fn stale_and_inconsistent_selection_and_wrong_retained_rollback_identity_refuse() {
    let mut intent = update_intent(&fixture::header(2)).unwrap();
    let selection = ObservedSelection {
        generation: 2,
        current: Some(fixture::identity('a')),
        previous: Some(fixture::identity('b')),
        pending: false,
        consistent: true,
        retained_count: 2,
    };
    assert!(admit_observation(&intent, true, Some(&fixture::identity('a')), &selection).is_ok());
    let mut stale = selection.clone();
    stale.generation = 3;
    assert!(admit_observation(&intent, true, None, &stale).is_err());
    stale = selection.clone();
    stale.consistent = false;
    assert!(admit_observation(&intent, true, None, &stale).is_err());
    intent.mutation.action = RuntimeAction::Rollback;
    assert!(admit_observation(&intent, true, None, &selection).is_err());
    intent.mutation.target_identity = fixture::identity('b');
    assert!(admit_observation(&intent, true, None, &selection).is_ok());
    intent.mutation.target_identity.source_revision = "f".repeat(40);
    assert!(admit_observation(&intent, true, None, &selection).is_err());
}

#[tokio::test]
async fn nothing_is_admitted_once_the_drain_has_begun() {
    let drain = crate::drain::Drain::default();
    assert!(admitting(&drain).is_ok());
    drain.begin(crate::drain::DRAIN_WINDOW);
    match admitting(&drain) {
        Err(AppError::ServiceUnavailable(detail)) => assert!(detail.contains("send it again")),
        other => panic!("expected a retryable refusal, got {other:?}"),
    }
}
