use super::*;
use crate::api::cw_runtime::model::{CheckpointAcknowledgement, EffectReceipt, RuntimeAction};
use crate::api::cw_runtime::service_test_support as fixture;

/// A request that ended unknown while `effect` was dispatched.
fn unknown(action: RuntimeAction, generation: u64, effect: RuntimeEffect) -> RuntimeRequest {
    let mut request = fixture::request(action, generation);
    request.phase = RuntimePhase::Unknown;
    request.checkpoint = 1;
    request.effect = Some(effect);
    request.error_code = Some("cw_runtime_dispatch_unknown".into());
    request
}

fn observed(generation: u64, current: Option<char>, previous: Option<char>) -> ObservedSelection {
    ObservedSelection {
        generation,
        current: current.map(fixture::identity),
        previous: previous.map(fixture::identity),
        pending: false,
        consistent: true,
        retained_count: usize::from(current.is_some()) + usize::from(previous.is_some()),
    }
}

#[test]
fn an_update_is_unchanged_at_its_before_selection_and_applied_at_exactly_its_after() {
    // Admitted against generation 2, current a, previous b; the target is c.
    let request = unknown(RuntimeAction::Update, 2, RuntimeEffect::Update);
    let before = observed(2, Some('a'), Some('b'));
    assert_eq!(resolution(&request, &before), Some(Resolution::Unchanged));
    assert_eq!(
        resolution(&request, &observed(3, Some('c'), Some('a'))),
        Some(Resolution::Applied)
    );
    for other in [
        observed(3, Some('d'), Some('a')),
        observed(4, Some('c'), Some('a')),
        observed(3, Some('c'), Some('b')),
        observed(2, Some('c'), Some('b')),
    ] {
        assert_eq!(resolution(&request, &other), None, "{other:?}");
    }
}

#[test]
fn a_pending_or_inconsistent_store_decides_nothing() {
    let request = unknown(RuntimeAction::Update, 2, RuntimeEffect::Update);
    let mut pending = observed(2, Some('a'), Some('b'));
    pending.pending = true;
    let mut inconsistent = observed(3, Some('c'), Some('a'));
    inconsistent.consistent = false;
    assert_eq!(resolution(&request, &pending), None);
    assert_eq!(resolution(&request, &inconsistent), None);
}

#[test]
fn only_a_request_that_ended_unknown_is_resolved() {
    let before = observed(2, Some('a'), Some('b'));
    for phase in [
        RuntimePhase::Admitted,
        RuntimePhase::Issued,
        RuntimePhase::Acknowledged,
        RuntimePhase::Succeeded,
        RuntimePhase::Failed,
    ] {
        let mut request = unknown(RuntimeAction::Update, 2, RuntimeEffect::Update);
        request.phase = phase;
        assert_eq!(resolution(&request, &before), None, "{phase:?}");
    }
}

#[test]
fn staging_and_cleanup_never_change_the_selection() {
    for effect in [RuntimeEffect::Staging, RuntimeEffect::Cleanup] {
        let request = unknown(RuntimeAction::Update, 2, effect);
        assert_eq!(
            resolution(&request, &observed(2, Some('a'), Some('b'))),
            Some(Resolution::Unchanged)
        );
        assert_eq!(
            resolution(&request, &observed(3, Some('c'), Some('a'))),
            None,
            "{effect:?}"
        );
    }
}

#[test]
fn a_rollback_and_a_bootstrap_resolve_against_their_own_targets() {
    let mut rollback = unknown(RuntimeAction::Rollback, 2, RuntimeEffect::Rollback);
    rollback.mutation.target_identity = fixture::identity('b');
    assert_eq!(
        resolution(&rollback, &observed(3, Some('b'), Some('a'))),
        Some(Resolution::Applied)
    );
    // Generation 0 bootstraps image a before staging the target c.
    let bootstrap = unknown(RuntimeAction::Update, 0, RuntimeEffect::Bootstrap);
    assert_eq!(
        resolution(&bootstrap, &observed(0, None, None)),
        Some(Resolution::Unchanged)
    );
    assert_eq!(
        resolution(&bootstrap, &observed(1, Some('a'), None)),
        Some(Resolution::Applied)
    );
    assert_eq!(resolution(&bootstrap, &observed(1, Some('c'), None)), None);
}

#[test]
fn the_before_selection_is_the_last_acknowledged_one() {
    // The update was acknowledged; the cleanup after it ended unknown.
    let mut request = unknown(RuntimeAction::Update, 2, RuntimeEffect::Cleanup);
    request.checkpoint = 3;
    request.acknowledgements = vec![
        CheckpointAcknowledgement {
            checkpoint: 1,
            effect: RuntimeEffect::Staging,
            receipt: EffectReceipt::Staged {
                sha256: fixture::identity('c').sha256,
                size: fixture::identity('c').size,
            },
        },
        CheckpointAcknowledgement {
            checkpoint: 2,
            effect: RuntimeEffect::Update,
            receipt: EffectReceipt::Selected {
                sha256: fixture::identity('c').sha256,
                generation: 3,
                previous_sha256: Some(fixture::identity('a').sha256),
                changed: true,
            },
        },
    ];
    assert_eq!(
        resolution(&request, &observed(3, Some('c'), Some('a'))),
        Some(Resolution::Unchanged)
    );
    assert_eq!(
        resolution(&request, &observed(2, Some('a'), Some('b'))),
        None
    );
}
