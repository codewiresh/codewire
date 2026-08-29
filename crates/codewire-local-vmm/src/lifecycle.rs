//! Auditable lifecycle-effect plans for durable supervisor replay.
//!
//! A journal checkpoint is the index of the next effect. Filesystem, process,
//! and private-RPC effects must therefore be idempotent: a supervisor can die
//! after the effect succeeds but before its checkpoint commits.
//! `StageWorkspaceGeneration` may prepare verified CAS objects before its
//! atomic state/checkpoint commit. A crash can leave only unreferenced content;
//! no resolved generation becomes authoritative before that transaction.

use crate::supervisor_store::OperationKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LifecycleEffect {
    RecordEnvironment,
    ProvisionWorkspace,
    StageWorkspaceGeneration,
    RecordStarting,
    EnsureRunner,
    StartVm,
    RecordRunning,
    StopVm,
    RecordStopped,
    GrowDisk,
    RecordResources,
    RestartVm,
    RecordResizeOutcome,
    PrepareDelete,
    MoveToTrash,
    RemoveEnvironment,
    CleanupTrash,
    RecordObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectDurability {
    Transactional,
    ExternalIdempotent,
}

impl LifecycleEffect {
    pub(crate) fn durability(self) -> EffectDurability {
        match self {
            Self::RecordEnvironment
            | Self::StageWorkspaceGeneration
            | Self::RecordStarting
            | Self::RecordRunning
            | Self::RecordStopped
            | Self::RecordResources
            | Self::RecordResizeOutcome
            | Self::RemoveEnvironment
            | Self::RecordObservation => EffectDurability::Transactional,
            Self::ProvisionWorkspace
            | Self::EnsureRunner
            | Self::StartVm
            | Self::StopVm
            | Self::GrowDisk
            | Self::RestartVm
            | Self::PrepareDelete
            | Self::MoveToTrash
            | Self::CleanupTrash => EffectDurability::ExternalIdempotent,
        }
    }
}

const CREATE: &[LifecycleEffect] = &[
    LifecycleEffect::RecordEnvironment,
    LifecycleEffect::ProvisionWorkspace,
    LifecycleEffect::StageWorkspaceGeneration,
    LifecycleEffect::EnsureRunner,
    LifecycleEffect::StartVm,
    LifecycleEffect::RecordRunning,
];
const START: &[LifecycleEffect] = &[
    LifecycleEffect::RecordStarting,
    LifecycleEffect::StageWorkspaceGeneration,
    LifecycleEffect::EnsureRunner,
    LifecycleEffect::StartVm,
    LifecycleEffect::RecordRunning,
];
const STOP: &[LifecycleEffect] = &[LifecycleEffect::StopVm, LifecycleEffect::RecordStopped];
const RESIZE: &[LifecycleEffect] = &[
    LifecycleEffect::StopVm,
    LifecycleEffect::RecordStopped,
    LifecycleEffect::GrowDisk,
    LifecycleEffect::RecordResources,
    LifecycleEffect::RestartVm,
    LifecycleEffect::RecordResizeOutcome,
];
const DELETE: &[LifecycleEffect] = &[
    LifecycleEffect::PrepareDelete,
    LifecycleEffect::MoveToTrash,
    LifecycleEffect::RemoveEnvironment,
    LifecycleEffect::CleanupTrash,
];
const RECONCILE: &[LifecycleEffect] = &[LifecycleEffect::RecordObservation];

pub(crate) fn effects(kind: OperationKind) -> &'static [LifecycleEffect] {
    match kind {
        OperationKind::Create => CREATE,
        OperationKind::Start => START,
        OperationKind::Stop => STOP,
        OperationKind::Restart | OperationKind::GrowDisk => RESIZE,
        OperationKind::Delete => DELETE,
        OperationKind::Reconcile => RECONCILE,
    }
}

pub(crate) fn next_effect(
    kind: OperationKind,
    checkpoint: u32,
) -> Result<Option<LifecycleEffect>, LifecyclePlanError> {
    let checkpoint = usize::try_from(checkpoint).map_err(|_| LifecyclePlanError)?;
    let effects = effects(kind);
    if checkpoint > effects.len() {
        return Err(LifecyclePlanError);
    }
    Ok(effects.get(checkpoint).copied())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("lifecycle journal checkpoint is outside its effect plan")]
pub(crate) struct LifecyclePlanError;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::linux::path::PrivateRoot;
    use crate::linux::state::{
        DeletionTreeLocation, VmPaths, cleanup_trashed_vm, deletion_tree_location,
        move_stopped_vm_to_trash,
    };
    use crate::supervisor_store::{OperationPhase, SupervisorStore};
    use uuid::Uuid;

    const KINDS: &[OperationKind] = &[
        OperationKind::Create,
        OperationKind::Start,
        OperationKind::Stop,
        OperationKind::Restart,
        OperationKind::GrowDisk,
        OperationKind::Delete,
        OperationKind::Reconcile,
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FaultEdge {
        Before,
        After,
    }

    #[derive(Default)]
    struct FakeEffects {
        durable: BTreeSet<LifecycleEffect>,
        attempts: BTreeMap<LifecycleEffect, usize>,
    }

    impl FakeEffects {
        fn apply(&mut self, effect: LifecycleEffect) {
            *self.attempts.entry(effect).or_default() += 1;
            self.durable.insert(effect);
        }
    }

    fn run_until_fault(
        kind: OperationKind,
        mut checkpoint: u32,
        effects: &mut FakeEffects,
        fault: Option<(LifecycleEffect, FaultEdge)>,
    ) -> Result<u32, u32> {
        while let Some(effect) = next_effect(kind, checkpoint).unwrap() {
            if fault == Some((effect, FaultEdge::Before)) {
                return Err(checkpoint);
            }
            effects.apply(effect);
            if fault == Some((effect, FaultEdge::After)) {
                return Err(checkpoint);
            }
            checkpoint += 1;
        }
        Ok(checkpoint)
    }

    #[test]
    fn every_effect_replays_deterministically_before_and_after_its_checkpoint() {
        for kind in KINDS {
            for fault_effect in effects(*kind) {
                for edge in [FaultEdge::Before, FaultEdge::After] {
                    let mut fake = FakeEffects::default();
                    let interrupted =
                        run_until_fault(*kind, 0, &mut fake, Some((*fault_effect, edge)))
                            .unwrap_err();
                    let completed = run_until_fault(*kind, interrupted, &mut fake, None).unwrap();

                    assert_eq!(completed as usize, effects(*kind).len());
                    assert_eq!(fake.durable, effects(*kind).iter().copied().collect());
                    let attempts = fake.attempts[fault_effect];
                    assert_eq!(attempts, if edge == FaultEdge::After { 2 } else { 1 });
                }
            }
        }
    }

    #[test]
    fn sqlite_journal_reopen_replays_every_injected_effect_boundary() {
        for kind in KINDS {
            for fault_effect in effects(*kind) {
                for edge in [FaultEdge::Before, FaultEdge::After] {
                    let parent = tempfile::tempdir().unwrap();
                    let root_path = parent.path().join("runtime");
                    fs::create_dir(&root_path).unwrap();
                    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
                    let root = PrivateRoot::open(&root_path).unwrap();
                    let (store, _) = SupervisorStore::open(&root).unwrap();
                    let mut operation = store
                        .begin_operation(
                            Uuid::new_v4(),
                            Some(Uuid::new_v4()),
                            *kind,
                            &serde_json::json!({"name": "dev"}),
                        )
                        .unwrap();
                    let mut fake = FakeEffects::default();

                    while let Some(effect) = next_effect(*kind, operation.checkpoint).unwrap() {
                        if effect == *fault_effect && edge == FaultEdge::Before {
                            break;
                        }
                        fake.apply(effect);
                        if effect == *fault_effect && edge == FaultEdge::After {
                            break;
                        }
                        operation = store
                            .advance_operation(
                                operation.operation_id,
                                operation.checkpoint,
                                OperationPhase::EffectApplied,
                                None,
                                None,
                            )
                            .unwrap();
                    }
                    let interrupted_checkpoint = operation.checkpoint;
                    drop(store);

                    let (store, _) = SupervisorStore::open(&root).unwrap();
                    operation = store.pending_operations().unwrap().pop().unwrap();
                    assert_eq!(operation.checkpoint, interrupted_checkpoint);
                    while let Some(effect) = next_effect(*kind, operation.checkpoint).unwrap() {
                        fake.apply(effect);
                        operation = store
                            .advance_operation(
                                operation.operation_id,
                                operation.checkpoint,
                                OperationPhase::EffectApplied,
                                None,
                                None,
                            )
                            .unwrap();
                    }
                    operation = store
                        .advance_operation(
                            operation.operation_id,
                            operation.checkpoint,
                            OperationPhase::Completed,
                            Some(&serde_json::json!({"name": "dev"})),
                            None,
                        )
                        .unwrap();

                    assert_eq!(operation.checkpoint as usize, effects(*kind).len() + 1);
                    assert_eq!(fake.durable, effects(*kind).iter().copied().collect());
                    assert_eq!(
                        fake.attempts[fault_effect],
                        if edge == FaultEdge::After { 2 } else { 1 }
                    );
                    assert!(store.pending_operations().unwrap().is_empty());
                }
            }
        }
    }

    #[test]
    fn only_atomic_state_checkpoint_effects_are_classified_transactional() {
        for kind in KINDS {
            for effect in effects(*kind) {
                let expected = matches!(
                    effect,
                    LifecycleEffect::RecordEnvironment
                        | LifecycleEffect::StageWorkspaceGeneration
                        | LifecycleEffect::RecordStarting
                        | LifecycleEffect::RecordRunning
                        | LifecycleEffect::RecordStopped
                        | LifecycleEffect::RecordResources
                        | LifecycleEffect::RecordResizeOutcome
                        | LifecycleEffect::RemoveEnvironment
                        | LifecycleEffect::RecordObservation
                );
                assert_eq!(
                    effect.durability() == EffectDurability::Transactional,
                    expected
                );
            }
        }
    }

    #[test]
    fn interrupted_delete_reuses_the_exact_trash_generation() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        let engine_path = root_path.join("engine");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&engine_path).unwrap();
        fs::set_permissions(&engine_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        let engine = PrivateRoot::open(&engine_path).unwrap();
        let environment_id = Uuid::new_v4();
        VmPaths::create(&engine, environment_id).unwrap();

        let (store, _) = SupervisorStore::open(&root).unwrap();
        let mut operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Delete,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            next_effect(operation.kind, operation.checkpoint).unwrap(),
            Some(LifecycleEffect::MoveToTrash)
        );

        let trash =
            move_stopped_vm_to_trash(&engine_path, environment_id, operation.operation_id).unwrap();
        drop(store); // Crash after rename, before its checkpoint commit.

        let (store, _) = SupervisorStore::open(&root).unwrap();
        operation = store.pending_operations().unwrap().pop().unwrap();
        assert_eq!(operation.checkpoint, 1);
        assert!(matches!(
            deletion_tree_location(&engine_path, environment_id, operation.operation_id).unwrap(),
            DeletionTreeLocation::Trash(path) if path == trash
        ));
        assert_eq!(
            move_stopped_vm_to_trash(&engine_path, environment_id, operation.operation_id,)
                .unwrap(),
            trash
        );
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();

        cleanup_trashed_vm(&engine_path, environment_id, operation.operation_id).unwrap();
        drop(store); // Crash after cleanup, before its checkpoint commit.

        let (store, _) = SupervisorStore::open(&root).unwrap();
        operation = store.pending_operations().unwrap().pop().unwrap();
        assert_eq!(operation.checkpoint, 3);
        cleanup_trashed_vm(&engine_path, environment_id, operation.operation_id).unwrap();
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Completed,
                Some(&serde_json::json!({"name": "dev", "removed": true})),
                None,
            )
            .unwrap();

        assert_eq!(operation.checkpoint, 5);
        assert!(matches!(
            deletion_tree_location(&engine_path, environment_id, operation.operation_id).unwrap(),
            DeletionTreeLocation::Missing
        ));
        assert!(store.pending_operations().unwrap().is_empty());
    }

    #[test]
    fn checkpoints_beyond_a_plan_fail_closed() {
        for kind in KINDS {
            let invalid = u32::try_from(effects(*kind).len() + 1).unwrap();
            assert_eq!(next_effect(*kind, invalid), Err(LifecyclePlanError));
        }
    }
}
