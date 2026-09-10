use super::*;
use crate::ProjectionRecipient;

const NOW: u64 = 1_000_000;

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 7,
        selection_sha256: [2; 32],
        deadline_unix_ms: NOW + 5_000,
    }
}

fn inventory(
    source: WorkloadSecretSource,
    contributor: ProjectionContributor,
    keys: &[&str],
) -> ProjectionSourceInventory {
    ProjectionSourceInventory {
        source,
        contributor,
        source_identity: format!("selected-{source:?}-scope"),
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
    }
}

fn inventories() -> Vec<ProjectionSourceInventory> {
    vec![
        inventory(
            WorkloadSecretSource::Organization,
            ProjectionContributor::Platform,
            &["ORG_ONLY", "SHARED"],
        ),
        inventory(
            WorkloadSecretSource::Project,
            ProjectionContributor::Local,
            &["PROJECT_ONLY", "SHARED"],
        ),
        inventory(
            WorkloadSecretSource::User,
            ProjectionContributor::Platform,
            &["SHARED", "OVERRIDDEN"],
        ),
    ]
}

fn plan(
    inventories: &[ProjectionSourceInventory],
) -> Result<ProjectionCompositionPlan, ProjectionError> {
    ProjectionCompositionPlan::new(
        &context(),
        [3; 16],
        ProjectionRecipient::new().public_key(),
        inventories,
        &BTreeSet::from(["OVERRIDDEN".into()]),
        &BTreeSet::from(["CODEX_HOME".into()]),
        NOW,
    )
}

#[test]
fn mixed_winners_use_existing_rank_precedence_before_any_material_reads() {
    let plan = plan(&inventories()).unwrap();
    assert_eq!(
        plan.winning_keys(ProjectionContributor::Local),
        &BTreeSet::from(["PROJECT_ONLY".into()])
    );
    assert_eq!(
        plan.winning_keys(ProjectionContributor::Platform),
        &BTreeSet::from(["ORG_ONLY".into(), "SHARED".into()])
    );
    assert_ne!(plan.digest(), [0; 32]);
}

#[test]
fn empty_or_fully_overridden_contributor_still_requires_both_selected_origins() {
    for local_names in [vec![], vec!["SHARED"]] {
        let plan = plan(&[
            inventory(
                WorkloadSecretSource::Project,
                ProjectionContributor::Local,
                &local_names,
            ),
            inventory(
                WorkloadSecretSource::User,
                ProjectionContributor::Platform,
                &["SHARED"],
            ),
        ])
        .unwrap();
        assert!(plan.winning_keys(ProjectionContributor::Local).is_empty());
        assert_eq!(
            plan.winning_keys(ProjectionContributor::Platform),
            &BTreeSet::from(["SHARED".into()])
        );
    }
    assert!(plan(&inventories()[..1]).is_err());
}

#[test]
fn inventory_rank_identity_duplicates_reserved_names_and_union_limits_fail_closed() {
    for field in 0..8 {
        let mut invalid = inventories();
        match field {
            0 => invalid.swap(0, 1),
            1 => invalid[1].source = WorkloadSecretSource::Organization,
            2 => invalid[0].contributor = ProjectionContributor::Local,
            3 => invalid[1].source_identity.clear(),
            4 => invalid[1].keys = BTreeSet::from(["CODEX_HOME".into()]),
            5 => invalid[1].keys = BTreeSet::from(["invalid-key".into()]),
            6 => invalid[1].keys = (0..256).map(|i| format!("KEY_{i}")).collect(),
            _ => invalid[2].source = WorkloadSecretSource::ExplicitEnvironment,
        }
        assert!(plan(&invalid).is_err(), "field {field}");
    }
    let mut maximum = inventories();
    maximum[0].keys = (0..128).map(|i| format!("KEY_{i}")).collect();
    maximum[1].keys = (0..255).map(|i| format!("KEY_{i}")).collect();
    maximum[2].keys.clear();
    assert!(plan(&maximum).is_ok()); // 255 union names plus one explicit key.
    maximum[2].keys.insert("EXTRA".into());
    assert!(plan(&maximum).is_err());
}

#[test]
fn group_digest_binds_launch_recipient_scopes_inventories_and_winners() {
    let recipient = ProjectionRecipient::new().public_key();
    let original = inventories();
    let ordinary = BTreeSet::from(["OVERRIDDEN".into()]);
    let reserved = BTreeSet::from(["CODEX_HOME".into()]);
    let expected = ProjectionCompositionPlan::new(
        &context(),
        [3; 16],
        recipient,
        &original,
        &ordinary,
        &reserved,
        NOW,
    )
    .unwrap();
    for field in 0..10 {
        let mut context = context();
        let mut changed = original.clone();
        let mut request = [3; 16];
        let mut recipient = recipient;
        let mut ordinary = ordinary.clone();
        let mut reserved = reserved.clone();
        match field {
            0 => context.environment_id = [4; 16],
            1 => context.operation_generation += 1,
            2 => context.selection_sha256 = [5; 32],
            3 => context.deadline_unix_ms += 1,
            4 => request = [6; 16],
            5 => recipient = ProjectionRecipient::new().public_key(),
            6 => changed[1].source_identity.push_str("-changed"),
            7 => {
                changed[1].keys.insert("ANOTHER_KEY".into());
            }
            8 => {
                ordinary.insert("SHARED".into());
            }
            _ => {
                reserved.insert("SSH_AUTH_SOCK".into());
            }
        }
        let actual = ProjectionCompositionPlan::new(
            &context, request, recipient, &changed, &ordinary, &reserved, NOW,
        )
        .unwrap();
        assert_ne!(actual.digest(), expected.digest(), "field {field}");
    }
    expected.validate_context(&context(), recipient).unwrap();
    assert!(
        expected
            .validate_context(&context(), ProjectionRecipient::new().public_key())
            .is_err()
    );
    assert_ne!(
        composition_winning_keys_digest(
            expected.winning_keys(ProjectionContributor::Local),
            expected.winning_keys(ProjectionContributor::Platform)
        ),
        composition_winning_keys_digest(
            expected.winning_keys(ProjectionContributor::Platform),
            expected.winning_keys(ProjectionContributor::Local)
        )
    );
}

#[test]
fn source_inventory_checks_do_not_freeze_material_or_create_an_extra_generation() {
    let recipient = ProjectionRecipient::new().public_key();
    let inventories = inventories();
    let first = ProjectionCompositionPlan::new(
        &context(),
        [3; 16],
        recipient,
        &inventories,
        &BTreeSet::new(),
        &BTreeSet::new(),
        NOW,
    )
    .unwrap();
    let second = ProjectionCompositionPlan::new(
        &context(),
        [3; 16],
        recipient,
        &inventories,
        &BTreeSet::new(),
        &BTreeSet::new(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(first, second);
    // Values/material versions are intentionally absent. Each authority reads
    // current winning material only after its names have been rechecked.
    assert!(
        ProjectionCompositionPlan::new(
            &context(),
            [0; 16],
            recipient,
            &inventories,
            &BTreeSet::new(),
            &BTreeSet::new(),
            NOW
        )
        .is_err()
    );
}
