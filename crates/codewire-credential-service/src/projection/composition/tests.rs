use std::collections::BTreeSet;

use codewire_workload_secrets::{
    ProjectionContext, ProjectionContributor, ProjectionSourceInventory, WorkloadSecretSource,
};

use super::*;

fn row(key: &str) -> KeyRow {
    KeyRow {
        key: key.into(),
        scope: "synthetic".into(),
        scope_id: "synthetic".into(),
    }
}

fn inventory(
    contributor: ProjectionContributor,
    source: WorkloadSecretSource,
    identity: &str,
    keys: &[&str],
) -> ProjectionSourceInventory {
    ProjectionSourceInventory {
        contributor,
        source,
        source_identity: identity.into(),
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
    }
}

fn selection() -> PlatformProjectionSelection {
    PlatformProjectionSelection {
        creator: "owner".into(),
        organization: "organization".into(),
        organization_selected: false,
        project_id: None,
        user_selected: false,
        profile: None,
        ordinary_keys: BTreeSet::new(),
        reserved_keys: BTreeSet::new(),
    }
}

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 1,
        selection_sha256: [2; 32],
        deadline_unix_ms: 10_000,
    }
}

#[test]
fn mixed_precedence_selects_only_platform_winners_in_both_directions() {
    let selected = selection();
    let platform_project = inventory(
        ProjectionContributor::Platform,
        WorkloadSecretSource::Project,
        "/projects/organization/project",
        &["PLATFORM_ONLY", "SHARED"],
    );
    let local_user = inventory(
        ProjectionContributor::Local,
        WorkloadSecretSource::User,
        "/users/local-owner",
        &["LOCAL_ONLY", "SHARED"],
    );
    let first = plan(
        &selected,
        &[local_user],
        &[platform_project],
        &context(),
        [3; 16],
        [4; 32],
        1,
    )
    .unwrap();
    assert_eq!(
        first.winning_keys(ProjectionContributor::Platform),
        &BTreeSet::from(["PLATFORM_ONLY".into()])
    );

    let local_project = inventory(
        ProjectionContributor::Local,
        WorkloadSecretSource::Project,
        "/projects/local/project",
        &["LOCAL_ONLY", "SHARED"],
    );
    let platform_user = inventory(
        ProjectionContributor::Platform,
        WorkloadSecretSource::User,
        "/users/platform-owner",
        &["PLATFORM_ONLY", "SHARED"],
    );
    let second = plan(
        &selected,
        &[local_project],
        &[platform_user],
        &context(),
        [3; 16],
        [4; 32],
        1,
    )
    .unwrap();
    assert_eq!(
        second.winning_keys(ProjectionContributor::Platform),
        &BTreeSet::from(["PLATFORM_ONLY".into(), "SHARED".into()])
    );
}

#[test]
fn platform_winner_paths_use_highest_selected_platform_rank_only() {
    let inventories = vec![
        (
            "/projects/organization/project".into(),
            vec![row("PROJECT"), row("SHARED")],
        ),
        ("/users/owner".into(), vec![row("SHARED"), row("USER")]),
    ];
    assert_eq!(
        winner_paths(
            &inventories,
            &BTreeSet::from(["PROJECT".into(), "SHARED".into()])
        )
        .unwrap(),
        BTreeMap::from([
            ("PROJECT".into(), "/projects/organization/project".into()),
            ("SHARED".into(), "/users/owner".into()),
        ])
    );
    assert!(winner_paths(&inventories, &BTreeSet::from(["MISSING".into()])).is_err());
}

#[test]
fn local_inventory_is_closed_complete_and_canonical_before_capture() {
    let wire = |source, identity: &str, keys: &[&str]| v1::EnvironmentProjectionInventory {
        source,
        source_identity: identity.into(),
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
    };
    assert!(decode_local(&[]).is_err());
    assert!(
        decode_local(&[wire(
            v1::EnvironmentProjectionSource::Organization as i32,
            "/org-secrets/not-local",
            &["KEY"]
        )])
        .is_err()
    );
    assert!(
        decode_local(&[
            wire(
                v1::EnvironmentProjectionSource::User as i32,
                "/users/owner",
                &["KEY"]
            ),
            wire(
                v1::EnvironmentProjectionSource::Project as i32,
                "/projects/owner/project",
                &["OTHER"]
            ),
        ])
        .is_err()
    );
}

#[test]
fn composition_requires_both_contributors_and_one_inventory_per_rank() {
    let selected = selection();
    let platform = inventory(
        ProjectionContributor::Platform,
        WorkloadSecretSource::Project,
        "/projects/organization/project",
        &["KEY"],
    );
    assert!(
        plan(
            &selected,
            &[],
            std::slice::from_ref(&platform),
            &context(),
            [3; 16],
            [4; 32],
            1,
        )
        .is_err()
    );
    let local_same_rank = inventory(
        ProjectionContributor::Local,
        WorkloadSecretSource::Project,
        "/projects/local/project",
        &["OTHER"],
    );
    assert!(
        plan(
            &selected,
            &[local_same_rank],
            &[platform],
            &context(),
            [3; 16],
            [4; 32],
            1,
        )
        .is_err()
    );
}
