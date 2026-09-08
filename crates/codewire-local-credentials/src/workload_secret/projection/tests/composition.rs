use codewire_workload_secrets::compose_environment_projection;

use super::*;

const REQUEST_ID: [u8; 16] = [3; 16];
const PLATFORM_VALUE: &str = "synthetic-platform-winning-value";

fn platform_inventory(source: WorkloadSecretSource, keys: &[&str]) -> ProjectionSourceInventory {
    ProjectionSourceInventory {
        contributor: ProjectionContributor::Platform,
        source,
        source_identity: match source {
            WorkloadSecretSource::Organization => "/org-secrets/synthetic-organization",
            WorkloadSecretSource::Project => {
                "/projects/synthetic-organization/11111111-1111-4111-8111-111111111111"
            }
            WorkloadSecretSource::User => "/users/synthetic-owner",
            WorkloadSecretSource::ExplicitEnvironment => panic!("not a protected source"),
        }
        .into(),
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
    }
}

fn inventories(
    authority: &LocalCredentialAuthority<ObservedStore>,
    selected: &LocalLaunchSecretSelection,
    platform: ProjectionSourceInventory,
) -> Vec<ProjectionSourceInventory> {
    let mut inventories = authority.inventory_workload_projection(selected).unwrap();
    inventories.push(platform);
    inventories.sort_by_key(|inventory| inventory.source);
    inventories
}

fn platform_fragment(
    selected: &LocalLaunchSecretSelection,
    context: &ProjectionContext,
    recipient: [u8; 32],
    inventories: &[ProjectionSourceInventory],
) -> Vec<u8> {
    // Synthetic authenticated producer: only its own winners reach encryption.
    // No platform store, credentials, transport, or runtime admission is claimed.
    let plan = ProjectionCompositionPlan::new(
        context,
        REQUEST_ID,
        recipient,
        inventories,
        &selected.overridden_keys,
        &selected.reserved_keys,
        unix_millis().unwrap(),
    )
    .unwrap();
    let values = EnvironmentProjection::from_entries(
        plan.winning_keys(ProjectionContributor::Platform)
            .iter()
            .map(|key| {
                (
                    key.clone(),
                    Zeroizing::new(PLATFORM_VALUE.as_bytes().to_vec()),
                )
            }),
    )
    .unwrap();
    seal_environment_projection_fragment(
        values,
        context,
        recipient,
        ProjectionContributor::Platform,
        &plan,
        unix_millis().unwrap(),
    )
    .unwrap()
}

fn mixed_bundle(
    authority: &LocalCredentialAuthority<ObservedStore>,
    selected: &LocalLaunchSecretSelection,
    context: &ProjectionContext,
    recipient: [u8; 32],
    inventories: &[ProjectionSourceInventory],
) -> Vec<u8> {
    let local = authority
        .seal_workload_projection_fragment(selected, context, recipient, REQUEST_ID, inventories)
        .unwrap();
    let platform = platform_fragment(selected, context, recipient, inventories);
    compose_environment_projection(&local, &platform).unwrap()
}

#[test]
fn inventory_preserves_exact_complete_scopes_and_names_without_protected_reads() {
    let (_temp, authority, store, project_id) = fixture();
    *store.denied.lock().unwrap() = true;
    let captured = authority
        .inventory_workload_projection(&selection(project_id))
        .unwrap();
    assert_eq!(
        captured,
        [
            ProjectionSourceInventory {
                contributor: ProjectionContributor::Local,
                source: WorkloadSecretSource::Project,
                source_identity: format!("local:project:{project_id}"),
                keys: BTreeSet::from(["SHARED".into()]),
            },
            ProjectionSourceInventory {
                contributor: ProjectionContributor::Local,
                source: WorkloadSecretSource::User,
                source_identity: "local:user".into(),
                keys: BTreeSet::from(["OVERRIDDEN".into(), "SHARED".into()]),
            },
        ]
    );
    // Inventory remains complete even when a named value is not ready.
    authority.connection().unwrap().execute("UPDATE workload_secrets SET material_state = 'pending_write' WHERE scope_kind = 'user' AND key = 'SHARED'", []).unwrap();
    assert_eq!(
        authority
            .inventory_workload_projection(&selection(project_id))
            .unwrap(),
        captured
    );
    assert!(
        authority
            .inventory_workload_projection(&LocalLaunchSecretSelection::default())
            .unwrap()
            .is_empty()
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn invalid_inventory_selection_denies_without_protected_reads() {
    let (_temp, authority, store, project_id) = fixture();
    *store.denied.lock().unwrap() = true;
    let mut reserved = selection(project_id);
    reserved.reserved_keys.insert("SHARED".into());
    let mut invalid_key = selection(project_id);
    invalid_key.overridden_keys.insert("INVALID-KEY".into());
    for selected in [
        LocalLaunchSecretSelection {
            project_id: Some(Uuid::nil()),
            ..Default::default()
        },
        LocalLaunchSecretSelection {
            project_id: Some(Uuid::new_v4()),
            ..Default::default()
        },
        reserved,
        invalid_key,
    ] {
        assert!(authority.inventory_workload_projection(&selected).is_err());
    }
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn local_user_wins_over_platform_project_and_only_winners_are_read() {
    let (_temp, authority, store, _) = fixture();
    let selected = LocalLaunchSecretSelection {
        user: true,
        overridden_keys: BTreeSet::from(["OVERRIDDEN".into()]),
        ..Default::default()
    };
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Project, &["SHARED", "PLATFORM_ONLY"]),
    );
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(
        *store.reads.lock().unwrap(),
        [user_entry(&authority, "SHARED")]
    );
    assert!(
        ProjectionRecipient::new()
            .open(&bundle, &expected, unix_millis().unwrap())
            .is_err()
    );
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("PLATFORM_ONLY", PLATFORM_VALUE), ("SHARED", "user-value")]
    );
}

#[test]
fn platform_user_wins_over_local_project_without_reading_denied_loser() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = LocalLaunchSecretSelection {
        project_id: Some(project_id),
        ..Default::default()
    };
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::User, &["SHARED"]),
    );
    *store.denied.lock().unwrap() = true;
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("SHARED", PLATFORM_VALUE)]
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn local_precedence_is_resolved_before_global_winner_material_read() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &["SHARED"]),
    );
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(
        *store.reads.lock().unwrap(),
        [user_entry(&authority, "SHARED")]
    );
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("SHARED", "user-value")]
    );
}

#[test]
fn ordinary_names_suppress_both_authorities_without_material_reads() {
    let (_temp, authority, store, project_id) = fixture();
    let mut selected = selection(project_id);
    selected
        .overridden_keys
        .extend(["SHARED".into(), "PLATFORM_ONLY".into()]);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(
            WorkloadSecretSource::Organization,
            &["SHARED", "PLATFORM_ONLY"],
        ),
    );
    *store.denied.lock().unwrap() = true;
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .len(),
        0
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn missing_extra_wrong_identity_role_or_reordered_local_inventory_denies_before_get() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let original = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &[]),
    );
    for variant in 0..9 {
        let mut changed = original.clone();
        match variant {
            0 => {
                changed[1].keys.remove("SHARED");
            }
            1 => {
                changed[1].keys.insert("EXTRA".into());
            }
            2 => {
                changed.remove(1);
            }
            3 => changed[1].source_identity = format!("local:project:{}", Uuid::new_v4()),
            4 => changed[2].source_identity = "local:user:other".into(),
            5 => changed[1].contributor = ProjectionContributor::Platform,
            6 => changed.swap(1, 2),
            7 => changed.push(changed[1].clone()),
            _ => changed[1].source = WorkloadSecretSource::User,
        }
        assert!(
            authority
                .seal_workload_projection_fragment(
                    &selected,
                    &context(),
                    ProjectionRecipient::new().public_key(),
                    REQUEST_ID,
                    &changed
                )
                .is_err(),
            "variant {variant}"
        );
        assert!(store.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn added_deleted_or_reassigned_names_invalidate_inventory_before_get() {
    for variant in 0..3 {
        let (_temp, authority, store, project_id) = fixture();
        let selected = selection(project_id);
        let original = inventories(
            &authority,
            &selected,
            platform_inventory(WorkloadSecretSource::Organization, &[]),
        );
        match variant {
            0 => {
                authority
                    .set_user_workload_secret(
                        "ADDED",
                        ProtectedValue::from_slice(b"synthetic-added").unwrap(),
                    )
                    .unwrap();
            }
            1 => {
                authority.delete_user_workload_secret("SHARED").unwrap();
            }
            _ => {
                authority.delete_user_workload_secret("OVERRIDDEN").unwrap();
                authority
                    .set_project_workload_secret(
                        project_id,
                        "OVERRIDDEN",
                        ProtectedValue::from_slice(b"synthetic-moved").unwrap(),
                    )
                    .unwrap();
            }
        }
        store.reads.lock().unwrap().clear();
        assert!(
            authority
                .seal_workload_projection_fragment(
                    &selected,
                    &context(),
                    ProjectionRecipient::new().public_key(),
                    REQUEST_ID,
                    &original
                )
                .is_err()
        );
        assert!(store.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn missing_or_denied_winning_material_never_falls_back_to_lower_rank() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &["SHARED"]),
    );
    let entry = user_entry(&authority, "SHARED");
    for denied in [true, false] {
        *store.denied.lock().unwrap() = denied;
        if !denied {
            store.delete(&entry).unwrap();
        }
        assert!(
            authority
                .seal_workload_projection_fragment(
                    &selected,
                    &context(),
                    ProjectionRecipient::new().public_key(),
                    REQUEST_ID,
                    &inventories
                )
                .is_err()
        );
        assert_eq!(
            store.reads.lock().unwrap().as_slice(),
            std::slice::from_ref(&entry)
        );
        store.reads.lock().unwrap().clear();
    }
}

#[test]
fn empty_selected_local_scope_is_complete_and_cannot_be_omitted() {
    let (_temp, authority, store, _) = fixture();
    let empty_project = authority.create_secret_project("empty-synthetic").unwrap();
    let selected = LocalLaunchSecretSelection {
        project_id: Some(empty_project.id),
        ..Default::default()
    };
    let mut inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::User, &["SHARED"]),
    );
    assert!(inventories[0].keys.is_empty());
    *store.denied.lock().unwrap() = true;
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("SHARED", PLATFORM_VALUE)]
    );
    inventories.remove(0);
    assert!(
        authority
            .seal_workload_projection_fragment(
                &selected,
                &context(),
                ProjectionRecipient::new().public_key(),
                REQUEST_ID,
                &inventories
            )
            .is_err()
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn same_key_rotation_after_inventory_uses_current_material_without_new_inventory_identity() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &[]),
    );
    let old_entry = user_entry(&authority, "SHARED");
    authority
        .set_user_workload_secret(
            "SHARED",
            ProtectedValue::from_slice(b"latest-synthetic-value").unwrap(),
        )
        .unwrap();
    let new_entry = user_entry(&authority, "SHARED");
    assert_ne!(new_entry, old_entry);
    store.reads.lock().unwrap().clear();
    assert_eq!(
        authority.inventory_workload_projection(&selected).unwrap(),
        inventories[1..]
    );
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let bundle = mixed_bundle(
        &authority,
        &selected,
        &expected,
        recipient.public_key(),
        &inventories,
    );
    assert_eq!(*store.reads.lock().unwrap(), [new_entry]);
    assert_eq!(
        recipient
            .open(&bundle, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("SHARED", "latest-synthetic-value")]
    );
}

#[test]
fn malformed_context_request_recipient_and_reserved_names_deny_before_get() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &[]),
    );
    for variant in 0..6 {
        let mut expected = context();
        let mut recipient = ProjectionRecipient::new().public_key();
        let mut request_id = REQUEST_ID;
        let mut selected = selected.clone();
        match variant {
            0 => expected.deadline_unix_ms = 1,
            1 => expected.operation_generation = 0,
            2 => recipient = [0; 32],
            3 => request_id = [0; 16],
            4 => {
                selected.reserved_keys.insert("SHARED".into());
            }
            _ => {
                selected.reserved_keys.insert("OVERRIDDEN".into());
            }
        }
        assert!(
            authority
                .seal_workload_projection_fragment(
                    &selected,
                    &expected,
                    recipient,
                    request_id,
                    &inventories
                )
                .is_err()
        );
        assert!(store.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn invalid_foreign_inventory_and_global_union_fail_before_local_material_read() {
    let (_temp, authority, store, _) = fixture();
    let selected = LocalLaunchSecretSelection {
        user: true,
        overridden_keys: BTreeSet::from(["OVERRIDDEN".into()]),
        ..Default::default()
    };
    for variant in 0..4 {
        let mut foreign = platform_inventory(WorkloadSecretSource::Project, &[]);
        match variant {
            0 => {
                foreign.keys.insert("INVALID-KEY".into());
            }
            1 => foreign.source_identity.clear(),
            2 => foreign.source = WorkloadSecretSource::User,
            _ => {
                foreign.keys = (0..MAX_WORKLOAD_SECRETS)
                    .map(|index| format!("FOREIGN_{index}"))
                    .collect()
            }
        }
        let supplied = inventories(&authority, &selected, foreign);
        assert!(
            authority
                .seal_workload_projection_fragment(
                    &selected,
                    &context(),
                    ProjectionRecipient::new().public_key(),
                    REQUEST_ID,
                    &supplied
                )
                .is_err()
        );
        assert!(store.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn blocking_winner_read_cannot_extend_the_mixed_original_deadline() {
    let (_temp, authority, store, project_id) = fixture();
    let selected = selection(project_id);
    let inventories = inventories(
        &authority,
        &selected,
        platform_inventory(WorkloadSecretSource::Organization, &[]),
    );
    let mut expected = context();
    expected.deadline_unix_ms = unix_millis().unwrap() + 200;
    store
        .block_until_ms
        .store(expected.deadline_unix_ms, Ordering::Relaxed);
    assert!(
        authority
            .seal_workload_projection_fragment(
                &selected,
                &expected,
                ProjectionRecipient::new().public_key(),
                REQUEST_ID,
                &inventories
            )
            .is_err()
    );
    assert_eq!(
        *store.reads.lock().unwrap(),
        [user_entry(&authority, "SHARED")]
    );
}
