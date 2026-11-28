//! A bound local secret projects its placeholder, never its value, in a
//! whole projection and in a composed one; without its placeholder it is
//! refused by name and never projected raw (#4003). Synthetic values only.

use codewire_access::{
    BindingWrite, EnvironmentId, PlaceholderPrefix, SecretKind, SecretPlaceholder, SecretSlot,
    StoredBinding, StoredPresentation,
};
use codewire_workload_secrets::compose_environment_projection;

use super::*;

const CANARY: &str = "canary-local-bound-value-never-projected";

fn binding() -> BindingWrite {
    BindingWrite::Bind(StoredBinding {
        hosts: vec!["api.fancy.example".into()],
        presentation: StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("Bearer".into()),
        },
        prefix: Some("ft_".into()),
        preset: None,
    })
}

fn canary() -> Option<ProtectedValue> {
    Some(ProtectedValue::from_slice(CANARY.as_bytes()).unwrap())
}

/// The fixture with a bound personal secret and a bound project secret.
fn bound_fixture() -> (
    TempDir,
    LocalCredentialAuthority<ObservedStore>,
    ObservedStore,
    Uuid,
) {
    let (temp, authority, store, project_id) = fixture();
    authority
        .write_user_workload_secret("FANCY_TOKEN", canary(), binding(), true)
        .unwrap();
    authority
        .write_project_workload_secret(project_id, "PROJECT_TOKEN", canary(), binding(), true)
        .unwrap();
    store.reads.lock().unwrap().clear();
    (temp, authority, store, project_id)
}

fn entry(
    authority: &LocalCredentialAuthority<ObservedStore>,
    scope: SecretScope<'_>,
    key: &str,
) -> (ProtectedEntryId, Uuid, u64) {
    let connection = authority.connection().unwrap();
    let secret = crate::workload_secret::load_secret_by_key(&connection, scope, key)
        .unwrap()
        .unwrap();
    (
        secret.protected_entry_id,
        secret.binding_id.unwrap(),
        secret.metadata.binding_generation,
    )
}

/// The placeholder `key` in `kind`'s set `collection` should project as,
/// derived from its record's binding ID and generation.
fn expected(
    authority: &LocalCredentialAuthority<ObservedStore>,
    kind: SecretKind,
    collection: &str,
    scope: SecretScope<'_>,
    key: &str,
) -> String {
    let (_, binding_id, generation) = entry(authority, scope, key);
    let connection = authority.connection().unwrap();
    let (_, application_key) = authority.application_secret_key(&connection).unwrap();
    SecretPlaceholder::derive(
        &application_key,
        &EnvironmentId::parse(Uuid::from_bytes(context().environment_id).to_string()).unwrap(),
        &SecretSlot::new(kind, collection, key).unwrap(),
        binding_id.as_bytes(),
        generation,
        Some(&PlaceholderPrefix::parse("ft_").unwrap()),
    )
    .as_str()
    .to_owned()
}

fn authority_id(authority: &LocalCredentialAuthority<ObservedStore>) -> String {
    authority
        .connection()
        .unwrap()
        .query_row(
            "SELECT value FROM authority_metadata WHERE key = 'authority_id'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn local_bound_secrets_project_their_placeholders_and_never_read_their_values() {
    let (_temp, authority, store, project_id) = bound_fixture();
    let recipient = ProjectionRecipient::new();
    let launch = context();
    let sealed = authority
        .seal_workload_projection(&selection(project_id), &launch, recipient.public_key())
        .unwrap();
    let opened = recipient
        .open(&sealed, &launch, unix_millis().unwrap())
        .unwrap();
    let entries: BTreeMap<String, String> = opened
        .entries()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let reads = store.reads.lock().unwrap().clone();
    let local_id = authority_id(&authority);
    assert_eq!(local_id.len(), 32);
    let personal = expected(
        &authority,
        SecretKind::Local,
        &local_id,
        SecretScope::User,
        "FANCY_TOKEN",
    );
    let project = expected(
        &authority,
        SecretKind::Project,
        &project_id.to_string(),
        SecretScope::Project(&project_id),
        "PROJECT_TOKEN",
    );
    assert_eq!(
        entries,
        BTreeMap::from([
            ("FANCY_TOKEN".to_owned(), personal.clone()),
            ("PROJECT_TOKEN".to_owned(), project.clone()),
            ("SHARED".to_owned(), "user-value".to_owned()),
        ])
    );
    assert!(entries.values().all(|value| !value.contains(CANARY)));
    assert!(!personal.contains(&local_id) && !project.contains(&project_id.to_string()));
    for (scope, key) in [
        (SecretScope::User, "FANCY_TOKEN"),
        (SecretScope::Project(&project_id), "PROJECT_TOKEN"),
    ] {
        let (bound_entry, _, _) = entry(&authority, scope, key);
        assert!(!reads.contains(&bound_entry), "{key}'s value was read");
    }
    assert!(reads.contains(&user_entry(&authority, "SHARED")));
}

#[test]
fn local_bound_secret_projects_its_placeholder_in_a_composed_projection() {
    let (_temp, authority, store, project_id) = bound_fixture();
    let selected = LocalLaunchSecretSelection {
        project_id: Some(project_id),
        user: true,
        overridden_keys: BTreeSet::from(["OVERRIDDEN".into()]),
        reserved_keys: BTreeSet::new(),
    };
    let recipient = ProjectionRecipient::new();
    let launch = context();
    let mut inventories = authority.inventory_workload_projection(&selected).unwrap();
    inventories.push(ProjectionSourceInventory {
        contributor: ProjectionContributor::Platform,
        source: WorkloadSecretSource::Organization,
        source_identity: "/org-secrets/synthetic-organization".into(),
        keys: BTreeSet::new(),
    });
    inventories.sort_by_key(|inventory| inventory.source);
    let local = authority
        .seal_workload_projection_fragment(
            &selected,
            &launch,
            recipient.public_key(),
            [3; 16],
            &inventories,
        )
        .unwrap();
    let plan = ProjectionCompositionPlan::new(
        &launch,
        [3; 16],
        recipient.public_key(),
        &inventories,
        &selected.overridden_keys,
        &selected.reserved_keys,
        unix_millis().unwrap(),
    )
    .unwrap();
    let platform = seal_environment_projection_fragment(
        EnvironmentProjection::from_entries(Vec::new()).unwrap(),
        &launch,
        recipient.public_key(),
        ProjectionContributor::Platform,
        &plan,
        unix_millis().unwrap(),
    )
    .unwrap();
    let composed = compose_environment_projection(&local, &platform).unwrap();
    let opened = recipient
        .open(&composed, &launch, unix_millis().unwrap())
        .unwrap();
    let entries: BTreeMap<&str, &str> = opened.entries().collect();
    let personal = expected(
        &authority,
        SecretKind::Local,
        &authority_id(&authority),
        SecretScope::User,
        "FANCY_TOKEN",
    );
    assert_eq!(entries.get("FANCY_TOKEN"), Some(&personal.as_str()));
    assert!(entries.values().all(|value| !value.contains(CANARY)));
    let (bound_entry, _, _) = entry(&authority, SecretScope::User, "FANCY_TOKEN");
    assert!(!store.reads.lock().unwrap().contains(&bound_entry));
}

/// A placeholder key the store won't give, or an authority ID that isn't
/// its kind's spelling (a set with no slot), refuses the projection by the
/// secret's name before any value is read; made plain, it projects raw.
#[test]
fn local_bound_secret_without_its_placeholder_is_refused_by_name_never_raw() {
    let only_fancy = LocalLaunchSecretSelection {
        user: true,
        overridden_keys: BTreeSet::from(["SHARED".into(), "OVERRIDDEN".into()]),
        ..Default::default()
    };
    let refused = LocalCredentialError::BoundSecretUnprojectable("FANCY_TOKEN".into());

    let (_temp, authority, store, _) = bound_fixture();
    *store.denied.lock().unwrap() = true;
    assert_eq!(
        authority
            .seal_workload_projection(
                &only_fancy,
                &context(),
                ProjectionRecipient::new().public_key()
            )
            .unwrap_err(),
        refused
    );
    let (bound_entry, _, _) = entry(&authority, SecretScope::User, "FANCY_TOKEN");
    assert!(!store.reads.lock().unwrap().contains(&bound_entry));

    let (_temp, authority, store, _) = bound_fixture();
    authority
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO authority_metadata(key, value) VALUES ('authority_id', 'local-user')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )
        .unwrap();
    assert_eq!(
        authority
            .seal_workload_projection(
                &only_fancy,
                &context(),
                ProjectionRecipient::new().public_key()
            )
            .unwrap_err(),
        refused
    );
    let (bound_entry, _, _) = entry(&authority, SecretScope::User, "FANCY_TOKEN");
    assert!(!store.reads.lock().unwrap().contains(&bound_entry));

    authority
        .write_user_workload_secret("FANCY_TOKEN", canary(), BindingWrite::Plain, true)
        .unwrap();
    let recipient = ProjectionRecipient::new();
    let launch = context();
    let sealed = authority
        .seal_workload_projection(&only_fancy, &launch, recipient.public_key())
        .unwrap();
    assert_eq!(
        recipient
            .open(&sealed, &launch, unix_millis().unwrap())
            .unwrap()
            .entries()
            .collect::<Vec<_>>(),
        [("FANCY_TOKEN", CANARY)]
    );
}
