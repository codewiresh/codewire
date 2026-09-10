use super::*;

#[test]
fn tenant_lock_encoding_matches_existing_writer_and_projects_share_org_lock() {
    let org = DekContext::from_secret_path("/org-secrets/synthetic-org").unwrap();
    let project = DekContext::from_secret_path("/projects/synthetic-org/development").unwrap();
    let user = DekContext::from_secret_path("/users/synthetic-creator").unwrap();
    assert_eq!(scope_lock_key(&org), 3_674_221_173_805_525_420);
    assert_eq!(scope_lock_key(&project), scope_lock_key(&org));
    assert_eq!(scope_lock_key(&user), -498_343_500_859_002_603);
}

#[test]
fn projection_references_require_exact_canonical_platform_ids() {
    let id = "a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417";
    assert_eq!(exact_id(&format!("platform:id:{id}")).unwrap(), id);
    for invalid in [
        id.to_owned(),
        format!("local:id:{id}"),
        format!("platform:{id}"),
        "platform:development".into(),
        format!("platform:id:{}", id.to_uppercase()),
        format!("platform:id:{}", Uuid::nil()),
    ] {
        assert!(exact_id(&invalid).is_err());
    }
}

#[test]
fn projection_paths_have_fixed_precedence_and_immutable_owners() {
    let mut selection = PlatformProjectionSelection {
        creator: "creator".into(),
        organization: "organization".into(),
        organization_selected: true,
        project_id: Some("a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417".into()),
        user_selected: true,
        profile: None,
        ordinary_keys: BTreeSet::new(),
        reserved_keys: BTreeSet::new(),
    };
    assert_eq!(
        paths(&selection),
        [
            "/org-secrets/organization",
            "/projects/organization/a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417",
            "/users/creator",
        ]
    );
    selection.organization_selected = false;
    selection.project_id = None;
    selection.user_selected = false;
    assert!(paths(&selection).is_empty());
}

#[test]
fn source_metadata_rejects_absent_mismatched_pins_and_invalid_key_names() {
    let mut scope = crate::tests::scope();
    let mut metadata = ProjectionMetadata {
        organization_selected: false,
        user_placement: Some("platform".into()),
        project_reference: None,
        credential_reference: Some(format!(
            "platform:id:{}",
            scope.profile_id.as_ref().unwrap()
        )),
        ordinary_keys: vec!["CONFIGURED".into()],
        selection_valid: true,
    };
    assert!(metadata.selection(&scope, BTreeSet::new()).is_ok());
    metadata.credential_reference = None;
    assert!(metadata.selection(&scope, BTreeSet::new()).is_err());
    scope.profile_id = None;
    scope.profile_revision = None;
    assert!(metadata.selection(&scope, BTreeSet::new()).is_ok());
    metadata.user_placement = Some("local".into());
    assert!(metadata.selection(&scope, BTreeSet::new()).is_err());
    metadata.user_placement = Some("platform".into());
    metadata.ordinary_keys = vec!["UNSAFE-KEY".into()];
    assert!(metadata.selection(&scope, BTreeSet::new()).is_err());
    metadata.ordinary_keys = vec!["DUPLICATE".into(), "DUPLICATE".into()];
    assert!(metadata.selection(&scope, BTreeSet::new()).is_err());
}

#[test]
fn winning_metadata_uses_shared_precedence_and_combined_configuration_bound() {
    let row = |key: &str| KeyRow {
        key: key.into(),
        scope: "user".into(),
        scope_id: "creator".into(),
    };
    let mut inventories = vec![
        (
            "/org-secrets/organization".into(),
            vec![row("SHARED"), row("ORG")],
        ),
        ("/projects/organization/project".into(), vec![row("SHARED")]),
        (
            "/users/creator".into(),
            vec![row("SHARED"), row("CONFIGURED")],
        ),
    ];
    let mut selection = PlatformProjectionSelection {
        creator: "creator".into(),
        organization: "organization".into(),
        organization_selected: true,
        project_id: None,
        user_selected: true,
        profile: None,
        ordinary_keys: ["CONFIGURED".into()].into(),
        reserved_keys: BTreeSet::new(),
    };
    let winners = selected_winners(&inventories, &selection).unwrap();
    assert_eq!(
        winners.get("SHARED").map(String::as_str),
        Some("/users/creator")
    );
    assert!(!winners.contains_key("CONFIGURED"));
    inventories[2]
        .1
        .extend((0..253).map(|i| row(&format!("KEY_{i}"))));
    assert!(selected_winners(&inventories, &selection).is_ok()); // 256 union names.
    selection.ordinary_keys.insert("ONE_MORE_CONFIGURED".into());
    assert!(selected_winners(&inventories, &selection).is_err());
}
