use super::*;
use codewire_project::{CredentialBinding, StoragePlacement};

const PROJECT: &str = "96b91974-a022-4c0f-bbb9-3f8398b9f86e";
const PROFILE: &str = "98657d60-ce77-40c7-897c-6323b52e3a96";

fn capture() -> ProjectionCapture {
    ProjectionCapture {
        creator: Some("synthetic-creator".into()),
        profile_id: None,
        profile_revision: None,
        profile_revision_exists: false,
        profile_slots: Vec::new(),
        profile_slots_overflow: false,
    }
}

fn selected_profile() -> (ProjectSpec, ProjectionCapture) {
    let project = ProjectSpec {
        credentials: Some(CredentialBinding {
            profile: format!("platform:id:{PROFILE}"),
        }),
        ..ProjectSpec::default()
    };
    let mut captured = capture();
    captured.profile_id = Some(PROFILE.into());
    captured.profile_revision = Some(3);
    captured.profile_revision_exists = true;
    captured.profile_slots = vec!["codex".into()];
    (project, captured)
}

#[test]
fn no_selection_is_none_and_app_only_selection_never_needs_a_profile() {
    assert_eq!(
        capture().selection(&ProjectSpec::default(), "synthetic-org", 7),
        Ok(None)
    );
    for source in 0..3 {
        let mut project = ProjectSpec::default();
        match source {
            0 => project.secrets.organization = true,
            1 => project.secrets.project = format!("platform:id:{PROJECT}"),
            2 => project.secrets.user = Some(StoragePlacement::Platform),
            _ => unreachable!(),
        }
        let selected = capture()
            .selection(&project, "synthetic-org", 7)
            .unwrap()
            .unwrap();
        assert!(selected.profile.is_none());
        assert_eq!(selected.organization_selected, source == 0);
        assert_eq!(
            selected.project_id.as_deref(),
            (source == 1).then_some(PROJECT)
        );
        assert_eq!(selected.user_selected, source == 2);
        assert_eq!(
            selected.reserved_keys,
            platform_projection_reserved_keys([]).unwrap()
        );
    }
}

#[test]
fn profile_uses_exact_pinned_revision_and_shared_reserved_key_reducer() {
    let (mut project, mut captured) = selected_profile();
    project.secrets.organization = true;
    project.secrets.project = format!("platform:id:{PROJECT}");
    project.secrets.user = Some(StoragePlacement::Platform);
    captured.profile_slots = ["codex", "openai", "anthropic", "github", "ssh"]
        .map(str::to_owned)
        .into();
    let selected = captured
        .selection(&project, "synthetic-org", 7)
        .unwrap()
        .unwrap();
    assert_eq!(selected.profile, Some((PROFILE.into(), 3)));
    assert_eq!(selected.creator, "synthetic-creator");
    assert_eq!(selected.organization, "synthetic-org");
    assert_eq!(
        selected.reserved_keys,
        platform_projection_reserved_keys(captured.profile_slots.iter().map(String::as_str))
            .unwrap()
    );
    captured.profile_revision = Some(4);
    let changed = captured
        .selection(&project, "synthetic-org", 7)
        .unwrap()
        .unwrap();
    assert_ne!(selected.sha256().unwrap(), changed.sha256().unwrap());
}

#[test]
fn exact_pinned_empty_profile_is_valid_but_missing_revision_is_not() {
    let (project, mut captured) = selected_profile();
    captured.profile_slots.clear();
    let selected = captured
        .selection(&project, "synthetic-org", 7)
        .unwrap()
        .unwrap();
    assert_eq!(selected.profile, Some((PROFILE.into(), 3)));
    assert_eq!(
        selected.reserved_keys,
        platform_projection_reserved_keys([]).unwrap()
    );
    assert_eq!(
        captured.managed_credential_clients(&project).unwrap(),
        Default::default()
    );

    captured.profile_revision_exists = false;
    assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
}

#[test]
fn digest_binds_ordinary_names_but_never_their_values_or_an_extra_generation() {
    let mut project = ProjectSpec::default();
    project.secrets.user = Some(StoragePlacement::Platform);
    project
        .environment
        .insert("DATABASE_URL".into(), "synthetic-ordinary-first".into());
    let selected = capture()
        .selection(&project, "synthetic-org", 7)
        .unwrap()
        .unwrap();
    assert_eq!(selected.ordinary_keys, ["DATABASE_URL".into()].into());
    assert!(!format!("{selected:?}").contains("synthetic-ordinary-first"));
    project
        .environment
        .insert("DATABASE_URL".into(), "synthetic-ordinary-second".into());
    let changed = capture()
        .selection(&project, "synthetic-org", 8)
        .unwrap()
        .unwrap();
    assert_eq!(selected.sha256(), changed.sha256());
    project
        .environment
        .insert("SECOND_NAME".into(), "synthetic-ordinary-second".into());
    let renamed = capture()
        .selection(&project, "synthetic-org", 8)
        .unwrap()
        .unwrap();
    assert_ne!(selected.sha256(), renamed.sha256());
}

#[test]
fn capture_errors_are_content_free_and_do_not_require_a_live_cleanup_binding() {
    let project = ProjectSpec::default();
    for generation in [0, -1, i64::MIN] {
        assert_eq!(
            capture().selection(&project, "synthetic-org", generation),
            Err(Error)
        );
    }
    let (project, mut captured) = selected_profile();
    captured.profile_id = None;
    captured.profile_revision = None;
    captured.profile_revision_exists = false;
    captured.profile_slots.clear();
    // The loader stores this error as data, allowing teardown after authority
    // cleanup removed the binding. Creation/rendering must refuse the error.
    assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
    assert_eq!(
        Error.to_string(),
        "invalid platform environment projection selection"
    );
    let mut missing_creator = capture();
    missing_creator.creator = None;
    assert_eq!(
        missing_creator.selection(&ProjectSpec::default(), "synthetic-org", 7),
        Err(Error)
    );
}

#[test]
fn missing_partial_stale_and_orphan_profile_bindings_are_rejected() {
    for changed_field in 0..6 {
        let (mut project, mut captured) = selected_profile();
        match changed_field {
            0 => captured.profile_id = None,
            1 => captured.profile_revision = None,
            2 => captured.profile_id = Some(PROJECT.into()),
            3 => captured.profile_revision = Some(0),
            4 => captured.profile_revision_exists = false,
            5 => project.credentials = None,
            _ => unreachable!(),
        }
        assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
    }
}

#[test]
fn bare_local_nil_and_noncanonical_storage_references_are_not_reresolved() {
    for reference in [
        "work",
        "platform:work",
        "platform:user/work",
        "local:id:98657d60-ce77-40c7-897c-6323b52e3a96",
        "platform:id:00000000-0000-0000-0000-000000000000",
        "platform:id:98657D60-CE77-40C7-897C-6323B52E3A96",
    ] {
        let (mut project, captured) = selected_profile();
        project.credentials.as_mut().unwrap().profile = reference.into();
        assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
        let mut project = ProjectSpec::default();
        project.secrets.project = reference.into();
        assert_eq!(
            capture().selection(&project, "synthetic-org", 7),
            Err(Error)
        );
    }
    let mut project = ProjectSpec::default();
    project.secrets.user = Some(StoragePlacement::Local);
    assert_eq!(
        capture().selection(&project, "synthetic-org", 7),
        Err(Error)
    );
}

#[test]
fn duplicate_unknown_and_truncated_slots_fail_instead_of_changing_reserved_keys() {
    for slots in [vec!["codex", "codex"], vec!["unknown"], vec!["codex", ""]] {
        let (project, mut captured) = selected_profile();
        captured.profile_slots = slots.into_iter().map(str::to_owned).collect();
        assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
    }
    let (project, mut captured) = selected_profile();
    captured.profile_slots = (0..65).map(|slot| format!("slot-{slot}")).collect();
    assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
    captured.profile_slots = vec!["codex".into()];
    captured.profile_slots_overflow = true;
    assert_eq!(captured.selection(&project, "synthetic-org", 7), Err(Error));
}

#[test]
fn captured_clients_are_exact_slots_not_provider_families_or_global_configuration() {
    for (slots, encoded) in [
        (vec!["codex"], "v1:codex"),
        (vec!["openai"], "v1:openai"),
        (vec!["anthropic"], "v1:anthropic"),
        (vec!["github"], "v1:none"),
        (vec!["ssh"], "v1:ssh"),
        (vec!["codex", "openai"], "v1:codex,openai"),
        (
            vec!["codex", "openai", "anthropic", "github", "ssh"],
            "v1:codex,openai,anthropic,ssh",
        ),
    ] {
        let (project, mut captured) = selected_profile();
        captured.profile_slots = slots.into_iter().map(str::to_owned).collect();
        assert!(captured.selection(&project, "synthetic-org", 7).is_ok());
        assert_eq!(
            captured
                .managed_credential_clients(&project)
                .unwrap()
                .encode(),
            encoded
        );
    }
    assert_eq!(
        capture()
            .managed_credential_clients(&ProjectSpec::default())
            .unwrap()
            .encode(),
        "v1:none"
    );
}

#[test]
fn only_selected_clients_reject_declared_routing_collisions_without_reading_values() {
    for (slot, name) in [
        ("codex", "CODEX_HOME"),
        ("openai", "OPENAI_BASE_URL"),
        ("anthropic", "ANTHROPIC_AUTH_TOKEN"),
        ("ssh", "SSH_AUTH_SOCK"),
    ] {
        let (mut project, mut captured) = selected_profile();
        captured.profile_slots = vec![slot.into()];
        project
            .environment
            .insert(name.into(), "must-not-appear-in-error".into());
        let error = captured
            .selection(&project, "synthetic-org", 7)
            .unwrap_err();
        assert!(!format!("{error:?}").contains("must-not-appear-in-error"));
        captured.profile_slots = vec!["github".into()];
        assert!(captured.selection(&project, "synthetic-org", 7).is_ok());
    }
}

#[test]
fn app_only_and_other_clients_preserve_unselected_ordinary_provider_settings() {
    let mut project = ProjectSpec::default();
    project.secrets.user = Some(StoragePlacement::Platform);
    for name in [
        "CODEX_HOME",
        "CODEX_CA_CERTIFICATE",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "SSH_AUTH_SOCK",
    ] {
        project
            .environment
            .insert(name.into(), "ordinary-user-setting".into());
    }
    assert!(capture().selection(&project, "synthetic-org", 7).is_ok());
    assert_eq!(
        capture().managed_credential_clients(&project).unwrap(),
        Default::default()
    );
    let (mut project, captured) = selected_profile(); // Codex, not OpenAI API.
    project.environment.insert(
        "OPENAI_BASE_URL".into(),
        "https://ordinary.example.test".into(),
    );
    assert!(captured.selection(&project, "synthetic-org", 7).is_ok());
    assert_eq!(
        captured
            .managed_credential_clients(&project)
            .unwrap()
            .encode(),
        "v1:codex"
    );
}
