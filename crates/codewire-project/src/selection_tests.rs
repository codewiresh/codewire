use super::*;

#[test]
fn one_document_preserves_platform_sources_for_local_or_platform_execution() {
    let document = parse_project_yaml(
        "image: workspace\nsecrets: {project: 'platform:development', user: platform, organization: true}\ncredentials: {profile: 'platform:work'}\n",
    )
    .unwrap();
    document.ensure_platform_compatible().unwrap();
    assert_eq!(document.spec.secrets.user, Some(StoragePlacement::Platform));
    assert!(document.spec.secrets.organization);
    assert_eq!(document.spec.secrets.project, "platform:development");
    assert_eq!(
        document.spec.credentials.as_ref().unwrap().profile,
        "platform:work"
    );
    let canonical = document.canonical_json().unwrap();
    let decoded: ProjectSpec = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(decoded, document.spec);
    assert_eq!(decoded.canonical_json().unwrap(), canonical);
    let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert!(value.get("access").is_none());
    assert_eq!(value["secrets"]["user"], "platform");
    assert_eq!(value["credentials"]["profile"], "platform:work");
}

#[test]
fn platform_rejects_each_explicit_local_source_before_resolution() {
    for (yaml, field) in [
        ("secrets: {user: local}\n", "secrets.user"),
        (
            "secrets: {project: 'local:development'}\n",
            "secrets.project",
        ),
        (
            "credentials: {profile: 'local:work'}\n",
            "credentials.profile",
        ),
    ] {
        let document = parse_project_yaml(yaml).unwrap();
        assert!(matches!(
            document.ensure_platform_compatible(),
            Err(ProjectError::PlatformUnsupported { field: actual }) if actual == field
        ));
        assert!(matches!(
            document.spec.ensure_platform_compatible(),
            Err(ProjectError::PlatformUnsupported { field: actual }) if actual == field
        ));
    }
}

#[test]
fn omitted_sources_and_profile_do_not_choose_defaults() {
    let document = parse_project_yaml("image: workspace\n").unwrap();
    assert!(document.spec.secrets.is_empty());
    assert!(document.spec.credentials.is_none());
    let value: serde_json::Value =
        serde_json::from_slice(&document.canonical_json().unwrap()).unwrap();
    assert!(value.get("secrets").is_none());
    assert!(value.get("credentials").is_none());
}

#[test]
fn retired_and_ambiguous_personal_source_shapes_are_not_compatibility_inputs() {
    for yaml in [
        "access: {profile: user/work}\n",
        "secrets: {user: true}\n",
        "secrets: {user: false}\n",
        "secrets: {user: current}\n",
        "credentials: {profile: 'platform:work', exposure: true}\n",
        "credentials: {profile: 'platform:work', mappings: {A: B}}\n",
    ] {
        assert!(parse_project_yaml(yaml).is_err(), "accepted retired shape");
    }
}

#[test]
fn bare_names_stay_unresolved_and_are_not_normalized_to_local_or_personal() {
    let document =
        parse_project_yaml("secrets: {project: development}\ncredentials: {profile: work}\n")
            .unwrap();
    assert_eq!(
        document.spec.secrets.project_reference().unwrap().placement,
        None
    );
    assert_eq!(
        document
            .spec
            .credentials
            .unwrap()
            .reference()
            .unwrap()
            .placement,
        None
    );
}
