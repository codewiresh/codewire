use std::path::Path;

use super::*;

fn merged(files: &[&str]) -> Result<ProjectDocument, ProjectError> {
    files
        .iter()
        .map(|content| ProjectYamlFile::parse(content))
        .collect::<Result<Vec<_>, _>>()
        .and_then(merge_project_files)
}

const BASE: &str = r#"
version: 1
image: workspace
repositories:
  - source: https://example.test/org/api.git
    destination: /workspace/api
  - source: https://example.test/org/web.git
    destination: /workspace/web
working_directory: /workspace
environment:
  NODE_ENV: development
  LOG_LEVEL: info
cpu: "4"
memory: "8Gi"
"#;

#[test]
fn mappings_merge_by_key_and_later_values_replace() {
    let document = merged(&[
        BASE,
        r#"
environment:
  LOG_LEVEL: debug
  EXTRA: "1"
memory: "16Gi"
"#,
    ])
    .unwrap();
    let environment = &document.spec.environment;
    assert_eq!(environment["NODE_ENV"], "development");
    assert_eq!(environment["LOG_LEVEL"], "debug");
    assert_eq!(environment["EXTRA"], "1");
    assert_eq!(document.spec.resources.cpu_millicores, Some(4000));
    assert_eq!(document.spec.resources.memory_mib, Some(16 * 1024));
    assert_eq!(document.spec.repositories.len(), 2);
}

#[test]
fn a_later_list_replaces_the_earlier_one_whole() {
    let document = merged(&[
        BASE,
        r#"
repositories:
  - source: https://example.test/org/docs.git
    destination: /workspace/docs
"#,
    ])
    .unwrap();
    let sources = document
        .spec
        .repositories
        .iter()
        .map(|repository| repository.source.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sources, ["https://example.test/org/docs.git"]);
}

#[test]
fn null_removes_a_key_at_any_depth() {
    let document = merged(&[
        BASE,
        r#"
cpu: null
environment:
  LOG_LEVEL: null
  ABSENT: null
"#,
    ])
    .unwrap();
    assert_eq!(document.spec.resources.cpu_millicores, None);
    assert_eq!(document.spec.resources.memory_mib, Some(8 * 1024));
    assert!(!document.spec.environment.contains_key("LOG_LEVEL"));
    assert!(!document.spec.environment.contains_key("ABSENT"));
    assert_eq!(document.spec.environment["NODE_ENV"], "development");
}

#[test]
fn null_inside_a_new_mapping_adds_nothing() {
    let document = merged(&[
        "version: 1\nimage: workspace\n",
        "environment:\n  ONLY: null\n  KEPT: yes-really\n",
    ])
    .unwrap();
    assert_eq!(
        document.spec.environment.keys().collect::<Vec<_>>(),
        ["KEPT"]
    );
}

#[test]
fn an_empty_file_adds_nothing() {
    assert_eq!(merged(&[BASE, ""]).unwrap(), merged(&[BASE]).unwrap());
}

#[test]
fn one_file_merges_to_what_the_single_file_parser_reads() {
    assert_eq!(merged(&[BASE]).unwrap(), parse_project_yaml(BASE).unwrap());
}

#[test]
fn each_file_is_checked_on_its_own_with_its_position() {
    let error = ProjectYamlFile::parse("environment:\n  A: b\nimgae: workspace\n")
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field `imgae`"), "{error}");
    assert!(error.contains("line 3"), "{error}");

    let error = ProjectYamlFile::parse("cpu: 4\n").unwrap_err().to_string();
    assert!(error.contains("quoted quantity"), "{error}");

    assert!(matches!(
        ProjectYamlFile::parse("version: 2\n"),
        Err(ProjectError::UnsupportedSchema(2))
    ));
}

#[test]
fn only_the_merged_document_must_be_valid() {
    let base = "version: 1\nimage: workspace\ncpu: \"999\"\n";
    assert!(parse_project_yaml(base).is_err());
    let document = merged(&[base, "cpu: \"4\"\n"]).unwrap();
    assert_eq!(document.spec.resources.cpu_millicores, Some(4000));
}

#[test]
fn the_merged_document_keeps_the_size_limit() {
    let half = "x".repeat(MAX_PROJECT_DOCUMENT_BYTES / 2 + 1);
    let first = format!("environment:\n  FIRST: {half}\n");
    let second = format!("environment:\n  SECOND: {half}\n");
    assert!(matches!(
        merged(&[&first, &second]),
        Err(ProjectError::DocumentTooLarge { .. })
    ));
}

#[test]
fn relative_mount_sources_resolve_from_their_own_file() {
    let mut file = ProjectYamlFile::parse(
        r#"
mounts:
  - {source: ../infra, destination: /workspace/infra, mode: direct, read_only: false}
  - {source: /srv/data, destination: /workspace/data, mode: copy}
"#,
    )
    .unwrap();
    file.resolve_mount_sources(Path::new("/srv/root")).unwrap();
    let document = merge_project_files([file]).unwrap();
    let sources = document
        .local
        .mounts
        .iter()
        .map(|mount| mount.source.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sources, ["/srv/root/../infra", "/srv/data"]);
}

#[test]
fn an_override_can_set_the_workspace_path_mode() {
    let document = merged(&[
        "version: 1\nworkspace:\n  vm_only: [target]\n",
        "workspace:\n  path_mode: Mount\n",
    ])
    .unwrap();
    assert_eq!(document.local.path_mode, Some(WorkspacePathMode::Mount));
    assert_eq!(document.local.vm_only, Some(vec!["target".to_owned()]));
    assert_eq!(
        parse_project_yaml("version: 1\n").unwrap().local.path_mode,
        None
    );
    let error = parse_project_yaml("workspace: {path_mode: live}\n")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("must be mount, copy, clone or empty"),
        "{error}"
    );
}
