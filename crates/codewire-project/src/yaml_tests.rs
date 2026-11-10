use super::*;

const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";

/// Every field the schema has, so the writer is proven against all of them.
fn full_document() -> String {
    format!(
        r#"
version: 1
image: ghcr.io/codewiresh/workspace@sha256:{digest}
repositories:
  - source: https://example.test/org/api.git
    revision: deadbeef
    destination: /workspace/api
  - source: git@example.test:org/web.git
    branch: release/1.0
    destination: /workspace/web
    known_hosts:
      - example.test ssh-ed25519 {KEY}
working_directory: /workspace/api
install_command: |
  npm ci
  npm run build
startup_script: npm run dev -- --port "3000"
environment:
  NODE_ENV: production
  QUOTED: "yes: no # not a comment"
agents: {{install: false, tools: [claude-code, codex]}}
skills:
  - {{source: repository, path: .agents/skills/rust, agents: [codex]}}
  - {{source: user, name: personal}}
ports:
  - {{port: 3000, label: web, access: creator}}
  - {{host_port: 18080, guest_port: 8080, label: api}}
cpu: "2"
memory: "4Gi"
disk: "40Gi"
secrets: {{project: local:app-dev, organization: true, user: platform}}
credentials: {{profile: local:user/work}}
mounts:
  - {{source: ../shared, destination: /workspace/shared, mode: direct, read_only: true}}
  - {{source: ./fixtures, destination: /workspace/fixtures, mode: copy}}
workspace:
  vm_only: [node_modules, '**/target']
  path_mode: mount
"#,
        digest = "0".repeat(64)
    )
}

fn reparse(document: &ProjectDocument) -> (String, ProjectDocument) {
    let yaml = document.to_yaml().expect("render codewire.yaml");
    let parsed = parse_project_yaml(&yaml)
        .unwrap_or_else(|error| panic!("rendered codewire.yaml does not parse: {error}\n{yaml}"));
    (yaml, parsed)
}

#[test]
fn a_parsed_document_renders_back_to_the_same_document() {
    let document = parse_project_yaml(&full_document()).unwrap();
    let (yaml, parsed) = reparse(&document);
    assert_eq!(parsed, document, "{yaml}");
    assert_eq!(
        parsed.canonical_json().unwrap(),
        document.canonical_json().unwrap()
    );
    // Rendering is deterministic, so an export can be compared and committed.
    assert_eq!(parsed.to_yaml().unwrap(), yaml);
}

#[test]
fn keys_follow_the_schema_order_and_omit_empty_values() {
    let document = parse_project_yaml(&full_document()).unwrap();
    let yaml = document.to_yaml().unwrap();
    let keys = yaml
        .lines()
        .filter(|line| !line.starts_with([' ', '-']))
        .map(|line| line.split(':').next().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "version",
            "image",
            "repositories",
            "working_directory",
            "install_command",
            "startup_script",
            "secrets",
            "environment",
            "agents",
            "skills",
            "ports",
            "cpu",
            "memory",
            "disk",
            "credentials",
            "mounts",
            "workspace",
        ]
    );
    assert!(yaml.contains("cpu: '2'\n"), "{yaml}");
    assert!(yaml.contains("memory: 4Gi\n"), "{yaml}");
    assert!(
        yaml.contains("- host_port: 18080\n  guest_port: 8080\n"),
        "{yaml}"
    );

    let minimal = ProjectDocument::new(ProjectSpec::default(), LocalProjectIntent::default(), true);
    assert_eq!(
        minimal.to_yaml().unwrap(),
        "version: 1\nworking_directory: /workspace\n"
    );
}

#[test]
fn resources_render_in_the_units_people_write() {
    for (cpu, memory) in [("'2'", "4Gi"), ("1500m", "1536Mi"), ("100m", "128Mi")] {
        let yaml = format!("cpu: {cpu}\nmemory: {memory}\ndisk: 1Gi\n");
        let document = parse_project_yaml(&yaml).unwrap();
        let (rendered, parsed) = reparse(&document);
        assert_eq!(parsed.spec.resources, document.spec.resources);
        assert!(
            rendered.contains(&format!("cpu: {cpu}\nmemory: {memory}\ndisk: 1Gi\n")),
            "{rendered}"
        );
    }
}

#[test]
fn an_implicit_working_directory_is_left_to_the_creator() {
    let spec = ProjectSpec {
        working_directory: "/workspace/app".to_owned(),
        ..Default::default()
    };
    let document = ProjectDocument::new(spec, LocalProjectIntent::default(), false);
    let (yaml, parsed) = reparse(&document);
    assert!(!yaml.contains("working_directory"), "{yaml}");
    assert!(!parsed.working_directory_is_explicit());
    assert_eq!(parsed.spec.working_directory, "/workspace");

    let explicit = parse_project_yaml("working_directory: /workspace\n").unwrap();
    let (yaml, parsed) = reparse(&explicit);
    assert!(yaml.contains("working_directory: /workspace\n"), "{yaml}");
    assert!(parsed.working_directory_is_explicit());
}

#[test]
fn a_host_binding_without_an_application_port_becomes_one() {
    let mut document = parse_project_yaml("ports: [{port: 3000}]\n").unwrap();
    document.local.host_ports.push(HostPortBinding {
        host_port: 14000,
        guest_port: 4000,
    });
    let (_, parsed) = reparse(&document);
    assert_eq!(
        parsed
            .spec
            .application_ports
            .iter()
            .map(|port| port.port)
            .collect::<Vec<_>>(),
        [3000, 4000]
    );
    assert_eq!(parsed.local.host_ports, document.local.host_ports);
}

#[test]
fn vm_only_absent_and_off_stay_distinct() {
    for (yaml, expected) in [
        ("version: 1\n", None),
        ("workspace: {vm_only: []}\n", Some(Vec::new())),
    ] {
        let document = parse_project_yaml(yaml).unwrap();
        let (_, parsed) = reparse(&document);
        assert_eq!(parsed.local.vm_only, expected);
    }
}

#[test]
fn an_invalid_spec_is_refused_rather_than_written() {
    let spec = ProjectSpec {
        schema_version: PROJECT_SCHEMA_VERSION + 1,
        ..Default::default()
    };
    let error = ProjectDocument::new(spec, LocalProjectIntent::default(), true)
        .to_yaml()
        .unwrap_err();
    assert!(
        matches!(error, ProjectError::UnsupportedSchema(_)),
        "{error}"
    );
}
