use super::*;

#[test]
fn legacy_and_canonical_forms_normalize_to_one_spec() {
    let legacy = parse_project_yaml(
        r#"
preset: workspace
install: bun install
startup: bun test
cpu: 2
memory: 4096
disk: 20
env: {B: two, A: one}
agent: claude
secrets: dev
ports: [3000]
"#,
    )
    .unwrap();
    let canonical = parse_project_yaml(
        r#"
version: 1
preset: workspace
install_command: bun install
startup_script: bun test
cpu: 2000m
memory: 4Gi
disk: 20Gi
environment: {A: one, B: two}
agents: [claude-code]
secrets: {project: dev}
app_ports: [{port: 3000}]
"#,
    )
    .unwrap();
    assert_eq!(legacy.spec, canonical.spec);
    let encoded = legacy.canonical_json().unwrap();
    assert_eq!(encoded, canonical.canonical_json().unwrap());
    assert_eq!(
        String::from_utf8(encoded).unwrap(),
        r#"{"schema_version":1,"preset":"workspace","working_directory":"/workspace","install_command":"bun install","startup_script":"bun test","environment":{"A":"one","B":"two"},"agents":{"tools":["claude-code"]},"application_ports":[{"port":3000}],"resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":20},"secrets":{"project":"dev"}}"#
    );
}

#[test]
fn normalizes_repositories_workdir_skills_and_credentials() {
    let document = parse_project_yaml(
        r#"
repositories:
  - url: https://example.com/org/api.git
    branch: main
    mount_path: /workspace/services/api
  - source: git@example.com:org/web.git
skills:
  - path: .agents/skills/rust
    agents: [claude, codex]
  - user:personal
credentials:
  work: {provider: openai, account_ref: acct-work}
  personal: acct-personal
"#,
    )
    .unwrap();
    assert_eq!(document.spec.working_directory, "/workspace");
    assert_eq!(document.spec.repositories[1].destination, "/workspace/web");
    assert_eq!(document.spec.skills[0].agents, ["claude-code", "codex"]);
    assert_eq!(document.spec.skills[1].source, SkillSource::User);
    assert_eq!(document.spec.credentials.len(), 2);
    document.ensure_platform_compatible().unwrap();
}

#[test]
fn defaults_working_directory_from_repository_count() {
    let none = parse_project_yaml("{}\n").unwrap();
    assert_eq!(none.spec.working_directory, "/workspace");

    let one = parse_project_yaml("repositories: [{url: https://example.com/app.git}]\n").unwrap();
    assert_eq!(one.spec.working_directory, "/workspace/app");

    let many = parse_project_yaml(
        "repositories: [{url: https://example.com/a.git}, {url: https://example.com/b.git}]\n",
    )
    .unwrap();
    assert_eq!(many.spec.working_directory, "/workspace");
}

#[test]
fn separates_local_only_directives_from_portable_intent() {
    let document = parse_project_yaml(
        r#"
mounts:
  - source: ../shared
    target: /workspace/shared
    mode: direct
    readonly: true
ports: ["18080:8080"]
"#,
    )
    .unwrap();
    assert_eq!(document.spec.application_ports[0].port, 8080);
    assert_eq!(document.local.mounts[0].source, "../shared");
    assert_eq!(document.local.mounts[0].mode, LocalMountMode::Direct);
    assert_eq!(document.local.mounts[0].read_only, Some(true));
    assert_eq!(document.local.host_ports[0].host_port, 18080);
    assert!(matches!(
        document.ensure_platform_compatible(),
        Err(ProjectError::PlatformUnsupported { field: "mounts" })
    ));
    assert!(
        !document
            .canonical_json()
            .unwrap()
            .windows(b"../shared".len())
            .any(|window| window == b"../shared")
    );
}

#[test]
fn separates_local_filesystem_copies_from_portable_repositories() {
    let document = parse_project_yaml(
        r#"
repositories:
  - source: https://example.com/acme/api.git
    destination: /workspace/api
mounts:
  - source: ./fixtures
    destination: /workspace/fixtures
    mode: copy
  - source: ../shared
    destination: /workspace/shared
    mode: direct
    read_only: true
working_directory: /workspace/api
"#,
    )
    .unwrap();
    assert_eq!(document.spec.repositories.len(), 1);
    assert_eq!(document.local.mounts.len(), 2);
    assert_eq!(document.local.mounts[0].destination, "/workspace/fixtures");
    assert_eq!(document.local.mounts[0].mode, LocalMountMode::Copy);
    assert_eq!(document.local.mounts[1].mode, LocalMountMode::Direct);
    assert!(matches!(
        document.ensure_platform_compatible(),
        Err(ProjectError::PlatformUnsupported { field: "mounts" })
    ));
    let canonical = document.canonical_json().unwrap();
    assert!(
        !canonical
            .windows(b"./fixtures".len())
            .any(|value| value == b"./fixtures")
    );
}

#[test]
fn rejects_unknown_unsafe_overlapping_and_nonportable_shapes() {
    for yaml in [
        "mystery: true\n",
        "repositories: [{url: https://x/a, mount_path: /workspace/../x}]\n",
        "repositories: [{url: https://x/a, mount_path: /workspace/a}, {url: https://x/b, mount_path: /workspace/a/b}]\n",
        "mounts: [{source: ./a, destination: /workspace, mode: copy}]\n",
        "mounts: [{source: ./a, destination: /outside, mode: copy}]\n",
        "mounts: [{source: ./a}]\n",
        "mounts: [{source: ./a, destination: /workspace/a, mode: direct}]\n",
        "mounts: [{source: ./a, destination: /workspace/a, mode: copy, read_only: true}]\n",
        "repositories: [{source: https://x/a, destination: /workspace/a}]\nmounts: [{source: ./a, destination: /workspace/a, mode: copy}]\n",
        "mounts: [{source: ./a, destination: /workspace/a, mode: copy}, {source: ./b, destination: /workspace/a/b, mode: direct, read_only: true}]\n",
        "credentials: {work: {provider: openai, account: ''}}\n",
        "skills: [{path: ../outside}]\n",
        "workspace: {mode: clone, source: .}\n",
        "ports: [3000, 3000]\n",
        "credentials: {Work: acct-a, work: acct-b}\n",
        "credentials: {work: /home/user/.config/account}\n",
        "repositories: [{source: 'https://userinfo@example.com/org/app.git'}]\n",
        "repositories: [{source: 'ssh://git:password@example.com/org/app.git'}]\n",
        "repositories: [{source: 'ssh://git%3Apassword@example.com/org/app.git'}]\n",
        "repositories: [{source: 'git://userinfo@example.com/org/app.git'}]\n",
        "repositories: [{source: 'https://example.com/org/app.git?ref=main'}]\n",
        "repositories: [{source: /home/user/app}]\n",
        "repositories: [{source: ../app}]\n",
        "repositories: [{source: 'file:///home/user/app'}]\n",
        "repositories: [{source: 'https://example.com/'}]\n",
        "repositories: [{source: 'https://example.com/org/app.git', branch: '--upload-pack'}]\n",
        "repositories: [{source: 'https://example.com/org/app.git', branch: main, revision: deadbeef}]\n",
        "disk: 1536Mi\n",
        &format!(
            "working_directory: /workspace/{}\n",
            "x".repeat(MAX_SHORT_VALUE_BYTES + 1)
        ),
    ] {
        assert!(parse_project_yaml(yaml).is_err(), "accepted {yaml:?}");
    }
}

#[test]
fn accepts_remote_https_ssh_and_scp_repository_sources() {
    for (source, name) in [
        ("https://example.com/org/app.git", "app"),
        ("ssh://git@example.com/org/app.git", "app"),
        ("git://example.com/org/app.git", "app"),
        ("git@example.com:org/app.git", "app"),
        ("codewiresh/codewire", "codewire"),
    ] {
        let yaml = format!("repositories: [{{source: {source:?}}}]\n");
        let project = parse_project_yaml(&yaml).unwrap().spec;
        assert_eq!(
            project.repositories[0].destination,
            format!("/workspace/{name}")
        );
    }
}

#[test]
fn schema_and_input_bounds_fail_closed() {
    assert!(matches!(
        parse_project_yaml("version: 2\n"),
        Err(ProjectError::UnsupportedSchema(2))
    ));
    assert!(matches!(
        parse_project_yaml("version: 1\nschema_version: 2\n"),
        Err(ProjectError::ConflictingSchemaVersion { .. })
    ));
    let oversized = "x".repeat(MAX_PROJECT_DOCUMENT_BYTES + 1);
    assert!(matches!(
        parse_project_yaml(&oversized),
        Err(ProjectError::DocumentTooLarge { .. })
    ));

    let too_many_ports = format!(
        "ports: [{}]\n",
        (1..=MAX_APPLICATION_PORTS + 1)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(matches!(
        parse_project_yaml(&too_many_ports),
        Err(ProjectError::TooManyEntries { field: "ports", .. })
    ));

    let bounded_collections = [
        (
            "repositories",
            format!(
                "repositories: [{}]\n",
                (0..=MAX_REPOSITORIES)
                    .map(|index| format!("{{source: https://example.com/org/r{index}.git}}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "environment",
            format!(
                "environment: {{{}}}\n",
                (0..=MAX_ENVIRONMENT_VALUES)
                    .map(|index| format!("V{index}: value"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "agent_env",
            format!(
                "agent_env: {{{}}}\n",
                (0..=MAX_ENVIRONMENT_VALUES)
                    .map(|index| format!("V{index}: value"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "agents",
            format!("agents: [{}]\n", vec!["codex"; MAX_AGENTS + 1].join(",")),
        ),
        (
            "skills",
            format!(
                "skills: [{}]\n",
                (0..=MAX_SKILLS)
                    .map(|index| format!(".agents/skills/s{index}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "skills.agents",
            format!(
                "skills: [{{path: .agents/skills/rust, agents: [{}]}}]\n",
                vec!["codex"; MAX_AGENTS + 1].join(",")
            ),
        ),
        (
            "credentials",
            format!(
                "credentials: {{{}}}\n",
                (0..=MAX_CREDENTIALS)
                    .map(|index| format!("a{index}: acct-{index}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "mounts",
            format!(
                "mounts: [{}]\n",
                (0..=MAX_LOCAL_MOUNTS)
                    .map(|index| format!(
                        "{{source: ./shared-{index}, destination: /workspace/shared-{index}, mode: copy}}"
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
    ];
    for (field, yaml) in bounded_collections {
        assert!(
            matches!(
                parse_project_yaml(&yaml),
                Err(ProjectError::TooManyEntries { field: actual, .. }) if actual == field
            ),
            "{field} count was not bounded"
        );
    }
}

#[test]
fn canonicalization_is_idempotent_for_generated_valid_specs() {
    for repositories in 0..=3 {
        for agents in ["[]", "[claude, codex]"] {
            let repos = (0..repositories)
                .map(|index| {
                    format!(
                        "{{url: https://example.com/org/r{index}.git, mount_path: /workspace/r{index}}}"
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let yaml = format!(
                "version: 1\nrepositories: [{repos}]\nagents: {agents}\nenv: {{Z: last, A: first}}\n"
            );
            let first = parse_project_yaml(&yaml).unwrap().spec;
            let encoded = first.canonical_json().unwrap();
            let second: ProjectSpec = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(first, second);
            assert_eq!(encoded, second.canonical_json().unwrap());
        }
    }
}

#[test]
fn repository_destination_helper_preserves_legacy_defaults() {
    assert_eq!(
        validate_repository_destinations([
            ("https://example.com/org/app.git", ""),
            ("git@host:org/api.git", "/workspace/services/api"),
            ("codewiresh/codewire", "/workspace/codewire"),
        ])
        .unwrap(),
        [
            "/workspace/app",
            "/workspace/services/api",
            "/workspace/codewire"
        ]
    );
    assert_eq!(repository_name("git@host:org/app.git"), "app");
}

#[test]
fn typed_specs_validate_before_crossing_adapter_boundaries() {
    let mut spec = parse_project_yaml(
        "agents: [claude]\nskills: [.agents/skills/rust]\ncredentials: {work: acct-work}\n",
    )
    .unwrap()
    .spec;
    spec.validate().unwrap();

    spec.agents.tools[0] = "claude".to_string();
    assert!(spec.validate().is_err());
    assert!(spec.canonical_json().is_err());

    let unknown = serde_json::from_str::<ProjectSpec>(
        r#"{"schema_version":1,"working_directory":"/workspace","host_path":"/tmp/x"}"#,
    );
    assert!(unknown.is_err());
}

#[test]
fn local_source_paths_are_explicit_but_not_resolved_by_the_parser() {
    for source in [".", "../shared", "/srv/workspace"] {
        let yaml = format!(
            "mounts: [{{mode: direct, source: {source:?}, destination: /workspace/source, read_only: true}}]\n"
        );
        assert!(parse_project_yaml(&yaml).is_ok(), "rejected {source:?}");
    }
    for source in ["/", "foo//bar", "/srv//workspace", "path/"] {
        let yaml = format!(
            "mounts: [{{mode: direct, source: {source:?}, destination: /workspace/source, read_only: true}}]\n"
        );
        assert!(parse_project_yaml(&yaml).is_err(), "accepted {source:?}");
    }
}
