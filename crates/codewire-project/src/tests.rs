use super::*;

#[test]
fn repository_codewire_yaml_parses() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../codewire.yaml");
    let content = std::fs::read_to_string(&path).expect("read the repository codewire.yaml");
    parse_project_yaml(&content).expect("the repository codewire.yaml parses");
}

/// Leading comments, as in the repository's codewire.yaml, so a position at
/// the document's start (line 4, `version:`) cannot pass for a key's own.
const COMMENTED_HEADER: &str =
    "# A Codewire environment.\n#\n# Resources suit a full build.\nversion: 1\nimage: workspace\n";

/// A document error's whole printed text and its line and column. The text is
/// not also the error's source, so printing the chain shows it once.
fn document_error(yaml: &str) -> (String, usize, usize) {
    let error = parse_project_yaml(yaml).unwrap_err();
    let ProjectError::Yaml(parser) = &error else {
        panic!("not a document error: {error}");
    };
    assert!(
        std::error::Error::source(&error).is_none(),
        "printing the chain would repeat {error}"
    );
    let location = parser.location().expect("the parser reports a position");
    (error.to_string(), location.line(), location.column())
}

#[test]
fn a_bare_number_quantity_names_its_key_position_and_quoted_form() {
    for (field, value, example, column) in [
        ("cpu", "8", "\"8\"", 6),
        ("memory", "16", "\"16Gi\"", 9),
        ("disk", "100", "\"100Gi\"", 7),
    ] {
        let yaml = format!("{COMMENTED_HEADER}{field}: {value}\n");
        assert_eq!(
            document_error(&yaml),
            (
                format!(
                    "{field}: invalid type: integer `{value}`, expected a quoted quantity such as {example} at line 6 column {column}"
                ),
                6,
                column
            )
        );
    }
    let (message, ..) = document_error("cpu: 0.5\n");
    assert_eq!(
        message,
        "cpu: invalid type: floating point `0.5`, expected a quoted quantity such as \"8\" at line 1 column 6"
    );
}

#[test]
fn quoted_and_null_quantities_still_parse() {
    let document = parse_project_yaml("cpu: \"500m\"\nmemory: '1Gi'\ndisk: \"20\"\n").unwrap();
    assert_eq!(document.spec.resources.cpu_millicores, Some(500));
    assert_eq!(document.spec.resources.memory_mib, Some(1024));
    assert_eq!(document.spec.resources.disk_gib, Some(20));
    for yaml in ["cpu: ~\n", "cpu: null\n", "cpu:\nmemory:\ndisk:\n"] {
        let document = parse_project_yaml(yaml).unwrap();
        assert!(document.spec.resources.is_empty(), "{yaml:?}");
    }
}

#[test]
fn an_unknown_key_is_named_at_its_own_position() {
    let (message, line, column) = document_error(&format!("{COMMENTED_HEADER}gpu: \"1\"\n"));
    assert!(
        message.starts_with("unknown field `gpu`, expected one of `version`, `preset`"),
        "{message}"
    );
    assert!(
        message.ends_with("`workspace` at line 6 column 1"),
        "{message}"
    );
    assert_eq!((line, column), (6, 1));

    assert_eq!(
        document_error(&format!(
            "{COMMENTED_HEADER}agents:\n  tools: [codex]\n  toolz: [codex]\n"
        )),
        (
            "agents: unknown field `toolz`, expected `install` or `tools` at line 8 column 3"
                .to_owned(),
            8,
            3
        )
    );
}

#[test]
fn a_wrong_type_inside_a_list_names_the_item_path() {
    assert_eq!(
        document_error(&format!(
            "{COMMENTED_HEADER}agents:\n  tools:\n    - claude-code\n    - {{name: codex}}\n"
        )),
        (
            "agents.tools[1]: invalid type: map, expected a string at line 9 column 7".to_owned(),
            9,
            7
        )
    );
    assert_eq!(
        document_error(&format!(
            "{COMMENTED_HEADER}skills:\n  - source: repository\n    path: a\n  - source: repo\n    path: b\n"
        )),
        (
            "skills[1].source: unknown variant `repo`, expected `repository` or `user` at line 9 column 13"
                .to_owned(),
            9,
            13
        )
    );
}

#[test]
fn an_environment_type_error_names_the_key_not_the_value() {
    let (message, ..) = document_error("environment:\n  TOKEN: [synthetic-secret-value]\n");
    assert_eq!(
        message,
        "environment.TOKEN: invalid type: sequence, expected a string at line 2 column 10"
    );
}

#[test]
fn invalid_yaml_syntax_is_reported_once_with_its_position() {
    assert_eq!(
        document_error(&format!("{COMMENTED_HEADER}memory \"16Gi\"\ndisk: \"100Gi\"\n")),
        (
            "could not find expected ':' at line 7 column 1, while scanning a simple key at line 6 column 1"
                .to_owned(),
            7,
            1
        )
    );
}

#[test]
fn canonical_mapping_grammar_normalizes_to_one_spec() {
    let canonical = parse_project_yaml(
        r#"
version: 1
preset: workspace
install_command: bun install
startup_script: bun test
cpu: "2000m"
memory: "4Gi"
disk: "20Gi"
environment: {A: one, B: two}
agents: {tools: [claude-code]}
secrets: {project: dev}
ports: [{port: 3000}]
"#,
    )
    .unwrap();
    let encoded = canonical.canonical_json().unwrap();
    assert_eq!(
        String::from_utf8(encoded).unwrap(),
        r#"{"schema_version":1,"preset":"workspace","working_directory":"/workspace","install_command":"bun install","startup_script":"bun test","environment":{"A":"one","B":"two"},"agents":{"tools":["claude-code"]},"application_ports":[{"port":3000}],"resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":20},"secrets":{"project":"dev"}}"#
    );
}

#[test]
fn removed_compatibility_forms_are_rejected() {
    for yaml in [
        "schema_version: 1\n",
        "repos: [{source: https://example.com/org/app.git}]\n",
        "repositories: [{url: https://example.com/org/app.git}]\n",
        "repositories: [{source: https://example.com/org/app.git, mount_path: /workspace/app}]\n",
        "workdir: /workspace\n",
        "install: bun install\n",
        "startup: bun test\n",
        "env: {A: one}\n",
        "agent: codex\n",
        "install_agents: true\n",
        "agents: codex\n",
        "agents: [codex]\n",
        "agents: {tools: [claude]}\n",
        "skills: [.agents/skills/rust]\n",
        "skills: [{path: .agents/skills/rust}]\n",
        "skills: [{source: repo, path: .agents/skills/rust}]\n",
        "ports: [3000]\n",
        "ports: ['18080:8080']\n",
        "app_ports: [{port: 3000}]\n",
        "ports: [{published: 18080, target: 8080}]\n",
        "cpu: 2\n",
        "memory: 4096\n",
        "disk: 20\n",
        "mounts: [{source: ./fixtures, target: /workspace/fixtures, mode: copy}]\n",
        "mounts: [{source: ../shared, destination: /workspace/shared, mode: direct, readonly: true}]\n",
    ] {
        assert!(parse_project_yaml(yaml).is_err(), "accepted {yaml:?}");
    }
}

#[test]
fn accepts_human_gigabyte_resource_quantities() {
    let document = parse_project_yaml("memory: \"8GB\"\ndisk: \"40GB\"\n").unwrap();
    assert_eq!(document.spec.resources.memory_mib, Some(8 * 1024));
    assert_eq!(document.spec.resources.disk_gib, Some(40));

    for (quantity, memory_mib) in [
        ("16gi", 16 * 1024),
        ("16gb", 16 * 1024),
        ("1024mb", 1024),
        ("2048mb", 2048),
    ] {
        let document = parse_project_yaml(&format!("memory: {quantity:?}\n")).unwrap();
        assert_eq!(document.spec.resources.memory_mib, Some(memory_mib));
    }
}

#[test]
fn rejects_cpu_quantities_that_overflow_millicore_conversion() {
    let error = parse_project_yaml("cpu: \"9223372036854775807\"\n").unwrap_err();
    assert_eq!(error.to_string(), "invalid cpu: quantity is too large");
}

#[test]
fn environment_names_use_the_canonical_workload_secret_key_grammar() {
    let maximum = format!("A{}", "_".repeat(MAX_ENVIRONMENT_KEY_BYTES - 1));
    let too_long = format!("A{}", "_".repeat(MAX_ENVIRONMENT_KEY_BYTES));

    assert!(parse_project_yaml(&format!("environment:\n  {maximum}: value\n")).is_ok());
    assert!(parse_project_yaml(&format!("environment:\n  {too_long}: value\n")).is_err());
    assert!(parse_project_yaml("environment:\n  1DIGIT_FIRST: value\n").is_err());
}

#[test]
fn reserved_runtime_environment_keys_are_rejected_at_yaml_and_typed_boundaries() {
    for key in RESERVED_RUNTIME_ENVIRONMENT_KEYS {
        let expected =
            format!("invalid environment: {key} is reserved for Codewire runtime control");
        let yaml = format!("environment: {{{key}: synthetic}}\n");
        assert_eq!(parse_project_yaml(&yaml).unwrap_err().to_string(), expected);

        let spec = ProjectSpec {
            environment: BTreeMap::from([(key.to_string(), "synthetic".to_string())]),
            ..Default::default()
        };
        assert_eq!(spec.validate().unwrap_err().to_string(), expected);
    }
}

#[test]
fn normalizes_repositories_workdir_skills_and_credential_profile() {
    let document = parse_project_yaml(
        r#"
repositories:
  - source: https://example.com/org/api.git
    branch: main
    destination: /workspace/services/api
  - source: git@example.com:org/web.git
    known_hosts:
      - example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx
skills:
  - source: repository
    path: .agents/skills/rust
    agents: [claude-code, codex]
  - source: user
    name: personal
credentials: {profile: user/work}
"#,
    )
    .unwrap();
    assert_eq!(document.spec.working_directory, "/workspace");
    assert_eq!(document.spec.repositories[1].destination, "/workspace/web");
    assert_eq!(document.spec.skills[0].agents, ["claude-code", "codex"]);
    assert_eq!(document.spec.skills[1].source, SkillSource::User);
    assert_eq!(
        document
            .spec
            .credentials
            .as_ref()
            .expect("credential binding")
            .profile
            .to_string(),
        "user/work"
    );
    document.ensure_platform_compatible().unwrap();
}

#[test]
fn defaults_working_directory_from_workspace_input_count() {
    let none = parse_project_yaml("{}\n").unwrap();
    assert_eq!(none.spec.working_directory, "/workspace");

    let one =
        parse_project_yaml("repositories: [{source: https://example.com/app.git}]\n").unwrap();
    assert_eq!(one.spec.working_directory, "/workspace/app");

    let many = parse_project_yaml(
        "repositories: [{source: https://example.com/a.git}, {source: https://example.com/b.git}]\n",
    )
    .unwrap();
    assert_eq!(many.spec.working_directory, "/workspace");

    let mount = parse_project_yaml(
        "mounts: [{source: ./fixtures, destination: /workspace/fixtures, mode: copy}]\n",
    )
    .unwrap();
    assert_eq!(mount.spec.working_directory, "/workspace/fixtures");

    let mixed = parse_project_yaml(
        "repositories: [{source: https://example.com/app.git}]\nmounts: [{source: ./fixtures, destination: /workspace/fixtures, mode: copy}]\n",
    )
    .unwrap();
    assert_eq!(mixed.spec.working_directory, "/workspace");
}

#[test]
fn separates_local_only_directives_from_portable_intent() {
    let document = parse_project_yaml(
        r#"
mounts:
  - source: ../shared
    destination: /workspace/shared
    mode: direct
    read_only: true
ports:
  - host_port: 18080
    guest_port: 8080
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
        "credentials: {work: {provider: openai, account: acct-work}}\n",
        "secrets: development\n",
        "secrets: {org: true}\n",
        "secret_project: development\n",
        "include_org_secrets: true\n",
        "include_user_secrets: true\n",
        "access: {profile: work}\n",
        "access: {profile: local/work}\n",
        "access: {profile: user/Work}\n",
        "access: {profile: user/work, credential: codex-work}\n",
        "skills: [{path: ../outside}]\n",
        "workspace: {mode: clone, source: .}\n",
        "ports: [3000, 3000]\n",
        "repositories: [{source: 'https://userinfo@example.com/org/app.git'}]\n",
        "repositories: [{source: 'https://synthetic-user%3Asynthetic-secret%40example.com/org/app.git'}]\n",
        "repositories: [{source: 'http://synthetic-user%253Asynthetic-secret%2540example.com/org/app.git'}]\n",
        "repositories: [{source: 'ssh://git:password@example.com/org/app.git'}]\n",
        "repositories: [{source: 'ssh://git%3Apassword@example.com/org/app.git'}]\n",
        "repositories: [{source: 'git://userinfo@example.com/org/app.git'}]\n",
        "repositories: [{source: 'https://example.com/org/app.git?ref=main'}]\n",
        "repositories: [{source: /home/user/app}]\n",
        "repositories: [{source: ../app}]\n",
        "repositories: [{source: 'file:///home/user/app'}]\n",
        "repositories: [{source: 'https://example.com/'}]\n",
        "repositories: [{source: codewiresh/codewire}]\n",
        "repositories: [{source: 'https://example.com/org/app.git', branch: '--upload-pack'}]\n",
        "repositories: [{source: 'https://example.com/org/app.git', branch: main, revision: deadbeef}]\n",
        "disk: \"1536Mi\"\n",
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
    for (source, name, known_hosts) in [
        ("https://example.com/org/app.git", "app", ""),
        (
            "https://example.com:8443/org/app%20with%20spaces.git",
            "app%20with%20spaces",
            "",
        ),
        (
            "ssh://git@example.com/org/app.git",
            "app",
            "known_hosts: [example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx]",
        ),
        ("git://example.com/org/app.git", "app", ""),
        (
            "git@example.com:org/app.git",
            "app",
            "known_hosts: [example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx]",
        ),
    ] {
        let yaml = format!("repositories: [{{source: {source:?}, {known_hosts}}}]\n");
        let project = parse_project_yaml(&yaml).unwrap().spec;
        assert_eq!(
            project.repositories[0].destination,
            format!("/workspace/{name}")
        );
    }
}

#[test]
fn ssh_repository_host_trust_is_exact_bounded_and_canonical() {
    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";
    let yaml = format!(
        "repositories:\n  - source: ssh://git@Example.COM:2222/org/app.git\n    known_hosts:\n      - ' [example.com]:2222   ssh-ed25519   {KEY}   owner supplied '\n      - '[example.com]:2222 ssh-rsa QUJDRA=='\n"
    );
    let project = parse_project_yaml(&yaml).unwrap().spec;
    assert_eq!(
        project.repositories[0].known_hosts,
        [
            format!("[example.com]:2222 ssh-ed25519 {KEY} owner supplied"),
            "[example.com]:2222 ssh-rsa QUJDRA==".to_owned(),
        ]
    );
    project.validate().unwrap();
    let mut noncanonical = project.clone();
    noncanonical.repositories[0].known_hosts.reverse();
    assert!(noncanonical.validate().is_err());

    for yaml in [
        "repositories: [{source: 'git@example.com:org/app.git'}]\n".to_owned(),
        format!("repositories: [{{source: https://example.com/org/app.git, known_hosts: [example.com ssh-ed25519 {KEY}]}}]\n"),
        format!("repositories: [{{source: 'ssh://git@example.com:2222/org/app.git', known_hosts: [example.com ssh-ed25519 {KEY}]}}]\n"),
        format!("repositories: [{{source: 'git@example.com:org/app.git', known_hosts: ['*.example.com ssh-ed25519 {KEY}']}}]\n"),
        format!("repositories: [{{source: 'git@example.com:org/app.git', known_hosts: ['example.com,alias.example.com ssh-ed25519 {KEY}']}}]\n"),
        format!("repositories: [{{source: 'git@example.com:org/app.git', known_hosts: ['@cert-authority example.com ssh-ed25519 {KEY}']}}]\n"),
        "repositories: [{source: 'git@example.com:org/app.git', known_hosts: ['example.com ssh-ed25519 A']} ]\n".to_owned(),
        format!("repositories:\n  - source: 'git@example.com:org/app.git'\n    known_hosts: [\"example.com ssh-ed25519 {KEY}\\nother.invalid ssh-ed25519 {KEY}\"]\n"),
    ] {
        assert!(parse_project_yaml(&yaml).is_err(), "accepted {yaml:?}");
    }

    let too_many = vec![format!("example.com ssh-ed25519 {KEY}"); MAX_REPOSITORY_KNOWN_HOSTS + 1];
    let spec = ProjectSpec {
        repositories: vec![RepositorySpec {
            source: "git@example.com:org/app.git".into(),
            destination: "/workspace/app".into(),
            known_hosts: too_many,
            ..Default::default()
        }],
        working_directory: "/workspace/app".into(),
        ..Default::default()
    };
    assert!(matches!(
        spec.validate(),
        Err(ProjectError::TooManyEntries {
            field: "repositories.known_hosts",
            ..
        })
    ));
    let mut oversized = spec;
    oversized.repositories[0].known_hosts = vec![format!(
        "example.com ssh-ed25519 {}",
        "A".repeat(MAX_REPOSITORY_KNOWN_HOST_LINE_BYTES)
    )];
    assert!(oversized.validate().is_err());
    oversized.repositories[0].known_hosts = (0..MAX_REPOSITORY_KNOWN_HOSTS)
        .map(|index| {
            format!(
                "example.com ssh-ed25519 {} key-{index}",
                "A".repeat(MAX_REPOSITORY_KNOWN_HOSTS_BYTES / MAX_REPOSITORY_KNOWN_HOSTS)
            )
        })
        .collect();
    assert!(oversized.validate().is_err());
}

#[test]
fn encoded_http_authority_rejection_is_value_blind() {
    const MARKER: &str = "synthetic-user%3Asynthetic-secret%40host.invalid";
    let error = parse_project_yaml(&format!(
        "repositories: [{{source: 'https://{MARKER}/org/app.git'}}]\n"
    ))
    .unwrap_err()
    .to_string();

    assert!(error.contains("must not percent-encode URL authority characters"));
    assert!(!error.contains(MARKER));
}

#[test]
fn schema_and_input_bounds_fail_closed() {
    assert!(matches!(
        parse_project_yaml("version: 2\n"),
        Err(ProjectError::UnsupportedSchema(2))
    ));
    assert!(parse_project_yaml("version: 1\nschema_version: 2\n").is_err());
    let oversized = "x".repeat(MAX_PROJECT_DOCUMENT_BYTES + 1);
    assert!(matches!(
        parse_project_yaml(&oversized),
        Err(ProjectError::DocumentTooLarge { .. })
    ));

    let too_many_ports = format!(
        "ports: [{}]\n",
        (1..=MAX_APPLICATION_PORTS + 1)
            .map(|port| format!("{{port: {port}}}"))
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
            "agents",
            format!(
                "agents: {{tools: [{}]}}\n",
                vec!["codex"; MAX_AGENTS + 1].join(",")
            ),
        ),
        (
            "skills",
            format!(
                "skills: [{}]\n",
                (0..=MAX_SKILLS)
                    .map(|index| format!(
                        "{{source: repository, path: .agents/skills/s{index}}}"
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        (
            "skills.agents",
            format!(
                "skills: [{{source: repository, path: .agents/skills/rust, agents: [{}]}}]\n",
                vec!["codex"; MAX_AGENTS + 1].join(",")
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
        for agents in ["{tools: []}", "{tools: [claude-code, codex]}"] {
            let repos = (0..repositories)
                .map(|index| {
                    format!(
                        "{{source: https://example.com/org/r{index}.git, destination: /workspace/r{index}}}"
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let yaml = format!(
                "version: 1\nrepositories: [{repos}]\nagents: {agents}\nenvironment: {{Z: last, A: first}}\n"
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
fn repository_destination_helper_preserves_inferred_defaults() {
    assert_eq!(
        validate_repository_destinations([
            ("git@example.com:org/app.git", ""),
            ("https://host/org/api.git", "/workspace/services/api"),
            (
                "https://github.com/codewiresh/codewire.git",
                "/workspace/codewire",
            ),
        ])
        .unwrap(),
        [
            "/workspace/app",
            "/workspace/services/api",
            "/workspace/codewire"
        ]
    );
    assert!(validate_repository_destinations([("SSH://git@host/org/api.git", "")]).is_err());
    assert_eq!(repository_name("git@host:org/app.git"), "app");
}

#[test]
fn typed_specs_validate_before_crossing_adapter_boundaries() {
    let mut spec = parse_project_yaml(
        "agents: {tools: [claude-code]}\nskills: [{source: repository, path: .agents/skills/rust}]\ncredentials: {profile: user/work}\n",
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

    assert!(parse_project_yaml("agent_env: {TOKEN: value}\n").is_err());
    assert!(
        serde_json::from_str::<ProjectSpec>(
            r#"{"schema_version":1,"working_directory":"/workspace","agent_environment":{"TOKEN":"value"}}"#,
        )
        .is_err()
    );
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

#[test]
fn vm_only_defaults_turns_off_and_stays_out_of_the_portable_spec() {
    let absent = parse_project_yaml("version: 1\n").unwrap();
    assert_eq!(absent.local.vm_only, None);
    assert_eq!(
        absent.local.effective_vm_only(),
        ["node_modules", "target", ".venv"]
    );

    let off = parse_project_yaml("workspace: {vm_only: []}\n").unwrap();
    assert_eq!(off.local.vm_only, Some(Vec::new()));
    assert!(off.local.effective_vm_only().is_empty());

    let declared = parse_project_yaml(
        "workspace:\n  vm_only:\n    - target\n    - ' packages/web/node_modules '\n    - .venv\n",
    )
    .unwrap();
    assert_eq!(
        declared.local.effective_vm_only(),
        ["target", "packages/web/node_modules", ".venv"]
    );
    // Local-only: the portable spec is unchanged and platform placement
    // ignores it, since a platform workspace already lives on its own disk.
    assert_eq!(
        declared.canonical_json().unwrap(),
        absent.canonical_json().unwrap()
    );
    declared.ensure_platform_compatible().unwrap();
}

#[test]
fn vm_only_accepts_dockerignore_patterns_and_refuses_unsafe_ones() {
    let document = parse_project_yaml(
        "workspace:\n  vm_only:\n    - node_modules\n    - '**/node_modules'\n    - packages/*/dist/\n    - '[bt]arget'\n",
    )
    .unwrap();
    // Overlapping patterns are fine, and a trailing / is dropped.
    assert_eq!(
        document.local.effective_vm_only(),
        [
            "node_modules",
            "**/node_modules",
            "packages/*/dist",
            "[bt]arget"
        ]
    );
    for (yaml, detail) in [
        ("workspace: {vm_only: ['']}\n", "is empty"),
        ("workspace: {vm_only: ['  ']}\n", "is empty"),
        ("workspace: {vm_only: [/abs]}\n", "relative"),
        ("workspace: {vm_only: [../up]}\n", ". or .."),
        ("workspace: {vm_only: [a/../b]}\n", ". or .."),
        ("workspace: {vm_only: [./a]}\n", ". or .."),
        ("workspace: {vm_only: [a//b]}\n", "empty segment"),
        ("workspace: {vm_only: [\"a\\tb\"]}\n", "control"),
        ("workspace: {vm_only: [a, a]}\n", "listed twice"),
        ("workspace: {vm_only: [.git]}\n", "Git repository"),
        ("workspace: {vm_only: ['**/.GIT']}\n", "Git repository"),
        ("workspace: {vm_only: ['**']}\n", "whole project"),
        ("workspace: {vm_only: ['!keep']}\n", "exception"),
        ("workspace: {vm_only: ['[ab']}\n", "unclosed"),
    ] {
        let error = parse_project_yaml(yaml).unwrap_err().to_string();
        assert!(
            error.contains("workspace.vm_only") && error.contains(detail),
            "{yaml:?}: {error}"
        );
    }
    let wide = (0..9)
        .map(|index| format!("{index}{}", "y".repeat(250)))
        .collect::<Vec<_>>();
    let error = parse_project_yaml(&format!("workspace: {{vm_only: [{}]}}\n", wide.join(", ")))
        .unwrap_err()
        .to_string();
    assert!(error.contains("2 KiB"), "{error}");
    let long = "x".repeat(256);
    assert!(parse_project_yaml(&format!("workspace: {{vm_only: [{long}]}}\n")).is_err());

    let many = (0..33).map(|index| format!("d{index}")).collect::<Vec<_>>();
    let error = parse_project_yaml(&format!("workspace: {{vm_only: [{}]}}\n", many.join(", ")))
        .unwrap_err();
    assert!(matches!(
        error,
        ProjectError::TooManyEntries {
            field: "workspace.vm_only",
            maximum: 32
        }
    ));
    for yaml in [
        "workspace: {vm-only: [a]}\n",
        "workspace: {unshared: [a]}\n",
        "workspace: [a]\n",
        "workspace: {vm_only: a}\n",
    ] {
        assert!(parse_project_yaml(yaml).is_err(), "accepted {yaml:?}");
    }
}
