use super::*;

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

/// Every name a selection projects: its reserved names, except the Anthropic
/// form it did not select; for GitHub the two `gh` names; and one Git
/// configuration entry per rewritten GitHub URL form (see
/// [`git_rewrite_entries`]). All but the first Git entry, and the `gh` names,
/// are projected without being reserved.
fn projected_names(selected: ManagedCredentialClients) -> BTreeSet<&'static str> {
    const KEYS: [&str; 4] = [
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_KEY_1",
        "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_KEY_3",
    ];
    const VALUES: [&str; 4] = [
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_VALUE_2",
        "GIT_CONFIG_VALUE_3",
    ];
    let mut names = selected.reserved_environment_keys();
    if selected.contains(ManagedCredentialClient::Anthropic) {
        names.remove("ANTHROPIC_API_KEY");
        if selected.anthropic_sign_in() {
            names.remove("ANTHROPIC_AUTH_TOKEN");
            names.remove("CLAUDE_CODE_OAUTH_TOKEN");
        } else {
            names.remove(if selected.anthropic_subscription_token() {
                "ANTHROPIC_AUTH_TOKEN"
            } else {
                "CLAUDE_CODE_OAUTH_TOKEN"
            });
        }
    }
    if selected.contains(ManagedCredentialClient::GitHub) {
        names.extend(["GH_CONFIG_DIR", "GH_TOKEN"]);
    }
    let entries = git_rewrite_entries(selected);
    if entries > 0 {
        names.insert("GIT_CONFIG_COUNT");
        names.extend(&KEYS[..entries]);
        names.extend(&VALUES[..entries]);
    }
    names
}

/// The number of GitHub URL forms a selection rewrites (issue #2720).
fn git_rewrite_entries(selected: ManagedCredentialClients) -> usize {
    match (
        selected.contains(ManagedCredentialClient::GitHub),
        selected.contains(ManagedCredentialClient::Ssh),
    ) {
        (true, false) => 4,
        (true, true) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

/// The managed GitHub route as an `insteadOf` key.
const MANAGED_GIT_KEY: &str = "url.http://127.0.0.1:38081/_codewire/github/.insteadOf";

#[test]
fn managed_clients_validate_exact_slots_without_discarding_github() {
    assert_eq!(clients(&[]), ManagedCredentialClients::default());
    assert_ne!(clients(&["github"]), clients(&[]));
    assert!(clients(&["github"]).contains(ManagedCredentialClient::GitHub));
    assert_eq!(
        clients(&["anthropic", "github", "codex", "ssh", "openai"]),
        clients(&["codex", "openai", "anthropic", "ssh", "github"])
    );
    for slot in ["codex", "openai", "anthropic", "github", "ssh"] {
        assert_eq!(
            ManagedCredentialClients::from_profile_slots([slot, slot]),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
    }
    let bounded = ["codex", "openai", "anthropic", "github", "ssh", "codex"]
        .into_iter()
        .chain(std::iter::once_with(|| {
            panic!("read beyond the closed slot bound")
        }));
    assert_eq!(
        ManagedCredentialClients::from_profile_slots(bounded),
        Err(ProjectionError::InvalidManagedClientSelection)
    );
    for slot in [
        "",
        "Codex",
        "openai-api-key",
        "codex-oauth",
        "claude",
        "codex ",
        " codex",
        "codex\n",
        "codex\0",
        "codex,openai",
        "v1:codex",
        "unknown",
    ] {
        assert_eq!(
            ManagedCredentialClients::from_profile_slots([slot]),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
    }
}

#[test]
fn managed_clients_have_exactly_32_canonical_private_encodings_preserving_v1() {
    let slots = ["codex", "openai", "anthropic", "ssh", "github"];
    let encodings = [
        "v1:none",
        "v1:codex",
        "v1:openai",
        "v1:codex,openai",
        "v1:anthropic",
        "v1:codex,anthropic",
        "v1:openai,anthropic",
        "v1:codex,openai,anthropic",
        "v1:ssh",
        "v1:codex,ssh",
        "v1:openai,ssh",
        "v1:codex,openai,ssh",
        "v1:anthropic,ssh",
        "v1:codex,anthropic,ssh",
        "v1:openai,anthropic,ssh",
        "v1:codex,openai,anthropic,ssh",
        "v2:10",
        "v2:11",
        "v2:12",
        "v2:13",
        "v2:14",
        "v2:15",
        "v2:16",
        "v2:17",
        "v2:18",
        "v2:19",
        "v2:1a",
        "v2:1b",
        "v2:1c",
        "v2:1d",
        "v2:1e",
        "v2:1f",
    ];
    let mut unique = BTreeSet::new();
    for (bits, expected) in encodings.into_iter().enumerate() {
        let selected = ManagedCredentialClients::from_profile_slots(
            slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| (bits & (1 << index) != 0).then_some(*slot)),
        )
        .unwrap();
        assert_eq!(selected.encode(), expected);
        assert!(selected.encode().len() < 32);
        assert!(unique.insert(selected.encode()));
        assert_eq!(
            ManagedCredentialClients::decode(expected).unwrap(),
            selected
        );
    }
    assert_eq!(unique.len(), 32);
    assert_eq!(
        encodings[..8].to_vec(),
        [
            "v1:none",
            "v1:codex",
            "v1:openai",
            "v1:codex,openai",
            "v1:anthropic",
            "v1:codex,anthropic",
            "v1:openai,anthropic",
            "v1:codex,openai,anthropic",
        ]
    );
    assert_eq!(encodings[15].len(), 29);
    for invalid in [
        "",
        "none",
        "codex",
        "v0:codex",
        "v2:codex",
        "v2:00",
        "v2:0f",
        "v2:20",
        "v2:1F",
        "v2:010",
        "v1:",
        "v1:0",
        "v1:github",
        "v1:ssh,codex",
        "v1:none,codex",
        "v1:openai,codex",
        "v1:codex,codex",
        "v1:codex,",
        "v1:codex, openai",
        "v1:CODEX",
        "v1:codex\n",
        "v1:codex\0",
    ] {
        assert_eq!(
            ManagedCredentialClients::decode(invalid),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
    }
}

#[test]
fn managed_clients_reserve_only_selected_client_names() {
    for (slots, expected) in [
        (vec![], vec![]),
        (
            vec!["github"],
            vec!["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"],
        ),
        (vec!["ssh"], vec!["SSH_AUTH_SOCK"]),
        (vec!["codex"], vec!["CODEX_HOME"]),
        (vec!["openai"], vec!["OPENAI_API_KEY", "OPENAI_BASE_URL"]),
        (
            vec!["anthropic"],
            vec![
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ],
        ),
    ] {
        assert_eq!(
            clients(&slots).reserved_environment_keys(),
            expected.into_iter().collect()
        );
    }
    let codex = clients(&["codex"]);
    let openai = clients(&["openai"]);
    assert_ne!(codex, openai);
    assert!(codex.contains(ManagedCredentialClient::Codex));
    assert!(!codex.contains(ManagedCredentialClient::OpenAi));
    assert!(openai.contains(ManagedCredentialClient::OpenAi));
    assert!(!openai.contains(ManagedCredentialClient::Codex));
    assert!(clients(&["ssh"]).contains(ManagedCredentialClient::Ssh));
    assert_eq!(
        clients(&["codex", "openai"]).reserved_environment_keys(),
        codex
            .reserved_environment_keys()
            .union(&openai.reserved_environment_keys())
            .copied()
            .collect()
    );
}

#[test]
fn managed_client_collisions_are_exact_selected_names_and_value_blind() {
    let all_names = clients(&["codex", "openai", "anthropic", "ssh"]).reserved_environment_keys();
    assert!(
        clients(&[])
            .check_collisions(all_names.iter().copied())
            .is_ok()
    );
    assert!(
        clients(&["codex"])
            .check_collisions(["OPENAI_API_KEY", "DATABASE_URL"])
            .is_ok()
    );
    assert!(
        clients(&["openai"])
            .check_collisions(["CODEX_HOME"])
            .is_ok()
    );
    for slot in ["codex", "openai", "anthropic", "ssh"] {
        let selected = clients(&[slot]);
        for name in selected.reserved_environment_keys() {
            let error = selected
                .check_collisions(["DATABASE_URL", name])
                .unwrap_err();
            assert_eq!(error, ProjectionError::ManagedEnvironmentCollision);
            assert!(!error.to_string().contains(name));
            assert!(
                selected
                    .check_collisions([format!("{name}_EXTRA").as_str()])
                    .is_ok()
            );
        }
    }
}

#[test]
fn managed_client_projection_is_selected_only_and_same_route_in_both_placements() {
    for placement in [
        ManagedCredentialClientPlacement::Native,
        ManagedCredentialClientPlacement::Platform,
    ] {
        let empty = clients(&[]).for_placement(placement);
        assert!(empty.environment.is_empty());
        assert!(empty.codex.is_none());
        // GitHub projects Git's URL rewrite to the managed route, and for
        // stock `gh` a public placeholder and Codewire's own configuration
        // directory, whose one file names the placement's ingress socket.
        let github = clients(&["github"]).for_placement(placement);
        assert!(github.codex.is_none());
        let (gh_directory, ingress_socket) = match placement {
            ManagedCredentialClientPlacement::Native => (
                "/run/codewire-host/gh",
                "/run/codewire-host/credential.sock",
            ),
            ManagedCredentialClientPlacement::Platform => {
                ("/codewire/run/gh", "/codewire/run/credentials.sock")
            }
        };
        assert_eq!(
            github.environment,
            BTreeMap::from(
                [
                    ("GH_CONFIG_DIR", gh_directory),
                    ("GH_TOKEN", "codewire-managed"),
                    ("GIT_CONFIG_COUNT", "4"),
                    ("GIT_CONFIG_KEY_0", MANAGED_GIT_KEY),
                    ("GIT_CONFIG_VALUE_0", "https://github.com/"),
                    ("GIT_CONFIG_KEY_1", MANAGED_GIT_KEY),
                    ("GIT_CONFIG_VALUE_1", "git://github.com/"),
                    ("GIT_CONFIG_KEY_2", MANAGED_GIT_KEY),
                    ("GIT_CONFIG_VALUE_2", "git@github.com:"),
                    ("GIT_CONFIG_KEY_3", MANAGED_GIT_KEY),
                    ("GIT_CONFIG_VALUE_3", "ssh://git@github.com/"),
                ]
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
            )
        );
        assert_eq!(
            github.gh.as_ref().unwrap().config_yml(),
            format!("version: 1\nhttp_unix_socket: {ingress_socket}\n")
        );
        assert!(empty.gh.is_none());
        let codex = clients(&["codex"]).for_placement(placement);
        let expected_home = match placement {
            ManagedCredentialClientPlacement::Native => "/run/codewire-agent/codex",
            ManagedCredentialClientPlacement::Platform => "/home/codewire/.codex",
        };
        assert_eq!(
            codex.environment,
            BTreeMap::from([("CODEX_HOME".into(), expected_home.into())])
        );
        let config = codex.codex.unwrap();
        let route = CodexProviderProjection::for_loopback_port(38_081).unwrap();
        match placement {
            ManagedCredentialClientPlacement::Native => assert_eq!(config, route),
            ManagedCredentialClientPlacement::Platform => assert_eq!(
                config.config_toml(),
                format!("{CODEX_MANAGED_CONFIG_HEADER}\n{}", route.config_toml())
            ),
        }
        assert!(
            !config
                .config_toml()
                .contains("[model_providers.codewire_openai.auth]")
        );
        assert!(!config.config_toml().contains("env_key"));

        let openai = clients(&["openai"]).for_placement(placement);
        assert!(openai.codex.is_none());
        assert_eq!(
            openai.environment,
            BTreeMap::from([
                (
                    "OPENAI_BASE_URL".into(),
                    "http://127.0.0.1:38081/_codewire/openai/v1".into()
                ),
                ("OPENAI_API_KEY".into(), "codewire-managed".into()),
            ])
        );
        let anthropic = clients(&["anthropic"]).for_placement(placement);
        assert!(anthropic.codex.is_none());
        assert_eq!(
            anthropic.environment,
            BTreeMap::from([
                (
                    "ANTHROPIC_BASE_URL".into(),
                    "http://127.0.0.1:38081/_codewire/anthropic".into()
                ),
                ("ANTHROPIC_AUTH_TOKEN".into(), "codewire-managed".into()),
            ])
        );
        let ssh = clients(&["ssh"]).for_placement(placement);
        assert!(ssh.codex.is_none());
        let expected_socket = match placement {
            ManagedCredentialClientPlacement::Native => SSH_NATIVE_AUTH_SOCK,
            ManagedCredentialClientPlacement::Platform => SSH_PLATFORM_AUTH_SOCK,
        };
        assert_eq!(
            ssh.environment,
            BTreeMap::from(
                [
                    ("SSH_AUTH_SOCK", expected_socket),
                    ("GIT_CONFIG_COUNT", "1"),
                    ("GIT_CONFIG_KEY_0", "url.git@github.com:.insteadOf"),
                    ("GIT_CONFIG_VALUE_0", "git://github.com/"),
                ]
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
            )
        );
    }
    assert_eq!(MANAGED_HTTP_PORT, 38_081);
    assert_eq!(MANAGED_OPENAI_API_PREFIX, "/_codewire/openai/v1");
    assert_eq!(MANAGED_ANTHROPIC_API_PREFIX, "/_codewire/anthropic");
    assert_eq!(MANAGED_GITHUB_GIT_PREFIX, "/_codewire/github/");
    assert_eq!(CODEX_NATIVE_HOME, "/run/codewire-agent/codex");
    assert_eq!(SSH_NATIVE_AUTH_SOCK, "/run/codewire-host/ssh-agent.sock");
    assert_eq!(SSH_PLATFORM_AUTH_SOCK, "/codewire/run/ssh-agent.sock");
}

#[test]
fn managed_client_projection_covers_all_owned_names_without_environment_lookup() {
    for bits in 0..32 {
        let slots = ["codex", "openai", "anthropic", "ssh", "github"];
        let selected = ManagedCredentialClients::from_profile_slots(
            slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| (bits & (1 << index) != 0).then_some(*slot)),
        )
        .unwrap();
        for placement in [
            ManagedCredentialClientPlacement::Native,
            ManagedCredentialClientPlacement::Platform,
        ] {
            let projection = selected.for_placement(placement);
            assert_eq!(
                projection
                    .environment
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                projected_names(selected)
            );
            assert_eq!(
                projection.codex.is_some(),
                selected.contains(ManagedCredentialClient::Codex)
            );
            assert_eq!(
                projection.gh.is_some(),
                selected.contains(ManagedCredentialClient::GitHub)
            );
            assert!(
                projection
                    .environment
                    .values()
                    .all(|value| !value.contains('\0') && !value.contains('\n'))
            );
        }
    }
}

#[test]
fn anthropic_subscription_form_adds_16_canonical_encodings_and_keeps_the_api_key_bytes() {
    for slots in [vec![], vec!["codex"], vec!["openai", "ssh", "github"]] {
        assert_eq!(
            clients(&slots).with_anthropic_subscription_token(),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
        assert!(!clients(&slots).anthropic_subscription_token());
    }
    // From slot names alone the Anthropic client is always the API-key form.
    assert!(!clients(&["anthropic"]).anthropic_subscription_token());
    let others = ["codex", "openai", "ssh", "github"];
    let expected = [
        "v2:24", "v2:25", "v2:26", "v2:27", "v2:2c", "v2:2d", "v2:2e", "v2:2f", "v2:34", "v2:35",
        "v2:36", "v2:37", "v2:3c", "v2:3d", "v2:3e", "v2:3f",
    ];
    let mut unique = BTreeSet::new();
    for (index, encoding) in expected.into_iter().enumerate() {
        let api_key = clients(
            &std::iter::once("anthropic")
                .chain(
                    others
                        .iter()
                        .enumerate()
                        .filter_map(|(bit, slot)| (index & (1 << bit) != 0).then_some(*slot)),
                )
                .collect::<Vec<_>>(),
        );
        let subscription = api_key.with_anthropic_subscription_token().unwrap();
        assert_eq!(subscription.encode(), encoding);
        assert!(subscription.encode().len() < 32);
        assert_eq!(
            ManagedCredentialClients::decode(encoding).unwrap(),
            subscription
        );
        assert!(subscription.anthropic_subscription_token());
        assert!(subscription.contains(ManagedCredentialClient::Anthropic));
        assert_eq!(
            subscription.with_anthropic_subscription_token(),
            Ok(subscription)
        );
        assert_ne!(subscription, api_key);
        assert_ne!(subscription.encode(), api_key.encode());
        for client in [
            ManagedCredentialClient::Codex,
            ManagedCredentialClient::OpenAi,
            ManagedCredentialClient::Ssh,
            ManagedCredentialClient::GitHub,
        ] {
            assert_eq!(subscription.contains(client), api_key.contains(client));
        }
        // The same names are owned in both forms; only their values differ.
        assert_eq!(
            subscription.reserved_environment_keys(),
            api_key.reserved_environment_keys()
        );
        for placement in [
            ManagedCredentialClientPlacement::Native,
            ManagedCredentialClientPlacement::Platform,
        ] {
            let projection = subscription.for_placement(placement);
            let reference = api_key.for_placement(placement);
            assert_eq!(projection.codex, reference.codex);
            assert_eq!(
                projection
                    .environment
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                projected_names(subscription)
            );
            for (name, value) in &reference.environment {
                if !name.starts_with("ANTHROPIC_") && name != "CLAUDE_CODE_OAUTH_TOKEN" {
                    assert_eq!(projection.environment.get(name), Some(value), "{name}");
                }
            }
        }
        assert!(unique.insert(encoding));
    }
    for bits in 0..32 {
        let slots = ["codex", "openai", "anthropic", "ssh", "github"];
        let selected = ManagedCredentialClients::from_profile_slots(
            slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| (bits & (1 << index) != 0).then_some(*slot)),
        )
        .unwrap();
        assert!(unique.insert(selected.encode()));
    }
    assert_eq!(unique.len(), 48);
    for invalid in [
        "v2:20",
        "v2:21",
        "v2:22",
        "v2:23",
        "v2:28",
        "v2:30",
        "v2:3b",
        "v2:3F",
        "v2:40",
        "v2:024",
        "v3:24",
        "v1:anthropic",
        "v1:anthropic-subscription",
        "v2:24\n",
    ] {
        if invalid == "v1:anthropic" {
            assert!(
                !ManagedCredentialClients::decode(invalid)
                    .unwrap()
                    .anthropic_subscription_token()
            );
            continue;
        }
        assert_eq!(
            ManagedCredentialClients::decode(invalid),
            Err(ProjectionError::InvalidManagedClientSelection),
            "{invalid}"
        );
    }
}

/// The sign-in form: 16 more encodings, never combined with the
/// subscription-token form, projecting the base URL alone while every
/// Anthropic name stays reserved.
#[test]
fn anthropic_sign_in_form_adds_16_encodings_and_projects_the_base_url_alone() {
    for slots in [vec![], vec!["codex"], vec!["openai", "ssh", "github"]] {
        assert_eq!(
            clients(&slots).with_anthropic_sign_in(),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
    }
    assert!(!clients(&["anthropic"]).anthropic_sign_in());
    let others = ["codex", "openai", "ssh", "github"];
    let expected = [
        "v2:44", "v2:45", "v2:46", "v2:47", "v2:4c", "v2:4d", "v2:4e", "v2:4f", "v2:54", "v2:55",
        "v2:56", "v2:57", "v2:5c", "v2:5d", "v2:5e", "v2:5f",
    ];
    let mut unique = BTreeSet::new();
    for (index, encoding) in expected.into_iter().enumerate() {
        let api_key = clients(
            &std::iter::once("anthropic")
                .chain(
                    others
                        .iter()
                        .enumerate()
                        .filter_map(|(bit, slot)| (index & (1 << bit) != 0).then_some(*slot)),
                )
                .collect::<Vec<_>>(),
        );
        let sign_in = api_key.with_anthropic_sign_in().unwrap();
        assert_eq!(sign_in.encode(), encoding);
        assert!(sign_in.encode().len() < 32);
        assert_eq!(ManagedCredentialClients::decode(encoding).unwrap(), sign_in);
        assert!(sign_in.anthropic_sign_in() && !sign_in.anthropic_subscription_token());
        assert_eq!(sign_in.with_anthropic_sign_in(), Ok(sign_in));
        // The two forms never combine, in either order.
        assert_eq!(
            sign_in.with_anthropic_subscription_token(),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
        assert_eq!(
            api_key
                .with_anthropic_subscription_token()
                .unwrap()
                .with_anthropic_sign_in(),
            Err(ProjectionError::InvalidManagedClientSelection)
        );
        for client in [
            ManagedCredentialClient::Codex,
            ManagedCredentialClient::OpenAi,
            ManagedCredentialClient::Ssh,
            ManagedCredentialClient::GitHub,
        ] {
            assert_eq!(sign_in.contains(client), api_key.contains(client));
        }
        assert_eq!(
            sign_in.reserved_environment_keys(),
            api_key.reserved_environment_keys()
        );
        for placement in [
            ManagedCredentialClientPlacement::Native,
            ManagedCredentialClientPlacement::Platform,
        ] {
            let projection = sign_in.for_placement(placement);
            let reference = api_key.for_placement(placement);
            assert_eq!(projection.codex, reference.codex);
            assert_eq!(
                projection
                    .environment
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                projected_names(sign_in)
            );
            assert_eq!(
                projection.environment["ANTHROPIC_BASE_URL"],
                "http://127.0.0.1:38081/_codewire/anthropic"
            );
            for name in [
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_API_KEY",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ] {
                assert!(!projection.environment.contains_key(name), "{name}");
                assert!(sign_in.reserved_environment_keys().contains(name), "{name}");
            }
            for (name, value) in &reference.environment {
                if !name.starts_with("ANTHROPIC_") {
                    assert_eq!(projection.environment.get(name), Some(value), "{name}");
                }
            }
        }
        assert!(unique.insert(encoding));
    }
    // Disjoint from the other 48 encodings.
    for bits in 0..32 {
        let slots = ["codex", "openai", "anthropic", "ssh", "github"];
        let selected = ManagedCredentialClients::from_profile_slots(
            slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| (bits & (1 << index) != 0).then_some(*slot)),
        )
        .unwrap();
        assert!(unique.insert(selected.encode()));
        if let Ok(subscription) = selected.with_anthropic_subscription_token() {
            assert!(unique.insert(subscription.encode()));
        }
    }
    assert_eq!(unique.len(), 64);
    for invalid in [
        "v2:40", "v2:41", "v2:48", "v2:50", "v2:60", "v2:64", "v2:7f", "v2:4F",
    ] {
        assert_eq!(
            ManagedCredentialClients::decode(invalid),
            Err(ProjectionError::InvalidManagedClientSelection),
            "{invalid}"
        );
    }
}

#[test]
fn anthropic_subscription_projection_is_the_exact_claude_code_oauth_placeholder() {
    for placement in [
        ManagedCredentialClientPlacement::Native,
        ManagedCredentialClientPlacement::Platform,
    ] {
        let projection = clients(&["anthropic"])
            .with_anthropic_subscription_token()
            .unwrap()
            .for_placement(placement);
        assert!(projection.codex.is_none());
        assert_eq!(
            projection.environment,
            BTreeMap::from([
                (
                    "ANTHROPIC_BASE_URL".into(),
                    "http://127.0.0.1:38081/_codewire/anthropic".into()
                ),
                ("CLAUDE_CODE_OAUTH_TOKEN".into(), "codewire-managed".into()),
            ])
        );
        // The API-key form projects only its own variable too.
        assert_eq!(
            clients(&["anthropic"]).for_placement(placement).environment,
            BTreeMap::from([
                (
                    "ANTHROPIC_BASE_URL".into(),
                    "http://127.0.0.1:38081/_codewire/anthropic".into()
                ),
                ("ANTHROPIC_AUTH_TOKEN".into(), "codewire-managed".into()),
            ])
        );
    }
}

/// Each Anthropic form projects only its own variable, never the other
/// form's and never `ANTHROPIC_API_KEY`, while all four names stay reserved,
/// so a declared value of any of them is still refused.
#[test]
fn each_anthropic_form_projects_only_its_own_variable_and_reserves_all_four() {
    let api_key = clients(&["anthropic"]);
    let subscription = api_key.with_anthropic_subscription_token().unwrap();
    for placement in [
        ManagedCredentialClientPlacement::Native,
        ManagedCredentialClientPlacement::Platform,
    ] {
        for (selected, own, others) in [
            (
                subscription,
                "CLAUDE_CODE_OAUTH_TOKEN",
                ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"],
            ),
            (
                api_key,
                "ANTHROPIC_AUTH_TOKEN",
                ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"],
            ),
        ] {
            let environment = selected.for_placement(placement).environment;
            assert_eq!(environment[own], "codewire-managed");
            for other in others {
                assert!(!environment.contains_key(other), "{other}");
            }
            // No projected value is empty: nothing is cleared by an empty
            // string, which a client could read as set.
            assert!(environment.values().all(|value| !value.is_empty()));
            for name in [
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_API_KEY",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ] {
                assert!(selected.reserved_environment_keys().contains(name));
                assert_eq!(
                    selected.check_collisions([name]),
                    Err(ProjectionError::ManagedEnvironmentCollision),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn github_git_configuration_is_only_the_loopback_route_or_githubs_own_url_forms() {
    let forms = [
        GITHUB_HTTPS_URL,
        GITHUB_GIT_URL,
        GITHUB_SCP_URL,
        GITHUB_SSH_URL,
    ];
    assert_eq!(
        forms,
        [
            "https://github.com/",
            "git://github.com/",
            "git@github.com:",
            "ssh://git@github.com/"
        ]
    );
    for slots in [&["github"][..], &["ssh"], &["github", "ssh"]] {
        for placement in [
            ManagedCredentialClientPlacement::Native,
            ManagedCredentialClientPlacement::Platform,
        ] {
            let projection = clients(slots).for_placement(placement);
            for (name, value) in &projection.environment {
                if name.starts_with("GIT_CONFIG_VALUE_") {
                    // A value is only a GitHub URL form, matched as a prefix.
                    assert!(forms.contains(&value.as_str()), "{name}={value}");
                } else if name.starts_with("GIT_CONFIG_KEY_") {
                    // A destination only: the loopback route, or GitHub's own
                    // SSH form for the selected key. Never a credential,
                    // token, placeholder, userinfo or other Git setting.
                    assert!(
                        value == MANAGED_GIT_KEY || value == "url.git@github.com:.insteadOf",
                        "{name}={value}"
                    );
                    for forbidden in ["token", "codewire-managed", "Bearer", "Basic", "gh"] {
                        assert!(!value.contains(forbidden), "{name}={value}");
                    }
                }
            }
        }
    }
}

/// Issue #2720: which GitHub URL forms Git in the workspace rewrites, and to
/// where, for each selection and placement.
///
/// | Selected | Rewritten |
/// |---|---|
/// | GitHub connection only | every form to the managed GitHub route |
/// | SSH key only | `git://` to `git@github.com:`; HTTPS stays anonymous |
/// | both | HTTPS and `git://` to the managed route; SSH forms keep the key |
/// | neither | nothing |
#[test]
fn each_selection_rewrites_exactly_its_github_url_forms() {
    let managed = "url.http://127.0.0.1:38081/_codewire/github/.insteadOf";
    let ssh = "url.git@github.com:.insteadOf";
    let http_forms = ["https://github.com/", "git://github.com/"];
    let git_protocol = ["git://github.com/"];
    let all_forms = [
        "https://github.com/",
        "git://github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
    ];
    for (slots, key, values) in [
        (&["github"][..], Some(managed), &all_forms[..]),
        (&["ssh"], Some(ssh), &git_protocol[..]),
        (&["github", "ssh"], Some(managed), &http_forms[..]),
        (&[], None, &[][..]),
        (&["codex", "openai", "anthropic"], None, &[][..]),
    ] {
        for extra in [&[][..], &["codex", "anthropic"]] {
            let slots: Vec<_> = slots.iter().chain(extra).copied().collect();
            let mut deduplicated = slots.clone();
            deduplicated.sort_unstable();
            deduplicated.dedup();
            if deduplicated.len() != slots.len() {
                continue;
            }
            for placement in [
                ManagedCredentialClientPlacement::Native,
                ManagedCredentialClientPlacement::Platform,
            ] {
                let environment = clients(&slots).for_placement(placement).environment;
                let git: BTreeMap<_, _> = environment
                    .iter()
                    .filter(|(name, _)| name.starts_with("GIT_"))
                    .collect();
                let Some(key) = key else {
                    assert!(git.is_empty(), "{slots:?}");
                    continue;
                };
                assert_eq!(
                    environment["GIT_CONFIG_COUNT"],
                    values.len().to_string(),
                    "{slots:?}"
                );
                assert_eq!(git.len(), 1 + 2 * values.len(), "{slots:?}");
                for (index, value) in values.iter().enumerate() {
                    assert_eq!(environment[&format!("GIT_CONFIG_KEY_{index}")], key);
                    assert_eq!(environment[&format!("GIT_CONFIG_VALUE_{index}")], *value);
                }
            }
        }
    }
}

/// Stock Git, given exactly the projected environment, rewrites each GitHub
/// URL form to the table's destination and leaves every other host as
/// written. `git ls-remote --get-url` applies `insteadOf` without contacting
/// any remote.
#[cfg(unix)]
#[test]
fn stock_git_resolves_every_github_url_form_as_the_table_says() {
    let route = "http://127.0.0.1:38081/_codewire/github/";
    let untouched = [
        "https://gitlab.com/org/app.git",
        "git@gitlab.com:org/app.git",
        "ssh://git@gitlab.com/org/app.git",
        "git://gitlab.com/org/app.git",
        "https://github.example.com/org/app.git",
        "git@github.example.com:org/app.git",
        "https://gist.github.com/org/app.git",
        "ssh://git@github.com:2222/org/app.git",
        "https://user@github.com/org/app.git",
    ];
    for (slots, expected) in [
        (
            &["github"][..],
            [
                format!("{route}org/app.git"),
                format!("{route}org/app.git"),
                format!("{route}org/app.git"),
                format!("{route}org/app.git"),
            ],
        ),
        // A key GitHub may not accept never breaks a public HTTPS fetch.
        (
            &["ssh"],
            [
                "https://github.com/org/app.git".to_owned(),
                "git@github.com:org/app.git".to_owned(),
                "git@github.com:org/app.git".to_owned(),
                "ssh://git@github.com/org/app.git".to_owned(),
            ],
        ),
        (
            &["github", "ssh"],
            [
                format!("{route}org/app.git"),
                format!("{route}org/app.git"),
                "git@github.com:org/app.git".to_owned(),
                "ssh://git@github.com/org/app.git".to_owned(),
            ],
        ),
        (
            &[],
            [
                "https://github.com/org/app.git".to_owned(),
                "git://github.com/org/app.git".to_owned(),
                "git@github.com:org/app.git".to_owned(),
                "ssh://git@github.com/org/app.git".to_owned(),
            ],
        ),
    ] {
        for placement in [
            ManagedCredentialClientPlacement::Native,
            ManagedCredentialClientPlacement::Platform,
        ] {
            let environment = clients(slots).for_placement(placement).environment;
            let resolve = |url: &str| {
                let output = std::process::Command::new("git")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", "/nonexistent")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .envs(&environment)
                    .args(["-C", "/", "ls-remote", "--get-url", "--", url])
                    .output()
                    .expect("stock git is installed");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout)
                    .unwrap()
                    .trim_end()
                    .to_owned()
            };
            for (url, expected) in [
                "https://github.com/org/app.git",
                "git://github.com/org/app.git",
                "git@github.com:org/app.git",
                "ssh://git@github.com/org/app.git",
            ]
            .into_iter()
            .zip(&expected)
            {
                assert_eq!(&resolve(url), expected, "{slots:?} {url}");
            }
            for url in untouched {
                assert_eq!(resolve(url), url, "{slots:?}");
            }
        }
    }
}

#[test]
fn a_declared_git_configuration_is_refused_while_github_is_selected() {
    let github = clients(&["github"]);
    for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"] {
        assert_eq!(
            github.check_collisions([name]),
            Err(ProjectionError::ManagedEnvironmentCollision),
            "{name}"
        );
        assert_eq!(clients(&["codex"]).check_collisions([name]), Ok(()));
    }
    // The further rewrite entries are projected without being reserved, so
    // a declared one is not refused (the projected value wins instead), and
    // other Git settings stay the workload's own. An SSH-only selection
    // reserves none of Git's names, though it projects its rewrite.
    for slots in [&["github"][..], &["ssh"], &["github", "ssh"]] {
        assert_eq!(
            clients(slots).check_collisions([
                "GIT_CONFIG_KEY_1",
                "GIT_CONFIG_VALUE_3",
                "GIT_AUTHOR_NAME"
            ]),
            Ok(())
        );
    }
    assert_eq!(
        clients(&["ssh"]).check_collisions(["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0"]),
        Ok(())
    );
}

/// Every managed HTTP route is the workspace's loopback ingress, so a proxy
/// the user declares must never receive those requests. The exemption list is
/// extended, never replaced, and only while an HTTP client is selected.
#[test]
fn a_declared_proxy_is_bypassed_for_loopback_while_an_http_client_is_selected() {
    assert_eq!(MANAGED_NO_PROXY, ["127.0.0.1", "localhost", "::1"]);
    assert_eq!(NO_PROXY_NAMES, ["NO_PROXY", "no_proxy"]);
    for slots in [
        &["codex"][..],
        &["openai"],
        &["anthropic"],
        &["github"],
        &["ssh", "github"],
        &["codex", "openai", "anthropic", "ssh", "github"],
    ] {
        let selected = clients(slots);
        assert!(selected.uses_loopback_http(), "{slots:?}");
        // Nothing declared: exactly the loopback destinations.
        for empty in [None, Some("")] {
            assert_eq!(
                selected.no_proxy(empty).as_deref(),
                Some("127.0.0.1,localhost,::1"),
                "{slots:?}"
            );
        }
        // A declared list keeps its entries, as written and in order.
        assert_eq!(
            selected
                .no_proxy(Some("corp.example, 10.0.0.0/8,.internal"))
                .as_deref(),
            Some("corp.example, 10.0.0.0/8,.internal,127.0.0.1,localhost,::1")
        );
        // An entry already listed is not repeated, whatever its case.
        assert_eq!(
            selected
                .no_proxy(Some("LOCALHOST,corp.example,127.0.0.1"))
                .as_deref(),
            Some("LOCALHOST,corp.example,127.0.0.1,::1")
        );
        assert_eq!(
            selected.no_proxy(Some("*")).as_deref(),
            Some("*,127.0.0.1,localhost,::1")
        );
        assert_eq!(
            selected.no_proxy(Some("corp.example,")).as_deref(),
            Some("corp.example,127.0.0.1,localhost,::1")
        );
        // Applying it again changes nothing.
        let once = selected.no_proxy(Some("corp.example")).unwrap();
        assert_eq!(selected.no_proxy(Some(&once)), Some(once));
    }
    // SSH alone, or nothing, uses no HTTP route: the value is the caller's.
    for slots in [&[][..], &["ssh"]] {
        let selected = clients(slots);
        assert!(!selected.uses_loopback_http());
        assert_eq!(selected.no_proxy(None), None);
        assert_eq!(
            selected.no_proxy(Some("corp.example")).as_deref(),
            Some("corp.example")
        );
    }
    // The names are not reserved and not part of the projected variables:
    // a declared list is extended by each placement's environment builder.
    let all = clients(&["codex", "openai", "anthropic", "ssh", "github"]);
    assert_eq!(all.check_collisions(NO_PROXY_NAMES), Ok(()));
    for placement in [
        ManagedCredentialClientPlacement::Native,
        ManagedCredentialClientPlacement::Platform,
    ] {
        let projection = all.for_placement(placement);
        for name in NO_PROXY_NAMES {
            assert!(!projection.environment.contains_key(name));
        }
    }
}

/// Stock `gh` is configured by a public placeholder and one Codewire-owned
/// file. Neither can carry a credential: the placeholder is a fixed constant
/// the broker never forwards, and the file names only a local socket.
#[test]
fn github_cli_configuration_is_a_public_placeholder_and_the_ingress_socket_only() {
    assert_eq!(GH_TOKEN_PLACEHOLDER, "codewire-managed");
    assert_eq!(GH_CONFIG_FILE_NAME, "config.yml");
    for (placement, directory, socket, signer) in [
        (
            ManagedCredentialClientPlacement::Native,
            GH_NATIVE_CONFIG_DIR,
            MANAGED_HTTP_NATIVE_SOCKET,
            SSH_NATIVE_AUTH_SOCK,
        ),
        (
            ManagedCredentialClientPlacement::Platform,
            GH_PLATFORM_CONFIG_DIR,
            MANAGED_HTTP_PLATFORM_SOCKET,
            SSH_PLATFORM_AUTH_SOCK,
        ),
    ] {
        let projection = clients(&["github"]).for_placement(placement);
        assert_eq!(projection.environment["GH_TOKEN"], GH_TOKEN_PLACEHOLDER);
        assert_eq!(projection.environment["GH_CONFIG_DIR"], directory);
        // No host override: `gh` keeps its own default, github.com.
        for absent in ["GH_HOST", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GH_REPO"] {
            assert!(!projection.environment.contains_key(absent), "{absent}");
        }
        let config = projection.gh.unwrap();
        assert_eq!(
            config.config_yml().lines().collect::<Vec<_>>(),
            ["version: 1", &format!("http_unix_socket: {socket}")]
        );
        for forbidden in [
            "token",
            "oauth",
            "hosts",
            "user",
            "git_protocol",
            "@",
            "http://",
        ] {
            assert!(!config.config_yml().contains(forbidden), "{forbidden}");
        }
        // The directory and the HTTP ingress socket sit beside the signer
        // socket, in the placement's one runtime directory.
        let runtime = std::path::Path::new(signer).parent().unwrap();
        assert_eq!(std::path::Path::new(directory).parent(), Some(runtime));
        assert_eq!(std::path::Path::new(socket).parent(), Some(runtime));
        // Without GitHub nothing of `gh` is projected, whatever else is.
        let others = clients(&["codex", "openai", "anthropic", "ssh"]).for_placement(placement);
        assert!(others.gh.is_none());
        assert!(
            !others
                .environment
                .keys()
                .any(|name| name.starts_with("GH_"))
        );
    }
}

/// The `gh` names are projected but not reserved. The reserved set is bound
/// into each environment's projection selection digest, so it stays exactly
/// Git's three names; `GH_TOKEN` is refused with the GitHub provider's own.
#[test]
fn github_cli_names_do_not_change_the_reserved_set() {
    let github = clients(&["github"]);
    assert_eq!(
        github.reserved_environment_keys(),
        ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"]
            .into_iter()
            .collect()
    );
    assert_eq!(
        github.check_collisions(["GH_CONFIG_DIR", "GH_TOKEN"]),
        Ok(())
    );
    assert!(
        crate::HttpProvider::GitHubOAuth
            .reserved_environment_keys()
            .contains(&"GH_TOKEN")
    );
}

/// One rule picks a managed agent's provider client on every placement.
#[test]
fn a_managed_agent_uses_the_codex_slot_first_and_the_api_key_slot_only_without_it() {
    use ManagedCredentialClient::{Anthropic, Codex, OpenAi};
    for (slots, codex, claude) in [
        (&[][..], None, None),
        (&["codex"], Some(Codex), None),
        (&["openai"], Some(OpenAi), None),
        (&["codex", "openai"], Some(Codex), None),
        (&["anthropic"], None, Some(Anthropic)),
        (&["ssh", "github"], None, None),
        (
            &["codex", "openai", "anthropic", "ssh", "github"],
            Some(Codex),
            Some(Anthropic),
        ),
    ] {
        let selected = clients(slots);
        assert_eq!(
            selected.managed_agent_client(ManagedAgent::Codex),
            codex,
            "{slots:?}"
        );
        assert_eq!(
            selected.managed_agent_client(ManagedAgent::Claude),
            claude,
            "{slots:?}"
        );
    }
    // The subscription form is still the Anthropic client.
    let subscription = clients(&["anthropic"])
        .with_anthropic_subscription_token()
        .unwrap();
    assert_eq!(
        subscription.managed_agent_client(ManagedAgent::Claude),
        Some(Anthropic)
    );
}

#[test]
fn a_launch_without_a_usable_github_connection_omits_only_the_github_client() {
    let all = clients(&["codex", "openai", "anthropic", "ssh", "github"]);
    assert_eq!(
        all.without_github(),
        clients(&["codex", "openai", "anthropic", "ssh"])
    );
    assert_eq!(clients(&["github"]).without_github(), clients(&[]));
    assert_eq!(clients(&["codex"]).without_github(), clients(&["codex"]));
    // The Anthropic form is unaffected.
    let subscription = clients(&["anthropic", "github"])
        .with_anthropic_subscription_token()
        .unwrap();
    assert_eq!(
        subscription.without_github(),
        clients(&["anthropic"])
            .with_anthropic_subscription_token()
            .unwrap()
    );
}
