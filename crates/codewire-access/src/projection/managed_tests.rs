use super::*;

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

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
        (vec!["github"], vec![]),
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
        for empty in [clients(&[]), clients(&["github"])] {
            let projection = empty.for_placement(placement);
            assert!(projection.environment.is_empty());
            assert!(projection.codex.is_none());
        }
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
                ("ANTHROPIC_API_KEY".into(), String::new()),
                ("CLAUDE_CODE_OAUTH_TOKEN".into(), String::new()),
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
            BTreeMap::from([("SSH_AUTH_SOCK".into(), expected_socket.into())])
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
                selected.reserved_environment_keys()
            );
            assert_eq!(
                projection.codex.is_some(),
                selected.contains(ManagedCredentialClient::Codex)
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
                subscription.reserved_environment_keys()
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
                ("ANTHROPIC_AUTH_TOKEN".into(), String::new()),
                ("ANTHROPIC_API_KEY".into(), String::new()),
            ])
        );
        // The API-key form keeps its exact projection.
        assert_eq!(
            clients(&["anthropic"]).for_placement(placement).environment,
            BTreeMap::from([
                (
                    "ANTHROPIC_BASE_URL".into(),
                    "http://127.0.0.1:38081/_codewire/anthropic".into()
                ),
                ("ANTHROPIC_AUTH_TOKEN".into(), "codewire-managed".into()),
                ("ANTHROPIC_API_KEY".into(), String::new()),
                ("CLAUDE_CODE_OAUTH_TOKEN".into(), String::new()),
            ])
        );
    }
}
