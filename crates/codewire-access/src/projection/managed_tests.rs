use super::*;

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

/// Every name a selection projects: its reserved names, except the Anthropic
/// form it did not select, and for GitHub the two `gh` names, which are
/// projected without being reserved.
fn projected_names(selected: ManagedCredentialClients) -> BTreeSet<&'static str> {
    let mut names = selected.reserved_environment_keys();
    if selected.contains(ManagedCredentialClient::Anthropic) {
        names.remove("ANTHROPIC_API_KEY");
        names.remove(if selected.anthropic_subscription_token() {
            "ANTHROPIC_AUTH_TOKEN"
        } else {
            "CLAUDE_CODE_OAUTH_TOKEN"
        });
    }
    if selected.contains(ManagedCredentialClient::GitHub) {
        names.extend(["GH_CONFIG_DIR", "GH_TOKEN"]);
    }
    names
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
            BTreeMap::from([
                ("GH_CONFIG_DIR".to_owned(), gh_directory.to_owned()),
                ("GH_TOKEN".to_owned(), "codewire-managed".to_owned()),
                ("GIT_CONFIG_COUNT".to_owned(), "1".to_owned()),
                (
                    "GIT_CONFIG_KEY_0".to_owned(),
                    "url.http://127.0.0.1:38081/_codewire/github/.insteadOf".to_owned()
                ),
                (
                    "GIT_CONFIG_VALUE_0".to_owned(),
                    "https://github.com/".to_owned()
                ),
            ])
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
fn github_git_configuration_is_only_the_loopback_route() {
    for placement in [
        ManagedCredentialClientPlacement::Native,
        ManagedCredentialClientPlacement::Platform,
    ] {
        let projection = clients(&["github"]).for_placement(placement);
        for (name, value) in &projection.environment {
            if !name.starts_with("GIT_CONFIG_") {
                continue;
            }
            // An endpoint only: no credential, token, placeholder or userinfo.
            for forbidden in ["@", "token", "codewire-managed", "Bearer", "Basic", "gh"] {
                assert!(
                    !value.contains(forbidden) || value == "https://github.com/",
                    "{name}={value} carries {forbidden:?}"
                );
            }
        }
        let key = &projection.environment["GIT_CONFIG_KEY_0"];
        assert!(key.starts_with("url.http://127.0.0.1:38081/_codewire/github/"));
        assert!(key.ends_with(".insteadOf"));
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
    // Other git settings stay the workload's own.
    assert_eq!(
        github.check_collisions(["GIT_CONFIG_KEY_1", "GIT_AUTHOR_NAME"]),
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
