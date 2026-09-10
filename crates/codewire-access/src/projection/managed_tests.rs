use super::*;

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

#[test]
fn managed_clients_validate_exact_slots_before_discarding_unmanaged_slots() {
    assert_eq!(clients(&[]), ManagedCredentialClients::default());
    assert_eq!(clients(&["github"]), clients(&[]));
    assert_eq!(
        clients(&["anthropic", "github", "codex", "ssh", "openai"]),
        clients(&["codex", "openai", "anthropic", "ssh"])
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
fn managed_clients_have_exactly_sixteen_canonical_private_encodings() {
    let slots = ["codex", "openai", "anthropic", "ssh"];
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
        assert!(unique.insert(selected.encode()));
        assert_eq!(
            ManagedCredentialClients::decode(expected).unwrap(),
            selected
        );
    }
    assert_eq!(unique.len(), 16);
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
            ManagedCredentialClientPlacement::Platform => "/run/codewire-codex/home",
        };
        assert_eq!(
            codex.environment,
            BTreeMap::from([("CODEX_HOME".into(), expected_home.into())])
        );
        let config = codex.codex.unwrap();
        assert_eq!(
            config,
            CodexProviderProjection::for_loopback_port(38_081).unwrap()
        );
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
                ("ANTHROPIC_BASE_URL".into(), "http://127.0.0.1:38081".into()),
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
    assert_eq!(CODEX_NATIVE_HOME, "/run/codewire-agent/codex");
    assert_eq!(SSH_NATIVE_AUTH_SOCK, "/run/codewire-host/ssh-agent.sock");
    assert_eq!(SSH_PLATFORM_AUTH_SOCK, "/codewire/run/ssh-agent.sock");
}

#[test]
fn managed_client_projection_covers_all_owned_names_without_environment_lookup() {
    for bits in 0..16 {
        let slots = ["codex", "openai", "anthropic", "ssh"];
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
