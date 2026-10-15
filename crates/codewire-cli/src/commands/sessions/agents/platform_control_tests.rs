//! Proposed source-only fixture tests. No provider or production path override.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _temp: tempfile::TempDir,
    environment: DriverEnvironment,
    origin: Origin,
    session: String,
    dir: PathBuf,
    message: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let driver = uuid::Uuid::new_v4().to_string();
        let environment = DriverEnvironment::Guest {
            id: id.clone(),
            root: temp.path().to_owned(),
        };
        let session = format!("session-{driver}");
        private_directory(&agents_root(&environment)).unwrap();
        let dir = agents_root(&environment).join(&driver);
        private_directory(&dir).unwrap();
        private_directory(&dir.join("messages")).unwrap();
        let origin = Origin {
            version: 1,
            environment_id: id.clone(),
            org_id: "fixture-org".into(),
            pod_uid: uuid::Uuid::new_v4().to_string(),
            binding_generation: u64::MAX,
            projection_selection_sha256: [1; 32],
            driver_id: driver.clone(),
            agent: AgentKind::Codex,
            support_image_sha256: [2; 32],
            support_image_size: 1024,
            provider: codewire_daemon::platform_managed::ProviderIdentity {
                sha256: [3; 32],
                size: 1024,
                version: "0.160.0".into(),
            },
            parent_generation: None,
        };
        write_private_json(&dir.join(ORIGIN), &origin).unwrap();
        write_private_json(
            &dir.join(GENERATION),
            &Generation {
                version: 1,
                driver_id: driver.clone(),
                session_id: session.clone(),
                generation: 1,
                resumed_from_pod_uid: None,
            },
        )
        .unwrap();
        write_private_json(
            &dir.join("config.json"),
            &AgentConfig {
                version: 1,
                driver_id: driver.clone(),
                environment_id: id,
                agent: AgentKind::Codex,
                program: PathBuf::from("/usr/bin/false"),
                program_fallback: None,
                model: "synthetic".into(),
                effort: Some("high".into()),
                working_dir: temp.path().to_string_lossy().into_owned(),
                name: String::new(),
                parent: None,
                initial_message_id: None,
                created_at: now(),
            },
        )
        .unwrap();
        write_private_json(
            &dir.join("binding.json"),
            &AgentBinding {
                driver_id: driver.clone(),
                session_id: session.clone(),
                bound_at: now(),
            },
        )
        .unwrap();
        let mut record = MessageRecord::new(
            &driver,
            &session,
            MessageAction::Message,
            "synthetic".into(),
        );
        record.platform_launch_generation = Some(1);
        let message = record.id.clone();
        write_private_json(&message_path(&dir, &message), &record).unwrap();
        Self {
            _temp: temp,
            environment,
            origin,
            session,
            dir,
            message,
        }
    }
    fn request(&self) -> Envelope {
        Envelope {
            version: 1,
            origin: self.origin.clone(),
            session_id: self.session.clone(),
            launch_generation: 1,
            request: Request::GetMessage {
                driver_id: self.origin.driver_id.clone(),
                message_id: self.message.clone(),
            },
        }
    }
    fn clean_peer(&self) -> guest_peer::PeerIdentity {
        // Synthetic retained custody records exercise the actual file/lock/CAS
        // helper. They are not an observed guardian or provider qualification.
        let at = now();
        let peer = guest_peer::PeerIdentity {
            environment_id: self.environment.id().into(),
            driver_id: self.origin.driver_id.clone(),
            session_id: self.session.clone(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            driver_started_at: at.clone(),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
                .into(),
            driver_pid: 42,
            driver_start_ticks: 100,
        };
        write_private_json(
            &self.dir.join("state.json"),
            &DriverState {
                version: 1,
                driver_id: self.origin.driver_id.clone(),
                agent: AgentKind::Codex,
                phase: DriverPhase::Stopped,
                native_thread_id: Some("synthetic-thread".into()),
                native_thread_established: true,
                current_turn_id: None,
                active_message_id: None,
                queued: 0,
                capabilities: AgentCapabilities {
                    steer: true,
                    interrupt: true,
                    resume: false,
                    note: "synthetic".into(),
                },
                policy: CODEX_POLICY.into(),
                last_error: None,
                started_at: at.clone(),
                updated_at: at.clone(),
            },
        )
        .unwrap();
        write_private_json(&self.dir.join("peer-current.json"), &peer).unwrap();
        write_private_json(
            &self.dir.join(format!("peer-{}.json", peer.instance_id)),
            &guest_peer::PeerReceipt {
                version: 1,
                identity: peer.clone(),
                guardian_pid: Some(43),
                guardian_start_ticks: Some(101),
                provider_pid: Some(44),
                cleanup_unknown: false,
                finished_at: Some(at),
                exit_code: Some(0),
                error: None,
            },
        )
        .unwrap();
        peer
    }
}
#[test]
fn platform_control_ordinary_native_role_cannot_mutate_scoped_records() {
    let f = Fixture::new();
    let path = message_path(&f.dir, &f.message);
    let before = fs::read(&path).unwrap();
    assert!(
        native::handle(
            &f.environment,
            native::ControlRequest::MarkDelivery {
                driver_id: f.origin.driver_id.clone(),
                session_id: f.session.clone(),
                message_id: f.message.clone(),
                outcome: native::DeliveryOutcome::Written,
                error: None
            },
            &|_| panic!("no provider resolution")
        )
        .is_err()
    );
    assert_eq!(before, fs::read(path).unwrap());
}
#[test]
fn platform_control_historical_read_requires_saved_original_message_generation() {
    let f = Fixture::new();
    write_private_json(
        &f.dir.join(GENERATION),
        &Generation {
            version: 1,
            driver_id: f.origin.driver_id.clone(),
            session_id: f.session.clone(),
            generation: 2,
            resumed_from_pod_uid: None,
        },
    )
    .unwrap();
    assert_eq!(
        handle_fixed(&f.environment, f.request()).unwrap()["record"]["id"],
        f.message
    );
    let mut wrong = f.request();
    wrong.launch_generation = 2;
    assert!(handle_fixed(&f.environment, wrong).is_err());
    update_message(&f.dir, &f.message, |r| r.platform_launch_generation = None).unwrap();
    assert!(handle_fixed(&f.environment, f.request()).is_err());
}
#[test]
fn platform_control_parent_generation_and_original_scope_never_adopt_ordinary_records() {
    let f = Fixture::new();
    let other = uuid::Uuid::new_v4().to_string();
    assert!(parent_generation(&f.environment, &other, &f.origin.driver_id).is_err());
    let mut changed = f.origin.clone();
    changed.parent_generation = Some(1);
    changed.org_id = "another-org".into();
    assert!(!same_scope(&f.origin, &changed));
    changed.org_id = f.origin.org_id.clone();
    assert!(same_scope(&f.origin, &changed));
}
#[test]
fn platform_control_generation_filter_refuses_mixed_or_replayed_messages() {
    let f = Fixture::new();
    let mut record: MessageRecord = private_record(&message_path(&f.dir, &f.message)).unwrap();
    assert!(managed_message_generation_matches((None, Some(1)), &record));
    assert!(!managed_message_generation_matches(
        (None, Some(2)),
        &record
    ));
    assert!(!managed_message_generation_matches((None, None), &record));
    record.member_launch_generation = Some(1);
    assert!(!managed_message_generation_matches(
        (Some(1), None),
        &record
    ));
}
#[test]
fn platform_control_private_homes_never_copy_a_saved_login_and_set_only_the_lockdown() {
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    let sentinel = f._temp.path().join("unrelated-auth.json");
    fs::write(&sentinel, b"synthetic unrelated login").unwrap();
    lockdown::prepare(&f.dir, &config, Route::OpenAi).unwrap();
    // The route's key and base URL are the shared projection's, inherited
    // from the session: the lockdown is only the private home.
    assert_eq!(
        lockdown::environment(&f.dir, &config, Route::OpenAi).unwrap(),
        [(
            "CODEX_HOME".to_owned(),
            f.dir.join("codex").to_string_lossy().into_owned()
        )]
    );
    assert_eq!(
        fs::read_dir(f.dir.join("codex"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>(),
        ["config.toml"]
    );
    // No private `HOME` and no home of the other agent are made.
    assert!(!f.dir.join("home").exists());
    assert!(!f.dir.join("claude").exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"synthetic unrelated login");
    fs::write(
        f.dir.join("codex/config.toml"),
        b"model_provider=\"unrelated\"\n",
    )
    .unwrap();
    assert!(lockdown::environment(&f.dir, &config, Route::OpenAi).is_err());
}

/// A hosted managed Claude agent has no lockdown: no private home, no variable
/// and no fixed argument, so it runs as `claude` does for the user in that
/// Sandbox. Its credential form is the session's, which outranks a saved login.
#[test]
fn platform_control_claude_has_no_hosted_only_lockdown() {
    let f = Fixture::new();
    let mut config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    config.agent = AgentKind::Claude;
    let before: Vec<_> = fs::read_dir(&f.dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    lockdown::prepare(&f.dir, &config, Route::Anthropic).unwrap();
    // Nothing is written: no private Claude home, settings file or `HOME`.
    let after: Vec<_> = fs::read_dir(&f.dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    assert_eq!(lockdown::check(&f.dir, &config).unwrap(), Route::Anthropic);
    assert_eq!(
        lockdown::environment(&f.dir, &config, Route::Anthropic).unwrap(),
        []
    );
    assert_eq!(lockdown::arguments(Route::Anthropic), [] as [String; 0]);
    // Claude's one route is never another agent's.
    for route in [Route::Codex, Route::OpenAi] {
        assert!(lockdown::environment(&f.dir, &config, route).is_err());
    }
}

type Environment = std::collections::BTreeMap<String, String>;

/// One daemon's session configuration with `selected` bound, as the hosted
/// workspace daemon or a local VM's guest daemon holds it.
fn session_config(
    home: &Path,
    selected: codewire_access::ManagedCredentialClients,
    transport: codewire_daemon::CredentialBridgeTransport,
) -> codewire_daemon::Config {
    codewire_daemon::Config {
        listen_addr: "unused:0".into(),
        workspace_root: "/workspace".into(),
        home_root: home.to_owned(),
        auth_token: codewire_daemon::DaemonAuthToken::new("synthetic-session-environment").unwrap(),
        process_execution: codewire_daemon::execution::ProcessExecution::Native,
        host: None,
        launch_projection: Some(codewire_daemon::LaunchProjectionConfig {
            selection_sha256: [7; 32],
            native: None,
        }),
        credential_bridge: Some(codewire_daemon::CredentialBridgeConfig {
            transport,
            environment_id: uuid::Uuid::from_u128(2559),
            environment_generation: 1,
            ingress_socket: "/run/codewire/fixture-only.sock".into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        }),
        managed_credential_clients: selected,
        session_working_dir: None,
    }
}

/// What the daemon's one shared builder gives a session started with `term`
/// and no other input, over the synthetic `daemon` environment. Nothing of
/// the environment this test runs in is read, so nothing of it can appear in
/// a failure.
fn session_environment(
    config: &codewire_daemon::Config,
    term: &str,
    daemon: &[(&str, &str)],
) -> Environment {
    codewire_daemon::env::build_process_env_in(
        config,
        &[],
        term,
        daemon
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    )
    .unwrap()
    .entries
    .into_iter()
    .map(|entry| {
        let (name, value) = entry.split_once('=').unwrap();
        (name.to_owned(), value.to_owned())
    })
    .collect()
}

/// What a provider sees when the guardian that starts it runs in `inherited`:
/// the guardian's own provider command decides what is set over it.
fn provider_environment(inherited: &Environment, lockdown: &[(String, String)]) -> Environment {
    let command = guest_peer::provider_command(Path::new("/proc/self/exe"), &[], Some(lockdown));
    let mut environment = inherited.clone();
    for (name, value) in command.get_envs() {
        let name = name.to_str().unwrap().to_owned();
        match value {
            Some(value) => environment.insert(name, value.to_str().unwrap().to_owned()),
            None => environment.remove(&name),
        };
    }
    environment
}

/// The names two environments disagree on, never their values.
fn differing<'a>(left: &'a Environment, right: &'a Environment) -> Vec<&'a str> {
    left.keys()
        .chain(right.keys())
        .filter(|name| left.get(*name) != right.get(*name))
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// For the same selected slots, a hosted managed agent, a hosted interactive
/// session and a local VM session get the same Git, `gh`, SSH and
/// proxy-exemption environment, byte for byte, from the one shared builder. The managed
/// launch differs from the session it runs in by its login lockdown alone.
/// Each selection runs twice: with nothing declared, and with a proxy and an
/// exemption list declared by the image and by the project.
#[test]
fn platform_managed_agent_git_and_ssh_environment_is_the_interactive_sessions() {
    use codewire_access::{
        GH_NATIVE_CONFIG_DIR, GH_PLATFORM_CONFIG_DIR, GH_TOKEN_PLACEHOLDER,
        ManagedCredentialClient, ManagedCredentialClientPlacement, ManagedCredentialClients,
        NO_PROXY_NAMES, SSH_NATIVE_AUTH_SOCK, SSH_PLATFORM_AUTH_SOCK,
    };
    use codewire_daemon::CredentialBridgeTransport;
    // Git's GitHub URL rewrite: at most four `insteadOf` entries.
    const GIT: [&str; 9] = [
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_KEY_1",
        "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_VALUE_2",
        "GIT_CONFIG_KEY_3",
        "GIT_CONFIG_VALUE_3",
    ];
    const GH_TOKEN: &str = "GH_TOKEN";
    const GH_CONFIG_DIR: &str = "GH_CONFIG_DIR";
    const SSH: &str = "SSH_AUTH_SOCK";
    const LOOPBACK: &str = "127.0.0.1,localhost,::1";
    // A daemon's own environment, as its placement renders it.
    const PLAIN: [(&str, &str); 4] = [
        ("HOME", "/home/codewire"),
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("SHELL", "/bin/sh"),
        ("IMAGE_VALUE", "visible"),
    ];
    // The same with a proxy and an exemption list from the image.
    const PROXIED: [(&str, &str); 7] = [
        ("HOME", "/home/codewire"),
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("SHELL", "/bin/sh"),
        ("IMAGE_VALUE", "visible"),
        ("http_proxy", "http://image-proxy.example:3128"),
        ("ALL_PROXY", "socks5://image-proxy.example:1080"),
        ("no_proxy", ".image.example"),
    ];
    let plain_home = tempfile::tempdir().unwrap();
    // The project declares a proxy and its own exemptions.
    let proxied_home = tempfile::tempdir().unwrap();
    fs::create_dir(proxied_home.path().join(".codewire")).unwrap();
    fs::write(
        proxied_home.path().join(".codewire/environment.json"),
        br#"{"HTTPS_PROXY":"http://proxy.example:3128","NO_PROXY":"corp.example,10.0.0.0/8"}"#,
    )
    .unwrap();
    struct Case {
        slots: &'static [&'static str],
        claude_subscription: bool,
        claude_sign_in: bool,
        launches: &'static [(AgentKind, Route)],
    }
    fn case(slots: &'static [&'static str], launches: &'static [(AgentKind, Route)]) -> Case {
        Case {
            slots,
            claude_subscription: false,
            claude_sign_in: false,
            launches,
        }
    }
    let cases = [
        case(
            &["codex", "github", "ssh"],
            &[(AgentKind::Codex, Route::Codex)],
        ),
        case(&["openai", "github"], &[(AgentKind::Codex, Route::OpenAi)]),
        case(
            &["anthropic", "ssh"],
            &[(AgentKind::Claude, Route::Anthropic)],
        ),
        case(
            &["codex", "openai", "anthropic", "ssh", "github"],
            &[
                (AgentKind::Codex, Route::Codex),
                (AgentKind::Claude, Route::Anthropic),
            ],
        ),
        // Neither Git credential: the builder projects none of the names.
        case(
            &["codex", "anthropic"],
            &[
                (AgentKind::Codex, Route::Codex),
                (AgentKind::Claude, Route::Anthropic),
            ],
        ),
        // The Claude subscription form is part of the selection.
        Case {
            claude_subscription: true,
            ..case(
                &["anthropic", "github", "ssh"],
                &[(AgentKind::Claude, Route::Anthropic)],
            )
        },
        // So is the sign-in form, whose login the daemon writes in the home.
        Case {
            claude_sign_in: true,
            ..case(
                &["anthropic", "github", "ssh"],
                &[(AgentKind::Claude, Route::Anthropic)],
            )
        },
        // The signer alone uses no HTTP route, and no agent can launch.
        case(&["ssh"], &[]),
    ];
    for Case {
        slots,
        claude_subscription,
        claude_sign_in,
        launches,
    } in cases
    {
        let mut selected =
            ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap();
        if claude_subscription {
            selected = selected.with_anthropic_subscription_token().unwrap();
        }
        if claude_sign_in {
            selected = selected.with_anthropic_sign_in().unwrap();
        }
        for (declared, home, daemon) in [
            (false, plain_home.path(), &PLAIN[..]),
            (true, proxied_home.path(), &PROXIED[..]),
        ] {
            let context = format!("{slots:?} declared proxy: {declared}");
            let hosted = session_config(home, selected, CredentialBridgeTransport::Hosted);
            let native = session_config(home, selected, CredentialBridgeTransport::Local);
            // A hosted interactive session, with its terminal.
            let shell = session_environment(&hosted, "xterm-256color", daemon);
            // The hosted managed driver: the daemon starts it through the
            // same builder, with no input of its own.
            let driver = session_environment(&hosted, "", daemon);
            // A local VM session, which a local managed agent inherits.
            let local = session_environment(&native, "", daemon);
            let projected = selected
                .for_placement(ManagedCredentialClientPlacement::Platform)
                .environment;

            let github = selected.contains(ManagedCredentialClient::GitHub);
            let ssh = selected.contains(ManagedCredentialClient::Ssh);
            // Either Git credential rewrites GitHub's URL forms (#2720).
            assert_eq!(
                shell.contains_key(GIT[0]),
                github || ssh,
                "{context} {}",
                GIT[0]
            );
            for name in GIT {
                assert_eq!(shell.get(name), projected.get(name), "{context} {name}");
                assert_eq!(local.get(name), shell.get(name), "{context} {name}");
            }
            // Stock `gh`: the same public placeholder everywhere, and each
            // placement's own Codewire-written configuration directory.
            for name in [GH_TOKEN, GH_CONFIG_DIR] {
                assert_eq!(projected.contains_key(name), github, "{context} {name}");
            }
            if github {
                assert_eq!(shell[GH_TOKEN], GH_TOKEN_PLACEHOLDER, "{context}");
                assert_eq!(local[GH_TOKEN], GH_TOKEN_PLACEHOLDER, "{context}");
                assert_eq!(shell[GH_CONFIG_DIR], GH_PLATFORM_CONFIG_DIR, "{context}");
                assert_eq!(local[GH_CONFIG_DIR], GH_NATIVE_CONFIG_DIR, "{context}");
            } else {
                for name in [GH_TOKEN, GH_CONFIG_DIR] {
                    assert!(
                        !shell.contains_key(name) && !local.contains_key(name),
                        "{context} {name}"
                    );
                }
            }
            // Each placement's signer socket is where its daemon listens.
            assert_eq!(
                shell.get(SSH).map(String::as_str),
                ssh.then_some(SSH_PLATFORM_AUTH_SOCK),
                "{context}"
            );
            assert_eq!(
                local.get(SSH).map(String::as_str),
                ssh.then_some(SSH_NATIVE_AUTH_SOCK),
                "{context}"
            );
            // A proxy is the user's own and stays as declared; every managed
            // HTTP route is exempt from it, on both placements alike.
            let expected_no_proxy = |name: &str| -> Option<String> {
                let own = match (declared, name) {
                    (true, "NO_PROXY") => Some("corp.example,10.0.0.0/8"),
                    (true, "no_proxy") => Some(".image.example"),
                    _ => None,
                };
                if selected.uses_loopback_http() {
                    Some(match own {
                        Some(own) => format!("{own},{LOOPBACK}"),
                        None => LOOPBACK.to_owned(),
                    })
                } else {
                    own.map(str::to_owned)
                }
            };
            for name in NO_PROXY_NAMES {
                assert_eq!(
                    shell.get(name),
                    expected_no_proxy(name).as_ref(),
                    "{context} {name}"
                );
                assert_eq!(local.get(name), shell.get(name), "{context} {name}");
            }
            for (name, value) in [
                ("HTTPS_PROXY", "http://proxy.example:3128"),
                ("http_proxy", "http://image-proxy.example:3128"),
                ("ALL_PROXY", "socks5://image-proxy.example:1080"),
            ] {
                for environment in [&shell, &driver, &local] {
                    assert_eq!(
                        environment.get(name).map(String::as_str),
                        declared.then_some(value),
                        "{context} {name}"
                    );
                }
            }
            // The driver's session differs from the terminal's by the
            // terminal alone.
            assert_eq!(differing(&driver, &shell), ["TERM"], "{context}");

            for (agent, route) in launches {
                let f = Fixture::new();
                let mut config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
                config.agent = *agent;
                lockdown::prepare(&f.dir, &config, *route).unwrap();
                let locked = lockdown::environment(&f.dir, &config, *route).unwrap();
                let managed = provider_environment(&driver, &locked);
                let context = format!("{context} {route:?}");

                for name in GIT
                    .into_iter()
                    .chain([GH_TOKEN, GH_CONFIG_DIR, SSH])
                    .chain(NO_PROXY_NAMES)
                {
                    assert_eq!(managed.get(name), shell.get(name), "{context} {name}");
                }
                // Every provider variable is the session's too. Codex alone
                // has a lockdown, which replaces its home; Claude has none,
                // so its environment is the session's exactly.
                let private_home = (*agent == AgentKind::Codex).then_some("CODEX_HOME");
                for (name, value) in &projected {
                    assert_eq!(shell.get(name), Some(value), "{context} {name}");
                    if Some(name.as_str()) != private_home {
                        assert_eq!(managed.get(name), Some(value), "{context} {name}");
                    }
                }
                // The managed launch differs from the session by its lockdown
                // alone: nothing else is set, changed or removed.
                let locked_names: Vec<&str> =
                    locked.iter().map(|(name, _)| name.as_str()).collect();
                assert_eq!(differing(&managed, &driver), locked_names, "{context}");
                for (name, value) in &locked {
                    assert_eq!(managed.get(name), Some(value), "{context} {name}");
                }
                match private_home {
                    Some(home) => assert!(
                        managed[home].starts_with(f.dir.to_str().unwrap()),
                        "{context}"
                    ),
                    None => assert!(locked.is_empty(), "{context}"),
                }
            }
        }
    }
}

/// The hosted guardian starts a provider only with exactly the arguments its
/// driver builds: the route's login lockdown, then the driver's own. Nothing
/// can be added, dropped or changed, so a caller cannot widen Claude's
/// permission mode, pass a bypass option or drop Codex's lockdown.
#[test]
fn platform_peer_arguments_are_exactly_the_drivers_for_its_route() {
    let f = Fixture::new();
    let codex: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    let strings = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();

    for route in [Route::Codex, Route::OpenAi] {
        let mut exact = lockdown::arguments(route);
        exact.extend(codex_app_server_arguments(&codex.working_dir));
        assert!(check_peer_arguments(&codex, route, None, &exact).is_ok());
        // Another route's lockdown, no lockdown, or anything extra.
        let other = if route == Route::Codex {
            Route::OpenAi
        } else {
            Route::Codex
        };
        let mut wrong_route = lockdown::arguments(other);
        wrong_route.extend(codex_app_server_arguments(&codex.working_dir));
        assert!(check_peer_arguments(&codex, route, None, &wrong_route).is_err());
        assert!(
            check_peer_arguments(
                &codex,
                route,
                None,
                &codex_app_server_arguments(&codex.working_dir)
            )
            .is_err()
        );
        for extra in [
            &["--dangerously-bypass-approvals-and-sandbox"][..],
            &["-c", "model_provider=\"openai\""],
            &["exec"],
        ] {
            let mut widened = exact.clone();
            widened.extend(strings(extra));
            assert!(
                check_peer_arguments(&codex, route, None, &widened).is_err(),
                "{extra:?}"
            );
        }
        let mut elsewhere = lockdown::arguments(route);
        elsewhere.extend(codex_app_server_arguments("/other"));
        assert!(check_peer_arguments(&codex, route, None, &elsewhere).is_err());
        assert!(check_peer_arguments(&codex, route, None, &exact[..exact.len() - 1]).is_err());
    }

    let mut claude = codex.clone();
    claude.agent = AgentKind::Claude;
    let session = uuid::Uuid::new_v4().to_string();
    let state = |established: bool, thread: Option<&str>| DriverState {
        version: 1,
        driver_id: claude.driver_id.clone(),
        agent: AgentKind::Claude,
        phase: DriverPhase::Starting,
        native_thread_id: thread.map(str::to_owned),
        native_thread_established: established,
        current_turn_id: None,
        active_message_id: None,
        queued: 0,
        capabilities: AgentCapabilities {
            steer: false,
            interrupt: false,
            resume: false,
            note: "synthetic".into(),
        },
        policy: String::new(),
        last_error: None,
        started_at: now(),
        updated_at: now(),
    };
    for established in [false, true] {
        let saved = state(established, Some(&session));
        // Exactly the Sandbox launch, auto mode included.
        let exact = claude_arguments(&claude, true, established, &session);
        assert_eq!(exact[exact.len() - 2..], ["--permission-mode", "auto"]);
        assert!(check_peer_arguments(&claude, Route::Anthropic, Some(&saved), &exact).is_ok());
        // A trusted host's launch (no permission mode) is not a hosted one.
        let host = claude_arguments(&claude, false, established, &session);
        assert!(check_peer_arguments(&claude, Route::Anthropic, Some(&saved), &host).is_err());
        for widened in [
            &["--dangerously-skip-permissions"][..],
            &["--allow-dangerously-skip-permissions"],
            &["--permission-mode", "bypassPermissions"],
            &[
                "--settings",
                "{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}",
            ],
            &["--allowedTools", "Bash"],
        ] {
            let mut arguments = exact.clone();
            arguments.extend(strings(widened));
            assert!(
                check_peer_arguments(&claude, Route::Anthropic, Some(&saved), &arguments).is_err(),
                "{widened:?}"
            );
        }
        let mut bypass = exact.clone();
        *bypass.last_mut().unwrap() = "bypassPermissions".into();
        assert!(check_peer_arguments(&claude, Route::Anthropic, Some(&saved), &bypass).is_err());
        // The other conversation flag, another model or another conversation.
        let flipped = state(!established, Some(&session));
        assert!(check_peer_arguments(&claude, Route::Anthropic, Some(&flipped), &exact).is_err());
        let mut model = claude.clone();
        model.model = "another-model".into();
        assert!(check_peer_arguments(&model, Route::Anthropic, Some(&saved), &exact).is_err());
        let another = state(established, Some(&uuid::Uuid::new_v4().to_string()));
        assert!(check_peer_arguments(&claude, Route::Anthropic, Some(&another), &exact).is_err());
        // No saved conversation, or one that is not a conversation identity.
        assert!(check_peer_arguments(&claude, Route::Anthropic, None, &exact).is_err());
        assert!(
            check_peer_arguments(
                &claude,
                Route::Anthropic,
                Some(&state(established, None)),
                &exact
            )
            .is_err()
        );
        let unsafe_name = state(established, Some("../session"));
        assert!(
            check_peer_arguments(
                &claude,
                Route::Anthropic,
                Some(&unsafe_name),
                &claude_arguments(&claude, true, established, "../session")
            )
            .is_err()
        );
    }
    // Claude has no lockdown prefix, so Codex's is not admitted for it.
    let mut prefixed = lockdown::arguments(Route::Codex);
    prefixed.extend(claude_arguments(&claude, true, false, &session));
    assert!(
        check_peer_arguments(
            &claude,
            Route::Anthropic,
            Some(&state(false, Some(&session))),
            &prefixed
        )
        .is_err()
    );
}

#[test]
fn platform_control_directories_below_a_setgid_home_are_exactly_private() {
    // A Pod fsGroup home is setgid; directories made below it inherit setgid.
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o2700)).unwrap();
    let leaf = temp.path().join("state").join("agents");
    make_directory(&leaf).unwrap();
    for made in [temp.path().join("state"), leaf] {
        assert_eq!(
            fs::metadata(&made).unwrap().mode() & 0o7777,
            0o700,
            "{made:?}"
        );
    }
}

#[test]
fn platform_control_codex_private_config_allows_only_its_exact_project_suffix() {
    for route in [Route::OpenAi, Route::Codex] {
        let f = Fixture::new();
        let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
        lockdown::prepare(&f.dir, &config, route).unwrap();
        let path = f.dir.join("codex/config.toml");
        let baseline = fs::read(&path).unwrap();
        let suffix = format!(
            "\n[projects.{}]\ntrust_level = \"trusted\"\n",
            serde_json::to_string(&config.working_dir).unwrap()
        );
        let mut admitted = baseline.clone();
        admitted.extend(suffix.as_bytes());
        fs::write(&path, &admitted).unwrap();
        assert_eq!(lockdown::check(&f.dir, &config).unwrap(), route);
        assert!(lockdown::environment(&f.dir, &config, route).is_ok());
        for extra in [
            b"\n[projects.\"/other\"]\ntrust_level = \"trusted\"\n".as_slice(),
            b"\nmodel_provider = \"unrelated\"\n",
        ] {
            let mut invalid = admitted.clone();
            invalid.extend(extra);
            fs::write(&path, &invalid).unwrap();
            assert!(lockdown::environment(&f.dir, &config, route).is_err());
        }
        fs::write(&path, admitted).unwrap();
        let mut changed = config.clone();
        changed.working_dir = "/other".into();
        assert!(lockdown::environment(&f.dir, &changed, route).is_err());
    }
}

/// Parse the generated private Codex configuration and the command-line
/// overrides into one table each, so tests compare what Codex reads.
fn codex_settings(dir: &Path, route: Route) -> (toml::Table, toml::Table) {
    let file: toml::Table =
        toml::from_str(&fs::read_to_string(dir.join("codex/config.toml")).unwrap()).unwrap();
    fn merge(into: &mut toml::Table, from: toml::Table) {
        for (key, value) in from {
            match (into.get_mut(&key), value) {
                (Some(toml::Value::Table(existing)), toml::Value::Table(table)) => {
                    merge(existing, table)
                }
                (_, value) => {
                    into.insert(key, value);
                }
            }
        }
    }
    let mut overrides = toml::Table::new();
    let arguments = lockdown::arguments(route);
    assert_eq!(arguments.len() % 2, 0);
    for pair in arguments.chunks(2) {
        assert_eq!(pair[0], "-c");
        merge(&mut overrides, toml::from_str(&pair[1]).unwrap());
    }
    (file, overrides)
}

/// The private Codex configuration is the login lockdown followed by the
/// provider configuration every placement generates in `codewire-access`,
/// byte for byte: no hosted-only Codex builder exists.
#[test]
fn platform_control_codex_private_config_is_the_lockdown_then_the_shared_provider_config() {
    use codewire_access::{
        CODEX_MANAGED_CONFIG_HEADER, CodexProviderProjection, MANAGED_HTTP_PORT,
        ManagedCredentialClientPlacement, ManagedCredentialClients,
    };
    const LOCKDOWN: &str = "forced_login_method = \"api\"\ncli_auth_credentials_store = \"file\"\n";
    let private = |route| {
        let f = Fixture::new();
        let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
        lockdown::prepare(&f.dir, &config, route).unwrap();
        fs::read_to_string(f.dir.join("codex/config.toml")).unwrap()
    };

    let codex = private(Route::Codex);
    let provider = codex.strip_prefix(LOCKDOWN).unwrap();
    let selected = ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
    // A local VM's Codex home holds exactly the provider configuration.
    let native = selected
        .for_placement(ManagedCredentialClientPlacement::Native)
        .codex
        .unwrap();
    assert_eq!(provider, native.config_toml());
    // The hosted user's `~/.codex/config.toml` adds only its ownership header.
    let hosted = selected
        .for_placement(ManagedCredentialClientPlacement::Platform)
        .codex
        .unwrap();
    assert_eq!(
        hosted.config_toml(),
        format!("{CODEX_MANAGED_CONFIG_HEADER}\n{provider}")
    );

    let openai = private(Route::OpenAi);
    assert_eq!(
        openai.strip_prefix(LOCKDOWN).unwrap(),
        CodexProviderProjection::for_openai_api_loopback_port(MANAGED_HTTP_PORT)
            .unwrap()
            .config_toml()
    );
    // The lockdown lines are the only ones this path writes itself.
    for (route, config) in [(Route::Codex, &codex), (Route::OpenAi, &openai)] {
        let overrides = lockdown::arguments(route);
        assert_eq!(
            &overrides[..4],
            [
                "-c",
                "forced_login_method=\"api\"",
                "-c",
                "cli_auth_credentials_store=\"file\""
            ]
        );
        assert_eq!(config.matches(LOCKDOWN).count(), 1);
    }
}

#[test]
fn platform_control_codex_slot_route_is_credential_free_through_the_codex_route() {
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    let sentinel = f._temp.path().join("unrelated-auth.json");
    fs::write(&sentinel, b"synthetic unrelated login").unwrap();
    lockdown::prepare(&f.dir, &config, Route::Codex).unwrap();
    assert_eq!(lockdown::check(&f.dir, &config).unwrap(), Route::Codex);
    let environment = lockdown::environment(&f.dir, &config, Route::Codex)
        .unwrap()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    // Its own fixed home and no key, placeholder or OpenAI base URL; nothing
    // from `~/.codex`.
    assert_eq!(
        environment.keys().map(String::as_str).collect::<Vec<_>>(),
        ["CODEX_HOME"]
    );
    assert_eq!(
        environment["CODEX_HOME"],
        f.dir.join("codex").to_string_lossy()
    );
    assert!(!environment.values().any(|value| value.contains(".codex")));
    assert!(!f.dir.join("codex/auth.json").exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"synthetic unrelated login");

    let (file, overrides) = codex_settings(&f.dir, Route::Codex);
    // The file and the overrides configure the same provider.
    for settings in [&file, &overrides] {
        assert_eq!(settings["model_provider"].as_str(), Some("codewire_openai"));
        assert_eq!(settings["forced_login_method"].as_str(), Some("api"));
        assert_eq!(
            settings["cli_auth_credentials_store"].as_str(),
            Some("file")
        );
        assert_eq!(
            settings["features"]["enable_request_compression"].as_bool(),
            Some(false)
        );
        let provider = settings["model_providers"]["codewire_openai"]
            .as_table()
            .unwrap();
        // The Codex slot's own route on the managed ingress; no key name.
        assert_eq!(
            provider["base_url"].as_str().unwrap(),
            format!("http://127.0.0.1:{}/v1", codewire_access::MANAGED_HTTP_PORT)
        );
        assert_eq!(provider["wire_api"].as_str(), Some("responses"));
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(false));
        assert_eq!(provider["supports_websockets"].as_bool(), Some(false));
        assert!(!provider.contains_key("env_key"));
        assert!(!provider.contains_key("experimental_bearer_token"));
    }
    assert_eq!(file, overrides);

    // The recorded route is the only one admitted for this home.
    assert!(lockdown::environment(&f.dir, &config, Route::OpenAi).is_err());
    assert!(lockdown::environment(&f.dir, &config, Route::Anthropic).is_err());
}

#[test]
fn platform_control_openai_route_keeps_its_key_slot_configuration() {
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    lockdown::prepare(&f.dir, &config, Route::OpenAi).unwrap();
    assert_eq!(lockdown::check(&f.dir, &config).unwrap(), Route::OpenAi);
    let (file, overrides) = codex_settings(&f.dir, Route::OpenAi);
    for settings in [&file, &overrides] {
        assert_eq!(
            settings["model_provider"].as_str(),
            Some("codewire_openai_api")
        );
        let provider = settings["model_providers"]["codewire_openai_api"]
            .as_table()
            .unwrap();
        assert_eq!(
            provider["base_url"].as_str().unwrap(),
            format!(
                "http://127.0.0.1:{}{}",
                codewire_access::MANAGED_HTTP_PORT,
                codewire_access::MANAGED_OPENAI_API_PREFIX
            )
        );
        assert_eq!(provider["env_key"].as_str(), Some("OPENAI_API_KEY"));
    }
    assert_eq!(file, overrides);
    assert!(lockdown::environment(&f.dir, &config, Route::Codex).is_err());
}

#[test]
fn platform_control_private_home_is_written_only_for_a_route_of_its_agent() {
    let f = Fixture::new();
    let codex: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    let mut claude = codex.clone();
    claude.agent = AgentKind::Claude;
    for (config, route) in [
        (&codex, Route::Anthropic),
        (&claude, Route::Codex),
        (&claude, Route::OpenAi),
    ] {
        let stage = f
            ._temp
            .path()
            .join(format!("stage-{}", uuid::Uuid::new_v4()));
        private_directory(&stage).unwrap();
        assert!(lockdown::prepare(&stage, config, route).is_err());
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 0, "{route:?}");
    }
    // Claude's own route is admitted, and writes nothing.
    let stage = f._temp.path().join("claude-stage");
    private_directory(&stage).unwrap();
    lockdown::prepare(&stage, &claude, Route::Anthropic).unwrap();
    assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
    assert_eq!(lockdown::check(&stage, &claude).unwrap(), Route::Anthropic);
}

#[test]
fn platform_control_prepare_requires_a_route_of_the_origin_agent() {
    let fixture = Fixture::new();
    let prepare = |route: serde_json::Value| {
        json!({"version":1,"origin":fixture.origin,"session_id":fixture.session,
            "launch_generation":1,"request":{"op":"prepare","model":"synthetic","effort":null,
            "working_dir":"/","name":"","prompt":null,"parent_session_id":"",
            "initial_message_id":null,"route":route}})
    };
    let mut missing = prepare(json!("codex"));
    missing["request"].as_object_mut().unwrap().remove("route");
    for invalid in [
        missing,
        prepare(json!("open_ai")),
        prepare(json!("chatgpt")),
    ] {
        assert!(serde_json::from_value::<Envelope>(invalid).is_err());
    }
    let envelope = serde_json::from_value::<Envelope>(prepare(json!("anthropic"))).unwrap();
    let error = handle_fixed(&fixture.environment, envelope).unwrap_err();
    assert!(
        format!("{error:#}").contains("platform route serves another agent"),
        "{error:#}"
    );
    for route in ["codex", "openai"] {
        assert!(serde_json::from_value::<Envelope>(prepare(json!(route))).is_ok());
    }
}

#[test]
fn platform_control_reads_full_admitted_record_without_provider_resolution() {
    let fixture = Fixture::new();
    let value = handle_fixed(&fixture.environment, fixture.request()).unwrap();
    assert_eq!(value["record"]["id"], fixture.message);
    assert_eq!(value["record"]["text"], "synthetic");
}
#[test]
fn platform_control_stale_or_changed_origin_refuses_without_changing_record() {
    let fixture = Fixture::new();
    let path = message_path(&fixture.dir, &fixture.message);
    let before = fs::read(&path).unwrap();
    let mut stale = fixture.request();
    stale.launch_generation = 2;
    assert!(handle_fixed(&fixture.environment, stale).is_err());
    let mut changed = fixture.request();
    changed.origin.pod_uid = uuid::Uuid::new_v4().to_string();
    assert!(handle_fixed(&fixture.environment, changed).is_err());
    assert_eq!(before, fs::read(path).unwrap());
}
#[test]
fn platform_control_legacy_and_mixed_member_scope_refuse() {
    let fixture = Fixture::new();
    fs::rename(fixture.dir.join(ORIGIN), fixture.dir.join("saved-origin")).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    fs::rename(fixture.dir.join("saved-origin"), fixture.dir.join(ORIGIN)).unwrap();
    fs::write(fixture.dir.join("member-origin.json"), b"unrecognized").unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
}
#[test]
fn platform_control_linked_or_nonprivate_record_refuses_without_repairing_it() {
    let fixture = Fixture::new();
    let path = message_path(&fixture.dir, &fixture.message);
    let linked = fixture.dir.join("unrelated-link");
    fs::hard_link(&path, &linked).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    fs::remove_file(&linked).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o644);
}
/// A platform steer and interrupt each name the active turn; native intake
/// takes an explicit turn only for a steer, so the interrupt must still queue
/// and keep that turn on its record (#2787). A changed turn refuses.
#[test]
fn platform_control_queues_a_steer_and_an_interrupt_naming_the_active_turn() {
    let f = Fixture::new();
    f.clean_peer();
    let mut state: DriverState = private_record(&f.dir.join("state.json")).unwrap();
    state.phase = DriverPhase::Busy;
    state.active_message_id = Some(f.message.clone());
    state.current_turn_id = Some("turn-1".into());
    write_private_json(&f.dir.join("state.json"), &state).unwrap();
    let queue = |action, text: &str, turn: &str| {
        let id = uuid::Uuid::new_v4().to_string();
        let request = Envelope {
            request: Request::Queue {
                driver_id: f.origin.driver_id.clone(),
                session_id: f.session.clone(),
                message_id: id.clone(),
                action,
                text: text.into(),
                reply_to: None,
                expected_turn_id: Some(turn.into()),
                expected_active_message_id: Some(f.message.clone()),
            },
            ..f.request()
        };
        (id, handle_fixed(&f.environment, request))
    };
    let controls = [
        (MessageAction::Steer, "Keep waiting."),
        (MessageAction::Interrupt, ""),
    ];
    for (action, text) in controls {
        let (id, queued) = queue(action, text, "turn-1");
        let record = &queued.unwrap()["record"];
        assert_eq!(record["id"], id);
        assert_eq!(record["action"], json!(action));
        assert_eq!(record["expected_turn_id"], "turn-1");
        assert_eq!(record["expected_active_message_id"], json!(f.message));
        assert_eq!(record["platform_launch_generation"], 1);
        let saved: MessageRecord = private_record(&message_path(&f.dir, &id)).unwrap();
        assert_eq!(saved.expected_turn_id.as_deref(), Some("turn-1"));
    }
    for (action, text) in controls {
        let (id, queued) = queue(action, text, "turn-0");
        assert!(queued.is_err());
        assert!(!message_path(&f.dir, &id).exists());
    }
}
#[test]
fn platform_control_raw_queue_and_unknown_envelope_fields_cannot_reach_native_intake() {
    let fixture = Fixture::new();
    let base = json!({"version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"queue","driver_id":"ignored"}});
    assert!(serde_json::from_value::<Envelope>(base).is_err());
    let mut extra = json!({"version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"peer_status", "driver_id":fixture.origin.driver_id,
        "session_id":fixture.session}});
    extra["program"] = json!("untrusted");
    assert!(serde_json::from_value::<Envelope>(extra).is_err());
}

#[test]
fn platform_control_production_reader_refuses_trailing_data_and_overbound_before_io() {
    let fixture = Fixture::new();
    let mut body = serde_json::to_vec(&json!({
        "version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"get_message", "driver_id":fixture.origin.driver_id,
        "message_id":fixture.message},
    }))
    .unwrap();
    let parsed = parse_envelope(body.as_slice()).unwrap();
    assert_eq!(
        handle_fixed(&fixture.environment, parsed).unwrap()["record"]["id"],
        fixture.message
    );
    body.extend_from_slice(b" {}");
    assert!(parse_envelope(body.as_slice()).is_err());
    let oversized = vec![b' '; 512 * 1024 + 1];
    assert!(
        parse_envelope(oversized.as_slice())
            .err()
            .unwrap()
            .to_string()
            .contains("too large")
    );
}

#[test]
fn platform_control_linked_generation_cas_retains_peer_and_historical_messages_after_lost_ack() {
    let f = Fixture::new();
    let peer = f.clean_peer();
    let before = fs::read(message_path(&f.dir, &f.message)).unwrap();
    let peer_before = fs::read(f.dir.join("peer-current.json")).unwrap();
    let mut advance = f.request();
    advance.request = Request::AdvanceGeneration {
        expected_generation: 1,
        expected_peer: peer.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, advance).unwrap()["launch_generation"],
        2
    );
    // A later explicit cleanup observes to; it never replays the from->to CAS.
    let mut observed = f.request();
    observed.request = Request::GenerationStatus {
        driver_id: f.origin.driver_id.clone(),
        session_id: f.session.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, observed).unwrap()["launch_generation"],
        2
    );
    let mut confirmed = f.request();
    confirmed.launch_generation = 2;
    confirmed.request = Request::ConfirmCleanGeneration {
        expected_peer: peer.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, confirmed).unwrap()["peer"]["identity"]["instance_id"],
        peer.instance_id
    );
    let mut repeated = f.request();
    repeated.request = Request::AdvanceGeneration {
        expected_generation: 1,
        expected_peer: peer,
    };
    assert!(handle_fixed(&f.environment, repeated).is_err());
    assert_eq!(before, fs::read(message_path(&f.dir, &f.message)).unwrap());
    assert_eq!(
        peer_before,
        fs::read(f.dir.join("peer-current.json")).unwrap()
    );
    assert_eq!(
        handle_fixed(&f.environment, f.request()).unwrap()["record"]["id"],
        f.message
    );
}

#[test]
fn platform_control_generation_refuses_live_lock_changed_peer_and_active_turn_without_advance() {
    let f = Fixture::new();
    let peer = f.clean_peer();
    let before = fs::read(f.dir.join(GENERATION)).unwrap();
    let request = |expected_peer| Envelope {
        request: Request::AdvanceGeneration {
            expected_generation: 1,
            expected_peer,
        },
        ..f.request()
    };
    let driver = StateLock::acquire(&f.dir.join("driver.lock")).unwrap();
    assert!(handle_fixed(&f.environment, request(peer.clone())).is_err());
    drop(driver);
    let mut changed = peer.clone();
    changed.instance_id = uuid::Uuid::new_v4().to_string();
    assert!(handle_fixed(&f.environment, request(changed)).is_err());
    let mut state: DriverState = private_record(&f.dir.join("state.json")).unwrap();
    state.active_message_id = Some(f.message.clone());
    state.current_turn_id = Some("new-turn".into());
    write_private_json(&f.dir.join("state.json"), &state).unwrap();
    assert!(handle_fixed(&f.environment, request(peer)).is_err());
    assert_eq!(before, fs::read(f.dir.join(GENERATION)).unwrap());
}

#[test]
fn platform_control_identity_accepts_only_fixed_platform_driver_shape_and_preserves_native_role() {
    let environment = uuid::Uuid::new_v4().to_string();
    let driver = uuid::Uuid::new_v4().to_string();
    let command = vec![
        "/codewire/bin/cw".into(),
        "__platform-agent-driver".into(),
        "--environment".into(),
        environment.clone(),
        "--driver-id".into(),
        driver.clone(),
    ];
    assert_eq!(
        driver_identity(&command),
        Some((environment.clone(), driver.clone()))
    );
    for field in 0..3 {
        let mut wrong = command.clone();
        match field {
            0 => wrong[0] = "/usr/local/bin/cw".into(),
            1 => wrong.push("--program".into()),
            _ => wrong[4] = "--unknown".into(),
        };
        assert!(driver_identity(&wrong).is_none());
    }
    let native = vec![
        "cw".into(),
        DRIVER_COMMAND.into(),
        "--environment".into(),
        environment.clone(),
        "--driver-id".into(),
        driver.clone(),
    ];
    assert_eq!(driver_identity(&native), Some((environment, driver)));
}

fn successor(f: &Fixture) -> Origin {
    Origin {
        pod_uid: uuid::Uuid::new_v4().to_string(),
        binding_generation: 7,
        projection_selection_sha256: [9; 32],
        support_image_sha256: [8; 32],
        ..f.origin.clone()
    }
}

fn adopt_request(f: &Fixture, origin: Origin, route: Route, commit: bool) -> Envelope {
    Envelope {
        request: Request::Adopt {
            origin,
            route,
            commit,
        },
        ..f.request()
    }
}

#[test]
fn platform_adopt_refuses_another_scope_a_live_driver_and_a_changed_route() {
    // #2705: every refusal comes before any file changes, so the daemon can
    // answer it as refused before issue.
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    lockdown::prepare(&f.dir, &config, Route::Codex).unwrap();
    let markers = || {
        (
            fs::read(f.dir.join(ORIGIN)).unwrap(),
            fs::read(f.dir.join(GENERATION)).unwrap(),
            fs::read(f.dir.join("config.json")).unwrap(),
        )
    };
    let before = markers();
    let refused = |request: Envelope, reason: &str| {
        let error = handle_fixed(&f.environment, request)
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{error}");
    };
    // The same Pod stays Restart's.
    refused(
        adopt_request(&f, f.origin.clone(), Route::Codex, false),
        "platform resume differs",
    );
    for changed in [
        Origin {
            org_id: "another-org".into(),
            ..successor(&f)
        },
        Origin {
            agent: AgentKind::Claude,
            provider: codewire_daemon::platform_managed::ProviderIdentity {
                version: "2.1.288".into(),
                ..f.origin.provider.clone()
            },
            ..successor(&f)
        },
        Origin {
            parent_generation: Some(1),
            ..successor(&f)
        },
    ] {
        refused(
            adopt_request(&f, changed, Route::Codex, false),
            "platform resume differs",
        );
    }
    // The new origin must carry the current pin.
    refused(
        adopt_request(
            &f,
            Origin {
                provider: codewire_daemon::platform_managed::ProviderIdentity {
                    version: "0.159.0".into(),
                    ..f.origin.provider.clone()
                },
                ..successor(&f)
            },
            Route::Codex,
            false,
        ),
        "platform incarnation differs",
    );
    refused(
        adopt_request(&f, successor(&f), Route::Anthropic, false),
        "platform route serves another agent",
    );
    // A plain refusal names its closed reason when only checking, so the
    // user is told why; the commit checks the same again and errors.
    let plain = |request: &dyn Fn(bool) -> Envelope, reason: &str, message: &str| {
        let unchanged = markers();
        assert_eq!(
            handle_fixed(&f.environment, request(false)).unwrap(),
            json!({ "refused": reason })
        );
        refused(request(true), message);
        assert_eq!(markers(), unchanged);
    };
    // A driver holding its lock is alive in this Pod.
    let driver = StateLock::acquire(&f.dir.join("driver.lock")).unwrap();
    plain(
        &|commit| adopt_request(&f, successor(&f), Route::Codex, commit),
        "resume-driver-alive",
        "a platform driver is still alive",
    );
    drop(driver);
    // A stale generation.
    let mut stale = adopt_request(&f, successor(&f), Route::Codex, true);
    stale.launch_generation = 2;
    assert!(handle_fixed(&f.environment, stale).is_err());
    // The working directory is gone.
    let saved_config = fs::read(f.dir.join("config.json")).unwrap();
    let gone = AgentConfig {
        working_dir: f.dir.join("gone").to_string_lossy().into_owned(),
        ..config.clone()
    };
    write_private_json(&f.dir.join("config.json"), &gone).unwrap();
    plain(
        &|commit| adopt_request(&f, successor(&f), Route::Codex, commit),
        "resume-working-directory-missing",
        "platform working directory is gone",
    );
    fs::write(f.dir.join("config.json"), saved_config).unwrap();
    assert_eq!(markers(), before);
    // The saved conversation used another credential route.
    plain(
        &|commit| adopt_request(&f, successor(&f), Route::OpenAi, commit),
        "resume-credential-changed",
        "the agent's credential changed",
    );
    // The fixture's synthetic provider identity is never the image's, so a
    // fully valid request reaches provider admission and is refused there.
    plain(
        &|commit| adopt_request(&f, successor(&f), Route::Codex, commit),
        "resume-provider-not-admitted",
        "this agent's provider is not admitted here",
    );
    // The predecessor's origin may carry an earlier provider pin; it is the
    // new origin's pin that is admitted.
    let mut earlier = f.origin.clone();
    earlier.provider.version = "0.159.0".into();
    write_private_json(&f.dir.join(ORIGIN), &earlier).unwrap();
    let mut request = adopt_request(&f, successor(&f), Route::Codex, false);
    request.origin = earlier.clone();
    assert_eq!(
        handle_fixed(&f.environment, request).unwrap(),
        json!({ "refused": "resume-provider-not-admitted" })
    );
    write_private_json(&f.dir.join(ORIGIN), &f.origin).unwrap();
    assert_eq!(markers(), before);
}

#[test]
fn platform_adopt_commit_moves_markers_and_retires_the_predecessor_custody() {
    let f = Fixture::new();
    f.clean_peer();
    let next = successor(&f);
    let old: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    assert!(!resumed(&f.environment, &f.origin.driver_id).unwrap());
    assert_eq!(
        commit_adoption(
            &f.dir,
            &f.origin,
            &next,
            old,
            config,
            Path::new("/usr/bin/true"),
        )
        .unwrap(),
        2
    );
    let origin: Origin = private_record(&f.dir.join(ORIGIN)).unwrap();
    assert!(origin == next);
    let generation: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    assert_eq!(generation.generation, 2);
    assert_eq!(
        generation.resumed_from_pod_uid.as_deref(),
        Some(f.origin.pod_uid.as_str())
    );
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    assert_eq!(config.program, Path::new("/usr/bin/true"));
    assert!(!f.dir.join("peer-current.json").exists());
    assert!(resumed(&f.environment, &f.origin.driver_id).unwrap());
    // A pre-Stop message keeps its own generation and is never adopted into
    // the new one.
    let record: MessageRecord = private_record(&message_path(&f.dir, &f.message)).unwrap();
    assert_eq!(record.platform_launch_generation, Some(1));
    let mut read = f.request();
    read.origin = next.clone();
    read.launch_generation = 2;
    assert!(handle_fixed(&f.environment, read).is_err());
    // The old origin no longer opens anything.
    assert!(handle_fixed(&f.environment, f.request()).is_err());
    // The next generation clears the resumed mark.
    let advanced = Generation {
        generation: 3,
        resumed_from_pod_uid: None,
        ..generation
    };
    write_private_json(&f.dir.join(GENERATION), &advanced).unwrap();
    assert!(!resumed(&f.environment, &f.origin.driver_id).unwrap());
}

#[test]
fn platform_adopt_commit_crash_points_never_open_either_pod() {
    // #2705: the daemon's record names this Pod at g+1 before the helper
    // commits. Whatever prefix of the commit survives a crash, a mutation at
    // the daemon's record (new origin, g+1) is refused, and so is one at the
    // predecessor's (old origin, g) once the origin has moved. The driver
    // fence stays closed until the generation names the resumed Pod.
    let f = Fixture::new();
    f.clean_peer();
    let next = successor(&f);
    let at = |origin: &Origin, generation: u64| Envelope {
        origin: origin.clone(),
        launch_generation: generation,
        request: Request::Adopt {
            origin: next.clone(),
            route: Route::Codex,
            commit: false,
        },
        ..f.request()
    };
    let closed = || {
        assert!(check_markers(&f.dir, &at(&next, 2)).is_err());
        assert!(!resumed(&f.environment, &f.origin.driver_id).unwrap());
    };
    closed();
    // 1. The config names the admitted program.
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    write_private_json(
        &f.dir.join("config.json"),
        &AgentConfig {
            program: PathBuf::from("/usr/bin/true"),
            ..config
        },
    )
    .unwrap();
    closed();
    // 2. The predecessor's custody pointer is retired. Only the
    // predecessor's markers still hold, and a later adopt rewrites the
    // program, so this prefix is the state before adoption.
    fs::remove_file(f.dir.join("peer-current.json")).unwrap();
    closed();
    check_markers(&f.dir, &at(&f.origin, 1)).unwrap();
    // 3. The origin moves to this Pod; the generation has not.
    write_private_json(&f.dir.join(ORIGIN), &next).unwrap();
    closed();
    assert!(check_markers(&f.dir, &at(&f.origin, 1)).is_err());
    assert!(
        handle_fixed(
            &f.environment,
            adopt_request(&f, next.clone(), Route::Codex, false)
        )
        .is_err()
    );
    // 4. The generation moves last and marks the resumed Pod.
    let old: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    write_private_json(
        &f.dir.join(GENERATION),
        &Generation {
            generation: 2,
            resumed_from_pod_uid: Some(f.origin.pod_uid.clone()),
            ..old
        },
    )
    .unwrap();
    check_markers(&f.dir, &at(&next, 2)).unwrap();
    assert!(resumed(&f.environment, &f.origin.driver_id).unwrap());
}

#[test]
fn platform_revert_undoes_only_an_adoption_no_driver_started() {
    // #2769: the environment projection was refused before the agent ran in
    // this Pod, so the adoption is undone and the conversation can resume
    // again. Every refusal comes before any file changes.
    let f = Fixture::new();
    f.clean_peer();
    let next = successor(&f);
    let old: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    commit_adoption(
        &f.dir,
        &f.origin,
        &next,
        old,
        config,
        Path::new("/usr/bin/true"),
    )
    .unwrap();
    let revert = |previous: Origin, generation: u64| Envelope {
        origin: next.clone(),
        launch_generation: generation,
        request: Request::Revert { previous },
        ..f.request()
    };
    let markers = || {
        (
            fs::read(f.dir.join(ORIGIN)).unwrap(),
            fs::read(f.dir.join(GENERATION)).unwrap(),
        )
    };
    let adopted = markers();
    let refused = |request: Envelope| {
        assert!(handle_fixed(&f.environment, request).is_err());
        assert_eq!(markers(), adopted);
    };
    // Another predecessor, organization or agent, or this Pod itself.
    for previous in [
        Origin {
            pod_uid: uuid::Uuid::new_v4().to_string(),
            ..f.origin.clone()
        },
        Origin {
            org_id: "another-org".into(),
            ..f.origin.clone()
        },
        Origin {
            agent: AgentKind::Claude,
            ..f.origin.clone()
        },
        next.clone(),
    ] {
        refused(revert(previous, 2));
    }
    // Not the generation the adoption moved to.
    refused(revert(f.origin.clone(), 1));
    refused(revert(f.origin.clone(), 3));
    // A driver is alive here.
    let driver = StateLock::acquire(&f.dir.join("driver.lock")).unwrap();
    refused(revert(f.origin.clone(), 2));
    drop(driver);
    // A driver started here and took custody.
    let peer = f.clean_peer();
    refused(revert(f.origin.clone(), 2));
    fs::remove_file(f.dir.join("peer-current.json")).unwrap();
    let _ = peer;
    // The generation is not marked resumed from this predecessor.
    let marked: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    write_private_json(
        &f.dir.join(GENERATION),
        &Generation {
            resumed_from_pod_uid: None,
            ..marked.clone()
        },
    )
    .unwrap();
    assert!(handle_fixed(&f.environment, revert(f.origin.clone(), 2)).is_err());
    write_private_json(&f.dir.join(GENERATION), &marked).unwrap();
    assert_eq!(markers(), adopted);
    // Undone: the predecessor at its generation, unmarked, so the adopt
    // check holds again and the resumed fence is closed.
    assert_eq!(
        handle_fixed(&f.environment, revert(f.origin.clone(), 2)).unwrap(),
        json!({"launch_generation": 1})
    );
    let origin: Origin = private_record(&f.dir.join(ORIGIN)).unwrap();
    assert!(origin == f.origin);
    let generation: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    assert_eq!(generation.generation, 1);
    assert!(generation.resumed_from_pod_uid.is_none());
    assert!(!resumed(&f.environment, &f.origin.driver_id).unwrap());
    check_markers(
        &f.dir,
        &adopt_request(&f, next.clone(), Route::Codex, false),
    )
    .unwrap();
    // A second revert finds nothing to undo.
    assert!(handle_fixed(&f.environment, revert(f.origin.clone(), 2)).is_err());
}

#[test]
fn platform_revert_crash_point_never_opens_either_pod() {
    // #2769: the generation moves back before the origin. A crash between
    // them leaves the origin on this Pod at the predecessor's generation,
    // unmarked: the adoption's own crash point 3, which neither Pod opens.
    let f = Fixture::new();
    f.clean_peer();
    let next = successor(&f);
    let old: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    commit_adoption(
        &f.dir,
        &f.origin,
        &next,
        old,
        config,
        Path::new("/usr/bin/true"),
    )
    .unwrap();
    let marked: Generation = private_record(&f.dir.join(GENERATION)).unwrap();
    write_private_json(
        &f.dir.join(GENERATION),
        &Generation {
            generation: 1,
            resumed_from_pod_uid: None,
            ..marked
        },
    )
    .unwrap();
    let at = |origin: &Origin, generation: u64| Envelope {
        origin: origin.clone(),
        launch_generation: generation,
        request: Request::Adopt {
            origin: next.clone(),
            route: Route::Codex,
            commit: false,
        },
        ..f.request()
    };
    assert!(check_markers(&f.dir, &at(&next, 2)).is_err());
    assert!(check_markers(&f.dir, &at(&f.origin, 1)).is_err());
    assert!(!resumed(&f.environment, &f.origin.driver_id).unwrap());
    // Nor can the revert be repeated from there.
    assert!(
        handle_fixed(
            &f.environment,
            Envelope {
                origin: next.clone(),
                launch_generation: 2,
                request: Request::Revert {
                    previous: f.origin.clone()
                },
                ..f.request()
            }
        )
        .is_err()
    );
}

#[test]
fn platform_generation_records_without_the_resumed_mark_still_decode() {
    let f = Fixture::new();
    let bytes = fs::read(f.dir.join(GENERATION)).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("resumed_from_pod_uid"));
    let generation: Generation = serde_json::from_slice(&bytes).unwrap();
    assert!(generation.resumed_from_pod_uid.is_none());
}
