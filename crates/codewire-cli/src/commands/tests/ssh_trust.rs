    /// A scripted environment resolution: the id, or an error message.
    type FakeEnvironmentAnswer = Result<&'static str, &'static str>;
    /// A scripted host-key read: the recorded key if any, or an error message.
    type FakeKeyAnswer = Result<Option<&'static str>, &'static str>;

    /// A scripted platform for `cw ssh known-hosts`.
    struct FakeHostKeys {
        environment: FakeEnvironmentAnswer,
        key: FakeKeyAnswer,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl FakeHostKeys {
        fn new(environment: FakeEnvironmentAnswer, key: FakeKeyAnswer) -> Self {
            Self {
                environment,
                key,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl EnvironmentHostKeys for FakeHostKeys {
        async fn resolve_environment(
            &self,
            org_id: &str,
            alias: SshAlias<'_>,
        ) -> anyhow::Result<String> {
            self.seen.lock().unwrap().push(format!(
                "resolve {org_id} {:?} {}",
                alias.placement, alias.environment_ref
            ));
            self.environment
                .map(str::to_string)
                .map_err(|error| anyhow::anyhow!(error))
        }

        async fn recorded_host_key(
            &self,
            org_id: &str,
            environment_id: &str,
        ) -> anyhow::Result<Option<RecordedHostKey>> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("key {org_id} {environment_id}"));
            self.key
                .map(|key| {
                    key.map(|key| RecordedHostKey {
                        generation: 7,
                        public_key_openssh: key.to_string(),
                    })
                })
                .map_err(|error| anyhow::anyhow!(error))
        }
    }

    /// `ssh-ed25519` wire blob with key bytes 0..32.
    fn ed25519_public_key_base64() -> String {
        use base64::Engine as _;
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend((0u8..32).collect::<Vec<_>>());
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    fn leak(value: String) -> &'static str {
        Box::leak(value.into_boxed_str())
    }

    #[tokio::test]
    async fn known_hosts_prints_one_line_for_the_recorded_key() {
        let encoded = ed25519_public_key_base64();
        let source = FakeHostKeys::new(
            Ok("env-1"),
            Ok(Some(leak(format!("ssh-ed25519 {encoded} daemon@generation-7")))),
        );
        let target = KnownHostsTarget::parse("cw-my-app").unwrap();

        let line = known_hosts_line(&source, "org-1", &target).await.unwrap();

        assert_eq!(line, format!("cw-my-app ssh-ed25519 {encoded}\n"));
        assert_eq!(
            *source.seen.lock().unwrap(),
            ["resolve org-1 Bare my-app", "key org-1 env-1"]
        );
    }

    #[tokio::test]
    async fn known_hosts_keeps_a_bracketed_port_host_verbatim() {
        let encoded = ed25519_public_key_base64();
        let source = FakeHostKeys::new(
            Ok("env-1"),
            Ok(Some(leak(format!("ssh-ed25519 {encoded}")))),
        );
        let target = KnownHostsTarget::parse("[cw-my-app]:2222").unwrap();

        let line = known_hosts_line(&source, "org-1", &target).await.unwrap();

        assert_eq!(line, format!("[cw-my-app]:2222 ssh-ed25519 {encoded}\n"));
        assert_eq!(source.seen.lock().unwrap()[0], "resolve org-1 Bare my-app");
    }

    #[tokio::test]
    async fn known_hosts_fails_closed() {
        let encoded = ed25519_public_key_base64();
        let valid = leak(format!("ssh-ed25519 {encoded}"));
        let cases: Vec<(&str, FakeEnvironmentAnswer, FakeKeyAnswer)> = vec![
            (
                "unknown environment",
                Err("environment not found"),
                Ok(Some(valid)),
            ),
            ("no recorded key", Ok("env-1"), Ok(None)),
            ("API failure", Ok("env-1"), Err("unavailable")),
            (
                "RSA key",
                Ok("env-1"),
                Ok(Some("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ")),
            ),
            (
                "bad base64",
                Ok("env-1"),
                Ok(Some("ssh-ed25519 !!!notbase64")),
            ),
            ("missing key data", Ok("env-1"), Ok(Some("ssh-ed25519"))),
            ("empty", Ok("env-1"), Ok(Some(""))),
            (
                "truncated blob",
                Ok("env-1"),
                Ok(Some(leak(format!("ssh-ed25519 {}", &encoded[..40])))),
            ),
            (
                "mislabelled blob",
                Ok("env-1"),
                Ok(Some(leak({
                    use base64::Engine as _;
                    let mut blob = Vec::new();
                    blob.extend_from_slice(&11u32.to_be_bytes());
                    blob.extend_from_slice(b"ssh-ed448!!");
                    blob.extend_from_slice(&32u32.to_be_bytes());
                    blob.extend([0u8; 32]);
                    format!(
                        "ssh-ed25519 {}",
                        base64::engine::general_purpose::STANDARD.encode(blob)
                    )
                }))),
            ),
            (
                "trailing bytes",
                Ok("env-1"),
                Ok(Some(leak({
                    use base64::Engine as _;
                    let mut blob = base64::engine::general_purpose::STANDARD
                        .decode(&encoded)
                        .unwrap();
                    blob.push(0);
                    format!(
                        "ssh-ed25519 {}",
                        base64::engine::general_purpose::STANDARD.encode(blob)
                    )
                }))),
            ),
        ];
        let target = KnownHostsTarget::parse("cw-my-app").unwrap();
        for (name, environment, key) in cases {
            let source = FakeHostKeys::new(environment, key);
            assert!(
                known_hosts_line(&source, "org-1", &target).await.is_err(),
                "{name} must fail closed"
            );
        }
    }

    #[test]
    fn known_hosts_refuses_hosts_outside_the_managed_alias() {
        for host in [
            "",
            "my-app",
            "cw-",
            "cw-my app",
            "cw-a,cw-b",
            "cw-*",
            "cw-a\nevil ssh-ed25519 AAAA",
            "[cw-my-app]",
            "[cw-my-app]:",
            "[cw-my-app]:0",
            "[cw-my-app]:70000",
            "[cw-my-app]:22x",
            "[other]:22",
            "cw-my-app ",
            "cw-cloud-",
            "cw-local-",
            "[cw-cloud-]:22",
        ] {
            assert!(
                KnownHostsTarget::parse(host).is_err(),
                "{host:?} must be refused"
            );
        }
        assert!(KnownHostsTarget::parse("cw-My_App.2").is_ok());
    }

    #[test]
    fn known_hosts_command_is_wired_under_cw_ssh() {
        let cli = Cli::try_parse_from(["cw", "ssh", "known-hosts", "cw-my-app"]).unwrap();
        let Command::Ssh {
            command: SshCommand::KnownHosts(args),
        } = cli.command
        else {
            panic!("expected cw ssh known-hosts");
        };
        assert_eq!(args.host, "cw-my-app");
    }

    #[tokio::test]
    async fn known_hosts_resolves_a_qualified_cloud_alias_and_keeps_it_verbatim() {
        let encoded = ed25519_public_key_base64();
        let key = leak(format!("ssh-ed25519 {encoded}"));
        for host in ["cw-cloud-my-app", "[cw-cloud-my-app]:2222"] {
            let source = FakeHostKeys::new(Ok("env-1"), Ok(Some(key)));
            let target = KnownHostsTarget::parse(host).unwrap();
            let line = known_hosts_line(&source, "org-1", &target).await.unwrap();
            assert_eq!(line, format!("{host} ssh-ed25519 {encoded}\n"));
            assert_eq!(source.seen.lock().unwrap()[0], "resolve org-1 Cloud my-app");
        }
    }

    /// `cw-local-` is reserved for local VMs: known-hosts never vouches for a
    /// cloud key under it, whichever block ran the command, and reads nothing.
    #[tokio::test]
    async fn known_hosts_refuses_a_local_alias_before_any_read() {
        let encoded = ed25519_public_key_base64();
        for host in ["cw-local-my-app", "[cw-local-my-app]:22"] {
            let source = FakeHostKeys::new(
                Ok("env-1"),
                Ok(Some(leak(format!("ssh-ed25519 {encoded}")))),
            );
            let target = KnownHostsTarget::parse(host).unwrap();
            let error = known_hosts_line(&source, "org-1", &target)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("names a local VM, which the cloud does not serve"),
                "{error}"
            );
            assert!(
                source.seen.lock().unwrap().is_empty(),
                "{host} read the platform"
            );
        }
    }

    #[test]
    fn ssh_aliases_name_their_placement() {
        let alias = |placement, environment_ref| {
            Some(SshAlias {
                placement,
                environment_ref,
            })
        };
        assert_eq!(
            SshAlias::parse("cw-cloud-app"),
            alias(AliasPlacement::Cloud, "app")
        );
        // `cw-cloud-local-x` is the cloud environment named `local-x`.
        assert_eq!(
            SshAlias::parse("cw-cloud-local-x"),
            alias(AliasPlacement::Cloud, "local-x")
        );
        assert_eq!(
            SshAlias::parse("cw-local-app"),
            alias(AliasPlacement::Local, "app")
        );
        assert_eq!(
            SshAlias::parse("cw-app"),
            alias(AliasPlacement::Bare, "app")
        );
        assert_eq!(SshAlias::parse("app"), alias(AliasPlacement::Bare, "app"));
        // Without the `cw-` prefix nothing is qualified.
        assert_eq!(
            SshAlias::parse("cloud-app"),
            alias(AliasPlacement::Bare, "cloud-app")
        );
        assert_eq!(
            SshAlias::parse("cw-cloud"),
            alias(AliasPlacement::Bare, "cloud")
        );
        for empty in ["", " ", "cw-", "cw-cloud-", "cw-local-"] {
            assert_eq!(SshAlias::parse(empty), None, "{empty:?}");
        }
        // A cloud alias under --local is a contradiction, refused before any
        // lookup; --cloud and no flag accept it.
        let cloud = SshAlias::parse("cw-cloud-app").unwrap();
        assert!(cloud.check_placement(None).is_ok());
        assert!(
            cloud
                .check_placement(Some(EnvironmentPlacement::Platform))
                .is_ok()
        );
        let error = cloud
            .check_placement(Some(EnvironmentPlacement::Local))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`cw-cloud-app` names a cloud environment, which --local does not reach"
        );
    }

    #[test]
    fn a_qualified_cloud_alias_falls_back_only_to_its_old_meaning() {
        let app = test_environment(
            "11111111-0000-4000-8000-000000000001",
            Some("app"),
            "running",
        );
        let cloud_app = test_environment(
            "22222222-0000-4000-8000-000000000002",
            Some("cloud-app"),
            "running",
        );
        let other = test_environment(
            "33333333-0000-4000-8000-000000000003",
            Some("other"),
            "running",
        );
        // `<ref>` resolves as any reference does: by name, ID or ID prefix.
        assert_eq!(
            resolve_qualified_cloud_ref(&[app.clone(), other.clone()], "app").unwrap(),
            app.id
        );
        assert_eq!(
            resolve_qualified_cloud_ref(&[app.clone(), other.clone()], "3333").unwrap(),
            other.id
        );
        // With no `<ref>`, the environment named exactly `cloud-<ref>`, which
        // `cw-cloud-<ref>` meant before it was qualified.
        assert_eq!(
            resolve_qualified_cloud_ref(&[cloud_app.clone(), other.clone()], "app").unwrap(),
            cloud_app.id
        );
        // Both: refused, naming both, rather than trusting either one's key.
        let error = resolve_qualified_cloud_ref(&[app.clone(), cloud_app.clone()], "app")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&app.id) && error.contains(&cloud_app.id),
            "{error}"
        );
        assert!(error.contains(&format!("`cw-cloud-{}`", app.id)), "{error}");
        // Neither: not found, with where to look.
        let error = resolve_qualified_cloud_ref(&[other], "app")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no cloud environment matches \"app\""),
            "{error}"
        );
    }

    #[test]
    fn a_local_alias_names_the_cloud_aliases_of_its_old_meaning() {
        let error = local_alias_not_found("app", None).to_string();
        assert_eq!(
            error,
            "no local VM matches \"app\" (from `cw-local-app`); `cw --local ls` lists yours"
        );
        let local_app = test_environment(
            "44444444-0000-4000-8000-000000000004",
            Some("local-app"),
            "running",
        );
        let error =
            local_alias_not_found("app", Some(std::slice::from_ref(&local_app))).to_string();
        assert!(
            error.ends_with(&format!(
                ". The cloud environment \"local-app\" is `cw-cloud-local-app` or `cw-{}`",
                local_app.id
            )),
            "{error}"
        );
    }

    #[test]
    fn an_alias_names_its_placement_and_refuses_the_other_flag() {
        let local = SshAlias::parse("cw-local-app").unwrap();
        assert!(local.is_local(None));
        assert!(local.is_local(Some(EnvironmentPlacement::Local)));
        let error = local
            .check_placement(Some(EnvironmentPlacement::Platform))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`cw-local-app` names a local VM, which --cloud does not reach"
        );
        // A bare alias is local only under --local; a cloud alias never is.
        let bare = SshAlias::parse("cw-app").unwrap();
        assert!(!bare.is_local(None));
        assert!(!bare.is_local(Some(EnvironmentPlacement::Platform)));
        assert!(bare.is_local(Some(EnvironmentPlacement::Local)));
        let cloud = SshAlias::parse("cw-cloud-app").unwrap();
        assert!(!cloud.is_local(None));
    }

    #[test]
    fn a_local_known_hosts_line_carries_the_host_as_asked() {
        let encoded = ed25519_public_key_base64();
        for host in ["cw-local-app", "[cw-local-app]:22"] {
            let target = KnownHostsTarget::parse(host).unwrap();
            // The supervisor's key line has no host field.
            let line = local_known_hosts_line(&target, &format!("ssh-ed25519 {encoded}")).unwrap();
            assert_eq!(line, format!("{host} ssh-ed25519 {encoded}\n"));
        }
        let target = KnownHostsTarget::parse("cw-local-app").unwrap();
        for invalid in ["", "ssh-rsa AAAAB3NzaC1yc2E", "ssh-ed25519 !!!"] {
            assert!(
                local_known_hosts_line(&target, invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn known_hosts_takes_a_placement() {
        let cli =
            Cli::try_parse_from(["cw", "--local", "ssh", "known-hosts", "cw-local-app"]).unwrap();
        crate::validate_placement_scope(&cli.command, "ssh", cli.placement().unwrap(), false)
            .unwrap();
    }

    #[test]
    fn known_hosts_takes_a_cloud_placement() {
        let cli =
            Cli::try_parse_from(["cw", "--cloud", "ssh", "known-hosts", "cw-cloud-app"]).unwrap();
        crate::validate_placement_scope(&cli.command, "ssh", cli.placement().unwrap(), false)
            .unwrap();
    }
