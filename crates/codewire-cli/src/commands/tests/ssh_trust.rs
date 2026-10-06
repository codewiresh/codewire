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
            environment_ref: &str,
        ) -> anyhow::Result<String> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("resolve {org_id} {environment_ref}"));
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
            ["resolve org-1 my-app", "key org-1 env-1"]
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
        assert_eq!(source.seen.lock().unwrap()[0], "resolve org-1 my-app");
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
