#[test]
fn live_runtime_cli_requires_explicit_environment_pins_revision_and_stable_request() {
    let image = "a".repeat(64);
    let payload = "b".repeat(64);
    let request = uuid::Uuid::new_v4().to_string();
    let args = [
        "cw",
        "--local",
        "runtime",
        "update",
        "vm-a",
        "--source",
        "/owned/cw-runtime.lock.json",
        "--image-sha256",
        &image,
        "--target-sha256",
        &payload,
        "--expected-revision",
        "7",
        "--request-id",
        &request,
        "--output",
        "json",
    ];
    let parsed = Cli::try_parse_from(args).unwrap();
    let (
        local,
        platform,
        EnvCommand::Runtime(EnvRuntimeArgs {
            command: EnvRuntimeCommand::Update(update),
        }),
    ) = env_operation(parsed)
    else {
        panic!("wrong route")
    };
    assert!(local);
    assert!(!platform);
    assert_eq!(update.environment, "vm-a");
    assert_eq!(update.expected_revision, Some(7));
    assert_eq!(update.image_sha256, Some(image.clone()));
    assert_eq!(update.target_sha256, payload);
    assert_eq!(update.request_id.unwrap().to_string(), request);
    assert_eq!(update.output, OutputFormat::Json);
    for (index, value) in [
        (9, "A"),
        (11, "../payload"),
        (13, "0"),
        (15, "00000000-0000-0000-0000-000000000000"),
    ] {
        let mut bad = args;
        bad[index] = value;
        assert!(Cli::try_parse_from(bad).is_err());
    }
    let missing_environment = ["cw", "runtime", "info"];
    assert!(Cli::try_parse_from(missing_environment).is_err());
    for flag in [
        "--source",
        "--image-sha256",
        "--target-sha256",
        "--expected-revision",
    ] {
        let index = args.iter().position(|value| *value == flag).unwrap();
        let missing: Vec<_> = args
            .iter()
            .enumerate()
            .filter_map(|(i, value)| (!(i == index || i == index + 1)).then_some(*value))
            .collect();
        assert!(Cli::try_parse_from(missing).is_err());
    }
}

#[test]
fn live_runtime_cli_observe_cancel_and_rollback_never_accept_a_source_or_lifecycle_command() {
    let request = uuid::Uuid::new_v4().to_string();
    for action in ["observe", "cancel"] {
        let parsed = Cli::try_parse_from([
            "cw",
            "--local",
            "runtime",
            action,
            "vm-a",
            "--request-id",
            &request,
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::Runtime(_)));
        assert!(Cli::try_parse_from(["cw", "runtime", action, "vm-a"]).is_err());
        assert!(
            Cli::try_parse_from([
                "cw",
                "runtime",
                action,
                "vm-a",
                "--request-id",
                &request,
                "--source",
                "/owned/source"
            ])
            .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "cw",
            "runtime",
            "rollback",
            "vm-a",
            "--expected-revision",
            "2"
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["cw", "runtime", "rollback", "vm-a"]).is_err());
    for extra in ["--source", "--restart", "--force", "--shell"] {
        assert!(
            Cli::try_parse_from([
                "cw",
                "runtime",
                "rollback",
                "vm-a",
                "--expected-revision",
                "2",
                extra,
                "/owned/source"
            ])
            .is_err()
        );
    }
}
