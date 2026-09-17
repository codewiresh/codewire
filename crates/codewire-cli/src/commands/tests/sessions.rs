    #[test]
    fn attach_navigation_uses_only_ctrl_b_prefix_and_preserves_literal_input() {
        let mut decoder = AttachNavigationDecoder::default();

        assert_eq!(decoder.feed(b"echo"), (None, b"echo".to_vec()));
        assert_eq!(decoder.feed(b"\x02"), (None, Vec::new()));
        assert_eq!(decoder.feed(b"b"), (None, vec![0x02]));
        assert_eq!(decoder.feed(b"\x02l"), (Some(AttachExit::NextSession), Vec::new()));
        assert_eq!(decoder.feed(b"\x02k"), (Some(AttachExit::PreviousEnvironment), Vec::new()));
        assert_eq!(decoder.feed(b"\x02x"), (None, vec![0x02, b'x']));
        assert_eq!(decoder.feed(b"\x02"), (None, Vec::new()));
        assert_eq!(decoder.finish(), vec![0x02]);
    }

    #[test]
    fn attach_navigation_recognizes_every_session_action() {
        let cases = [
            (b"\x02h".as_slice(), AttachExit::PreviousSession),
            (b"\x02l".as_slice(), AttachExit::NextSession),
            (b"\x02k".as_slice(), AttachExit::PreviousEnvironment),
            (b"\x02j".as_slice(), AttachExit::NextEnvironment),
            (b"\x02w".as_slice(), AttachExit::OpenWorkspaces),
            (b"\x02r".as_slice(), AttachExit::Restart),
            (b"\x02d".as_slice(), AttachExit::Detached),
        ];
        for (input, expected) in cases {
            let mut decoder = AttachNavigationDecoder::default();
            assert_eq!(decoder.feed(input), (Some(expected), Vec::new()));
        }
    }

    #[test]
    fn attachment_reconnect_budget_is_bounded_and_resets_on_output_progress() {
        let mut budget = AttachmentReconnectBudget::default();
        assert_eq!(
            budget.retry_delay(0).unwrap(),
            ATTACH_RECONNECT_BASE_DELAY
        );
        assert_eq!(
            budget.retry_delay(0).unwrap(),
            ATTACH_RECONNECT_BASE_DELAY * 2
        );
        assert_eq!(
            budget.retry_delay(0).unwrap(),
            ATTACH_RECONNECT_BASE_DELAY * 3
        );
        assert!(budget.retry_delay(0).is_err());

        assert_eq!(
            budget.retry_delay(1).unwrap(),
            ATTACH_RECONNECT_BASE_DELAY
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_session_default_working_dir_uses_the_recorded_project_intent() {
        let environment = codewire_local_vmm::control::v1::Environment {
            name: "native".to_owned(),
            working_directory: "/workspace/github".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            native_environment_session_working_dir(&environment),
            "/workspace/github"
        );

        let fallback = codewire_local_vmm::control::v1::Environment {
            name: "native".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            native_environment_session_working_dir(&fallback),
            LOCAL_WORKSPACE_PATH
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_native_session_target_accepts_only_its_name_or_exact_id() {
        let environment = codewire_local_vmm::control::v1::Environment {
            id: "8fc6e44a-047a-4e65-8e56-26df709fee44".to_owned(),
            name: "native".to_owned(),
            ..Default::default()
        };
        assert!(native_session_request_matches(&environment, "native"));
        assert!(native_session_request_matches(
            &environment,
            "8fc6e44a-047a-4e65-8e56-26df709fee44"
        ));
        assert!(!native_session_request_matches(&environment, "nat"));
        assert!(!native_session_request_matches(&environment, "platform"));
    }

    #[test]
    fn environment_run_tty_selection_preserves_interactive_and_machine_modes() {
        let Command::Run(interactive) = Cli::try_parse_from(["cw", "run", "builder", "--", "codex"])
            .unwrap()
            .command
        else {
            panic!("expected run command");
        };
        assert!(environment_run_allocates_tty_for_streams(&interactive, true, true));
        assert!(!environment_run_allocates_tty_for_streams(&interactive, true, false));

        let Command::Run(no_tty) = Cli::try_parse_from([
            "cw", "run", "--no-tty", "builder", "--", "codex",
        ])
        .unwrap()
        .command
        else {
            panic!("expected run command");
        };
        assert!(!environment_run_allocates_tty_for_streams(&no_tty, true, true));

        let Command::Run(json) = Cli::try_parse_from([
            "cw", "run", "--output", "json", "builder", "--", "codex",
        ])
        .unwrap()
        .command
        else {
            panic!("expected run command");
        };
        assert!(!environment_run_allocates_tty_for_streams(&json, true, true));
    }

    #[test]
    fn platform_session_states_match_local_presentation_names() {
        use codewire_client::EnvironmentSessionState;

        let cases = [
            (EnvironmentSessionState::Unspecified, "Unspecified"),
            (EnvironmentSessionState::Starting, "Starting"),
            (EnvironmentSessionState::Running, "Running"),
            (EnvironmentSessionState::Stopping, "Stopping"),
            (EnvironmentSessionState::Stopped, "Stopped"),
            (EnvironmentSessionState::Exited, "Exited"),
            (EnvironmentSessionState::Failed, "Failed"),
            (EnvironmentSessionState::Interrupted, "Interrupted"),
        ];
        for (state, expected) in cases {
            assert_eq!(
                platform_environment_session_state_name(Some(state)),
                expected
            );
        }
        assert_eq!(platform_environment_session_state_name(None), "Unknown");
    }

    #[test]
    fn session_output_tail_is_line_based() {
        assert_eq!(
            tail_session_output(b"one\ntwo\nthree\n", Some(2)),
            b"two\nthree\n"
        );
        assert_eq!(tail_session_output(b"one\ntwo\n", Some(0)), b"");
        assert_eq!(tail_session_output(b"one\ntwo\n", None), b"one\ntwo\n");
    }

    #[test]
    fn adjacent_session_wraps_without_mutating_selected_environment() {
        let sessions = vec![
            EnvironmentSessionView {
                session_id: "a".to_string(),
                state: "Running".to_string(),
                command: vec!["first".to_string()],
                working_dir: String::new(),
                pty: true,
                exit_code: None,
                output_end_offset: 0,
                output_start_offset: 0,
                status_message: String::new(),
            },
            EnvironmentSessionView {
                session_id: "b".to_string(),
                state: "Running".to_string(),
                command: vec!["second".to_string()],
                working_dir: String::new(),
                pty: true,
                exit_code: None,
                output_end_offset: 0,
                output_start_offset: 0,
                status_message: String::new(),
            },
        ];

        assert_eq!(adjacent_session(&sessions, "a", true).unwrap().session_id, "b");
        assert_eq!(adjacent_session(&sessions, "a", false).unwrap().session_id, "b");
    }

    #[test]
    fn session_grammar_uses_environment_as_first_positional() {
        let list = Cli::try_parse_from(["cw", "list", "builder"]).unwrap();
        let Command::List(args) = list.command else {
            panic!("expected list command");
        };
        assert_eq!(args.environment.as_deref(), Some("builder"));

        let logs = Cli::try_parse_from(["cw", "logs", "builder", "session-1"]).unwrap();
        let Command::Logs(args) = logs.command else {
            panic!("expected logs command");
        };
        assert_eq!(args.environment.as_deref(), Some("builder"));
        assert_eq!(args.session.as_deref(), Some("session-1"));

        let attach = Cli::try_parse_from(["cw", "attach", "session-1"]).unwrap();
        let Command::Attach(args) = attach.command else {
            panic!("expected attach command");
        };
        assert_eq!(args.environment.as_deref(), Some("session-1"));
        assert_eq!(args.session, None);
    }

    #[test]
    fn foreground_run_fails_closed_on_session_exit_status() {
        let session = EnvironmentSessionView {
            session_id: "session-1".to_string(),
            state: "Exited".to_string(),
            command: vec!["false".to_string()],
            working_dir: LOCAL_WORKSPACE_PATH.to_string(),
            pty: false,
            exit_code: Some(42),
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        };
        assert_eq!(
            ensure_environment_session_succeeded(&session)
                .unwrap_err()
                .to_string(),
            "session exited with code 42"
        );

        let mut success = session.clone();
        success.exit_code = Some(0);
        ensure_environment_session_succeeded(&success).unwrap();

        let mut missing = session;
        missing.exit_code = None;
        missing.status_message = "worker disconnected".to_string();
        assert_eq!(
            ensure_environment_session_succeeded(&missing)
                .unwrap_err()
                .to_string(),
            "session reached terminal state Exited without an exit code: worker disconnected"
        );
    }
