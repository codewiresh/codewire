use super::*;

const REQUEST: &str = "6a162b2b-a758-4c8c-bccb-794502c82f09";
fn request() -> rpc::MutateEnvironmentAgentRequest {
    rpc::MutateEnvironmentAgentRequest {
        org_id: "org".into(),
        environment_id: "env".into(),
        request_id: REQUEST.into(),
        expected_scope: Some(rpc::EnvironmentAgentScope {
            incarnation: Some(
                codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation {
                    org_id: "org".into(),
                    environment_id: "env".into(),
                    pod_uid: "original-pod".into(),
                    binding_generation: u64::MAX,
                    ..Default::default()
                },
            )
            .into(),
            support_image_sha256: vec![7; 32],
            support_image_size: 123,
            ..Default::default()
        })
        .into(),
        operation: Some(rpc::mutate_environment_agent_request::Operation::Launch(
            Box::new(rpc::EnvironmentAgentLaunch {
                agent: rpc::EnvironmentAgentKind::Codex.into(),
                prompt: Some("PRIVATE_PROMPT_CANARY".into()),
                ..Default::default()
            }),
        )),
        ..Default::default()
    }
}

#[test]
fn saved_original_request_survives_reader_restart_without_prompt_values() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    let request = request();
    save_request_at(&directory, &request).unwrap();
    let path = directory.join(format!("{REQUEST}.json"));
    let raw = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("PRIVATE_PROMPT_CANARY"));
    let saved: RequestReference = read_record(&path).unwrap();
    assert_eq!(saved.request_id, REQUEST);
    assert_eq!(saved.scope, *request.expected_scope.as_option().unwrap());
    assert_eq!(
        saved.request_sha256,
        format!("{:x}", sha2::Sha256::digest(request.encode_to_vec()))
    );
    assert_eq!(saved.session_id, format!("session-{REQUEST}"));
    save_request_at(&directory, &request).unwrap();
    assert_eq!(fs::read(&path).unwrap(), raw);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn changed_payload_scope_or_cleanup_lineage_cannot_replace_original_uuid() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    let mut original = request();
    original.operation = Some(rpc::mutate_environment_agent_request::Operation::Control(
        Box::new(rpc::EnvironmentAgentControl {
            action: rpc::EnvironmentAgentAction::Stop.into(),
            session_id: "session-original".into(),
            driver_id: REQUEST.into(),
            expected_launch_generation: 2,
            cleanup_of_request_id: Some("6d370dab-3d67-4d76-93c3-3bd31581fbe9".into()),
            ..Default::default()
        }),
    ));
    save_request_at(&directory, &original).unwrap();
    let path = directory.join(format!("{REQUEST}.json"));
    let raw = fs::read(&path).unwrap();
    for kind in 0..3 {
        let mut changed = original.clone();
        if kind == 0 {
            changed.environment_id = "replacement".into();
        }
        if let Some(rpc::mutate_environment_agent_request::Operation::Control(control)) =
            &mut changed.operation
        {
            if kind == 1 {
                control.expected_launch_generation = 3;
            }
            if kind == 2 {
                control.cleanup_of_request_id = Some(REQUEST.into());
            }
        }
        assert!(save_request_at(&directory, &changed).is_err());
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
}

#[test]
fn contended_request_reference_and_oversized_payload_refuse_before_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    private_directory(&directory).unwrap();
    let lock = StateLock::try_acquire(&directory.join(format!("{REQUEST}.lock")))
        .unwrap()
        .unwrap();
    assert!(save_request_at(&directory, &request()).is_err());
    assert!(!directory.join(format!("{REQUEST}.json")).exists());
    drop(lock);
    let mut large = request();
    if let Some(rpc::mutate_environment_agent_request::Operation::Launch(launch)) =
        &mut large.operation
    {
        launch.prompt = Some("x".repeat(256 * 1024));
    }
    assert!(save_request_at(&directory, &large).is_err());
    assert!(!directory.join(format!("{REQUEST}.json")).exists());
}

#[test]
fn an_ended_conversation_is_said_plainly_and_recognised_on_every_client() {
    // #2705: a conversation of an earlier incarnation is named as ended with
    // its environment, with the way to start a new one.
    assert_eq!(
        ended_with_environment("reviewer"),
        "managed conversation \"reviewer\" ended when its environment stopped; \
         start a new one with `cw run ENV --agent codex|claude`"
    );
    // The driver runs in the Sandbox, which is always Linux, so the client's
    // own OS never decides whether a listed session is a managed one.
    let driver = |second: &str| {
        vec![
            "/codewire/bin/cw".to_owned(),
            second.to_owned(),
            "--environment".to_owned(),
            "env".to_owned(),
            "--driver-id".to_owned(),
            REQUEST.to_owned(),
        ]
    };
    assert!(is_platform_driver(&driver("__platform-agent-driver")));
    assert!(!is_platform_driver(&driver("__agent-driver")));
    assert!(!is_platform_driver(&["sh".to_owned()]));
    assert!(!is_platform_driver(&[]));
}

#[test]
fn platform_refusals_are_definite_only_with_their_exact_reason() {
    // #2782: a refusal at admission names its reason; nothing else is
    // treated as definite, so a lost answer stays an uncertain outcome.
    use codewire_proto::google::rpc::ErrorInfo;
    use connectrpc::{ConnectError, ErrorDetail};
    let reasoned = |error: ConnectError, reason: &str| {
        codewire_client::ClientError::from(error.with_detail(ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &ErrorInfo {
                reason: reason.into(),
                domain: "codewire.sh".into(),
                ..Default::default()
            },
        )))
    };
    let blocked = reasoned(
        ConnectError::failed_precondition("message x is still in progress; try again shortly"),
        "PLATFORM_AGENT_REQUEST_REFUSED",
    );
    assert!(request_refused(&blocked));
    assert!(!resume_refused(&blocked));
    let resume = reasoned(
        ConnectError::failed_precondition("the previous Pod is still stopping"),
        "PLATFORM_AGENT_RESUME_REFUSED",
    );
    assert!(resume_refused(&resume));
    assert!(!request_refused(&resume));
    // The right reason under another code, a plain conflict, or no reason at
    // all stay uncertain.
    for error in [
        reasoned(
            ConnectError::unavailable("transport"),
            "PLATFORM_AGENT_REQUEST_REFUSED",
        ),
        codewire_client::ClientError::from(ConnectError::already_exists(
            "platform managed request requires observation or original-generation cleanup",
        )),
        codewire_client::ClientError::new(
            codewire_client::ErrorCode::FailedPrecondition,
            "no reason",
        ),
    ] {
        assert!(!request_refused(&error), "{error:?}");
        assert!(!resume_refused(&error), "{error:?}");
    }
}
