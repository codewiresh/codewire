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
