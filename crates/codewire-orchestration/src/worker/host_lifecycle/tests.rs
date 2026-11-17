use super::*;

fn scope(run: &str, at: i64) -> OperationScope {
    OperationScope {
        workflow_run_id: run.into(),
        scheduled_at_unix_nanos: at,
    }
}

#[test]
fn an_operation_id_is_stable_for_one_activity_and_new_for_every_other() {
    let id = operation_id("env-1", &scope("run-1", 10), HostOperationKind::Create);
    // A UUID, as the host contract asks.
    assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
    // A Temporal retry of the same activity sends the same operation.
    assert_eq!(
        id,
        operation_id("env-1", &scope("run-1", 10), HostOperationKind::Create)
    );
    // Any other command is a new operation: a later activity in the same run
    // (start, stop, start), another run, another kind or environment.
    for other in [
        operation_id("env-1", &scope("run-1", 11), HostOperationKind::Create),
        operation_id("env-1", &scope("run-2", 10), HostOperationKind::Create),
        operation_id("env-1", &scope("run-1", 10), HostOperationKind::Start),
        operation_id("env-2", &scope("run-1", 10), HostOperationKind::Create),
    ] {
        assert_ne!(id, other);
    }
}

fn spec(image: &str) -> codewire_project::ProjectSpec {
    codewire_project::ProjectSpec {
        image: image.into(),
        ..codewire_project::parse_project_yaml("{}\n").unwrap().spec
    }
}

#[test]
fn a_create_sends_the_shape_and_the_exact_bytes_the_host_hashes() {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let encoded = create_operation(&CreateRequest {
        environment_id: "00000000-0000-4000-8000-000000000001",
        operation_id: "00000000-0000-4000-8000-000000000002",
        project_spec: &spec(canonical),
        cpu_millicores: 1500,
        memory_mib: 4096,
        disk_gib: 40,
    })
    .unwrap();
    let operation: proto::HostOperation = buffa::Message::decode(&mut encoded.as_slice()).unwrap();
    assert_eq!(
        operation.operation_id,
        "00000000-0000-4000-8000-000000000002"
    );
    assert_eq!(operation.local_environment_id, "");
    assert_eq!(operation.expected_generation, 0);
    let Some(proto::__buffa::oneof::host_operation::Kind::Create(create)) = operation.kind else {
        panic!("not a create: {:?}", operation.kind);
    };
    // 1.5 cores round up to 2 vCPUs.
    assert_eq!((create.vcpus, create.memory_mib), (2, 4096));
    assert_eq!(create.disk_bytes, 40 << 30);
    assert_eq!(create.docker_disk_bytes, 8 << 30);
    // The canonical image is cleared: the host runs its own default.
    let sent: codewire_project::ProjectSpec =
        serde_json::from_slice(&create.project_spec_json).unwrap();
    assert!(sent.image.is_empty());
    assert_eq!(
        create.project_spec_sha256,
        format!("{:x}", Sha256::digest(&create.project_spec_json))
    );
}

#[test]
fn a_create_never_sends_another_image_or_an_empty_shape() {
    let request = |spec, cpu| CreateRequest {
        environment_id: "env",
        operation_id: "op",
        project_spec: spec,
        cpu_millicores: cpu,
        memory_mib: 2048,
        disk_gib: 10,
    };
    let custom = spec("example.test/custom:1");
    assert!(create_operation(&request(&custom, 1000)).is_err());
    let empty = spec("");
    assert!(create_operation(&request(&empty, 0)).is_err());
    assert!(create_operation(&request(&empty, 1000)).is_ok());
}

#[test]
fn each_outcome_reads_as_the_lifecycle_acts_on_it() {
    let encode = |outcome: proto::__buffa::oneof::host_operation_result::Outcome| {
        buffa::Message::encode_to_vec(&proto::HostOperationResult {
            operation_id: "op".into(),
            outcome: Some(outcome),
            ..Default::default()
        })
    };
    let done = encode(
        proto::HostEnvironmentObservation {
            environment_id: "env-1".into(),
            local_environment_id: "local-1".into(),
            generation: 3,
            state: proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING.into(),
            ..Default::default()
        }
        .into(),
    );
    assert_eq!(
        answer("env-1", &done).unwrap(),
        Answer::Done {
            state: proto::HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
        }
    );
    // Another environment's VM is never taken for this one's.
    assert!(answer("env-2", &done).is_err());
    let failed = encode(
        proto::HostOperationFailure {
            code: "invalid_argument".into(),
            message: "vcpus must be 1 to 32".into(),
            ..Default::default()
        }
        .into(),
    );
    assert_eq!(
        answer("env-1", &failed).unwrap(),
        Answer::Failed {
            code: "invalid_argument".into(),
            message: "vcpus must be 1 to 32".into(),
        }
    );
    let stale = encode(
        proto::HostStaleGeneration {
            expected_generation: 1,
            current_generation: 2,
            ..Default::default()
        }
        .into(),
    );
    assert_eq!(
        answer("env-1", &stale).unwrap(),
        Answer::Stale {
            expected: 1,
            current: 2
        }
    );
    assert!(answer("env-1", b"\xff").is_err());
}

#[test]
fn a_hosts_words_are_shown_as_one_bounded_line_with_nothing_hidden() {
    let failure = Answer::Failed {
        code: "disk full\n\u{1b}[31m".into(),
        message: "no  space\r\nleft \u{202e}on\u{7} this\u{200b} host".into(),
    };
    assert_eq!(
        failure_text(&failure),
        "no space left on this host (diskfull31m)"
    );

    let long = Answer::Failed {
        code: String::new(),
        message: "é".repeat(5_000),
    };
    let text = failure_text(&long);
    assert_eq!(
        text.chars().filter(|character| *character == 'é').count(),
        300
    );
    assert!(text.ends_with(" (unknown)"), "{text}");

    // Nothing readable left: the reason still says what happened.
    let empty = Answer::Failed {
        code: "x".repeat(200),
        message: "\u{202e}\n".into(),
    };
    assert_eq!(
        failure_text(&empty),
        format!("the host refused the operation ({})", "x".repeat(64))
    );
}

#[test]
fn a_vm_state_reads_as_a_word() {
    use proto::HostEnvironmentState as Vm;
    let stopped = Answer::Done {
        state: Vm::HOST_ENVIRONMENT_STATE_STOPPED,
    };
    assert_eq!(failure_text(&stopped), "the host's VM is stopped");
    assert_eq!(vm_state(Vm::HOST_ENVIRONMENT_STATE_ABSENT), "gone");
    assert_eq!(
        vm_state(Vm::HOST_ENVIRONMENT_STATE_UNSPECIFIED),
        "in an unknown state"
    );
}
