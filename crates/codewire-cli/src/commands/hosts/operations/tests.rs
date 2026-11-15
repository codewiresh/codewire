use std::collections::HashMap;

use super::*;

const ENVIRONMENT: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
const LOCAL: &str = "9b2e7c1a-0d4f-4e8b-a6c3-5f1d2e3a4b5c";
const OPERATION: &str = "c0ffee00-1234-4abc-8def-0123456789ab";
const HOST: &str = "5f0e2a7c-8d1b-4c3e-9a6f-2b4d6e8f0a1c";

fn environment_id() -> Uuid {
    Uuid::parse_str(ENVIRONMENT).unwrap()
}

fn placement() -> Placement {
    Placement::new(HOST)
}

#[test]
fn a_placed_vm_is_named_for_its_enrollment_and_environment_and_only_that_name_is_placed() {
    let name = placement().vm_name(environment_id());
    // A supervisor name is at most 63 bytes.
    assert!(name.len() <= 63, "{name}");
    assert!(
        name.starts_with("cw-") && name.ends_with(ENVIRONMENT),
        "{name}"
    );
    assert_eq!(placement().environment(&name), Some(environment_id()));

    // Another enrollment of this computer places other names: its VMs are
    // never this host's.
    let earlier = Placement::new("9c1d3e5f-7a2b-4c6d-8e0f-1a3b5c7d9e2f");
    assert_eq!(earlier.environment(&name), None);
    assert_eq!(
        placement().environment(&earlier.vm_name(environment_id())),
        None
    );

    let prefix = name.strip_suffix(ENVIRONMENT).unwrap();
    for name in [
        ENVIRONMENT.to_owned(),
        format!("cw-{ENVIRONMENT}"),
        format!("{prefix}{}", ENVIRONMENT.to_uppercase()),
        format!("{prefix}{}", ENVIRONMENT.replace('-', "")),
        format!("{prefix}{{{ENVIRONMENT}}}"),
        format!("{prefix}dev"),
    ] {
        assert_eq!(placement().environment(&name), None, "{name}");
    }
}

fn operation(kind: host_operation::Kind, local: &str, generation: u64) -> HostOperation {
    HostOperation {
        operation_id: OPERATION.into(),
        environment_id: ENVIRONMENT.into(),
        local_environment_id: local.into(),
        expected_generation: generation,
        kind: Some(kind),
        ..Default::default()
    }
}

fn stop() -> host_operation::Kind {
    host_operation::Kind::Stop(Box::default())
}

fn create() -> host_operation::Kind {
    host_operation::Kind::Create(Box::default())
}

fn invalid(operation: HostOperation) -> String {
    match Operation::parse(operation, &placement()) {
        Err(failure) => {
            assert_eq!(failure.code, "invalid_operation");
            failure.message
        }
        Ok(_) => panic!("parsed"),
    }
}

#[test]
fn an_operation_names_valid_ids_and_a_kind() {
    let parsed = Operation::parse(operation(stop(), LOCAL, 3), &placement()).unwrap();
    assert_eq!(parsed.id.to_string(), OPERATION);
    assert_eq!(parsed.environment_id, environment_id());
    assert_eq!(parsed.expected_generation, 3);
    assert!(matches!(
        parsed.kind,
        Kind::Lifecycle(Lifecycle::Stop, id) if id.to_string() == LOCAL
    ));

    let mut nil = operation(stop(), LOCAL, 3);
    nil.operation_id = Uuid::nil().to_string();
    invalid(nil);
    let mut no_kind = operation(stop(), LOCAL, 3);
    no_kind.kind = None;
    invalid(no_kind);
    // Every kind but create acts on the host's own environment.
    invalid(operation(stop(), "", 3));
    // A create names neither: the environment does not exist yet.
    invalid(operation(create(), LOCAL, 0));
    invalid(operation(create(), "", 1));
    assert!(Operation::parse(operation(create(), "", 0), &placement()).is_ok());
}

fn local_environment(
    id: &str,
    generation: u64,
    state: local::EnvironmentState,
) -> local::Environment {
    local::Environment {
        id: id.into(),
        name: placement().vm_name(environment_id()),
        state: state as i32,
        generation,
        vcpus: 2,
        memory_mib: 4096,
        disk_bytes: 20 << 30,
        ..Default::default()
    }
}

#[test]
fn the_fence_names_the_same_environment_at_the_generation_last_seen() {
    let local_id = Uuid::parse_str(LOCAL).unwrap();
    let environment = local_environment(LOCAL, 4, local::EnvironmentState::Running);
    assert_eq!(check_fence(&environment, local_id, 4), Ok(()));
    assert_eq!(
        check_fence(&environment, local_id, 3),
        Err(Outcome::Stale {
            expected: 3,
            current: 4
        })
    );
    let other = local_environment(ENVIRONMENT, 4, local::EnvironmentState::Running);
    match check_fence(&other, local_id, 4) {
        Err(Outcome::Failed(failure)) => assert_eq!(failure.code, "environment_mismatch"),
        outcome => panic!("{outcome:?}"),
    }
}

fn host_create(spec: &codewire_project::ProjectSpec) -> HostCreate {
    let json = serde_json::to_vec(spec).unwrap();
    HostCreate {
        vcpus: 2,
        memory_mib: 4096,
        disk_bytes: 20 << 30,
        project_spec_sha256: format!("{:x}", Sha256::digest(&json)),
        project_spec_json: json,
        ..Default::default()
    }
}

fn refused(create: &HostCreate) -> Failure {
    accepted_project(create).unwrap_err()
}

#[test]
fn a_create_is_refused_unless_this_host_can_build_it_from_the_project() {
    let empty = codewire_project::ProjectSpec::default();
    let mut tampered = host_create(&empty);
    tampered.project_spec_sha256 = "0".repeat(64);
    assert_eq!(refused(&tampered).code, "invalid_operation");

    // The host's own runtime picks the image.
    let imaged = host_create(&codewire_project::ProjectSpec {
        image: "ubuntu".into(),
        ..Default::default()
    });
    assert_eq!(refused(&imaged).code, "unsupported_project");

    let repository = host_create(&codewire_project::ProjectSpec {
        repositories: vec![codewire_project::RepositorySpec {
            source: "https://example.com/app.git".into(),
            destination: "app".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    assert_eq!(refused(&repository).code, "unsupported_project");

    let credentials = host_create(&codewire_project::ProjectSpec {
        credentials: Some(codewire_project::CredentialBinding {
            profile: "work".into(),
        }),
        ..Default::default()
    });
    assert_eq!(refused(&credentials).code, "unsupported_project");
    let secrets = host_create(&codewire_project::ProjectSpec {
        secrets: codewire_project::SecretBindings {
            organization: true,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(refused(&secrets).code, "unsupported_project");

    // A skill is copied from the store of the user running the supervisor:
    // the host owner's own files.
    let skills = host_create(&codewire_project::ProjectSpec {
        skills: vec![Default::default()],
        ..Default::default()
    });
    assert_eq!(refused(&skills).code, "unsupported_project");

    // And what `cw --local create` refuses.
    let preset = host_create(&codewire_project::ProjectSpec {
        preset: "node".into(),
        ..Default::default()
    });
    let failure = refused(&preset);
    assert_eq!(failure.code, "unsupported_project");
    assert!(failure.message.contains("preset"), "{}", failure.message);
    let elsewhere = host_create(&codewire_project::ProjectSpec {
        working_directory: "/srv".into(),
        ..Default::default()
    });
    assert!(refused(&elsewhere).message.contains("working_directory"));

    assert!(accepted_project(&host_create(&codewire_project::ProjectSpec::default())).is_ok());
}

#[test]
fn an_observation_reports_the_hosts_environment_in_the_contracts_states() {
    let running = observation(
        environment_id(),
        &local_environment(LOCAL, 5, local::EnvironmentState::Running),
    );
    assert_eq!(running.environment_id, ENVIRONMENT);
    assert_eq!(running.local_environment_id, LOCAL);
    assert_eq!(running.generation, 5);
    assert_eq!(
        running.state.as_known(),
        Some(HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING)
    );
    assert_eq!(
        (running.vcpus, running.memory_mib, running.disk_bytes),
        (2, 4096, 20 << 30)
    );

    // An orphan is not a state the control plane can act on.
    let orphan = observation(
        environment_id(),
        &local_environment(LOCAL, 5, local::EnvironmentState::Orphaned),
    );
    assert_eq!(
        orphan.state.as_known(),
        Some(HostEnvironmentState::HOST_ENVIRONMENT_STATE_ERROR)
    );
    assert_eq!(orphan.error_code, "orphaned");

    let mut broken = local_environment(LOCAL, 5, local::EnvironmentState::Error);
    assert_eq!(observation(environment_id(), &broken).error_code, "unknown");
    broken.error_code = "disk_full".into();
    assert_eq!(
        observation(environment_id(), &broken).error_code,
        "disk_full"
    );
}

#[test]
fn a_supervisor_refusal_is_reported_by_its_code_with_no_words_from_this_computer() {
    let failure = status_failure(&tonic::Status::resource_exhausted(
        "not enough memory under /var/lib/codewire-state",
    ));
    assert_eq!(failure.code, "resource_exhausted");
    assert!(!failure.message.contains("/var/lib"), "{}", failure.message);

    // The operation's own error code, when the supervisor gives one.
    let mut status = tonic::Status::failed_precondition(
        "local lifecycle operation 1 failed: create_guest_docker_tooling_missing",
    );
    status.metadata_mut().insert(
        "codewire-operation-error-code",
        "create_guest_docker_tooling_missing".parse().unwrap(),
    );
    assert_eq!(
        status_failure(&status).code,
        "create_guest_docker_tooling_missing"
    );
    // An unreachable supervisor says nothing about the operation.
    assert!(transient(&tonic::Status::unavailable("gone")));
    assert!(!transient(&tonic::Status::failed_precondition("stopped")));
}

#[test]
fn a_long_message_is_cut_on_a_character_boundary() {
    let message = "é".repeat(MAX_MESSAGE_BYTES);
    let failure = Failure::new("x", message);
    assert!(failure.message.len() <= MAX_MESSAGE_BYTES);
    assert!(failure.message.chars().all(|character| character == 'é'));
}

/// A supervisor that keeps its journal and VMs in memory and counts what it
/// was asked to do.
#[derive(Default)]
struct FakeSupervisor {
    journal: HashMap<String, local::Operation>,
    environments: HashMap<String, local::Environment>,
    creates: usize,
    changes: usize,
}

impl FakeSupervisor {
    fn journal(&mut self, request_id: &str, kind: local::OperationKind, environment_id: &str) {
        self.journal.insert(
            request_id.to_owned(),
            local::Operation {
                request_id: request_id.to_owned(),
                environment_id: environment_id.to_owned(),
                kind: kind as i32,
                ..Default::default()
            },
        );
    }
}

impl Supervisor for FakeSupervisor {
    async fn operation_for_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<local::Operation>, tonic::Status> {
        Ok(self.journal.get(&request_id.to_string()).cloned())
    }

    async fn follow(&mut self, _operation: local::Operation) -> Result<(), tonic::Status> {
        Ok(())
    }

    async fn ensure_runtime(&mut self) -> Result<(), Failure> {
        Ok(())
    }

    fn empty_workspace(&mut self) -> Result<(String, String), Failure> {
        Ok(("/empty".into(), "copy".into()))
    }

    async fn create(
        &mut self,
        request: local::CreateEnvironmentRequest,
    ) -> Result<(), tonic::Status> {
        self.creates += 1;
        self.journal(&request.request_id, local::OperationKind::Create, LOCAL);
        let mut environment = local_environment(LOCAL, 1, local::EnvironmentState::Running);
        environment.name = request.name.clone();
        self.environments.insert(request.name, environment);
        Ok(())
    }

    async fn get(&mut self, name: &str) -> Result<local::Environment, tonic::Status> {
        self.environments
            .get(name)
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("no such environment"))
    }

    async fn change(
        &mut self,
        lifecycle: Lifecycle,
        selector: local::EnvironmentSelector,
    ) -> Result<(), tonic::Status> {
        self.changes += 1;
        let kind = match lifecycle {
            Lifecycle::Start => local::OperationKind::Start,
            Lifecycle::Stop => local::OperationKind::Stop,
            Lifecycle::Destroy => local::OperationKind::Delete,
        };
        self.journal(&selector.request_id, kind, &selector.environment_id);
        if lifecycle == Lifecycle::Destroy {
            self.environments.remove(&selector.name);
            return Ok(());
        }
        let environment = self.environments.get_mut(&selector.name).unwrap();
        environment.generation += 1;
        environment.state = match lifecycle {
            Lifecycle::Start => local::EnvironmentState::Running,
            _ => local::EnvironmentState::Stopped,
        } as i32;
        Ok(())
    }
}

fn finished(attempt: Attempt) -> Outcome {
    match attempt {
        Attempt::Finished(outcome) => outcome,
        Attempt::Retry(reason) => panic!("retry: {reason}"),
    }
}

fn parsed(kind: host_operation::Kind, local: &str, generation: u64) -> Operation {
    Operation::parse(operation(kind, local, generation), &placement()).unwrap()
}

fn host_create_operation() -> host_operation::Kind {
    host_operation::Kind::Create(Box::new(host_create(
        &codewire_project::ProjectSpec::default(),
    )))
}

#[tokio::test]
async fn an_operation_sent_again_is_answered_from_the_journal_and_done_once() {
    let mut supervisor = FakeSupervisor::default();
    let create = parsed(host_create_operation(), "", 0);
    let first = finished(attempt_with(&mut supervisor, &create).await);
    let again = finished(attempt_with(&mut supervisor, &create).await);
    assert!(
        matches!(&first, Outcome::Done(observation) if observation.local_environment_id == LOCAL)
    );
    assert_eq!(first, again);
    assert_eq!(supervisor.creates, 1, "the VM is created once");

    // A stop sent again, after the VM's generation moved on because of it,
    // is answered from the journal, not refused as stale.
    let stop = Operation {
        id: Uuid::new_v4(),
        ..parsed(stop(), LOCAL, 1)
    };
    let stopped = finished(attempt_with(&mut supervisor, &stop).await);
    let again = finished(attempt_with(&mut supervisor, &stop).await);
    assert_eq!(stopped, again);
    assert_eq!(supervisor.changes, 1, "the VM is stopped once");
}

#[tokio::test]
async fn a_destroy_of_a_vm_already_gone_is_done_and_reports_it_absent() {
    let mut supervisor = FakeSupervisor::default();
    let destroy = parsed(host_operation::Kind::Destroy(Box::default()), LOCAL, 4);
    match finished(attempt_with(&mut supervisor, &destroy).await) {
        Outcome::Done(observation) => {
            assert_eq!(
                observation.state.as_known(),
                Some(HostEnvironmentState::HOST_ENVIRONMENT_STATE_ABSENT)
            );
            assert_eq!(observation.local_environment_id, LOCAL);
            assert_eq!(observation.generation, 4);
        }
        outcome => panic!("{outcome:?}"),
    }
    assert_eq!(supervisor.changes, 0);
}

#[tokio::test]
async fn an_operation_id_used_before_for_another_operation_is_refused() {
    let mut supervisor = FakeSupervisor::default();
    // The journal has this ID as a create; a stop with the same ID is not it.
    supervisor.journal(OPERATION, local::OperationKind::Create, LOCAL);
    match finished(attempt_with(&mut supervisor, &parsed(stop(), LOCAL, 1)).await) {
        Outcome::Failed(failure) => assert_eq!(failure.code, "invalid_operation"),
        outcome => panic!("{outcome:?}"),
    }
    // Nor is a stop of another environment.
    let mut supervisor = FakeSupervisor::default();
    supervisor.journal(OPERATION, local::OperationKind::Stop, ENVIRONMENT);
    match finished(attempt_with(&mut supervisor, &parsed(stop(), LOCAL, 1)).await) {
        Outcome::Failed(failure) => assert_eq!(failure.code, "invalid_operation"),
        outcome => panic!("{outcome:?}"),
    }
    assert_eq!(supervisor.changes, 0);
}

#[tokio::test]
async fn a_refused_create_prepares_nothing() {
    let mut supervisor = FakeSupervisor::default();
    let skills =
        host_operation::Kind::Create(Box::new(host_create(&codewire_project::ProjectSpec {
            skills: vec![Default::default()],
            ..Default::default()
        })));
    match finished(attempt_with(&mut supervisor, &parsed(skills, "", 0)).await) {
        Outcome::Failed(failure) => assert_eq!(failure.code, "unsupported_project"),
        outcome => panic!("{outcome:?}"),
    }
    assert_eq!(supervisor.creates, 0);
}
