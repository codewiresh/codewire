use std::collections::VecDeque;

use super::*;
use crate::supervisor::tests::{
    project_environment, spawn_test_supervisor_server, test_supervisor_core,
    test_supervisor_service, test_workspace_generation,
};

const PROFILE_ID: &str = "11111111-1111-4111-8111-111111111111";

fn target_request(environment: &EnvironmentRecord) -> v1::UpdateEnvironmentSourcesRequest {
    let mut project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.secrets.user = Some(StoragePlacement::Local);
    let json = project.canonical_json().unwrap();
    v1::UpdateEnvironmentSourcesRequest {
        name: environment.name.clone(),
        request_id: Uuid::new_v4().to_string(),
        expected_environment_id: environment.id.to_string(),
        expected_generation: environment.generation,
        expected_project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
        expected_access_profile_id: environment
            .access_binding
            .as_ref()
            .map(|binding| binding.profile_id.to_string())
            .unwrap_or_default(),
        expected_access_profile_revision: environment
            .access_binding
            .as_ref()
            .map(|binding| binding.profile_revision)
            .unwrap_or_default(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&json)),
        project_spec_json: json,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        allow_restart: false,
        expected_platform_source_authority: environment
            .platform_source_authority
            .as_ref()
            .map(PlatformSourceAuthority::proto),
        platform_source_authority: None,
    }
}

fn edit_target(
    request: &mut v1::UpdateEnvironmentSourcesRequest,
    edit: impl FnOnce(&mut ProjectSpec),
) {
    let mut project = serde_json::from_slice(&request.project_spec_json).unwrap();
    edit(&mut project);
    request.project_spec_json = project.canonical_json().unwrap();
    request.project_spec_sha256 = format!("{:x}", Sha256::digest(&request.project_spec_json));
}

fn profile_target(request: &mut v1::UpdateEnvironmentSourcesRequest, placement: &str) {
    edit_target(request, |project| {
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("{placement}:id:{PROFILE_ID}"),
        });
    });
    request.access_profile_id = PROFILE_ID.into();
    request.access_profile_revision = 7;
    request.access_profile_reference = "user/work".into();
    if placement == "platform" {
        request.platform_source_authority = Some(v1::PlatformSourceAuthority {
            anthropic_form: String::new(),
            server_url: "https://synthetic.invalid".into(),
            organization_id: "org".into(),
            user_id: "owner".into(),
            profile_slots: vec!["codex".into(), "openai".into()],
        });
    }
}

fn begin_at(
    core: &SupervisorCore,
    transition: &SourceTransition,
    checkpoint: u32,
) -> OperationRecord {
    let mut operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(core.environment(&transition.name).unwrap().id),
            OperationKind::UpdateEnvironmentSources,
            &serde_json::to_value(transition).unwrap(),
        )
        .unwrap();
    for _ in 0..checkpoint {
        operation = core
            .store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
    }
    operation
}

#[test]
fn source_profile_admission_rejects_inactive_or_hard_expired_credential_metadata() {
    let mut metadata = codewire_access::CredentialMetadata {
        id: codewire_access::CredentialId::parse("synthetic-credential").unwrap(),
        placement: codewire_access::Placement::Local,
        owner: codewire_access::Owner::User(codewire_access::OwnerId::parse("local-user").unwrap()),
        provider: codewire_access::ProviderId::parse("openai").unwrap(),
        authentication_kind: codewire_access::CredentialAuthKind::ApiKey,
        display_name: "synthetic".into(),
        account_hint: None,
        ssh_public_key: None,
        status: codewire_access::CredentialStatus::Active,
        expires_at_unix: Some(101),
        revocation_generation: 1,
    };
    assert!(source_credential_active(&metadata, 100));
    assert!(!source_credential_active(&metadata, 101));
    metadata.expires_at_unix = None;
    for status in [
        codewire_access::CredentialStatus::Expired,
        codewire_access::CredentialStatus::RefreshFailed,
        codewire_access::CredentialStatus::Revoked,
    ] {
        metadata.status = status;
        assert!(!source_credential_active(&metadata, 100));
    }
}

#[test]
fn source_update_requires_every_exact_cas_dimension_and_only_source_drift() {
    let environment = project_environment();
    let request = target_request(&environment);
    SourceTransition::new(&request, &environment).unwrap();
    let mutations: &[fn(&mut v1::UpdateEnvironmentSourcesRequest)] = &[
        |r| r.expected_environment_id = Uuid::new_v4().to_string(),
        |r| r.expected_generation = 0,
        |r| r.expected_generation += 1,
        |r| r.expected_project_spec_sha256 = "a".repeat(64),
        |r| r.expected_access_profile_id = PROFILE_ID.into(),
        |r| r.expected_access_profile_revision = 1,
        |r| r.project_spec_sha256 = "b".repeat(64),
        |r| r.project_spec_json.push(b' '),
        |r| r.project_spec_json = vec![b'x'; codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1],
        |r| {
            edit_target(r, |p| {
                p.environment
                    .insert("NOT_A_SOURCE".into(), "synthetic-canary".into());
            })
        },
        |r| edit_target(r, |p| p.image = "alpine:3.21".into()),
        |r| edit_target(r, |p| p.resources.memory_mib = Some(1024)),
        |r| edit_target(r, |p| p.secrets.project = "unqualified-name".into()),
    ];
    for mutation in mutations {
        let mut changed = request.clone();
        mutation(&mut changed);
        assert!(SourceTransition::new(&changed, &environment).is_err());
    }
    for state in [
        StoredEnvironmentState::Starting,
        StoredEnvironmentState::Error,
        StoredEnvironmentState::Orphaned,
    ] {
        let mut unstable = environment.clone();
        unstable.state = state;
        assert!(SourceTransition::new(&request, &unstable).is_err());
    }
    let mut running = environment;
    running.state = StoredEnvironmentState::Running;
    assert!(SourceTransition::new(&request, &running).is_err());
    let mut confirmed = request;
    confirmed.allow_restart = true;
    assert!(
        SourceTransition::new(&confirmed, &running)
            .unwrap()
            .was_running
    );
}

#[test]
fn source_update_checks_profile_origin_revision_reference_and_platform_authority() {
    let environment = project_environment();
    let mut request = target_request(&environment);
    profile_target(&mut request, "local");
    let transition = SourceTransition::new(&request, &environment).unwrap();
    assert!(
        transition
            .target
            .local_binding(environment.id)
            .unwrap()
            .is_some()
    );
    let mut invalid = request.clone();
    invalid.access_profile_revision = 0;
    assert!(SourceTransition::new(&invalid, &environment).is_err());
    let mut invalid = request.clone();
    invalid.access_profile_reference = "organization/work".into();
    assert!(SourceTransition::new(&invalid, &environment).is_err());
    profile_target(&mut request, "platform");
    edit_target(&mut request, |project| project.secrets = Default::default());
    let transition = SourceTransition::new(&request, &environment).unwrap();
    assert!(transition.target.binding(environment.id).unwrap().is_some());
    assert!(
        transition
            .target
            .local_binding(environment.id)
            .unwrap()
            .is_none()
    );
    let mut selected = environment;
    transition.target.write_to(&mut selected).unwrap();
    assert_eq!(
        selected
            .platform_source_authority
            .as_ref()
            .unwrap()
            .profile_slots,
        BTreeSet::from(["codex".into(), "openai".into()])
    );
    let mut next = target_request(&selected);
    edit_target(&mut next, |project| project.credentials = None);
    SourceTransition::new(&next, &selected).unwrap();
    let mut invalid = next.clone();
    invalid
        .expected_platform_source_authority
        .as_mut()
        .unwrap()
        .user_id = "other-owner".into();
    assert!(SourceTransition::new(&invalid, &selected).is_err());
    let mut invalid = next.clone();
    invalid
        .expected_platform_source_authority
        .as_mut()
        .unwrap()
        .profile_slots = vec!["codex".into()];
    assert!(SourceTransition::new(&invalid, &selected).is_err());
    let mut invalid = next;
    invalid.expected_platform_source_authority = None;
    assert!(SourceTransition::new(&invalid, &selected).is_err());
    request.platform_source_authority = None;
    assert!(SourceTransition::new(&request, &project_environment()).is_err());
}

#[tokio::test]
async fn stopped_source_commit_is_atomic_preserves_built_identity_and_never_boots() {
    let mut environment = project_environment();
    environment.active_workspace_generation = Some(test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"source-update",
    ));
    let original = environment.clone();
    let mut request = target_request(&environment);
    profile_target(&mut request, "platform");
    edit_target(&mut request, |project| project.secrets = Default::default());
    let transition = SourceTransition::new(&request, &environment).unwrap();
    let (_parent, mut core) = test_supervisor_core(environment);
    // The authority effect has its own ACK tests below. Begin immediately
    // before the one SQLite state/checkpoint transaction, without material.
    let operation = begin_at(&core, &transition, 3);
    let finished = core.update_environment_sources(&operation).await.unwrap();
    assert_eq!(
        finished.checkpoint as usize,
        crate::lifecycle::effects(finished.kind).len()
    );
    let current = core.environment("dev").unwrap();
    assert_eq!(current.generation, original.generation + 1);
    assert!(SourceSelection::from_environment(current).unwrap() == transition.target);
    assert_eq!(current.state, StoredEnvironmentState::Stopped);
    assert!(current.runner.is_none());
    assert!(core.children.is_empty());
    assert_eq!(
        current.active_workspace_generation,
        original.active_workspace_generation
    );
    assert_eq!(
        current.rollback_workspace_generation,
        original.rollback_workspace_generation
    );
    assert_eq!(current.workspace_plan, original.workspace_plan);
    assert_eq!(
        current.active_artifact_generation,
        original.active_artifact_generation
    );
    let (_, stored) = SupervisorStore::inspect(&core.root).unwrap();
    assert_eq!(stored.environments["dev"], *current);
    let completed = core
        .complete_operation(&finished, &environment_operation_result(current))
        .unwrap();
    assert_eq!(
        completed.checkpoint as usize,
        crate::lifecycle::effects(completed.kind).len() + 1
    );
    assert_eq!(completed.checkpoint, 10);
    assert!(core.update_environment_sources(&operation).await.is_err());
    assert_eq!(core.environment("dev").unwrap().generation, 2);
    let safe = operation_proto(&completed).unwrap();
    assert!(!format!("{safe:?}").contains(PROFILE_ID));
    assert!(!format!("{safe:?}").contains("project_spec_json"));
}

#[tokio::test]
async fn source_clear_atomically_removes_both_profile_and_complete_secret_selection() {
    let mut environment = project_environment();
    let mut initial = target_request(&environment);
    profile_target(&mut initial, "local");
    SourceSelection::from_request(&initial)
        .unwrap()
        .write_to(&mut environment)
        .unwrap();
    let mut request = target_request(&environment);
    edit_target(&mut request, |project| {
        project.secrets = Default::default();
        project.credentials = None;
    });
    let transition = SourceTransition::new(&request, &environment).unwrap();
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = begin_at(&core, &transition, 3);
    core.update_environment_sources(&operation).await.unwrap();
    let current = core.environment("dev").unwrap();
    let selected = SourceSelection::from_environment(current).unwrap();
    assert!(selected.profile.is_none());
    assert!(selected.validate().unwrap().secrets.is_empty());
    assert!(current.access_profile.is_none());
    assert!(current.access_binding.is_none());
    assert_eq!(current.generation, 2);
}

#[tokio::test]
async fn source_replay_rejects_third_metadata_without_overwriting_or_advancing() {
    let environment = project_environment();
    let transition = SourceTransition::new(&target_request(&environment), &environment).unwrap();
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = begin_at(&core, &transition, 3);
    let mut third = target_request(core.environment("dev").unwrap());
    edit_target(&mut third, |project| {
        project.secrets.user = None;
        project.secrets.project = format!("local:id:{PROFILE_ID}");
    });
    SourceSelection::from_request(&third)
        .unwrap()
        .write_to(core.environment_mut("dev").unwrap())
        .unwrap();
    let before = core.environment("dev").unwrap().clone();
    core.save().unwrap();
    assert!(matches!(
        core.update_environment_sources(&operation).await,
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
    assert_eq!(*core.environment("dev").unwrap(), before);
    assert_eq!(
        core.store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap()
            .checkpoint,
        3
    );
}

#[tokio::test]
async fn source_request_replay_is_exact_after_completion_and_client_disconnect() {
    let environment = project_environment();
    let request = target_request(&environment);
    let (_parent, core) = test_supervisor_core(environment);
    let socket = core.config.supervisor_socket();
    let service = test_supervisor_service(core);
    let (identity, shutdown, server) = spawn_test_supervisor_server(&socket, service.clone());
    let mut client = NativeSupervisorClient::connect(&socket)
        .await
        .unwrap()
        .into_rpc_client_for_test();
    let submitted = client
        .update_environment_sources(request.clone())
        .await
        .unwrap()
        .into_inner();
    drop(client); // The submitting transport does not own the durable worker.
    let response = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: submitted.operation_id.clone(),
        }))
        .await
        .unwrap();
    let mut stream = response.into_inner();
    let terminal = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(update) = futures::StreamExt::next(&mut stream).await {
            let update = update.unwrap();
            if operation_terminal(&update).unwrap() {
                return update;
            }
        }
        panic!("operation watch ended before completion")
    })
    .await
    .unwrap();
    assert_eq!(terminal.phase, v1::OperationPhase::Completed as i32);
    let replay = service
        .admit_source_update(request.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay.operation_id, submitted.operation_id);
    assert_eq!(replay.checkpoint, 10);
    let mut changed = request;
    changed.allow_restart = true;
    assert_eq!(
        service
            .admit_source_update(changed)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert_eq!(
        service
            .core
            .lock()
            .await
            .environment("dev")
            .unwrap()
            .generation,
        2
    );
    drop(stream);
    shutdown.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &identity).unwrap();
}

#[tokio::test]
async fn running_source_admission_journals_mixed_delivery_before_stop() {
    for platform_profile in [false, true] {
        let mut environment = project_environment();
        environment.active_workspace_generation = Some(test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"source-admission",
        ));
        environment.state = StoredEnvironmentState::Running;
        let original = environment.clone();
        let mut request = target_request(&environment);
        request.allow_restart = true;
        if platform_profile {
            edit_target(&mut request, |project| {
                project.secrets = codewire_project::SecretBindings {
                    user: Some(StoragePlacement::Local),
                    ..Default::default()
                };
            });
            profile_target(&mut request, "platform");
        } else {
            edit_target(&mut request, |project| {
                project.secrets.user = Some(StoragePlacement::Platform);
                project.secrets.project = format!("local:id:{}", Uuid::new_v4());
            });
            request.platform_source_authority = Some(v1::PlatformSourceAuthority {
                anthropic_form: String::new(),
                server_url: "https://synthetic.invalid".into(),
                organization_id: "org".into(),
                user_id: "owner".into(),
                profile_slots: Vec::new(),
            });
        }
        let (_parent, core) = test_supervisor_core(environment);
        let service = test_supervisor_service(core);
        // Hold the worker at its existing admission boundary: this test proves
        // the durable selection, not a synthetic VM restart or platform login.
        service.worker_running.store(true, Ordering::Release);
        let target = SourceSelection::from_request(&request).unwrap();
        let admitted = service
            .admit_source_update(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(admitted.phase, v1::OperationPhase::Intent as i32);
        assert_eq!(admitted.checkpoint, 0);
        let core = service.core.lock().await;
        let pending = core.store.pending_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(
            SourceTransition::from_operation(&pending[0])
                .unwrap()
                .target
                == target
        );
        assert_eq!(pending[0].environment_id, Some(original.id));
        assert_eq!(core.environment("dev").unwrap(), &original);
    }
}

#[tokio::test]
async fn stopped_mixed_targets_require_local_profile_authority_and_can_be_cleared() {
    for scope in 0..3 {
        let environment = project_environment();
        let original = environment.clone();
        let mut request = target_request(&environment);
        profile_target(&mut request, "local");
        edit_target(&mut request, |project| {
            project.secrets = Default::default();
            match scope {
                0 => project.secrets.user = Some(StoragePlacement::Platform),
                1 => project.secrets.project = format!("platform:id:{}", Uuid::new_v4()),
                _ => project.secrets.organization = true,
            }
        });
        request.platform_source_authority = Some(v1::PlatformSourceAuthority {
            anthropic_form: String::new(),
            server_url: "https://synthetic.invalid".into(),
            organization_id: "org".into(),
            user_id: "owner".into(),
            profile_slots: Vec::new(),
        });
        let unavailable = SourceSelection::from_request(&request).unwrap();
        assert!(platform::requires_platform_authority(&unavailable.validate().unwrap()).unwrap());
        assert!(unavailable.local_binding(original.id).unwrap().is_some());
        let (_parent, core) = test_supervisor_core(environment);
        let service = test_supervisor_service(core);
        let error = service.admit_source_update(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        let core = service.core.lock().await;
        assert!(core.store.pending_operations().unwrap().is_empty());
        assert_eq!(core.environment("dev").unwrap(), &original);
        assert!(!core.config.credential_authority_root.exists());

        let mut existing = original;
        unavailable.write_to(&mut existing).unwrap();
        let mut clear = target_request(&existing);
        edit_target(&mut clear, |project| {
            project.secrets = Default::default();
            project.credentials = None;
        });
        let transition = SourceTransition::new(&clear, &existing).unwrap();
        assert!(transition.target.platform_source_authority.is_none());
        assert!(transition.target.profile.is_none());
    }
}

#[test]
fn running_source_feasibility_allows_local_application_selection_and_clear() {
    let mut environment = project_environment();
    environment.active_workspace_generation = Some(test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"source-clear",
    ));
    let selected = SourceSelection::from_request(&target_request(&environment)).unwrap();
    environment.state = StoredEnvironmentState::Running;
    let mut selecting = target_request(&environment);
    selecting.allow_restart = true;
    SourceTransition::new(&selecting, &environment)
        .unwrap()
        .validate_running_delivery(&environment)
        .unwrap();
    selected.write_to(&mut environment).unwrap();
    environment.state = StoredEnvironmentState::Running;
    let mut clear = target_request(&environment);
    clear.allow_restart = true;
    edit_target(&mut clear, |project| {
        project.secrets = Default::default();
        project.credentials = None;
    });
    SourceTransition::new(&clear, &environment)
        .unwrap()
        .validate_running_delivery(&environment)
        .unwrap();
    environment.state = StoredEnvironmentState::Stopped;
    let selected = SourceTransition::new(&target_request(&environment), &environment).unwrap();
    selected.validate_running_delivery(&environment).unwrap();
}

#[tokio::test]
async fn source_admission_rejects_stale_selection_before_journaling() {
    let environment = project_environment();
    let mut request = target_request(&environment);
    request.expected_generation += 1;
    let (_parent, core) = test_supervisor_core(environment);
    let service = test_supervisor_service(core);
    assert!(service.admit_source_update(request).await.is_err());
    assert!(
        service
            .core
            .lock()
            .await
            .store
            .pending_operations()
            .unwrap()
            .is_empty()
    );
}

#[derive(Default)]
struct FakeAuthority {
    writes: VecDeque<Result<(), Status>>,
    reads: VecDeque<Result<Option<EnvironmentAccessBinding>, Status>>,
    calls: Vec<(
        Option<EnvironmentAccessBinding>,
        Option<EnvironmentAccessBinding>,
    )>,
}

#[tonic::async_trait]
impl BindingAuthority for FakeAuthority {
    async fn apply(
        &mut self,
        _: &codewire_access::EnvironmentId,
        expected: Option<&EnvironmentAccessBinding>,
        target: Option<(&EnvironmentAccessBinding, &AccessProfileReference)>,
    ) -> Result<(), Status> {
        self.calls.push((
            expected.cloned(),
            target.map(|(binding, _)| binding.clone()),
        ));
        self.writes.pop_front().expect("unexpected write")
    }
    async fn read(
        &mut self,
        _: &codewire_access::EnvironmentId,
    ) -> Result<Option<EnvironmentAccessBinding>, Status> {
        self.reads.pop_front().expect("unexpected read")
    }
}

fn bindings() -> (
    EnvironmentAccessBinding,
    EnvironmentAccessBinding,
    AccessProfileReference,
) {
    let expected = EnvironmentAccessBinding {
        environment_id: access_environment_id(Uuid::new_v4()).unwrap(),
        profile_id: AccessProfileId::parse(PROFILE_ID).unwrap(),
        profile_revision: 1,
    };
    let mut target = expected.clone();
    target.profile_revision = 2;
    (expected, target, "user/work".parse().unwrap())
}

#[tokio::test]
async fn binding_unknown_ack_observes_target_or_retries_only_original_cas() {
    let (expected, target, reference) = bindings();
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::Unknown,
    ] {
        let mut authority = FakeAuthority {
            writes: [Err(Status::new(code, "synthetic-untrusted"))].into(),
            reads: [Ok(Some(target.clone()))].into(),
            ..Default::default()
        };
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference)),
        )
        .await
        .unwrap();
        assert_eq!(authority.calls.len(), 1);
        let mut authority = FakeAuthority {
            writes: [Err(Status::new(code, "synthetic-untrusted")), Ok(())].into(),
            reads: [Ok(Some(expected.clone()))].into(),
            ..Default::default()
        };
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference)),
        )
        .await
        .unwrap();
        assert_eq!(
            authority.calls,
            vec![(Some(expected.clone()), Some(target.clone())); 2]
        );
    }
}

#[tokio::test]
async fn binding_unknown_ack_does_not_fail_or_overwrite_unknown_or_third_state() {
    let (expected, target, reference) = bindings();
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::PermissionDenied,
        tonic::Code::Unknown,
    ] {
        let mut authority = FakeAuthority {
            writes: [Err(Status::unavailable("lost ACK"))].into(),
            reads: [Err(Status::new(code, "synthetic-untrusted"))].into(),
            ..Default::default()
        };
        assert!(matches!(
            publish_binding(
                &mut authority,
                &expected.environment_id,
                Some(&expected),
                Some((&target, &reference))
            )
            .await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        assert_eq!(authority.calls.len(), 1);
    }
    let mut third = target.clone();
    third.profile_revision = 3;
    let mut authority = FakeAuthority {
        writes: [Err(Status::unavailable("lost ACK"))].into(),
        reads: [Ok(Some(third))].into(),
        ..Default::default()
    };
    assert!(matches!(
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference))
        )
        .await,
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
    assert_eq!(authority.calls.len(), 1);
}

#[tokio::test]
async fn binding_replay_never_terminally_fails_an_earlier_unknown_publication() {
    let (expected, target, reference) = bindings();
    let mut authority = FakeAuthority {
        writes: [Err(Status::failed_precondition(
            "profile cannot currently be validated",
        ))]
        .into(),
        reads: [Ok(Some(target.clone()))].into(),
        ..Default::default()
    };
    assert!(matches!(
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference))
        )
        .await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    let mut authority = FakeAuthority {
        writes: [Err(Status::failed_precondition(
            "profile cannot currently be validated",
        ))]
        .into(),
        reads: [Ok(Some(expected.clone()))].into(),
        ..Default::default()
    };
    assert!(matches!(
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference))
        )
        .await,
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
}

#[tokio::test]
async fn binding_unknown_clear_ack_and_bounded_retry_never_adopt_new_expected_revision() {
    let (expected, target, reference) = bindings();
    let mut authority = FakeAuthority {
        writes: [Err(Status::unavailable("lost ACK"))].into(),
        reads: [Ok(None)].into(),
        ..Default::default()
    };
    publish_binding(
        &mut authority,
        &expected.environment_id,
        Some(&expected),
        None,
    )
    .await
    .unwrap();
    let mut authority = FakeAuthority {
        writes: [
            Err(Status::unavailable("lost ACK")),
            Err(Status::unknown("lost ACK")),
        ]
        .into(),
        reads: [Ok(Some(expected.clone())), Ok(Some(expected.clone()))].into(),
        ..Default::default()
    };
    assert!(matches!(
        publish_binding(
            &mut authority,
            &expected.environment_id,
            Some(&expected),
            Some((&target, &reference))
        )
        .await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    assert_eq!(
        authority.calls,
        vec![(Some(expected.clone()), Some(target)); 2]
    );
}

#[tokio::test]
async fn source_reboot_replay_keeps_exact_target_and_advances_generation_only_once_at_every_boundary()
 {
    for checkpoint in 0..=9 {
        let environment = project_environment();
        let request = target_request(&environment);
        let transition = SourceTransition::new(&request, &environment).unwrap();
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_at(&core, &transition, checkpoint);
        if checkpoint >= 4 {
            let environment = core.environment_mut("dev").unwrap();
            transition.target.write_to(environment).unwrap();
            environment.generation = transition.target_generation;
            core.save().unwrap();
        }
        let (store, state) =
            SupervisorStore::open_for_boot(&core.root, "synthetic-source-reboot").unwrap();
        core.store = store;
        core.state = state;
        let resumed = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.checkpoint, if checkpoint < 4 { 0 } else { 4 });
        core.execute_source_operation(&resumed).await.unwrap();
        let final_operation = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(final_operation.operation_id, operation.operation_id);
        assert_eq!(final_operation.phase, OperationPhase::Completed);
        assert_eq!(final_operation.checkpoint, 10);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.generation, 2);
        assert!(SourceSelection::from_environment(environment).unwrap() == transition.target);
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert!(environment.runner.is_none());
    }
}

#[tokio::test]
async fn running_source_reboot_after_start_cannot_publish_running_without_recreating_runtime() {
    for checkpoint in [7, 8, 9] {
        let mut environment = project_environment();
        environment.state = StoredEnvironmentState::Running;
        let mut request = target_request(&environment);
        request.allow_restart = true;
        let transition = SourceTransition::new(&request, &environment).unwrap();
        environment.state = StoredEnvironmentState::Stopped;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_at(&core, &transition, checkpoint);
        transition
            .target
            .write_to(core.environment_mut("dev").unwrap())
            .unwrap();
        core.environment_mut("dev").unwrap().generation = 2;
        core.save().unwrap();
        let (store, state) =
            SupervisorStore::open_for_boot(&core.root, "synthetic-source-reboot").unwrap();
        core.store = store;
        core.state = state;
        let resumed = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.checkpoint, 4);
        // No runtime is provisioned by this synthetic fixture. The restart
        // must reach real runner admission, not jump to RecordSourceOutcome.
        assert!(core.update_environment_sources(&resumed).await.is_err());
        let environment = core.environment("dev").unwrap();
        assert_ne!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.generation, 2);
        assert!(SourceSelection::from_environment(environment).unwrap() == transition.target);
        assert_eq!(
            core.store
                .operation_by_request(operation.request_id)
                .unwrap()
                .unwrap()
                .checkpoint,
            6
        );
    }
}

#[tokio::test]
async fn source_outcome_replay_cannot_claim_a_dead_same_boot_vm_is_running() {
    let mut environment = project_environment();
    environment.state = StoredEnvironmentState::Running;
    let mut request = target_request(&environment);
    request.allow_restart = true;
    let transition = SourceTransition::new(&request, &environment).unwrap();
    environment.state = StoredEnvironmentState::Starting;
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = begin_at(&core, &transition, 8);
    transition
        .target
        .write_to(core.environment_mut("dev").unwrap())
        .unwrap();
    core.environment_mut("dev").unwrap().generation = 2;
    core.save().unwrap();
    assert!(core.update_environment_sources(&operation).await.is_err());
    assert_ne!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Running
    );
    assert_eq!(
        core.store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap()
            .checkpoint,
        8
    );
}

#[tokio::test]
async fn source_worker_preserves_pending_intent_when_authority_is_unavailable() {
    for recovering in [false, true] {
        let environment = project_environment();
        let mut request = target_request(&environment);
        profile_target(&mut request, "local");
        let transition = SourceTransition::new(&request, &environment).unwrap();
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_at(&core, &transition, 2);
        assert!(matches!(
            core.run_pending_operations(recovering).await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 2);
        assert!(!pending.phase.terminal());
        assert!(
            SourceSelection::from_environment(core.environment("dev").unwrap()).unwrap()
                == transition.expected
        );
    }
}

#[tokio::test]
async fn failed_source_effect_records_and_logs_its_own_cause_without_secret_values() {
    // Application secret values never reach the supervisor; the values it
    // does hold for an environment, such as project environment values, and
    // any error text must not reach the recorded cause or the log either.
    const CANARY: &str = "synthetic-application-secret-value-must-not-escape";
    for (checkpoint, state, effect, expected) in [
        (
            6,
            StoredEnvironmentState::Stopped,
            "ensure_runner",
            "environment_sources_artifact_store",
        ),
        (
            8,
            StoredEnvironmentState::Starting,
            "record_source_outcome",
            "environment_sources_not_running",
        ),
    ] {
        let mut environment = project_environment();
        let mut project: ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project
            .environment
            .insert("APP_SETTING".into(), CANARY.into());
        let json = project.canonical_json().unwrap();
        let sha256 = format!("{:x}", Sha256::digest(&json));
        environment.active_workspace_generation =
            Some(test_workspace_generation(&json, &sha256, b"source-failure"));
        environment.project_spec_sha256 = Some(sha256);
        environment.project_spec_json = Some(json);
        environment.state = StoredEnvironmentState::Running;
        let mut request = target_request(&environment);
        request.allow_restart = true;
        // Keep the local credential authority out of this synthetic restart:
        // with it unavailable the journal stays pending, by design.
        edit_target(&mut request, |project| project.secrets = Default::default());
        let transition = SourceTransition::new(&request, &environment).unwrap();
        environment.state = state;
        let (_parent, mut core) = test_supervisor_core(environment);
        core.log = Some(
            DiagnosticLog::adopt(
                diagnostic_log::open_child_log(&core.root, diagnostic_log::SUPERVISOR_LOG).unwrap(),
            )
            .unwrap(),
        );
        let operation = begin_at(&core, &transition, checkpoint);
        transition
            .target
            .write_to(core.environment_mut("dev").unwrap())
            .unwrap();
        core.environment_mut("dev").unwrap().generation = 2;
        core.save().unwrap();

        // No runtime is provisioned, so the target start fails at `effect`.
        core.run_pending_operations(false).await.unwrap();

        // The journal row records the failing checkpoint and its cause.
        let failed = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(failed.phase, OperationPhase::Failed, "{effect}");
        assert_eq!(failed.checkpoint, checkpoint + 1);
        assert_eq!(
            supervisor_effect(failed.kind, checkpoint)
                .unwrap()
                .map(LifecycleEffect::name),
            Some(effect)
        );
        assert_eq!(failed.error_code.as_deref(), Some(expected));
        // `cw env info` shows it, and so does the failed `cw env update`.
        let shown = core.environment_proto("dev").unwrap();
        assert_eq!(shown.state, v1::EnvironmentState::Error as i32);
        assert_eq!(shown.error_code, expected);
        let failure = operation_outcome(operation_proto(&failed).unwrap()).unwrap_err();
        assert!(
            failure.message().contains(&format!("failed: {expected}")),
            "{}",
            failure.message()
        );
        // The supervisor log names the effect and the closed cause.
        let log = fs::read_to_string(
            core.root
                .path()
                .join(diagnostic_log::LOG_DIRECTORY)
                .join(diagnostic_log::SUPERVISOR_LOG),
        )
        .unwrap();
        let line = log
            .lines()
            .find(|line| line.contains(&operation.operation_id.to_string()))
            .unwrap_or_else(|| panic!("no failure line in {log:?}"));
        assert!(line.contains(" event=operation_failed "), "{line}");
        assert!(line.contains(" kind=update_environment_sources "), "{line}");
        assert!(line.contains(&format!(" effect={effect} ")), "{line}");
        assert!(
            line.contains(&format!(
                " cause={} ",
                expected.trim_start_matches("environment_sources_")
            )),
            "{line}"
        );
        assert!(line.ends_with(&format!(" error_code={expected}")), "{line}");

        let journal = core
            .store
            .recent_environment_operations(failed.environment_id.unwrap())
            .unwrap()
            .iter()
            .filter(|operation| operation.operation_id != failed.operation_id)
            .map(|operation| format!("{:?} {:?}", operation.error_code, operation.payload))
            .collect::<Vec<_>>()
            .join("\n");
        for text in [
            log.as_str(),
            expected,
            shown.error_code.as_str(),
            failure.message(),
            journal.as_str(),
        ] {
            assert!(!text.contains(CANARY), "{text}");
        }
    }
}
