use super::connect_only::connect_content_type;
use super::*;
use std::collections::BTreeMap;

use codewire_proto::codewire::v1::{
    EnvironmentServiceClient, EnvironmentSessionServiceClient, ExecServiceClient, FileServiceClient,
};
use connectrpc::Protocol;
use connectrpc::client::{ClientConfig, Http2Connection};
use http::HeaderValue;
use prost::Message as _;

use crate::uds::{bind_owner_only_listener, owner_only_connector, remove_bound_socket};

#[test]
fn generated_environment_routes_have_one_explicit_local_semantic() {
    let descriptor =
        prost_types::FileDescriptorSet::decode(codewire_proto::FILE_DESCRIPTOR_SET).unwrap();
    let methods = descriptor
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some("codewire.v1"))
        .flat_map(|file| &file.service)
        .find(|service| service.name.as_deref() == Some("EnvironmentService"))
        .unwrap()
        .method
        .iter()
        .map(|method| method.name.as_deref().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let semantics = ENVIRONMENT_RPC_SEMANTICS
        .iter()
        .map(|entry| entry.spec.method().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(methods, semantics);
    assert_eq!(semantics.len(), ENVIRONMENT_RPC_SEMANTICS.len());
    assert_eq!(
        ENVIRONMENT_RPC_SEMANTICS
            .iter()
            .filter(|entry| entry.behavior == RpcBehavior::Local)
            .count(),
        13
    );
}

#[test]
fn implemented_public_messages_have_exhaustive_field_semantics() {
    let descriptor =
        prost_types::FileDescriptorSet::decode(codewire_proto::FILE_DESCRIPTOR_SET).unwrap();
    let messages = descriptor
        .file
        .iter()
        .flat_map(|file| {
            let package = file.package.as_deref().unwrap_or_default();
            file.message_type.iter().map(move |message| {
                (
                    format!("{package}.{}", message.name.as_deref().unwrap()),
                    message,
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let semantics = PUBLIC_MESSAGE_SEMANTICS
        .iter()
        .map(|message| (message.full_name, message))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(semantics.len(), PUBLIC_MESSAGE_SEMANTICS.len());

    for (full_name, expected) in &semantics {
        let descriptor = messages
            .get(*full_name)
            .unwrap_or_else(|| panic!("missing generated message descriptor for {full_name}"));
        let actual_fields = descriptor
            .field
            .iter()
            .map(|field| {
                (
                    field.number.unwrap(),
                    field.name.as_deref().unwrap().to_owned(),
                )
            })
            .collect::<BTreeSet<_>>();
        let expected_fields = expected
            .fields
            .iter()
            .map(|field| (field.number, field.name.to_owned()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_fields, expected_fields, "{full_name}");
        assert_eq!(expected_fields.len(), expected.fields.len(), "{full_name}");

        for field_semantics in expected
            .fields
            .iter()
            .filter(|field| field.behavior == FieldBehavior::Local)
        {
            let field = descriptor
                .field
                .iter()
                .find(|field| field.number == Some(field_semantics.number))
                .unwrap();
            if field.r#type == Some(prost_types::field_descriptor_proto::Type::Message as i32)
                && field
                    .type_name
                    .as_deref()
                    .is_some_and(|name| name.starts_with(".codewire.v1."))
            {
                let nested = field.type_name.as_deref().unwrap().trim_start_matches('.');
                assert!(
                    semantics.contains_key(nested),
                    "local field {full_name}.{} lacks nested semantics for {nested}",
                    field_semantics.name
                );
            }
        }
    }

    let environment_service = descriptor
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some("codewire.v1"))
        .flat_map(|file| &file.service)
        .find(|service| service.name.as_deref() == Some("EnvironmentService"))
        .unwrap();
    for rpc in ENVIRONMENT_RPC_SEMANTICS
        .iter()
        .filter(|rpc| rpc.behavior == RpcBehavior::Local)
    {
        let method = environment_service
            .method
            .iter()
            .find(|method| method.name.as_deref() == Some(rpc.spec.method()))
            .unwrap();
        for message in [method.input_type.as_deref(), method.output_type.as_deref()] {
            let full_name = message.unwrap().trim_start_matches('.');
            assert!(
                semantics.contains_key(full_name),
                "implemented RPC {} lacks field semantics for {full_name}",
                rpc.spec.method()
            );
        }
    }
}

#[test]
fn connect_content_type_policy_never_admits_grpc_or_grpc_web() {
    for allowed in [
        "application/connect+json",
        "application/connect+proto",
        "application/json; charset=utf-8",
        "application/proto",
    ] {
        assert!(connect_content_type(
            &HeaderValue::from_str(allowed).unwrap()
        ));
    }
    for rejected in [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc-web",
        "application/grpc-web+proto",
        "text/plain",
    ] {
        assert!(!connect_content_type(
            &HeaderValue::from_str(rejected).unwrap()
        ));
    }
}

#[test]
fn public_source_metadata_is_exact_and_never_projects_the_rest_of_project_configuration() {
    let mut environment = super::super::tests::project_environment();
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.environment.insert(
        "PRIVATE_CONFIGURATION".into(),
        "synthetic-configuration-sentinel".into(),
    );
    project.secrets.user = Some(codewire_project::StoragePlacement::Local);
    let json = project.canonical_json().unwrap();
    environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
    environment.project_spec_json = Some(json);
    let mut private = environment.proto(false);
    let public = public_environment(Uuid::new_v4(), &private).unwrap();
    assert_eq!(public.operation_generation, 1);
    assert_eq!(
        public.source_selection.secrets.user.unwrap().as_known(),
        Some(proto::ProjectStoragePlacement::Local)
    );
    assert!(!format!("{public:?}").contains("synthetic-configuration-sentinel"));
    private.project_spec_json.clear();
    private.project_spec_sha256.clear();
    assert!(public_source_selection(&private).unwrap().is_none());
}

#[test]
fn public_source_update_requires_complete_sets_and_exact_generation_without_defaults() {
    let environment = super::super::tests::project_environment().proto(false);
    let current = public_source_selection(&environment).unwrap().unwrap();
    let mut request = proto::UpdateEnvironmentSourcesRequest {
        expected_operation_generation: environment.generation,
        expected: Some(current.clone()).into(),
        replacement: Some(current).into(),
        ..Default::default()
    };
    assert!(native_source_replacement(&request, &environment).unwrap().2);
    request.replacement = None.into();
    assert!(native_source_replacement(&request, &environment).is_err());
    request.replacement = Some(proto::EnvironmentSourceSelection {
        secrets: Some(proto::ProjectSecretBindings {
            user: Some(proto::ProjectStoragePlacement::Local.into()),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    })
    .into();
    let (target, revision, unchanged) = native_source_replacement(&request, &environment).unwrap();
    assert!(!unchanged);
    assert!(revision.is_none());
    assert_eq!(
        target.secrets.user,
        Some(codewire_project::StoragePlacement::Local)
    );
    request.expected_operation_generation += 1;
    assert!(native_source_replacement(&request, &environment).is_err());
    request.expected_operation_generation = environment.generation;
    request.expected = request.replacement.clone();
    assert!(native_source_replacement(&request, &environment).is_err());
    let invalid = proto::EnvironmentSourceSelection {
        secrets: Some(proto::ProjectSecretBindings {
            user: Some(proto::ProjectStoragePlacement::Unspecified.into()),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    assert!(source_selection_model(invalid).is_err());
    let incomplete_profile = proto::EnvironmentSourceSelection {
        credentials: Some(proto::ProjectCredentialBinding {
            profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    assert!(source_selection_model(incomplete_profile).is_err());
}

#[test]
fn public_source_clear_is_complete_and_new_platform_authority_is_never_inferred() {
    let mut environment = super::super::tests::project_environment().proto(false);
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(&environment.project_spec_json).unwrap();
    project.secrets.user = Some(codewire_project::StoragePlacement::Local);
    environment.project_spec_json = project.canonical_json().unwrap();
    environment.project_spec_sha256 =
        format!("{:x}", Sha256::digest(&environment.project_spec_json));
    let request = proto::UpdateEnvironmentSourcesRequest {
        expected_operation_generation: environment.generation,
        expected: public_source_selection(&environment).unwrap().into(),
        replacement: Some(proto::EnvironmentSourceSelection::default()).into(),
        ..Default::default()
    };
    let (cleared, revision, unchanged) = native_source_replacement(&request, &environment).unwrap();
    assert!(cleared.secrets.is_empty());
    assert!(cleared.credentials.is_none());
    assert!(revision.is_none());
    assert!(!unchanged);
    project.secrets.user = Some(codewire_project::StoragePlacement::Platform);
    assert!(native_platform_source_authority(&project, &environment).is_err());
    let authority = v1::PlatformSourceAuthority {
        anthropic_form: String::new(),
        server_url: "https://synthetic.invalid".into(),
        organization_id: "org".into(),
        user_id: "owner".into(),
        profile_slots: Vec::new(),
    };
    environment.platform_source_authority = Some(authority.clone());
    assert_eq!(
        native_platform_source_authority(&project, &environment).unwrap(),
        Some(authority)
    );
    assert!(
        native_platform_source_authority(&cleared, &environment)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn real_public_uds_source_update_uses_the_durable_native_operation_and_complete_cas() {
    let (_parent, core) =
        super::super::tests::test_supervisor_core(super::super::tests::project_environment());
    let socket = core.config.supervisor_socket();
    let environment_id = core.environment("dev").unwrap().id.to_string();
    let service = super::super::tests::test_supervisor_service(core);
    let namespace = service.public_namespace_id().await.unwrap();
    let (identity, shutdown, server) =
        super::super::tests::spawn_test_supervisor_server(&socket, service.clone());
    let authority: http::Uri = "http://codewire-local-control".parse().unwrap();
    let transport = Http2Connection::connect_with_connector(
        owner_only_connector(&socket).unwrap(),
        authority.clone(),
    )
    .await
    .unwrap()
    .shared(32);
    let client = EnvironmentServiceClient::new(transport, ClientConfig::new(authority).proto());
    let mut request = proto::UpdateEnvironmentSourcesRequest {
        org_id: namespace.to_string(),
        environment_id: environment_id.clone(),
        expected_operation_generation: 1,
        expected: Some(proto::EnvironmentSourceSelection::default()).into(),
        replacement: Some(proto::EnvironmentSourceSelection {
            secrets: Some(proto::ProjectSecretBindings {
                user: Some(proto::ProjectStoragePlacement::Local.into()),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let denied = client
        .update_environment_sources(request.clone())
        .await
        .unwrap_err();
    assert_eq!(denied.code, connectrpc::ErrorCode::FailedPrecondition);
    assert!(
        service
            .supervisor
            .core()
            .store
            .pending_operations()
            .unwrap()
            .is_empty()
    );
    request.confirm_personal_secrets = true;
    // The update's answer ends the wait; the bound only turns a hang into
    // a failure. 3 s failed on a loaded CI slot (#3325).
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        client.update_environment_sources(request.clone()),
    )
    .await
    .expect("the confirmed update answered")
    .unwrap()
    .into_owned();
    assert_eq!(result.operation_generation, 2);
    assert_eq!(
        result.outcome.as_known(),
        Some(proto::EnvironmentSourcesUpdateOutcome::Stored)
    );
    assert_eq!(result.selection, request.replacement);
    let stale = client
        .update_environment_sources(request.clone())
        .await
        .unwrap_err();
    assert_eq!(stale.code, connectrpc::ErrorCode::FailedPrecondition);
    request.expected_operation_generation = 2;
    request.expected = request.replacement.clone();
    let unchanged = client
        .update_environment_sources(request)
        .await
        .unwrap()
        .into_owned();
    assert_eq!(unchanged.operation_generation, 2);
    assert_eq!(
        unchanged.outcome.as_known(),
        Some(proto::EnvironmentSourcesUpdateOutcome::Unchanged)
    );
    let current = client
        .get_environment(proto::GetEnvironmentRequest {
            org_id: namespace.to_string(),
            environment_id,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(current.environment.operation_generation, 2);
    assert_eq!(current.environment.source_selection, result.selection);
    assert_eq!(
        current.environment.state.as_known(),
        Some(proto::EnvironmentState::Stopped)
    );
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &identity).unwrap();
}

#[test]
fn daemon_status_projection_never_reflects_guest_controlled_text() {
    let sentinel = "guest-bearer-and-terminal-sentinel\u{1b}[31m";
    let capabilities = daemon_v1::GetCapabilitiesResponse {
        protocol_version: DAEMON_PROTOCOL_VERSION,
        minimum_protocol_version: DAEMON_MINIMUM_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: REQUIRED_LOCAL_DAEMON_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .chain([sentinel.to_owned()])
            .collect(),
        state: daemon_v1::DaemonState::Ready as i32,
        message: sentinel.to_owned(),
        default_shell: sentinel.to_owned(),
    };
    let health = daemon_v1::GetHealthResponse {
        state: daemon_v1::DaemonState::Ready as i32,
        message: sentinel.to_owned(),
        diagnostics: vec![daemon_v1::HealthDiagnostic {
            name: sentinel.to_owned(),
            healthy: false,
            message: sentinel.to_owned(),
        }],
    };

    let status = project_daemon_status(&capabilities, &health);
    assert_eq!(
        status.state.as_known(),
        Some(proto::EnvironmentDaemonState::Ready)
    );
    assert_eq!(status.capabilities, REQUIRED_LOCAL_DAEMON_CAPABILITIES);
    assert_eq!(status.message, "local environment daemon is ready");
    assert_eq!(status.diagnostics.len(), 1);
    assert_eq!(status.diagnostics[0].name, "daemon");
    assert!(status.diagnostics[0].healthy);
    assert!(!format!("{status:?}").contains(sentinel));

    for required in ["session_input.v1", "session_metadata.v1"] {
        let mut older = capabilities.clone();
        older.capabilities.retain(|value| value != required);
        let status = project_daemon_status(&older, &health);
        assert_eq!(
            status.state.as_known(),
            Some(proto::EnvironmentDaemonState::Unsupported),
            "missing {required} must not report the current session profile ready"
        );
        assert!(!status.diagnostics[0].healthy);
    }

    let mut incompatible = capabilities;
    incompatible.daemon_version = sentinel.to_owned();
    let status = project_daemon_status(&incompatible, &health);
    assert_eq!(
        status.state.as_known(),
        Some(proto::EnvironmentDaemonState::UpgradeRequired)
    );
    assert_eq!(status.daemon_version, env!("CARGO_PKG_VERSION"));
    assert!(!format!("{status:?}").contains(sentinel));
}

#[test]
fn public_resize_identity_and_resources_round_trip_through_the_durable_operation() {
    let environment = super::super::tests::project_environment();
    let private_environment = environment.proto(false);
    let namespace = Uuid::new_v4();
    let public_request_id = "codex-profile:secondary";
    let durable_request_id = deterministic_request_id(namespace, environment.id, public_request_id);
    assert_eq!(
        durable_request_id,
        deterministic_request_id(namespace, environment.id, public_request_id)
    );
    assert_ne!(
        durable_request_id,
        deterministic_request_id(namespace, environment.id, "codex-profile:primary")
    );
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: durable_request_id,
        environment_id: Some(environment.id),
        kind: OperationKind::Restart,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: serde_json::json!({
            "name": "dev",
            "vcpus": 3,
            "memory_mib": 24 * 1024,
            "disk_bytes": 24 * GIB,
            "was_running": false,
            "previous_vcpus": 2,
            "previous_memory_mib": 16 * 1024,
            "previous_disk_bytes": 20 * GIB,
            "public_request_id": public_request_id,
            "public_disruption_policy": "allow_restart",
        }),
        result: None,
        error_code: None,
        created_unix_ms: 1_000,
        updated_unix_ms: 2_000,
    };

    let public = public_resize_operation(&operation, &private_environment).unwrap();
    assert_eq!(public.environment_id, environment.id.to_string());
    assert_eq!(public.request_id, public_request_id);
    assert_eq!(public.previous_resources.cpu_millicores, 2_000);
    assert_eq!(public.previous_resources.memory_mb, 16 * 1024);
    assert_eq!(public.previous_resources.disk_gb, 20);
    assert_eq!(public.desired_resources.cpu_millicores, 3_000);
    assert_eq!(public.desired_resources.memory_mb, 24 * 1024);
    assert_eq!(public.desired_resources.disk_gb, 24);
    assert_eq!(
        public.state.as_known(),
        Some(proto::EnvironmentResizeOperationState::Pending)
    );
    assert_eq!(
        public.disruption_policy.as_known(),
        Some(proto::EnvironmentResizeDisruptionPolicy::AllowRestart)
    );
    assert_eq!(
        public.planned_mode.as_known(),
        Some(proto::EnvironmentResizeExecutionMode::ApplyOnStart)
    );
    assert!(private_resources(2_000, 16 * 1024, 1024).is_ok());
    let too_large = private_resources(2_000, 16 * 1024, 1025).unwrap_err();
    assert_eq!(too_large.code, connectrpc::ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn real_uds_connect_client_shares_the_owner_only_supervisor_endpoint() {
    let (parent, core) =
        super::super::tests::test_supervisor_core(super::super::tests::project_environment());
    let socket = core.config.supervisor_socket();
    let service = super::super::tests::test_supervisor_service(core);
    let namespace = service.public_namespace_id().await.unwrap();
    let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_service = service.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, supervisor_router(server_service))
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let authority: http::Uri = "http://codewire-local-control".parse().unwrap();
    let transport = Http2Connection::connect_with_connector(
        owner_only_connector(&socket).unwrap(),
        authority.clone(),
    )
    .await
    .unwrap()
    .shared(32);
    let client = EnvironmentServiceClient::new(
        transport.clone(),
        ClientConfig::new(authority.clone()).proto(),
    );
    let listed = client
        .list_environments(proto::ListEnvironmentsRequest::default())
        .await
        .unwrap()
        .into_owned();
    assert_eq!(listed.environments.len(), 1);
    let listed_environment = &listed.environments[0];
    assert_eq!(listed_environment.org_id, namespace.to_string());
    assert_eq!(listed_environment.name, "dev");
    assert_eq!(listed_environment.r#type, "local");
    assert_eq!(listed_environment.cpu_millicores, 2_000);
    assert_eq!(listed_environment.memory_mb, 16 * 1024);
    assert_eq!(listed_environment.disk_gb, 20);
    assert_eq!(
        listed_environment.state.as_known(),
        Some(proto::EnvironmentState::Stopped)
    );
    let environment_id = listed_environment.id.clone();

    let fetched = client
        .get_environment(proto::GetEnvironmentRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(fetched.environment.id, environment_id);
    assert_eq!(fetched.environment.org_id, namespace.to_string());

    let daemon_status = client
        .get_environment_daemon_status(proto::GetEnvironmentDaemonStatusRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned()
        .status
        .into_option()
        .unwrap();
    assert_eq!(
        daemon_status.state.as_known(),
        Some(proto::EnvironmentDaemonState::Starting)
    );
    assert_eq!(daemon_status.message, "local environment is stopped");
    assert!(daemon_status.pod_name.is_empty());

    let mut daemon_logs = client
        .stream_environment_daemon_logs(proto::StreamEnvironmentDaemonLogsRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let daemon_logs = daemon_logs
        .message::<proto::StreamEnvironmentDaemonLogsResponse>()
        .await
        .unwrap()
        .unwrap()
        .to_owned_message();
    // A stopped VM with no operations and no credential authority: each part
    // says why it has nothing, and no authority is started to ask.
    assert_eq!(
        String::from_utf8(daemon_logs.data).unwrap(),
        "# operations\n\
         no operations recorded\n\
         # guest daemon\n\
         guest daemon log unavailable: the VM is not running\n\
         # credential leases\n\
         credential leases unavailable: the credential authority is not running\n"
    );

    let repair_error = client
        .repair_environment_daemon(proto::RepairEnvironmentDaemonRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(repair_error.code, connectrpc::ErrorCode::FailedPrecondition);

    let plan = client
        .plan_environment_resize(proto::PlanEnvironmentResizeRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            cpu_millicores: 3_000,
            memory_mb: 16 * 1024,
            disk_gb: 20,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(
        plan.plan.execution_mode.as_known(),
        Some(proto::EnvironmentResizeExecutionMode::ApplyOnStart)
    );

    let stopped = client
        .stop_environment(proto::StopEnvironmentRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(stopped.status, "stop requested");

    let create_error = client
        .create_environment(proto::CreateEnvironmentRequest::default())
        .await
        .unwrap_err();
    assert_eq!(create_error.code, connectrpc::ErrorCode::Unimplemented);

    let sessions = EnvironmentSessionServiceClient::new(
        transport.clone(),
        ClientConfig::new(authority.clone()).proto(),
    );
    let stopped_error = sessions
        .list_sessions(proto::ListSessionsRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        stopped_error.code,
        connectrpc::ErrorCode::FailedPrecondition
    );
    assert_eq!(
        stopped_error.message.as_deref(),
        Some("local environment is not in the required state")
    );

    let exec = ExecServiceClient::new(
        transport.clone(),
        ClientConfig::new(authority.clone()).proto(),
    );
    let stopped_error = exec
        .exec(proto::ExecRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            command: vec!["true".to_owned()],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        stopped_error.code,
        connectrpc::ErrorCode::FailedPrecondition
    );
    assert_eq!(
        stopped_error.message.as_deref(),
        Some("local environment is not in the required state")
    );

    let files = FileServiceClient::new(transport, ClientConfig::new(authority.clone()).proto());
    let stopped_error = files
        .list_files(proto::ListFilesRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            path: "/workspace".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        stopped_error.code,
        connectrpc::ErrorCode::FailedPrecondition
    );
    assert_eq!(
        stopped_error.message.as_deref(),
        Some("local environment is not in the required state")
    );
    // StatFile is served by the same file service and refused the same way.
    let stopped_error = files
        .stat_file(proto::StatFileRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            path: "/workspace/f.txt".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        stopped_error.code,
        connectrpc::ErrorCode::FailedPrecondition
    );
    assert_eq!(
        stopped_error.message.as_deref(),
        Some("local environment is not in the required state")
    );
    // WriteFiles reads a request of 16 MiB of content on this route: one at
    // the limit reaches the same state check, and one byte more is refused by
    // the bridge's rule rather than the transport.
    let write = |sizes: &[usize]| proto::WriteFilesRequest {
        org_id: namespace.to_string(),
        environment_id: environment_id.clone(),
        files: sizes
            .iter()
            .enumerate()
            .map(|(index, &size)| proto::WriteFile {
                path: format!("/workspace/{index}.bin"),
                content: vec![7; size],
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let half = codewire_daemon_bridge::file::WRITE_FILES_MAX_CONTENT_BYTES / 2;
    let stopped_error = files.write_files(write(&[half, half])).await.unwrap_err();
    assert_eq!(
        stopped_error.code,
        connectrpc::ErrorCode::FailedPrecondition
    );
    assert_eq!(
        stopped_error.message.as_deref(),
        Some("local environment is not in the required state")
    );
    let over = files
        .write_files(write(&[half, half + 1]))
        .await
        .unwrap_err();
    assert_eq!(over.code, connectrpc::ErrorCode::InvalidArgument);
    assert_eq!(
        over.message.as_deref(),
        Some("local file request is invalid: /files")
    );

    drop(client);
    let grpc_transport = Http2Connection::connect_with_connector(
        owner_only_connector(&socket).unwrap(),
        authority.clone(),
    )
    .await
    .unwrap()
    .shared(32);
    let grpc_client = EnvironmentServiceClient::new(
        grpc_transport,
        ClientConfig::new(authority)
            .with_protocol(Protocol::Grpc)
            .proto(),
    );
    assert!(
        grpc_client
            .list_environments(proto::ListEnvironmentsRequest::default())
            .await
            .is_err()
    );

    drop(grpc_client);
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
    drop(parent);
}

#[tokio::test]
async fn the_desktop_service_is_served_on_the_owner_only_socket_and_scoped_before_any_daemon() {
    let (parent, core) =
        super::super::tests::test_supervisor_core(super::super::tests::project_environment());
    let socket = core.config.supervisor_socket();
    let service = super::super::tests::test_supervisor_service(core);
    let namespace = service.public_namespace_id().await.unwrap();
    let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_service = service.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, supervisor_router(server_service))
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let authority: http::Uri = "http://codewire-local-control".parse().unwrap();
    let transport = Http2Connection::connect_with_connector(
        owner_only_connector(&socket).unwrap(),
        authority.clone(),
    )
    .await
    .unwrap()
    .shared(32);
    let desktop = proto::EnvironmentDesktopServiceClient::new(
        transport.clone(),
        ClientConfig::new(authority.clone()).proto(),
    );

    // A VM that does not exist, and another namespace's coordinates, are
    // refused on each call before any guest daemon is looked for.
    let unknown = Uuid::new_v4().to_string();
    let foreign = Uuid::new_v4().to_string();
    for (org_id, environment_id, code) in [
        (
            namespace.to_string(),
            unknown.clone(),
            connectrpc::ErrorCode::NotFound,
        ),
        (foreign, unknown, connectrpc::ErrorCode::NotFound),
    ] {
        let read = desktop
            .get_desktop(proto::GetDesktopRequest {
                org_id: org_id.clone(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .expect_err("GetDesktop is scoped");
        assert_eq!(read.code, code, "{read:?}");
        let started = desktop
            .start_desktop(proto::StartDesktopRequest {
                org_id: org_id.clone(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .expect_err("StartDesktop is scoped");
        assert_eq!(started.code, code, "{started:?}");
        let stopped = desktop
            .stop_desktop(proto::StopDesktopRequest {
                org_id,
                environment_id,
                ..Default::default()
            })
            .await
            .expect_err("StopDesktop is scoped");
        assert_eq!(stopped.code, code, "{stopped:?}");
    }

    // The route is Connect only, as the other public routes are.
    let grpc = proto::EnvironmentDesktopServiceClient::new(
        transport,
        ClientConfig::new(authority)
            .proto()
            .with_protocol(Protocol::Grpc),
    );
    assert!(
        grpc.get_desktop(proto::GetDesktopRequest::default())
            .await
            .is_err()
    );

    drop(grpc);
    drop(desktop);
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
    drop(parent);
}
