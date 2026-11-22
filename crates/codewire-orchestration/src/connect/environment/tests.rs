use super::*;
use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

/// #3747: `org_id` passes through untouched, and asking for both is refused
/// before any read, so a mismatch can't pick one.
#[tokio::test]
async fn a_create_names_its_organization_one_way() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://synthetic@127.0.0.1:1/synthetic")
        .unwrap();
    let user = codewire_server_core::auth::AuthUser {
        user_id: "synthetic-user".into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    let by_id = proto::CreateEnvironmentRequest {
        org_id: "org-1".into(),
        ..Default::default()
    };
    assert_eq!(
        create_organization(&pool, &user, &by_id).await.unwrap(),
        "org-1"
    );
    let both = proto::CreateEnvironmentRequest {
        organization: Some("org-2".into()),
        ..by_id
    };
    let error = create_organization(&pool, &user, &both).await.unwrap_err();
    let rendered = ConnectError::from_app_error(&error, None);
    assert_eq!(rendered.code, ConnectCode::InvalidArgument);
}

#[test]
fn source_update_requires_both_complete_selections_and_preserves_fences() {
    assert!(source_update_body(proto::UpdateEnvironmentSourcesRequest::default()).is_err());
    let selection = EnvironmentSourceSelection {
        credentials: Some(codewire_project::CredentialBinding {
            profile: "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd".into(),
        }),
        profile_revision: Some(3),
        ..Default::default()
    };
    let body = source_update_body(proto::UpdateEnvironmentSourcesRequest {
        expected_operation_generation: 7,
        expected: Some(proto_source_selection(selection.clone())).into(),
        replacement: Some(proto::EnvironmentSourceSelection::default()).into(),
        confirm_personal_secrets: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(body.expected_operation_generation, 7);
    assert_eq!(body.expected, selection);
    assert_eq!(body.replacement, EnvironmentSourceSelection::default());
    assert!(
        body.confirm_personal_secrets && !body.confirm_personal_credentials && !body.allow_restart
    );
    let unknown = proto::EnvironmentSourceSelection {
        secrets: Some(proto::ProjectSecretBindings {
            user: Some(99.into()),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    assert!(source_selection(Some(unknown)).is_err());
}

#[test]
fn source_metadata_and_restart_outcomes_never_collapse_into_successful_start() {
    let mut environment = test_environment("stopped", true);
    environment
        .source_selection
        .as_mut()
        .unwrap()
        .secrets
        .organization = true;
    let wire = proto_environment(
        environment,
        NetworkPolicyFlags::default(),
        Default::default(),
    )
    .unwrap();
    assert_eq!(wire.operation_generation, 7);
    assert!(
        wire.source_selection
            .as_option()
            .unwrap()
            .secrets
            .as_option()
            .unwrap()
            .organization
    );
    let mut unavailable = test_environment("destroyed", true);
    unavailable.source_selection = None;
    assert!(
        proto_environment(
            unavailable,
            NetworkPolicyFlags::default(),
            Default::default()
        )
        .unwrap()
        .source_selection
        .is_unset()
    );
    for (outcome, expected) in [
        (
            EnvironmentSourcesUpdateOutcome::Unchanged,
            proto::EnvironmentSourcesUpdateOutcome::Unchanged,
        ),
        (
            EnvironmentSourcesUpdateOutcome::Stored,
            proto::EnvironmentSourcesUpdateOutcome::Stored,
        ),
        (
            EnvironmentSourcesUpdateOutcome::RestartRequired,
            proto::EnvironmentSourcesUpdateOutcome::RestartRequired,
        ),
    ] {
        let wire = proto_source_update(EnvironmentSourcesUpdate {
            environment_id: "environment".into(),
            operation_generation: 7,
            selection: Default::default(),
            outcome,
        });
        assert_eq!(wire.outcome.as_known(), Some(expected));
        assert_eq!(wire.operation_generation, 7);
        assert!(wire.selection.as_option().is_some());
    }
}

#[test]
fn create_round_trip_keeps_profile_revision_and_personal_confirmations_distinct() {
    let request = proto::CreateEnvironmentRequest {
        project_spec: Some(codewire_project_proto::to_proto(
            codewire_project::ProjectSpec::default(),
        ))
        .into(),
        expected_profile_revision: Some(3),
        confirm_personal_credentials: true,
        confirm_personal_secrets: false,
        omit_application_previews: true,
        ..Default::default()
    };
    let body = create_body(request).unwrap();
    assert_eq!(body.expected_profile_revision, Some(3));
    assert!(body.confirm_personal_credentials && !body.confirm_personal_secrets);
    assert!(body.omit_application_previews);
    let wire = proto_create_request(body, "organization");
    assert_eq!(wire.expected_profile_revision, Some(3));
    assert!(wire.confirm_personal_credentials && !wire.confirm_personal_secrets);
    assert!(wire.omit_application_previews);
}

#[test]
fn schema_states_round_trip_without_collapsing_unknown() {
    let states = [
        ("pending", proto::EnvironmentState::Pending),
        ("pending_build", proto::EnvironmentState::PendingBuild),
        ("building", proto::EnvironmentState::Building),
        ("build_failed", proto::EnvironmentState::BuildFailed),
        ("pulling_snapshot", proto::EnvironmentState::PullingSnapshot),
        ("creating", proto::EnvironmentState::Creating),
        ("starting", proto::EnvironmentState::Starting),
        ("running", proto::EnvironmentState::Running),
        ("stopping", proto::EnvironmentState::Stopping),
        ("stopped", proto::EnvironmentState::Stopped),
        ("archiving", proto::EnvironmentState::Archiving),
        ("archived", proto::EnvironmentState::Archived),
        ("restoring", proto::EnvironmentState::Restoring),
        ("resizing", proto::EnvironmentState::Resizing),
        ("destroying", proto::EnvironmentState::Destroying),
        ("destroyed", proto::EnvironmentState::Destroyed),
        ("error", proto::EnvironmentState::Error),
        ("unknown", proto::EnvironmentState::Unknown),
    ];

    for (stored, wire) in states {
        assert_eq!(proto_environment_state(stored).unwrap(), wire);
        assert_eq!(api_environment_state(wire.into()).unwrap(), stored);
    }
    assert_eq!(
        api_environment_state(proto::EnvironmentState::Unspecified.into()).unwrap(),
        ""
    );
}

#[test]
fn schema_desired_states_map_one_to_one() {
    for (stored, wire) in [
        ("started", proto::DesiredState::Started),
        ("stopped", proto::DesiredState::Stopped),
        ("destroyed", proto::DesiredState::Destroyed),
        ("archived", proto::DesiredState::Archived),
        ("resized", proto::DesiredState::Resized),
    ] {
        assert_eq!(proto_desired_state(stored).unwrap(), wire);
    }
}

#[test]
fn poll_interval_table_is_bounded_and_terminal_states_are_absent() {
    let mut environment = test_environment("pending", false);
    assert_eq!(poll_interval_seconds(&environment), Some(5));
    environment.state = "creating".into();
    assert_eq!(poll_interval_seconds(&environment), Some(3));
    environment.state = "running".into();
    assert_eq!(poll_interval_seconds(&environment), Some(2));
    environment.setup_complete = true;
    assert_eq!(poll_interval_seconds(&environment), None);

    for state in [
        "pending_build",
        "building",
        "build_failed",
        "pulling_snapshot",
        "starting",
        "stopping",
        "stopped",
        "archiving",
        "archived",
        "restoring",
        "resizing",
        "destroying",
        "destroyed",
        "error",
        "unknown",
    ] {
        environment.state = state.into();
        assert_eq!(poll_interval_seconds(&environment), None, "{state}");
    }
}

#[test]
fn pagination_and_ttl_validation_render_invalid_argument_details() {
    assert!(validate_pagination("").is_ok());
    let pagination = validate_pagination("future").unwrap_err();
    assert_eq!(
        ConnectError::from_app_error(&pagination, None).code,
        ConnectCode::InvalidArgument
    );

    let ttl = validate_additional_seconds(59).unwrap_err();
    let rendered = ConnectError::from_app_error(&ttl, None);
    assert_eq!(rendered.code, ConnectCode::InvalidArgument);
    let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
        panic!("expected BadRequest detail");
    };
    assert_eq!(detail.field_violations[0].field, "additional_seconds");
    assert!(validate_additional_seconds(60).is_ok());
    assert!(validate_additional_seconds(86_400).is_ok());
    assert!(validate_additional_seconds(86_401).is_err());
}

#[test]
fn start_outcomes_are_explicit() {
    assert_eq!(
        proto_start_outcome(StartOutcomeCore::Started),
        proto::StartOutcome::Started
    );
    assert_eq!(
        proto_start_outcome(StartOutcomeCore::Retried),
        proto::StartOutcome::Retried
    );
}

#[test]
fn daemon_state_mapping_preserves_every_contract_state() {
    use codewire_daemon_proto::daemon::v1::DaemonState as Internal;

    for (internal, public) in [
        (
            Internal::Unspecified,
            proto::EnvironmentDaemonState::Unspecified,
        ),
        (
            Internal::Unsupported,
            proto::EnvironmentDaemonState::Unsupported,
        ),
        (Internal::Starting, proto::EnvironmentDaemonState::Starting),
        (Internal::Ready, proto::EnvironmentDaemonState::Ready),
        (
            Internal::Unhealthy,
            proto::EnvironmentDaemonState::Unhealthy,
        ),
        (
            Internal::UpgradeRequired,
            proto::EnvironmentDaemonState::UpgradeRequired,
        ),
    ] {
        assert_eq!(proto_environment_daemon_state(internal), public);
    }
}

#[test]
fn access_timestamp_normalizes_postgres_text() {
    let timestamp = proto_postgres_timestamp("2026-07-18 12:34:56.123456").unwrap();
    assert_eq!(timestamp.nanos, 123_456_000);
}

#[test]
fn create_requires_and_round_trips_one_canonical_project_spec() {
    let error = create_body(proto::CreateEnvironmentRequest::default()).unwrap_err();
    assert!(matches!(
        error,
        AppError::Coded {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "project_spec_required",
            ..
        }
    ));

    let project_spec = codewire_project::parse_project_yaml(
        r#"
image: ghcr.io/example/workspace:1
repositories:
  - source: https://example.test/acme/repo.git
    destination: /workspace/repo
working_directory: /workspace/repo
environment: {RUST_LOG: info}
agents: {install: false, tools: [codex]}
ports: [{port: 8080, label: api, access: private}]
cpu: "2"
memory: "8Gi"
"#,
    )
    .unwrap()
    .spec;
    let body = create_body(proto::CreateEnvironmentRequest {
        org_id: "org_contract".into(),
        name: Some("canonical".into()),
        isolation_tier: proto::IsolationTier::Confidential.into(),
        project_spec: Some(codewire_project_proto::to_proto(project_spec.clone())).into(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(body.project_spec, project_spec);
    assert_eq!(body.isolation_tier, "confidential");

    let request = proto_create_request(body, "org_contract");
    let mapped = codewire_project_proto::from_proto(
        request
            .project_spec
            .into_option()
            .expect("project spec remains present"),
    )
    .unwrap();
    assert_eq!(mapped, project_spec);
}

#[test]
fn prepare_connect_stream_preserves_one_recorded_sequence() {
    let repo = "https://example.test/acme/repo";
    let events = [
        PrepareStreamEvent::Progress {
            phase: "repo_config".into(),
            message: "Checking saved configuration...".into(),
            total: None,
            repo: None,
        },
        PrepareStreamEvent::Progress {
            phase: "resolving".into(),
            message: "Resolving preset...".into(),
            total: None,
            repo: None,
        },
        PrepareStreamEvent::Complete(Box::new(PrepareResponse {
            draft: CreateEnvironmentBody {
                project_spec: codewire_project::parse_project_yaml(&format!(
                    "repositories: [{{source: {repo}}}]\n"
                ))
                .unwrap()
                .spec,
                ..Default::default()
            },
            resolved_preset: None,
            repo_config: None,
        })),
    ];
    let connect = events
        .iter()
        .cloned()
        .map(|event| proto_prepare_event(event, "org_contract").unwrap())
        .collect::<Vec<_>>();
    assert_eq!(connect.len(), events.len());

    use proto::watch_environment_create_response::Event;
    assert!(
        matches!(connect[0].event, Some(Event::Progress(ref event)) if
            event.phase == "repo_config" && event.message == "Checking saved configuration...")
    );
    assert!(
        matches!(connect[1].event, Some(Event::Progress(ref event)) if
            event.phase == "resolving" && event.message == "Resolving preset...")
    );
    assert!(
        matches!(connect[2].event, Some(Event::Complete(ref event)) if
            event.draft.org_id == "org_contract"
                && event.draft.project_spec.repositories[0].source == repo)
    );
}

#[test]
fn prepare_complete_maps_canonical_project_specs_at_every_boundary() {
    let draft_spec = codewire_project::parse_project_yaml(
        r#"
image: example.test/draft:latest
environment: {RUST_LOG: info}
agents: {install: true, tools: [codex]}
ports: [{port: 3000, label: web, access: public}]
"#,
    )
    .unwrap()
    .spec;
    let preset_spec = codewire_project::parse_project_yaml(
        "image: example.test/preset:latest\nmemory: \"4Gi\"\n",
    )
    .unwrap()
    .spec;
    let repo_spec = codewire_project::parse_project_yaml(
        "install_command: cargo build\nenvironment: {RUST_BACKTRACE: '1'}\n",
    )
    .unwrap()
    .spec;
    let complete = proto_prepare_complete(
        PrepareResponse {
            draft: CreateEnvironmentBody {
                name: Some("typed-draft".into()),
                isolation_tier: "confidential".into(),
                project_spec: draft_spec,
                ..Default::default()
            },
            resolved_preset: Some(crate::api::prepare::PresetWire {
                id: "preset_typed".into(),
                org_id: Some("org_contract".into()),
                name: "Typed".into(),
                slug: Some("typed".into()),
                language: Some("rust".into()),
                official: false,
                description: None,
                build_status: "ready".into(),
                build_error: None,
                default_ttl_seconds: Some(3_600),
                project_spec: preset_spec,
                created_at: "2026-07-18T12:34:56Z".into(),
            }),
            repo_config: Some(RepoConfig {
                id: "repo_config_typed".into(),
                org_id: "org_contract".into(),
                repo_url: "https://example.test/acme/typed".into(),
                project_spec: repo_spec,
                created_by: "usr_contract".into(),
                updated_at: "2026-07-18T12:34:56Z".into(),
            }),
        },
        "org_contract",
    )
    .unwrap();

    let json = serde_json::to_value(complete).unwrap();
    assert_eq!(json["draft"]["orgId"], "org_contract");
    assert_eq!(
        json["draft"]["isolationTier"],
        "ISOLATION_TIER_CONFIDENTIAL"
    );
    assert_eq!(
        json["draft"]["projectSpec"]["applicationPorts"][0]["port"],
        3000
    );
    assert_eq!(
        json["draft"]["projectSpec"]["environment"]["RUST_LOG"],
        "info"
    );
    assert!(json.get("detection").is_none());
    assert_eq!(json["resolvedPreset"]["id"], "preset_typed");
    assert_eq!(
        json["resolvedPreset"]["projectSpec"]["image"],
        "example.test/preset:latest"
    );
    assert_eq!(
        json["repoConfig"]["projectSpec"]["installCommand"],
        "cargo build"
    );
}

#[test]
fn log_events_map_metadata_timestamp_and_typed_heartbeat() {
    let log = proto_log_event(LogStreamEvent::Log(ApiEnvironmentLog {
        id: "log_1".into(),
        environment_id: "env_1".into(),
        phase: "setup".into(),
        status: "running".into(),
        message: "installing".into(),
        metadata: serde_json::value::RawValue::from_string(
            r#"{"step":2,"nested":{"ok":true}}"#.into(),
        )
        .ok(),
        created_at: "2026-07-18T21:00:00Z".into(),
    }))
    .unwrap();
    let json = serde_json::to_value(log).unwrap();
    assert_eq!(json["log"]["id"], "log_1");
    assert_eq!(json["log"]["metadata"]["step"], 2.0);
    assert_eq!(json["log"]["metadata"]["nested"]["ok"], true);
    assert_eq!(json["log"]["createdAt"], "2026-07-18T21:00:00Z");

    let sent_at = DateTime::parse_from_rfc3339("2026-07-18T21:00:15.123456Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let heartbeat = proto_log_event(LogStreamEvent::Heartbeat(sent_at)).unwrap();
    let json = serde_json::to_value(heartbeat).unwrap();
    assert_eq!(json["heartbeat"]["sentAt"], "2026-07-18T21:00:15.123456Z");

    let null_metadata = proto_environment_log(ApiEnvironmentLog {
        id: "log_null".into(),
        environment_id: "env_1".into(),
        phase: "setup".into(),
        status: "running".into(),
        message: String::new(),
        metadata: serde_json::value::RawValue::from_string("null".into()).ok(),
        created_at: "2026-07-18T21:00:00Z".into(),
    })
    .unwrap();
    assert!(null_metadata.metadata.is_unset());
}

#[test]
fn shutdown_deadline_round_trips_source_precision_through_environment_mapping() {
    for (value, expected_nanos) in [
        ("2026-09-17T00:43:17Z", 0),
        ("2026-09-17T00:43:17.753549Z", 753_549_000),
    ] {
        let source = chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .naive_utc();
        let mut environment = test_environment("running", true);
        environment.shutdown_at = crate::api::environments::shutdown_deadline_string(Some(source));
        let mapped = proto_environment(
            environment,
            NetworkPolicyFlags::default(),
            Default::default(),
        )
        .unwrap();
        let timestamp = mapped.shutdown_at.as_option().unwrap();
        assert_eq!(timestamp.seconds, source.and_utc().timestamp());
        assert_eq!(timestamp.nanos, expected_nanos);
        let json = serde_json::to_value(&mapped).unwrap();
        assert_eq!(json["shutdownAt"], value);
    }
    let absent = proto_environment(
        test_environment("running", true),
        NetworkPolicyFlags::default(),
        Default::default(),
    )
    .unwrap();
    assert!(absent.shutdown_at.as_option().is_none());
}

/// An environment says whether this server stops idle Sandboxes, so a
/// timeout a server with the switch off keeps is never read as enforced
/// (#3384).
#[test]
fn an_environment_says_whether_idle_stop_is_enforced() {
    use crate::worker::idle_stop::IdleStop;
    for (switch, enforced) in [(IdleStop::Off, false), (IdleStop::On, true)] {
        let wire = proto_environment(
            test_environment("running", true),
            NetworkPolicyFlags::default(),
            switch,
        )
        .unwrap();
        assert_eq!(wire.idle_stop_enforced, Some(enforced));
    }
}

#[test]
fn the_network_policy_shows_only_while_platform_policies_are_on() {
    let mut environment = test_environment("running", true);
    environment.network_policy = Some(crate::api::network_policies::EnvironmentPolicyView {
        reference: "hosted-default".into(),
        name: "hosted-default".into(),
        revision: 0,
        digest: codewire_egress_policy::HOSTED_DEFAULT_DIGEST.into(),
        enforcement: crate::api::network_policies::EnforcementView::NotEnforced,
    });
    let off = proto_environment(
        environment.clone(),
        NetworkPolicyFlags::default(),
        Default::default(),
    )
    .unwrap();
    assert!(off.network_policy.as_option().is_none());
    let on = proto_environment(
        environment,
        NetworkPolicyFlags { enabled: true },
        Default::default(),
    )
    .unwrap();
    let policy = on.network_policy.as_option().unwrap();
    assert_eq!(policy.reference, "hosted-default");
    assert_eq!(
        policy.enforcement.as_known(),
        Some(proto::NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED)
    );
}

fn test_environment(state: &str, setup_complete: bool) -> Environment {
    Environment {
        id: "env_1".into(),
        org_id: "org_1".into(),
        created_by: "usr_1".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        name: None,
        state: state.into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        error_reason: None,
        error_code: None,
        stop_reason: None,
        idle_stop_seconds: 0,
        recoverable: false,
        state_changed_at: "2026-07-18T12:34:56Z".into(),
        retry_count: 0,
        setup_phase: 0,
        setup_complete,
        operation_generation: 7,
        source_selection: Some(Default::default()),
        setup_error: None,
        ttl_seconds: None,
        shutdown_at: None,
        cpu_millicores: 2_000,
        memory_mb: 4_096,
        disk_gb: 10,
        total_running_seconds: 0,
        created_at: "2026-07-18T12:34:56Z".into(),
        started_at: None,
        stopped_at: None,
        destroyed_at: None,
        protected: false,
        deletion_requested_at: None,
        deletion_grace_until: None,
        preset_name: None,
        network: None,
        network_state: None,
        network_failure: None,
        ports: Vec::new(),
        network_policy: None,
    }
}
