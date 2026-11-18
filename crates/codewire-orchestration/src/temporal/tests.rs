use super::*;

/// A trigger whose every Temporal call fails without touching the network,
/// for tests that need an `ApiState` but never start a workflow.
pub(crate) async fn offline_trigger() -> TemporalTrigger {
    use temporalio_client::callback_based::CallbackBasedGrpcService;
    use temporalio_client::tonic::Status;

    let service = CallbackBasedGrpcService {
        // Connecting asks for the server's capabilities; "unknown method"
        // is how an older server says it has none, so the connect succeeds.
        callback: Arc::new(|_request| {
            Box::pin(async {
                Err(Status::unimplemented(
                    "unknown method: no Temporal in tests",
                ))
            })
        }),
    };
    let options = ConnectionOptions::new(url::Url::parse("http://temporal.invalid:7233").unwrap())
        .dns_load_balancing(None)
        .service_override(service)
        .build();
    let connection = Connection::connect(options).await.unwrap();
    TemporalTrigger {
        client: Client::new(
            connection,
            ClientOptions::new("default".to_string()).build(),
        )
        .unwrap(),
        task_queue: "offline".to_string(),
    }
}

#[test]
fn workflow_id_is_stable() {
    assert_eq!(environment_workflow_id("env-1"), "environment/env-1");
    assert_eq!(
        organization_deletion_workflow_id("org-1", 7),
        "organization-deletion/org-1/7"
    );
}

#[test]
fn organization_deletion_payload_matches_external_billing_contract() {
    let input = OrganizationDeletionWorkflowInput {
        operation_id: "op-1".into(),
        organization_id: "org-1".into(),
        generation: 7,
    };
    assert_eq!(
        serde_json::to_string(&input).unwrap(),
        r#"{"operation_id":"op-1","organization_id":"org-1","generation":7}"#
    );
    assert!(
        serde_json::from_str::<OrganizationDeletionWorkflowInput>(
            r#"{"operation_id":"op-1","org_id":"org-1","generation":7}"#
        )
        .is_err()
    );
}

#[test]
fn organization_billing_activity_uses_only_the_billing_queue() {
    let opts = organization_billing_activity_opts();
    assert_eq!(opts.task_queue.as_deref(), Some(BILLING_TASK_QUEUE));
    assert_eq!(opts.heartbeat_timeout, None);
    assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts(), 3);
}

#[test]
fn organization_deletion_failure_write_retries_until_durable() {
    let opts = organization_deletion_failure_opts();
    assert_eq!(opts.heartbeat_timeout, Some(Duration::from_secs(15)));
    assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts(), 0);
}

#[test]
fn account_deletion_phases_retry_until_done_and_billing_runs_on_its_queue() {
    let local = account_deletion_activity_opts();
    let billing = account_deletion_billing_activity_opts();
    for opts in [&local, &billing] {
        assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts(), 0);
    }
    assert_eq!(local.task_queue, None);
    assert_eq!(billing.task_queue.as_deref(), Some(BILLING_TASK_QUEUE));
}

#[test]
fn account_deletion_payload_matches_the_billing_contract() {
    let input = AccountDeletionWorkflowInput {
        operation_id: "account-deletion/abc".into(),
    };
    let json = serde_json::to_string(&input).unwrap();
    assert_eq!(json, r#"{"operation_id":"account-deletion/abc"}"#);
    assert!(
        serde_json::from_str::<AccountDeletionWorkflowInput>(
            r#"{"operation_id":"account-deletion/abc","user_id":"u"}"#
        )
        .is_err()
    );
}

#[test]
fn signal_payload_is_rust_native_and_rejects_go_aliases() {
    let json = r#"{"action":"create","environment_id":"env-1","requested_by":"usr-1"}"#;
    let cmd: EnvironmentCommand = serde_json::from_str(json).unwrap();
    assert_eq!(cmd.action, "create");
    assert_eq!(cmd.environment_id, "env-1");
    assert_eq!(cmd.requested_by, "usr-1");
    assert_eq!(serde_json::to_string(&cmd).unwrap(), json);
    assert!(
        serde_json::from_str::<EnvironmentCommand>(
            r#"{"Action":"create","EnvironmentID":"env-1","RequestedBy":"usr-1"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<EnvironmentCommand>(
            r#"{"action":"create","environment_id":"env-1"}"#
        )
        .is_err()
    );

    let empty: EnvironmentCommand =
        serde_json::from_str(r#"{"action":"","environment_id":"","requested_by":""}"#).unwrap();
    assert!(empty.action.is_empty());
}

#[test]
fn activity_payload_requires_positive_generation() {
    let cmd: EnvironmentActivityCommand = serde_json::from_str(
        r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#,
    )
    .unwrap();
    assert_eq!(cmd.operation_generation, 7);
    assert!(
        serde_json::from_str::<EnvironmentActivityCommand>(
            r#"{"environment_id":"env-1","requested_by":""}"#
        )
        .is_err()
    );
    let signal = EnvironmentCommand {
        action: "setup".into(),
        environment_id: "env-1".into(),
        requested_by: String::new(),
        ..Default::default()
    };
    assert!(EnvironmentActivityCommand::from_signal(&signal, 0).is_err());
}

/// #3630: the merged first create's input carries no generation, since
/// the activity claims it, and refuses unknown fields like every other
/// workflow payload; the command it builds keeps the claim's checks.
#[test]
fn claim_and_create_input_carries_no_authority() {
    let input: EnvironmentClaimAndCreateInput =
        serde_json::from_str(r#"{"environment_id":"env-1","requested_by":"alice"}"#).unwrap();
    assert_eq!(input.environment_id, "env-1");
    assert!(
        serde_json::from_str::<EnvironmentClaimAndCreateInput>(
            r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#
        )
        .is_err()
    );
    let cmd = EnvironmentActivityCommand::claimed(
        &input.environment_id,
        &input.requested_by,
        &input.trace_context,
        7,
    )
    .unwrap();
    assert_eq!(
        (
            cmd.environment_id.as_str(),
            cmd.requested_by.as_str(),
            cmd.operation_generation
        ),
        ("env-1", "alice", 7)
    );
    assert!(
        EnvironmentActivityCommand::claimed("env-1", "alice", &TraceContext::default(), 0).is_err()
    );
    assert!(
        EnvironmentActivityCommand::claimed(" ", "alice", &TraceContext::default(), 7).is_err()
    );
}

#[test]
fn final_workflow_activates_heartbeat_and_cancellation_completion() {
    let opts = environment_activity_opts();
    assert_eq!(
        opts.close_timeouts,
        temporalio_sdk::ActivityCloseTimeouts::StartToClose(Duration::from_secs(30 * 60))
    );
    assert_eq!(opts.heartbeat_timeout, Some(Duration::from_secs(15)));
    assert_eq!(
        opts.cancellation_type,
        ActivityCancellationType::WaitCancellationCompleted
    );
    assert_eq!(opts.retry_policy.as_ref().unwrap().maximum_attempts(), 3);
    assert!(known_environment_action("resize"));
    assert!(known_environment_action("restart_sources"));
    assert!(known_environment_action("retry_setup"));
}

#[test]
fn reconcile_outcome_is_directly_typed() {
    let json = serde_json::to_string(&ReconcileOutcome::Destroyed).unwrap();
    assert_eq!(
        serde_json::from_str::<ReconcileOutcome>(&json).unwrap(),
        ReconcileOutcome::Destroyed
    );
    assert_ne!(json, "null");
}

/// A create's trace context rides the signal through the Temporal data
/// converter into the claim and activity inputs, and a command sent while
/// trace export is off keeps its exact pre-tracing payload.
#[tokio::test]
async fn trace_context_rides_from_the_signal_into_activity_inputs() {
    use temporalio_common::data_converters::{
        ActivitySerializationContext, DataConverter, SerializationContextData,
        WorkflowSerializationContext,
    };

    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let converter = DataConverter::default();
    let signal = EnvironmentCommand {
        action: "create".into(),
        environment_id: "env-1".into(),
        requested_by: String::new(),
        trace_context: TraceContext {
            traceparent: Some(traceparent.into()),
            tracestate: Some("codewire=dev".into()),
        },
    };
    let payloads = converter
        .to_payloads(
            &SerializationContextData::Workflow(WorkflowSerializationContext::new()),
            &signal,
        )
        .await
        .unwrap();
    let received: EnvironmentCommand = converter
        .from_payloads(
            &SerializationContextData::Workflow(WorkflowSerializationContext::new()),
            payloads,
        )
        .await
        .unwrap();
    assert_eq!(received.trace_context, signal.trace_context);

    let claim = EnvironmentClaimInput {
        environment_id: received.environment_id.clone(),
        trace_context: received.trace_context.clone(),
    };
    let claim_payloads = converter
        .to_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            &claim,
        )
        .await
        .unwrap();
    let claim: EnvironmentClaimInput = converter
        .from_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            claim_payloads,
        )
        .await
        .unwrap();
    assert_eq!(
        claim.trace_context.traceparent.as_deref(),
        Some(traceparent)
    );

    let activity = EnvironmentActivityCommand::from_signal(&received, 7).unwrap();
    let activity_payloads = converter
        .to_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            &activity,
        )
        .await
        .unwrap();
    let activity: EnvironmentActivityCommand = converter
        .from_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            activity_payloads,
        )
        .await
        .unwrap();
    assert_eq!(activity.operation_generation, 7);
    assert_eq!(
        activity.trace_context.traceparent.as_deref(),
        Some(traceparent)
    );
    assert_eq!(
        activity.trace_context.tracestate.as_deref(),
        Some("codewire=dev")
    );

    let untraced = EnvironmentActivityCommand::from_signal(
        &EnvironmentCommand {
            action: "create".into(),
            environment_id: "env-1".into(),
            ..Default::default()
        },
        7,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&untraced).unwrap(),
        r#"{"environment_id":"env-1","requested_by":"","operation_generation":7}"#
    );
    assert!(
            serde_json::from_str::<EnvironmentActivityCommand>(
                r#"{"environment_id":"env-1","requested_by":"","operation_generation":7,"trace_context":{"traceparent":"x","authority":"y"}}"#
            )
            .is_err()
        );
}

#[test]
fn workflow_rejects_cross_environment_signals() {
    let mut expected = None;
    let first = EnvironmentCommand {
        action: "create".into(),
        environment_id: "env-1".into(),
        requested_by: String::new(),
        ..Default::default()
    };
    let other = EnvironmentCommand {
        action: "destroy".into(),
        environment_id: "env-2".into(),
        requested_by: String::new(),
        ..Default::default()
    };
    ensure_workflow_environment(&mut expected, &first).unwrap();
    assert!(ensure_workflow_environment(&mut expected, &other).is_err());
}

/// #3684: a history recorded before setup moved into the create activity
/// holds claim-and-create's bare generation. Through the SDK's converter
/// it still decodes, as "setup still to run", and the new outcome
/// round-trips.
#[tokio::test]
async fn a_recorded_bare_generation_still_runs_setup() {
    use temporalio_common::data_converters::{
        ActivitySerializationContext, DataConverter, SerializationContextData,
    };

    let converter = DataConverter::default();
    let recorded = converter
        .to_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            &7_i64,
        )
        .await
        .unwrap();
    let result: ClaimAndCreateResult = converter
        .from_payloads(
            &SerializationContextData::Activity(ActivitySerializationContext::new()),
            recorded,
        )
        .await
        .unwrap();
    assert_eq!(result, ClaimAndCreateResult::Generation(7));
    assert_eq!(
        (result.operation_generation(), result.setup_completed()),
        (7, false)
    );

    for setup_completed in [false, true] {
        let outcome = ClaimAndCreateResult::Outcome {
            operation_generation: 7,
            setup_completed,
        };
        let payloads = converter
            .to_payloads(
                &SerializationContextData::Activity(ActivitySerializationContext::new()),
                &outcome,
            )
            .await
            .unwrap();
        let decoded: ClaimAndCreateResult = converter
            .from_payloads(
                &SerializationContextData::Activity(ActivitySerializationContext::new()),
                payloads,
            )
            .await
            .unwrap();
        assert_eq!(decoded, outcome);
        assert_eq!(
            (decoded.operation_generation(), decoded.setup_completed()),
            (7, setup_completed)
        );
    }
}
