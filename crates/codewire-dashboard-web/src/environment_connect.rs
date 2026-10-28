use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::{
    console::v1::{
        BillingServiceClient, EnvironmentSetupServiceClient, GetBillingOverviewRequest,
        GetEnvironmentCreateOptionsRequest, ListResourcePlansRequest,
    },
    v1::{
        CreateEnvironmentRequest, CreatePortRequest, DeleteEnvironmentRequest, DeletePortRequest,
        Environment, EnvironmentResizeExecutionMode, EnvironmentResizeOperation,
        EnvironmentResizeOperationState, EnvironmentResizePlan, EnvironmentResources,
        EnvironmentServiceClient, EnvironmentSourcesUpdateOutcome, EnvironmentState,
        GetEnvironmentRequest, GetEnvironmentResizeOperationRequest,
        GetEnvironmentTrustReportRequest, ListEnvironmentsRequest, ListPortsRequest,
        PlanEnvironmentResizeRequest, Port, PortAccess, PortServiceClient,
        ResizeEnvironmentRequest, StartEnvironmentRequest, StopEnvironmentRequest,
        StreamLogsRequest, StreamLogsResponse, UpdateEnvironmentSourcesRequest,
    },
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    state::AppState,
    transport::BrowserTransport,
    view::{
        EnvironmentAgentView, EnvironmentPortRow, EnvironmentPresetOption,
        EnvironmentResizeConfirmationView, EnvironmentResizeOperationView, EnvironmentRow,
        EnvironmentTrustSummaryView,
    },
};

const UNARY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct EnvironmentCreateOptions {
    pub(crate) presets: Vec<EnvironmentPresetOption>,
    pub(crate) preview_base_domain: String,
    pub(crate) agents: Vec<EnvironmentAgentView>,
    pub(crate) confidential_available: bool,
    pub(crate) confidential_price: String,
    pub(crate) sources: crate::view::EnvironmentSourceFieldsView,
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn client_config(state: &AppState, timeout: Duration) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone()).with_default_timeout(timeout)
}

fn environment_client(
    state: &AppState,
    cookie: HeaderValue,
) -> EnvironmentServiceClient<BrowserTransport> {
    EnvironmentServiceClient::new(
        transport(state, cookie),
        client_config(state, UNARY_TIMEOUT),
    )
}

/// Reads one environment's log rows (`StreamLogs`) into a channel, with the
/// viewer's own session, so orchestration applies its usual environment
/// access check. The reader owns the stream's lifetime: dropping the receiver
/// ends the call. A `follow` read keeps going until orchestration ends it.
pub(crate) fn environment_log_events(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
    after_log_id: &str,
    follow: bool,
) -> tokio::sync::mpsc::Receiver<Result<StreamLogsResponse, ConnectError>> {
    let (events, receiver) = tokio::sync::mpsc::channel(16);
    let client = EnvironmentServiceClient::new(
        BrowserTransport {
            http: state.stream_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone()),
    );
    let request = StreamLogsRequest {
        org_id: org_id.to_owned(),
        environment_id: environment_id.to_owned(),
        follow,
        after_log_id: after_log_id.to_owned(),
        ..Default::default()
    };
    tokio::spawn(async move {
        let mut stream = match client.stream_logs(request).await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = events.send(Err(error)).await;
                return;
            }
        };
        loop {
            // Stop as soon as the reader goes away, so orchestration releases
            // this account's live-follow slot without waiting for a heartbeat.
            let message = tokio::select! {
                () = events.closed() => return,
                message = stream.message::<StreamLogsResponse>() => message,
            };
            let message = match message {
                Ok(Some(message)) => Ok(message.to_owned_message()),
                Ok(None) => return,
                Err(error) => Err(error),
            };
            let failed = message.is_err();
            if events.send(message).await.is_err() || failed {
                return;
            }
        }
    });
    receiver
}

fn billing_client(state: &AppState, cookie: HeaderValue) -> BillingServiceClient<BrowserTransport> {
    BillingServiceClient::new(
        transport(state, cookie),
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(UNARY_TIMEOUT),
    )
}

fn port_client(state: &AppState, cookie: HeaderValue) -> PortServiceClient<BrowserTransport> {
    PortServiceClient::new(
        transport(state, cookie),
        client_config(state, UNARY_TIMEOUT),
    )
}

pub(crate) async fn environments(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    include_destroyed: bool,
) -> Result<Vec<EnvironmentRow>, ConnectError> {
    let response = environment_client(state, cookie)
        .list_environments(ListEnvironmentsRequest {
            org_id: org_id.to_owned(),
            include_destroyed,
            page_size: 100,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response
        .environments
        .into_iter()
        .map(environment_row)
        .collect())
}

/// The Sandbox inventory. Orchestration's default list leaves out Sandboxes
/// being deleted, so those are asked for by state: a deleted Sandbox stays in
/// its place, shown as Deleting, until it is gone. Destroyed Sandboxes are
/// listed only on request, and that list already includes deleting ones.
pub(crate) async fn inventory(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    include_destroyed: bool,
) -> Result<Vec<EnvironmentRow>, ConnectError> {
    if include_destroyed {
        return environments(state, cookie, org_id, true).await;
    }
    let list = |request: ListEnvironmentsRequest| {
        let client = environment_client(state, cookie.clone());
        async move {
            client
                .list_environments(request)
                .await
                .map(|response| response.into_owned().environments)
        }
    };
    let (listed, deleting) = tokio::try_join!(
        list(ListEnvironmentsRequest {
            org_id: org_id.to_owned(),
            page_size: 100,
            ..Default::default()
        }),
        list(ListEnvironmentsRequest {
            org_id: org_id.to_owned(),
            state: EnvironmentState::Destroying.into(),
            page_size: 100,
            ..Default::default()
        }),
    )?;
    Ok(merge_inventory(listed, deleting)
        .into_iter()
        .map(environment_row)
        .collect())
}

/// Newest first, as orchestration lists them. A Sandbox in both lists changed
/// state between the two reads; its deleting copy is kept, and the next
/// refresh shows whatever followed.
fn merge_inventory(listed: Vec<Environment>, deleting: Vec<Environment>) -> Vec<Environment> {
    let deleting_ids: std::collections::HashSet<String> = deleting
        .iter()
        .map(|environment| environment.id.clone())
        .collect();
    let mut merged: Vec<Environment> = listed
        .into_iter()
        .filter(|environment| !deleting_ids.contains(&environment.id))
        .chain(deleting)
        .collect();
    merged.sort_by_key(|environment| {
        std::cmp::Reverse(
            environment
                .created_at
                .as_option()
                .map(|created| (created.seconds, created.nanos)),
        )
    });
    merged
}

pub(crate) async fn environment(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
) -> Result<EnvironmentRow, ConnectError> {
    environment_data(state, cookie, org_id, environment_id)
        .await
        .map(environment_row)
}

pub(crate) async fn environment_data(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
) -> Result<Environment, ConnectError> {
    let response = environment_client(state, cookie)
        .get_environment(GetEnvironmentRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    response
        .environment
        .into_option()
        .ok_or_else(|| ConnectError::not_found("environment not found"))
}

pub(crate) async fn environment_trust_summary(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
    environment_name: String,
) -> Result<EnvironmentTrustSummaryView, ConnectError> {
    let report = environment_client(state, cookie)
        .get_environment_trust_report(GetEnvironmentTrustReportRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned()
        .trust_report
        .into_option()
        .ok_or_else(|| ConnectError::not_found("environment trust report not found"))?;
    let attestation = report.attestation.into_option().unwrap_or_default();
    let summary = report.summary.into_option().unwrap_or_default();
    Ok(EnvironmentTrustSummaryView {
        environment_name,
        trust_level: summary.trust_level,
        production_verified: summary.production_verified,
        attestation_status: attestation.status,
        tee: attestation.tee,
        warnings: summary.warnings,
    })
}

pub(crate) async fn create_options(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<EnvironmentCreateOptions, ConnectError> {
    let setup_client = EnvironmentSetupServiceClient::new(
        transport(state, cookie.clone()),
        client_config(state, UNARY_TIMEOUT),
    );
    let overview_client = billing_client(state, cookie.clone());
    let plans_client = billing_client(state, cookie.clone());
    // Presets, billing and sources are independent reads; waiting on each in
    // turn only adds round trips before the choices appear.
    let (setup, overview, plans, sources) = tokio::join!(
        setup_client.get_environment_create_options(GetEnvironmentCreateOptionsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        overview_client.get_billing_overview(GetBillingOverviewRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        plans_client.list_resource_plans(ListResourcePlansRequest {
            resource_type: "confidential_sandbox".to_owned(),
            ..Default::default()
        }),
        crate::environment_sources::options(state, cookie, org_id),
    );
    let setup = setup?.into_owned();

    // The catalog is public to organization members.  Failure to read it does
    // not block the create form; the server still performs authoritative,
    // atomic admission when a confidential environment is submitted.
    let (confidential_available, confidential_price) = match (overview, plans) {
        (Ok(overview), Ok(plans)) => {
            let plan_key = overview.into_owned().plan;
            let plans = plans.into_owned().plans;
            plans
                .get(&plan_key)
                .map(|plan| {
                    let available = plan.max_concurrent_ws != 0
                        && plan.cpu_overage_millicents > 0
                        && plan.mem_overage_millicents > 0;
                    let price = available.then(|| {
                        format!(
                            "${:.4} / CPU-hour + ${:.4} / GiB-hour",
                            plan.cpu_overage_millicents as f64 / 100_000.0,
                            plan.mem_overage_millicents as f64 / 100_000.0,
                        )
                    });
                    (available, price.unwrap_or_default())
                })
                .unwrap_or_default()
        }
        _ => (false, String::new()),
    };

    let presets = setup
        .presets
        .into_iter()
        .map(|preset| {
            let project_spec = preset.project_spec.into_option().ok_or_else(|| {
                ConnectError::internal("preset omitted its canonical project spec")
            })?;
            let project_spec =
                codewire_project_proto::from_proto(project_spec).map_err(|error| {
                    ConnectError::internal(format!(
                        "preset has an invalid canonical project spec: {error}"
                    ))
                })?;
            let uses_protected_secret_bindings =
                project_spec_uses_protected_secret_bindings(&project_spec);
            Ok(EnvironmentPresetOption {
                id: preset.id,
                name: preset.name,
                description: preset.description.unwrap_or_default(),
                image: project_spec.image,
                default_cpu_millicores: project_spec.resources.cpu_millicores,
                default_memory_mib: project_spec.resources.memory_mib,
                default_disk_gib: project_spec.resources.disk_gib,
                default_ttl_seconds: preset.default_ttl_seconds,
                default_install_command: project_spec.install_command,
                default_startup_script: project_spec.startup_script,
                default_agents: project_spec.agents.tools,
                default_app_ports: project_spec
                    .application_ports
                    .into_iter()
                    .enumerate()
                    .map(|(index, port)| crate::view::EnvironmentAppPortFormRow {
                        index,
                        port: port.port.to_string(),
                        label: port.label,
                        access: port.access,
                        ..Default::default()
                    })
                    .collect(),
                uses_protected_secret_bindings,
                official: preset.official,
            })
        })
        .collect::<Result<Vec<_>, ConnectError>>()?;

    Ok(EnvironmentCreateOptions {
        presets,
        preview_base_domain: validated_preview_domain(&setup.preview_base_domain),
        agents: agent_catalog(),
        confidential_available,
        confidential_price,
        sources,
    })
}

fn validated_preview_domain(domain: &str) -> String {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || !url::Url::parse(&format!("https://preview.{domain}"))
            .is_ok_and(|url| matches!(url.host(), Some(url::Host::Domain(_))))
    {
        String::new()
    } else {
        domain.to_ascii_lowercase()
    }
}

fn project_spec_uses_protected_secret_bindings(spec: &codewire_project::ProjectSpec) -> bool {
    !spec.secrets.is_empty() || spec.credentials.is_some()
}

pub(crate) async fn create_environment(
    state: &AppState,
    cookie: HeaderValue,
    request: CreateEnvironmentRequest,
) -> Result<String, ConnectError> {
    let expected_org = request.org_id.clone();
    let expected_selection =
        crate::environment_source_forms::create_selection(&request).map_err(|()| {
            ConnectError::invalid_argument(crate::environment_source_forms::INVALID_SELECTION)
        })?;
    let response = environment_client(state, cookie)
        .create_environment(request)
        .await?
        .into_owned();
    let environment = response
        .environment
        .into_option()
        .ok_or_else(|| ConnectError::internal("environment creation omitted its environment"))?;
    verify_created_selection(&environment, &expected_org, &expected_selection)?;
    Ok(environment.id)
}

fn verify_created_selection(
    environment: &Environment,
    org_id: &str,
    selection: &codewire_proto::codewire::v1::EnvironmentSourceSelection,
) -> Result<(), ConnectError> {
    if crate::environment_source_forms::exact_id(&environment.id).is_err()
        || environment.org_id != org_id
        || environment.operation_generation != 0
        || !same_selection(environment.source_selection.as_option(), Some(selection))
    {
        return Err(ConnectError::internal(
            "environment creation omitted its exact source selection",
        ));
    }
    Ok(())
}

fn same_selection(
    actual: Option<&codewire_proto::codewire::v1::EnvironmentSourceSelection>,
    expected: Option<&codewire_proto::codewire::v1::EnvironmentSourceSelection>,
) -> bool {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            actual.secrets.as_option().cloned().unwrap_or_default()
                == expected.secrets.as_option().cloned().unwrap_or_default()
                && actual.credentials == expected.credentials
                && actual.profile_revision == expected.profile_revision
        }
        _ => false,
    }
}

pub(crate) async fn start_environment(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
) -> Result<(), ConnectError> {
    environment_client(state, cookie)
        .start_environment(StartEnvironmentRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_environment_sources(
    state: &AppState,
    cookie: HeaderValue,
    request: UpdateEnvironmentSourcesRequest,
) -> Result<&'static str, ConnectError> {
    let expected_environment = request.environment_id.clone();
    let expected_generation = request.expected_operation_generation;
    let expected_selection = request.replacement.clone();
    let response = environment_client(state, cookie)
        .update_environment_sources(request)
        .await?
        .into_owned();
    source_update_outcome(
        &response,
        &expected_environment,
        expected_generation,
        expected_selection.as_option(),
    )
}

fn source_update_outcome(
    response: &codewire_proto::codewire::v1::UpdateEnvironmentSourcesResponse,
    expected_environment: &str,
    expected_generation: u64,
    expected_selection: Option<&codewire_proto::codewire::v1::EnvironmentSourceSelection>,
) -> Result<&'static str, ConnectError> {
    if response.environment_id != expected_environment
        || response.operation_generation != expected_generation
        || expected_generation == 0
        || !same_selection(response.selection.as_option(), expected_selection)
    {
        return Err(ConnectError::internal(
            "source update omitted its exact environment result",
        ));
    }
    match response.outcome.as_known() {
        Some(EnvironmentSourcesUpdateOutcome::Unchanged) => Ok("environment-sources-unchanged"),
        Some(EnvironmentSourcesUpdateOutcome::Stored) => Ok("environment-sources-stored"),
        Some(EnvironmentSourcesUpdateOutcome::RestartRequired) => {
            Ok("environment-sources-restarting")
        }
        _ => Err(ConnectError::internal(
            "source update has an unknown outcome",
        )),
    }
}

pub(crate) async fn stop_environment(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
) -> Result<(), ConnectError> {
    environment_client(state, cookie)
        .stop_environment(StopEnvironmentRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn delete_environment(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
) -> Result<(), ConnectError> {
    environment_client(state, cookie)
        .delete_environment(DeleteEnvironmentRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn plan_environment_resize(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
) -> Result<(EnvironmentResizePlan, Environment), ConnectError> {
    let request = PlanEnvironmentResizeRequest {
        org_id,
        environment_id,
        cpu_millicores,
        memory_mb,
        disk_gb,
        ..Default::default()
    };
    let response = environment_client(state, cookie)
        .plan_environment_resize(request.clone())
        .await?
        .into_owned();
    let plan = response
        .plan
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize plan was omitted"))?;
    let environment = response
        .environment
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize environment was omitted"))?;
    verify_resize_plan(&request, &plan, &environment)?;
    Ok((plan, environment))
}

/// Orchestration refuses Resize while setup still owns a running Sandbox with
/// its known `invalid_state` conflict (failed_precondition). Only its detail
/// separates it from other state conflicts; orchestration pins that text in
/// `assert_setup_in_progress`. Callers map it to a fixed message and never
/// forward the detail itself.
pub(crate) fn resize_refused_during_setup(error: &ConnectError) -> bool {
    error.code == connectrpc::ErrorCode::FailedPrecondition
        && crate::view::connect_error_reason(error)
            .is_some_and(|reason| reason.eq_ignore_ascii_case("invalid_state"))
        && error
            .message
            .as_deref()
            .is_some_and(|message| message.contains("setup is still in progress"))
}

pub(crate) async fn resize_environment(
    state: &AppState,
    cookie: HeaderValue,
    request: ResizeEnvironmentRequest,
) -> Result<EnvironmentResizeOperation, ConnectError> {
    let response = environment_client(state, cookie)
        .resize_environment(request.clone())
        .await?
        .into_owned();
    let operation = response
        .operation
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize operation was omitted"))?;
    let environment = response
        .environment
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize environment was omitted"))?;
    verify_resize_acknowledgement(&request, &operation, &environment)?;
    Ok(operation)
}

pub(crate) async fn environment_resize_operation(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
    operation_id: String,
) -> Result<(EnvironmentResizeOperation, Environment), ConnectError> {
    let request = GetEnvironmentResizeOperationRequest {
        org_id,
        environment_id,
        operation_id,
        ..Default::default()
    };
    let response = environment_client(state, cookie)
        .get_environment_resize_operation(request.clone())
        .await?
        .into_owned();
    let operation = response
        .operation
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize operation was omitted"))?;
    let environment = response
        .environment
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize environment was omitted"))?;
    verify_resize_operation(&request, &operation, &environment)?;
    Ok((operation, environment))
}

fn resize_environment_matches(
    environment: &Environment,
    org_id: &str,
    environment_id: &str,
) -> bool {
    !org_id.is_empty()
        && !environment_id.is_empty()
        && environment.org_id == org_id
        && environment.id == environment_id
}

fn resize_resources_match(
    resources: Option<&EnvironmentResources>,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
) -> bool {
    resources.is_some_and(|resources| {
        resources.cpu_millicores == cpu_millicores
            && resources.memory_mb == memory_mb
            && resources.disk_gb == disk_gb
    })
}

fn verify_resize_plan(
    request: &PlanEnvironmentResizeRequest,
    plan: &EnvironmentResizePlan,
    environment: &Environment,
) -> Result<(), ConnectError> {
    if !resize_environment_matches(environment, &request.org_id, &request.environment_id)
        || !resize_resources_match(
            plan.desired_resources.as_option(),
            request.cpu_millicores,
            request.memory_mb,
            request.disk_gb,
        )
    {
        return Err(ConnectError::internal("resize plan identity did not match"));
    }
    Ok(())
}

fn verify_resize_acknowledgement(
    request: &ResizeEnvironmentRequest,
    operation: &EnvironmentResizeOperation,
    environment: &Environment,
) -> Result<(), ConnectError> {
    if !resize_environment_matches(environment, &request.org_id, &request.environment_id)
        || operation.environment_id != request.environment_id
        || operation.id.len() != 32
        || !operation
            .id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || request.request_id.is_empty()
        || operation.request_id != request.request_id
        || operation.disruption_policy != request.disruption_policy
        || !resize_resources_match(
            operation.desired_resources.as_option(),
            request.cpu_millicores,
            request.memory_mb,
            request.disk_gb,
        )
    {
        return Err(ConnectError::internal(
            "resize acknowledgement identity did not match",
        ));
    }
    // Force is bound to this immutable request by the owning backend; it is not
    // echoed in an operation. Resource equality alone is never an acknowledgement.
    Ok(())
}

fn verify_resize_operation(
    request: &GetEnvironmentResizeOperationRequest,
    operation: &EnvironmentResizeOperation,
    environment: &Environment,
) -> Result<(), ConnectError> {
    if !resize_environment_matches(environment, &request.org_id, &request.environment_id)
        || request.operation_id.is_empty()
        || operation.id != request.operation_id
        || operation.environment_id != request.environment_id
        || operation.request_id.is_empty()
    {
        return Err(ConnectError::internal(
            "resize operation identity did not match",
        ));
    }
    Ok(())
}

pub(crate) fn resize_confirmation(
    environment: Environment,
    plan: EnvironmentResizePlan,
    request_id: String,
) -> EnvironmentResizeConfirmationView {
    let previous_resources = plan.previous_resources.into_option();
    let desired_resources = plan.desired_resources.into_option().unwrap_or_default();
    let execution_mode = match plan.execution_mode.as_known() {
        Some(EnvironmentResizeExecutionMode::InPlace) => "live in-place update",
        Some(EnvironmentResizeExecutionMode::ApplyOnStart) => "apply when started",
        Some(EnvironmentResizeExecutionMode::Restart) => "restart required",
        Some(EnvironmentResizeExecutionMode::Noop) => "already applied",
        _ => "review required",
    };
    let requires_restart = matches!(
        plan.execution_mode.as_known(),
        Some(EnvironmentResizeExecutionMode::Restart)
    );
    EnvironmentResizeConfirmationView {
        environment_id: environment.id,
        environment_name: environment.name,
        request_id,
        previous_resources: resize_resources_label(previous_resources),
        desired_resources: resize_resources_label(Some(desired_resources.clone())),
        cpu_millicores: desired_resources.cpu_millicores,
        memory_mb: desired_resources.memory_mb,
        disk_gb: desired_resources.disk_gb,
        execution_mode,
        requires_restart,
        active_session_count: plan.active_session_count,
        active_sessions_will_be_terminated: plan.active_sessions_will_be_terminated,
        reason: plan.reason,
        warnings: plan.warnings,
    }
}

pub(crate) fn resize_operation_view(
    operation: EnvironmentResizeOperation,
) -> EnvironmentResizeOperationView {
    let state = match operation.state.as_known() {
        Some(EnvironmentResizeOperationState::Pending) => "pending",
        Some(EnvironmentResizeOperationState::Applying) => "applying",
        Some(EnvironmentResizeOperationState::Restarting) => "restarting",
        Some(EnvironmentResizeOperationState::Completed) => "completed",
        Some(EnvironmentResizeOperationState::Failed) => "failed",
        _ => "unknown",
    };
    let active = matches!(state, "pending" | "applying" | "restarting");
    let failure = operation
        .failure
        .into_option()
        .map(|failure| format!("{}: {}", failure.code, failure.message))
        .unwrap_or_default();
    EnvironmentResizeOperationView {
        environment_id: operation.environment_id,
        operation_id: operation.id,
        state,
        desired_resources: resize_resources_label(operation.desired_resources.into_option()),
        applied_resources: resize_resources_label(operation.last_applied_resources.into_option()),
        failure,
        active,
        pod_replaced: operation.pod_replaced,
    }
}

fn resize_resources_label(resources: Option<EnvironmentResources>) -> String {
    let resources = resources.unwrap_or_default();
    format!(
        "{} vCPU / {} / {} GiB disk",
        cpu_label(resources.cpu_millicores),
        memory_label(resources.memory_mb),
        resources.disk_gb,
    )
}

pub(crate) async fn ports(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
) -> Result<Vec<EnvironmentPortRow>, ConnectError> {
    let response = port_client(state, cookie)
        .list_ports(ListPortsRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response.ports.into_iter().map(port_row).collect())
}

pub(crate) async fn create_port(
    state: &AppState,
    cookie: HeaderValue,
    request: CreatePortRequest,
) -> Result<(), ConnectError> {
    port_client(state, cookie).create_port(request).await?;
    Ok(())
}

pub(crate) async fn delete_port(
    state: &AppState,
    cookie: HeaderValue,
    request: DeletePortRequest,
) -> Result<(), ConnectError> {
    port_client(state, cookie).delete_port(request).await?;
    Ok(())
}

pub(crate) fn environment_row(environment: Environment) -> EnvironmentRow {
    let sources = source_summary(&environment);
    let (deletion_state, shutdown_at, shutdown_at_label) = deletion_deadline(&environment);
    let state = state_name(environment.state.to_i32());
    // Mirrors orchestration's setup window for a running Sandbox (#2328).
    let setup_running = state == "running"
        && !environment.setup_complete
        && environment.setup_error.trim().is_empty();
    let setup_failure = if state == "running" && !environment.setup_complete {
        environment
            .setup_error
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(300)
            .collect::<String>()
            .trim()
            .to_owned()
    } else {
        String::new()
    };
    let display_name = if environment.name.trim().is_empty() {
        environment.id.chars().take(8).collect()
    } else {
        environment.name.clone()
    };
    let cpu_vcpu = f64::from(environment.cpu_millicores) / 1_000.0;
    let memory_gib = f64::from(environment.memory_mb) / 1_024.0;
    let per_second = cpu_vcpu * 0.000_014 + memory_gib * 0.000_004_5;
    let running_seconds = f64::from(environment.total_running_seconds);
    EnvironmentRow {
        id: environment.id.clone(),
        name: display_name,
        state,
        state_tone: state_tone(state),
        state_symbol: state_symbol(state),
        preset_name: environment.preset_name,
        isolation_tier: match environment.isolation_tier.as_known() {
            Some(codewire_proto::codewire::v1::IsolationTier::Confidential) => "confidential",
            _ => "standard",
        },
        last_event: environment
            .state_changed_at
            .into_option()
            .map(|timestamp| past_time(timestamp.seconds))
            .unwrap_or_else(|| "—".to_owned()),
        created: environment
            .created_at
            .into_option()
            .map(|timestamp| past_time(timestamp.seconds))
            .unwrap_or_else(|| "—".to_owned()),
        cost: format!("${:.2}", running_seconds * per_second),
        deletion_state,
        shutdown_at,
        shutdown_at_label,
        running_time: duration_label(environment.total_running_seconds),
        resources: format!(
            "{} vCPU · {} · {} GiB",
            cpu_label(environment.cpu_millicores),
            memory_label(environment.memory_mb),
            environment.disk_gb,
        ),
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
        hourly_rate: format!("${:.2}/h", per_second * 3_600.0),
        // Start from error asks the runtime to retry creation.
        can_start: matches!(state, "stopped" | "error"),
        can_stop: state == "running",
        can_destroy: !matches!(state, "destroying" | "destroyed"),
        setup_running,
        setup_failure,
        confidential_actions_allowed: true,
        vscode_url: format!(
            "vscode://vscode-remote/ssh-remote+cw-cloud-{}/workspace",
            environment.id
        ),
        ports: environment.ports.into_iter().map(port_row).collect(),
        sources,
        credential_attention: Vec::new(),
    }
}

/// Mark each Sandbox's bound capabilities whose credential needs the viewer.
/// Only the viewer's own profiles are given, so another member's Sandbox, a
/// bound revision other than the one read, or a failed read marks nothing.
pub(crate) fn apply_credential_attention(
    rows: &mut [EnvironmentRow],
    profiles: &[crate::view::CredentialProfileRowView],
) {
    for row in rows {
        // A profile's name belongs to the profile, not one revision.
        let name = row.bound_profile().and_then(|(id, _)| {
            profiles
                .iter()
                .find(|profile| profile.id == id)
                .map(|profile| profile.name.clone())
        });
        row.credential_attention = row
            .bound_profile()
            .and_then(|(id, revision)| {
                profiles
                    .iter()
                    .find(|profile| profile.id == id && profile.revision == revision)
            })
            .map(|profile| profile.attention.clone())
            .unwrap_or_default();
        if let (Some(name), Some(sources)) = (name, row.sources.as_mut()) {
            sources.profile_name = name;
        }
    }
}

/// The Sandbox list's notices: one read of the viewer's current profiles, made
/// only when a listed Sandbox that is not being deleted is bound to a profile.
pub(crate) async fn mark_credential_attention(
    state: &AppState,
    cookie: HeaderValue,
    rows: &mut [EnvironmentRow],
) {
    if rows
        .iter()
        .any(|row| !row.deletion_started() && row.bound_profile().is_some())
    {
        let profiles = crate::credentials_connect::current_profile_attention(state, cookie).await;
        apply_credential_attention(rows, &profiles);
    }
}

/// The Sandbox page's notices, read for its exact bound profile revision.
pub(crate) async fn mark_bound_credential_attention(
    state: &AppState,
    cookie: HeaderValue,
    row: &mut EnvironmentRow,
) {
    let Some((id, revision)) = row
        .bound_profile()
        .filter(|_| !row.deletion_started())
        .map(|(id, revision)| (id.to_owned(), revision))
    else {
        return;
    };
    let profiles =
        crate::credentials_connect::bound_profile_attention(state, cookie, &id, revision).await;
    apply_credential_attention(std::slice::from_mut(row), &profiles);
}

fn source_summary(environment: &Environment) -> Option<crate::view::EnvironmentSourcesSummaryView> {
    use codewire_proto::codewire::v1::ProjectStoragePlacement;
    let selection = environment.source_selection.as_option()?;
    crate::environment_source_forms::validate_selection(selection).ok()?;
    if environment.operation_generation == 0 || environment.operation_generation > i64::MAX as u64 {
        return None;
    }
    let secrets = selection.secrets.as_option().cloned().unwrap_or_default();
    let personal = match secrets.user.and_then(|placement| placement.as_known()) {
        Some(ProjectStoragePlacement::Platform) => true,
        None if secrets.user.is_none() => false,
        _ => return None,
    };
    let profile = selection
        .credentials
        .as_option()
        .map(|profile| profile.profile.clone())
        .unwrap_or_default();
    for reference in [&secrets.project, &profile]
        .into_iter()
        .filter(|reference| !reference.is_empty())
    {
        if !reference.starts_with("platform:id:")
            || codewire_project::StorageReference::project(reference).is_err()
        {
            return None;
        }
    }
    if profile.is_empty() != selection.profile_revision.is_none()
        || selection
            .profile_revision
            .is_some_and(|revision| revision == 0)
    {
        return None;
    }
    Some(crate::view::EnvironmentSourcesSummaryView {
        selection: selection.clone(),
        operation_generation: environment.operation_generation,
        project: secrets.project,
        organization: secrets.organization,
        personal,
        profile,
        profile_revision: selection
            .profile_revision
            .map(|revision| revision.to_string())
            .unwrap_or_default(),
        profile_name: String::new(),
    })
}

fn port_row(port: Port) -> EnvironmentPortRow {
    let preview_url = port.preview_url.unwrap_or_default();
    EnvironmentPortRow {
        id: port.id,
        port: port.port,
        label: port.label,
        access: match port.access.to_i32() {
            value if value == PortAccess::Public as i32 => "Anyone with the URL",
            value if value == PortAccess::OrgMembers as i32 => "Organization members",
            _ => "Sandbox creator",
        },
        has_preview: valid_assigned_preview_url(&preview_url),
        preview_url,
    }
}

fn valid_assigned_preview_url(value: &str) -> bool {
    value.starts_with("https://")
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && matches!(url.host(), Some(url::Host::Domain(_)))
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

fn agent_catalog() -> Vec<EnvironmentAgentView> {
    [
        ("claude-code", "Claude Code"),
        ("codex", "OpenAI Codex"),
        ("gemini-cli", "Gemini CLI"),
        ("kimi-code", "Kimi Code"),
        ("pi", "Pi"),
        ("aider", "Aider"),
    ]
    .into_iter()
    .map(|(id, label)| EnvironmentAgentView { id, label })
    .collect()
}

fn state_name(value: i32) -> &'static str {
    match value {
        value if value == EnvironmentState::Pending as i32 => "pending",
        value if value == EnvironmentState::PendingBuild as i32 => "pending build",
        value if value == EnvironmentState::Building as i32 => "building",
        value if value == EnvironmentState::BuildFailed as i32 => "build failed",
        value if value == EnvironmentState::PullingSnapshot as i32 => "pulling snapshot",
        value if value == EnvironmentState::Creating as i32 => "creating",
        value if value == EnvironmentState::Starting as i32 => "starting",
        value if value == EnvironmentState::Running as i32 => "running",
        value if value == EnvironmentState::Stopping as i32 => "stopping",
        value if value == EnvironmentState::Stopped as i32 => "stopped",
        value if value == EnvironmentState::Archiving as i32 => "archiving",
        value if value == EnvironmentState::Archived as i32 => "archived",
        value if value == EnvironmentState::Restoring as i32 => "restoring",
        value if value == EnvironmentState::Resizing as i32 => "resizing",
        value if value == EnvironmentState::Destroying as i32 => "destroying",
        value if value == EnvironmentState::Destroyed as i32 => "destroyed",
        value if value == EnvironmentState::Error as i32 => "error",
        _ => "unknown",
    }
}

fn state_tone(state: &str) -> &'static str {
    match state {
        "running" => "success",
        "error" | "build failed" => "danger",
        "stopped" | "destroyed" => "neutral",
        _ => "warning",
    }
}

fn state_symbol(state: &str) -> &'static str {
    match state {
        "running" => "✓",
        "error" | "build failed" => "×",
        "stopped" => "○",
        "destroyed" => "—",
        _ => "◌",
    }
}

fn duration_label(seconds: i32) -> String {
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn cpu_label(millicores: i32) -> String {
    let value = i64::from(millicores).abs();
    let sign = if millicores < 0 { "-" } else { "" };
    if value % 1000 == 0 {
        format!("{sign}{}", value / 1000)
    } else {
        let fraction = format!("{:03}", value % 1000);
        format!("{sign}{}.{}", value / 1000, fraction.trim_end_matches('0'))
    }
}

fn memory_label(mib: i32) -> String {
    if mib % 1024 == 0 {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

/// Only the source deadline is authoritative. Neither activity nor a passed
/// deadline changes observed lifecycle state; backend cleanup can be pending.
fn deletion_deadline(environment: &Environment) -> (&'static str, Option<String>, String) {
    if environment.protected {
        return (
            "protected",
            None,
            "Protected from automatic deletion".into(),
        );
    }
    let Some(timestamp) = environment.shutdown_at.as_option() else {
        return ("unscheduled", None, "Not currently scheduled".into());
    };
    // Bound the canonical wire value to four-digit UTC years and valid nanos.
    if !(-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
        || !(0..=999_999_999).contains(&timestamp.nanos)
    {
        return ("unavailable", None, "Deletion deadline unavailable".into());
    }
    let Some(date) = chrono::DateTime::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
    else {
        return ("unavailable", None, "Deletion deadline unavailable".into());
    };
    (
        "scheduled",
        Some(date.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
        date.format("%d %b %Y, %H:%M UTC").to_string(),
    )
}

fn past_time(seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(seconds);
    let elapsed = now.saturating_sub(seconds);
    match elapsed {
        0..=9 => "just now".to_owned(),
        10..=59 => format!("{elapsed}s ago"),
        60..=3_599 => format!("{}m ago", elapsed / 60),
        3_600..=86_399 => format!("{}h ago", elapsed / 3_600),
        _ => format!("{}d ago", elapsed / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_deadline(seconds: i64, nanos: i32) -> Environment {
        let mut environment = Environment::default();
        let mut timestamp = environment.shutdown_at.into_option().unwrap_or_default();
        timestamp.seconds = seconds;
        timestamp.nanos = nanos;
        environment.shutdown_at = Some(timestamp).into();
        environment
    }

    /// A deleted Sandbox keeps its place in the inventory, read as Deleting,
    /// until orchestration reports it destroyed.
    #[test]
    fn inventory_keeps_deleting_sandboxes_in_place_and_reads_them_as_deleting() {
        let sandbox = |id: &str, created: i64, state: EnvironmentState| {
            let mut environment = Environment {
                id: id.into(),
                name: id.into(),
                state: state.into(),
                ..Default::default()
            };
            let mut timestamp = environment.created_at.into_option().unwrap_or_default();
            timestamp.seconds = created;
            environment.created_at = Some(timestamp).into();
            environment
        };
        let rows: Vec<_> = merge_inventory(
            vec![
                sandbox("newest", 40, EnvironmentState::Running),
                sandbox("raced", 30, EnvironmentState::Error),
                sandbox("oldest", 10, EnvironmentState::Stopped),
            ],
            vec![
                sandbox("deleting", 20, EnvironmentState::Destroying),
                sandbox("raced", 30, EnvironmentState::Destroying),
            ],
        )
        .into_iter()
        .map(environment_row)
        .collect();
        let listed: Vec<_> = rows
            .iter()
            .map(|row| (row.id.as_str(), row.state_label()))
            .collect();
        assert_eq!(
            listed,
            [
                ("newest", "running"),
                ("raced", "deleting…"),
                ("deleting", "deleting…"),
                ("oldest", "stopped"),
            ]
        );
        let deleting = &rows[2];
        assert!(deleting.deletion_started());
        assert!(!deleting.can_destroy && !deleting.can_start && !deleting.can_stop);
        assert!(!rows[0].deletion_started() && !rows[3].deletion_started());
        let destroyed = environment_row(sandbox("gone", 1, EnvironmentState::Destroyed));
        assert_eq!(destroyed.state_label(), "deleted");
        assert!(destroyed.deletion_started());
    }

    #[test]
    fn resource_labels_preserve_exact_cpu_and_memory_without_changing_prices() {
        for (millicores, expected) in [
            (100, "0.1"),
            (750, "0.75"),
            (1000, "1"),
            (1001, "1.001"),
            (1250, "1.25"),
            (128000, "128"),
        ] {
            assert_eq!(cpu_label(millicores), expected);
        }
        assert_eq!(memory_label(128), "128 MiB");
        assert_eq!(memory_label(1536), "1536 MiB");
        assert_eq!(memory_label(2048), "2 GiB");
        let row = environment_row(Environment {
            cpu_millicores: 750,
            memory_mb: 1536,
            disk_gb: 10,
            total_running_seconds: 3600,
            ..Default::default()
        });
        assert_eq!(row.resources, "0.75 vCPU · 1536 MiB · 10 GiB");
        assert_eq!(
            resize_resources_label(Some(EnvironmentResources {
                cpu_millicores: 750,
                memory_mb: 1536,
                disk_gb: 10,
                ..Default::default()
            })),
            "0.75 vCPU / 1536 MiB / 10 GiB disk"
        );
        let price = format!("${:.2}", 3600.0 * (0.75 * 0.000_014 + 1.5 * 0.000_004_5));
        assert_eq!(row.cost, price);
        assert_eq!(row.hourly_rate, format!("{price}/h"));
    }

    #[test]
    fn deletion_deadline_preserves_precision_and_never_infers_lifecycle() {
        let seconds = chrono::DateTime::parse_from_rfc3339("2026-09-17T00:26:00Z")
            .unwrap()
            .timestamp();
        let mut environment = with_deadline(seconds, 123_456_789);
        environment.state = EnvironmentState::Running.into();
        let row = environment_row(environment);
        assert_eq!(row.deletion_state, "scheduled");
        assert_eq!(
            row.shutdown_at.as_deref(),
            Some("2026-09-17T00:26:00.123456789Z")
        );
        assert_eq!(row.shutdown_at_label, "17 Sep 2026, 00:26 UTC");
        let mut past = with_deadline(0, 0);
        past.state = EnvironmentState::Running.into();
        let row = environment_row(past);
        assert_eq!(row.state, "running");
        assert!(row.can_stop);
        assert_eq!(row.deletion_state, "scheduled");
    }

    #[test]
    fn deletion_deadline_distinguishes_absence_protection_and_invalid_source() {
        assert_eq!(
            deletion_deadline(&Environment::default()),
            ("unscheduled", None, "Not currently scheduled".into())
        );
        for (seconds, nanos) in [
            (-62_135_596_801, 0),
            (253_402_300_800, 0),
            (0, -1),
            (0, 1_000_000_000),
        ] {
            let mut environment = with_deadline(seconds, nanos);
            assert_eq!(
                deletion_deadline(&environment),
                ("unavailable", None, "Deletion deadline unavailable".into())
            );
            environment.protected = true;
            assert_eq!(
                deletion_deadline(&environment),
                (
                    "protected",
                    None,
                    "Protected from automatic deletion".into()
                )
            );
        }
        assert_eq!(
            deletion_deadline(&with_deadline(-62_135_596_800, 0))
                .1
                .as_deref(),
            Some("0001-01-01T00:00:00.000000000Z")
        );
        assert_eq!(
            deletion_deadline(&with_deadline(253_402_300_799, 999_999_999))
                .1
                .as_deref(),
            Some("9999-12-31T23:59:59.999999999Z")
        );
    }

    fn resize_identity_fixture() -> (Environment, EnvironmentResizeOperation) {
        (
            Environment {
                id: "sandbox".into(),
                org_id: "organization".into(),
                ..Default::default()
            },
            EnvironmentResizeOperation {
                id: "0123456789abcdef0123456789abcdef".into(),
                environment_id: "sandbox".into(),
                request_id: "request".into(),
                desired_resources: Some(EnvironmentResources {
                    cpu_millicores: 2000,
                    memory_mb: 4096,
                    disk_gb: 20,
                    ..Default::default()
                })
                .into(),
                disruption_policy:
                    codewire_proto::codewire::v1::EnvironmentResizeDisruptionPolicy::LiveOnly.into(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn resize_plan_binds_organization_sandbox_and_requested_resources() {
        let (environment, operation) = resize_identity_fixture();
        let request = PlanEnvironmentResizeRequest {
            org_id: "organization".into(),
            environment_id: "sandbox".into(),
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 20,
            ..Default::default()
        };
        let plan = EnvironmentResizePlan {
            desired_resources: operation.desired_resources,
            ..Default::default()
        };
        assert!(verify_resize_plan(&request, &plan, &environment).is_ok());
        for wrong_environment in [
            Environment {
                id: "foreign".into(),
                ..environment.clone()
            },
            Environment {
                org_id: "foreign".into(),
                ..environment.clone()
            },
        ] {
            assert!(verify_resize_plan(&request, &plan, &wrong_environment).is_err());
        }
        for desired in [
            None,
            Some(EnvironmentResources {
                cpu_millicores: 4000,
                memory_mb: 4096,
                disk_gb: 20,
                ..Default::default()
            }),
            Some(EnvironmentResources {
                cpu_millicores: 2000,
                memory_mb: 8192,
                disk_gb: 20,
                ..Default::default()
            }),
            Some(EnvironmentResources {
                cpu_millicores: 2000,
                memory_mb: 4096,
                disk_gb: 40,
                ..Default::default()
            }),
        ] {
            let wrong_plan = EnvironmentResizePlan {
                desired_resources: desired.into(),
                ..plan.clone()
            };
            assert!(verify_resize_plan(&request, &wrong_plan, &environment).is_err());
        }
    }

    #[test]
    fn resize_acknowledgement_requires_exact_request_not_just_equal_resources() {
        let (environment, operation) = resize_identity_fixture();
        let request = ResizeEnvironmentRequest {
            org_id: "organization".into(),
            environment_id: "sandbox".into(),
            request_id: "request".into(),
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 20,
            disruption_policy:
                codewire_proto::codewire::v1::EnvironmentResizeDisruptionPolicy::LiveOnly.into(),
            ..Default::default()
        };
        assert!(verify_resize_acknowledgement(&request, &operation, &environment).is_ok());
        for wrong_operation in [
            EnvironmentResizeOperation {
                request_id: "another-request".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                environment_id: "foreign".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                id: "not-an-operation".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                id: "0123456789ABCDEF0123456789ABCDEF".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                disruption_policy:
                    codewire_proto::codewire::v1::EnvironmentResizeDisruptionPolicy::AllowRestart
                        .into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                desired_resources: None.into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                desired_resources: Some(EnvironmentResources {
                    cpu_millicores: 4000,
                    memory_mb: 4096,
                    disk_gb: 20,
                    ..Default::default()
                })
                .into(),
                ..operation.clone()
            },
        ] {
            assert!(
                verify_resize_acknowledgement(&request, &wrong_operation, &environment).is_err()
            );
        }
        let foreign = Environment {
            org_id: "foreign".into(),
            ..environment.clone()
        };
        assert!(verify_resize_acknowledgement(&request, &operation, &foreign).is_err());
        let empty_request = ResizeEnvironmentRequest {
            request_id: String::new(),
            ..request
        };
        assert!(verify_resize_acknowledgement(&empty_request, &operation, &environment).is_err());
    }

    #[test]
    fn resize_operation_poll_requires_exact_operation_and_environment_identity() {
        let (environment, operation) = resize_identity_fixture();
        let request = GetEnvironmentResizeOperationRequest {
            org_id: "organization".into(),
            environment_id: "sandbox".into(),
            operation_id: operation.id.clone(),
            ..Default::default()
        };
        assert!(verify_resize_operation(&request, &operation, &environment).is_ok());
        for wrong_operation in [
            EnvironmentResizeOperation {
                id: "fedcba9876543210fedcba9876543210".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                environment_id: "foreign".into(),
                ..operation.clone()
            },
            EnvironmentResizeOperation {
                request_id: String::new(),
                ..operation.clone()
            },
        ] {
            assert!(verify_resize_operation(&request, &wrong_operation, &environment).is_err());
        }
        for foreign in [
            Environment {
                id: "foreign".into(),
                ..environment.clone()
            },
            Environment {
                org_id: "foreign".into(),
                ..environment.clone()
            },
        ] {
            assert!(verify_resize_operation(&request, &operation, &foreign).is_err());
        }
    }

    #[test]
    fn preview_suffix_is_bounded_and_never_a_url_or_hardcoded_fallback() {
        assert_eq!(
            validated_preview_domain("preview.EXAMPLE.test"),
            "preview.example.test"
        );
        for invalid in [
            "",
            "https://cwpreview.sh",
            "*.cwpreview.sh",
            "cwpreview.sh:443",
            "cwpreview.sh/path",
            "evil@example.test",
            "bad_name.example",
            "cwpreview.sh.",
            "127.0.0.1",
            "example.123",
            "example.0x7f",
        ] {
            assert_eq!(validated_preview_domain(invalid), "");
        }
    }

    #[test]
    fn assigned_preview_requires_a_valid_https_root_and_preserves_exact_api_text() {
        let exact = "https://9web-ab123-example.preview.example.test";
        assert!(valid_assigned_preview_url(exact));
        let row = port_row(Port {
            preview_url: Some(exact.into()),
            ..Default::default()
        });
        assert!(row.has_preview);
        assert_eq!(row.preview_url, exact);
        for invalid in [
            "https://",
            "http://web.example.test",
            "https://user:password@web.example.test",
            "https://web.example.test:8443",
            "https://web.example.test/path",
            "https://web.example.test/?token=secret",
            "https://web.example.test/#fragment",
            "https://web.example.test.127.0.0.1",
        ] {
            assert!(!valid_assigned_preview_url(invalid), "admitted {invalid:?}");
        }
    }

    #[test]
    fn source_summary_displays_only_exact_metadata_and_never_infers_missing_selection() {
        use codewire_proto::codewire::v1::{
            EnvironmentSourceSelection, ProjectCredentialBinding, ProjectSecretBindings,
            ProjectStoragePlacement,
        };
        assert!(source_summary(&Environment::default()).is_none());
        let reference = "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let mut environment = Environment {
            operation_generation: 9,
            source_selection: Some(EnvironmentSourceSelection {
                secrets: Some(ProjectSecretBindings {
                    project: reference.into(),
                    organization: true,
                    user: Some(ProjectStoragePlacement::Platform.into()),
                    ..Default::default()
                })
                .into(),
                credentials: Some(ProjectCredentialBinding {
                    profile: reference.into(),
                    ..Default::default()
                })
                .into(),
                profile_revision: Some(7),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let view = source_summary(&environment).unwrap();
        assert_eq!(view.operation_generation, 9);
        assert_eq!(view.profile_revision, "7");
        assert_eq!(view.project, reference);
        assert!(view.personal && view.organization);
        environment
            .source_selection
            .as_option_mut()
            .unwrap()
            .profile_revision = None;
        assert!(source_summary(&environment).is_none());
        environment
            .source_selection
            .as_option_mut()
            .unwrap()
            .profile_revision = Some(7);
        environment
            .source_selection
            .as_option_mut()
            .unwrap()
            .secrets
            .as_option_mut()
            .unwrap()
            .user = Some(ProjectStoragePlacement::Local.into());
        assert!(source_summary(&environment).is_none());
    }

    #[test]
    fn agent_catalog_contains_only_selectable_tools() {
        let catalog = agent_catalog();
        assert_eq!(
            catalog
                .iter()
                .map(|agent| (agent.id, agent.label))
                .collect::<Vec<_>>(),
            vec![
                ("claude-code", "Claude Code"),
                ("codex", "OpenAI Codex"),
                ("gemini-cli", "Gemini CLI"),
                ("kimi-code", "Kimi Code"),
                ("pi", "Pi"),
                ("aider", "Aider"),
            ]
        );
    }

    #[test]
    fn preset_secret_source_detection_uses_only_canonical_bindings() {
        let bindings = [
            codewire_project::SecretBindings {
                project: "development".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                organization: true,
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                ..Default::default()
            },
        ];
        for secrets in bindings {
            let project_spec = codewire_project::ProjectSpec {
                secrets,
                ..Default::default()
            };
            assert!(project_spec_uses_protected_secret_bindings(&project_spec));
        }

        assert!(!project_spec_uses_protected_secret_bindings(
            &codewire_project::ProjectSpec::default()
        ));
        assert!(project_spec_uses_protected_secret_bindings(
            &codewire_project::ProjectSpec {
                credentials: Some(codewire_project::CredentialBinding {
                    profile: "platform:work".into()
                }),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn create_response_requires_exact_admitted_sources_and_pre_lifecycle_generation() {
        use codewire_proto::codewire::v1::{EnvironmentSourceSelection, ProjectSecretBindings};
        let requested = EnvironmentSourceSelection {
            secrets: Some(ProjectSecretBindings::default()).into(),
            ..Default::default()
        };
        let mut response = Environment {
            id: "6bf8d155-e84c-4fc5-b479-b17022fe41dd".into(),
            org_id: "org".into(),
            source_selection: Some(EnvironmentSourceSelection::default()).into(),
            ..Default::default()
        };
        assert!(verify_created_selection(&response, "org", &requested).is_ok());
        response.operation_generation = 1;
        assert!(verify_created_selection(&response, "org", &requested).is_err());
        response.operation_generation = 0;
        assert!(verify_created_selection(&response, "other-org", &requested).is_err());
        response.source_selection = None.into();
        assert!(verify_created_selection(&response, "org", &requested).is_err());
        let selected = crate::environment_source_forms::SourceSubmission::parse(
            b"secret_project=6bf8d155-e84c-4fc5-b479-b17022fe41dd&credential_profile=6bf8d155-e84c-4fc5-b479-b17022fe41dd%407"
        ).unwrap().selection;
        response.source_selection = Some(selected.clone()).into();
        assert!(verify_created_selection(&response, "org", &selected).is_ok());
        response
            .source_selection
            .as_option_mut()
            .unwrap()
            .profile_revision = Some(8);
        assert!(verify_created_selection(&response, "org", &selected).is_err());
    }

    #[test]
    fn update_response_requires_exact_replacement_without_allocating_a_generation() {
        use codewire_proto::codewire::v1::{
            EnvironmentSourceSelection, ProjectSecretBindings, UpdateEnvironmentSourcesResponse,
        };
        let expected = EnvironmentSourceSelection {
            secrets: Some(ProjectSecretBindings::default()).into(),
            ..Default::default()
        };
        let mut response = UpdateEnvironmentSourcesResponse {
            environment_id: "environment".into(),
            operation_generation: 9,
            selection: Some(EnvironmentSourceSelection::default()).into(),
            ..Default::default()
        };
        for outcome in [
            EnvironmentSourcesUpdateOutcome::Unchanged,
            EnvironmentSourcesUpdateOutcome::Stored,
            EnvironmentSourcesUpdateOutcome::RestartRequired,
        ] {
            response.outcome = outcome.into();
            assert!(source_update_outcome(&response, "environment", 9, Some(&expected)).is_ok());
        }
        assert!(source_update_outcome(&response, "wrong-environment", 9, Some(&expected)).is_err());
        assert!(source_update_outcome(&response, "environment", 10, Some(&expected)).is_err());
        response.selection.as_option_mut().unwrap().secrets = Some(ProjectSecretBindings {
            organization: true,
            ..Default::default()
        })
        .into();
        assert!(source_update_outcome(&response, "environment", 9, Some(&expected)).is_err());
        response.selection = None.into();
        assert!(source_update_outcome(&response, "environment", 9, Some(&expected)).is_err());
    }

    #[test]
    fn environment_states_are_extensible_and_safe() {
        assert_eq!(state_name(EnvironmentState::Running as i32), "running");
        assert_eq!(state_name(i32::MAX), "unknown");
        assert_eq!(state_tone("unknown"), "warning");
    }
}
