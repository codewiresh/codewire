use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::HeaderValue;
use codewire_proto::codewire::{
    console::v1::{
        BillingServiceClient, EnvironmentSetupServiceClient, GetBillingOverviewRequest,
        GetEnvironmentCreateOptionsRequest, GitHubServiceClient, ListGitHubReposRequest,
        ListResourcePlansRequest,
    },
    v1::{
        CreateEnvironmentRequest, CreatePortRequest, DeleteEnvironmentRequest, DeletePortRequest,
        DetectionResult, Environment, EnvironmentResizeExecutionMode, EnvironmentResizeOperation,
        EnvironmentResizeOperationState, EnvironmentResizePlan, EnvironmentResources,
        EnvironmentServiceClient, EnvironmentState, GetEnvironmentRequest,
        GetEnvironmentResizeOperationRequest, GetEnvironmentTrustReportRequest,
        ListEnvironmentsRequest, ListPortsRequest, ListUserSecretsRequest,
        PlanEnvironmentResizeRequest, Port, PortAccess, PortServiceClient,
        ResizeEnvironmentRequest, SecretServiceClient, SetUserSecretRequest,
        StartEnvironmentRequest, StopEnvironmentRequest, WatchEnvironmentCreateRequest,
        watch_environment_create_response,
    },
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};
use tokio::sync::mpsc;

use crate::{
    state::AppState,
    transport::BrowserTransport,
    view::{
        EnvironmentAgentSecretView, EnvironmentAgentView, EnvironmentDetectionView,
        EnvironmentPortRow, EnvironmentPresetOption, EnvironmentResizeConfirmationView,
        EnvironmentResizeOperationView, EnvironmentRow, EnvironmentSecretProjectOption,
        EnvironmentTrustSummaryView, GitHubRepositoryOption,
    },
};

const UNARY_TIMEOUT: Duration = Duration::from_secs(10);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) struct EnvironmentCreateOptions {
    pub(crate) github_connected: bool,
    pub(crate) github_username: String,
    pub(crate) github_repositories_available: bool,
    pub(crate) github_repositories: Vec<GitHubRepositoryOption>,
    pub(crate) presets: Vec<EnvironmentPresetOption>,
    pub(crate) secret_projects: Vec<EnvironmentSecretProjectOption>,
    pub(crate) agents: Vec<EnvironmentAgentView>,
    pub(crate) confidential_available: bool,
    pub(crate) confidential_price: String,
}

pub(crate) enum EnvironmentPrepareEvent {
    Progress {
        phase: String,
        message: String,
        total: i32,
    },
    RepoFetched {
        index: i32,
        repo: String,
        ok: bool,
    },
    Complete {
        draft: Box<CreateEnvironmentRequest>,
        detection: Box<Option<DetectionResult>>,
    },
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
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

pub(crate) async fn environment(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
) -> Result<EnvironmentRow, ConnectError> {
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
        .map(environment_row)
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
    let setup = EnvironmentSetupServiceClient::new(
        transport(state, cookie.clone()),
        client_config(state, UNARY_TIMEOUT),
    )
    .get_environment_create_options(GetEnvironmentCreateOptionsRequest {
        org_id: org_id.to_owned(),
        ..Default::default()
    })
    .await?
    .into_owned();

    let github = setup.github_status.into_option().unwrap_or_default();
    let (github_repositories, github_repositories_available) = if github.connected {
        match GitHubServiceClient::new(
            transport(state, cookie.clone()),
            client_config(state, UNARY_TIMEOUT),
        )
        .list_git_hub_repos(ListGitHubReposRequest {
            page: 1,
            per_page: 100,
            ..Default::default()
        })
        .await
        {
            Ok(response) => (
                response
                    .into_owned()
                    .repos
                    .into_iter()
                    .map(|repository| GitHubRepositoryOption {
                        full_name: repository.full_name,
                        url: repository.html_url,
                        description: repository.description,
                        language: repository.language,
                        private: repository.private,
                    })
                    .collect(),
                true,
            ),
            Err(error) if error.code == ErrorCode::Unauthenticated => return Err(error),
            Err(_) => (Vec::new(), false),
        }
    } else {
        (Vec::new(), false)
    };

    let configured_user_secrets: HashSet<String> = SecretServiceClient::new(
        transport(state, cookie.clone()),
        client_config(state, UNARY_TIMEOUT),
    )
    .list_user_secrets(ListUserSecretsRequest {
        page_size: 100,
        ..Default::default()
    })
    .await?
    .into_owned()
    .secrets
    .into_iter()
    .map(|secret| secret.key)
    .collect();

    // The catalog is public to organization members.  Failure to read it does
    // not block the create form; the server still performs authoritative,
    // atomic admission when a confidential environment is submitted.
    let overview_client = billing_client(state, cookie.clone());
    let plans_client = billing_client(state, cookie.clone());
    let (overview, plans) = tokio::join!(
        overview_client.get_billing_overview(GetBillingOverviewRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        plans_client.list_resource_plans(ListResourcePlansRequest {
            resource_type: "confidential_sandbox".to_owned(),
            ..Default::default()
        }),
    );
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

    let secret_projects = setup
        .secret_projects
        .into_iter()
        .map(|project| EnvironmentSecretProjectOption {
            id: project.id,
            name: project.name,
            secret_count: project.secret_count,
        })
        .collect::<Vec<_>>();
    let presets = setup
        .presets
        .into_iter()
        .map(|preset| {
            let secret_project = preset
                .secret_project_id
                .as_deref()
                .and_then(|id| secret_projects.iter().find(|project| project.id == id))
                .map(|project| project.name.clone())
                .unwrap_or_default();
            let defaults = preset
                .default_setup_config
                .into_option()
                .unwrap_or_default();
            EnvironmentPresetOption {
                id: preset.id,
                name: preset.name,
                description: preset.description.unwrap_or_default(),
                image: preset.image.unwrap_or_default(),
                default_cpu_millicores: preset.default_cpu_millicores,
                default_memory_mb: preset.default_memory_mb,
                default_disk_gb: preset.default_disk_gb,
                default_ttl_seconds: preset.default_ttl_seconds,
                default_install_command: defaults.install_command,
                default_startup_script: defaults.startup_script,
                default_agents: defaults
                    .agents
                    .into_iter()
                    .map(|agent| agent.r#type)
                    .collect(),
                default_app_ports: defaults
                    .app_ports
                    .into_iter()
                    .enumerate()
                    .map(|(index, port)| crate::view::EnvironmentAppPortFormRow {
                        index,
                        port: port.port.to_string(),
                        label: port.label,
                        access: port.access,
                    })
                    .collect(),
                default_include_org_secrets: defaults.include_org_secrets.unwrap_or(true),
                default_include_user_secrets: defaults.include_user_secrets.unwrap_or(true),
                secret_project,
                official: preset.official,
            }
        })
        .collect();

    Ok(EnvironmentCreateOptions {
        github_connected: github.connected,
        github_username: github.username,
        github_repositories_available,
        github_repositories,
        presets,
        secret_projects,
        agents: agent_catalog(&configured_user_secrets),
        confidential_available,
        confidential_price,
    })
}

pub(crate) async fn prepare_events(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    draft: CreateEnvironmentRequest,
    analyze: bool,
) -> Result<mpsc::Receiver<Result<EnvironmentPrepareEvent, ConnectError>>, ConnectError> {
    let client = EnvironmentServiceClient::new(
        transport(state, cookie),
        client_config(state, PREPARE_TIMEOUT),
    );
    let mut stream = client
        .watch_environment_create(WatchEnvironmentCreateRequest {
            org_id,
            draft: Some(draft).into(),
            analyze: Some(analyze),
            ..Default::default()
        })
        .await?;
    let (sender, receiver) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let message = match tokio::select! {
                // A dropped browser response closes the route receiver. Stop
                // waiting on upstream immediately so dropping `stream`
                // cancels the generated Connect response body as well.
                _ = sender.closed() => break,
                message = stream.message::<codewire_proto::codewire::v1::WatchEnvironmentCreateResponse>() => message,
            } {
                Ok(Some(message)) => message.to_owned_message(),
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    break;
                }
            };
            let event = match message.event {
                Some(watch_environment_create_response::Event::Progress(progress)) => {
                    EnvironmentPrepareEvent::Progress {
                        phase: progress.phase,
                        message: progress.message,
                        total: progress.total,
                    }
                }
                Some(watch_environment_create_response::Event::RepoFetched(repo)) => {
                    EnvironmentPrepareEvent::RepoFetched {
                        index: repo.index,
                        repo: repo.repo,
                        ok: repo.ok,
                    }
                }
                Some(watch_environment_create_response::Event::Complete(complete)) => {
                    let Some(draft) = complete.draft.into_option() else {
                        let _ = sender
                            .send(Err(ConnectError::internal(
                                "environment preparation omitted its draft",
                            )))
                            .await;
                        break;
                    };
                    EnvironmentPrepareEvent::Complete {
                        draft: Box::new(draft),
                        detection: Box::new(complete.detection.into_option()),
                    }
                }
                None => continue,
            };
            if sender.send(Ok(event)).await.is_err() {
                // The browser or no-JS caller went away. Dropping this task
                // drops the generated Connect stream and cancels upstream.
                break;
            }
        }
    });
    Ok(receiver)
}

pub(crate) async fn create_environment(
    state: &AppState,
    cookie: HeaderValue,
    request: CreateEnvironmentRequest,
) -> Result<String, ConnectError> {
    let response = environment_client(state, cookie)
        .create_environment(request)
        .await?
        .into_owned();
    response
        .environment
        .into_option()
        .map(|environment| environment.id)
        .ok_or_else(|| ConnectError::internal("environment creation omitted its environment"))
}

pub(crate) async fn set_user_secrets(
    state: &AppState,
    cookie: HeaderValue,
    secrets: Vec<(String, String)>,
) -> Result<(), ConnectError> {
    let client = SecretServiceClient::new(
        transport(state, cookie),
        client_config(state, UNARY_TIMEOUT),
    );
    for (key, value) in secrets {
        client
            .set_user_secret(SetUserSecretRequest {
                key,
                value,
                ..Default::default()
            })
            .await?;
    }
    Ok(())
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
    let response = environment_client(state, cookie)
        .plan_environment_resize(PlanEnvironmentResizeRequest {
            org_id,
            environment_id,
            cpu_millicores,
            memory_mb,
            disk_gb,
            ..Default::default()
        })
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
    Ok((plan, environment))
}

pub(crate) async fn resize_environment(
    state: &AppState,
    cookie: HeaderValue,
    request: ResizeEnvironmentRequest,
) -> Result<EnvironmentResizeOperation, ConnectError> {
    let response = environment_client(state, cookie)
        .resize_environment(request)
        .await?
        .into_owned();
    response
        .operation
        .into_option()
        .ok_or_else(|| ConnectError::internal("resize operation was omitted"))
}

pub(crate) async fn environment_resize_operation(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
    operation_id: String,
) -> Result<(EnvironmentResizeOperation, Environment), ConnectError> {
    let response = environment_client(state, cookie)
        .get_environment_resize_operation(GetEnvironmentResizeOperationRequest {
            org_id,
            environment_id,
            operation_id,
            ..Default::default()
        })
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
    Ok((operation, environment))
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
        "{} vCPU / {} GiB / {} GiB disk",
        compact_decimal(f64::from(resources.cpu_millicores) / 1_000.0),
        compact_decimal(f64::from(resources.memory_mb) / 1_024.0),
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

pub(crate) fn detection_view(detection: Option<DetectionResult>) -> EnvironmentDetectionView {
    detection
        .map(|detection| EnvironmentDetectionView {
            project_type: detection.project_type,
            language: detection.language,
            framework: detection.framework,
            image: detection.preset_image,
            setup_notes: detection.setup_notes,
            needs_docker: detection.needs_docker,
            has_compose: detection.has_compose,
        })
        .unwrap_or_default()
}

fn environment_row(environment: Environment) -> EnvironmentRow {
    let state = state_name(environment.state.to_i32());
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
        running_time: duration_label(environment.total_running_seconds),
        resources: format!(
            "{} vCPU / {} GiB",
            compact_decimal(cpu_vcpu),
            compact_decimal(memory_gib)
        ),
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
        hourly_rate: format!("${:.2}/h", per_second * 3_600.0),
        can_start: state == "stopped",
        can_stop: state == "running",
        can_destroy: !matches!(state, "destroying" | "destroyed"),
        vscode_url: format!(
            "vscode://vscode-remote/ssh-remote+cw-{}/workspace",
            environment.id
        ),
        ports: environment.ports.into_iter().map(port_row).collect(),
    }
}

fn port_row(port: Port) -> EnvironmentPortRow {
    let preview_url = port.preview_url.unwrap_or_default();
    EnvironmentPortRow {
        id: port.id,
        port: port.port,
        label: port.label,
        access: match port.access.to_i32() {
            value if value == PortAccess::Public as i32 => "Public",
            value if value == PortAccess::OrgMembers as i32 => "Org",
            _ => "Creator",
        },
        has_preview: preview_url.starts_with("https://") || preview_url.starts_with("http://"),
        preview_url,
    }
}

fn agent_catalog(configured: &HashSet<String>) -> Vec<EnvironmentAgentView> {
    [
        (
            "claude-code",
            "Claude Code",
            &[
                ("ANTHROPIC_API_KEY", "Anthropic API Key", "sk-ant-..."),
                (
                    "CLAUDE_CODE_OAUTH_TOKEN",
                    "Claude Code OAuth Token",
                    "Claude auth token",
                ),
            ][..],
        ),
        (
            "codex",
            "OpenAI Codex",
            &[("OPENAI_API_KEY", "OpenAI API Key", "sk-...")][..],
        ),
        (
            "gemini-cli",
            "Gemini CLI",
            &[("GEMINI_API_KEY", "Gemini API Key", "AIza...")][..],
        ),
        ("kimi-code", "Kimi Code", &[][..]),
        ("pi", "Pi", &[][..]),
        (
            "aider",
            "Aider",
            &[("OPENAI_API_KEY", "OpenAI API Key", "sk-...")][..],
        ),
    ]
    .into_iter()
    .map(|(id, label, secrets)| EnvironmentAgentView {
        id,
        label,
        secrets: secrets
            .iter()
            .map(|(key, label, placeholder)| EnvironmentAgentSecretView {
                key,
                label,
                placeholder,
                configured: configured.contains(*key),
            })
            .collect(),
    })
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

fn compact_decimal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
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

    #[test]
    fn agent_catalog_exposes_only_configured_metadata() {
        let catalog = agent_catalog(&HashSet::from(["OPENAI_API_KEY".to_owned()]));
        let openai = catalog
            .iter()
            .flat_map(|agent| &agent.secrets)
            .find(|secret| secret.key == "OPENAI_API_KEY")
            .expect("OpenAI metadata");
        assert!(openai.configured);
        assert!(!openai.placeholder.is_empty());
    }

    #[test]
    fn environment_states_are_extensible_and_safe() {
        assert_eq!(state_name(EnvironmentState::Running as i32), "running");
        assert_eq!(state_name(i32::MAX), "unknown");
        assert_eq!(state_tone("unknown"), "warning");
    }
}
