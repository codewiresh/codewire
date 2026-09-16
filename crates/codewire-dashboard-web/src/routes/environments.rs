use std::{
    collections::{BTreeMap, HashMap},
    pin::Pin,
};

use axum::{
    Form,
    extract::{Path, Query, RawForm, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use codewire_project::{
    AgentsSpec, ApplicationPort, PROJECT_SCHEMA_VERSION, ProjectSpec, RepositorySpec, ResourceSpec,
};
use codewire_proto::codewire::v1::{
    CreateEnvironmentRequest, CreatePortRequest, DeletePortRequest,
    EnvironmentResizeDisruptionPolicy, IsolationTier, PortAccess, ResizeEnvironmentRequest,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;
use url::Url;

use crate::{
    environment_connect::{self, EnvironmentCreateOptions},
    error::WebError,
    response::{
        HTMX_REQUEST, error_page, login_redirect, render_page_with_connect_origin, render_template,
        render_template_with_connect_origin,
    },
    routes::organization_governance::{
        action_context, connect_page_error, get_context, mutation_redirect, valid_identifier,
    },
    security::{csrf_cookie, csrf_cookie_value, new_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::{
        EnvironmentListTemplate, EnvironmentResizeOperationTemplate,
        OrganizationEnvironmentsContentTemplate, OrganizationEnvironmentsTemplate,
        SandboxRailTemplate,
    },
    view::{
        EnvironmentAppPortFormRow, EnvironmentCreateFormView, EnvironmentPortPanelView,
        EnvironmentRepositoryFormRow, EnvironmentsPageView, OrganizationContext,
        bad_request_fields, connect_error_reason,
    },
};

const MAX_REPOSITORIES: usize = 108;
const MAX_APP_PORTS: usize = 16;
const MAX_FIELD: usize = 16_384;
const DEFAULT_TTL: &str = "infinity";
const PROTECTED_SECRET_ACCESS_UNAVAILABLE: &str =
    crate::environment_source_forms::INVALID_SELECTION;
const PROJECT_SPEC_INVALID: &str = "The Sandbox service returned an invalid project configuration.";
const PROJECT_FEATURE_UNAVAILABLE: &str =
    "This project uses features that the current platform Sandbox editor cannot execute safely.";

#[derive(Debug, Default, Deserialize)]
pub(super) struct EnvironmentsQuery {
    #[serde(default)]
    search: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    ports: String,
    #[serde(default)]
    sources: String,
    #[serde(default)]
    trust: String,
    #[serde(default)]
    resize_environment: String,
    #[serde(default)]
    resize_operation: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct EnvironmentIdSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    #[serde(default)]
    return_to: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PortCreateSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    port: String,
    label: String,
    access: String,
    #[serde(default)]
    dialog: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct PortDeleteSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    port_id: String,
    #[serde(default)]
    dialog: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResizePlanSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    cpu_millicores: String,
    memory_mb: String,
    disk_gb: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResizeApplySubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    cpu_millicores: String,
    memory_mb: String,
    disk_gb: String,
    request_id: String,
    #[serde(default)]
    allow_restart: String,
    #[serde(default)]
    force: String,
}

// Deliberately not Debug. Secret-source inputs must not become available to
// derived diagnostics, retained form models, or errors.
struct EnvironmentSubmission {
    csrf: String,
    name: String,
    preset_id: String,
    image: String,
    install_command: String,
    startup_script: String,
    cpu: String,
    memory: String,
    disk: String,
    ttl: String,
    isolation_tier: String,
    repositories: Vec<(String, String, String)>,
    agents: Vec<String>,
    app_ports: Vec<(String, String, String)>,
    agent_secret_supplied: bool,
    sources: Result<crate::environment_source_forms::SourceSubmission, ()>,
}

impl EnvironmentSubmission {
    fn parse(bytes: &[u8]) -> Result<Self, ()> {
        let mut values = HashMap::<String, String>::new();
        let mut repositories = BTreeMap::<usize, (String, String, String)>::new();
        let mut app_ports = BTreeMap::<usize, (String, String, String)>::new();
        let mut agents = Vec::new();
        let mut agent_secret_supplied = false;

        for (key, value) in url::form_urlencoded::parse(bytes) {
            if key.len() > 128 || value.len() > MAX_FIELD {
                return Err(());
            }
            let key = key.into_owned();
            let value = value.into_owned();
            if key == "agent" {
                if agents.len() >= 16 {
                    return Err(());
                }
                agents.push(value);
            } else if let Some(index) = indexed_key(&key, "repo_url_") {
                if index >= MAX_REPOSITORIES {
                    return Err(());
                }
                repositories.entry(index).or_default().0 = value;
            } else if let Some(index) = indexed_key(&key, "repo_branch_") {
                if index >= MAX_REPOSITORIES {
                    return Err(());
                }
                repositories.entry(index).or_default().1 = value;
            } else if let Some(index) = indexed_key(&key, "repo_mount_") {
                if index >= MAX_REPOSITORIES {
                    return Err(());
                }
                repositories.entry(index).or_default().2 = value;
            } else if let Some(index) = indexed_key(&key, "app_port_") {
                if index >= MAX_APP_PORTS {
                    return Err(());
                }
                app_ports.entry(index).or_default().0 = value;
            } else if let Some(index) = indexed_key(&key, "app_label_") {
                if index >= MAX_APP_PORTS {
                    return Err(());
                }
                app_ports.entry(index).or_default().1 = value;
            } else if let Some(index) = indexed_key(&key, "app_access_") {
                if index >= MAX_APP_PORTS {
                    return Err(());
                }
                app_ports.entry(index).or_default().2 = value;
            } else if matches!(key.as_str(), "secret_project" | "credential_profile") {
                // Parsed exactly once by the metadata-only source adapter below.
            } else if key.starts_with("agent_secret_") {
                if !value.trim().is_empty() {
                    agent_secret_supplied = true;
                }
            } else {
                values.entry(key).or_insert(value);
            }
        }

        Ok(Self {
            csrf: take(&mut values, "_csrf"),
            name: take(&mut values, "name"),
            preset_id: take(&mut values, "preset_id"),
            image: take(&mut values, "image"),
            install_command: take(&mut values, "install_command"),
            startup_script: take(&mut values, "startup_script"),
            cpu: take(&mut values, "cpu"),
            memory: take(&mut values, "memory"),
            disk: take(&mut values, "disk"),
            ttl: take(&mut values, "ttl"),
            isolation_tier: take(&mut values, "isolation_tier"),
            repositories: repositories.into_values().collect(),
            agents,
            app_ports: app_ports.into_values().collect(),
            agent_secret_supplied,
            sources: crate::environment_source_forms::SourceSubmission::parse(bytes),
        })
    }

    fn form_view(&self, token: String) -> EnvironmentCreateFormView {
        let mut sources = crate::view::EnvironmentSourceFieldsView::default();
        if let Ok(submission) = &self.sources {
            submission.hydrate(&mut sources);
        }
        EnvironmentCreateFormView {
            csrf_token: token,
            expanded: true,
            name: self.name.trim().to_owned(),
            preset_id: self.preset_id.trim().to_owned(),
            image: self.image.trim().to_owned(),
            repositories: repository_rows(&self.repositories),
            install_command: self.install_command.clone(),
            startup_script: self.startup_script.clone(),
            cpu: self.cpu.trim().to_owned(),
            memory: self.memory.trim().to_owned(),
            disk: self.disk.trim().to_owned(),
            ttl: self.ttl.trim().to_owned(),
            isolation_tier: self.isolation_tier.trim().to_owned(),
            confidential_available: false,
            show_confidential_controls: false,
            confidential_price: String::new(),
            selected_agents: self.agents.clone(),
            app_ports: app_port_rows(&self.app_ports),
            presets: Vec::new(),
            agents: Vec::new(),
            sources,
            repo_error: String::new(),
            image_error: String::new(),
            name_error: String::new(),
            cpu_error: String::new(),
            memory_error: String::new(),
            disk_error: String::new(),
            ttl_error: String::new(),
            form_error: String::new(),
        }
    }

    fn apply_selected_preset_defaults(&mut self, options: &EnvironmentCreateOptions) {
        let Some(preset) = options
            .presets
            .iter()
            .find(|preset| preset.id == self.preset_id.trim())
        else {
            return;
        };
        if self.image.trim().is_empty() {
            self.image = preset.image.clone();
        }
        if self.cpu.trim().is_empty()
            && let Some(cpu) = preset.default_cpu_millicores
        {
            self.cpu = cpu.to_string();
        }
        if self.memory.trim().is_empty()
            && let Some(memory) = preset.default_memory_mib
        {
            self.memory = memory.to_string();
        }
        if self.disk.trim().is_empty()
            && let Some(disk) = preset.default_disk_gib
        {
            self.disk = disk.to_string();
        }
        if ttl_uses_default(&self.ttl)
            && let Some(ttl) = preset.default_ttl_seconds
        {
            self.ttl = format!("{ttl}s");
        }
        if self.install_command.is_empty() {
            self.install_command = preset.default_install_command.clone();
        }
        if self.startup_script.is_empty() {
            self.startup_script = preset.default_startup_script.clone();
        }
        if self.agents.is_empty() {
            self.agents = preset.default_agents.clone();
        }
        if self.app_ports.is_empty() {
            self.app_ports = preset
                .default_app_ports
                .iter()
                .map(|port| (port.port.clone(), port.label.clone(), port.access.clone()))
                .collect();
        }
    }

    fn validate_and_draft(
        &self,
        org_id: &str,
        form: &mut EnvironmentCreateFormView,
    ) -> Option<CreateEnvironmentRequest> {
        let mut repositories: Vec<RepositorySpec> = self
            .repositories
            .iter()
            .filter_map(|(url, branch, mount_path)| {
                let url = url.trim();
                (!url.is_empty()).then(|| RepositorySpec {
                    source: url.to_owned(),
                    revision: String::new(),
                    branch: branch.trim().to_owned(),
                    destination: workspace_mount_path(mount_path),
                    known_hosts: Vec::new(),
                })
            })
            .collect();

        if repositories
            .iter()
            .any(|repository| !valid_repository_url(&repository.source))
        {
            form.repo_error =
                "Repository URLs must be clean HTTP(S) URLs without embedded credentials."
                    .to_owned();
        }
        if repositories.is_empty()
            && self.image.trim().is_empty()
            && self.preset_id.trim().is_empty()
        {
            form.image_error = "Enter a workspace image or choose a repository.".to_owned();
        }
        match codewire_project::validate_repository_destinations(
            repositories
                .iter()
                .map(|repository| (repository.source.as_str(), repository.destination.as_str())),
        ) {
            Ok(destinations) => {
                for (repository, destination) in repositories.iter_mut().zip(destinations) {
                    repository.destination = destination;
                }
            }
            Err(_) => {
                form.repo_error =
                    "Repository destinations must be distinct paths inside /workspace.".to_owned();
            }
        }

        if self.name.len() > 128 || self.name.bytes().any(|byte| byte.is_ascii_control()) {
            form.name_error = "Name must be 128 characters or fewer.".to_owned();
        }
        let cpu = parse_bounded_i32(&self.cpu, 100, 128_000, "CPU", &mut form.cpu_error);
        let memory = parse_bounded_i32(
            &self.memory,
            128,
            1_048_576,
            "Memory",
            &mut form.memory_error,
        );
        let disk = parse_bounded_i32(&self.disk, 1, 16_384, "Disk", &mut form.disk_error);
        let ttl = parse_ttl(&self.ttl, &mut form.ttl_error);
        let agents = allowlisted_agents(&self.agents);
        if agents.len() != self.agents.len() {
            form.form_error = "One of the selected agents is not supported.".to_owned();
        }
        let isolation_tier = match self.isolation_tier.trim() {
            "" | "standard" => IsolationTier::Standard,
            "confidential" if form.confidential_available => IsolationTier::Confidential,
            "confidential" => {
                form.form_error =
                    "Confidential Sandboxes are not available for this organization.".to_owned();
                IsolationTier::Unspecified
            }
            _ => {
                form.form_error = "Choose a valid isolation tier.".to_owned();
                IsolationTier::Unspecified
            }
        };

        let mut ports = Vec::new();
        for (port, label, access) in &self.app_ports {
            if port.trim().is_empty() && label.trim().is_empty() {
                continue;
            }
            let Ok(port_number) = port.trim().parse::<i32>() else {
                form.form_error = "Application ports must be between 1 and 65535.".to_owned();
                continue;
            };
            if !(1..=65_535).contains(&port_number) || !valid_port_label(label.trim()) {
                form.form_error =
                    "Application ports need a valid port and lowercase label.".to_owned();
                continue;
            }
            ports.push(ApplicationPort {
                port: port_number as u16,
                label: label.trim().to_owned(),
                access: allowlisted_access(access).to_owned(),
            });
        }

        if self.agent_secret_supplied || self.sources.is_err() {
            form.form_error = PROTECTED_SECRET_ACCESS_UNAVAILABLE.to_owned();
        }

        if form.has_errors() {
            return None;
        }
        let working_directory = match repositories.as_slice() {
            [repository] => repository.destination.clone(),
            _ => "/workspace".to_owned(),
        };
        let project_spec = ProjectSpec {
            schema_version: PROJECT_SCHEMA_VERSION,
            image: self.image.trim().to_owned(),
            repositories,
            working_directory,
            install_command: self.install_command.clone(),
            startup_script: self.startup_script.clone(),
            agents: AgentsSpec {
                install: None,
                tools: agents,
            },
            application_ports: ports,
            resources: ResourceSpec {
                cpu_millicores: cpu.map(|value| value as u32),
                memory_mib: memory.map(|value| value as u64),
                disk_gib: disk.map(|value| value as u64),
            },
            ..ProjectSpec::default()
        };
        if project_spec.validate().is_err() {
            form.form_error = "The Sandbox project configuration is invalid.".to_owned();
            return None;
        }
        let mut request = CreateEnvironmentRequest {
            org_id: org_id.to_owned(),
            preset_id: nonempty(self.preset_id.trim()),
            name: nonempty(self.name.trim()),
            ttl_seconds: ttl,
            isolation_tier: isolation_tier.into(),
            project_spec: Some(codewire_project_proto::to_proto(project_spec)).into(),
            ..Default::default()
        };
        if self
            .sources
            .as_ref()
            .ok()?
            .apply_create(&mut request)
            .is_err()
        {
            form.form_error = PROTECTED_SECRET_ACCESS_UNAVAILABLE.to_owned();
            return None;
        }
        Some(request)
    }
}

fn validated_dashboard_project_spec(
    draft: &CreateEnvironmentRequest,
    presets: &[crate::view::EnvironmentPresetOption],
) -> Result<ProjectSpec, &'static str> {
    let project_spec = draft
        .project_spec
        .as_option()
        .cloned()
        .ok_or(PROJECT_SPEC_INVALID)
        .and_then(|project_spec| {
            codewire_project_proto::from_proto(project_spec).map_err(|_| PROJECT_SPEC_INVALID)
        })?;
    let preset_is_safe = match draft
        .preset_id
        .as_deref()
        .map(str::trim)
        .filter(|preset_id| !preset_id.is_empty())
    {
        Some(preset_id) => presets
            .iter()
            .find(|preset| preset.id == preset_id)
            .is_some_and(|preset| !preset.uses_protected_secret_bindings),
        None => true,
    };
    if crate::environment_source_forms::create_selection(draft).is_err() || !preset_is_safe {
        return Err(PROTECTED_SECRET_ACCESS_UNAVAILABLE);
    }
    if (project_spec.secrets.user.is_some() && !draft.confirm_personal_secrets)
        || (project_spec.credentials.is_some() && !draft.confirm_personal_credentials)
    {
        return Err(
            "Confirm personal application secrets and provider access independently before creating the Sandbox.",
        );
    }
    ensure_dashboard_project_support(&project_spec)?;
    Ok(project_spec)
}

fn ensure_dashboard_project_support(project_spec: &ProjectSpec) -> Result<(), &'static str> {
    let expected_working_directory = match project_spec.repositories.as_slice() {
        [repository] => repository.destination.as_str(),
        _ => "/workspace",
    };
    let repositories_supported = project_spec.repositories.iter().all(|repository| {
        repository.revision.is_empty()
            && valid_repository_url(&repository.source)
            && repository.destination.starts_with("/workspace/")
    });
    let ports_supported = project_spec.application_ports.len() <= MAX_APP_PORTS
        && project_spec.application_ports.iter().all(|port| {
            valid_port_label(&port.label)
                && matches!(port.access.as_str(), "creator" | "org_members" | "public")
        });
    let agents_supported = project_spec.agents.install.is_none()
        && allowlisted_agents(&project_spec.agents.tools).len() == project_spec.agents.tools.len();
    if !project_spec.preset.is_empty()
        || project_spec.working_directory != expected_working_directory
        || !project_spec.environment.is_empty()
        || !project_spec.skills.is_empty()
        || !repositories_supported
        || !ports_supported
        || !agents_supported
        || project_spec.install_command.len() > MAX_FIELD
        || project_spec.startup_script.len() > MAX_FIELD
    {
        return Err(PROJECT_FEATURE_UNAVAILABLE);
    }
    Ok(())
}

fn with_dashboard_draft<T>(
    draft: CreateEnvironmentRequest,
    presets: &[crate::view::EnvironmentPresetOption],
    dispatch: impl FnOnce(CreateEnvironmentRequest) -> T,
) -> Result<T, &'static str> {
    validated_dashboard_project_spec(&draft, presets)?;
    Ok(dispatch(draft))
}

pub(super) async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<EnvironmentsQuery>,
    headers: HeaderMap,
) -> Response {
    render_page(state, slug, query, headers, false).await
}

pub(super) async fn new_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<EnvironmentsQuery>,
    headers: HeaderMap,
) -> Response {
    render_page(state, slug, query, headers, true).await
}

async fn render_page(
    state: AppState,
    slug: String,
    query: EnvironmentsQuery,
    headers: HeaderMap,
    create_open: bool,
) -> Response {
    let continuation = if create_open {
        format!("/{slug}/new/")
    } else {
        environments_path(&slug)
    };
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let token = new_csrf_token();
    let form = default_create_form(token.clone(), create_open);
    let page = match build_page(
        &state,
        cookie,
        &organization,
        &query,
        form,
        dashboard.is_admin,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let websocket_origin = match crate::routes::terminal::browser_websocket_origin(
        &state.public_origin,
        &state.browser_api_origin,
    ) {
        Some(origin) => origin,
        None => return error_page(WebError::BrowserConfigurationUnavailable),
    };
    with_csrf_cookie(
        render_page_with_connect_origin(
            OrganizationEnvironmentsTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
            },
            &websocket_origin,
        ),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn list_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<EnvironmentsQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = environments_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut environments =
        match filtered_environments(&state, cookie, &organization.id, &query).await {
            Ok(environments) => environments,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    for environment in &mut environments {
        apply_confidential_visibility(&state, dashboard.is_admin, environment);
    }
    let token = csrf_cookie_value(&headers).unwrap_or_default().to_owned();
    let page = EnvironmentsPageView {
        environments,
        create_form: default_create_form(token, false),
        source_editor: None,
        port_panel: None,
        trust_summary: None,
        resize_confirmation: None,
        resize_operation: None,
        search: bounded_query(&query.search),
        state: allowlisted_state(&query.state).to_owned(),
        message: String::new(),
        error: String::new(),
    };
    render_template(
        StatusCode::OK,
        EnvironmentListTemplate {
            organization: &organization,
            page: &page,
        },
    )
}

pub(super) async fn rail_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let continuation = environments_path(&slug);
    let (dashboard, _, _) = match get_context(&state, &headers, &slug, &continuation).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    render_template(StatusCode::OK, SandboxRailTemplate { view: &dashboard })
}

pub(super) async fn create(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    RawForm(bytes): RawForm,
) -> Response {
    let mut submission = match EnvironmentSubmission::parse(&bytes) {
        Ok(submission) => submission,
        Err(()) => return error_page(WebError::CsrfRejected),
    };
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        environments_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let options =
        match environment_connect::create_options(&state, cookie.clone(), &organization.id).await {
            Ok(options) => options,
            Err(error) => return connect_page_error(error, &environments_path(&slug), &headers),
        };
    submission.apply_selected_preset_defaults(&options);
    let mut form = submission.form_view(submission.csrf.clone());
    hydrate_options(&mut form, options);
    let Some(draft) = submission.validate_and_draft(&organization.id, &mut form) else {
        return render_action_page(
            &state,
            &headers,
            dashboard,
            organization,
            cookie,
            form,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    };

    let create = match with_dashboard_draft(draft, &form.presets, |draft| {
        environment_connect::create_environment(&state, cookie.clone(), draft)
    }) {
        Ok(create) => create,
        Err(message) => {
            form.form_error = message.to_owned();
            return render_action_page(
                &state,
                &headers,
                dashboard,
                organization,
                cookie,
                form,
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };
    match create.await {
        Ok(_) => mutation_redirect(
            &state,
            environments_path(&slug),
            "environment-created",
            "",
            &headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(&slug), &headers)
        }
        Err(error) => {
            apply_create_error(&mut form, &error);
            render_action_page(
                &state,
                &headers,
                dashboard,
                organization,
                cookie,
                form,
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await
        }
    }
}

pub(super) async fn start(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<EnvironmentIdSubmission>,
) -> Response {
    lifecycle_action(
        &state,
        &headers,
        &slug,
        submission,
        "environment-started",
        |state, cookie, org_id, environment_id| {
            Box::pin(environment_connect::start_environment(
                state,
                cookie,
                org_id,
                environment_id,
            ))
        },
    )
    .await
}

pub(super) async fn update_sources(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    RawForm(bytes): RawForm,
) -> Response {
    let mut identity = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&bytes) {
        if matches!(key.as_ref(), "_csrf" | "environment_id")
            && (value.len() > MAX_FIELD
                || identity
                    .insert(key.into_owned(), value.into_owned())
                    .is_some())
        {
            return error_page(WebError::CsrfRejected);
        }
    }
    let csrf = take(&mut identity, "_csrf");
    let environment = take(&mut identity, "environment_id");
    if !valid_identifier(&environment) {
        return error_page(WebError::CsrfRejected);
    }
    let (_, organization, cookie) =
        match action_context(&state, &headers, &slug, &csrf, environments_path(&slug)).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let request = match crate::environment_source_forms::update_request(
        &bytes,
        &organization.id,
        &environment,
    ) {
        Ok(request) => request,
        Err(()) => {
            return mutation_redirect(
                &state,
                environments_path(&slug),
                "",
                "The source selection changed or is invalid. Reload and review it again.",
                &headers,
            );
        }
    };
    match environment_connect::update_environment_sources(&state, cookie, request).await {
        Ok(outcome) => mutation_redirect(&state, environments_path(&slug), outcome, "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(&slug), &headers)
        }
        Err(error) => mutation_redirect(
            &state,
            environments_path(&slug),
            "",
            match error.code {
                ErrorCode::Aborted | ErrorCode::AlreadyExists => {
                    "The Sandbox operation or sources changed. Reload before trying again."
                }
                ErrorCode::FailedPrecondition => {
                    "Review the selected profile revision, personal-access confirmations and restart confirmation, then try again."
                }
                ErrorCode::PermissionDenied => {
                    "You do not have permission to change this Sandbox's sources."
                }
                _ => {
                    "The source change could not be confirmed. Reload to check the current selection before trying again."
                }
            },
            &headers,
        ),
    }
}

pub(super) async fn stop(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<EnvironmentIdSubmission>,
) -> Response {
    lifecycle_action(
        &state,
        &headers,
        &slug,
        submission,
        "environment-stopping",
        |state, cookie, org_id, environment_id| {
            Box::pin(environment_connect::stop_environment(
                state,
                cookie,
                org_id,
                environment_id,
            ))
        },
    )
    .await
}

pub(super) async fn delete(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<EnvironmentIdSubmission>,
) -> Response {
    lifecycle_action(
        &state,
        &headers,
        &slug,
        submission,
        "environment-destroying",
        |state, cookie, org_id, environment_id| {
            Box::pin(environment_connect::delete_environment(
                state,
                cookie,
                org_id,
                environment_id,
            ))
        },
    )
    .await
}

pub(super) async fn resize_plan(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<ResizePlanSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        environments_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some((cpu_millicores, memory_mb, disk_gb)) = resize_submission_resources(
        &submission.environment_id,
        &submission.cpu_millicores,
        &submission.memory_mb,
        &submission.disk_gb,
    ) else {
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    };
    let result = environment_connect::plan_environment_resize(
        &state,
        cookie.clone(),
        organization.id.clone(),
        submission.environment_id,
        cpu_millicores,
        memory_mb,
        disk_gb,
    )
    .await;
    let response = match result {
        Ok(response) => response,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&environments_path(&slug), &headers);
        }
        Err(error) => {
            return mutation_redirect(
                &state,
                environments_path(&slug),
                "",
                mutation_error(&error),
                &headers,
            );
        }
    };
    let (plan, environment) = response;
    let form = default_create_form(submission.csrf, false);
    let query = EnvironmentsQuery::default();
    let mut page = match build_page(
        &state,
        cookie,
        &organization,
        &query,
        form,
        dashboard.is_admin,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => return connect_page_error(error, &environments_path(&slug), &headers),
    };
    page.resize_confirmation = Some(environment_connect::resize_confirmation(
        environment,
        plan,
        uuid::Uuid::new_v4().simple().to_string(),
    ));
    render_environments_page(
        &state,
        &headers,
        dashboard,
        organization,
        page,
        StatusCode::OK,
    )
}

pub(super) async fn resize_apply(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<ResizeApplySubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        environments_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some((cpu_millicores, memory_mb, disk_gb)) = resize_submission_resources(
        &submission.environment_id,
        &submission.cpu_millicores,
        &submission.memory_mb,
        &submission.disk_gb,
    ) else {
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    };
    if submission.request_id.trim().is_empty() || submission.request_id.len() > 128 {
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    }
    let allow_restart = checkbox_checked(&submission.allow_restart);
    let force = checkbox_checked(&submission.force);
    let response = environment_connect::resize_environment(
        &state,
        cookie,
        ResizeEnvironmentRequest {
            org_id: organization.id,
            environment_id: submission.environment_id.clone(),
            cpu_millicores,
            memory_mb,
            disk_gb,
            request_id: submission.request_id,
            force,
            disruption_policy: if allow_restart {
                EnvironmentResizeDisruptionPolicy::AllowRestart
            } else {
                EnvironmentResizeDisruptionPolicy::LiveOnly
            }
            .into(),
            ..Default::default()
        },
    )
    .await;
    let response = match response {
        Ok(response) => response,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&environments_path(&slug), &headers);
        }
        Err(error) => {
            return mutation_redirect(
                &state,
                environments_path(&slug),
                "",
                mutation_error(&error),
                &headers,
            );
        }
    };
    resize_operation_redirect(
        &state,
        &headers,
        &slug,
        &submission.environment_id,
        &response.id,
    )
}

pub(super) async fn resize_operation_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<EnvironmentsQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = environments_path(&slug);
    let (_, organization, cookie) = match get_context(&state, &headers, &slug, &continuation).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&query.resize_environment) || !valid_identifier(&query.resize_operation) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let operation = environment_connect::environment_resize_operation(
        &state,
        cookie,
        organization.id.clone(),
        query.resize_environment,
        query.resize_operation,
    )
    .await;
    let (operation, _) = match operation {
        Ok(operation) => operation,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    render_template(
        StatusCode::OK,
        EnvironmentResizeOperationTemplate {
            organization: &organization,
            operation: &environment_connect::resize_operation_view(operation),
        },
    )
}

pub(super) async fn create_port(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PortCreateSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        environments_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.environment_id) {
        if submission.dialog && headers.contains_key(HTMX_REQUEST) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    }
    let port = submission
        .port
        .parse::<i32>()
        .ok()
        .filter(|port| (1..=65_535).contains(port));
    let result = if let Some(port) = port.filter(|_| valid_port_label(&submission.label)) {
        match environment_connect::create_port(
            &state,
            cookie.clone(),
            CreatePortRequest {
                org_id: organization.id.clone(),
                environment_id: submission.environment_id.clone(),
                port,
                label: submission.label.clone(),
                access: port_access(&submission.access).into(),
                ..Default::default()
            },
        )
        .await
        {
            Ok(()) => "port-created",
            Err(error) if error.code == ErrorCode::Unauthenticated => {
                return login_redirect(&environments_path(&slug), &headers);
            }
            Err(error) if error.code == ErrorCode::PermissionDenied => "not-authorized",
            Err(_) => "port-unavailable",
        }
    } else {
        "invalid-port"
    };
    port_response(
        &state,
        &headers,
        &organization,
        cookie,
        dashboard.is_admin,
        PortActionView {
            environment_id: &submission.environment_id,
            modal: submission.dialog,
            result,
            draft: Some((&submission.port, &submission.label, &submission.access)),
        },
    )
    .await
}

pub(super) async fn delete_port(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PortDeleteSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        environments_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.environment_id) || !valid_identifier(&submission.port_id) {
        if submission.dialog && headers.contains_key(HTMX_REQUEST) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    }
    let result = match environment_connect::delete_port(
        &state,
        cookie.clone(),
        DeletePortRequest {
            org_id: organization.id.clone(),
            environment_id: submission.environment_id.clone(),
            port_id: submission.port_id,
            ..Default::default()
        },
    )
    .await
    {
        Ok(()) => "port-deleted",
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&environments_path(&slug), &headers);
        }
        Err(error) if error.code == ErrorCode::PermissionDenied => "not-authorized",
        Err(_) => "port-unavailable",
    };
    port_response(
        &state,
        &headers,
        &organization,
        cookie,
        dashboard.is_admin,
        PortActionView {
            environment_id: &submission.environment_id,
            modal: submission.dialog,
            result,
            draft: None,
        },
    )
    .await
}

pub(super) async fn port_fragment(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !super::terminal::canonical_environment_id(&environment_id)
        || !codewire_server_core::organization_slug::valid_organization_slug(&slug)
    {
        return error_page(WebError::NotFound);
    }
    let continuation = super::terminal::terminal_path(&slug, &environment_id);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    render_port_dialog(
        &state,
        &headers,
        &organization,
        cookie,
        dashboard.is_admin,
        PortActionView {
            environment_id: &environment_id,
            modal: true,
            result: "",
            draft: None,
        },
    )
    .await
}

struct PortActionView<'a> {
    environment_id: &'a str,
    modal: bool,
    result: &'a str,
    draft: Option<(&'a str, &'a str, &'a str)>,
}

async fn port_response(
    state: &AppState,
    headers: &HeaderMap,
    organization: &OrganizationContext,
    cookie: HeaderValue,
    is_admin: bool,
    action: PortActionView<'_>,
) -> Response {
    if action.modal && headers.contains_key(HTMX_REQUEST) {
        render_port_dialog(state, headers, organization, cookie, is_admin, action).await
    } else {
        ports_redirect(
            state,
            headers,
            &organization.slug,
            action.environment_id,
            action.result,
        )
    }
}

async fn render_port_dialog(
    state: &AppState,
    headers: &HeaderMap,
    organization: &OrganizationContext,
    cookie: HeaderValue,
    is_admin: bool,
    action: PortActionView<'_>,
) -> Response {
    if !super::terminal::canonical_environment_id(action.environment_id) {
        return error_page(WebError::NotFound);
    }
    let continuation = super::terminal::terminal_path(&organization.slug, action.environment_id);
    let mut environment = match environment_connect::environment(
        state,
        cookie.clone(),
        &organization.id,
        action.environment_id,
    )
    .await
    {
        Ok(environment) => environment,
        Err(error) => return connect_page_error(error, &continuation, headers),
    };
    apply_confidential_visibility(state, is_admin, &mut environment);
    if !environment.confidential_actions_allowed {
        return error_page(WebError::Forbidden);
    }
    let ports =
        match environment_connect::ports(state, cookie, &organization.id, action.environment_id)
            .await
        {
            Ok(ports) => ports,
            Err(error) => return connect_page_error(error, &continuation, headers),
        };
    let error = port_error(action.result);
    let (port, label, access) = if error.is_empty() {
        ("", "", "creator")
    } else {
        action.draft.unwrap_or(("", "", "creator"))
    };
    let panel = EnvironmentPortPanelView {
        environment_id: environment.id,
        environment_name: environment.name,
        ports,
        port: port.chars().take(16).collect(),
        label: label.chars().take(128).collect(),
        access: allowlisted_access(access).to_owned(),
        form_error: error.to_owned(),
    };
    // A partial response must not rotate the page's CSRF cookie or navigate
    // away: the terminal and every unswapped form still belong to that page.
    render_port_panel(
        organization,
        &panel,
        csrf_cookie_value(headers).unwrap_or_default(),
        page_message(action.result),
    )
}

fn render_port_panel(
    organization: &OrganizationContext,
    panel: &EnvironmentPortPanelView,
    csrf_token: &str,
    message: &str,
) -> Response {
    render_template(
        if panel.form_error.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        crate::templates::EnvironmentPortsTemplate {
            organization,
            panel,
            csrf_token,
            in_dialog: true,
            message,
        },
    )
}

type LifecycleFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ConnectError>> + Send + 'a>>;

async fn lifecycle_action<F>(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    submission: EnvironmentIdSubmission,
    message: &str,
    operation: F,
) -> Response
where
    F: for<'a> FnOnce(&'a AppState, HeaderValue, String, String) -> LifecycleFuture<'a>,
{
    let continuation =
        lifecycle_return_path(slug, &submission.environment_id, &submission.return_to);
    let (_, organization, cookie) =
        match action_context(state, headers, slug, &submission.csrf, continuation.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !valid_identifier(&submission.environment_id) {
        return mutation_redirect(state, environments_path(slug), "", "invalid", headers);
    }
    match operation(state, cookie, organization.id, submission.environment_id).await {
        Ok(()) => mutation_redirect(
            state,
            if message == "environment-destroying" {
                environments_path(slug)
            } else {
                continuation
            },
            message,
            "",
            headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, headers)
        }
        Err(error) => mutation_redirect(state, continuation, "", mutation_error(&error), headers),
    }
}

fn lifecycle_return_path(slug: &str, environment_id: &str, return_to: &str) -> String {
    if return_to == "detail" && super::terminal::canonical_environment_id(environment_id) {
        super::terminal::terminal_path(slug, environment_id)
    } else {
        environments_path(slug)
    }
}

pub(super) fn apply_confidential_visibility(
    state: &AppState,
    is_admin: bool,
    environment: &mut crate::view::EnvironmentRow,
) {
    environment.confidential_actions_allowed = confidential_interaction_visible(
        environment.isolation_tier,
        state.confidential_storage_enabled,
        state.confidential_admin_only,
        is_admin,
    );
}

fn confidential_interaction_visible(
    tier: &str,
    enabled: bool,
    admin_only: bool,
    is_admin: bool,
) -> bool {
    tier != "confidential" || (enabled && (!admin_only || is_admin))
}

async fn build_page(
    state: &AppState,
    cookie: HeaderValue,
    organization: &OrganizationContext,
    query: &EnvironmentsQuery,
    mut form: EnvironmentCreateFormView,
    is_admin: bool,
) -> Result<EnvironmentsPageView, ConnectError> {
    let mut environments =
        filtered_environments(state, cookie.clone(), &organization.id, query).await?;
    let confidential_actions_allowed =
        state.confidential_storage_enabled && (!state.confidential_admin_only || is_admin);
    for environment in &mut environments {
        apply_confidential_visibility(state, is_admin, environment);
    }
    hydrate_options(
        &mut form,
        environment_connect::create_options(state, cookie.clone(), &organization.id).await?,
    );
    let source_editor = if valid_identifier(&query.sources) {
        environments
            .iter()
            .find(|environment| {
                environment.id == query.sources
                    && environment.can_destroy
                    && environment.confidential_actions_allowed
            })
            .and_then(|environment| {
                environment.sources.as_ref().map(|expected| {
                    let mut fields = form.sources.clone();
                    fields.select_bound(&expected.selection);
                    fields.personal_secrets_confirmed = false;
                    fields.personal_credentials_confirmed = false;
                    crate::view::EnvironmentSourcesEditView {
                        environment_id: environment.id.clone(),
                        environment_name: environment.name.clone(),
                        expected: expected.clone(),
                        fields,
                    }
                })
            })
    } else {
        None
    };
    form.show_confidential_controls = confidential_actions_allowed;
    form.confidential_available &= confidential_actions_allowed;
    let port_panel = if valid_identifier(&query.ports) {
        environments
            .iter()
            .find(|environment| {
                environment.id == query.ports && environment.confidential_actions_allowed
            })
            .map(|environment| (environment.id.clone(), environment.name.clone()))
    } else {
        None
    };
    let port_panel = match port_panel {
        Some((environment_id, environment_name)) => Some(EnvironmentPortPanelView {
            ports: environment_connect::ports(
                state,
                cookie.clone(),
                &organization.id,
                &environment_id,
            )
            .await?,
            environment_id,
            environment_name,
            port: String::new(),
            label: String::new(),
            access: "creator".to_owned(),
            form_error: port_error(&query.error).to_owned(),
        }),
        None => None,
    };
    let trust_summary = if valid_identifier(&query.trust) {
        match environments.iter().find(|environment| {
            environment.id == query.trust && environment.confidential_actions_allowed
        }) {
            Some(environment) => Some(
                environment_connect::environment_trust_summary(
                    state,
                    cookie.clone(),
                    &organization.id,
                    &environment.id,
                    environment.name.clone(),
                )
                .await?,
            ),
            None => None,
        }
    } else {
        None
    };
    let resize_operation = if valid_identifier(&query.resize_environment)
        && valid_identifier(&query.resize_operation)
        && environments.iter().any(|environment| {
            environment.id == query.resize_environment && environment.confidential_actions_allowed
        }) {
        let (operation, _) = environment_connect::environment_resize_operation(
            state,
            cookie.clone(),
            organization.id.clone(),
            query.resize_environment.clone(),
            query.resize_operation.clone(),
        )
        .await?;
        Some(environment_connect::resize_operation_view(operation))
    } else {
        None
    };
    Ok(EnvironmentsPageView {
        environments,
        create_form: form,
        source_editor,
        port_panel,
        trust_summary,
        resize_confirmation: None,
        resize_operation,
        search: bounded_query(&query.search),
        state: allowlisted_state(&query.state).to_owned(),
        message: page_message(&query.message).to_owned(),
        error: page_error(&query.error).to_owned(),
    })
}

async fn filtered_environments(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    query: &EnvironmentsQuery,
) -> Result<Vec<crate::view::EnvironmentRow>, ConnectError> {
    let mut environments = environment_connect::environments(
        state,
        cookie,
        org_id,
        query.destroyed || query.state == "destroyed",
    )
    .await?;
    let search = bounded_query(&query.search).to_lowercase();
    let state_filter = allowlisted_state(&query.state);
    environments.retain(|environment| {
        (state_filter == "all" || environment.state == state_filter)
            && (search.is_empty()
                || environment.id.to_lowercase().contains(&search)
                || environment.name.to_lowercase().contains(&search)
                || environment.preset_name.to_lowercase().contains(&search))
    });
    Ok(environments)
}

async fn render_action_page(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: crate::view::DashboardView,
    organization: OrganizationContext,
    cookie: HeaderValue,
    form: EnvironmentCreateFormView,
    status: StatusCode,
) -> Response {
    let query = EnvironmentsQuery::default();
    let page = match build_page(
        state,
        cookie,
        &organization,
        &query,
        form,
        dashboard.is_admin,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => {
            return connect_page_error(error, &environments_path(&organization.slug), headers);
        }
    };
    let websocket_origin = match crate::routes::terminal::browser_websocket_origin(
        &state.public_origin,
        &state.browser_api_origin,
    ) {
        Some(origin) => origin,
        None => return error_page(WebError::BrowserConfigurationUnavailable),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            status,
            OrganizationEnvironmentsContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template_with_connect_origin(
            status,
            OrganizationEnvironmentsTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
            },
            &websocket_origin,
        )
    }
}

fn render_environments_page(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: crate::view::DashboardView,
    organization: OrganizationContext,
    page: EnvironmentsPageView,
    status: StatusCode,
) -> Response {
    let websocket_origin = match crate::routes::terminal::browser_websocket_origin(
        &state.public_origin,
        &state.browser_api_origin,
    ) {
        Some(origin) => origin,
        None => return error_page(WebError::BrowserConfigurationUnavailable),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            status,
            OrganizationEnvironmentsContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template_with_connect_origin(
            status,
            OrganizationEnvironmentsTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
            },
            &websocket_origin,
        )
    }
}

fn default_create_form(token: String, expanded: bool) -> EnvironmentCreateFormView {
    EnvironmentCreateFormView {
        csrf_token: token,
        expanded,
        name: String::new(),
        preset_id: String::new(),
        image: "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff".to_owned(),
        repositories: vec![EnvironmentRepositoryFormRow {
            index: 100,
            url: String::new(),
            branch: String::new(),
            mount_path: String::new(),
        }],
        install_command: String::new(),
        startup_script: String::new(),
        cpu: "1000".to_owned(),
        memory: "2048".to_owned(),
        disk: "10".to_owned(),
        ttl: DEFAULT_TTL.to_owned(),
        isolation_tier: "standard".to_owned(),
        confidential_available: false,
        show_confidential_controls: false,
        confidential_price: String::new(),
        selected_agents: Vec::new(),
        app_ports: Vec::new(),
        presets: Vec::new(),
        agents: Vec::new(),
        sources: Default::default(),
        repo_error: String::new(),
        image_error: String::new(),
        name_error: String::new(),
        cpu_error: String::new(),
        memory_error: String::new(),
        disk_error: String::new(),
        ttl_error: String::new(),
        form_error: String::new(),
    }
}

fn hydrate_options(form: &mut EnvironmentCreateFormView, options: EnvironmentCreateOptions) {
    form.presets = options.presets;
    form.agents = options.agents;
    form.confidential_available = options.confidential_available;
    form.confidential_price = options.confidential_price;
    let mut sources = options.sources;
    sources.retain_submission(&form.sources);
    form.sources = sources;
}

fn apply_create_error(form: &mut EnvironmentCreateFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "project_spec.repositories" | "project_spec.repositories.source" => {
                form.repo_error = description;
            }
            "project_spec.image" | "preset_id" => form.image_error = description,
            "name" => form.name_error = description,
            "project_spec.resources.cpu_millicores" => form.cpu_error = description,
            "project_spec.resources.memory_mib" => form.memory_error = description,
            "project_spec.resources.disk_gib" => form.disk_error = description,
            "ttl_seconds" => form.ttl_error = description,
            _ => {}
        }
    }
    if !form.has_errors() {
        form.form_error = create_error_message(error).to_owned();
    }
}

fn create_error_message(error: &ConnectError) -> &'static str {
    match connect_error_reason(error).as_deref() {
        Some("PROJECT_FEATURE_PENDING") => {
            return "This repository has no saved Sandbox configuration. Enter a workspace image or use a configured repository.";
        }
        Some("INVALID_REPO_URL") => return "Enter a valid repository URL.",
        Some("REPO_NOT_FOUND") => {
            return "The repository was not found. Check the URL and repository access.";
        }
        Some("REPO_NOT_ACCESSIBLE") => {
            return "The repository could not be read. Check its URL and repository access.";
        }
        _ => {}
    }
    match error.code {
        ErrorCode::InvalidArgument => "The repository or Sandbox options are invalid.",
        ErrorCode::FailedPrecondition => "This Sandbox configuration cannot be created yet.",
        ErrorCode::PermissionDenied => "You do not have permission to create this Sandbox.",
        ErrorCode::DeadlineExceeded => "Sandbox creation took too long and was cancelled.",
        _ => "Sandbox creation is temporarily unavailable.",
    }
}

fn indexed_key(key: &str, prefix: &str) -> Option<usize> {
    key.strip_prefix(prefix)?.parse().ok()
}

fn take(values: &mut HashMap<String, String>, key: &str) -> String {
    values.remove(key).unwrap_or_default()
}

fn repository_rows(values: &[(String, String, String)]) -> Vec<EnvironmentRepositoryFormRow> {
    let values = if values.is_empty() {
        vec![(String::new(), String::new(), String::new())]
    } else {
        values.to_vec()
    };
    values
        .into_iter()
        .enumerate()
        .map(
            |(index, (url, branch, mount_path))| EnvironmentRepositoryFormRow {
                index: index + 100,
                url,
                branch,
                mount_path,
            },
        )
        .collect()
}

fn app_port_rows(values: &[(String, String, String)]) -> Vec<EnvironmentAppPortFormRow> {
    values
        .iter()
        .enumerate()
        .map(|(index, (port, label, access))| EnvironmentAppPortFormRow {
            index,
            port: port.clone(),
            label: label.clone(),
            access: allowlisted_access(access).to_owned(),
        })
        .collect()
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn valid_repository_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn workspace_mount_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "/workspace" || value == "/workspace/" {
        return String::new();
    }
    let suffix = value
        .strip_prefix("/workspace/")
        .unwrap_or(value)
        .trim_start_matches('/');
    format!("/workspace/{suffix}")
}

fn parse_bounded_i32(
    value: &str,
    minimum: i32,
    maximum: i32,
    label: &str,
    error: &mut String,
) -> Option<i32> {
    if value.trim().is_empty() {
        return None;
    }
    match value.trim().parse::<i32>() {
        Ok(value) if (minimum..=maximum).contains(&value) => Some(value),
        _ => {
            *error = format!("{label} must be between {minimum} and {maximum}.");
            None
        }
    }
}

fn parse_ttl(value: &str, error: &mut String) -> Option<i32> {
    let value = value.trim();
    if ttl_uses_default(value) {
        return None;
    }
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1_i64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        Some(b'd') => (&value[..value.len() - 1], 86_400),
        _ => (value, 60),
    };
    match digits
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
    {
        Some(seconds) if (60..=31_536_000).contains(&seconds) => Some(seconds as i32),
        _ => {
            *error = "TTL must be infinity or 60 seconds to 365 days, such as 8h or 7d.".to_owned();
            None
        }
    }
}

fn ttl_uses_default(value: &str) -> bool {
    let value = value.trim();
    value.is_empty() || value == "0" || value.eq_ignore_ascii_case(DEFAULT_TTL) || value == "∞"
}

fn allowlisted_agents(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| {
            matches!(
                value.as_str(),
                "claude-code" | "codex" | "gemini-cli" | "kimi-code" | "pi" | "aider"
            )
        })
        .cloned()
        .collect()
}

fn valid_port_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=22).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn allowlisted_access(value: &str) -> &'static str {
    match value {
        "public" => "public",
        "org_members" => "org_members",
        _ => "creator",
    }
}

fn port_access(value: &str) -> PortAccess {
    match value {
        "public" => PortAccess::Public,
        "org_members" => PortAccess::OrgMembers,
        _ => PortAccess::Creator,
    }
}

fn bounded_query(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

fn allowlisted_state(value: &str) -> &'static str {
    match value {
        "running" => "running",
        "stopped" => "stopped",
        "pending" => "pending",
        "creating" => "creating",
        "starting" => "starting",
        "stopping" => "stopping",
        "error" => "error",
        "destroyed" => "destroyed",
        _ => "all",
    }
}

fn mutation_error(error: &ConnectError) -> &'static str {
    match error.code {
        ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition => "invalid",
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::NotFound => "not-found",
        _ => "unavailable",
    }
}

pub(super) fn page_message(value: &str) -> &'static str {
    match value {
        "environment-created" => "Sandbox creation started.",
        "environment-started" => "Sandbox start requested.",
        "environment-stopping" => "Sandbox stop requested.",
        "environment-destroying" => "Sandbox destruction requested.",
        "environment-sources-unchanged" => "Sandbox sources are unchanged.",
        "environment-sources-stored" => "Sandbox sources saved. The Sandbox remains stopped.",
        "environment-sources-restarting" => "Sandbox sources saved; managed restart requested.",
        "port-created" => "Port created.",
        "port-deleted" => "Port deleted.",
        _ => "",
    }
}

fn resize_submission_resources(
    environment_id: &str,
    cpu_millicores: &str,
    memory_mb: &str,
    disk_gb: &str,
) -> Option<(i32, i32, i32)> {
    if !valid_identifier(environment_id) {
        return None;
    }
    Some((
        cpu_millicores
            .trim()
            .parse()
            .ok()
            .filter(|value: &i32| (100..=128_000).contains(value))?,
        memory_mb
            .trim()
            .parse()
            .ok()
            .filter(|value: &i32| (128..=1_048_576).contains(value))?,
        disk_gb
            .trim()
            .parse()
            .ok()
            .filter(|value: &i32| (1..=16_384).contains(value))?,
    ))
}

fn checkbox_checked(value: &str) -> bool {
    matches!(value, "on" | "true")
}

fn resize_operation_redirect(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    environment_id: &str,
    operation_id: &str,
) -> Response {
    let mut target = Url::parse(&format!(
        "http://codewire.invalid{}",
        environments_path(slug)
    ))
    .expect("fixed dashboard URL is valid");
    target
        .query_pairs_mut()
        .append_pair("resize_environment", environment_id)
        .append_pair("resize_operation", operation_id);
    let target = format!(
        "{}{}",
        target.path(),
        target
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    );
    mutation_redirect(state, target, "", "", headers)
}

pub(super) fn page_error(value: &str) -> &'static str {
    match value {
        "invalid" => "The Sandbox request was invalid for its current state.",
        "not-authorized" => "You do not have permission to change that Sandbox.",
        "not-found" => "The Sandbox no longer exists.",
        "unavailable" => "The Sandbox service is temporarily unavailable.",
        _ => "",
    }
}

fn port_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change this preview.",
        "invalid-port" => "Port must be 1–65535 with a lowercase 2–22 character label.",
        "port-unavailable" => {
            "The port change could not be confirmed. Check the current list before trying again."
        }
        _ => "",
    }
}

fn ports_redirect(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    environment_id: &str,
    result: &str,
) -> Response {
    let mut target = environments_path(slug);
    target.push_str("?ports=");
    target.push_str(environment_id);
    if result.starts_with("port-") && matches!(result, "port-created" | "port-deleted") {
        target.push_str("&message=");
    } else {
        target.push_str("&error=");
    }
    target.push_str(result);
    mutation_redirect(state, target, "", "", headers)
}

fn environments_path(slug: &str) -> String {
    format!("/{slug}/")
}

#[cfg(test)]
mod tests {
    use askama::Template as _;

    use super::*;
    use crate::templates::EnvironmentCreateFormTemplate;

    #[tokio::test]
    async fn port_fragments_preserve_the_existing_csrf_token_and_terminal_document() {
        let panel = EnvironmentPortPanelView {
            environment_id: "5d1db799-4300-4ab3-b957-efb980760542".into(),
            environment_name: "Example".into(),
            ports: vec![crate::view::EnvironmentPortRow {
                id: "port-id".into(),
                port: 3000,
                label: "web".into(),
                access: "Creator",
                preview_url: "https://web-5d1db-test.preview.example".into(),
                has_preview: true,
            }],
            port: "8080".into(),
            label: "<invalid>".into(),
            access: "creator".into(),
            form_error: "Check the preview label.".into(),
        };
        let response =
            render_port_panel(&test_organization(), &panel, "existing-synthetic-csrf", "");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        for absent in [
            "set-cookie",
            "hx-redirect",
            "hx-location",
            "hx-refresh",
            "location",
        ] {
            assert!(
                !response.headers().contains_key(absent),
                "unexpected {absent}"
            );
        }
        let body = axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            html.matches("name=\"_csrf\" value=\"existing-synthetic-csrf\"")
                .count(),
            2
        );
        assert!(html.contains("hx-target=\"#sandbox-ports-content\""));
        assert!(html.contains("Internal 3000"));
        assert!(html.contains("https://web-5d1db-test.preview.example"));
        assert!(html.contains("name=\"port\" type=\"number\""));
        assert!(html.contains("value=\"8080\""));
        assert!(html.contains("Check the preview label."));
        assert!(!html.contains("<invalid>"));
        assert!(html.contains("Sandbox creator"));
        for forbidden in [
            "<html",
            "<script",
            "data-terminal-root",
            "Only me",
            "External port",
        ] {
            assert!(!html.contains(forbidden), "unexpected {forbidden}");
        }
        let plain = crate::templates::EnvironmentPortsTemplate {
            organization: &test_organization(),
            panel: &panel,
            csrf_token: "synthetic",
            in_dialog: false,
            message: "",
        }
        .render()
        .unwrap();
        assert!(!plain.contains("hx-post="));
        assert!(plain.contains("method=\"post\""));
    }

    #[test]
    fn lifecycle_returns_only_to_the_validated_current_sandbox() {
        let id = "5d1db799-4300-4ab3-b957-efb980760542";
        assert_eq!(
            lifecycle_return_path("my-org", id, "detail"),
            format!("/my-org/{id}/")
        );
        for target in [
            "",
            "list",
            "//evil.test",
            "https://evil.test/",
            "/other-org/",
            "Detail",
        ] {
            assert_eq!(lifecycle_return_path("my-org", id, target), "/my-org/");
        }
        for invalid in [
            "",
            "other-env",
            "../other",
            "5D1DB799-4300-4AB3-B957-EFB980760542",
        ] {
            assert_eq!(
                lifecycle_return_path("my-org", invalid, "detail"),
                "/my-org/"
            );
        }
        let legacy: EnvironmentIdSubmission = serde_json::from_value(serde_json::json!({
            "_csrf": "synthetic", "environment_id": id,
        }))
        .unwrap();
        assert_eq!(legacy.return_to, "");
    }

    #[test]
    fn confidential_visibility_is_identical_for_pages_and_fragments() {
        for enabled in [false, true] {
            for admin_only in [false, true] {
                for is_admin in [false, true] {
                    assert!(confidential_interaction_visible(
                        "standard", enabled, admin_only, is_admin
                    ));
                    assert_eq!(
                        confidential_interaction_visible(
                            "confidential",
                            enabled,
                            admin_only,
                            is_admin
                        ),
                        enabled && (!admin_only || is_admin),
                    );
                }
            }
        }
    }

    fn test_organization() -> OrganizationContext {
        OrganizationContext {
            id: "org-test".into(),
            name: "Test".into(),
            slug: "test".into(),
            role: "owner",
            can_admin: true,
            environments_url: "/test/".into(),
            snapshots_url: "/test/snapshots/".into(),
            presets_url: "/test/presets/".into(),
            secrets_url: "/test/secrets/".into(),
            api_keys_url: "/test/api-keys/".into(),
            members_url: "/test/members/".into(),
            billing_url: "/test/billing/".into(),
        }
    }

    fn test_preset(
        id: &str,
        uses_protected_secret_bindings: bool,
    ) -> crate::view::EnvironmentPresetOption {
        crate::view::EnvironmentPresetOption {
            id: id.to_owned(),
            name: "Preset".to_owned(),
            description: String::new(),
            image: "example.test/workspace@sha256:abc".to_owned(),
            default_cpu_millicores: Some(1_000),
            default_memory_mib: Some(2_048),
            default_disk_gib: Some(10),
            default_ttl_seconds: None,
            default_install_command: String::new(),
            default_startup_script: String::new(),
            default_agents: Vec::new(),
            default_app_ports: Vec::new(),
            uses_protected_secret_bindings,
            official: false,
        }
    }

    #[test]
    fn confidential_controls_are_hidden_by_the_dashboard_gate() {
        let organization = test_organization();
        let mut form = default_create_form("csrf".into(), true);
        form.confidential_available = true;
        form.show_confidential_controls = false;
        let hidden = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .unwrap();
        assert!(!hidden.contains("environment-isolation-tier"));

        form.show_confidential_controls = true;
        let visible = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .unwrap();
        assert!(visible.contains("environment-isolation-tier"));
    }

    #[test]
    fn resource_values_outside_the_catalog_round_trip_in_the_form() {
        let organization = test_organization();
        let mut form = default_create_form("csrf".into(), true);
        form.cpu = "750".to_owned();
        form.memory = "1024".to_owned();
        form.disk = "5".to_owned();

        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .expect("environment create form");

        assert!(html.contains("<option value=\"750\" selected>750 millicores</option>"));
        assert!(html.contains("<option value=\"1024\" selected>1024 MiB</option>"));
        assert!(html.contains("<option value=\"5\" selected>5 GiB</option>"));
    }

    #[test]
    fn confidential_interactive_actions_hide_without_hiding_stop_or_destroy() {
        let organization = test_organization();
        let page = EnvironmentsPageView {
            environments: vec![crate::view::EnvironmentRow {
                id: "env-test".into(),
                name: "Confidential test".into(),
                state: "running",
                state_tone: "success",
                state_symbol: "●",
                preset_name: String::new(),
                isolation_tier: "confidential",
                last_event: String::new(),
                created: String::new(),
                deletion_state: "unscheduled",
                shutdown_at: None,
                shutdown_at_label: "Not currently scheduled".into(),
                cost: String::new(),
                running_time: String::new(),
                resources: String::new(),
                cpu_millicores: 1000,
                memory_mb: 2048,
                disk_gb: 10,
                hourly_rate: String::new(),
                can_start: false,
                can_stop: true,
                can_destroy: true,
                confidential_actions_allowed: false,
                vscode_url: "https://vscode.invalid".into(),
                ports: Vec::new(),
                sources: None,
            }],
            create_form: default_create_form("csrf".into(), false),
            source_editor: None,
            port_panel: None,
            trust_summary: None,
            resize_confirmation: None,
            resize_operation: None,
            search: String::new(),
            state: "all".into(),
            message: String::new(),
            error: String::new(),
        };
        let rendered = EnvironmentListTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .unwrap();
        assert!(rendered.contains(">Stop</button>"));
        assert!(rendered.contains("Destroy permanently"));
        for hidden in [
            ">Start</button>",
            ">Resize</summary>",
            ">Ports</a>",
            ">Terminal</a>",
            ">VS Code</a>",
        ] {
            assert!(!rendered.contains(hidden), "unexpected action {hidden}");
        }
    }

    #[test]
    fn repository_urls_reject_credentials_and_unsafe_schemes() {
        assert!(valid_repository_url("https://github.com/codewire/codewire"));
        assert!(valid_repository_url(
            "https://github.com/noeljackson/stocks"
        ));
        assert!(!valid_repository_url("https://token@example.test/private"));
        assert!(!valid_repository_url("file:///etc/passwd"));
    }

    #[test]
    fn unknown_repository_configuration_maps_to_a_bounded_create_error() {
        let detail = codewire_proto::google::rpc::ErrorInfo {
            reason: "PROJECT_FEATURE_PENDING".to_owned(),
            domain: "codewire.dev".to_owned(),
            ..Default::default()
        };
        let error = ConnectError::invalid_argument("untrusted upstream detail").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &detail),
        );
        let mut form = default_create_form("token".to_owned(), true);

        apply_create_error(&mut form, &error);

        assert_eq!(
            form.form_error,
            "This repository has no saved Sandbox configuration. Enter a workspace image or use a configured repository."
        );
        assert!(form.repo_error.is_empty());
        assert!(!form.form_error.contains("untrusted upstream detail"));
    }

    #[test]
    fn invalid_or_retired_source_fields_are_rejected_without_retaining_values() {
        for bytes in [
            &b"image=example.test%2Fworkspace&secret_project=development"[..],
            &b"image=example.test%2Fworkspace&secret_project=&secret_project=development"[..],
            &b"image=example.test%2Fworkspace&include_org_secrets=true"[..],
            &b"image=example.test%2Fworkspace&include_user_secrets=true"[..],
            &b"image=example.test%2Fworkspace&credential_profile=profile-id%407"[..],
            &b"image=example.test%2Fworkspace&credential_profile=&credential_profile=profile-id%407"[..],
            &b"image=example.test%2Fworkspace&agent_secret_OPENAI_API_KEY=write-only-marker"[..],
            &b"image=example.test%2Fworkspace&agent_secret_forged-name=write-only-marker"[..],
            &b"image=example.test%2Fworkspace&agent_secret_OPENAI_API_KEY=&agent_secret_OPENAI_API_KEY=write-only-marker&agent_secret_OPENAI_API_KEY="[..],
        ] {
            let submission = EnvironmentSubmission::parse(bytes).expect("submission");
            let mut form = submission.form_view("token".to_owned());

            assert!(
                submission
                    .validate_and_draft("org-test", &mut form)
                    .is_none()
            );
            assert_eq!(form.form_error, PROTECTED_SECRET_ACCESS_UNAVAILABLE);
            assert!(!form.form_error.contains("write-only-marker"));
        }
    }

    #[test]
    fn no_selection_emits_one_canonical_source_free_project_spec() {
        let submission =
            EnvironmentSubmission::parse(b"image=example.test%2Fworkspace").expect("submission");
        let mut form = submission.form_view("token".to_owned());

        let draft = submission
            .validate_and_draft("org-test", &mut form)
            .expect("safe draft");

        let project_spec = validated_dashboard_project_spec(&draft, &[]).expect("project spec");
        assert_eq!(project_spec.image, "example.test/workspace");
        assert!(project_spec.secrets.is_empty());
    }

    #[test]
    fn selected_create_preserves_explicit_source_intent_on_rerender() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let submission = EnvironmentSubmission::parse(format!(
            "image=example.test%2Fworkspace&secret_project={id}&credential_profile={id}%407&include_user_secrets=platform"
        ).as_bytes()).unwrap();
        let mut form = submission.form_view("token".into());
        let options = || EnvironmentCreateOptions {
            presets: vec![],
            agents: vec![],
            confidential_available: false,
            confidential_price: String::new(),
            sources: crate::view::EnvironmentSourceFieldsView {
                application_selection_enabled: true,
                credential_selection_enabled: true,
                projects: vec![crate::view::EnvironmentSecretProjectOption {
                    id: id.into(),
                    name: "development".into(),
                    selected: false,
                }],
                profiles: vec![crate::view::EnvironmentCredentialProfileOption {
                    id: id.into(),
                    name: "work".into(),
                    revision: 7,
                    identity_count: 2,
                    bound_revision: false,
                    selected: false,
                }],
                ..Default::default()
            },
        };
        hydrate_options(&mut form, options());
        let draft = submission
            .validate_and_draft("org-test", &mut form)
            .unwrap();
        let spec = validated_dashboard_project_spec(&draft, &[]).unwrap();
        assert_eq!(spec.secrets.project, format!("platform:id:{id}"));
        assert_eq!(draft.expected_profile_revision, Some(7));
        assert!(draft.confirm_personal_secrets && draft.confirm_personal_credentials);
        form.name_error = "Choose another name.".into();
        hydrate_options(&mut form, options());
        assert!(form.sources.projects[0].selected && form.sources.profiles[0].selected);
        assert!(
            form.sources.personal_secrets_confirmed && form.sources.personal_credentials_confirmed
        );
        let mut no_credentials_consent = draft;
        no_credentials_consent.confirm_personal_credentials = false;
        assert!(validated_dashboard_project_spec(&no_credentials_consent, &[]).is_err());
    }

    #[test]
    fn edit_form_preserves_exact_cas_and_can_clear_a_deleted_bound_project() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let selection = crate::environment_source_forms::SourceSubmission::parse(
            format!("secret_project={id}&include_user_secrets=platform").as_bytes(),
        )
        .unwrap()
        .selection;
        let mut fields = crate::view::EnvironmentSourceFieldsView {
            application_selection_enabled: true,
            credential_selection_enabled: true,
            ..Default::default()
        };
        fields.select_bound(&selection);
        let mut page = EnvironmentsPageView {
            environments: vec![],
            create_form: default_create_form("csrf-token".into(), false),
            source_editor: Some(crate::view::EnvironmentSourcesEditView {
                environment_id: id.into(),
                environment_name: "<unsafe>".into(),
                fields,
                expected: crate::view::EnvironmentSourcesSummaryView {
                    selection,
                    operation_generation: 9,
                    project: format!("platform:id:{id}"),
                    organization: false,
                    personal: true,
                    profile: String::new(),
                    profile_revision: String::new(),
                },
            }),
            port_panel: None,
            trust_summary: None,
            resize_confirmation: None,
            resize_operation: None,
            search: String::new(),
            state: "all".into(),
            message: String::new(),
            error: String::new(),
        };
        let organization = test_organization();
        let render = |page: &EnvironmentsPageView| {
            OrganizationEnvironmentsContentTemplate {
                organization: &organization,
                page,
            }
            .render()
            .unwrap()
        };
        let html = render(&page);
        assert!(html.contains("name=\"expected_operation_generation\" value=\"9\""));
        assert!(html.contains(&format!("name=\"expected_secret_project\" value=\"{id}\"")));
        assert!(html.contains("name=\"expected_include_user_secrets\" value=\"platform\""));
        assert!(!html.contains("name=\"confirm_personal_secrets\""));
        assert!(!html.contains("name=\"confirm_personal_credentials\""));
        assert!(html.contains("type=\"submit\">Save sources</button>"));
        assert!(!html.contains("<unsafe>"));
        let request = crate::environment_source_forms::update_request(format!(
            "expected_operation_generation=9&expected_secret_project={id}&expected_include_user_secrets=platform&secret_project=&credential_profile="
        ).as_bytes(), "org", id).unwrap();
        assert_eq!(
            request
                .expected
                .as_option()
                .unwrap()
                .secrets
                .as_option()
                .unwrap()
                .project,
            format!("platform:id:{id}")
        );
        assert!(
            request
                .replacement
                .as_option()
                .unwrap()
                .secrets
                .as_option()
                .unwrap()
                .project
                .is_empty()
        );
        assert!(!request.confirm_personal_secrets && !request.confirm_personal_credentials);
        page.source_editor.as_mut().unwrap().fields.project_error = "Catalog unavailable".into();
        assert!(render(&page).contains("type=\"submit\" disabled>Save sources</button>"));
    }

    #[test]
    fn unsafe_drafts_never_invoke_the_dispatch_closure() {
        fn assert_not_dispatched(
            draft: CreateEnvironmentRequest,
            presets: &[crate::view::EnvironmentPresetOption],
        ) {
            let dispatched = std::cell::Cell::new(false);
            let result = with_dashboard_draft(draft, presets, |_| dispatched.set(true));
            assert_eq!(result, Err(PROTECTED_SECRET_ACCESS_UNAVAILABLE));
            assert!(!dispatched.get());
        }

        let safe_project_spec = ProjectSpec {
            image: "example.test/workspace@sha256:abc".to_owned(),
            ..Default::default()
        };
        let dispatched = std::cell::Cell::new(false);
        let missing = with_dashboard_draft(CreateEnvironmentRequest::default(), &[], |_| {
            dispatched.set(true)
        });
        assert_eq!(missing, Err(PROJECT_SPEC_INVALID));
        assert!(!dispatched.get());
        for secrets in [
            codewire_project::SecretBindings {
                project: "development".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
        ] {
            let project_spec = ProjectSpec {
                secrets,
                ..safe_project_spec.clone()
            };
            assert_not_dispatched(
                CreateEnvironmentRequest {
                    project_spec: Some(codewire_project_proto::to_proto(project_spec)).into(),
                    ..Default::default()
                },
                &[],
            );
        }
        let safe = CreateEnvironmentRequest {
            project_spec: Some(codewire_project_proto::to_proto(safe_project_spec)).into(),
            ..Default::default()
        };
        assert_not_dispatched(
            CreateEnvironmentRequest {
                preset_id: Some("missing-preset".to_owned()),
                ..safe.clone()
            },
            &[],
        );
        assert_not_dispatched(
            CreateEnvironmentRequest {
                preset_id: Some("unsafe-preset".to_owned()),
                ..safe.clone()
            },
            &[test_preset("unsafe-preset", true)],
        );

        let dispatched = std::cell::Cell::new(false);
        let result = with_dashboard_draft(
            CreateEnvironmentRequest {
                preset_id: Some("safe-preset".to_owned()),
                ..safe
            },
            &[test_preset("safe-preset", false)],
            |_| {
                dispatched.set(true);
                "sent"
            },
        );
        assert_eq!(result, Ok("sent"));
        assert!(dispatched.get());
    }

    #[test]
    fn preset_defaults_fill_missing_resources_without_overwriting_edits() {
        let mut submission =
            EnvironmentSubmission::parse(b"preset_id=preset-id&cpu=750").expect("submission");
        let options = EnvironmentCreateOptions {
            confidential_available: false,
            confidential_price: String::new(),
            presets: vec![crate::view::EnvironmentPresetOption {
                id: "preset-id".to_owned(),
                name: "Preset".to_owned(),
                description: String::new(),
                image: "example.test/workspace@sha256:abc".to_owned(),
                default_cpu_millicores: Some(500),
                default_memory_mib: Some(1_024),
                default_disk_gib: Some(5),
                default_ttl_seconds: Some(3_600),
                default_install_command: "install-dependencies".to_owned(),
                default_startup_script: "start-services".to_owned(),
                default_agents: vec!["codex".to_owned()],
                default_app_ports: vec![EnvironmentAppPortFormRow {
                    index: 0,
                    port: "3000".to_owned(),
                    label: "web".to_owned(),
                    access: "creator".to_owned(),
                }],
                uses_protected_secret_bindings: true,
                official: false,
            }],
            agents: Vec::new(),
            sources: Default::default(),
        };

        submission.apply_selected_preset_defaults(&options);

        assert_eq!(submission.cpu, "750");
        assert_eq!(submission.memory, "1024");
        assert_eq!(submission.disk, "5");
        assert_eq!(submission.ttl, "3600s");
        assert_eq!(submission.image, "example.test/workspace@sha256:abc");
        assert_eq!(submission.install_command, "install-dependencies");
        assert_eq!(submission.startup_script, "start-services");
        assert_eq!(submission.agents, vec!["codex"]);
        let sources = submission.sources.as_ref().ok().unwrap();
        assert!(sources.selection.credentials.is_unset());
        assert_eq!(
            sources.selection.secrets.as_option().unwrap(),
            &codewire_proto::codewire::v1::ProjectSecretBindings::default()
        );
        assert_eq!(submission.app_ports[0].0, "3000");

        let mut form = submission.form_view("token".to_owned());
        form.presets = options.presets;
        let draft = submission
            .validate_and_draft("org-test", &mut form)
            .expect("source-free submitted fields");
        assert_eq!(
            validated_dashboard_project_spec(&draft, &form.presets),
            Err(PROTECTED_SECRET_ACCESS_UNAVAILABLE)
        );
    }

    #[test]
    fn workspace_image_and_repositories_are_complementary_inputs() {
        let submission = EnvironmentSubmission::parse(
            b"image=ghcr.io%2Fcodewiresh%2Fworkspace%40sha256%3A18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff&repo_url_0=https%3A%2F%2Fexample.test%2Frepo&preset_id=preset-id",
        )
        .expect("combined submission");
        assert_eq!(submission.repositories.len(), 1);
        assert_eq!(
            submission.image,
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff"
        );
        assert_eq!(submission.preset_id, "preset-id");
    }

    #[test]
    fn ttl_without_a_suffix_matches_the_react_minutes_default() {
        let mut error = String::new();
        assert_eq!(parse_ttl("30", &mut error), Some(1_800));
        assert!(error.is_empty());
        assert_eq!(parse_ttl("infinity", &mut error), None);
        assert_eq!(parse_ttl("∞", &mut error), None);
        assert_eq!(parse_ttl("0", &mut error), None);
        assert!(error.is_empty());
    }

    #[test]
    fn repository_mount_inputs_are_scoped_under_workspace() {
        assert_eq!(workspace_mount_path("codewire"), "/workspace/codewire");
        assert_eq!(
            workspace_mount_path("services/api"),
            "/workspace/services/api"
        );
        assert_eq!(
            workspace_mount_path("/workspace/legacy"),
            "/workspace/legacy"
        );
        assert_eq!(workspace_mount_path(""), "");
    }

    #[test]
    fn environment_form_escapes_metadata_and_omits_retired_repository_surfaces() {
        let mut form = default_create_form("csrf-token".to_owned(), true);
        form.repositories = vec![EnvironmentRepositoryFormRow {
            index: 0,
            url: "https://example.test/<b>unsafe repository</b>".to_owned(),
            branch: "<b>unsafe branch</b>".to_owned(),
            mount_path: "/workspace/repository".to_owned(),
        }];
        form.presets = vec![crate::view::EnvironmentPresetOption {
            id: "preset-id".to_owned(),
            name: "<b>unsafe preset</b>".to_owned(),
            description: "<b>unsafe preset description</b>".to_owned(),
            image: "example.test/<b>unsafe image</b>".to_owned(),
            default_cpu_millicores: Some(1_000),
            default_memory_mib: Some(2_048),
            default_disk_gib: Some(10),
            default_ttl_seconds: Some(3_600),
            default_install_command: String::new(),
            default_startup_script: String::new(),
            default_agents: Vec::new(),
            default_app_ports: Vec::new(),
            uses_protected_secret_bindings: false,
            official: false,
        }];
        let organization = OrganizationContext {
            id: "organization-id".to_owned(),
            name: "Organization".to_owned(),
            slug: "organization".to_owned(),
            role: "owner",
            can_admin: true,
            environments_url: "/organization/".to_owned(),
            snapshots_url: "/organization/snapshots/".to_owned(),
            presets_url: "/organization/presets/".to_owned(),
            secrets_url: "/organization/secrets/".to_owned(),
            api_keys_url: "/organization/api-keys/".to_owned(),
            members_url: "/organization/members/".to_owned(),
            billing_url: "/organization/billing/".to_owned(),
        };

        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .expect("environment form");

        assert!(html.contains("unsafe repository"));
        assert!(html.contains("unsafe preset"));
        assert!(!html.contains("<b>unsafe"));
        assert!(html.contains("data-manual-repositories"));
        assert!(html.contains("value=\"repository\" placeholder=\"repo\""));
        assert!(!html.contains("value=\"/workspace/repository\""));
        for retired in [
            "GitHub connected",
            "/api/v1/github/",
            "data-repository-virtual-list",
            "data-show-github-repositories",
            "Analyze and generate from repo",
            "/_actions/sandboxes/prepare",
            "/_events/sandboxes/prepare",
            "data-environment-prepare",
            "cw-detection-summary",
        ] {
            assert!(
                !html.contains(retired),
                "retired surface remains: {retired}"
            );
        }
        assert!(
            html.contains("Application-secret selection is not available in this dashboard yet.")
        );
        assert!(
            html.contains("Credential-profile selection is not available in this dashboard yet.")
        );
        assert!(html.contains("<fieldset class=\"cw-source-fields\" aria-describedby=\"environment-create-secrets-help\" disabled>"));
        assert!(html.contains("<fieldset class=\"cw-source-fields\" aria-describedby=\"environment-create-credentials-help\" disabled>"));
        for forbidden in ["name=\"agent_secret_", "name=\"exposed", "name=\"exposure"] {
            assert!(!html.contains(forbidden), "unexpected field {forbidden}");
        }
    }

    #[test]
    fn resize_confirmation_requires_explicit_restart_and_session_consent() {
        let organization = OrganizationContext {
            id: "organization-id".to_owned(),
            name: "Organization".to_owned(),
            slug: "organization".to_owned(),
            role: "owner",
            can_admin: true,
            environments_url: "/organization/".to_owned(),
            snapshots_url: "/organization/snapshots/".to_owned(),
            presets_url: String::new(),
            secrets_url: String::new(),
            api_keys_url: String::new(),
            members_url: String::new(),
            billing_url: String::new(),
        };
        let page = EnvironmentsPageView {
            environments: Vec::new(),
            create_form: default_create_form("csrf-token".to_owned(), false),
            source_editor: None,
            port_panel: None,
            trust_summary: None,
            resize_confirmation: Some(crate::view::EnvironmentResizeConfirmationView {
                environment_id: "environment-id".to_owned(),
                environment_name: "<unsafe>".to_owned(),
                request_id: "stable-request".to_owned(),
                previous_resources: "1 vCPU / 2 GiB / 10 GiB disk".to_owned(),
                desired_resources: "2 vCPU / 4 GiB / 20 GiB disk".to_owned(),
                cpu_millicores: 2_000,
                memory_mb: 4_096,
                disk_gb: 20,
                execution_mode: "restart required",
                requires_restart: true,
                active_session_count: 2,
                active_sessions_will_be_terminated: true,
                reason: "live resize is unavailable".to_owned(),
                warnings: vec!["<unsafe warning>".to_owned()],
            }),
            resize_operation: None,
            search: String::new(),
            state: "all".to_owned(),
            message: String::new(),
            error: String::new(),
        };

        let html = OrganizationEnvironmentsContentTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .expect("resize confirmation template");

        assert!(html.contains("name=\"allow_restart\""));
        assert!(html.contains("name=\"force\""));
        assert!(html.contains("name=\"request_id\" value=\"stable-request\""));
        assert!(html.contains("does not delete or recreate storage"));
        assert!(!html.contains("<unsafe>"));
        assert!(!html.contains("<unsafe warning>"));
    }

    #[test]
    fn resize_inputs_are_bounded_before_any_connect_call() {
        assert_eq!(
            resize_submission_resources("environment-id", "2000", "4096", "20"),
            Some((2_000, 4_096, 20))
        );
        assert_eq!(
            resize_submission_resources("environment-id", "99", "4096", "20"),
            None
        );
        assert_eq!(
            resize_submission_resources("environment-id", "2000", "4096", "19"),
            Some((2_000, 4_096, 19))
        );
        assert!(checkbox_checked("true"));
        assert!(!checkbox_checked("yes"));
    }

    #[test]
    fn active_resize_operation_polls_only_until_terminal() {
        let organization = OrganizationContext {
            id: "organization-id".to_owned(),
            name: "Organization".to_owned(),
            slug: "organization".to_owned(),
            role: "owner",
            can_admin: true,
            environments_url: String::new(),
            snapshots_url: String::new(),
            presets_url: String::new(),
            secrets_url: String::new(),
            api_keys_url: String::new(),
            members_url: String::new(),
            billing_url: String::new(),
        };
        let active = crate::view::EnvironmentResizeOperationView {
            environment_id: "environment-id".to_owned(),
            operation_id: "operation-id".to_owned(),
            state: "applying",
            desired_resources: "2 vCPU / 4 GiB / 20 GiB disk".to_owned(),
            applied_resources: "1 vCPU / 2 GiB / 10 GiB disk".to_owned(),
            failure: String::new(),
            active: true,
            pod_replaced: false,
        };
        let active_html = EnvironmentResizeOperationTemplate {
            organization: &organization,
            operation: &active,
        }
        .render()
        .expect("active resize operation template");
        assert!(
            active_html.contains("_fragments/sandbox-resize?resize_environment=environment-id")
        );
        assert!(active_html.contains("every 2s"));

        let completed = crate::view::EnvironmentResizeOperationView {
            state: "completed",
            active: false,
            ..active
        };
        let completed_html = EnvironmentResizeOperationTemplate {
            organization: &organization,
            operation: &completed,
        }
        .render()
        .expect("completed resize operation template");
        assert!(!completed_html.contains("every 2s"));
        assert!(completed_html.contains("Close"));
    }

    #[test]
    fn manual_repository_entry_coexists_with_unavailable_github_profile_selection() {
        let form = default_create_form("csrf-token".to_owned(), true);
        let organization = OrganizationContext {
            id: "organization-id".to_owned(),
            name: "Organization".to_owned(),
            slug: "organization".to_owned(),
            role: "owner",
            can_admin: true,
            environments_url: "/organization/".to_owned(),
            snapshots_url: "/organization/snapshots/".to_owned(),
            presets_url: "/organization/presets/".to_owned(),
            secrets_url: "/organization/secrets/".to_owned(),
            api_keys_url: "/organization/api-keys/".to_owned(),
            members_url: "/organization/members/".to_owned(),
            billing_url: "/organization/billing/".to_owned(),
        };

        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .expect("environment form");

        let (manual_form, picker) = html.split_once("<dialog ").expect("native GitHub dialog");
        assert!(manual_form.contains("Repository URL"));
        assert!(manual_form.contains("Branch"));
        assert!(manual_form.contains("Mount path"));
        assert!(manual_form.contains("data-manual-repositories"));
        assert!(manual_form.contains("Custom Git URL"));
        let index = form.repositories[0].index;
        for (name_prefix, id_prefix) in [
            ("repo_url", "repo-url"),
            ("repo_branch", "repo-branch"),
            ("repo_mount", "repo-mount"),
        ] {
            let name = format!("{name_prefix}_{index}");
            let id = format!("{id_prefix}-{index}");
            assert!(manual_form.contains(&format!("for=\"{id}\"")));
            let input = manual_form
                .split("<input ")
                .skip(1)
                .filter_map(|element| element.split('>').next())
                .find(|tag| tag.contains(&format!("name=\"{name}\"")))
                .expect("manual input outside the picker");
            assert!(input.contains(&format!("id=\"{id}\"")));
            assert!(!input.split_ascii_whitespace().any(|attribute| {
                attribute == "disabled" || attribute.starts_with("disabled=")
            }));
        }
        assert!(manual_form.contains("type=\"button\" data-open-github-repositories aria-haspopup=\"dialog\" aria-controls=\"github-repository-picker\""));
        assert!(
            manual_form
                .contains("<a href=\"/settings/credentials/?org=organization\">Connect GitHub</a>")
        );
        let dialog = picker.split('>').next().expect("dialog opening tag");
        assert!(dialog.contains("id=\"github-repository-picker\""));
        assert!(dialog.contains("aria-labelledby=\"github-repository-picker-title\""));
        assert!(dialog.contains("data-github-repository-picker"));
        assert!(
            dialog
                .contains("data-repositories-url=\"/organization/_fragments/github-repositories\"")
        );
        assert!(
            !dialog
                .split_ascii_whitespace()
                .any(|attribute| attribute == "open" || attribute.starts_with("open="))
        );
        assert!(
            picker.contains(
                "<h2 id=\"github-repository-picker-title\">Choose a GitHub repository</h2>"
            )
        );
        assert!(!form.sources.credential_selection_enabled);
        assert!(picker.contains("data-github-profile disabled"));
        assert!(!html.contains("data-show-github-repositories"));
        assert!(!html.contains("GitHub connected"));
    }

    #[test]
    fn feedback_query_values_are_bounded() {
        assert_eq!(
            page_message("environment-created"),
            "Sandbox creation started."
        );
        assert_eq!(page_message("<script>"), "");
    }

    #[test]
    fn ttl_and_port_validation_match_form_contract() {
        let mut error = String::new();
        assert_eq!(parse_ttl("8h", &mut error), Some(28_800));
        assert!(valid_port_label("web-ui"));
        assert!(!valid_port_label("Web UI"));
    }
}
