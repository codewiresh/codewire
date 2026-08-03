use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use askama::Template as _;
use axum::{
    Form, Json,
    body::{Body, Bytes},
    extract::{Path, Query, RawForm, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use codewire_proto::codewire::v1::{
    AppPort, CreateEnvironmentRequest, CreatePortRequest, DeletePortRequest, PortAccess, RepoEntry,
    SetupAgent,
};
use connectrpc::{ConnectError, ErrorCode, http_body};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;

use crate::{
    environment_connect::{self, EnvironmentCreateOptions, EnvironmentPrepareEvent},
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
        EnvironmentCreateFormTemplate, EnvironmentListTemplate,
        OrganizationEnvironmentsContentTemplate, OrganizationEnvironmentsTemplate,
    },
    view::{
        EnvironmentAppPortFormRow, EnvironmentCreateFormView, EnvironmentDetectionView,
        EnvironmentPortPanelView, EnvironmentRepositoryFormRow, EnvironmentsPageView,
        OrganizationContext, bad_request_fields, connect_error_reason,
    },
};

const MAX_REPOSITORIES: usize = 108;
const MAX_APP_PORTS: usize = 16;
const MAX_FIELD: usize = 16_384;

#[derive(Debug, Default, Deserialize)]
pub(super) struct EnvironmentsQuery {
    #[serde(default)]
    search: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    create: bool,
    #[serde(default)]
    ports: String,
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
}

#[derive(Debug, Deserialize)]
pub(super) struct PortCreateSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    port: String,
    label: String,
    access: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PortDeleteSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    port_id: String,
}

// Deliberately not Debug. Agent credential values are write-only and must not
// become available to derived diagnostics, retained form models, or errors.
struct EnvironmentSubmission {
    csrf: String,
    mode: String,
    prepared: bool,
    name: String,
    preset_id: String,
    image: String,
    install_command: String,
    startup_script: String,
    cpu: String,
    memory: String,
    disk: String,
    ttl: String,
    repositories: Vec<(String, String)>,
    agents: Vec<String>,
    secret_project: String,
    include_org_secrets: bool,
    include_user_secrets: bool,
    app_ports: Vec<(String, String, String)>,
    agent_secrets: HashMap<String, String>,
}

#[derive(Deserialize)]
pub(super) struct InlineSecretProjectSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
}

#[derive(Serialize)]
struct InlineSecretProjectResponse {
    id: String,
    name: String,
    secret_count: i64,
}

impl EnvironmentSubmission {
    fn parse(bytes: &[u8]) -> Result<Self, ()> {
        let mut values = HashMap::<String, String>::new();
        let mut repositories = BTreeMap::<usize, (String, String)>::new();
        let mut app_ports = BTreeMap::<usize, (String, String, String)>::new();
        let mut agents = Vec::new();
        let mut agent_secrets = HashMap::<String, String>::new();

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
            } else if let Some(secret_key) = key.strip_prefix("agent_secret_") {
                if valid_agent_secret_key(secret_key) {
                    let current = agent_secrets.entry(secret_key.to_owned()).or_default();
                    if current.is_empty() || !value.is_empty() {
                        *current = value;
                    }
                }
            } else {
                values.entry(key).or_insert(value);
            }
        }

        Ok(Self {
            csrf: take(&mut values, "_csrf"),
            mode: take(&mut values, "mode"),
            prepared: values.contains_key("prepared"),
            name: take(&mut values, "name"),
            preset_id: take(&mut values, "preset_id"),
            image: take(&mut values, "image"),
            install_command: take(&mut values, "install_command"),
            startup_script: take(&mut values, "startup_script"),
            cpu: take(&mut values, "cpu"),
            memory: take(&mut values, "memory"),
            disk: take(&mut values, "disk"),
            ttl: take(&mut values, "ttl"),
            repositories: repositories.into_values().collect(),
            agents,
            secret_project: take(&mut values, "secret_project"),
            include_org_secrets: values.contains_key("include_org_secrets"),
            include_user_secrets: values.contains_key("include_user_secrets"),
            app_ports: app_ports.into_values().collect(),
            agent_secrets,
        })
    }

    fn form_view(&self, token: String) -> EnvironmentCreateFormView {
        EnvironmentCreateFormView {
            csrf_token: token,
            expanded: true,
            prepared: false,
            mode: if self.mode == "image" {
                "image"
            } else {
                "repo"
            }
            .to_owned(),
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
            selected_agents: self.agents.clone(),
            secret_project: self.secret_project.trim().to_owned(),
            include_org_secrets: self.include_org_secrets,
            include_user_secrets: self.include_user_secrets,
            app_ports: app_port_rows(&self.app_ports),
            github_connected: false,
            github_username: String::new(),
            github_repositories: Vec::new(),
            presets: Vec::new(),
            secret_projects: Vec::new(),
            agents: Vec::new(),
            detection: EnvironmentDetectionView::default(),
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
        if self.prepared
            && !self.image.trim().is_empty()
            && self.image.trim() != preset.image.trim()
        {
            self.preset_id.clear();
            return;
        }
        if self.image.trim().is_empty() {
            self.image = preset.image.clone();
        }
        if !self.prepared && self.cpu.trim().is_empty() {
            self.cpu = preset.default_cpu_millicores.to_string();
        }
        if !self.prepared && self.memory.trim().is_empty() {
            self.memory = preset.default_memory_mb.to_string();
        }
        if !self.prepared && self.disk.trim().is_empty() {
            self.disk = preset.default_disk_gb.to_string();
        }
        if !self.prepared
            && self.ttl.trim().is_empty()
            && let Some(ttl) = preset.default_ttl_seconds
        {
            self.ttl = format!("{ttl}s");
        }
        if !self.prepared && self.install_command.is_empty() {
            self.install_command = preset.default_install_command.clone();
        }
        if !self.prepared && self.startup_script.is_empty() {
            self.startup_script = preset.default_startup_script.clone();
        }
        if !self.prepared && self.agents.is_empty() {
            self.agents = preset.default_agents.clone();
        }
        if !self.prepared && self.app_ports.is_empty() {
            self.app_ports = preset
                .default_app_ports
                .iter()
                .map(|port| (port.port.clone(), port.label.clone(), port.access.clone()))
                .collect();
        }
        if !self.prepared && self.secret_project.trim().is_empty() {
            self.secret_project = preset.secret_project.clone();
        }
        if !self.prepared {
            self.include_org_secrets = preset.default_include_org_secrets;
            self.include_user_secrets = preset.default_include_user_secrets;
        }
    }

    fn normalize_source(&mut self) {
        if self.mode == "image" {
            self.repositories.clear();
        } else {
            self.mode = "repo".to_owned();
            self.preset_id.clear();
            self.image.clear();
        }
    }

    fn validate_and_draft(
        &self,
        org_id: &str,
        form: &mut EnvironmentCreateFormView,
    ) -> Option<CreateEnvironmentRequest> {
        let mode = if self.mode == "image" {
            "image"
        } else {
            "repo"
        };
        let repositories: Vec<RepoEntry> = self
            .repositories
            .iter()
            .filter_map(|(url, branch)| {
                let url = url.trim();
                (!url.is_empty()).then(|| RepoEntry {
                    url: url.to_owned(),
                    branch: branch.trim().to_owned(),
                    ..Default::default()
                })
            })
            .collect();

        if mode == "repo" {
            if repositories.is_empty() {
                form.repo_error = "Choose or enter at least one repository.".to_owned();
            } else if repositories
                .iter()
                .any(|repository| !valid_repository_url(&repository.url))
            {
                form.repo_error =
                    "Repository URLs must be clean HTTP(S) URLs without embedded credentials."
                        .to_owned();
            }
        } else if self.image.trim().is_empty() && self.preset_id.trim().is_empty() {
            form.image_error = "Choose a preset or enter an image.".to_owned();
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
            ports.push(AppPort {
                port: port_number,
                label: label.trim().to_owned(),
                access: allowlisted_access(access).to_owned(),
                ..Default::default()
            });
        }

        if form.has_errors() {
            return None;
        }
        let primary = repositories.first().cloned().unwrap_or_default();
        Some(CreateEnvironmentRequest {
            org_id: org_id.to_owned(),
            preset_id: nonempty(self.preset_id.trim()),
            name: nonempty(self.name.trim()),
            cpu_millicores: cpu,
            memory_mb: memory,
            disk_gb: disk,
            ttl_seconds: ttl,
            repo_url: if mode == "repo" {
                primary.url.clone()
            } else {
                String::new()
            },
            branch: if mode == "repo" {
                primary.branch.clone()
            } else {
                String::new()
            },
            repos: if repositories.len() > 1 {
                repositories
            } else {
                Vec::new()
            },
            image: if mode == "image" || !self.image.trim().is_empty() {
                self.image.trim().to_owned()
            } else {
                String::new()
            },
            install_command: self.install_command.clone(),
            startup_script: self.startup_script.clone(),
            agents,
            secret_project: self.secret_project.trim().to_owned(),
            app_ports: ports,
            include_org_secrets: (!self.include_org_secrets).then_some(false),
            include_user_secrets: (!self.include_user_secrets).then_some(false),
            ..Default::default()
        })
    }

    fn take_secret_values(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.agent_secrets)
            .into_iter()
            .filter_map(|(key, value)| (!value.trim().is_empty()).then_some((key, value)))
            .collect()
    }
}

pub(super) async fn page(
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
    let token = new_csrf_token();
    let form = default_create_form(token.clone(), query.create);
    let page = match build_page(&state, cookie, &organization, &query, form).await {
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
                active_tab: "environments",
                terminal_websocket_origin: &websocket_origin,
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
    let (_, organization, cookie) = match get_context(&state, &headers, &slug, &continuation).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let environments = match filtered_environments(&state, cookie, &organization.id, &query).await {
        Ok(environments) => environments,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let token = csrf_cookie_value(&headers).unwrap_or_default().to_owned();
    let page = EnvironmentsPageView {
        environments,
        create_form: default_create_form(token, false),
        port_panel: None,
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

pub(super) async fn prepare(
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
    submission.normalize_source();
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
    let mut events = match environment_connect::prepare_events(
        &state,
        cookie.clone(),
        organization.id.clone(),
        draft,
        submission.mode != "image",
    )
    .await
    {
        Ok(events) => events,
        Err(error) => {
            apply_prepare_error(&mut form, &error);
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
    while let Some(event) = events.recv().await {
        match event {
            Ok(EnvironmentPrepareEvent::Complete { draft, detection }) => {
                apply_prepared_draft(&mut form, *draft, *detection);
                return render_action_page(
                    &state,
                    &headers,
                    dashboard,
                    organization,
                    cookie,
                    form,
                    StatusCode::OK,
                )
                .await;
            }
            Ok(_) => {}
            Err(error) => {
                apply_prepare_error(&mut form, &error);
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
        }
    }
    form.form_error = "Repository preparation ended before it produced a configuration.".to_owned();
    render_action_page(
        &state,
        &headers,
        dashboard,
        organization,
        cookie,
        form,
        StatusCode::BAD_GATEWAY,
    )
    .await
}

pub(super) async fn prepare_events(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    RawForm(bytes): RawForm,
) -> Response {
    let mut submission = match EnvironmentSubmission::parse(&bytes) {
        Ok(submission) => submission,
        Err(()) => return error_page(WebError::CsrfRejected),
    };
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
    let options =
        match environment_connect::create_options(&state, cookie.clone(), &organization.id).await {
            Ok(options) => options,
            Err(error) => return connect_page_error(error, &environments_path(&slug), &headers),
        };
    submission.normalize_source();
    submission.apply_selected_preset_defaults(&options);
    let mut form = submission.form_view(submission.csrf.clone());
    hydrate_options(&mut form, options);
    let Some(draft) = submission.validate_and_draft(&organization.id, &mut form) else {
        return render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            EnvironmentCreateFormTemplate {
                organization: &organization,
                form: &form,
            },
        );
    };
    let mut upstream = match environment_connect::prepare_events(
        &state,
        cookie,
        organization.id.clone(),
        draft,
        submission.mode != "image",
    )
    .await
    {
        Ok(events) => events,
        Err(error) => {
            apply_prepare_error(&mut form, &error);
            return render_template(
                StatusCode::UNPROCESSABLE_ENTITY,
                EnvironmentCreateFormTemplate {
                    organization: &organization,
                    form: &form,
                },
            );
        }
    };
    let (sender, receiver) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                // The browser aborted its fetch. Dropping `upstream` here
                // closes the adapter receiver, which cancels the generated
                // Connect stream without a retry or detached background job.
                _ = sender.closed() => break,
                event = upstream.recv() => match event {
                    Some(event) => event,
                    None => break,
                },
            };
            let frame = match event {
                Ok(EnvironmentPrepareEvent::Progress {
                    phase,
                    message,
                    total,
                }) => sse_event(
                    "progress",
                    &format!(
                        "{}|{}|{total}",
                        safe_event_text(&phase),
                        safe_event_text(&message)
                    ),
                ),
                Ok(EnvironmentPrepareEvent::RepoFetched { index, repo, ok }) => {
                    sse_event("repo", &format!("{index}|{}|{ok}", safe_event_text(&repo)))
                }
                Ok(EnvironmentPrepareEvent::Complete { draft, detection }) => {
                    apply_prepared_draft(&mut form, *draft, *detection);
                    let html = EnvironmentCreateFormTemplate {
                        organization: &organization,
                        form: &form,
                    }
                    .render()
                    .unwrap_or_else(|_| {
                        "<div role=\"alert\">The prepared form could not be rendered.</div>"
                            .to_owned()
                    });
                    sse_event("complete", &STANDARD.encode(html))
                }
                Err(error) => sse_event("error", prepare_error_message(&error)),
            };
            let terminal =
                frame.starts_with(b"event: complete") || frame.starts_with(b"event: error");
            if sender.send(frame).await.is_err() || terminal {
                break;
            }
        }
    });
    sse_response(receiver)
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
    submission.normalize_source();
    submission.apply_selected_preset_defaults(&options);
    let mut form = submission.form_view(submission.csrf.clone());
    hydrate_options(&mut form, options);
    form.prepared = true;
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

    let secret_values = submission.take_secret_values();
    if !secret_values.is_empty()
        && let Err(error) =
            environment_connect::set_user_secrets(&state, cookie.clone(), secret_values).await
    {
        form.form_error =
            "The selected agent credential could not be saved. No environment was created."
                .to_owned();
        if error.code == ErrorCode::Unauthenticated {
            return login_redirect(&environments_path(&slug), &headers);
        }
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

    match environment_connect::create_environment(&state, cookie.clone(), draft).await {
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

pub(super) async fn create_secret_project(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<InlineSecretProjectSubmission>,
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
    let name = submission.name.trim();
    if !organization.can_admin || name.is_empty() || name.len() > 128 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Enter a project name up to 128 characters.",
        )
            .into_response();
    }
    if let Err(error) = crate::secrets_presets_connect::create_secret_project(
        &state,
        cookie.clone(),
        organization.id.clone(),
        name.to_owned(),
    )
    .await
    {
        return match error.code {
            ErrorCode::AlreadyExists => (
                StatusCode::CONFLICT,
                "A secret project with that name already exists.",
            )
                .into_response(),
            ErrorCode::PermissionDenied => {
                (StatusCode::FORBIDDEN, "You cannot create secret projects.").into_response()
            }
            _ => (
                StatusCode::BAD_GATEWAY,
                "The secret service is temporarily unavailable.",
            )
                .into_response(),
        };
    }
    let options = match environment_connect::create_options(&state, cookie, &organization.id).await
    {
        Ok(options) => options,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "The project was created, but its details could not be refreshed.",
            )
                .into_response();
        }
    };
    let Some(project) = options
        .secret_projects
        .into_iter()
        .find(|project| project.name == name)
    else {
        return (
            StatusCode::BAD_GATEWAY,
            "The project was created, but its details could not be refreshed.",
        )
            .into_response();
    };
    Json(InlineSecretProjectResponse {
        id: project.id,
        name: project.name,
        secret_count: project.secret_count,
    })
    .into_response()
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

pub(super) async fn create_port(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PortCreateSubmission>,
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
    if !valid_identifier(&submission.environment_id) {
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    }
    let Ok(port) = submission.port.parse::<i32>() else {
        return ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "invalid-port",
        );
    };
    if !(1..=65_535).contains(&port) || !valid_port_label(&submission.label) {
        return ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "invalid-port",
        );
    }
    let result = environment_connect::create_port(
        &state,
        cookie,
        CreatePortRequest {
            org_id: organization.id,
            environment_id: submission.environment_id.clone(),
            port,
            label: submission.label,
            access: port_access(&submission.access).into(),
            ..Default::default()
        },
    )
    .await;
    match result {
        Ok(()) => ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "port-created",
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(&slug), &headers)
        }
        Err(_) => ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "port-unavailable",
        ),
    }
}

pub(super) async fn delete_port(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PortDeleteSubmission>,
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
    if !valid_identifier(&submission.environment_id) || !valid_identifier(&submission.port_id) {
        return mutation_redirect(&state, environments_path(&slug), "", "invalid", &headers);
    }
    let result = environment_connect::delete_port(
        &state,
        cookie,
        DeletePortRequest {
            org_id: organization.id,
            environment_id: submission.environment_id.clone(),
            port_id: submission.port_id,
            ..Default::default()
        },
    )
    .await;
    match result {
        Ok(()) => ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "port-deleted",
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(&slug), &headers)
        }
        Err(_) => ports_redirect(
            &state,
            &headers,
            &slug,
            &submission.environment_id,
            "port-unavailable",
        ),
    }
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
    let (_, organization, cookie) = match action_context(
        state,
        headers,
        slug,
        &submission.csrf,
        environments_path(slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.environment_id) {
        return mutation_redirect(state, environments_path(slug), "", "invalid", headers);
    }
    match operation(state, cookie, organization.id, submission.environment_id).await {
        Ok(()) => mutation_redirect(state, environments_path(slug), message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(slug), headers)
        }
        Err(error) => mutation_redirect(
            state,
            environments_path(slug),
            "",
            mutation_error(&error),
            headers,
        ),
    }
}

async fn build_page(
    state: &AppState,
    cookie: HeaderValue,
    organization: &OrganizationContext,
    query: &EnvironmentsQuery,
    mut form: EnvironmentCreateFormView,
) -> Result<EnvironmentsPageView, ConnectError> {
    let environments =
        filtered_environments(state, cookie.clone(), &organization.id, query).await?;
    if form.expanded {
        hydrate_options(
            &mut form,
            environment_connect::create_options(state, cookie.clone(), &organization.id).await?,
        );
    }
    let port_panel = if valid_identifier(&query.ports) {
        environments
            .iter()
            .find(|environment| environment.id == query.ports)
            .map(|environment| (environment.id.clone(), environment.name.clone()))
    } else {
        None
    };
    let port_panel = match port_panel {
        Some((environment_id, environment_name)) => Some(EnvironmentPortPanelView {
            ports: environment_connect::ports(state, cookie, &organization.id, &environment_id)
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
    Ok(EnvironmentsPageView {
        environments,
        create_form: form,
        port_panel,
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
    let query = EnvironmentsQuery {
        create: true,
        ..Default::default()
    };
    let page = match build_page(state, cookie, &organization, &query, form).await {
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
                active_tab: "environments",
                terminal_websocket_origin: &websocket_origin,
            },
            &websocket_origin,
        )
    }
}

fn default_create_form(token: String, expanded: bool) -> EnvironmentCreateFormView {
    EnvironmentCreateFormView {
        csrf_token: token,
        expanded,
        prepared: false,
        mode: "repo".to_owned(),
        name: String::new(),
        preset_id: String::new(),
        image: String::new(),
        repositories: vec![EnvironmentRepositoryFormRow {
            index: 100,
            url: String::new(),
            branch: String::new(),
        }],
        install_command: String::new(),
        startup_script: String::new(),
        cpu: "1000".to_owned(),
        memory: "2048".to_owned(),
        disk: "10".to_owned(),
        ttl: String::new(),
        selected_agents: Vec::new(),
        secret_project: String::new(),
        include_org_secrets: true,
        include_user_secrets: true,
        app_ports: Vec::new(),
        github_connected: false,
        github_username: String::new(),
        github_repositories: Vec::new(),
        presets: Vec::new(),
        secret_projects: Vec::new(),
        agents: Vec::new(),
        detection: EnvironmentDetectionView::default(),
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
    form.github_connected = options.github_connected;
    form.github_username = options.github_username;
    form.github_repositories = options.github_repositories;
    form.presets = options.presets;
    form.secret_projects = options.secret_projects;
    form.agents = options.agents;
}

fn apply_prepared_draft(
    form: &mut EnvironmentCreateFormView,
    draft: CreateEnvironmentRequest,
    detection: Option<codewire_proto::codewire::v1::DetectionResult>,
) {
    form.prepared = true;
    form.expanded = true;
    form.name = draft.name.unwrap_or_default();
    form.preset_id = draft.preset_id.unwrap_or_default();
    form.image = draft.image;
    form.install_command = draft.install_command;
    form.startup_script = draft.startup_script;
    form.cpu = draft
        .cpu_millicores
        .map(|value| value.to_string())
        .unwrap_or_else(|| "1000".to_owned());
    form.memory = draft
        .memory_mb
        .map(|value| value.to_string())
        .unwrap_or_else(|| "2048".to_owned());
    form.disk = draft
        .disk_gb
        .map(|value| value.to_string())
        .unwrap_or_else(|| "10".to_owned());
    form.ttl = draft
        .ttl_seconds
        .map(|value| format!("{value}s"))
        .unwrap_or_default();
    form.selected_agents = draft.agents.into_iter().map(|agent| agent.r#type).collect();
    form.secret_project = draft.secret_project;
    form.include_org_secrets = draft.include_org_secrets.unwrap_or(true);
    form.include_user_secrets = draft.include_user_secrets.unwrap_or(true);
    form.app_ports = draft
        .app_ports
        .into_iter()
        .enumerate()
        .map(|(index, port)| EnvironmentAppPortFormRow {
            index,
            port: port.port.to_string(),
            label: port.label,
            access: port.access,
        })
        .collect();
    let repositories = if draft.repos.is_empty() {
        vec![(draft.repo_url, draft.branch)]
    } else {
        draft
            .repos
            .into_iter()
            .map(|repo| (repo.url, repo.branch))
            .collect()
    };
    form.repositories = repository_rows(&repositories);
    form.detection = environment_connect::detection_view(detection);
    form.form_error.clear();
}

fn apply_create_error(form: &mut EnvironmentCreateFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "repo_url" | "repos" => form.repo_error = description,
            "image" | "preset_id" | "preset_slug" => form.image_error = description,
            "name" => form.name_error = description,
            "cpu_millicores" => form.cpu_error = description,
            "memory_mb" => form.memory_error = description,
            "disk_gb" => form.disk_error = description,
            "ttl_seconds" => form.ttl_error = description,
            _ => {}
        }
    }
    if !form.has_errors() {
        form.form_error = prepare_error_message(error).to_owned();
    }
}

fn apply_prepare_error(form: &mut EnvironmentCreateFormView, error: &ConnectError) {
    if matches!(
        connect_error_reason(error).as_deref(),
        Some("INVALID_REPO_URL" | "REPO_NOT_FOUND" | "REPO_NOT_ACCESSIBLE")
    ) {
        form.repo_error = prepare_error_message(error).to_owned();
    } else {
        form.form_error = prepare_error_message(error).to_owned();
    }
}

fn prepare_error_message(error: &ConnectError) -> &'static str {
    match connect_error_reason(error).as_deref() {
        Some("AI_DETECTION_UNAVAILABLE") => {
            return "Automatic repository analysis is not configured. Use the universal image or choose a preset instead.";
        }
        Some("AI_DETECTION_FAILED") => {
            return "Automatic repository analysis failed. Retry, or use the universal image instead.";
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
        ErrorCode::InvalidArgument => "The repository or environment options are invalid.",
        ErrorCode::FailedPrecondition => {
            "Repository analysis is not available for this configuration."
        }
        ErrorCode::PermissionDenied => "You do not have permission to prepare this environment.",
        ErrorCode::DeadlineExceeded => "Repository preparation took too long and was cancelled.",
        _ => "Repository preparation is temporarily unavailable.",
    }
}

struct SseBody {
    receiver: mpsc::Receiver<Bytes>,
}

impl http_body::Body for SseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(http_body::Frame::data(bytes)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn sse_response(receiver: mpsc::Receiver<Bytes>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE.as_str(),
                "text/event-stream; charset=utf-8",
            ),
            (header::CACHE_CONTROL.as_str(), "private, no-store"),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
            ("x-accel-buffering", "no"),
        ],
        Body::new(SseBody { receiver }),
    )
        .into_response()
}

fn sse_event(event: &str, data: &str) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {data}\n\n"))
}

fn safe_event_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() && *character != '|')
        .take(240)
        .collect()
}

fn indexed_key(key: &str, prefix: &str) -> Option<usize> {
    key.strip_prefix(prefix)?.parse().ok()
}

fn take(values: &mut HashMap<String, String>, key: &str) -> String {
    values.remove(key).unwrap_or_default()
}

fn repository_rows(values: &[(String, String)]) -> Vec<EnvironmentRepositoryFormRow> {
    let values = if values.is_empty() {
        vec![(String::new(), String::new())]
    } else {
        values.to_vec()
    };
    values
        .into_iter()
        .enumerate()
        .map(|(index, (url, branch))| EnvironmentRepositoryFormRow {
            index: index + 100,
            url,
            branch,
        })
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
    if value.is_empty() {
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
            *error = "TTL must be 60 seconds to 365 days, such as 8h or 7d.".to_owned();
            None
        }
    }
}

fn allowlisted_agents(values: &[String]) -> Vec<SetupAgent> {
    values
        .iter()
        .filter(|value| {
            matches!(
                value.as_str(),
                "claude-code" | "codex" | "gemini-cli" | "kimi-code" | "pi" | "aider"
            )
        })
        .map(|value| SetupAgent {
            r#type: value.clone(),
            ..Default::default()
        })
        .collect()
}

fn valid_agent_secret_key(value: &str) -> bool {
    matches!(
        value,
        "ANTHROPIC_API_KEY" | "CLAUDE_CODE_OAUTH_TOKEN" | "OPENAI_API_KEY" | "GEMINI_API_KEY"
    )
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

fn page_message(value: &str) -> &'static str {
    match value {
        "environment-created" => "Environment creation started.",
        "environment-started" => "Environment start requested.",
        "environment-stopping" => "Environment stop requested.",
        "environment-destroying" => "Environment destruction requested.",
        "port-created" => "Port created.",
        "port-deleted" => "Port deleted.",
        _ => "",
    }
}

fn page_error(value: &str) -> &'static str {
    match value {
        "invalid" => "The environment request was invalid for its current state.",
        "not-authorized" => "You do not have permission to change that environment.",
        "not-found" => "The environment no longer exists.",
        "unavailable" => "The environment service is temporarily unavailable.",
        _ => "",
    }
}

fn port_error(value: &str) -> &'static str {
    match value {
        "invalid-port" => "Port must be 1–65535 with a lowercase 2–22 character label.",
        "port-unavailable" => "The port service is temporarily unavailable.",
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
    format!("/dashboard/orgs/{slug}/environments")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn prepare_errors_map_only_allowlisted_typed_reasons() {
        let detail = codewire_proto::google::rpc::ErrorInfo {
            reason: "AI_DETECTION_UNAVAILABLE".to_owned(),
            domain: "codewire.dev".to_owned(),
            ..Default::default()
        };
        let error = ConnectError::invalid_argument("untrusted upstream detail").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &detail),
        );
        let mut form = default_create_form("token".to_owned(), true);

        apply_prepare_error(&mut form, &error);

        assert_eq!(
            form.form_error,
            "Automatic repository analysis is not configured. Use the universal image or choose a preset instead."
        );
        assert!(form.repo_error.is_empty());
        assert!(!form.form_error.contains("untrusted upstream detail"));
    }

    #[test]
    fn raw_submission_never_puts_agent_values_in_the_form_view() {
        let bytes = b"_csrf=token&mode=image&image=example.test%2Fworkspace&agent=codex&agent_secret_OPENAI_API_KEY=write-only-marker";
        let mut submission = EnvironmentSubmission::parse(bytes).expect("submission");
        let form = submission.form_view("token".to_owned());
        let values = submission.take_secret_values();
        assert_eq!(values.len(), 1);
        let rendered_metadata = format!("{}{}", form.image, form.selected_agents.join(""));
        assert!(!rendered_metadata.contains("write-only-marker"));
    }

    #[test]
    fn duplicate_agent_inputs_do_not_erase_a_supplied_secret() {
        let bytes = b"agent_secret_OPENAI_API_KEY=&agent_secret_OPENAI_API_KEY=write-only-marker&agent_secret_OPENAI_API_KEY=";
        let mut submission = EnvironmentSubmission::parse(bytes).expect("submission");
        let values = submission.take_secret_values();
        assert_eq!(
            values,
            vec![("OPENAI_API_KEY".to_owned(), "write-only-marker".to_owned())]
        );
    }

    #[test]
    fn preset_defaults_fill_missing_resources_without_overwriting_edits() {
        let mut submission =
            EnvironmentSubmission::parse(b"preset_id=preset-id&cpu=750").expect("submission");
        let options = EnvironmentCreateOptions {
            github_connected: false,
            github_username: String::new(),
            github_repositories: Vec::new(),
            presets: vec![crate::view::EnvironmentPresetOption {
                id: "preset-id".to_owned(),
                name: "Preset".to_owned(),
                description: String::new(),
                image: "example.test/workspace@sha256:abc".to_owned(),
                default_cpu_millicores: 500,
                default_memory_mb: 1_024,
                default_disk_gb: 5,
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
                default_include_org_secrets: false,
                default_include_user_secrets: true,
                secret_project: "development".to_owned(),
                official: false,
            }],
            secret_projects: Vec::new(),
            agents: Vec::new(),
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
        assert_eq!(submission.secret_project, "development");
        assert!(!submission.include_org_secrets);
        assert!(submission.include_user_secrets);
        assert_eq!(submission.app_ports[0].0, "3000");
    }

    #[test]
    fn selected_source_mode_discards_stale_values_from_the_other_mode() {
        let mut image = EnvironmentSubmission::parse(
            b"mode=image&image=ghcr.io%2Fcodewiresh%2Fworkspace%40sha256%3A03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467&repo_url_0=https%3A%2F%2Fstale.invalid%2Frepo",
        )
        .expect("image submission");
        image.normalize_source();
        assert!(image.repositories.is_empty());
        assert_eq!(
            image.image,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"
        );

        let mut repository = EnvironmentSubmission::parse(
            b"mode=repo&repo_url_0=https%3A%2F%2Fexample.test%2Frepo&preset_id=stale&image=stale.invalid%2Fimage",
        )
        .expect("repository submission");
        repository.normalize_source();
        assert_eq!(repository.repositories.len(), 1);
        assert!(repository.preset_id.is_empty());
        assert!(repository.image.is_empty());
    }

    #[test]
    fn ttl_without_a_suffix_matches_the_react_minutes_default() {
        let mut error = String::new();
        assert_eq!(parse_ttl("30", &mut error), Some(1_800));
        assert!(error.is_empty());
    }

    #[test]
    fn environment_form_escapes_all_upstream_metadata() {
        let mut form = default_create_form("csrf-token".to_owned(), true);
        form.github_repositories = vec![crate::view::GitHubRepositoryOption {
            full_name: "<b>unsafe repository</b>".to_owned(),
            url: "https://example.test/repository".to_owned(),
            description: "<b>unsafe description</b>".to_owned(),
            language: "<b>unsafe language</b>".to_owned(),
            private: true,
        }];
        form.github_connected = true;
        form.presets = vec![crate::view::EnvironmentPresetOption {
            id: "preset-id".to_owned(),
            name: "<b>unsafe preset</b>".to_owned(),
            description: "<b>unsafe preset description</b>".to_owned(),
            image: "example.test/<b>unsafe image</b>".to_owned(),
            default_cpu_millicores: 1_000,
            default_memory_mb: 2_048,
            default_disk_gb: 10,
            default_ttl_seconds: Some(3_600),
            default_install_command: String::new(),
            default_startup_script: String::new(),
            default_agents: Vec::new(),
            default_app_ports: Vec::new(),
            default_include_org_secrets: true,
            default_include_user_secrets: true,
            secret_project: String::new(),
            official: false,
        }];
        form.detection = EnvironmentDetectionView {
            project_type: "<b>unsafe type</b>".to_owned(),
            image: "example.test/<b>unsafe detected image</b>".to_owned(),
            ..EnvironmentDetectionView::default()
        };
        let organization = OrganizationContext {
            id: "organization-id".to_owned(),
            name: "Organization".to_owned(),
            slug: "organization".to_owned(),
            role: "owner",
            can_admin: true,
            environments_url: "/dashboard/orgs/organization/environments".to_owned(),
            presets_url: "/dashboard/orgs/organization/presets".to_owned(),
            secrets_url: "/dashboard/orgs/organization/secrets".to_owned(),
            api_keys_url: "/dashboard/orgs/organization/api-keys".to_owned(),
            members_url: "/dashboard/orgs/organization/members".to_owned(),
            billing_url: "/dashboard/orgs/organization/billing".to_owned(),
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

        form.prepared = true;
        let prepared_html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .expect("prepared environment form");
        assert!(prepared_html.contains("unsafe type"));
        assert!(!prepared_html.contains("<b>unsafe"));
    }

    #[test]
    fn feedback_and_stream_text_are_bounded() {
        assert_eq!(
            page_message("environment-created"),
            "Environment creation started."
        );
        assert_eq!(page_message("<script>"), "");
        assert_eq!(safe_event_text("line\nother|field"), "lineotherfield");
    }

    #[test]
    fn dropping_the_browser_stream_closes_the_route_sender() {
        let (sender, receiver) = mpsc::channel(1);
        let body = SseBody { receiver };
        assert!(!sender.is_closed());
        drop(body);
        assert!(sender.is_closed());
    }

    #[test]
    fn ttl_and_port_validation_match_form_contract() {
        let mut error = String::new();
        assert_eq!(parse_ttl("8h", &mut error), Some(28_800));
        assert!(valid_port_label("web-ui"));
        assert!(!valid_port_label("Web UI"));
    }
}
