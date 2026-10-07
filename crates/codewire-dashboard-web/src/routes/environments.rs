use std::{
    collections::{BTreeMap, HashMap},
    pin::Pin,
};

use axum::{
    Form,
    extract::{
        Path, Query, RawForm, RawQuery, State,
        rejection::{QueryRejection, RawFormRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
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
    auth::{authenticated_identity, enforce_two_factor},
    environment_connect::{self, EnvironmentCreateOptions},
    error::WebError,
    response::{
        HTMX_REQUEST, error_page, login_redirect, redirect, render_page_with_connect_origin,
        render_template, render_template_with_connect_origin,
    },
    routes::organization_governance::{
        action_context, action_context_without_rail, connect_page_error, get_context,
        get_context_without_rail, mutation_redirect, valid_identifier,
    },
    security::{
        canonical_cookie, csrf_cookie, csrf_cookie_value, page_csrf_token, with_csrf_cookie,
    },
    state::AppState,
    templates::{
        EnvironmentCreateFormTemplate, EnvironmentListTemplate, EnvironmentResizeOperationTemplate,
        OrganizationEnvironmentsContentTemplate, OrganizationEnvironmentsTemplate,
        SandboxRailTemplate,
    },
    view::{
        EnvironmentAppPortFormRow, EnvironmentCreateFormView, EnvironmentPortPanelView,
        EnvironmentRepositoryFormRow, EnvironmentsPageView, OrganizationContext,
        SandboxListContext, bad_request_fields, connect_error_reason, lifetime_field_value,
        ttl_uses_default,
    },
};

const MAX_REPOSITORIES: usize = crate::view::MAX_CREATE_REPOSITORIES;
const MAX_APP_PORTS: usize = 16;
const MAX_FIELD: usize = 16_384;
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
    /// The Sandbox a Delete named, so the list can say what became of it.
    #[serde(default)]
    environment: String,
    #[serde(default)]
    error: String,
}

impl EnvironmentsQuery {
    fn has_detail_selector(&self) -> bool {
        !self.ports.is_empty()
            || !self.sources.is_empty()
            || !self.trust.is_empty()
            || !self.resize_environment.is_empty()
            || !self.resize_operation.is_empty()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct EnvironmentIdSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environment_id: String,
    #[serde(default)]
    return_to: String,
    #[serde(flatten)]
    list_context: SandboxListContext,
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
    application_previews_explicit: bool,
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
            application_previews_explicit: take(&mut values, "application_previews_explicit")
                == "true",
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
            draft_actor: String::new(),
            draft_organization: String::new(),
            draft_id: uuid::Uuid::new_v4().to_string(),
            draft_return: crate::environment_drafts::DraftReturn::default(),
            draft_restore_allowed: false,
            draft_restored: false,
            options_loading: false,
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
            // Legacy `0`, `infinity` and `∞` mean the default; never echo them.
            ttl: if ttl_uses_default(&self.ttl) {
                String::new()
            } else {
                self.ttl.trim().to_owned()
            },
            isolation_tier: self.isolation_tier.trim().to_owned(),
            confidential_available: false,
            show_confidential_controls: false,
            confidential_price: String::new(),
            preview_base_domain: String::new(),
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
            self.ttl = lifetime_field_value(ttl);
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
        if self.app_ports.is_empty() && !self.application_previews_explicit {
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
                form.form_error = "Confidential isolation is temporarily unavailable.".to_owned();
                IsolationTier::Unspecified
            }
            _ => {
                form.form_error = "Choose a valid isolation tier.".to_owned();
                IsolationTier::Unspecified
            }
        };

        let mut ports = Vec::new();
        let mut seen_ports = std::collections::HashSet::new();
        let mut seen_labels = std::collections::HashSet::new();
        for (index, (port, label, access)) in self.app_ports.iter().enumerate() {
            if port.trim().is_empty() && label.trim().is_empty() {
                continue;
            }
            let row = &mut form.app_ports[index];
            let port_number = port.trim().parse::<u16>().ok().filter(|port| *port != 0);
            match port_number {
                None => row.port_error = "Enter an internal port from 1 to 65535.".into(),
                Some(2222) => {
                    row.port_error = "Port 2222 is reserved for the Sandbox runtime.".into()
                }
                Some(port) if !seen_ports.insert(port) => {
                    row.port_error = "This internal port is already used in another row.".into()
                }
                Some(_) => {}
            }
            if !valid_port_label(label.trim()) {
                row.label_error = "Use 2–22 lowercase letters, digits or hyphens; start and end with a letter or digit.".into();
            } else if !seen_labels.insert(label.trim()) {
                row.label_error = "This preview label is already used in another row.".into();
            }
            if !matches!(access.as_str(), "" | "creator" | "org_members" | "public") {
                row.access_error = "Choose who can open this HTTPS preview.".into();
            }
            if !row.port_error.is_empty()
                || !row.label_error.is_empty()
                || !row.access_error.is_empty()
            {
                continue;
            };
            ports.push(ApplicationPort {
                port: port_number.expect("validated internal port"),
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
        let omit_application_previews = self.application_previews_explicit && ports.is_empty();
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
            omit_application_previews,
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
    render_page(
        state,
        slug,
        query,
        headers,
        false,
        Default::default(),
        false,
    )
    .await
}

pub(super) async fn new_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    query: Result<Query<EnvironmentsQuery>, QueryRejection>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let draft_return = crate::environment_drafts::DraftReturn::parse(raw.as_deref());
    // Explicit returns have no inventory/source-editor selectors. A malformed
    // discarded selector must not reject navigation before authentication.
    let query = match create_return_query(query, &draft_return) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let canonicalize = draft_return.requested() && !draft_return.canonical_query(raw.as_deref());
    render_page(
        state,
        slug,
        query,
        headers,
        true,
        draft_return,
        canonicalize,
    )
    .await
}

fn create_return_query(
    query: Result<Query<EnvironmentsQuery>, QueryRejection>,
    draft_return: &crate::environment_drafts::DraftReturn,
) -> Result<EnvironmentsQuery, QueryRejection> {
    if draft_return.requested() {
        Ok(EnvironmentsQuery::default())
    } else {
        query.map(|Query(query)| query)
    }
}

#[cfg(test)]
mod draft_return_tests {
    use super::*;

    #[test]
    fn explicit_return_discards_invalid_and_conflicting_inventory_selectors() {
        for uri in [
            "/org/new/?creation_draft=00000000-0000-4000-8000-000000000003&destroyed=bogus",
            "/org/new/?sources=first&sources=second&creation_draft=unavailable",
            "/org/new/?creation_draft=unavailable&sources=editor&ports=other&resize_environment=another&search=private-canary",
        ] {
            let uri: axum::http::Uri = uri.parse().unwrap();
            let navigation = crate::environment_drafts::DraftReturn::parse(uri.query());
            assert!(navigation.requested());
            let query = create_return_query(Query::try_from_uri(&uri), &navigation).unwrap();
            assert!(query.sources.is_empty() && query.ports.is_empty());
            assert!(query.resize_environment.is_empty() && query.search.is_empty());
            assert!(!query.destroyed);
        }
    }

    #[test]
    fn ordinary_inventory_query_keeps_original_values_and_rejection() {
        let uri = axum::http::Uri::from_static("/org/new/?search=app&state=running");
        let query = create_return_query(Query::try_from_uri(&uri), &Default::default()).unwrap();
        assert_eq!(query.search, "app");
        assert_eq!(query.state, "running");
        let invalid = axum::http::Uri::from_static("/org/new/?destroyed=bogus");
        let response =
            create_return_query(Query::try_from_uri(&invalid), &Default::default()).unwrap_err();
        assert_eq!(response.into_response().status(), StatusCode::BAD_REQUEST);
    }
}

async fn render_page(
    state: AppState,
    slug: String,
    query: EnvironmentsQuery,
    headers: HeaderMap,
    create_open: bool,
    draft_return: crate::environment_drafts::DraftReturn,
    canonicalize: bool,
) -> Response {
    let continuation = if create_open {
        format!("/{slug}/new/{}", draft_return.query())
    } else {
        environments_path(&slug)
    };
    let (dashboard, organization, cookie) = match if create_open && !query.has_detail_selector() {
        get_context_without_rail(&state, &headers, &slug, &continuation).await
    } else {
        get_context(&state, &headers, &slug, &continuation).await
    } {
        Ok(context) => context,
        Err(response) => return response,
    };
    if canonicalize {
        return redirect(
            format!("/{}/new/{}", organization.slug, draft_return.query()),
            &headers,
        );
    }
    let token = page_csrf_token(&headers);
    let mut form = default_create_form(token.clone(), create_open);
    if let crate::environment_drafts::DraftReturn::Exact(id) = &draft_return {
        form.draft_id.clone_from(id);
    }
    form.draft_return = draft_return;
    let page = if create_open && !query.has_detail_selector() {
        form.draft_actor = match crate::environment_drafts::actor(&state, cookie).await {
            Ok(actor) => actor,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
        form.draft_organization.clone_from(&organization.id);
        form.options_loading = true;
        form.show_confidential_controls = state.confidential_storage_enabled
            && (!state.confidential_admin_only || dashboard.is_admin);
        EnvironmentsPageView {
            environments: Vec::new(),
            environments_loading: true,
            create_form: form,
            source_editor: None,
            port_panel: None,
            trust_summary: None,
            resize_confirmation: None,
            resize_operation: None,
            search: bounded_query(&query.search),
            state: allowlisted_state(&query.state).to_owned(),
            message: page_message(&query.message).to_owned(),
            error: page_error(&query.error).to_owned(),
        }
    } else {
        match build_page(
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
        }
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
        match get_context_without_rail(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut environments =
        match filtered_environments(&state, cookie.clone(), &organization.id, &query).await {
            Ok(environments) => environments,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    for environment in &mut environments {
        apply_confidential_visibility(&state, dashboard.is_admin, environment);
    }
    environment_connect::mark_credential_attention(&state, cookie, &mut environments).await;
    let token = csrf_cookie_value(&headers).unwrap_or_default().to_owned();
    let page = EnvironmentsPageView {
        environments,
        environments_loading: false,
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

struct CreateOptionsRequest {
    csrf: String,
    actor: String,
    organization: String,
    draft_id: String,
    draft_return: crate::environment_drafts::DraftReturn,
}

impl CreateOptionsRequest {
    fn parse(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() > 1024 {
            return Err(());
        }
        let mut values = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(bytes) {
            if !matches!(
                key.as_ref(),
                "_csrf" | "actor" | "organization" | "draft_id" | "draft_return"
            ) || values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(());
            }
        }
        let csrf = values.remove("_csrf").ok_or(())?;
        let actor = values.remove("actor").ok_or(())?;
        let organization = values.remove("organization").ok_or(())?;
        let draft_id = values.remove("draft_id").ok_or(())?;
        let raw_return = values.remove("draft_return").ok_or(())?;
        let draft_return =
            crate::environment_drafts::DraftReturn::parse(Some(raw_return.trim_start_matches('?')));
        if !values.is_empty()
            || csrf.len() > 64
            || !crate::environment_drafts::actor_id(&actor)
            || !crate::environment_drafts::organization_id(&organization)
            || !crate::environment_drafts::canonical_id(&draft_id)
            || draft_return.query() != raw_return
            || matches!(&draft_return, crate::environment_drafts::DraftReturn::Exact(id) if id != &draft_id)
        {
            return Err(());
        }
        Ok(Self {
            csrf,
            actor,
            organization,
            draft_id,
            draft_return,
        })
    }
}

fn create_options_error(status: StatusCode) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "private, no-store"),
            (header::VARY, "Cookie"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        "Sandbox choices could not be loaded. Retry without leaving this form.",
    )
        .into_response()
}

/// Fetch optional choices after the editable Create shell has rendered. This
/// endpoint does not create anything and never trusts the submitted identity.
pub(super) async fn create_options_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Result<RawForm, RawFormRejection>,
) -> Response {
    let request = match body
        .ok()
        .and_then(|body| CreateOptionsRequest::parse(&body.0).ok())
    {
        Some(request) => request,
        None => return create_options_error(StatusCode::BAD_REQUEST),
    };
    if !super::environment_drafts::valid_authority(&headers, &state.public_origin, &request.csrf) {
        return create_options_error(StatusCode::FORBIDDEN);
    }
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return create_options_error(StatusCode::UNAUTHORIZED),
        Err(_) => return create_options_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    if enforce_two_factor(&identity).is_err() || identity.id != request.actor {
        return create_options_error(StatusCode::FORBIDDEN);
    }
    let cookie = canonical_cookie(&headers).expect("options authority validated canonical cookie");
    let organizations = match crate::connect::organizations(&state, cookie.clone()).await {
        Ok(organizations) => organizations,
        Err(_) => return create_options_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(row) = organizations.iter().find(|row| row.slug == slug) else {
        return create_options_error(StatusCode::NOT_FOUND);
    };
    if row.id != request.organization {
        return create_options_error(StatusCode::FORBIDDEN);
    }
    let organization = OrganizationContext::from_row(row);
    let options = match environment_connect::create_options(&state, cookie, &organization.id).await
    {
        Ok(options) => options,
        Err(_) => return create_options_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut form = default_create_form(request.csrf, true);
    form.draft_actor = identity.id;
    form.draft_organization.clone_from(&organization.id);
    form.draft_id = request.draft_id;
    form.draft_return = request.draft_return;
    form.show_confidential_controls =
        state.confidential_storage_enabled && (!state.confidential_admin_only || identity.is_admin);
    hydrate_options(&mut form, options);
    form.confidential_available &= form.show_confidential_controls;
    let mut response = render_template(
        StatusCode::OK,
        EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        },
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
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
    let (dashboard, organization, cookie) = match action_context_without_rail(
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
        return render_create_action_page(
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
            return render_create_action_page(
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
        // Land on the new Sandbox, where its setup stages stream live (A5c).
        Ok(environment_id) => mutation_redirect(
            &state,
            super::terminal::terminal_path(&slug, &environment_id),
            "environment-created",
            "",
            &headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&environments_path(&slug), &headers)
        }
        Err(error) => {
            apply_create_error(&mut form, &error);
            render_create_action_page(
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
            let code = if environment_connect::resize_refused_during_setup(&error) {
                "setup-running"
            } else {
                mutation_error(&error)
            };
            return mutation_redirect(&state, environments_path(&slug), "", code, &headers);
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
    let result = match port {
        None => "invalid-port",
        Some(2222) => "reserved-port",
        Some(_) if !valid_port_label(&submission.label) => "invalid-port-label",
        Some(_)
            if !matches!(
                submission.access.as_str(),
                "creator" | "org_members" | "public"
            ) =>
        {
            "invalid-port-access"
        }
        Some(port) => match environment_connect::create_port(
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
            Err(error) if error.code == ErrorCode::AlreadyExists => "port-conflict",
            Err(_) => "port-unavailable",
        },
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
        port_error: if matches!(
            action.result,
            "invalid-port" | "reserved-port" | "port-conflict"
        ) {
            error.into()
        } else {
            String::new()
        },
        label_error: if matches!(action.result, "invalid-port-label" | "port-conflict") {
            error.into()
        } else {
            String::new()
        },
        access_error: if action.result == "invalid-port-access" {
            error.into()
        } else {
            String::new()
        },
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
    let list_context = submission.list_context.normalized();
    let continuation = lifecycle_return_path(
        slug,
        &submission.environment_id,
        &submission.return_to,
        &list_context,
    );
    let (_, organization, cookie) =
        match action_context(state, headers, slug, &submission.csrf, continuation.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !valid_identifier(&submission.environment_id) {
        return mutation_redirect(
            state,
            lifecycle_feedback_path(&list_context.list_url(slug), "", "invalid"),
            "",
            "",
            headers,
        );
    }
    let environment_id = submission.environment_id.clone();
    match operation(state, cookie, organization.id, submission.environment_id).await {
        Ok(()) => {
            let destination = if message == "environment-destroying" {
                deletion_feedback_path(&list_context.list_url(slug), &environment_id)
            } else {
                lifecycle_feedback_path(&continuation, message, "")
            };
            mutation_redirect(state, destination, "", "", headers)
        }
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, headers)
        }
        Err(error) => mutation_redirect(
            state,
            lifecycle_feedback_path(&continuation, "", mutation_error(&error)),
            "",
            "",
            headers,
        ),
    }
}

fn lifecycle_return_path(
    slug: &str,
    environment_id: &str,
    return_to: &str,
    context: &SandboxListContext,
) -> String {
    if return_to == "detail" && super::terminal::canonical_environment_id(environment_id) {
        context.detail_url(slug, environment_id)
    } else {
        context.list_url(slug)
    }
}

/// Delete lands on the list and names the Sandbox there, so the page can say
/// what became of it. Only a canonical Sandbox id is ever echoed.
fn deletion_feedback_path(path: &str, environment_id: &str) -> String {
    let mut target = lifecycle_feedback_path(path, "environment-destroying", "");
    if super::terminal::canonical_environment_id(environment_id) {
        target.push_str("&environment=");
        target.push_str(environment_id);
    }
    target
}

fn lifecycle_feedback_path(path: &str, message: &str, error: &str) -> String {
    // The path is constructed above, never supplied as a browser return URL.
    let mut target = Url::parse(&format!("https://codewire.invalid{path}"))
        .expect("server-owned lifecycle path");
    if matches!(
        message,
        "environment-started" | "environment-stopping" | "environment-destroying"
    ) {
        target.query_pairs_mut().append_pair("message", message);
    } else if matches!(
        error,
        "invalid"
            | "not-authorized"
            | "not-found"
            | "quota"
            | "rate-limited"
            | "unconfirmed"
            | "unavailable"
    ) {
        target.query_pairs_mut().append_pair("error", error);
    }
    let mut result = target.path().to_owned();
    if let Some(query) = target.query() {
        result.push('?');
        result.push_str(query);
    }
    result
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
    form.draft_actor = crate::environment_drafts::actor(state, cookie.clone()).await?;
    form.draft_organization.clone_from(&organization.id);
    let mut environments =
        filtered_environments(state, cookie.clone(), &organization.id, query).await?;
    let message = if query.message == "environment-destroying" {
        deletion_announcement(state, cookie.clone(), &organization.id, &query.environment).await
    } else {
        page_message(&query.message).to_owned()
    };
    let confidential_actions_allowed =
        state.confidential_storage_enabled && (!state.confidential_admin_only || is_admin);
    for environment in &mut environments {
        apply_confidential_visibility(state, is_admin, environment);
    }
    let (options, ()) = tokio::join!(
        environment_connect::create_options(state, cookie.clone(), &organization.id),
        environment_connect::mark_credential_attention(state, cookie.clone(), &mut environments),
    );
    hydrate_options(&mut form, options?);
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
            port_error: String::new(),
            label_error: String::new(),
            access_error: String::new(),
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
        environments_loading: false,
        create_form: form,
        source_editor,
        port_panel,
        trust_summary,
        resize_confirmation: None,
        resize_operation,
        search: bounded_query(&query.search),
        state: allowlisted_state(&query.state).to_owned(),
        message,
        error: page_error(&query.error).to_owned(),
    })
}

/// What became of the Sandbox a Delete named: still deleting, deleted, or not
/// deleted. Reading it is presentation only; when it cannot be read, the page
/// still confirms the accepted request.
async fn deletion_announcement(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    environment_id: &str,
) -> String {
    const REQUESTED: &str = "Sandbox deletion requested.";
    if !super::terminal::canonical_environment_id(environment_id) {
        return REQUESTED.to_owned();
    }
    match environment_connect::environment_data(state, cookie, org_id, environment_id).await {
        Ok(environment) if environment.id == environment_id => deletion_outcome(environment),
        _ => REQUESTED.to_owned(),
    }
}

fn deletion_outcome(environment: codewire_proto::codewire::v1::Environment) -> String {
    let deleting = environment.desired_state.to_i32()
        == codewire_proto::codewire::v1::DesiredState::Destroyed as i32;
    let sandbox = environment_connect::environment_row(environment);
    match sandbox.state {
        "destroying" => format!("Deleting {}…", sandbox.name),
        "destroyed" => format!("{} deleted.", sandbox.name),
        "error" if deleting => format!("{} could not be deleted.", sandbox.name),
        // A later lifecycle superseded the deletion: the list says the rest.
        _ => String::new(),
    }
}

async fn filtered_environments(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    query: &EnvironmentsQuery,
) -> Result<Vec<crate::view::EnvironmentRow>, ConnectError> {
    let mut environments = environment_connect::inventory(
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

async fn render_create_action_page(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: crate::view::DashboardView,
    organization: OrganizationContext,
    cookie: HeaderValue,
    mut form: EnvironmentCreateFormView,
    status: StatusCode,
) -> Response {
    form.draft_actor = match crate::environment_drafts::actor(state, cookie).await {
        Ok(actor) => actor,
        Err(error) => {
            return connect_page_error(error, &environments_path(&organization.slug), headers);
        }
    };
    form.draft_organization.clone_from(&organization.id);
    form.show_confidential_controls = state.confidential_storage_enabled
        && (!state.confidential_admin_only || dashboard.is_admin);
    form.confidential_available &= form.show_confidential_controls;
    let page = EnvironmentsPageView {
        environments: Vec::new(),
        environments_loading: true,
        create_form: form,
        source_editor: None,
        port_panel: None,
        trust_summary: None,
        resize_confirmation: None,
        resize_operation: None,
        search: String::new(),
        state: String::new(),
        message: String::new(),
        error: String::new(),
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

pub(super) fn default_create_form(token: String, expanded: bool) -> EnvironmentCreateFormView {
    EnvironmentCreateFormView {
        csrf_token: token,
        draft_actor: String::new(),
        draft_organization: String::new(),
        draft_id: uuid::Uuid::new_v4().to_string(),
        draft_return: crate::environment_drafts::DraftReturn::default(),
        draft_restore_allowed: true,
        draft_restored: false,
        options_loading: false,
        expanded,
        name: String::new(),
        preset_id: String::new(),
        image: codewire_server_core::runtime_images::DEFAULT_WORKSPACE_IMAGE.to_owned(),
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
        ttl: String::new(),
        isolation_tier: "standard".to_owned(),
        confidential_available: false,
        show_confidential_controls: false,
        confidential_price: String::new(),
        preview_base_domain: String::new(),
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

pub(super) fn hydrate_options(
    form: &mut EnvironmentCreateFormView,
    options: EnvironmentCreateOptions,
) {
    form.preview_base_domain = options.preview_base_domain;
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
            ..Default::default()
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
            *error = "Enter a duration from 60 seconds to 365 days, such as 8h or 7d, or leave it empty."
                .to_owned();
            None
        }
    }
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
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
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
    SandboxListContext::new(value, "all").list_search
}

fn allowlisted_state(value: &str) -> &'static str {
    SandboxListContext::state(value)
}

fn mutation_error(error: &ConnectError) -> &'static str {
    match error.code {
        ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition => "invalid",
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::NotFound => "not-found",
        // Quota refusals carry a reason; a bare ResourceExhausted is a rate limit.
        ErrorCode::ResourceExhausted => match connect_error_reason(error).as_deref() {
            Some("quota_exceeded" | "resource_limit_exceeded") => "quota",
            _ => "rate-limited",
        },
        // The request may have been applied: never suggest a blind retry.
        ErrorCode::Internal | ErrorCode::Unknown | ErrorCode::DeadlineExceeded => "unconfirmed",
        _ => "unavailable",
    }
}

pub(super) fn page_message(value: &str) -> &'static str {
    match value {
        "environment-created" => "Sandbox creation started.",
        "environment-started" => "Sandbox start requested.",
        "environment-stopping" => "Sandbox stop requested.",
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
        "setup-running" => {
            "Setup is still running. Nothing was applied. You can resize when it finishes."
        }
        "not-authorized" => "You do not have permission to change that Sandbox.",
        "not-found" => "The Sandbox no longer exists.",
        "quota" => {
            "This would exceed your organization's Sandbox quota. Stop or delete a Sandbox, then try again."
        }
        "rate-limited" => "Too many Sandbox changes at once. Wait a moment, then try again.",
        "unconfirmed" => {
            "The Sandbox change could not be confirmed. Check its current state before trying again."
        }
        "unavailable" => "The Sandbox service is temporarily unavailable.",
        _ => "",
    }
}

fn port_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change this preview.",
        "invalid-port" => "Enter an internal port from 1 to 65535.",
        "reserved-port" => "Port 2222 is reserved for the Sandbox runtime.",
        "invalid-port-label" => {
            "Use a 2–22 character lowercase preview label, starting and ending with a letter or digit."
        }
        "invalid-port-access" => "Choose who can open the HTTPS preview.",
        "port-conflict" => {
            "This internal port or preview label is already registered. Choose a different port or label."
        }
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

    fn setup_hrefs(html: &str) -> Vec<&str> {
        html.split("href=\"")
            .skip(1)
            .filter_map(|tail| tail.split('"').next())
            .filter(|href| href.contains("/settings/credentials/") || href.contains("/secrets/"))
            .collect()
    }

    #[test]
    fn create_setup_links_use_only_the_final_canonical_draft_handle() {
        let organization = test_organization();
        for kind in ["fresh", "restored", "error"] {
            let mut form = default_create_form("csrf-not-navigation".into(), true);
            form.draft_id = "00000000-0000-4000-8000-000000000003".into();
            form.draft_actor = "actor-not-navigation".into();
            form.name = "name-not-navigation".into();
            form.draft_restored = kind == "restored";
            if kind == "error" {
                form.form_error = "Review your selections".into();
                form.draft_restore_allowed = false;
            }
            // Options replace source fields. Navigation derives from the
            // final form, so hydration cannot drop or replace the handle.
            hydrate_options(
                &mut form,
                EnvironmentCreateOptions {
                    presets: vec![],
                    agents: vec![],
                    sources: Default::default(),
                    preview_base_domain: String::new(),
                    confidential_available: false,
                    confidential_price: String::new(),
                },
            );
            let html = EnvironmentCreateFormTemplate {
                organization: &organization,
                form: &form,
            }
            .render()
            .unwrap();
            let hrefs = setup_hrefs(&html);
            assert_eq!(hrefs.len(), 5);
            for href in hrefs {
                assert!(href.ends_with("creation_draft=00000000-0000-4000-8000-000000000003"));
                assert!(!href.contains("not-navigation"));
                assert!(
                    href.starts_with(&format!("/{}/secrets/", organization.slug))
                        || href.starts_with("/settings/secrets/?creation_draft=")
                        || href.starts_with("/settings/credentials/?creation_draft=")
                );
            }
        }
    }

    #[test]
    fn invalid_create_draft_ids_do_not_enter_setup_links() {
        let organization = test_organization();
        for id in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-ABCDEF123456",
            "https://canary.invalid/?private=value",
        ] {
            let mut form = default_create_form("current-csrf".into(), true);
            form.draft_id = id.into();
            assert!(form.creation_draft_parameter().is_empty());
            let html = EnvironmentCreateFormTemplate {
                organization: &organization,
                form: &form,
            }
            .render()
            .unwrap();
            assert!(
                setup_hrefs(&html).into_iter().all(
                    |href| !href.contains("creation_draft") && !href.contains("canary.invalid")
                )
            );
        }
    }

    #[test]
    fn edit_source_setup_links_do_not_inherit_the_inventory_create_handle() {
        let organization = test_organization();
        let page = EnvironmentsPageView {
            environments: vec![],
            environments_loading: false,
            create_form: default_create_form("current-csrf".into(), false),
            source_editor: Some(crate::view::EnvironmentSourcesEditView {
                environment_id: "00000000-0000-4000-8000-000000000004".into(),
                environment_name: "Existing Sandbox".into(),
                fields: Default::default(),
                expected: crate::view::EnvironmentSourcesSummaryView {
                    selection: Default::default(),
                    operation_generation: 1,
                    project: String::new(),
                    organization: false,
                    personal: false,
                    profile: String::new(),
                    profile_revision: String::new(),
                    profile_name: String::new(),
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
        let html = OrganizationEnvironmentsContentTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .unwrap();
        let hrefs = setup_hrefs(&html);
        // Each secret source's manage link follows its own choice.
        assert_eq!(hrefs.len(), 4);
        assert_eq!(
            hrefs[0],
            format!("/{}/secrets/organization/", organization.slug)
        );
        assert_eq!(hrefs[1], "/settings/secrets/");
        assert_eq!(hrefs[2], organization.secrets_url);
        assert_eq!(hrefs[3], "/settings/credentials/");
    }

    #[test]
    fn explicit_return_template_keeps_drawer_url_and_requested_marker_together() {
        use crate::environment_drafts::DraftReturn;
        let organization = test_organization();
        for navigation in [
            DraftReturn::NoRequest,
            DraftReturn::Exact("00000000-0000-4000-8000-000000000003".into()),
            DraftReturn::Unavailable,
        ] {
            let mut form = default_create_form("current-csrf".into(), true);
            if let DraftReturn::Exact(id) = &navigation {
                form.draft_id.clone_from(id);
            }
            form.draft_return = navigation.clone();
            let page = EnvironmentsPageView {
                environments: Vec::new(),
                environments_loading: false,
                create_form: form,
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
            let html = OrganizationEnvironmentsContentTemplate {
                organization: &organization,
                page: &page,
            }
            .render()
            .unwrap();
            assert!(html.contains(&format!(
                "data-create-url=\"{}new/{}\"",
                organization.environments_url,
                navigation.query()
            )));
            assert!(html.contains(&format!(
                "data-create-draft-exact=\"{}\"",
                navigation.requested()
            )));
            assert!(html.contains("name=\"_csrf\" value=\"current-csrf\""));
            assert!(crate::environment_drafts::canonical_id(
                &page.create_form.draft_id
            ));
        }
    }

    #[test]
    fn create_options_accept_opaque_product_organization_ids() {
        let draft = "00000000-0000-4000-8000-000000000003";
        let body = |organization: &str| {
            format!(
                "_csrf=synthetic&actor=11111111111140008000000000000001&organization={organization}&draft_id={draft}&draft_return="
            )
        };
        // Product organization IDs are opaque 32-hex strings, not UUIDs.
        for organization in [
            "6bf8d155e84c4fc5b479b17022fe41dd",
            "00000000-0000-4000-8000-000000000002",
        ] {
            let request = CreateOptionsRequest::parse(body(organization).as_bytes()).unwrap();
            assert_eq!(request.organization, organization);
        }
        for organization in ["", "organization%3Adelimiter", &"a".repeat(129)] {
            assert!(CreateOptionsRequest::parse(body(organization).as_bytes()).is_err());
        }
    }

    #[test]
    fn only_the_daemon_ssh_port_is_reserved_for_previews() {
        let submission = EnvironmentSubmission::parse(b"image=example.test/workspace&app_port_0=2222&app_label_0=ssh&app_access_0=creator&app_port_1=2223&app_label_1=web&app_access_1=creator").unwrap();
        let mut form = submission.form_view("synthetic-csrf".into());
        let _ = submission.validate_and_draft("org-test", &mut form);
        assert_eq!(
            form.app_ports[0].port_error,
            "Port 2222 is reserved for the Sandbox runtime."
        );
        assert!(form.app_ports[1].port_error.is_empty());
        assert_eq!(
            port_error("reserved-port"),
            "Port 2222 is reserved for the Sandbox runtime."
        );
    }

    #[test]
    fn preview_row_errors_preserve_all_inputs_and_are_field_associated() {
        let submission = EnvironmentSubmission::parse(b"image=example.test/workspace&app_port_0=3000&app_label_0=web&app_access_0=creator&app_port_1=8080&app_label_1=web&app_access_1=public&app_port_2=3000&app_label_2=api&app_access_2=org_members&app_port_3=2222&app_label_3=ssh&app_access_3=creator&app_port_4=65536&app_label_4=Bad&app_access_4=private").unwrap();
        let mut form = submission.form_view("synthetic-csrf".into());
        assert!(
            submission
                .validate_and_draft("org-test", &mut form)
                .is_none()
        );
        assert_eq!(form.app_ports.len(), 5);
        assert!(form.app_ports[0].port_error.is_empty());
        assert!(form.app_ports[1].label_error.contains("already used"));
        assert!(form.app_ports[2].port_error.contains("already used"));
        assert!(form.app_ports[3].port_error.contains("reserved"));
        assert!(!form.app_ports[4].port_error.is_empty());
        assert!(!form.app_ports[4].label_error.is_empty());
        assert!(!form.app_ports[4].access_error.is_empty());
        assert_eq!(form.app_ports[4].port, "65536");
        assert_eq!(form.app_ports[4].label, "Bad");
        let organization = test_organization();
        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .unwrap();
        assert!(html.contains("aria-describedby=\"app-label-error-1\""));
        assert!(html.contains("aria-describedby=\"app-port-error-2\""));
        assert!(html.contains("aria-describedby=\"app-access-error-4\""));
        assert!(html.contains("name=\"app_port_4\" type=\"number\""));
        assert!(html.contains("value=\"65536\""));
    }

    #[test]
    fn advanced_creation_disclosures_open_for_errors_and_preserve_exact_values() {
        let organization = test_organization();
        let render = |form: &EnvironmentCreateFormView| {
            EnvironmentCreateFormTemplate {
                organization: &organization,
                form,
            }
            .render()
            .unwrap()
        };
        let mut form = default_create_form("synthetic-csrf".into(), true);
        let html = render(&form);
        assert!(html.contains("data-create-resources aria-labelledby=\"create-resources-title\">"));
        assert!(html.contains("data-create-runtime>"));
        assert!(html.contains("1 vCPU</option>"));
        assert!(html.contains("2 GiB</option>"));
        assert!(html.contains("not an idle timeout"));
        assert!(!html.contains("cw-snapshot-meter"));
        assert!(!html.contains("Use 0 for infinity"));
        form.cpu = "750".into();
        form.cpu_error = "Choose a valid resource value".into();
        form.install_command = "printf '<preserved-command>'".into();
        let html = render(&form);
        assert!(html.contains("data-create-runtime open>"));
        assert!(html.contains("value=\"750\" selected>750 millicores"));
        assert!(!html.contains("<preserved-command>"));
        assert!(html.contains("preserved-command"));
    }

    #[test]
    fn configured_preview_pattern_is_provisional_and_never_a_fallback_address() {
        let mut form = default_create_form("synthetic-csrf".into(), true);
        let organization = test_organization();
        let render = |form: &EnvironmentCreateFormView| {
            EnvironmentCreateFormTemplate {
                organization: &organization,
                form,
            }
            .render()
            .unwrap()
        };
        let missing = render(&form);
        assert!(missing.contains("Preview URLs are unavailable on this deployment."));
        assert!(!missing.contains("cwpreview.sh"));
        form.preview_base_domain = "preview.example.test".into();
        let configured = render(&form);
        assert!(
            configured.contains("https://{label}-{sandbox-id-prefix}-test.preview.example.test")
        );
        assert!(configured.contains("not an assigned URL"));
        assert!(!configured.contains("href=\"https://{label}"));
        assert!(configured.contains("does not block every other form of network access"));
    }

    #[test]
    fn digit_first_preview_labels_and_default_creator_access_are_preserved() {
        let submission = EnvironmentSubmission::parse(
            b"image=example.test/workspace&app_port_0=3000&app_label_0=9web&app_access_0=",
        )
        .unwrap();
        let mut form = submission.form_view("synthetic-csrf".into());
        let request = submission
            .validate_and_draft("org-test", &mut form)
            .unwrap();
        let spec = codewire_project_proto::from_proto(request.project_spec.into_option().unwrap())
            .unwrap();
        assert_eq!(spec.application_ports[0].label, "9web");
        assert_eq!(spec.application_ports[0].access, "creator");
    }

    #[tokio::test]
    async fn port_fragments_preserve_the_existing_csrf_token_and_terminal_document() {
        let panel = EnvironmentPortPanelView {
            environment_id: "5d1db799-4300-4ab3-b957-efb980760542".into(),
            environment_name: "Example".into(),
            ports: vec![crate::view::EnvironmentPortRow {
                id: "port-id".into(),
                port: 3000,
                label: "web".into(),
                access: "Sandbox creator",
                preview_url: "https://web-5d1db-test.preview.example".into(),
                has_preview: true,
            }],
            port: "8080".into(),
            label: "<invalid>".into(),
            access: "creator".into(),
            form_error: "Check the preview label.".into(),
            port_error: String::new(),
            label_error: "Check the preview label.".into(),
            access_error: String::new(),
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
        assert!(html.contains("Internal port 3000 · Sandbox creator"));
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
        let context = SandboxListContext::default();
        assert_eq!(
            lifecycle_return_path("my-org", id, "detail", &context),
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
            assert_eq!(
                lifecycle_return_path("my-org", id, target, &context),
                "/my-org/"
            );
        }
        for invalid in [
            "",
            "other-env",
            "../other",
            "5D1DB799-4300-4AB3-B957-EFB980760542",
        ] {
            assert_eq!(
                lifecycle_return_path("my-org", invalid, "detail", &context),
                "/my-org/"
            );
        }
        let legacy: EnvironmentIdSubmission = serde_json::from_value(serde_json::json!({
            "_csrf": "synthetic", "environment_id": id,
        }))
        .unwrap();
        assert_eq!(legacy.return_to, "");
        assert_eq!(legacy.list_context.list_search, "");
        assert_eq!(legacy.list_context.normalized().list_state, "all");
    }

    #[test]
    fn lifecycle_feedback_preserves_encoded_same_org_list_context() {
        let id = "5d1db799-4300-4ab3-b957-efb980760542";
        let context = SandboxListContext::new("a&state=destroyed ☃", "running");
        for (destination, message, error, expected_path, expected_search_key) in [
            (
                "detail",
                "environment-started",
                "",
                format!("/my-org/{id}/"),
                "list_search",
            ),
            (
                "detail",
                "environment-stopping",
                "",
                format!("/my-org/{id}/"),
                "list_search",
            ),
            (
                "list",
                "environment-destroying",
                "",
                "/my-org/".to_owned(),
                "search",
            ),
            (
                "detail",
                "",
                "not-authorized",
                format!("/my-org/{id}/"),
                "list_search",
            ),
            (
                "detail",
                "",
                "quota",
                format!("/my-org/{id}/"),
                "list_search",
            ),
            (
                "detail",
                "",
                "rate-limited",
                format!("/my-org/{id}/"),
                "list_search",
            ),
            (
                "detail",
                "",
                "unconfirmed",
                format!("/my-org/{id}/"),
                "list_search",
            ),
        ] {
            let path = lifecycle_return_path("my-org", id, destination, &context);
            let target = lifecycle_feedback_path(&path, message, error);
            let url = Url::parse(&format!("https://codewire.invalid{target}")).unwrap();
            assert_eq!(url.path(), expected_path);
            assert_eq!(
                url.query_pairs()
                    .find(|(key, _)| key == expected_search_key)
                    .unwrap()
                    .1,
                "a&state=destroyed ☃"
            );
            let feedback = if message.is_empty() {
                ("error", error)
            } else {
                ("message", message)
            };
            assert_eq!(
                url.query_pairs()
                    .find(|(key, _)| key == feedback.0)
                    .unwrap()
                    .1,
                feedback.1
            );
            assert_eq!(url.query_pairs().count(), 3);
            assert_eq!(target.matches('?').count(), 1);
        }
        let path = lifecycle_return_path("my-org", id, "https://foreign.test/", &context);
        assert!(path.starts_with("/my-org/?search="));
        assert_eq!(
            lifecycle_feedback_path(&path, "unknown", "token=forbidden"),
            path
        );
    }

    #[tokio::test]
    async fn native_lifecycle_forms_decode_navigation_metadata_and_reject_duplicate_csrf() {
        use axum::extract::FromRequest as _;
        let request = |body: &str| {
            axum::http::Request::builder()
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(body.to_owned()))
                .unwrap()
        };
        let Form(form) = Form::<EnvironmentIdSubmission>::from_request(request("_csrf=synthetic&environment_id=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb&return_to=detail&list_search=a%26state%3Ddestroyed&list_state=running"), &()).await.unwrap();
        assert_eq!(form.csrf, "synthetic");
        assert_eq!(form.return_to, "detail");
        assert_eq!(form.list_context.list_search, "a&state=destroyed");
        assert_eq!(form.list_context.list_state, "running");
        assert!(Form::<EnvironmentIdSubmission>::from_request(request("_csrf=first&_csrf=second&environment_id=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb&list_search=test"), &()).await.is_err());
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
            can_admin: true,
            environments_url: "/test/".into(),
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
    fn confidential_choice_is_disabled_until_it_can_bind() {
        let organization = test_organization();
        let mut form = default_create_form("csrf".into(), true);
        form.show_confidential_controls = true;
        form.confidential_available = false;
        form.confidential_price = "$0.1000 / CPU-hour + $0.0500 / GiB-hour".to_owned();
        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &form,
        }
        .render()
        .unwrap();
        assert!(html.contains(
            r#"<option value="confidential" disabled>Confidential isolation is temporarily unavailable</option>"#
        ));
        assert!(!html.contains("CPU-hour"));
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

        assert!(html.contains("<option value=\"750\" selected>750 millicores</option><option value=\"1000\">1 vCPU</option><option value=\"2000\">2 vCPU</option><option value=\"4000\">4 vCPU</option><option value=\"8000\">8 vCPU</option></select>"));
        assert!(html.contains(
            "<option value=\"1024\" selected>1024 MiB</option><option value=\"2048\">2 GiB</option>"
        ));
        assert!(html.contains(
            "<option value=\"5\" selected>5 GiB</option><option value=\"10\">10 GiB</option>"
        ));

        let defaults = default_create_form("csrf".into(), true);
        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &defaults,
        }
        .render()
        .expect("environment create form");
        assert!(html.contains("name=\"cpu\" aria-describedby=\"environment-cpu-help\"><option value=\"1000\" selected>1 vCPU</option><option value=\"2000\">2 vCPU</option>"));
        assert!(html.contains("<option value=\"2048\" selected>2 GiB</option><option value=\"4096\">4 GiB</option><option value=\"8192\">8 GiB</option><option value=\"16384\">16 GiB</option></select>"));
        assert!(html.contains(
            "<option value=\"10\" selected>10 GiB</option><option value=\"20\">20 GiB</option>"
        ));
        assert!(!html.contains("Platform default"));
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
                setup_running: false,
                setup_failure: String::new(),
                confidential_actions_allowed: false,
                vscode_url: "https://vscode.invalid".into(),
                ports: Vec::new(),
                sources: None,
                credential_attention: Vec::new(),
            }],
            environments_loading: false,
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
        assert!(rendered.contains("Delete permanently"));
        assert_eq!(rendered.matches("scope=\"col\"").count(), 6);
        assert!(!rendered.contains("<th>"));
        assert!(!rendered.contains("Snapshots are coming soon"));
        assert!(!rendered.contains("Region unavailable"));
        for hidden in [
            ">Start</button>",
            ">Resize</summary>",
            ">Ports</a>",
            ">Terminal</a>",
            ">VS Code</a>",
        ] {
            assert!(!rendered.contains(hidden), "unexpected action {hidden}");
        }
        let mut empty = page.clone();
        empty.environments.clear();
        let rendered = EnvironmentListTemplate {
            organization: &organization,
            page: &empty,
        }
        .render()
        .unwrap();
        assert_eq!(rendered.matches("scope=\"col\"").count(), 6);
        assert!(rendered.contains("colspan=\"6\""));
        assert!(!rendered.contains("Region unavailable"));
    }

    fn resize_test_row(
        id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
    ) -> crate::view::EnvironmentRow {
        crate::view::EnvironmentRow {
            id: id.into(),
            name: "Resize test".into(),
            state: "running",
            state_tone: "success",
            state_symbol: "●",
            preset_name: String::new(),
            isolation_tier: "standard",
            last_event: String::new(),
            created: String::new(),
            deletion_state: "unscheduled",
            shutdown_at: None,
            shutdown_at_label: "Not currently scheduled".into(),
            cost: String::new(),
            running_time: String::new(),
            resources: String::new(),
            cpu_millicores,
            memory_mb,
            disk_gb: 10,
            hourly_rate: String::new(),
            can_start: false,
            can_stop: true,
            can_destroy: true,
            setup_running: false,
            setup_failure: String::new(),
            confidential_actions_allowed: true,
            vscode_url: "https://vscode.invalid".into(),
            ports: Vec::new(),
            sources: None,
            credential_attention: Vec::new(),
        }
    }

    fn render_terminal(
        organization: &OrganizationContext,
        environment: crate::view::EnvironmentRow,
    ) -> String {
        let view = crate::view::DashboardView {
            user_name: "Resize".into(),
            csrf_token: Default::default(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            organization_navigation_unavailable: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: "/settings/".into(),
            has_selected_organization: false,
            selected_organization_name: String::new(),
            selected_organization_slug: String::new(),
            selected_organization_url: String::new(),
            sandboxes: Vec::new(),
            recent_sandboxes: Vec::new(),
            sandbox_rail_available: false,
            sandbox_rail_loading: false,
            sandbox_total: 0,
            sandbox_running: 0,
            sandbox_stopped: 0,
            sandbox_attention: 0,
            provisioned_cpu_millicores: 0,
            provisioned_memory_mb: 0,
            provisioned_disk_gb: 0,
            sidebar_collapsed: false,
        };
        let terminal_page = crate::view::TerminalPageView {
            account_id: "account".into(),
            organization_id: organization.id.clone(),
            environment,
            websocket_origin: "wss://dashboard.invalid".into(),
            list_context: SandboxListContext::default(),
            list_url: "/test/".into(),
            message: String::new(),
            creation_notice: false,
            error: String::new(),
        };
        crate::templates::TerminalTemplate {
            view: &view,
            organization,
            page: &terminal_page,
            csrf_token: "csrf",
            style_nonce: "nonce",
        }
        .render()
        .unwrap()
    }

    fn resize_ids(html: &str) -> Vec<&str> {
        html.split(" id=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|id| id.starts_with("resize"))
            .collect()
    }

    #[test]
    fn every_resize_form_offers_create_choices_and_keeps_an_off_catalog_current_value() {
        const OFF: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        const ON: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let organization = test_organization();
        let off_catalog = resize_test_row(OFF, 750, 1_536);
        let page = EnvironmentsPageView {
            environments: vec![off_catalog.clone(), resize_test_row(ON, 2_000, 4_096)],
            environments_loading: false,
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
        let list = EnvironmentListTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .unwrap();
        assert!(list.contains(&format!(
            "<label class=\"cw-label\" for=\"resize-{OFF}-cpu\">CPU</label><select class=\"cw-select\" id=\"resize-{OFF}-cpu\" name=\"cpu_millicores\" required><option value=\"750\" selected data-resize-current>750 millicores (current)</option><option value=\"1000\">1 vCPU</option><option value=\"2000\">2 vCPU</option><option value=\"4000\">4 vCPU</option><option value=\"8000\">8 vCPU</option></select>"
        )));
        assert!(list.contains(&format!(
            "<label class=\"cw-label\" for=\"resize-{OFF}-memory\">Memory</label><select class=\"cw-select\" id=\"resize-{OFF}-memory\" name=\"memory_mb\" required><option value=\"1536\" selected data-resize-current>1536 MiB (current)</option><option value=\"2048\">2 GiB</option>"
        )));
        assert!(list.contains(&format!(
            "id=\"resize-{ON}-cpu\" name=\"cpu_millicores\" required><option value=\"1000\">1 vCPU</option><option value=\"2000\" selected>2 vCPU</option><option value=\"4000\">4 vCPU</option>"
        )));
        assert!(list.contains(&format!(
            "id=\"resize-{ON}-memory\" name=\"memory_mb\" required><option value=\"2048\">2 GiB</option><option value=\"4096\" selected>4 GiB</option>"
        )));
        assert!(list.contains(&format!(
            "<label class=\"cw-label\" for=\"resize-{ON}-disk\">Disk (GiB)</label><input class=\"cw-input\" id=\"resize-{ON}-disk\" name=\"disk_gb\" type=\"number\" min=\"1\" max=\"16384\" value=\"10\" required>"
        )));
        assert_eq!(list.matches("data-resize-current").count(), 2);
        assert!(!list.contains("millicores)"));

        let terminal = render_terminal(&organization, off_catalog);
        // The Resize dialog and its no-script fallback render the same fields.
        for form in ["resize", "resize-fallback"] {
            assert!(terminal.contains(&format!(
                "<label class=\"cw-label\" for=\"{form}-cpu\">CPU</label><select class=\"cw-select\" id=\"{form}-cpu\" name=\"cpu_millicores\" required><option value=\"750\" selected data-resize-current>750 millicores (current)</option><option value=\"1000\">1 vCPU</option>"
            )));
            assert!(terminal.contains(&format!(
                "id=\"{form}-memory\" name=\"memory_mb\" required><option value=\"1536\" selected data-resize-current>1536 MiB (current)</option>"
            )));
        }
        assert!(!terminal.contains("millicores)"));
        // One footer submits each step's form; no text Close duplicates
        // Cancel or Done. Only controllers from v2 reveal Apply in that footer,
        // so a cached v1 script must not pair with this markup.
        assert!(terminal.contains(crate::assets::SANDBOX_RESIZE_SCRIPT_PATH));
        assert_eq!(
            crate::assets::SANDBOX_RESIZE_SCRIPT_PATH,
            "/assets/codewire/sandbox-resize-v3.js"
        );
        let resize_dialog = terminal
            .split_once("id=\"sandbox-resize\"")
            .and_then(|(_, rest)| rest.split_once("</dialog>"))
            .map(|(dialog, _)| dialog)
            .expect("Resize dialog");
        assert_eq!(resize_dialog.matches("<footer").count(), 1);
        assert!(!resize_dialog.contains("Close"));
        for form in ["sandbox-resize-plan-form", "sandbox-resize-apply-form"] {
            assert!(resize_dialog.contains(&format!("<form id=\"{form}\"")));
            assert!(resize_dialog.contains(&format!("type=\"submit\" form=\"{form}\"")));
        }

        for html in [&list, &terminal] {
            let ids = resize_ids(html);
            let unique: std::collections::BTreeSet<_> = ids.iter().collect();
            assert_eq!(
                unique.len(),
                ids.len(),
                "duplicate Resize field id in {ids:?}"
            );
            for id in ids.iter().filter(|id| {
                id.ends_with("-cpu") || id.ends_with("-memory") || id.ends_with("-disk")
            }) {
                assert!(
                    html.contains(&format!("for=\"{id}\"")),
                    "unlabelled Resize field {id}"
                );
            }
        }
    }

    /// A5c: the Sandbox page follows live setup stages only while a start is
    /// in flight or setup still owns the running Sandbox, with a heading, a
    /// live status, an alert for failure and an ordered list of stages.
    #[test]
    fn sandbox_page_streams_setup_only_while_setup_runs() {
        const READY: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        const SETUP: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let organization = test_organization();
        let section = "<section class=\"cw-setup-progress\" aria-labelledby=\"setup-progress-title\" data-setup-progress";
        let ready = render_terminal(&organization, resize_test_row(READY, 1_000, 2_048));
        assert!(!ready.contains(section));
        assert!(ready.contains(crate::assets::SETUP_PROGRESS_SCRIPT_PATH));
        for row in [
            crate::view::EnvironmentRow {
                setup_running: true,
                setup_failure: String::new(),
                ..resize_test_row(SETUP, 1_000, 2_048)
            },
            crate::view::EnvironmentRow {
                state: "creating",
                ..resize_test_row(SETUP, 1_000, 2_048)
            },
        ] {
            let page = render_terminal(&organization, row);
            assert!(page.contains(section));
            assert!(page.contains(&format!(
                "data-setup-environment-id=\"{SETUP}\" data-setup-org-slug=\"{}\"><h2 id=\"setup-progress-title\">Setup</h2><p class=\"cw-setup-progress-status\" role=\"status\" data-setup-status>",
                organization.slug
            )));
            assert!(page.contains("<p class=\"cw-alert cw-alert--error\" role=\"alert\" data-setup-failure hidden></p><ol class=\"cw-setup-stages\" data-setup-stages></ol>"));
        }
    }

    /// A5c: a recorded setup failure keeps the Setup section and its alert
    /// after a reload, without script, escaped like any other text.
    #[test]
    fn a_failed_setup_keeps_its_alert_after_a_reload() {
        const FAILED: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
        let organization = test_organization();
        let page = render_terminal(
            &organization,
            crate::view::EnvironmentRow {
                setup_failure: "git clone: exited 128 <b>x</b>".into(),
                ..resize_test_row(FAILED, 1_000, 2_048)
            },
        );
        assert!(page.contains("data-setup-status>Setup stopped.</p>"));
        assert!(page.contains(
            "<p class=\"cw-alert cw-alert--error\" role=\"alert\" data-setup-failure>Setup failed: git clone: exited 128 &#60;b&#62;x&#60;/b&#62;</p>"
        ));
    }

    /// #2333: orchestration refuses Resize while setup owns a running Sandbox.
    /// Without script, neither the detail page nor the inventory may offer it
    /// then without saying why.
    #[test]
    fn resize_waits_for_setup_and_says_why_without_script() {
        const READY: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        const SETUP: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        const NOTE: &str = "Resize is available when setup finishes.";
        let organization = test_organization();
        let ready = resize_test_row(READY, 1_000, 2_048);
        let setup = crate::view::EnvironmentRow {
            setup_running: true,
            setup_failure: String::new(),
            ..resize_test_row(SETUP, 1_000, 2_048)
        };
        let page = EnvironmentsPageView {
            environments: vec![ready.clone(), setup.clone()],
            environments_loading: false,
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
        let list = EnvironmentListTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .unwrap();
        assert_eq!(list.matches(">Resize</summary>").count(), 1);
        assert!(list.contains(&format!("id=\"resize-{READY}-cpu\"")));
        assert!(!list.contains(&format!("id=\"resize-{SETUP}-cpu\"")));
        assert_eq!(
            list.matches(&format!("<p class=\"cw-row-menu-note\">{NOTE}</p>"))
                .count(),
            1
        );

        let waiting = render_terminal(&organization, setup);
        assert!(waiting.contains(&format!(
            "<p class=\"cw-row-menu-note\" id=\"sandbox-resize-setup-note\" data-resize-setup-note>{NOTE}</p>"
        )));
        assert!(waiting.contains(
            "data-resize-open aria-describedby=\"sandbox-resize-setup-note\" hidden>Resize</button>"
        ));
        assert!(waiting.contains(
            "data-sandbox-action=\"resize\" data-sandbox-confirm disabled aria-describedby=\"sandbox-resize-setup-note\">Review resize</button>"
        ));

        let offered = render_terminal(&organization, ready);
        assert!(offered.contains(&format!("data-resize-setup-note hidden>{NOTE}</p>")));
        assert!(!offered.contains("aria-describedby=\"sandbox-resize-setup-note\""));
        assert!(offered.contains(
            "data-sandbox-action=\"resize\" data-sandbox-confirm>Review resize</button>"
        ));
        // Only the readiness v3 and Resize v3 controllers keep this reason
        // and the Resize button in step. A cached older script would leave
        // the reason stale beside an enabled Resize, so both URLs moved.
        for path in [
            crate::assets::TERMINAL_READINESS_SCRIPT_PATH,
            crate::assets::SANDBOX_RESIZE_SCRIPT_PATH,
        ] {
            assert!(waiting.contains(path), "{path}");
        }
        assert_eq!(
            crate::assets::TERMINAL_READINESS_SCRIPT_PATH,
            "/assets/codewire/terminal-readiness-v3.js"
        );
        assert_eq!(
            page_error("setup-running"),
            "Setup is still running. Nothing was applied. You can resize when it finishes."
        );
    }

    fn lifecycle_test_row(
        id: &str,
        name: &str,
        state: codewire_proto::codewire::v1::EnvironmentState,
    ) -> crate::view::EnvironmentRow {
        environment_connect::environment_row(codewire_proto::codewire::v1::Environment {
            id: id.into(),
            name: name.into(),
            state: state.into(),
            setup_complete: true,
            ..Default::default()
        })
    }

    fn lifecycle_test_page(environments: Vec<crate::view::EnvironmentRow>) -> EnvironmentsPageView {
        EnvironmentsPageView {
            environments,
            environments_loading: false,
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
        }
    }

    /// Owner report (2026-10-01): a deleted Sandbox vanished at once behind a
    /// green "destruction requested" banner. It now stays listed, read as
    /// Deleting and offering only its detail page, until it is gone; a
    /// failed deletion offers Delete again.
    #[test]
    fn deleting_sandbox_stays_listed_as_deleting_with_no_lifecycle_actions() {
        use codewire_proto::codewire::v1::EnvironmentState;
        const RUNNING: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        const DELETING: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        const FAILED: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
        let organization = test_organization();
        let page = lifecycle_test_page(vec![
            lifecycle_test_row(RUNNING, "quiet-mesa", EnvironmentState::Running),
            lifecycle_test_row(DELETING, "old-pier", EnvironmentState::Destroying),
            lifecycle_test_row(FAILED, "dry-harbor", EnvironmentState::Error),
        ]);
        let list = EnvironmentListTemplate {
            organization: &organization,
            page: &page,
        }
        .render()
        .unwrap();
        let sandbox = |id: &str| {
            list.split_once(&format!("<tr data-environment-id=\"{id}\""))
                .and_then(|(_, rest)| rest.split_once("</tr>"))
                .map(|(row, _)| row)
                .expect("listed Sandbox")
        };
        let deleting = sandbox(DELETING);
        assert!(deleting.starts_with(
            " data-environment-name=\"old-pier\" data-environment-state=\"destroying\">"
        ));
        assert!(deleting.contains("data-tone=\"warning\"><span class=\"cw-sr-only\" aria-hidden=\"true\">◌</span>deleting…</span>"));
        assert!(deleting.contains(&format!("href=\"/test/{DELETING}/\">Open Sandbox</a>")));
        assert!(deleting.contains(
            "<p class=\"cw-row-menu-note\">Deletion in progress. No other actions are available.</p>"
        ));
        for action in [
            ">Stop</button>",
            "<summary>Stop</summary>",
            ">Start</button>",
            ">Resize</summary>",
            ">Ports</a>",
            ">Terminal</a>",
            ">VS Code</a>",
            "<summary>Delete</summary>",
            "Secrets and credentials",
            "<form",
        ] {
            assert!(
                !deleting.contains(action),
                "a deleting Sandbox offers {action}"
            );
        }
        let running = sandbox(RUNNING);
        for action in [
            ">Stop</button>",
            ">Resize</summary>",
            ">Ports</a>",
            ">Terminal</a>",
            "<summary>Delete</summary>",
        ] {
            assert!(running.contains(action), "a running Sandbox lacks {action}");
        }
        let failed = sandbox(FAILED);
        assert!(failed.contains(">error</span>"));
        assert!(failed.contains(">Start</button>"));
        assert!(failed.contains("Delete permanently"));
        // Script compares refreshes only under the same search and filter.
        assert!(list.contains("data-list-search=\"\" data-list-state=\"all\">"));
    }

    #[test]
    fn delete_names_the_sandbox_in_a_polite_status_instead_of_a_success_banner() {
        use codewire_proto::codewire::v1::{DesiredState, Environment, EnvironmentState};
        let id = "5d1db799-4300-4ab3-b957-efb980760542";
        let list = SandboxListContext::new("a&b", "running").list_url("my-org");
        let target = deletion_feedback_path(&list, id);
        let url = Url::parse(&format!("https://codewire.invalid{target}")).unwrap();
        assert_eq!(url.path(), "/my-org/");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            [
                ("search".into(), "a&b".into()),
                ("state".into(), "running".into()),
                ("message".into(), "environment-destroying".into()),
                ("environment".into(), id.into()),
            ]
        );
        for invalid in ["", "../other", "5D1DB799-4300-4AB3-B957-EFB980760542"] {
            assert_eq!(
                deletion_feedback_path("/my-org/", invalid),
                "/my-org/?message=environment-destroying"
            );
        }
        // No green banner: the polite status says what became of it.
        assert_eq!(page_message("environment-destroying"), "");
        let outcome = |state: EnvironmentState, desired: DesiredState| {
            deletion_outcome(Environment {
                id: id.into(),
                name: "quiet-mesa".into(),
                state: state.into(),
                desired_state: desired.into(),
                ..Default::default()
            })
        };
        assert_eq!(
            outcome(EnvironmentState::Destroying, DesiredState::Destroyed),
            "Deleting quiet-mesa…"
        );
        assert_eq!(
            outcome(EnvironmentState::Destroyed, DesiredState::Destroyed),
            "quiet-mesa deleted."
        );
        assert_eq!(
            outcome(EnvironmentState::Error, DesiredState::Destroyed),
            "quiet-mesa could not be deleted."
        );
        assert_eq!(outcome(EnvironmentState::Error, DesiredState::Started), "");
        assert_eq!(
            outcome(EnvironmentState::Running, DesiredState::Started),
            ""
        );

        let organization = test_organization();
        let mut page = lifecycle_test_page(vec![lifecycle_test_row(
            id,
            "quiet-mesa",
            EnvironmentState::Destroying,
        )]);
        page.message = "Deleting quiet-mesa…".into();
        let render = |page: &EnvironmentsPageView| {
            OrganizationEnvironmentsContentTemplate {
                organization: &organization,
                page,
            }
            .render()
            .unwrap()
        };
        let html = render(&page);
        assert!(html.contains(
            "<p class=\"cw-toast\" role=\"status\" data-inventory-status>Deleting quiet-mesa…</p>"
        ));
        assert!(!html.contains("cw-alert--success"));
        assert!(html.contains(&format!("<tr data-environment-id=\"{id}\"")));
        // Background refreshes stay quiet; the status speaks for transitions.
        assert!(html.contains("<div id=\"environment-list\" aria-live=\"off\" hx-get="));
        page.message.clear();
        assert!(
            render(&page)
                .contains("<p class=\"cw-toast\" role=\"status\" data-inventory-status></p>")
        );
        // Kind found a second status after Create: the list page has exactly
        // one polite status, empty or carrying any action's outcome, and the
        // refresh-failure note speaks through it rather than as its own.
        for message in ["", "Sandbox creation started.", "Deleting quiet-mesa…"] {
            page.message = message.into();
            let html = render(&page);
            // The closed Create drawer is hidden, so its form statuses are
            // not on the page until it opens.
            let (before, drawer) = html.split_once("<div class=\"cw-drawer-layer\"").unwrap();
            let (drawer, after) = drawer.split_once("<div id=\"environment-list\"").unwrap();
            assert!(drawer.contains("data-open=\"false\" hidden>"));
            let page_statuses = before.matches("role=\"status\"").count()
                + after.matches("role=\"status\"").count();
            assert_eq!(page_statuses, 1, "{message:?}");
            assert!(html.contains(&format!(
                "<p class=\"cw-toast\" role=\"status\" data-inventory-status>{message}</p>"
            )));
            assert!(
                html.contains("<p class=\"cw-field-help\" data-environment-list-error hidden>")
            );
        }
    }

    #[test]
    fn detail_page_of_a_deleting_or_deleted_sandbox_offers_no_dead_controls() {
        use codewire_proto::codewire::v1::EnvironmentState;
        const ID: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let organization = test_organization();
        let detail =
            |state| render_terminal(&organization, lifecycle_test_row(ID, "quiet-mesa", state));
        let deleting = detail(EnvironmentState::Destroying);
        assert!(deleting.contains("data-sandbox-state data-tone=\"warning\">deleting…</span>"));
        assert!(deleting.contains(
            "data-sandbox-observation-status role=\"status\">This Sandbox is being deleted.</p>"
        ));
        assert!(
            deleting.contains("<div class=\"cw-workspace-actions\" data-sandbox-actions hidden>")
        );
        assert!(deleting.contains("data-terminal-running=\"false\" hidden>"));
        assert!(deleting.contains("data-sandbox-deleted hidden><a class=\"cw-link-button\""));
        let deleted = detail(EnvironmentState::Destroyed);
        assert!(deleted.contains("data-sandbox-state data-tone=\"neutral\">deleted</span>"));
        assert!(deleted.contains(
            "data-sandbox-observation-status role=\"status\">This Sandbox was deleted.</p>"
        ));
        assert!(deleted.contains(
            "<p class=\"cw-field-help\" data-sandbox-deleted><a class=\"cw-link-button\" href=\"/test/\">Back to Sandboxes</a></p>"
        ));
        assert!(
            deleted.contains("<div class=\"cw-workspace-actions\" data-sandbox-actions hidden>")
        );
        assert!(deleted.contains("data-terminal-running=\"false\" hidden>"));
        let running = detail(EnvironmentState::Running);
        assert!(running.contains("data-sandbox-observation-status role=\"status\" hidden></p>"));
        assert!(running.contains("<div class=\"cw-workspace-actions\" data-sandbox-actions>"));
        assert!(running.contains("data-sandbox-deleted hidden>"));
        assert!(running.contains("data-terminal-running=\"true\">"));
    }

    /// The workspace reads like a desktop terminal: the header names the
    /// Sandbox, its state and resources; the status bar reads the last event
    /// and automatic deletion in short words after their labels.
    #[test]
    fn workspace_header_and_status_bar_read_the_sandbox_in_short_words() {
        use codewire_proto::codewire::v1::EnvironmentState;
        const ID: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let organization = test_organization();
        let mut row = lifecycle_test_row(ID, "quiet-mesa", EnvironmentState::Running);
        row.resources = "1 vCPU · 2 GiB · 10 GiB".into();
        row.last_event = "6m ago".into();
        let html = render_terminal(&organization, row.clone());
        assert!(html.contains("<h1>quiet-mesa</h1><span class=\"cw-status cw-status--pill\" data-sandbox-state data-tone=\"success\">running</span><span class=\"cw-workspace-resources\" data-sandbox-resources>1 vCPU · 2 GiB · 10 GiB</span>"));
        assert!(html.contains("<dt>Last event</dt><dd data-sandbox-last-event>6m ago</dd>"));
        assert!(html.contains(&format!("href=\"vscode://vscode-remote/ssh-remote+cw-{ID}/workspace\" data-sandbox-action=\"connect\">Open in VS Code</a>")));
        for (state, label) in [
            ("unscheduled", "off"),
            ("protected", "off (protected)"),
            ("unavailable", "unavailable"),
        ] {
            row.deletion_state = state;
            let html = render_terminal(&organization, row.clone());
            assert!(
                html.contains(&format!(
                    "<dt>Auto-delete</dt><dd data-sandbox-lifetime>{label}</dd>"
                )),
                "{state}"
            );
        }
        row.deletion_state = "scheduled";
        row.shutdown_at = Some("2026-09-17T00:26:00.123456789Z".into());
        row.shutdown_at_label = "17 Sep 2026, 00:26 UTC".into();
        let html = render_terminal(&organization, row);
        assert!(html.contains("<dt>Auto-delete</dt><dd data-sandbox-lifetime><time datetime=\"2026-09-17T00:26:00.123456789Z\">17 Sep 2026, 00:26 UTC</time></dd>"));
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
    fn lifecycle_failures_name_quota_rate_limits_and_unconfirmed_outcomes() {
        let quota = codewire_proto::google::rpc::ErrorInfo {
            reason: "quota_exceeded".to_owned(),
            domain: "codewire.dev".to_owned(),
            ..Default::default()
        };
        let quota = ConnectError::resource_exhausted("untrusted upstream detail").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &quota),
        );
        assert_eq!(mutation_error(&quota), "quota");
        assert_eq!(
            mutation_error(&ConnectError::resource_exhausted("slow down")),
            "rate-limited"
        );
        assert_eq!(
            mutation_error(&ConnectError::internal("boom")),
            "unconfirmed"
        );
        assert_eq!(
            mutation_error(&ConnectError::deadline_exceeded("late")),
            "unconfirmed"
        );
        assert_eq!(
            mutation_error(&ConnectError::unavailable("down")),
            "unavailable"
        );
        assert_eq!(
            mutation_error(&ConnectError::failed_precondition("stopped")),
            "invalid"
        );
        for code in ["quota", "rate-limited", "unconfirmed"] {
            assert!(!page_error(code).is_empty(), "{code}");
            assert!(!page_error(code).contains("untrusted"));
        }
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
            preview_base_domain: String::new(),
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
                    synthetic: false,
                }],
                profiles: vec![crate::view::EnvironmentCredentialProfileOption {
                    id: id.into(),
                    name: "work".into(),
                    revision: 7,
                    identity_count: 2,
                    bound_revision: false,
                    synthetic: false,
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
    fn create_rejects_stale_sources_before_dispatch_and_accepts_explicit_recovery() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let options = || EnvironmentCreateOptions {
            presets: vec![],
            preview_base_domain: String::new(),
            agents: vec![],
            confidential_available: false,
            confidential_price: String::new(),
            sources: crate::view::EnvironmentSourceFieldsView {
                application_selection_enabled: true,
                credential_selection_enabled: true,
                projects: vec![crate::view::EnvironmentSecretProjectOption {
                    id: "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76".into(),
                    name: "development".into(),
                    selected: false,
                    synthetic: false,
                }],
                profiles: vec![crate::view::EnvironmentCredentialProfileOption {
                    id: id.into(),
                    name: "work".into(),
                    revision: 8,
                    identity_count: 2,
                    bound_revision: false,
                    synthetic: false,
                    selected: false,
                }],
                ..Default::default()
            },
        };
        for selection in [
            format!("secret_project={id}"),
            format!("credential_profile={id}%407"),
            "credential_profile=315dd4c2-6bf2-4c3b-9d8f-68fc97654a76%407".into(),
        ] {
            let submission = EnvironmentSubmission::parse(
                format!("image=example.test%2Fworkspace&{selection}").as_bytes(),
            )
            .unwrap();
            let mut form = submission.form_view("synthetic-csrf".into());
            hydrate_options(&mut form, options());
            assert!(form.sources.complete());
            assert!(form.has_errors());
            assert!(
                submission
                    .validate_and_draft("org-test", &mut form)
                    .is_none()
            );
        }
        let alternate_project_id = "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76";
        for selection in [
            "secret_project=&credential_profile=".into(),
            format!("credential_profile={id}%408"),
            format!("secret_project={alternate_project_id}"),
        ] {
            let submission = EnvironmentSubmission::parse(
                format!("image=example.test%2Fworkspace&{selection}").as_bytes(),
            )
            .unwrap();
            let mut form = submission.form_view("synthetic-csrf".into());
            hydrate_options(&mut form, options());
            assert!(!form.has_errors());
            let draft = submission
                .validate_and_draft("org-test", &mut form)
                .unwrap();
            assert_eq!(
                draft.expected_profile_revision,
                if selection.ends_with("408") {
                    Some(8)
                } else {
                    None
                }
            );
        }
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
            environments_loading: false,
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
                    profile_name: String::new(),
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
        let fields = &mut page.source_editor.as_mut().unwrap().fields;
        fields.project_error.clear();
        fields.select_bound(&codewire_proto::codewire::v1::EnvironmentSourceSelection {
            profile_revision: Some(7),
            ..Default::default()
        });
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
            preview_base_domain: String::new(),
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
                    ..Default::default()
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
        assert_eq!(submission.ttl, "1h");
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
        assert!(!submission.application_previews_explicit);

        let mut explicit = EnvironmentSubmission::parse(
            b"preset_id=preset-id&cpu=750&application_previews_explicit=true",
        )
        .unwrap();
        explicit.apply_selected_preset_defaults(&options);
        assert!(explicit.app_ports.is_empty());
        assert_eq!(explicit.memory, "1024");
        let mut explicit_form = explicit.form_view("token".into());
        let explicit_draft = explicit
            .validate_and_draft("org-test", &mut explicit_form)
            .unwrap();
        assert!(explicit_draft.omit_application_previews);
        assert!(
            explicit_draft
                .project_spec
                .as_option()
                .unwrap()
                .application_ports
                .is_empty()
        );

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
    fn preset_lifetimes_use_the_largest_exact_unit_and_parse_back() {
        for (seconds, expected) in [
            (60, "1m"),
            (90, "90s"),
            (3_600, "1h"),
            (5_400, "90m"),
            (86_400, "1d"),
            (90_000, "25h"),
            (604_800, "7d"),
            (31_536_000, "365d"),
        ] {
            assert_eq!(lifetime_field_value(seconds), expected);
            let mut error = String::new();
            assert_eq!(parse_ttl(expected, &mut error), Some(seconds));
            assert!(error.is_empty());
        }
    }

    #[test]
    fn delete_after_shows_the_preset_default_and_never_infinity() {
        let organization = test_organization();
        let render = |form: &EnvironmentCreateFormView| {
            EnvironmentCreateFormTemplate {
                organization: &organization,
                form,
            }
            .render()
            .expect("environment create form")
        };
        let field = |value: &str, placeholder: &str| {
            format!("name=\"ttl\" value=\"{value}\" placeholder=\"{placeholder}\"")
        };

        let mut form = default_create_form("csrf".into(), true);
        let html = render(&form);
        assert!(html.contains(&field("", "Not scheduled")), "{html}");
        assert!(!html.to_lowercase().contains("infinity"));
        assert!(html.contains("without one, the Sandbox is not scheduled for automatic deletion"));

        // A preset without a default lifetime leaves the Sandbox unscheduled.
        form.preset_id = "preset-id".into();
        form.presets = vec![test_preset("preset-id", false)];
        form.follow_preset_ttl();
        assert!(render(&form).contains(&field("", "Not scheduled")));

        let mut preset = test_preset("preset-id", false);
        preset.default_ttl_seconds = Some(604_800);
        form.presets = vec![preset];
        for legacy in ["", "0", "infinity", "Infinity", "∞"] {
            form.ttl = legacy.into();
            form.follow_preset_ttl();
            assert!(render(&form).contains(&field("7d", "7d")), "{legacy}");
        }
        // The user's own value is kept; clearing it shows what empty resolves to.
        form.ttl = "8h".into();
        form.follow_preset_ttl();
        assert!(render(&form).contains(&field("8h", "7d")));
        form.ttl = String::new();
        assert!(render(&form).contains(&field("", "7d")));

        // Legacy input without a preset default comes back empty, not "infinity".
        let submission = EnvironmentSubmission::parse(b"ttl=infinity").unwrap();
        assert_eq!(submission.form_view("csrf".into()).ttl, "");
        let submission = EnvironmentSubmission::parse(b"ttl=%E2%88%9E").unwrap();
        assert_eq!(submission.form_view("csrf".into()).ttl, "");
        let submission = EnvironmentSubmission::parse(b"ttl=8h").unwrap();
        assert_eq!(submission.form_view("csrf".into()).ttl, "8h");
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
            can_admin: true,
            environments_url: "/organization/".to_owned(),
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
            can_admin: true,
            environments_url: "/organization/".to_owned(),
            presets_url: String::new(),
            secrets_url: String::new(),
            api_keys_url: String::new(),
            members_url: String::new(),
            billing_url: String::new(),
        };
        let page = EnvironmentsPageView {
            environments: Vec::new(),
            environments_loading: false,
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
            can_admin: true,
            environments_url: String::new(),
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
            can_admin: true,
            environments_url: "/organization/".to_owned(),
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

        assert!(html.contains("Repository URL"));
        assert!(html.contains("Branch"));
        assert!(html.contains("Mount path"));
        assert!(html.contains("data-manual-repositories"));
        assert!(html.contains("Add custom Git URL"));
        let index = form.repositories[0].index;
        for (name_prefix, id_prefix) in [
            ("repo_url", "repo-url"),
            ("repo_branch", "repo-branch"),
            ("repo_mount", "repo-mount"),
        ] {
            let name = format!("{name_prefix}_{index}");
            let id = format!("{id_prefix}-{index}");
            assert!(html.contains(&format!("for=\"{id}\"")));
            let input = html
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
        assert!(html.contains(&format!(
            "<a href=\"/settings/credentials/?{}\" data-github-setup-link data-create-draft-setup>Connect GitHub</a>",
            form.creation_draft_parameter()
        )));
        assert!(html.contains("data-github-browser data-github-state=\"not-configured\""));
        assert!(
            html.contains("data-repositories-url=\"/organization/_fragments/github-repositories\"")
        );
        assert!(html.contains("<h4 id=\"github-browser-title\""));
        assert!(!html.contains("data-github-repository-picker"));
        // The browser stops offering repositories at the count the form
        // parser accepts, and says why.
        assert!(html.contains(&format!(
            "data-repository-rows data-repository-limit=\"{MAX_REPOSITORIES}\""
        )));
        assert!(html.contains(&format!(
            "<p class=\"cw-field-help\" hidden data-github-repository-limit>This Sandbox has the most repositories it can take ({MAX_REPOSITORIES}). Remove one to add another.</p>"
        )));
        // Loaded choices render the list idle: no spinner, skeleton or busy list.
        assert!(html.contains("data-github-results></section><ul class=\"cw-github-repository-list\" aria-hidden=\"true\" data-github-placeholder hidden>"));
        assert_eq!(html.matches("<li class=\"cw-row-skeleton\">").count(), 4);
        assert!(html.contains("<span class=\"cw-spinner\" aria-hidden=\"true\" data-github-spinner hidden></span><p class=\"cw-field-help\" role=\"status\" data-github-status>"));
        assert!(!form.sources.credential_selection_enabled);
        // Browsing uses the account's one GitHub connection; profiles never
        // select or gate it.
        assert!(!html.contains("data-github-profile"));
        assert!(!html.contains("data-show-github-repositories"));
        assert!(!html.contains("GitHub connected"));

        // While choices load, the account is unknown and the list is busy.
        let mut loading = form;
        loading.options_loading = true;
        let html = EnvironmentCreateFormTemplate {
            organization: &organization,
            form: &loading,
        }
        .render()
        .expect("loading environment form");
        assert!(html.contains("data-github-results aria-busy=\"true\"></section><ul class=\"cw-github-repository-list\" aria-hidden=\"true\" data-github-placeholder>"));
        assert!(html.contains("<span class=\"cw-spinner\" aria-hidden=\"true\" data-github-spinner></span><p class=\"cw-field-help\" role=\"status\" data-github-status>Loading GitHub account…</p>"));
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

#[cfg(test)]
#[path = "sandbox_credential_attention_tests.rs"]
mod sandbox_credential_attention_tests;
