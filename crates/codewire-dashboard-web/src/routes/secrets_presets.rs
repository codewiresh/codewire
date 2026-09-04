use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use codewire_proto::codewire::v1::UpdatePresetRequest;
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_KEY_BYTES, validate_workload_secret_metadata_key,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    response::{HTMX_REQUEST, error_page, login_redirect, render_page, render_template},
    routes::organization_governance::{
        action_context, connect_page_error, get_context, mutation_redirect, valid_identifier,
    },
    secrets_presets_connect::{self, SecretBucket},
    security::{csrf_cookie, new_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::{
        OrganizationPresetsContentTemplate, OrganizationPresetsTemplate,
        OrganizationSecretBucketContentTemplate, OrganizationSecretBucketTemplate,
        OrganizationSecretsContentTemplate, OrganizationSecretsTemplate,
    },
    view::{
        PresetDeleteSubmission, PresetFormView, PresetUpdateSubmission, PresetsPageView,
        SecretBucketPageView, SecretFormView, SecretKeySubmission, SecretProjectCreateSubmission,
        SecretProjectDeleteSubmission, SecretProjectFormView, SecretProjectsPageView,
        SecretRenameSubmission, SecretSetSubmission, bad_request_fields,
    },
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct FeedbackQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

pub(super) async fn secrets_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = secrets_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let projects =
        match secrets_presets_connect::secret_projects(&state, cookie, &organization.id).await {
            Ok(projects) => projects,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    let token = new_csrf_token();
    let page = SecretProjectsPageView {
        projects,
        form: SecretProjectFormView::default(),
        csrf_token: token.clone(),
        message: secrets_message(&query.message).to_owned(),
        error: secrets_error(&query.error).to_owned(),
    };
    with_csrf_cookie(
        render_page(OrganizationSecretsTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "secrets",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn secret_bucket_page(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = secret_bucket_path(&slug, &bucket);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let page = match bucket_page(
        &state,
        cookie,
        &organization,
        &bucket,
        SecretFormView::default(),
        secrets_message(&query.message),
        secrets_error(&query.error),
    )
    .await
    {
        Ok(page) => page,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let token = page.csrf_token.clone();
    with_csrf_cookie(
        render_page(OrganizationSecretBucketTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "secrets",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn create_secret_project(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<SecretProjectCreateSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        secrets_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin {
        return mutation_redirect(&state, secrets_path(&slug), "", "not-authorized", &headers);
    }
    let mut form = SecretProjectFormView {
        name: submission.name.trim().to_owned(),
        expanded: true,
        ..Default::default()
    };
    if form.name.is_empty() || form.name.len() > 128 {
        form.name_error = "Name is required and must be at most 128 characters".to_owned();
    }
    if !form.name_error.is_empty() {
        return render_project_form_error(
            &state,
            &headers,
            dashboard,
            organization,
            cookie,
            form,
            &submission.csrf,
        )
        .await;
    }
    match secrets_presets_connect::create_secret_project(
        &state,
        cookie.clone(),
        organization.id.clone(),
        form.name.clone(),
    )
    .await
    {
        Ok(()) => mutation_redirect(&state, secrets_path(&slug), "project-created", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&secrets_path(&slug), &headers)
        }
        Err(error) => {
            apply_project_error(&mut form, &error);
            render_project_form_error(
                &state,
                &headers,
                dashboard,
                organization,
                cookie,
                form,
                &submission.csrf,
            )
            .await
        }
    }
}

pub(super) async fn delete_secret_project(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<SecretProjectDeleteSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        secrets_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.project_id) {
        return mutation_redirect(&state, secrets_path(&slug), "", "not-authorized", &headers);
    }
    let result = secrets_presets_connect::delete_secret_project(
        &state,
        cookie,
        organization.id,
        submission.project_id,
    )
    .await;
    secret_mutation_result(
        &state,
        &headers,
        secrets_path(&slug),
        result,
        "project-deleted",
    )
}

pub(super) async fn set_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<SecretSetSubmission>,
) -> Response {
    let continuation = secret_bucket_path(&slug, &bucket);
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !bucket_can_manage(&organization, &bucket) {
        return mutation_redirect(&state, continuation, "", "not-authorized", &headers);
    }
    let mut form = SecretFormView {
        key: submission.key.trim().to_owned(),
        expanded: true,
        ..Default::default()
    };
    validate_secret_form(&mut form, &submission.value);
    if !form.key_error.is_empty() || !form.form_error.is_empty() {
        return render_secret_form_error(
            &state,
            &headers,
            (dashboard, organization, cookie),
            &bucket,
            form,
            &submission.csrf,
        )
        .await;
    }

    let result = secrets_presets_connect::set_secret(
        &state,
        cookie.clone(),
        organization.id.clone(),
        bucket_scope(&bucket),
        form.key.clone(),
        submission.value,
    )
    .await;
    match result {
        Ok(()) => mutation_redirect(&state, continuation, "secret-saved", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, &headers)
        }
        Err(error) => {
            apply_secret_error(&mut form, &error);
            render_secret_form_error(
                &state,
                &headers,
                (dashboard, organization, cookie),
                &bucket,
                form,
                &submission.csrf,
            )
            .await
        }
    }
}

pub(super) async fn delete_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<SecretKeySubmission>,
) -> Response {
    let continuation = secret_bucket_path(&slug, &bucket);
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !bucket_can_manage(&organization, &bucket) || !valid_secret_key(&submission.key) {
        return mutation_redirect(&state, continuation, "", "not-authorized", &headers);
    }
    let result = secrets_presets_connect::delete_secret(
        &state,
        cookie,
        organization.id,
        bucket_scope(&bucket),
        submission.key,
    )
    .await;
    secret_mutation_result(&state, &headers, continuation, result, "secret-deleted")
}

pub(super) async fn rename_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<SecretRenameSubmission>,
) -> Response {
    let continuation = secret_bucket_path(&slug, &bucket);
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !bucket_can_manage(&organization, &bucket)
        || !valid_secret_key(&submission.key)
        || !valid_secret_key(&submission.new_key)
        || submission.key == submission.new_key
    {
        return mutation_redirect(&state, continuation, "", "invalid", &headers);
    }
    let result = secrets_presets_connect::rename_secret(
        &state,
        cookie,
        organization.id,
        bucket_scope(&bucket),
        submission.key,
        submission.new_key,
    )
    .await;
    secret_mutation_result(&state, &headers, continuation, result, "secret-renamed")
}

pub(super) async fn presets_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<FeedbackQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = presets_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let presets = match secrets_presets_connect::presets(&state, cookie, &organization.id).await {
        Ok(presets) => presets,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let token = new_csrf_token();
    let page = PresetsPageView {
        presets,
        csrf_token: token.clone(),
        message: presets_message(&query.message).to_owned(),
        error: presets_error(&query.error).to_owned(),
    };
    with_csrf_cookie(
        render_page(OrganizationPresetsTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "presets",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn update_preset(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PresetUpdateSubmission>,
) -> Response {
    let continuation = presets_path(&slug);
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.preset_id) {
        return mutation_redirect(&state, continuation, "", "not-authorized", &headers);
    }
    let mut form = preset_form(&submission);
    let cpu = parse_positive_i32(&form.cpu, "CPU", &mut form.cpu_error);
    let memory = parse_positive_i32(&form.memory, "Memory", &mut form.memory_error);
    let disk = parse_positive_i32(&form.disk, "Disk", &mut form.disk_error);
    let ttl = if form.ttl.trim().is_empty() {
        None
    } else {
        parse_positive_i32(&form.ttl, "TTL", &mut form.ttl_error)
    };
    if form.name.trim().is_empty() || form.name.len() > 128 {
        form.name_error = "Name is required and must be at most 128 characters".to_owned();
    }
    if preset_form_has_errors(&form) {
        return render_preset_form_error(
            &state,
            &headers,
            (dashboard, organization, cookie),
            &submission.preset_id,
            form,
            &submission.csrf,
        )
        .await;
    }
    let request = UpdatePresetRequest {
        org_id: organization.id.clone(),
        preset_id: submission.preset_id.clone(),
        name: Some(form.name.trim().to_owned()),
        description: Some(form.description.clone()),
        slug: Some(form.slug.trim().to_owned()),
        default_cpu_millicores: cpu,
        default_memory_mb: memory,
        default_disk_gb: disk,
        default_ttl_seconds: ttl,
        image: Some(form.image.trim().to_owned()),
        install_command: Some(form.install_command.clone()),
        startup_script: Some(form.startup_script.clone()),
        ..Default::default()
    };
    match secrets_presets_connect::update_preset(&state, cookie.clone(), request).await {
        Ok(()) => mutation_redirect(&state, continuation, "preset-updated", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, &headers)
        }
        Err(error) => {
            apply_preset_error(&mut form, &error);
            render_preset_form_error(
                &state,
                &headers,
                (dashboard, organization, cookie),
                &submission.preset_id,
                form,
                &submission.csrf,
            )
            .await
        }
    }
}

pub(super) async fn delete_preset(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<PresetDeleteSubmission>,
) -> Response {
    let continuation = presets_path(&slug);
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.preset_id) {
        return mutation_redirect(&state, continuation, "", "not-authorized", &headers);
    }
    let result = secrets_presets_connect::delete_preset(
        &state,
        cookie,
        organization.id,
        submission.preset_id,
    )
    .await;
    match result {
        Ok(()) => mutation_redirect(&state, continuation, "preset-deleted", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, &headers)
        }
        Err(error) => mutation_redirect(
            &state,
            continuation,
            "",
            if error.code == ErrorCode::FailedPrecondition || error.code == ErrorCode::Aborted {
                "preset-in-use"
            } else {
                mutation_error_code(&error)
            },
            &headers,
        ),
    }
}

async fn bucket_page(
    state: &AppState,
    cookie: HeaderValue,
    organization: &crate::view::OrganizationContext,
    bucket: &str,
    form: SecretFormView,
    message: &str,
    error: &str,
) -> Result<SecretBucketPageView, ConnectError> {
    let (title, description, can_manage) = match bucket {
        "organization" => (
            "Organization Secrets".to_owned(),
            "Shared credentials available to this organization's Sandboxes.",
            organization.can_admin,
        ),
        "user" => (
            "User Secrets".to_owned(),
            "Your personal credentials, available to Sandboxes when selected.",
            true,
        ),
        project_id => {
            let projects =
                secrets_presets_connect::secret_projects(state, cookie.clone(), &organization.id)
                    .await?;
            let Some(project) = projects
                .into_iter()
                .find(|project| project.id == project_id)
            else {
                return Err(ConnectError::not_found("secret project not found"));
            };
            (
                project.name,
                "Credentials grouped for one reusable Sandbox configuration.",
                organization.can_admin,
            )
        }
    };
    let secrets =
        secrets_presets_connect::secrets(state, cookie, &organization.id, bucket_scope(bucket))
            .await?;
    Ok(SecretBucketPageView {
        title,
        description,
        bucket: bucket.to_owned(),
        secrets,
        can_manage,
        form,
        csrf_token: new_csrf_token(),
        message: message.to_owned(),
        error: error.to_owned(),
    })
}

async fn render_project_form_error(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: crate::view::DashboardView,
    organization: crate::view::OrganizationContext,
    cookie: HeaderValue,
    form: SecretProjectFormView,
    csrf: &str,
) -> Response {
    let projects =
        match secrets_presets_connect::secret_projects(state, cookie, &organization.id).await {
            Ok(projects) => projects,
            Err(error) => return connect_page_error(error, &organization.secrets_url, headers),
        };
    let page = SecretProjectsPageView {
        projects,
        form,
        csrf_token: csrf.to_owned(),
        message: String::new(),
        error: String::new(),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationSecretsContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationSecretsTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
                active_tab: "secrets",
            },
        )
    }
}

async fn render_secret_form_error(
    state: &AppState,
    headers: &HeaderMap,
    context: (
        crate::view::DashboardView,
        crate::view::OrganizationContext,
        HeaderValue,
    ),
    bucket: &str,
    form: SecretFormView,
    csrf: &str,
) -> Response {
    let (dashboard, organization, cookie) = context;
    let mut page = match bucket_page(state, cookie, &organization, bucket, form, "", "").await {
        Ok(page) => page,
        Err(error) => {
            return connect_page_error(
                error,
                &secret_bucket_path(&organization.slug, bucket),
                headers,
            );
        }
    };
    page.csrf_token = csrf.to_owned();
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationSecretBucketContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationSecretBucketTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
                active_tab: "secrets",
            },
        )
    }
}

async fn render_preset_form_error(
    state: &AppState,
    headers: &HeaderMap,
    context: (
        crate::view::DashboardView,
        crate::view::OrganizationContext,
        HeaderValue,
    ),
    preset_id: &str,
    form: PresetFormView,
    csrf: &str,
) -> Response {
    let (dashboard, organization, cookie) = context;
    let mut presets = match secrets_presets_connect::presets(state, cookie, &organization.id).await
    {
        Ok(presets) => presets,
        Err(error) => return connect_page_error(error, &organization.presets_url, headers),
    };
    let Some(preset) = presets.iter_mut().find(|preset| preset.id == preset_id) else {
        return error_page(crate::error::WebError::NotFound);
    };
    preset.form = form;
    preset.form.expanded = true;
    let page = PresetsPageView {
        presets,
        csrf_token: csrf.to_owned(),
        message: String::new(),
        error: String::new(),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationPresetsContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationPresetsTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
                active_tab: "presets",
            },
        )
    }
}

fn validate_secret_form(form: &mut SecretFormView, value: &str) {
    if !valid_secret_key(&form.key) {
        form.key_error = format!(
            "Use 1–{MAX_WORKLOAD_SECRET_KEY_BYTES} ASCII letters, numbers, or underscores for the key"
        );
    }
    if value.is_empty() {
        form.form_error = "Enter a secret value. Values are never shown again.".to_owned();
    }
}

fn valid_secret_key(value: &str) -> bool {
    validate_workload_secret_metadata_key(value).is_ok()
}

fn bucket_scope(bucket: &str) -> SecretBucket<'_> {
    match bucket {
        "organization" => SecretBucket::Organization,
        "user" => SecretBucket::User,
        project_id => SecretBucket::Project(project_id),
    }
}

fn bucket_can_manage(organization: &crate::view::OrganizationContext, bucket: &str) -> bool {
    valid_secret_bucket(bucket) && (bucket == "user" || organization.can_admin)
}

fn valid_secret_bucket(bucket: &str) -> bool {
    matches!(bucket, "organization" | "user") || valid_identifier(bucket)
}

fn apply_project_error(form: &mut SecretProjectFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        if field.trim_start_matches('/') == "name" {
            form.name_error = description;
        }
    }
    if form.name_error.is_empty() {
        form.form_error = if matches!(error.code, ErrorCode::AlreadyExists | ErrorCode::Aborted) {
            "A secret project with this name already exists."
        } else {
            "The secret project could not be created."
        }
        .to_owned();
    }
}

fn apply_secret_error(form: &mut SecretFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        if field.trim_start_matches('/') == "key" {
            form.key_error = description;
        }
    }
    if form.key_error.is_empty() {
        form.form_error = if error.code == ErrorCode::PermissionDenied {
            "You do not have permission to change these secrets."
        } else {
            "The secret update could not be confirmed. Reload before retrying."
        }
        .to_owned();
    }
}

fn preset_form(submission: &PresetUpdateSubmission) -> PresetFormView {
    PresetFormView {
        name: submission.name.clone(),
        slug: submission.slug.clone(),
        description: submission.description.clone(),
        image: submission.image.clone(),
        cpu: submission.cpu.clone(),
        memory: submission.memory.clone(),
        disk: submission.disk.clone(),
        ttl: submission.ttl.clone(),
        install_command: submission.install_command.clone(),
        startup_script: submission.startup_script.clone(),
        expanded: true,
        ..Default::default()
    }
}

fn parse_positive_i32(value: &str, label: &str, error: &mut String) -> Option<i32> {
    match value.trim().parse::<i32>() {
        Ok(value) if value > 0 => Some(value),
        _ => {
            *error = format!("{label} must be a positive whole number");
            None
        }
    }
}

fn preset_form_has_errors(form: &PresetFormView) -> bool {
    !form.name_error.is_empty()
        || !form.cpu_error.is_empty()
        || !form.memory_error.is_empty()
        || !form.disk_error.is_empty()
        || !form.ttl_error.is_empty()
        || !form.form_error.is_empty()
}

fn apply_preset_error(form: &mut PresetFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "name" => form.name_error = description,
            "default_cpu_millicores" => form.cpu_error = description,
            "default_memory_mb" => form.memory_error = description,
            "default_disk_gb" => form.disk_error = description,
            "default_ttl_seconds" => form.ttl_error = description,
            _ => {}
        }
    }
    if !preset_form_has_errors(form) {
        form.form_error =
            "The preset could not be updated. Please reload and try again.".to_owned();
    }
}

fn secret_mutation_result(
    state: &AppState,
    headers: &HeaderMap,
    path: String,
    result: Result<(), ConnectError>,
    message: &str,
) -> Response {
    match result {
        Ok(()) => mutation_redirect(state, path, message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, headers),
        Err(error) => mutation_redirect(state, path, "", mutation_error_code(&error), headers),
    }
}

fn mutation_error_code(error: &ConnectError) -> &'static str {
    match error.code {
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::InvalidArgument => "invalid",
        ErrorCode::NotFound => "not-found",
        ErrorCode::AlreadyExists | ErrorCode::Aborted => "conflict",
        _ => "unavailable",
    }
}

fn secrets_path(slug: &str) -> String {
    format!("/{slug}/secrets/")
}

fn secret_bucket_path(slug: &str, bucket: &str) -> String {
    format!("/{slug}/secrets/{bucket}/")
}

fn presets_path(slug: &str) -> String {
    format!("/{slug}/presets/")
}

fn secrets_message(value: &str) -> &'static str {
    match value {
        "project-created" => "Secret project created.",
        "project-deleted" => "Secret project and its stored values deleted.",
        "secret-saved" => "Secret saved. Its value will not be shown.",
        "secret-renamed" => "Secret key renamed.",
        "secret-deleted" => "Secret deleted.",
        _ => "",
    }
}

fn secrets_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change these secrets.",
        "invalid" => "The requested secret change was invalid.",
        "not-found" => "The secret or project no longer exists.",
        "conflict" => "A secret with that key already exists.",
        "unavailable" => "The secret operation could not be confirmed. Reload before retrying.",
        _ => "",
    }
}

fn presets_message(value: &str) -> &'static str {
    match value {
        "preset-updated" => "Preset updated.",
        "preset-deleted" => "Preset deleted.",
        _ => "",
    }
}

fn presets_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change presets.",
        "invalid" => "The requested preset change was invalid.",
        "not-found" => "The preset no longer exists.",
        "preset-in-use" => "This preset is still used by an active Sandbox.",
        "conflict" => "A preset with that slug already exists.",
        "unavailable" => "The preset service is temporarily unavailable.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template as _;
    use codewire_proto::google::rpc::BadRequest;

    #[test]
    fn secret_keys_use_the_shared_storage_boundary() {
        let maximum = format!("1{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES - 1));
        let too_long = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES));

        assert_eq!(maximum.len(), 255);
        assert_eq!(too_long.len(), 256);
        assert!(valid_secret_key(&maximum));
        assert!(!valid_secret_key(&too_long));

        let mut form = SecretFormView {
            key: too_long,
            ..Default::default()
        };
        validate_secret_form(&mut form, "synthetic");
        assert_eq!(
            form.key_error,
            "Use 1–255 ASCII letters, numbers, or underscores for the key"
        );
    }

    #[test]
    fn secret_validation_never_retains_the_value() {
        let marker = "must-never-enter-the-view";
        let mut form = SecretFormView {
            key: "bad-key".into(),
            ..Default::default()
        };
        validate_secret_form(&mut form, marker);
        let diagnostic = format!("{form:?}");
        assert!(!diagnostic.contains(marker));
        assert!(!form.key_error.is_empty());
    }

    #[test]
    fn preset_bad_request_details_attach_to_exact_fields() {
        let detail = BadRequest {
            field_violations: vec![codewire_proto::google::rpc::bad_request::FieldViolation {
                field: "/default_memory_mb".into(),
                description: "Choose more memory".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = ConnectError::invalid_argument("validation failed").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.BadRequest", &detail),
        );
        let mut form = PresetFormView::default();
        apply_preset_error(&mut form, &error);
        assert_eq!(form.memory_error, "Choose more memory");
        assert!(form.form_error.is_empty());
    }

    #[test]
    fn feedback_queries_are_allowlisted() {
        assert_eq!(
            secrets_message("secret-saved"),
            "Secret saved. Its value will not be shown."
        );
        assert_eq!(secrets_message("<script>"), "");
        assert_eq!(presets_error("raw-upstream-detail"), "");
    }

    #[test]
    fn secret_bucket_identifiers_are_bounded_before_mutation() {
        assert!(valid_secret_bucket("organization"));
        assert!(valid_secret_bucket("project-123"));
        assert!(!valid_secret_bucket(""));
        assert!(!valid_secret_bucket(&"x".repeat(257)));
        assert!(!valid_secret_bucket("project\nother"));
    }

    #[test]
    fn secret_and_preset_templates_escape_server_metadata() {
        let organization = crate::view::OrganizationContext {
            id: "org-safe".into(),
            name: "Safe organization".into(),
            slug: "safe".into(),
            role: "Owner",
            can_admin: true,
            environments_url: "/environments".into(),
            snapshots_url: "/snapshots".into(),
            presets_url: "/presets".into(),
            secrets_url: "/secrets".into(),
            api_keys_url: "/api-keys".into(),
            members_url: "/members".into(),
            billing_url: "/billing".into(),
        };
        let secret_page = SecretBucketPageView {
            title: "Organization Secrets".into(),
            description: "Write-only credentials.",
            bucket: "organization".into(),
            secrets: vec![crate::view::SecretRow {
                key: "<script>secret-key</script>".into(),
                updated: "just now".into(),
            }],
            can_manage: true,
            form: SecretFormView::default(),
            csrf_token: "csrf-token".into(),
            message: String::new(),
            error: String::new(),
        };
        let secret_body = OrganizationSecretBucketContentTemplate {
            organization: &organization,
            page: &secret_page,
        }
        .render()
        .expect("render secret bucket");
        assert!(!secret_body.contains("<script>secret-key</script>"));
        assert_eq!(secret_body.matches("maxlength=\"255\"").count(), 2);
        assert!(!secret_body.contains("maxlength=\"256\""));

        let preset_page = PresetsPageView {
            presets: vec![crate::view::PresetRow {
                id: "preset-safe".into(),
                name: "<script>preset-name</script>".into(),
                slug: "safe".into(),
                description: "<b>unsafe-description</b>".into(),
                image: "rust:latest<unsafe>".into(),
                cpu: "1 vCPU".into(),
                memory: "1 GiB".into(),
                disk: "5 GB".into(),
                ttl: "1h TTL".into(),
                official: false,
                organization_owned: true,
                form: PresetFormView {
                    name: "<script>preset-name</script>".into(),
                    description: "<unsafe>".into(),
                    ..Default::default()
                },
            }],
            csrf_token: "csrf-token".into(),
            message: String::new(),
            error: String::new(),
        };
        let preset_body = OrganizationPresetsContentTemplate {
            organization: &organization,
            page: &preset_page,
        }
        .render()
        .expect("render presets");
        assert!(!preset_body.contains("<script>preset-name</script>"));
        assert!(!preset_body.contains("<b>unsafe-description</b>"));
        assert!(!preset_body.contains("rust:latest<unsafe>"));
    }
}
