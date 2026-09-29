use axum::{
    Form,
    extract::{Path, Query, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use codewire_project::ResourceSpec;
use codewire_proto::codewire::v1::UpdatePresetRequest;
use codewire_workload_secrets::{MAX_WORKLOAD_SECRET_KEY_BYTES, validate_workload_secret_key};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    environment_drafts::DraftReturn,
    response::{HTMX_REQUEST, error_page, login_redirect, render_page, render_template},
    routes::organization_governance::{
        action_context, connect_page_error, get_context, mutation_redirect, valid_identifier,
    },
    secrets_presets_connect::{self, SecretBucket},
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secrets_path(&slug), &draft);
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
    let token = page_csrf_token(&headers);
    let page = SecretProjectsPageView {
        creation_draft_query: draft.query(),
        creation_return_url: secret_creation_return(&organization.slug, &draft),
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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secret_bucket_path(&slug, &bucket), &draft);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut page = match bucket_page(
        &state,
        cookie,
        &organization,
        &bucket,
        SecretFormView::default(),
        (secrets_message(&query.message), secrets_error(&query.error)),
        &draft,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    page.csrf_token = page_csrf_token(&headers);
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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Form(submission): Form<SecretProjectCreateSubmission>,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secrets_path(&slug), &draft);
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
    if !organization.can_admin {
        return secret_mutation_redirect(
            &state,
            secrets_path(&organization.slug),
            &draft,
            "",
            "not-authorized",
            &headers,
        );
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
            (dashboard, organization, cookie),
            form,
            &submission.csrf,
            &draft,
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
        Ok(()) => secret_mutation_redirect(
            &state,
            secrets_path(&organization.slug),
            &draft,
            "project-created",
            "",
            &headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&continuation, &headers)
        }
        Err(error) => {
            apply_project_error(&mut form, &error);
            render_project_form_error(
                &state,
                &headers,
                (dashboard, organization, cookie),
                form,
                &submission.csrf,
                &draft,
            )
            .await
        }
    }
}

pub(super) async fn delete_secret_project(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Form(submission): Form<SecretProjectDeleteSubmission>,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        secret_navigation_path(secrets_path(&slug), &draft),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.project_id) {
        return secret_mutation_redirect(
            &state,
            secrets_path(&organization.slug),
            &draft,
            "",
            "not-authorized",
            &headers,
        );
    }
    let path = secrets_path(&organization.slug);
    let result = secrets_presets_connect::delete_secret_project(
        &state,
        cookie,
        organization.id,
        submission.project_id,
    )
    .await;
    secret_mutation_result(&state, &headers, path, &draft, result, "project-deleted")
}

pub(super) async fn set_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Form(submission): Form<SecretSetSubmission>,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secret_bucket_path(&slug, &bucket), &draft);
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
        return secret_mutation_redirect(
            &state,
            secret_bucket_path(&organization.slug, &bucket),
            &draft,
            "",
            "not-authorized",
            &headers,
        );
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
            &draft,
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
        Ok(()) => secret_mutation_redirect(
            &state,
            secret_bucket_path(&organization.slug, &bucket),
            &draft,
            "secret-saved",
            "",
            &headers,
        ),
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
                &draft,
            )
            .await
        }
    }
}

pub(super) async fn delete_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Form(submission): Form<SecretKeySubmission>,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secret_bucket_path(&slug, &bucket), &draft);
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
        return secret_mutation_redirect(
            &state,
            secret_bucket_path(&organization.slug, &bucket),
            &draft,
            "",
            "not-authorized",
            &headers,
        );
    }
    let path = secret_bucket_path(&organization.slug, &bucket);
    let result = secrets_presets_connect::delete_secret(
        &state,
        cookie,
        organization.id,
        bucket_scope(&bucket),
        submission.key,
    )
    .await;
    secret_mutation_result(&state, &headers, path, &draft, result, "secret-deleted")
}

pub(super) async fn rename_secret(
    State(state): State<AppState>,
    Path((slug, bucket)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Form(submission): Form<SecretRenameSubmission>,
) -> Response {
    let draft = secret_draft(raw.as_deref());
    let continuation = secret_navigation_path(secret_bucket_path(&slug, &bucket), &draft);
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
        return secret_mutation_redirect(
            &state,
            secret_bucket_path(&organization.slug, &bucket),
            &draft,
            "",
            "invalid",
            &headers,
        );
    }
    let path = secret_bucket_path(&organization.slug, &bucket);
    let result = secrets_presets_connect::rename_secret(
        &state,
        cookie,
        organization.id,
        bucket_scope(&bucket),
        submission.key,
        submission.new_key,
    )
    .await;
    secret_mutation_result(&state, &headers, path, &draft, result, "secret-renamed")
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
    let token = page_csrf_token(&headers);
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
    let mut project_spec = match secrets_presets_connect::preset_project_spec(
        &state,
        cookie.clone(),
        organization.id.clone(),
        submission.preset_id.clone(),
    )
    .await
    {
        Ok(project_spec) => project_spec,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&continuation, &headers);
        }
        Err(error) => {
            apply_preset_error(&mut form, &error);
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
    };
    if apply_preset_project_updates(&mut project_spec, &form, cpu, memory, disk).is_err() {
        form.form_error = "The preset project configuration is invalid.".to_owned();
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
        default_ttl_seconds: ttl,
        project_spec: Some(codewire_project_proto::to_proto(project_spec)).into(),
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
    feedback: (&str, &str),
    draft: &DraftReturn,
) -> Result<SecretBucketPageView, ConnectError> {
    let (message, error) = feedback;
    let (title, description, can_manage) = match bucket {
        "organization" => (
            "Organization Secrets".to_owned(),
            "Shared application secrets for this organization. Values are never shown in the dashboard.",
            organization.can_admin,
        ),
        "user" => (
            "Personal Secrets".to_owned(),
            "Your personal application secrets. Values are never shown in the dashboard.",
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
                "A named collection of application secrets, not a deployment stage. Values are never shown in the dashboard.",
                organization.can_admin,
            )
        }
    };
    let secrets =
        secrets_presets_connect::secrets(state, cookie, &organization.id, bucket_scope(bucket))
            .await?;
    Ok(SecretBucketPageView {
        creation_draft_query: draft.query(),
        creation_return_url: secret_creation_return(&organization.slug, draft),
        title,
        description,
        bucket: bucket.to_owned(),
        secrets,
        can_manage,
        form,
        csrf_token: String::new(),
        message: message.to_owned(),
        error: error.to_owned(),
    })
}

async fn render_project_form_error(
    state: &AppState,
    headers: &HeaderMap,
    context: (
        crate::view::DashboardView,
        crate::view::OrganizationContext,
        HeaderValue,
    ),
    form: SecretProjectFormView,
    csrf: &str,
    draft: &DraftReturn,
) -> Response {
    let (dashboard, organization, cookie) = context;
    let projects =
        match secrets_presets_connect::secret_projects(state, cookie, &organization.id).await {
            Ok(projects) => projects,
            Err(error) => {
                return connect_page_error(
                    error,
                    &secret_navigation_path(secrets_path(&organization.slug), draft),
                    headers,
                );
            }
        };
    let page = SecretProjectsPageView {
        creation_draft_query: draft.query(),
        creation_return_url: secret_creation_return(&organization.slug, draft),
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
    draft: &DraftReturn,
) -> Response {
    let (dashboard, organization, cookie) = context;
    let mut page =
        match bucket_page(state, cookie, &organization, bucket, form, ("", ""), draft).await {
            Ok(page) => page,
            Err(error) => {
                return connect_page_error(
                    error,
                    &secret_navigation_path(secret_bucket_path(&organization.slug, bucket), draft),
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
            "Use 1–{MAX_WORKLOAD_SECRET_KEY_BYTES} ASCII letters, numbers, or underscores; start with a letter or underscore"
        );
    }
    if value.is_empty() {
        form.form_error = "Enter a secret value. Values are never shown again.".to_owned();
    }
}

fn valid_secret_key(value: &str) -> bool {
    validate_workload_secret_key(value).is_ok()
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

fn apply_preset_project_updates(
    project_spec: &mut codewire_project::ProjectSpec,
    form: &PresetFormView,
    cpu: Option<i32>,
    memory: Option<i32>,
    disk: Option<i32>,
) -> Result<(), codewire_project::ProjectError> {
    project_spec.image = form.image.trim().to_owned();
    project_spec.install_command = form.install_command.clone();
    project_spec.startup_script = form.startup_script.clone();
    project_spec.resources = ResourceSpec {
        cpu_millicores: cpu.and_then(|value| u32::try_from(value).ok()),
        memory_mib: memory.and_then(|value| u64::try_from(value).ok()),
        disk_gib: disk.and_then(|value| u64::try_from(value).ok()),
    };
    project_spec.validate()
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
            "project_spec.resources.cpu_millicores" => form.cpu_error = description,
            "project_spec.resources.memory_mib" => form.memory_error = description,
            "project_spec.resources.disk_gib" => form.disk_error = description,
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
    draft: &DraftReturn,
    result: Result<(), ConnectError>,
    message: &str,
) -> Response {
    match result {
        Ok(()) => secret_mutation_redirect(state, path, draft, message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&secret_navigation_path(path, draft), headers)
        }
        Err(error) => {
            secret_mutation_redirect(state, path, draft, "", mutation_error_code(&error), headers)
        }
    }
}

// Presentation-only navigation is parsed separately from mutation authority.
// Bad handles drop navigation, not a valid secret operation or its CSRF fence.
fn secret_draft(raw: Option<&str>) -> DraftReturn {
    match DraftReturn::parse(raw) {
        exact @ DraftReturn::Exact(_) => exact,
        _ => DraftReturn::NoRequest,
    }
}

fn secret_navigation_path(path: String, draft: &DraftReturn) -> String {
    format!("{path}{}", draft.query())
}

fn secret_creation_return(slug: &str, draft: &DraftReturn) -> String {
    if matches!(draft, DraftReturn::Exact(_)) {
        secret_navigation_path(format!("/{slug}/new/"), draft)
    } else {
        String::new()
    }
}

fn secret_feedback_target(path: String, draft: &DraftReturn, message: &str, error: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if let DraftReturn::Exact(id) = draft {
        query.append_pair("creation_draft", id);
    }
    if !message.is_empty() {
        query.append_pair("message", message);
    } else if !error.is_empty() {
        query.append_pair("error", error);
    }
    let query = query.finish();
    if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    }
}

fn secret_mutation_redirect(
    state: &AppState,
    path: String,
    draft: &DraftReturn,
    message: &str,
    error: &str,
    headers: &HeaderMap,
) -> Response {
    // Preserve the existing token rotation and response behavior, without
    // handing a query-bearing path to its feedback-appending API.
    mutation_redirect(
        state,
        secret_feedback_target(path, draft, message, error),
        "",
        "",
        headers,
    )
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
#[path = "secrets_presets_navigation_tests.rs"]
mod navigation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template as _;
    use codewire_proto::google::rpc::BadRequest;

    #[test]
    fn secret_keys_use_the_canonical_workload_grammar() {
        let maximum = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES - 1));
        let too_long = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES));

        assert_eq!(maximum.len(), 255);
        assert_eq!(too_long.len(), 256);
        assert!(valid_secret_key(&maximum));
        assert!(!valid_secret_key(&too_long));
        assert!(valid_secret_key("_UNDERSCORE_FIRST"));
        assert!(!valid_secret_key("1DIGIT_FIRST"));

        let mut form = SecretFormView {
            key: "1DIGIT_FIRST".into(),
            ..Default::default()
        };
        validate_secret_form(&mut form, "synthetic");
        assert_eq!(
            form.key_error,
            "Use 1–255 ASCII letters, numbers, or underscores; start with a letter or underscore"
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
                field: "/project_spec.resources.memory_mib".into(),
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
    fn preset_edits_preserve_unexposed_canonical_project_fields() {
        let mut project_spec = codewire_project::ProjectSpec {
            repositories: vec![codewire_project::RepositorySpec {
                source: "https://example.test/org/app.git".to_owned(),
                destination: "/workspace/app".to_owned(),
                ..Default::default()
            }],
            working_directory: "/workspace/app".to_owned(),
            environment: [("RUST_LOG".to_owned(), "info".to_owned())]
                .into_iter()
                .collect(),
            agents: codewire_project::AgentsSpec {
                install: Some(true),
                tools: vec!["codex".to_owned()],
            },
            application_ports: vec![codewire_project::ApplicationPort {
                port: 3_000,
                label: "web".to_owned(),
                access: "creator".to_owned(),
            }],
            secrets: codewire_project::SecretBindings {
                project: "development".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let repositories = project_spec.repositories.clone();
        let environment = project_spec.environment.clone();
        let agents = project_spec.agents.clone();
        let application_ports = project_spec.application_ports.clone();
        let secrets = project_spec.secrets.clone();
        let form = PresetFormView {
            image: "example.test/workspace@sha256:def".to_owned(),
            install_command: "cargo build".to_owned(),
            startup_script: "cargo run".to_owned(),
            ..Default::default()
        };

        apply_preset_project_updates(&mut project_spec, &form, Some(2_000), Some(4_096), Some(40))
            .expect("valid preset edit");

        assert_eq!(project_spec.repositories, repositories);
        assert_eq!(project_spec.environment, environment);
        assert_eq!(project_spec.agents, agents);
        assert_eq!(project_spec.application_ports, application_ports);
        assert_eq!(project_spec.secrets, secrets);
        assert_eq!(project_spec.resources.cpu_millicores, Some(2_000));
        assert_eq!(project_spec.image, "example.test/workspace@sha256:def");
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
            can_admin: true,
            environments_url: "/environments".into(),
            presets_url: "/presets".into(),
            secrets_url: "/secrets".into(),
            api_keys_url: "/api-keys".into(),
            members_url: "/members".into(),
            billing_url: "/billing".into(),
        };
        let secret_page = SecretBucketPageView {
            creation_draft_query: String::new(),
            creation_return_url: String::new(),
            title: "Organization Secrets".into(),
            description: "Write-only application secrets.",
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
