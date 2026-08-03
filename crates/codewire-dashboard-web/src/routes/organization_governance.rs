use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use codewire_proto::codewire::v1::OrgRole;
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    error::WebError,
    organization_connect,
    response::{
        HTMX_REQUEST, error_page, login_redirect, redirect, render_page, render_template,
        two_factor_redirect,
    },
    routes::dashboard::dashboard_shell_view,
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{
        OrganizationApiKeysContentTemplate, OrganizationApiKeysTemplate,
        OrganizationMembersContentTemplate, OrganizationMembersTemplate,
    },
    view::{
        ASSIGNMENTS, ApiKeyCreateSubmission, ApiKeyFormView, ApiKeyIdSubmission,
        ApiKeyToggleSubmission, ApiKeysPageView, DashboardView, InvitationIdSubmission,
        InviteFormView, InviteSubmission, MemberIdSubmission, MemberRoleSubmission,
        MembersPageView, OrganizationContext, RemoveMemberSubmission, bad_request_fields,
    },
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct OrganizationQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

pub(super) async fn organization_root(
    State(_state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    redirect(format!("/dashboard/orgs/{slug}/environments"), &headers)
}

pub(super) async fn members_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<OrganizationQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = members_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let (members, invitations) = match organization_connect::members(
        &state,
        cookie,
        &organization.id,
        organization.can_admin,
    )
    .await
    {
        Ok(data) => data,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let token = new_csrf_token();
    let page = MembersPageView {
        members,
        invitations,
        assignment_options: &ASSIGNMENTS,
        invite_form: InviteFormView::default(),
        csrf_token: token.clone(),
        message: members_message(&query.message).to_owned(),
        error: members_error(&query.error).to_owned(),
    };
    with_csrf_cookie(
        render_page(OrganizationMembersTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "members",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn invite_member(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<InviteSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        members_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin {
        return mutation_redirect(&state, members_path(&slug), "", "not-authorized", &headers);
    }

    let assignments = submission.assignments();
    let mut form = InviteFormView {
        email: submission.email.trim().to_lowercase(),
        role: submission.role.clone(),
        assignments: assignments.clone(),
        expanded: true,
        ..Default::default()
    };
    if form.email.is_empty() || form.email.len() > 320 || !form.email.contains('@') {
        form.email_error = "Enter a valid email address".to_owned();
    }
    let role = match form.role.as_str() {
        "member" => Some(OrgRole::Member),
        "admin" => Some(OrgRole::Admin),
        _ => {
            form.role_error = "Choose Member or Admin".to_owned();
            None
        }
    };
    if form.has_errors() {
        return render_members_form_error(
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

    let result = organization_connect::create_invitation(
        &state,
        cookie.clone(),
        organization.id.clone(),
        form.email.clone(),
        role.expect("validated invitation role"),
        assignments,
    )
    .await;
    match result {
        Ok(()) => mutation_redirect(&state, members_path(&slug), "invite-sent", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&members_path(&slug), &headers)
        }
        Err(error) => {
            apply_invite_error(&mut form, &error);
            render_members_form_error(
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

pub(super) async fn update_role(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<MemberRoleSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        members_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.user_id) {
        return mutation_redirect(&state, members_path(&slug), "", "not-authorized", &headers);
    }
    let role = match submission.role.as_str() {
        "member" => OrgRole::Member,
        "admin" => OrgRole::Admin,
        _ => return mutation_redirect(&state, members_path(&slug), "", "invalid", &headers),
    };
    let result = organization_connect::update_member_role(
        &state,
        cookie,
        organization.id,
        submission.user_id,
        role,
    )
    .await;
    mutation_result(&state, &headers, &slug, result, "role-updated")
}

pub(super) async fn update_assignments(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<MemberIdSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        members_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.member_id) {
        return mutation_redirect(&state, members_path(&slug), "", "not-authorized", &headers);
    }
    let assignments = submission.assignments();
    let result = organization_connect::update_member_assignments(
        &state,
        cookie,
        organization.id,
        submission.member_id,
        assignments,
    )
    .await;
    mutation_result(&state, &headers, &slug, result, "assignments-updated")
}

pub(super) async fn remove_member(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<RemoveMemberSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        members_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.user_id) {
        return mutation_redirect(&state, members_path(&slug), "", "not-authorized", &headers);
    }
    let result =
        organization_connect::remove_member(&state, cookie, organization.id, submission.user_id)
            .await;
    mutation_result(&state, &headers, &slug, result, "member-removed")
}

pub(super) async fn revoke_invitation(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<InvitationIdSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        members_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.invitation_id) {
        return mutation_redirect(&state, members_path(&slug), "", "not-authorized", &headers);
    }
    let result = organization_connect::revoke_invitation(
        &state,
        cookie,
        organization.id,
        submission.invitation_id,
    )
    .await;
    mutation_result(&state, &headers, &slug, result, "invitation-revoked")
}

pub(super) async fn api_keys_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<OrganizationQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = api_keys_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let keys = match organization_connect::api_keys(&state, cookie, &organization.id).await {
        Ok(keys) => keys,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    let token = new_csrf_token();
    let page = ApiKeysPageView {
        keys,
        form: ApiKeyFormView {
            expiration: "never".to_owned(),
            ..Default::default()
        },
        csrf_token: token.clone(),
        one_time_key: String::new(),
        has_one_time_key: false,
        message: api_keys_message(&query.message).to_owned(),
        error: api_keys_error(&query.error).to_owned(),
    };
    with_csrf_cookie(
        render_page(OrganizationApiKeysTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "api-keys",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn create_api_key(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<ApiKeyCreateSubmission>,
) -> Response {
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        api_keys_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let mut form = ApiKeyFormView {
        name: submission.name.trim().to_owned(),
        expiration: submission.expiration.clone(),
        expanded: true,
        ..Default::default()
    };
    if form.name.is_empty() || form.name.len() > 128 {
        form.name_error = "Name is required and must be at most 128 characters".to_owned();
    }
    let expires_in_days = match form.expiration.as_str() {
        "never" => None,
        "30" => Some(30),
        "60" => Some(60),
        "90" => Some(90),
        _ => {
            form.expiration_error = "Choose a supported expiration".to_owned();
            None
        }
    };
    if form.has_errors() {
        return render_api_key_form_error(
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

    let raw_key = match organization_connect::create_api_key(
        &state,
        cookie.clone(),
        organization.id.clone(),
        form.name.clone(),
        expires_in_days,
    )
    .await
    {
        Ok(key) if !key.is_empty() => key,
        Ok(_) => return error_page(WebError::Connect(ConnectError::internal("empty API key"))),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&api_keys_path(&slug), &headers);
        }
        Err(error) => {
            apply_api_key_error(&mut form, &error);
            return render_api_key_form_error(
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
    };
    let keys = organization_connect::api_keys(&state, cookie, &organization.id)
        .await
        .unwrap_or_default();
    let token = new_csrf_token();
    let page = ApiKeysPageView {
        keys,
        form: ApiKeyFormView {
            expiration: "never".to_owned(),
            ..Default::default()
        },
        csrf_token: token.clone(),
        one_time_key: raw_key,
        has_one_time_key: true,
        message: String::new(),
        error: String::new(),
    };
    let response = if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::OK,
            OrganizationApiKeysContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_page(OrganizationApiKeysTemplate {
            view: &dashboard,
            organization: &organization,
            page: &page,
            active_tab: "api-keys",
        })
    };
    with_csrf_cookie(response, csrf_cookie(&state.public_origin, &token))
}

pub(super) async fn toggle_api_key(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<ApiKeyToggleSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        api_keys_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.key_id) {
        return mutation_redirect(&state, api_keys_path(&slug), "", "invalid", &headers);
    }
    let result = organization_connect::update_api_key(
        &state,
        cookie,
        organization.id,
        submission.key_id,
        submission.disabled,
    )
    .await;
    api_key_mutation_result(&state, &headers, &slug, result, "key-updated")
}

pub(super) async fn delete_api_key(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<ApiKeyIdSubmission>,
) -> Response {
    let (_, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        api_keys_path(&slug),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_identifier(&submission.key_id) {
        return mutation_redirect(&state, api_keys_path(&slug), "", "not-authorized", &headers);
    }
    let result =
        organization_connect::delete_api_key(&state, cookie, organization.id, submission.key_id)
            .await;
    api_key_mutation_result(&state, &headers, &slug, result, "key-deleted")
}

pub(super) async fn get_context(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    continuation: &str,
) -> Result<(DashboardView, OrganizationContext, HeaderValue), Response> {
    let dashboard = dashboard_shell_view(state, headers)
        .await
        .map_err(|error| route_error(error, continuation, headers))?;
    let row = dashboard
        .organizations
        .iter()
        .find(|organization| organization.slug == slug)
        .ok_or_else(|| error_page(WebError::NotFound))?;
    let organization = OrganizationContext::from_row(row);
    let cookie = canonical_cookie(headers).map_err(|()| login_redirect(continuation, headers))?;
    Ok((dashboard, organization, cookie))
}

pub(super) async fn action_context(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    csrf: &str,
    continuation: String,
) -> Result<(DashboardView, OrganizationContext, HeaderValue), Response> {
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    get_context(state, headers, slug, &continuation).await
}

async fn render_members_form_error(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: DashboardView,
    organization: OrganizationContext,
    cookie: HeaderValue,
    form: InviteFormView,
    csrf: &str,
) -> Response {
    let (members, invitations) = match organization_connect::members(
        state,
        cookie,
        &organization.id,
        organization.can_admin,
    )
    .await
    {
        Ok(data) => data,
        Err(error) => return connect_page_error(error, &organization.members_url, headers),
    };
    let page = MembersPageView {
        members,
        invitations,
        assignment_options: &ASSIGNMENTS,
        invite_form: form,
        csrf_token: csrf.to_owned(),
        message: String::new(),
        error: String::new(),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationMembersContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationMembersTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
                active_tab: "members",
            },
        )
    }
}

async fn render_api_key_form_error(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: DashboardView,
    organization: OrganizationContext,
    cookie: HeaderValue,
    form: ApiKeyFormView,
    csrf: &str,
) -> Response {
    let keys = match organization_connect::api_keys(state, cookie, &organization.id).await {
        Ok(keys) => keys,
        Err(error) => return connect_page_error(error, &organization.api_keys_url, headers),
    };
    let page = ApiKeysPageView {
        keys,
        form,
        csrf_token: csrf.to_owned(),
        one_time_key: String::new(),
        has_one_time_key: false,
        message: String::new(),
        error: String::new(),
    };
    if headers.contains_key(HTMX_REQUEST) {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationApiKeysContentTemplate {
                organization: &organization,
                page: &page,
            },
        )
    } else {
        render_template(
            StatusCode::UNPROCESSABLE_ENTITY,
            OrganizationApiKeysTemplate {
                view: &dashboard,
                organization: &organization,
                page: &page,
                active_tab: "api-keys",
            },
        )
    }
}

fn apply_invite_error(form: &mut InviteFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "email" => form.email_error = description,
            "role" => form.role_error = description,
            _ => {}
        }
    }
    if form.email_error.is_empty() && form.role_error.is_empty() {
        form.form_error = if matches!(error.code, ErrorCode::AlreadyExists | ErrorCode::Aborted) {
            "That person is already a member or has a pending invitation."
        } else if error.code == ErrorCode::PermissionDenied {
            "You do not have permission to invite that role."
        } else {
            "The invitation could not be sent. Please try again."
        }
        .to_owned();
    }
}

fn apply_api_key_error(form: &mut ApiKeyFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "name" => form.name_error = description,
            "expires_in_days" => form.expiration_error = description,
            _ => {}
        }
    }
    if form.name_error.is_empty() && form.expiration_error.is_empty() {
        form.form_error = "The API key could not be created. Please try again.".to_owned();
    }
}

fn mutation_result(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    result: Result<(), ConnectError>,
    message: &str,
) -> Response {
    match result {
        Ok(()) => mutation_redirect(state, members_path(slug), message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&members_path(slug), headers)
        }
        Err(error) => mutation_redirect(
            state,
            members_path(slug),
            "",
            mutation_error_code(&error),
            headers,
        ),
    }
}

fn api_key_mutation_result(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    result: Result<(), ConnectError>,
    message: &str,
) -> Response {
    match result {
        Ok(()) => mutation_redirect(state, api_keys_path(slug), message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&api_keys_path(slug), headers)
        }
        Err(error) => mutation_redirect(
            state,
            api_keys_path(slug),
            "",
            mutation_error_code(&error),
            headers,
        ),
    }
}

fn mutation_error_code(error: &ConnectError) -> &'static str {
    match error.code {
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::InvalidArgument => "invalid",
        ErrorCode::NotFound => "not-found",
        _ => "unavailable",
    }
}

pub(super) fn mutation_redirect(
    state: &AppState,
    path: String,
    message: &str,
    error: &str,
    headers: &HeaderMap,
) -> Response {
    let mut target = path;
    if !message.is_empty() {
        target.push_str("?message=");
        target.push_str(message);
    } else if !error.is_empty() {
        target.push_str("?error=");
        target.push_str(error);
    }
    let token = new_csrf_token();
    with_csrf_cookie(
        redirect(target, headers),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) fn connect_page_error(
    error: ConnectError,
    continuation: &str,
    headers: &HeaderMap,
) -> Response {
    if error.code == ErrorCode::Unauthenticated {
        login_redirect(continuation, headers)
    } else if error.code == ErrorCode::NotFound {
        error_page(WebError::NotFound)
    } else if error.code == ErrorCode::PermissionDenied {
        error_page(WebError::Forbidden)
    } else {
        error_page(WebError::Connect(error))
    }
}

fn route_error(error: WebError, continuation: &str, headers: &HeaderMap) -> Response {
    match error {
        WebError::Unauthorized => login_redirect(continuation, headers),
        WebError::TwoFactorRequired => two_factor_redirect(continuation, headers),
        WebError::Connect(error) => connect_page_error(error, continuation, headers),
        error => error_page(error),
    }
}

pub(super) fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn members_path(slug: &str) -> String {
    format!("/dashboard/orgs/{slug}/members")
}

fn api_keys_path(slug: &str) -> String {
    format!("/dashboard/orgs/{slug}/api-keys")
}

fn members_message(value: &str) -> &'static str {
    match value {
        "invite-sent" => "Invitation sent.",
        "role-updated" => "Member role updated.",
        "assignments-updated" => "Member assignments updated.",
        "member-removed" => "Member removed.",
        "invitation-revoked" => "Invitation revoked.",
        _ => "",
    }
}

fn members_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change organization membership.",
        "invalid" => "The requested member change was invalid.",
        "not-found" => "The member or invitation no longer exists.",
        "unavailable" => "The organization service is temporarily unavailable.",
        _ => "",
    }
}

fn api_keys_message(value: &str) -> &'static str {
    match value {
        "key-updated" => "API key status updated.",
        "key-deleted" => "API key deleted.",
        _ => "",
    }
}

fn api_keys_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to delete API keys.",
        "invalid" => "The requested API-key change was invalid.",
        "not-found" => "The API key no longer exists.",
        "unavailable" => "The API-key service is temporarily unavailable.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::google::rpc::BadRequest;

    #[test]
    fn query_feedback_is_allowlisted() {
        assert_eq!(members_message("invite-sent"), "Invitation sent.");
        assert_eq!(members_message("<script>"), "");
        assert_eq!(
            api_keys_error("not-authorized"),
            "You do not have permission to delete API keys."
        );
        assert_eq!(api_keys_error("raw-upstream-detail"), "");
    }

    #[test]
    fn mutation_identifiers_reject_control_bytes_and_unbounded_values() {
        assert!(valid_identifier("member_123"));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier("member\nother"));
        assert!(!valid_identifier(&"x".repeat(257)));
    }

    #[test]
    fn api_key_bad_request_details_attach_to_the_exact_form_field() {
        let detail = BadRequest {
            field_violations: vec![codewire_proto::google::rpc::bad_request::FieldViolation {
                field: "/name".into(),
                description: "Choose a key name".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = ConnectError::invalid_argument("validation failed").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.BadRequest", &detail),
        );
        let mut form = ApiKeyFormView::default();
        apply_api_key_error(&mut form, &error);
        assert_eq!(form.name_error, "Choose a key name");
        assert!(form.form_error.is_empty());
    }
}
