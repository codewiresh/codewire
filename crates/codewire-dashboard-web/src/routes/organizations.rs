use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use connectrpc::ErrorCode;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    connect::{create_organization as create_organization_rpc, organizations},
    error::WebError,
    response::{
        error_page, form_response, login_redirect, redirect, render_page, two_factor_redirect,
    },
    routes::{DASHBOARD_PATH, NEW_ORGANIZATION_PATH},
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, page_csrf_token, request_has_same_origin,
        valid_csrf_token, with_csrf_cookie,
    },
    state::AppState,
    templates::{NewOrganizationTemplate, OrganizationListTemplate},
    view::{
        OrganizationFormSubmission, OrganizationFormView, apply_organization_error,
        validate_organization_form,
    },
};

pub(super) async fn organization_fragment(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let identity = authenticated_identity(&state, &headers).await?;
        enforce_two_factor(&identity)?;
        let cookie = canonical_cookie(&headers).map_err(|()| WebError::Unauthorized)?;
        organizations(&state, cookie).await
    }
    .await;

    match result {
        Ok(organizations) => render_page(OrganizationListTemplate {
            organizations: &organizations,
            has_organizations: !organizations.is_empty(),
        }),
        Err(WebError::Unauthorized) => login_redirect(DASHBOARD_PATH, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(DASHBOARD_PATH, &headers),
        Err(error) => error_page(error),
    }
}

pub(super) async fn new_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    match super::dashboard::dashboard_view(&state, &headers).await {
        Ok(view) => {
            let token = page_csrf_token(&headers);
            let form = OrganizationFormView::default();
            let response = render_page(NewOrganizationTemplate {
                view: &view,
                form: &form,
                csrf_token: &token,
            });
            with_csrf_cookie(response, csrf_cookie(&state.public_origin, &token))
        }
        Err(WebError::Unauthorized) => login_redirect(NEW_ORGANIZATION_PATH, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(NEW_ORGANIZATION_PATH, &headers),
        Err(error) => error_page(error),
    }
}

pub(super) async fn create_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<OrganizationFormSubmission>,
) -> Response {
    let view = match super::dashboard::dashboard_view(&state, &headers).await {
        Ok(view) => view,
        Err(WebError::Unauthorized) => {
            return login_redirect(NEW_ORGANIZATION_PATH, &headers);
        }
        Err(WebError::TwoFactorRequired) => {
            return two_factor_redirect(NEW_ORGANIZATION_PATH, &headers);
        }
        Err(error) => return error_page(error),
    };

    if !request_has_same_origin(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &submission.csrf)
    {
        return error_page(WebError::CsrfRejected);
    }

    let mut form = OrganizationFormView {
        name: submission.name.trim().to_owned(),
        slug: submission.slug.trim().to_owned(),
        ..Default::default()
    };
    validate_organization_form(&mut form);
    if form.has_errors() {
        return form_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &headers,
            &view,
            &form,
            &submission.csrf,
        );
    }

    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => {
            return login_redirect(NEW_ORGANIZATION_PATH, &headers);
        }
    };
    match create_organization_rpc(&state, cookie, &form).await {
        Ok(()) => {
            let rotated = new_csrf_token();
            with_csrf_cookie(
                redirect(DASHBOARD_PATH.to_owned(), &headers),
                csrf_cookie(&state.public_origin, &rotated),
            )
        }
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(NEW_ORGANIZATION_PATH, &headers)
        }
        Err(error) => {
            apply_organization_error(&mut form, &error);
            form_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &headers,
                &view,
                &form,
                &submission.csrf,
            )
        }
    }
}
