use axum::{Form, extract::State, http::HeaderMap, response::Response};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    raw_auth::{post_json, user_message},
    response::{error_page, login_redirect, render_page, two_factor_redirect},
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::DeviceTemplate,
    view::{AuthQuery, DevicePageView, DeviceSubmission},
};

#[derive(Serialize)]
struct DeviceRequest<'a> {
    user_code: &'a str,
}

#[derive(Deserialize)]
struct DeviceResponse {
    #[allow(dead_code)]
    approved: bool,
}

pub(super) async fn device(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AuthQuery>,
) -> Response {
    let continuation = device_continuation(&query.user_code);
    match authenticated_identity(&state, &headers).await {
        Ok(identity) => {
            if enforce_two_factor(&identity).is_err() {
                return two_factor_redirect(&continuation, &headers);
            }
        }
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(error) => return error_page(error),
    }
    render_device(
        &state,
        query.user_code.trim().to_uppercase(),
        String::new(),
        false,
    )
}

pub(super) async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceSubmission>,
) -> Response {
    let user_code = form.user_code.trim().to_uppercase();
    let continuation = device_continuation(&user_code);
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(error) => return error_page(error),
    };
    if enforce_two_factor(&identity).is_err() {
        return two_factor_redirect(&continuation, &headers);
    }
    if !request_has_same_origin(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &form.csrf)
    {
        return error_page(WebError::CsrfRejected);
    }
    if user_code.is_empty() || user_code.len() > 64 {
        return render_device(
            &state,
            user_code,
            "Enter a valid device code.".to_owned(),
            false,
        );
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(&continuation, &headers),
    };
    match post_json::<_, DeviceResponse>(
        &state,
        "/api/oauth/device_verification",
        Some(cookie),
        &DeviceRequest {
            user_code: &user_code,
        },
    )
    .await
    {
        Ok(response) if response.status.is_success() => {
            render_device(&state, user_code, String::new(), true)
        }
        Ok(response) => render_device(
            &state,
            user_code,
            user_message(response.status, "device").to_owned(),
            false,
        ),
        Err(()) => error_page(WebError::IdentityUnavailable),
    }
}

fn render_device(state: &AppState, user_code: String, error: String, approved: bool) -> Response {
    let csrf = new_csrf_token();
    let view = DevicePageView {
        user_code,
        csrf_token: csrf.clone(),
        error,
        approved,
    };
    with_csrf_cookie(
        render_page(DeviceTemplate { view: &view }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

fn device_continuation(user_code: &str) -> String {
    if user_code.is_empty() {
        "/device".to_owned()
    } else {
        format!(
            "/device?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("user_code", user_code)
                .finish()
        )
    }
}
