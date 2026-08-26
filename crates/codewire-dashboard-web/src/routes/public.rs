use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Response,
};

use crate::{
    response::{render_page, render_template},
    state::AppState,
    templates::{AuthStatusTemplate, HomeTemplate},
    view::AuthQuery,
};

pub(super) async fn home() -> Response {
    render_page(HomeTemplate)
}

pub(super) async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Response {
    if query.token.is_empty()
        || query.token.len() > 512
        || query.token.bytes().any(|byte| byte.is_ascii_control())
    {
        return invalid_verification();
    }
    let url = format!(
        "{}/api/auth/verify-email?{}",
        state.identity_origin_string,
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", &query.token)
            .finish()
    );
    match state.http.get(url).send().await {
        Ok(response) if response.status().is_success() => render_page(AuthStatusTemplate {
            title: "Email verified",
            description: "Your email address is verified. You can continue to Codewire.",
            primary_label: "Continue to dashboard",
            primary_url: "/dashboard/",
        }),
        Ok(_) => invalid_verification(),
        Err(_) => render_template(
            StatusCode::BAD_GATEWAY,
            AuthStatusTemplate {
                title: "Verification unavailable",
                description: "The identity service is temporarily unavailable. Try the link again shortly.",
                primary_label: "Back to sign in",
                primary_url: "/login",
            },
        ),
    }
}

fn invalid_verification() -> Response {
    render_template(
        StatusCode::BAD_REQUEST,
        AuthStatusTemplate {
            title: "Invalid or expired link",
            description: "This email verification link is invalid or has expired.",
            primary_label: "Back to sign in",
            primary_url: "/login",
        },
    )
}
