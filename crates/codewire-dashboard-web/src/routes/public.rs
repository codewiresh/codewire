use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;

use crate::{
    response::{render_page, render_template},
    state::AppState,
    templates::{AuthStatusTemplate, HomeTemplate, PricingTemplate},
    view::AuthQuery,
};

#[derive(Deserialize)]
struct VerifyEmailResponse {
    #[serde(default, rename = "accessPending")]
    access_pending: bool,
}

pub(super) async fn home() -> Response {
    render_page(HomeTemplate)
}

pub(super) async fn pricing(State(state): State<AppState>) -> Response {
    let credit = crate::billing_connect::signup_credit_nano_eur(&state).await;
    render_page(PricingTemplate {
        signup_credit: crate::billing_connect::signup_credit_text(credit),
    })
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
        Ok(response) if response.status().is_success() => {
            match response.json::<VerifyEmailResponse>().await {
                Ok(body) => render_page(verified_view(body.access_pending)),
                Err(_) => verification_unavailable(),
            }
        }
        Ok(_) => invalid_verification(),
        Err(_) => verification_unavailable(),
    }
}

fn verified_view(access_pending: bool) -> AuthStatusTemplate<'static> {
    if access_pending {
        AuthStatusTemplate {
            title: "Access request verified",
            description: "Your email is verified and your access request is ready for review. We will email you when your account is enabled.",
            primary_label: "Back to Codewire",
            primary_url: "/",
        }
    } else {
        AuthStatusTemplate {
            title: "Email verified",
            description: "Your email address is verified. You can continue to Codewire.",
            primary_label: "Continue to dashboard",
            primary_url: "/dashboard/",
        }
    }
}

fn verification_unavailable() -> Response {
    render_template(
        StatusCode::BAD_GATEWAY,
        AuthStatusTemplate {
            title: "Verification unavailable",
            description: "The identity service is temporarily unavailable. Try the link again shortly.",
            primary_label: "Back to sign in",
            primary_url: "/login",
        },
    )
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

#[cfg(test)]
mod tests {
    use super::verified_view;

    #[test]
    fn pending_verification_waits_for_access_review() {
        let pending = verified_view(true);
        assert_eq!(pending.title, "Access request verified");
        assert_eq!(pending.primary_url, "/");

        let enabled = verified_view(false);
        assert_eq!(enabled.title, "Email verified");
        assert_eq!(enabled.primary_url, "/dashboard/");
    }
}
