use axum::{
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
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

/// The homepage is the same for every visitor: browsers check back on each
/// view, and a shared cache (the CDN) may serve one copy for five minutes.
/// `security::keep_cookie_responses_private` takes this back whenever the
/// response sets a cookie.
pub(crate) const HOME_CACHE_CONTROL: &str = "public, max-age=0, s-maxage=300";

pub(super) async fn home() -> Response {
    let mut response = render_page(HomeTemplate);
    if response.status() == StatusCode::OK {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(HOME_CACHE_CONTROL),
        );
    }
    response
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
    use axum::http::{StatusCode, header};
    use codewire_server_core::auth::SESSION_COOKIE_NAME;

    use super::{HOME_CACHE_CONTROL, verified_view};

    fn config() -> crate::Config {
        let unused = "http://127.0.0.1:9";
        crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://codewire.test".into(),
            api_origin: unused.parse().unwrap(),
            credential_origin: unused.parse().unwrap(),
            identity_origin_string: unused.into(),
            browser_api_origin: "https://codewire.test".into(),
            billing_origin: unused.parse().unwrap(),
            docs_root: std::path::PathBuf::new(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        }
    }

    #[tokio::test]
    async fn only_the_anonymous_homepage_may_be_kept_by_a_shared_cache() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server =
            tokio::spawn(async move { axum::serve(listener, crate::app(config())).await.unwrap() });
        let client = reqwest::Client::new();

        let anonymous = client.get(format!("{origin}/")).send().await.unwrap();
        assert_eq!(anonymous.status(), StatusCode::OK);
        assert_eq!(
            anonymous.headers()[header::CACHE_CONTROL],
            HOME_CACHE_CONTROL
        );
        assert!(!anonymous.headers().contains_key(header::SET_COOKIE));

        // A signed-in visitor without a CSRF cookie is handed one with the
        // page, so that page must never be shared.
        let signed_in = client
            .get(format!("{origin}/"))
            .header(header::COOKIE, format!("{SESSION_COOKIE_NAME}=synthetic"))
            .send()
            .await
            .unwrap();
        assert_eq!(signed_in.status(), StatusCode::OK);
        assert!(signed_in.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            signed_in.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );

        // Other pages stay private.
        let login = client.get(format!("{origin}/login")).send().await.unwrap();
        assert_ne!(login.headers()[header::CACHE_CONTROL], HOME_CACHE_CONTROL);
        server.abort();
    }

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
