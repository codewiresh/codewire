use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde::Deserialize;

use crate::{
    analytics::Analytics,
    response::{render_page, render_template, render_updates_page, with_analytics_policy},
    security::HOME_CACHE_CONTROL,
    state::AppState,
    templates::{
        AuthStatusTemplate, HomeTemplate, PricingTemplate, PrivacyTemplate, TermsTemplate,
        UpdatesTemplate,
    },
    view::AuthQuery,
};

#[derive(Deserialize)]
struct VerifyEmailResponse {
    #[serde(default, rename = "accessPending")]
    access_pending: bool,
}

/// The homepage carries the analytics tag for every visitor: a shared cache
/// keeps one copy for all of them (infra#2677).
pub(super) async fn home(State(state): State<AppState>) -> Response {
    let analytics = state.analytics;
    let mut response = tagged(
        render_page(HomeTemplate {
            analytics: analytics.clone(),
        }),
        analytics.as_ref(),
        StatusCode::OK,
    );
    if response.status() == StatusCode::OK {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(HOME_CACHE_CONTROL),
        );
    }
    response
}

/// `response` with the analytics policy when its page carries the tag.
fn tagged(response: Response, analytics: Option<&Analytics>, status: StatusCode) -> Response {
    match analytics {
        Some(analytics) => with_analytics_policy(response, status, &analytics.origin),
        None => response,
    }
}

pub(super) async fn pricing(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let analytics = Analytics::for_visitor(state.analytics.as_ref(), &headers);
    let credit = crate::billing_connect::signup_credit_nano_eur(&state).await;
    let response = render_page(PricingTemplate {
        analytics: analytics.clone(),
        signup_credit: crate::billing_connect::signup_credit_text(credit),
        rates: crate::public_rates::public_rates(&state).await,
    });
    tagged(response, analytics.as_ref(), StatusCode::OK)
}

/// The privacy policy: public, the same signed in or out but for the
/// analytics tag.
pub(super) async fn privacy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let analytics = Analytics::for_visitor(state.analytics.as_ref(), &headers);
    let response = render_page(PrivacyTemplate {
        analytics: analytics.clone(),
    });
    tagged(response, analytics.as_ref(), StatusCode::OK)
}

/// The terms of service: public, the same signed in or out but for the
/// analytics tag.
pub(super) async fn terms(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let analytics = Analytics::for_visitor(state.analytics.as_ref(), &headers);
    let response = render_page(TermsTemplate {
        analytics: analytics.clone(),
    });
    tagged(response, analytics.as_ref(), StatusCode::OK)
}

/// What's new: the configured Liminal site's posts, the same signed in or
/// out. Not found where no site is configured; unavailable while Liminal has
/// never answered. Like every page but the homepage it is never shared by a
/// cache (#5054); `updates_connect` keeps the posts for five minutes instead.
pub(super) async fn updates(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(updates) = state.updates.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let posts = crate::updates_connect::posts(&state).await;
    let status = if posts.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let analytics = Analytics::for_visitor(state.analytics.as_ref(), &headers);
    let response = render_updates_page(
        status,
        UpdatesTemplate {
            analytics: analytics.clone(),
            posts,
        },
        updates.site().media_origin(),
    );
    tagged(response, analytics.as_ref(), status)
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
    match state
        .http
        .get(url)
        .headers(crate::transport::trace_context())
        .send()
        .await
    {
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
            title: super::authentication::ON_THE_LIST_TITLE,
            description: super::authentication::ON_THE_LIST_DETAIL,
            primary_label: "Back to Codewire",
            primary_url: "/",
        }
    } else {
        AuthStatusTemplate {
            title: "Email verified",
            description: "Your email address is verified. Sign in with the password you chose.",
            primary_label: "Sign in",
            primary_url: "/login",
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
            support_email: None,
            updates_site: None,
            analytics: None,
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
            crate::security::PRIVATE_CACHE_CONTROL
        );

        // Other pages stay private.
        let login = client.get(format!("{origin}/login")).send().await.unwrap();
        assert_ne!(login.headers()[header::CACHE_CONTROL], HOME_CACHE_CONTROL);
        server.abort();
    }

    #[test]
    fn pending_verification_waits_for_access_review() {
        let pending = verified_view(true);
        assert_eq!(pending.title, "You're on the list");
        assert_eq!(pending.primary_url, "/");

        let enabled = verified_view(false);
        assert_eq!(enabled.title, "Email verified");
        assert_eq!(enabled.primary_label, "Sign in");
        assert_eq!(enabled.primary_url, "/login");
    }

    /// `/privacy` and `/terms` are whole public pages, the same for a visitor
    /// and for a browser with a session. Before these routes the organization
    /// catch-all `/{slug}` sent both to sign-in. They read no upstream, so the
    /// application runs here with its upstreams pointing nowhere.
    #[tokio::test]
    async fn privacy_and_terms_render_publicly_signed_in_and_out() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let nowhere = "http://upstream.invalid";
        let app = crate::app(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: nowhere.parse().unwrap(),
            credential_origin: nowhere.parse().unwrap(),
            identity_origin_string: nowhere.into(),
            browser_api_origin: nowhere.into(),
            billing_origin: nowhere.parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
            support_email: None,
            updates_site: None,
            analytics: None,
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        for (path, heading) in [
            ("/privacy", "Privacy policy"),
            ("/terms", "Terms of service"),
        ] {
            for session in [None, Some("codewire.session_token=synthetic")] {
                let mut request = client.get(format!("{origin}{path}"));
                if let Some(cookie) = session {
                    request = request.header(header::COOKIE, cookie);
                }
                let response = request.send().await.unwrap();
                let signed_in = session.is_some();
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "{path}, signed in: {signed_in}"
                );
                assert!(response.headers().get(header::LOCATION).is_none());
                assert!(
                    response.headers()[header::CONTENT_TYPE]
                        .to_str()
                        .unwrap()
                        .starts_with("text/html")
                );
                let body = response.text().await.unwrap();
                let id = &path[1..];
                assert!(body.contains(&format!("<h1 id=\"{id}-title\">{heading}</h1>")));
                assert!(body.contains("Product Engineering BV"));
                assert!(body.contains("mailto:hello@codewire.sh"));
                assert!(body.contains("John M. Keynesplein 4, 1066 EP Amsterdam, the Netherlands"));
                assert!(!body.contains("[OWNER"));
                // The footer links both pages and marks this one.
                assert!(body.contains(&format!("<a href=\"{path}\" aria-current=\"page\">")));
                assert!(body.contains("<nav aria-label=\"Legal\">"));
            }
        }

        let _ = stop.send(());
        server.await.unwrap();
    }
}

#[cfg(test)]
#[path = "updates_tests.rs"]
mod updates_tests;

#[cfg(test)]
#[path = "analytics_tests.rs"]
mod analytics_tests;
