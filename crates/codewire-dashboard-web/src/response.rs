use askama::Template;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use connectrpc::ErrorCode;
use url::Url;

use crate::{
    error::WebError,
    templates::{ErrorTemplate, NewOrganizationTemplate, OrganizationFormTemplate},
    view::{DashboardView, OrganizationFormView},
};

pub(crate) const HTMX_REQUEST: &str = "hx-request";
const HTMX_REDIRECT: &str = "hx-redirect";
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'";

pub(crate) fn render_page(template: impl Template) -> Response {
    render_template(StatusCode::OK, template)
}

pub(crate) fn render_page_with_connect_origin(
    template: impl Template,
    connect_origin: &str,
) -> Response {
    render_template_with_connect_origin(StatusCode::OK, template, connect_origin)
}

pub(crate) fn render_template(status: StatusCode, template: impl Template) -> Response {
    match template.render() {
        Ok(body) => html_response(status, body, None),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The dashboard could not be rendered.",
        ),
    }
}

pub(crate) fn render_template_with_connect_origin(
    status: StatusCode,
    template: impl Template,
    connect_origin: &str,
) -> Response {
    match template.render() {
        Ok(body) => html_response(status, body, Some(connect_origin)),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The dashboard could not be rendered.",
        ),
    }
}

pub(crate) fn form_response(
    status: StatusCode,
    headers: &HeaderMap,
    view: &DashboardView,
    form: &OrganizationFormView,
    csrf_token: &str,
) -> Response {
    if headers.contains_key(HTMX_REQUEST) {
        render_template(status, OrganizationFormTemplate { form, csrf_token })
    } else {
        render_template(
            status,
            NewOrganizationTemplate {
                view,
                form,
                csrf_token,
            },
        )
    }
}

pub(crate) fn error_page(error: WebError) -> Response {
    let (status, message) = match error {
        WebError::Unauthorized => (StatusCode::UNAUTHORIZED, "Sign in is required."),
        WebError::TwoFactorRequired => (
            StatusCode::FORBIDDEN,
            "Two-factor setup is required before opening the dashboard.",
        ),
        WebError::NotFound => (
            StatusCode::NOT_FOUND,
            "Organization not found or access denied.",
        ),
        WebError::Forbidden => (
            StatusCode::FORBIDDEN,
            "You do not have permission to perform that action.",
        ),
        WebError::CsrfRejected => (
            StatusCode::FORBIDDEN,
            "The form expired or came from another site. Reload it and try again.",
        ),
        WebError::Connect(error) if error.code == ErrorCode::Unauthenticated => {
            (StatusCode::UNAUTHORIZED, "Sign in is required.")
        }
        WebError::IdentityUnavailable => (
            StatusCode::BAD_GATEWAY,
            "The identity service is temporarily unavailable.",
        ),
        WebError::BrowserConfigurationUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The browser connection endpoint is not safely configured.",
        ),
        WebError::Connect(_) => (
            StatusCode::BAD_GATEWAY,
            "The organization service is temporarily unavailable.",
        ),
    };
    render_error(status, message)
}

fn render_error(status: StatusCode, message: &'static str) -> Response {
    match (ErrorTemplate { message }).render() {
        Ok(body) => html_response(status, body, None),
        Err(_) => (status, "Dashboard error").into_response(),
    }
}

pub(crate) fn login_redirect(continuation: &str, headers: &HeaderMap) -> Response {
    redirect(auth_url("/login", continuation), headers)
}

pub(crate) fn two_factor_redirect(continuation: &str, headers: &HeaderMap) -> Response {
    redirect(auth_url("/setup-2fa", continuation), headers)
}

pub(crate) fn auth_url(path: &str, continuation: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "return_to",
            safe_auth_continuation(continuation).unwrap_or("/dashboard"),
        )
        .finish();
    format!("{path}?{query}")
}

pub(crate) fn safe_auth_continuation(value: &str) -> Option<&str> {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let parsed = Url::parse(&format!("https://codewire.invalid{value}")).ok()?;
    (parsed.origin().ascii_serialization() == "https://codewire.invalid").then_some(value)
}

pub(crate) fn redirect(location: String, headers: &HeaderMap) -> Response {
    if headers.contains_key(HTMX_REQUEST) {
        return (
            StatusCode::OK,
            [
                (HTMX_REDIRECT, location),
                (header::CACHE_CONTROL.as_str(), "no-store".to_owned()),
            ],
        )
            .into_response();
    }
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION.as_str(), location),
            (header::CACHE_CONTROL.as_str(), "no-store".to_owned()),
        ],
    )
        .into_response()
}

fn html_response(status: StatusCode, body: String, connect_origin: Option<&str>) -> Response {
    let mut response = (
        status,
        [
            (header::CONTENT_TYPE.as_str(), "text/html; charset=utf-8"),
            (header::CACHE_CONTROL.as_str(), "private, no-store"),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
            (header::REFERRER_POLICY.as_str(), "same-origin"),
        ],
        body,
    )
        .into_response();
    let policy = connect_origin.map_or_else(
        || CONTENT_SECURITY_POLICY.to_owned(),
        |origin| {
            CONTENT_SECURITY_POLICY.replace(
                "connect-src 'self'",
                &format!("connect-src 'self' {origin}"),
            )
        },
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).expect("validated CSP connect origin"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_html_is_not_cached_and_has_browser_boundaries() {
        let response = html_response(StatusCode::OK, "<main>safe</main>".to_owned(), None);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-eval"));
    }

    #[test]
    fn terminal_pages_allow_only_the_validated_websocket_origin() {
        let response = html_response(
            StatusCode::OK,
            "<main>terminal</main>".to_owned(),
            Some("ws://127.0.0.1:8080"),
        );
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.contains("connect-src 'self' ws://127.0.0.1:8080"));
        assert!(!policy.contains("unsafe-inline"));
        assert!(!policy.contains("unsafe-eval"));
    }

    #[test]
    fn redirects_are_also_not_cached() {
        let response = redirect("/dashboard".to_owned(), &HeaderMap::new());
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
