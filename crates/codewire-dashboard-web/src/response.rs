use askama::Template;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connectrpc::ErrorCode;
use rand::{RngCore as _, rngs::OsRng};
use url::Url;

use crate::{
    error::WebError,
    templates::{ErrorTemplate, NewOrganizationTemplate, OrganizationFormTemplate},
    view::{DashboardView, OrganizationFormView},
};

pub(crate) const HTMX_REQUEST: &str = "hx-request";
const HTMX_REDIRECT: &str = "hx-redirect";
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'";

/// Only server-generated nonces can extend the terminal's style policy. This
/// capability never permits inline script or style attributes.
pub(crate) struct TerminalStyleNonce(String);

impl TerminalStyleNonce {
    pub(crate) fn new() -> Self {
        let mut bytes = [0_u8; 24];
        OsRng.fill_bytes(&mut bytes);
        Self(STANDARD.encode(bytes))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn render_terminal_page(
    template: impl Template,
    connect_origin: &str,
    nonce: &TerminalStyleNonce,
) -> Response {
    match template.render() {
        Ok(body) => html_response_with_terminal_styles(
            StatusCode::OK,
            body,
            Some(connect_origin),
            Some(nonce),
        ),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The dashboard could not be rendered.",
        ),
    }
}

pub(crate) fn render_page(template: impl Template) -> Response {
    render_template(StatusCode::OK, template)
}

pub(crate) fn render_credential_settings_page(template: impl Template) -> Response {
    let mut response = render_page(template);
    if response.status() == StatusCode::OK {
        // Chromium applies the initiating document's form-action policy to
        // the native authorization POST's cross-origin redirect as well. Only
        // Credentials permits this fixed provider destination; other pages,
        // scripts, connections and error responses keep the default policy.
        let policy = CONTENT_SECURITY_POLICY.replace(
            "form-action 'self'",
            "form-action 'self' https://github.com",
        );
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&policy).expect("static credential form policy"),
        );
    }
    response
}

/// The Account page's Connect button POSTs to its action, which answers with a
/// redirect to GitHub's or Google's authorize page (#4062). Chromium applies
/// this page's form-action to that cross-origin redirect too, so exactly those
/// two origins are added, and only here and only on this page's own renders;
/// error pages keep the default policy.
pub(crate) fn render_account_settings_page(
    status: StatusCode,
    template: impl Template,
) -> Response {
    let mut response = render_template(status, template);
    if response.status() == status {
        let policy = CONTENT_SECURITY_POLICY.replace(
            "form-action 'self'",
            &format!(
                "form-action 'self' {}",
                crate::account_sign_in_methods::PROVIDER_AUTHORIZE_ORIGINS.join(" ")
            ),
        );
        if let Ok(policy) = HeaderValue::from_str(&policy) {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, policy);
        }
    }
    response
}

/// The Billing page's policy (#4750): Stripe's script, its card form's
/// frames and its API, for the card form that stays in the page, and the two
/// Stripe pages a form may still redirect to. Chromium applies form-action to
/// a form's cross-origin redirect too: Add credit goes on to the invoice's
/// payment page when the bank wants a charge approved, and to Checkout for an
/// organization billing finds without a card. Only this page gets any of it.
const BILLING_POLICY: [(&str, &str); 4] = [
    (
        "connect-src 'self'",
        "connect-src 'self' https://api.stripe.com",
    ),
    (
        "form-action 'self'",
        "form-action 'self' https://checkout.stripe.com https://invoice.stripe.com",
    ),
    (
        "script-src 'self'",
        "script-src 'self' https://js.stripe.com https://*.js.stripe.com",
    ),
    (
        "img-src 'self' data:",
        "img-src 'self' data: https://*.stripe.com",
    ),
];
const BILLING_FRAMES: &str =
    "frame-src https://js.stripe.com https://*.js.stripe.com https://hooks.stripe.com";

/// `response` with the Billing page's referrer policy, whatever its status.
/// Back from a bank's redirect, the page's URL names a SetupIntent until the
/// card script cleans it: no request it makes may carry the path or query on,
/// to Stripe or to the console's own logs (#4750). Not no-referrer: under it
/// a form post sends `Origin: null`, which the same-origin CSRF gate refuses
/// (as personal_secrets.rs notes).
pub(crate) fn with_billing_referrer_policy(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin"),
    );
    response
}

pub(crate) fn render_billing_page(template: impl Template) -> Response {
    let mut response = with_billing_referrer_policy(render_page(template));
    if response.status() == StatusCode::OK {
        let mut policy = BILLING_POLICY
            .iter()
            .fold(CONTENT_SECURITY_POLICY.to_owned(), |policy, (from, to)| {
                policy.replace(from, to)
            });
        policy.push_str("; ");
        policy.push_str(BILLING_FRAMES);
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&policy).expect("static billing policy"),
        );
    }
    response
}

/// The Updates page shows its CMS posts' images, which the CMS keeps on one
/// media origin; the post HTML is cleaned to images from that origin, so only
/// it is added, and only on this page. Any other image host would let a post
/// count its readers.
pub(crate) fn render_updates_page(
    status: StatusCode,
    template: impl Template,
    media_origin: Option<&str>,
) -> Response {
    let mut response = render_template(status, template);
    if response.status() == status
        && let Some(media_origin) = media_origin
    {
        let policy = CONTENT_SECURITY_POLICY.replace(
            "img-src 'self' data:",
            &format!("img-src 'self' data: {media_origin}"),
        );
        if let Ok(policy) = HeaderValue::from_str(&policy) {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, policy);
        }
    }
    response
}

/// `response`, a page rendered with the analytics tag (infra#2677), with its
/// policy allowing the tracker's one connection, to `origin`. Its script is
/// the page's own, so only connect-src changes; a page whose render failed
/// keeps its policy.
pub(crate) fn with_analytics_policy(
    mut response: Response,
    status: StatusCode,
    origin: &str,
) -> Response {
    if response.status() != status {
        return response;
    }
    let policy = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .map(|policy| {
            policy.replace(
                "connect-src 'self'",
                &format!("connect-src 'self' {origin}"),
            )
        });
    if let Some(policy) = policy.and_then(|policy| HeaderValue::from_str(&policy).ok()) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    response
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
            safe_auth_continuation(continuation).unwrap_or("/dashboard/"),
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
    html_response_with_terminal_styles(status, body, connect_origin, None)
}

fn html_response_with_terminal_styles(
    status: StatusCode,
    body: String,
    connect_origin: Option<&str>,
    nonce: Option<&TerminalStyleNonce>,
) -> Response {
    let body = crate::assets::versioned(&body).unwrap_or(body);
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
    let mut policy = connect_origin.map_or_else(
        || CONTENT_SECURITY_POLICY.to_owned(),
        |origin| {
            CONTENT_SECURITY_POLICY.replace(
                "connect-src 'self'",
                &format!("connect-src 'self' {origin}"),
            )
        },
    );
    if let Some(nonce) = nonce {
        policy.push_str(&format!(
            " 'nonce-{}'; style-src-attr 'none'",
            nonce.as_str()
        ));
    }
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
    fn terminal_style_nonce_is_fresh_and_does_not_authorize_scripts_or_attributes() {
        let nonce = TerminalStyleNonce::new();
        assert_ne!(nonce.as_str(), TerminalStyleNonce::new().as_str());
        assert_eq!(STANDARD.decode(nonce.as_str()).unwrap().len(), 24);
        let response = html_response_with_terminal_styles(
            StatusCode::OK,
            "terminal".to_owned(),
            Some("wss://codewire.test"),
            Some(&nonce),
        );
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.contains(&format!("style-src 'self' 'nonce-{}'", nonce.as_str())));
        assert!(policy.contains("script-src 'self';"));
        assert!(policy.contains("style-src-attr 'none'"));
        assert!(!policy.contains("unsafe-inline"));
        assert!(!policy.contains("unsafe-eval"));
    }

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
    fn design_system_icons_load_under_the_page_policy() {
        // Icon tokens are data: URIs. Without data: in img-src every select
        // chevron, checkbox mark and close icon is blocked and disappears.
        let styles = concat!(
            include_str!("../../../packages/codewire-design/styles.css"),
            include_str!("../../../packages/codewire-design/components.css"),
        );
        assert!(styles.contains("url(\"data:image/svg+xml,"));
        let img_src = CONTENT_SECURITY_POLICY
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("img-src "));
        assert_eq!(img_src, Some("img-src 'self' data:"));
    }

    #[test]
    fn only_the_billing_page_allows_stripe() {
        #[derive(Template)]
        #[template(source = "<main>Billing</main>", ext = "html")]
        struct Billing;

        let response = render_billing_page(Billing);
        assert_eq!(response.status(), StatusCode::OK);
        // A bank's return URL names a SetupIntent: the Referer carries the
        // origin only, and a form post keeps its Origin for the CSRF gate.
        assert_eq!(response.headers()[header::REFERRER_POLICY], "strict-origin");
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        let directives: Vec<&str> = policy.split(';').map(str::trim).collect();
        // Each directive appears once: a second one would be ignored.
        for name in [
            "connect-src",
            "form-action",
            "script-src",
            "frame-src",
            "img-src",
        ] {
            let count = directives
                .iter()
                .filter(|directive| directive.split_whitespace().next() == Some(name))
                .count();
            assert_eq!(count, 1, "{name}: {policy}");
        }
        for expected in [
            "connect-src 'self' https://api.stripe.com",
            "form-action 'self' https://checkout.stripe.com https://invoice.stripe.com",
            "script-src 'self' https://js.stripe.com https://*.js.stripe.com",
            "frame-src https://js.stripe.com https://*.js.stripe.com https://hooks.stripe.com",
            "img-src 'self' data: https://*.stripe.com",
        ] {
            assert!(directives.contains(&expected), "{policy}");
        }
        // Everything else is the dashboard's own policy.
        let others: Vec<&str> = directives
            .into_iter()
            .filter(|directive| !directive.contains("stripe.com"))
            .collect();
        let base: Vec<&str> = CONTENT_SECURITY_POLICY
            .split(';')
            .map(str::trim)
            .filter(|directive| {
                !["connect-src", "form-action", "script-src", "img-src"]
                    .iter()
                    .any(|name| directive.starts_with(name))
            })
            .collect();
        assert_eq!(others, base);
        for other in [
            render_page(Billing),
            render_credential_settings_page(Billing),
        ] {
            let policy = other.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap();
            assert!(!policy.contains("stripe.com"), "{policy}");
        }
    }

    #[test]
    fn only_credential_settings_allow_the_github_app_form_redirect() {
        #[derive(Template)]
        #[template(source = "<main>Credentials</main>", ext = "html")]
        struct Credentials;

        let response = render_credential_settings_page(Credentials);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert_eq!(
            policy.replace(
                "form-action 'self' https://github.com",
                "form-action 'self'"
            ),
            CONTENT_SECURITY_POLICY
        );
        assert!(policy.contains("form-action 'self' https://github.com;"));
        assert_eq!(
            render_page(Credentials).headers()[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
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
