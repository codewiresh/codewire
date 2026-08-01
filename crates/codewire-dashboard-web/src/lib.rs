//! Production server-rendered dashboard adapter.
//!
//! The adapter owns presentation and progressive enhancement. Identity stays
//! on the raw IdP session contract and product data stays on generated Connect
//! services. Only the canonical browser session cookie crosses those bounds.

use std::{env, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context as _, bail};
use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use codewire_proto::codewire::{
    console::v1::{GetGitHubStatusRequest, GitHubServiceClient},
    v1::{ListOrganizationsRequest, OrganizationServiceClient},
};
use codewire_server_core::auth::{SESSION_COOKIE_NAME, session_cookie};
use connectrpc::client::{BoxFuture, ClientConfig, ClientTransport};
use connectrpc::{ConnectError, ErrorCode};
use http::{Request, Response as HttpResponse};
use http_body_util::BodyExt as _;
use serde::Deserialize;
use url::Url;

const DASHBOARD_PATH: &str = "/dashboard";
const ORGANIZATIONS_FRAGMENT_PATH: &str = "/dashboard/_fragments/organizations";
const HTMX_PATH: &str = "/assets/codewire/htmx-2.0.10.min.js";
const STYLE_PATH: &str = "/assets/codewire/design-v1.css";
const SCRIPT_PATH: &str = "/assets/codewire/dashboard-v1.js";
const LOGO_PATH: &str = "/assets/codewire/logo-v1.svg";
const HTMX_REQUEST: &str = "hx-request";
const HTMX_REDIRECT: &str = "hx-redirect";
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'";
const HTMX: &str = include_str!("../assets/htmx-2.0.10.min.js");
const STYLES: &str = include_str!("../../../packages/codewire-design/styles.css");
const DASHBOARD_SCRIPT: &str = include_str!("../../../packages/codewire-design/dashboard.js");
const LOGO: &str = include_str!("../../../packages/codewire-design/assets/logo.svg");

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    public_origin: String,
    api_origin: http::Uri,
    api_origin_string: String,
    legacy_origin: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen_addr = env::var("CODEWIRE_DASHBOARD_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:5174".to_owned())
            .parse()
            .context("CODEWIRE_DASHBOARD_LISTEN_ADDR must be a socket address")?;
        let (_, public_origin) = parse_origin(
            "CODEWIRE_PUBLIC_ORIGIN",
            env::var("CODEWIRE_PUBLIC_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:5174".to_owned()),
        )?;
        let (api_origin, api_origin_string) = parse_origin(
            "CODEWIRE_API_ORIGIN",
            env::var("CODEWIRE_API_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned()),
        )?;
        let (_, legacy_origin) = parse_origin(
            "CODEWIRE_LEGACY_UI_ORIGIN",
            env::var("CODEWIRE_LEGACY_UI_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:5173".to_owned()),
        )?;

        Ok(Self {
            listen_addr,
            public_origin,
            api_origin,
            api_origin_string,
            legacy_origin,
        })
    }
}

fn parse_origin(label: &str, raw: String) -> anyhow::Result<(http::Uri, String)> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = Url::parse(trimmed)
        .with_context(|| format!("{label} must be an absolute HTTP(S) origin"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("{label} must be an absolute HTTP(S) origin without a path, query, or fragment");
    }
    let normalized = url.as_str().trim_end_matches('/').to_owned();
    Ok((
        http::Uri::from_str(&normalized).context("origin is not a valid HTTP URI")?,
        normalized,
    ))
}

#[derive(Clone)]
struct AppState {
    public_origin: String,
    api_origin: http::Uri,
    api_origin_string: String,
    legacy_origin: String,
    http: reqwest::Client,
}

pub fn app(config: Config) -> Router {
    let state = AppState {
        public_origin: config.public_origin,
        api_origin: config.api_origin,
        api_origin_string: config.api_origin_string,
        legacy_origin: config.legacy_origin,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("static dashboard HTTP client configuration"),
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route(DASHBOARD_PATH, get(dashboard))
        .route(ORGANIZATIONS_FRAGMENT_PATH, get(organization_fragment))
        .route(HTMX_PATH, get(htmx_asset))
        .route(STYLE_PATH, get(stylesheet))
        .route(SCRIPT_PATH, get(dashboard_script))
        .route(LOGO_PATH, get(logo_asset))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match dashboard_view(&state, &headers).await {
        Ok(view) => render_page(DashboardTemplate {
            organizations: &view.organizations,
            has_organizations: view.has_organizations,
            view: &view,
        }),
        Err(WebError::Unauthorized) => login_redirect(&state.legacy_origin, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(&state.legacy_origin, &headers),
        Err(error) => error_page(error),
    }
}

async fn organization_fragment(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        let identity = authenticated_identity(&state, &headers).await?;
        enforce_two_factor(&identity)?;
        let cookie = canonical_cookie(&headers)?;
        organizations(&state, cookie).await
    }
    .await;

    match result {
        Ok(organizations) => render_page(OrganizationListTemplate {
            organizations: &organizations,
            has_organizations: !organizations.is_empty(),
        }),
        Err(WebError::Unauthorized) => login_redirect(&state.legacy_origin, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(&state.legacy_origin, &headers),
        Err(error) => error_page(error),
    }
}

async fn dashboard_view(state: &AppState, headers: &HeaderMap) -> Result<DashboardView, WebError> {
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers)?;
    let (organizations, github_status) = tokio::join!(
        organizations(state, cookie.clone()),
        github_status(state, cookie),
    );
    let organizations = organizations?;
    let (github_connected, github_available) = match github_status {
        Ok(connected) => (connected, true),
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            return Err(WebError::Unauthorized);
        }
        Err(_) => (false, false),
    };
    let has_organizations = !organizations.is_empty();
    let show_checklist = !has_organizations || !github_connected;

    Ok(DashboardView {
        user_name: identity.display_name().to_owned(),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        github_connected,
        github_available,
        show_checklist,
        new_organization_url: format!("{}/dashboard/orgs/new", state.legacy_origin),
        legacy_settings_url: format!("{}/dashboard/settings", state.legacy_origin),
        legacy_admin_url: format!("{}/admin", state.legacy_origin),
        legacy_home_url: format!("{}/dashboard", state.legacy_origin),
        github_connect_url: github_connect_url(state),
    })
}

fn github_connect_url(state: &AppState) -> String {
    let mut url = Url::parse(&format!(
        "{}/api/v1/github/oauth/authorize",
        state.api_origin_string
    ))
    .expect("validated API origin");
    url.query_pairs_mut()
        .append_pair("return_url", &format!("{}/dashboard", state.public_origin));
    url.into()
}

#[derive(Debug, Deserialize)]
struct IdentityEnvelope {
    user: Option<IdentityUser>,
    #[serde(default)]
    skip_2fa_setup: bool,
}

#[derive(Debug, Deserialize)]
struct IdentityUser {
    email: String,
    name: Option<String>,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    two_factor_enabled: bool,
    #[serde(skip)]
    skip_2fa_setup: bool,
}

impl IdentityUser {
    fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.email)
    }
}

async fn authenticated_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<IdentityUser, WebError> {
    let cookie = canonical_cookie(headers)?;
    let response = state
        .http
        .get(format!("{}/api/auth/get-session", state.api_origin_string))
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| WebError::IdentityUnavailable)?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(WebError::Unauthorized);
    }
    if !response.status().is_success() {
        return Err(WebError::IdentityUnavailable);
    }
    let envelope = response
        .json::<IdentityEnvelope>()
        .await
        .map_err(|_| WebError::IdentityUnavailable)?;
    let mut user = envelope.user.ok_or(WebError::Unauthorized)?;
    user.skip_2fa_setup = envelope.skip_2fa_setup;
    Ok(user)
}

fn enforce_two_factor(identity: &IdentityUser) -> Result<(), WebError> {
    if identity.two_factor_enabled || identity.skip_2fa_setup {
        Ok(())
    } else {
        Err(WebError::TwoFactorRequired)
    }
}

fn canonical_cookie(headers: &HeaderMap) -> Result<HeaderValue, WebError> {
    let token = session_cookie(headers).ok_or(WebError::Unauthorized)?;
    HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={token}"))
        .map_err(|_| WebError::Unauthorized)
}

async fn organizations(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<OrganizationRow>, WebError> {
    let client = OrganizationServiceClient::new(
        SessionCookieTransport {
            http: state.http.clone(),
            cookie,
        },
        ClientConfig::new(state.api_origin.clone()).with_default_timeout(Duration::from_secs(10)),
    );
    let response = client
        .list_organizations(ListOrganizationsRequest::default())
        .await
        .map_err(WebError::Connect)?
        .into_owned();

    Ok(response
        .organizations
        .into_iter()
        .filter_map(|membership| {
            let organization = membership.organization.into_option()?;
            Some(OrganizationRow {
                name: organization.name,
                slug: organization.slug.clone(),
                role: role_name(membership.role.to_i32()),
                billing_plan: membership.billing_plan,
                legacy_url: format!(
                    "{}/dashboard/orgs/{}",
                    state.legacy_origin, organization.slug
                ),
            })
        })
        .collect())
}

async fn github_status(state: &AppState, cookie: HeaderValue) -> Result<bool, WebError> {
    let client = GitHubServiceClient::new(
        SessionCookieTransport {
            http: state.http.clone(),
            cookie,
        },
        ClientConfig::new(state.api_origin.clone()).with_default_timeout(Duration::from_secs(10)),
    );
    Ok(client
        .get_git_hub_status(GetGitHubStatusRequest::default())
        .await
        .map_err(WebError::Connect)?
        .into_owned()
        .connected)
}

fn role_name(value: i32) -> &'static str {
    match value {
        1 => "Owner",
        2 => "Admin",
        3 => "Member",
        _ => "Member",
    }
}

#[derive(Clone)]
struct SessionCookieTransport {
    http: reqwest::Client,
    cookie: HeaderValue,
}

impl ClientTransport for SessionCookieTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<connectrpc::client::ClientBody>,
    ) -> BoxFuture<'static, Result<HttpResponse<Self::ResponseBody>, Self::Error>> {
        let client = self.http.clone();
        let cookie = self.cookie.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            parts.headers = session_cookie_headers(parts.headers, cookie);
            let body = reqwest::Body::wrap_stream(body.into_data_stream());
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|error| {
                    ConnectError::unavailable(format!("send dashboard request: {error}"))
                })?;
            Ok(HttpResponse::<reqwest::Body>::from(response))
        })
    }
}

fn session_cookie_headers(mut headers: HeaderMap, cookie: HeaderValue) -> HeaderMap {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
    headers.insert(header::COOKIE, cookie);
    headers
}

#[derive(Debug)]
enum WebError {
    Unauthorized,
    TwoFactorRequired,
    IdentityUnavailable,
    Connect(ConnectError),
}

fn render_page(template: impl Template) -> Response {
    match template.render() {
        Ok(body) => html_response(StatusCode::OK, body),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The dashboard could not be rendered.",
        ),
    }
}

fn error_page(error: WebError) -> Response {
    let (status, message) = match error {
        WebError::Unauthorized => (StatusCode::UNAUTHORIZED, "Sign in is required."),
        WebError::TwoFactorRequired => (
            StatusCode::FORBIDDEN,
            "Two-factor setup is required before opening the dashboard.",
        ),
        WebError::Connect(error) if error.code == ErrorCode::Unauthenticated => {
            (StatusCode::UNAUTHORIZED, "Sign in is required.")
        }
        WebError::IdentityUnavailable => (
            StatusCode::BAD_GATEWAY,
            "The identity service is temporarily unavailable.",
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
        Ok(body) => html_response(status, body),
        Err(_) => (status, "Dashboard error").into_response(),
    }
}

fn login_redirect(legacy_origin: &str, headers: &HeaderMap) -> Response {
    redirect(
        format!("{legacy_origin}/login?return_to=%2Fdashboard"),
        headers,
    )
}

fn two_factor_redirect(legacy_origin: &str, headers: &HeaderMap) -> Response {
    redirect(format!("{legacy_origin}/setup-2fa"), headers)
}

fn redirect(location: String, headers: &HeaderMap) -> Response {
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

fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE.as_str(), "text/html; charset=utf-8"),
            (header::CACHE_CONTROL.as_str(), "private, no-store"),
            (
                header::CONTENT_SECURITY_POLICY.as_str(),
                CONTENT_SECURITY_POLICY,
            ),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
            (header::REFERRER_POLICY.as_str(), "same-origin"),
        ],
        body,
    )
        .into_response()
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE.as_str(), content_type),
            (
                header::CACHE_CONTROL.as_str(),
                "public, max-age=31536000, immutable",
            ),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
        ],
        body,
    )
        .into_response()
}

async fn htmx_asset() -> Response {
    static_response("application/javascript; charset=utf-8", HTMX)
}

async fn stylesheet() -> Response {
    static_response("text/css; charset=utf-8", STYLES)
}

async fn dashboard_script() -> Response {
    static_response("application/javascript; charset=utf-8", DASHBOARD_SCRIPT)
}

async fn logo_asset() -> Response {
    static_response("image/svg+xml", LOGO)
}

#[derive(Debug)]
struct DashboardView {
    user_name: String,
    is_admin: bool,
    organizations: Vec<OrganizationRow>,
    has_organizations: bool,
    github_connected: bool,
    github_available: bool,
    show_checklist: bool,
    new_organization_url: String,
    legacy_settings_url: String,
    legacy_admin_url: String,
    legacy_home_url: String,
    github_connect_url: String,
}

#[derive(Debug)]
struct OrganizationRow {
    name: String,
    slug: String,
    role: &'static str,
    billing_plan: String,
    legacy_url: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    view: &'a DashboardView,
    organizations: &'a [OrganizationRow],
    has_organizations: bool,
}

#[derive(Template)]
#[template(path = "organization-list.html")]
struct OrganizationListTemplate<'a> {
    organizations: &'a [OrganizationRow],
    has_organizations: bool,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    message: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_require_clean_http_origins() {
        assert!(parse_origin("origin", "https://example.test".into()).is_ok());
        assert!(parse_origin("origin", "https://example.test/path".into()).is_err());
        assert!(parse_origin("origin", "https://example.test/?q=1".into()).is_err());
        assert!(parse_origin("origin", "file:///tmp/dashboard".into()).is_err());
    }

    #[test]
    fn organization_template_escapes_upstream_data() {
        let organizations = vec![OrganizationRow {
            name: "<unsafe>".into(),
            slug: "safe".into(),
            role: "Owner",
            billing_plan: "trial".into(),
            legacy_url: "https://example.test/dashboard/orgs/safe".into(),
        }];
        let body = OrganizationListTemplate {
            organizations: &organizations,
            has_organizations: true,
        }
        .render()
        .expect("render organization fragment");
        assert!(body.contains("&lt;unsafe&gt;") || body.contains("&#60;unsafe&#62;"));
        assert!(!body.contains("<unsafe>"));
    }

    #[test]
    fn transport_forwards_only_the_canonical_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer never-forward"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("unrelated=discard"),
        );
        let headers = session_cookie_headers(
            headers,
            HeaderValue::from_static("codewire.session_token=expected"),
        );
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert_eq!(
            headers.get(header::COOKIE).unwrap(),
            "codewire.session_token=expected"
        );
    }

    #[test]
    fn htmx_auth_redirect_uses_response_header() {
        let mut headers = HeaderMap::new();
        headers.insert(HTMX_REQUEST, HeaderValue::from_static("true"));
        let response = login_redirect("http://127.0.0.1:5173", &headers);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(HTMX_REDIRECT).unwrap(),
            "http://127.0.0.1:5173/login?return_to=%2Fdashboard"
        );
    }

    #[test]
    fn page_auth_redirect_uses_see_other() {
        let response = login_redirect("http://127.0.0.1:5173", &HeaderMap::new());
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "http://127.0.0.1:5173/login?return_to=%2Fdashboard"
        );
    }

    #[test]
    fn two_factor_gate_preserves_the_identity_opt_out() {
        let mut user = IdentityUser {
            email: "user@example.test".into(),
            name: None,
            is_admin: false,
            two_factor_enabled: false,
            skip_2fa_setup: false,
        };
        assert!(matches!(
            enforce_two_factor(&user),
            Err(WebError::TwoFactorRequired)
        ));
        user.skip_2fa_setup = true;
        assert!(enforce_two_factor(&user).is_ok());
    }
}
