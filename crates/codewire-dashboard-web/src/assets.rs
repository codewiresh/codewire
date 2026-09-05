use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get},
};

use crate::state::AppState;

pub(crate) const HTMX_PATH: &str = "/assets/codewire/htmx-2.0.10.min.js";
pub(crate) const STYLE_PATH: &str = "/assets/codewire/design-v1.css";
pub(crate) const DASHBOARD_STYLE_PATH: &str = "/assets/codewire/routes/dashboard-v1.css";
pub(crate) const AUTH_STYLE_PATH: &str = "/assets/codewire/routes/auth-v1.css";
pub(crate) const PUBLIC_STYLE_PATH: &str = "/assets/codewire/routes/public-v1.css";
pub(crate) const SETTINGS_STYLE_PATH: &str = "/assets/codewire/routes/settings-v1.css";
pub(crate) const ORGANIZATIONS_STYLE_PATH: &str = "/assets/codewire/routes/organizations-v1.css";
pub(crate) const SECRET_MANAGEMENT_STYLE_PATH: &str =
    "/assets/codewire/routes/secret-management-v1.css";
pub(crate) const ENVIRONMENTS_STYLE_PATH: &str = "/assets/codewire/routes/environments-v2.css";
pub(crate) const TERMINAL_STYLE_PATH: &str = "/assets/codewire/routes/terminal-v1.css";
pub(crate) const BILLING_ADMIN_STYLE_PATH: &str = "/assets/codewire/routes/billing-admin-v1.css";
pub(crate) const XTERM_STYLE_PATH: &str = "/assets/codewire/xterm-6.0.0.css";
pub(crate) const SCRIPT_PATH: &str = "/assets/codewire/dashboard-v1.js";
pub(crate) const PUBLIC_SCRIPT_PATH: &str = "/assets/codewire/public-v1.js";
pub(crate) const ORGANIZATIONS_SCRIPT_PATH: &str = "/assets/codewire/organizations-v1.js";
pub(crate) const ENVIRONMENTS_SCRIPT_PATH: &str = "/assets/codewire/environments-v2.js";
pub(crate) const TERMINAL_SCRIPT_PATH: &str = "/assets/codewire/terminal-v1.js";
pub(crate) const XTERM_SCRIPT_PATH: &str = "/assets/codewire/xterm-6.0.0.js";
pub(crate) const XTERM_FIT_SCRIPT_PATH: &str = "/assets/codewire/addon-fit-0.11.0.js";
pub(crate) const XTERM_WEB_LINKS_SCRIPT_PATH: &str = "/assets/codewire/addon-web-links-0.12.0.js";
pub(crate) const LOGO_PATH: &str = "/assets/codewire/logo-v1.svg";
pub(crate) const CONSOLE_LOGO_PATH: &str = "/assets/codewire/console-logo-v1.svg";
pub(crate) const ICONS_PATH: &str = "/assets/codewire/icons-v2.svg";
pub(crate) const IBM_PLEX_MONO_REGULAR_PATH: &str =
    "/assets/codewire/fonts/ibm-plex-mono-regular-2.5.0.woff2";
pub(crate) const IBM_PLEX_MONO_MEDIUM_PATH: &str =
    "/assets/codewire/fonts/ibm-plex-mono-medium-2.5.0.woff2";
pub(crate) const IBM_PLEX_MONO_SEMIBOLD_PATH: &str =
    "/assets/codewire/fonts/ibm-plex-mono-semibold-2.5.0.woff2";

const HTMX: &str = include_str!("../assets/htmx-2.0.10.min.js");
const STYLES: &str = concat!(
    include_str!("../../../packages/codewire-design/styles.css"),
    "\n",
    include_str!("../../../packages/codewire-design/components.css"),
);
const DASHBOARD_STYLES: &str =
    include_str!("../../../packages/codewire-design/routes/dashboard.css");
const AUTH_STYLES: &str = include_str!("../../../packages/codewire-design/routes/auth.css");
const PUBLIC_STYLES: &str = include_str!("../../../packages/codewire-design/routes/public.css");
const SETTINGS_STYLES: &str = include_str!("../../../packages/codewire-design/routes/settings.css");
const ORGANIZATIONS_STYLES: &str =
    include_str!("../../../packages/codewire-design/routes/organizations.css");
const SECRET_MANAGEMENT_STYLES: &str =
    include_str!("../../../packages/codewire-design/routes/secret-management.css");
const ENVIRONMENTS_STYLES: &str =
    include_str!("../../../packages/codewire-design/routes/environments.css");
const TERMINAL_STYLES: &str = include_str!("../../../packages/codewire-design/routes/terminal.css");
const BILLING_ADMIN_STYLES: &str =
    include_str!("../../../packages/codewire-design/routes/billing-admin.css");
const XTERM_STYLES: &str = include_str!("../assets/xterm/xterm-6.0.0.css");
const DASHBOARD_SCRIPT: &str = include_str!("../../../packages/codewire-design/dashboard.js");
const PUBLIC_SCRIPT: &str = include_str!("../../../packages/codewire-design/public.js");
const ORGANIZATIONS_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/organizations.js");
const ENVIRONMENTS_SCRIPT: &str = include_str!("../../../packages/codewire-design/environments.js");
const TERMINAL_SCRIPT: &str = include_str!("../../../packages/codewire-design/terminal.js");
const XTERM_SCRIPT: &str = include_str!("../assets/xterm/xterm-6.0.0.js");
const XTERM_FIT_SCRIPT: &str = include_str!("../assets/xterm/addon-fit-0.11.0.js");
const XTERM_WEB_LINKS_SCRIPT: &str = include_str!("../assets/xterm/addon-web-links-0.12.0.js");
const LOGO: &str = include_str!("../../../packages/codewire-design/assets/logo.svg");
const CONSOLE_LOGO: &str =
    include_str!("../../../packages/codewire-design/assets/console-logo.svg");
const ICONS: &str = include_str!("../../../packages/codewire-design/assets/icons.svg");
const IBM_PLEX_MONO_REGULAR: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-Regular-2.5.0.woff2");
const IBM_PLEX_MONO_MEDIUM: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-Medium-2.5.0.woff2");
const IBM_PLEX_MONO_SEMIBOLD: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-SemiBold-2.5.0.woff2");

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            HTMX_PATH,
            static_asset("application/javascript; charset=utf-8", HTMX),
        )
        .route(STYLE_PATH, static_asset("text/css; charset=utf-8", STYLES))
        .route(
            DASHBOARD_STYLE_PATH,
            static_asset("text/css; charset=utf-8", DASHBOARD_STYLES),
        )
        .route(
            AUTH_STYLE_PATH,
            static_asset("text/css; charset=utf-8", AUTH_STYLES),
        )
        .route(
            PUBLIC_STYLE_PATH,
            static_asset("text/css; charset=utf-8", PUBLIC_STYLES),
        )
        .route(
            SETTINGS_STYLE_PATH,
            static_asset("text/css; charset=utf-8", SETTINGS_STYLES),
        )
        .route(
            ORGANIZATIONS_STYLE_PATH,
            static_asset("text/css; charset=utf-8", ORGANIZATIONS_STYLES),
        )
        .route(
            SECRET_MANAGEMENT_STYLE_PATH,
            static_asset("text/css; charset=utf-8", SECRET_MANAGEMENT_STYLES),
        )
        .route(
            ENVIRONMENTS_STYLE_PATH,
            static_asset("text/css; charset=utf-8", ENVIRONMENTS_STYLES),
        )
        .route(
            TERMINAL_STYLE_PATH,
            static_asset("text/css; charset=utf-8", TERMINAL_STYLES),
        )
        .route(
            BILLING_ADMIN_STYLE_PATH,
            static_asset("text/css; charset=utf-8", BILLING_ADMIN_STYLES),
        )
        .route(
            XTERM_STYLE_PATH,
            static_asset("text/css; charset=utf-8", XTERM_STYLES),
        )
        .route(
            SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", DASHBOARD_SCRIPT),
        )
        .route(
            PUBLIC_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", PUBLIC_SCRIPT),
        )
        .route(
            ORGANIZATIONS_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                ORGANIZATIONS_SCRIPT,
            ),
        )
        .route(
            ENVIRONMENTS_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", ENVIRONMENTS_SCRIPT),
        )
        .route(
            TERMINAL_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", TERMINAL_SCRIPT),
        )
        .route(
            XTERM_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", XTERM_SCRIPT),
        )
        .route(
            XTERM_FIT_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", XTERM_FIT_SCRIPT),
        )
        .route(
            XTERM_WEB_LINKS_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                XTERM_WEB_LINKS_SCRIPT,
            ),
        )
        .route(LOGO_PATH, static_asset("image/svg+xml", LOGO))
        .route(
            CONSOLE_LOGO_PATH,
            static_asset("image/svg+xml", CONSOLE_LOGO),
        )
        .route(ICONS_PATH, static_asset("image/svg+xml", ICONS))
        .route(
            IBM_PLEX_MONO_REGULAR_PATH,
            static_binary_asset("font/woff2", IBM_PLEX_MONO_REGULAR),
        )
        .route(
            IBM_PLEX_MONO_MEDIUM_PATH,
            static_binary_asset("font/woff2", IBM_PLEX_MONO_MEDIUM),
        )
        .route(
            IBM_PLEX_MONO_SEMIBOLD_PATH,
            static_binary_asset("font/woff2", IBM_PLEX_MONO_SEMIBOLD),
        )
}

fn static_asset(content_type: &'static str, body: &'static str) -> MethodRouter<AppState> {
    get(move |headers: HeaderMap| async move { static_response(&headers, content_type, body) })
}

fn static_binary_asset(content_type: &'static str, body: &'static [u8]) -> MethodRouter<AppState> {
    get(
        move |headers: HeaderMap| async move { static_binary_response(&headers, content_type, body) },
    )
}

fn content_etag(body: &[u8]) -> String {
    // This is a cache validator, not a security digest. Including the length
    // and a deterministic content hash makes an embedded asset change its
    // validator automatically without another build dependency or manifest.
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    format!("\"{:x}-{:016x}\"", body.len(), hasher.finish())
}

fn static_response(
    headers: &HeaderMap,
    content_type: &'static str,
    body: &'static str,
) -> Response {
    static_binary_response(headers, content_type, body.as_bytes())
}

fn static_binary_response(
    headers: &HeaderMap,
    content_type: &'static str,
    body: &'static [u8],
) -> Response {
    let etag = content_etag(body);
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|candidate| matches!(candidate.trim(), "*") || candidate.trim() == etag)
        });
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Response::new(Body::from(body))
    };
    let response_headers = response.headers_mut();
    response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("asset ETag is valid"),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_assets_revalidate_by_content_etag_and_are_nosniff() {
        assert_eq!(
            ENVIRONMENTS_SCRIPT_PATH,
            "/assets/codewire/environments-v2.js"
        );
        assert_eq!(
            ENVIRONMENTS_STYLE_PATH,
            "/assets/codewire/routes/environments-v2.css"
        );
        assert_eq!(ICONS_PATH, "/assets/codewire/icons-v2.svg");
        let response = static_response(&HeaderMap::new(), "text/css; charset=utf-8", "body{}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, no-cache"
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        let etag = response.headers()[header::ETAG].clone();

        let mut conditional = HeaderMap::new();
        conditional.insert(header::IF_NONE_MATCH, etag.clone());
        let unchanged = static_response(&conditional, "text/css; charset=utf-8", "body{}");
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(unchanged.headers()[header::ETAG], etag);

        let changed = static_response(&conditional, "text/css; charset=utf-8", "body{color:red}");
        assert_eq!(changed.status(), StatusCode::OK);
        assert_ne!(changed.headers()[header::ETAG], etag);
    }

    #[test]
    fn manual_repository_entry_preserves_its_mount_contract() {
        assert!(ENVIRONMENTS_STYLES.contains(".cw-manual-repositories"));
        assert!(ENVIRONMENTS_STYLES.contains(".cw-repository-row"));
        assert!(ENVIRONMENTS_STYLES.contains(".cw-workspace-mount"));
        assert!(!ENVIRONMENTS_STYLES.contains(".cw-repository-picker"));
        assert!(!ENVIRONMENTS_STYLES.contains(".cw-github-banner"));
    }
}
