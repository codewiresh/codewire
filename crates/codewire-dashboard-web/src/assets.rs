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
pub(crate) const AUTH_STYLE_PATH: &str = "/assets/codewire/routes/auth-v2.css";
pub(crate) const PUBLIC_STYLE_PATH: &str = "/assets/codewire/routes/public-v1.css";
pub(crate) const COSMOS_STYLE_PATH: &str = "/assets/codewire/cosmos-v1.css";
pub(crate) const COSMOS_SCRIPT_PATH: &str = "/assets/codewire/cosmos-v1.js";
pub(crate) const DEVICE_SCRIPT_PATH: &str = "/assets/codewire/device-v1.js";
pub(crate) const SETTINGS_STYLE_PATH: &str = "/assets/codewire/routes/settings-v1.css";
pub(crate) const ORGANIZATIONS_STYLE_PATH: &str = "/assets/codewire/routes/organizations-v1.css";
pub(crate) const SECRET_MANAGEMENT_STYLE_PATH: &str =
    "/assets/codewire/routes/secret-management-v1.css";
pub(crate) const ENVIRONMENTS_STYLE_PATH: &str = "/assets/codewire/routes/environments-v2.css";
pub(crate) const TERMINAL_STYLE_PATH: &str = "/assets/codewire/routes/terminal-v2.css";
pub(crate) const BILLING_ADMIN_STYLE_PATH: &str = "/assets/codewire/routes/billing-admin-v1.css";
pub(crate) const XTERM_STYLE_PATH: &str = "/assets/codewire/xterm-6.0.0.css";
pub(crate) const SCRIPT_PATH: &str = "/assets/codewire/dashboard-v1.js";
pub(crate) const PUBLIC_SCRIPT_PATH: &str = "/assets/codewire/public-v1.js";
pub(crate) const ORGANIZATIONS_SCRIPT_PATH: &str = "/assets/codewire/organizations-v1.js";
pub(crate) const ENVIRONMENTS_SCRIPT_PATH: &str = "/assets/codewire/environments-v2.js";
pub(crate) const TERMINAL_SCRIPT_PATH: &str = "/assets/codewire/terminal-v1.js";
pub(crate) const DURABLE_TERMINAL_SCRIPT_PATH: &str = "/assets/codewire/durable-terminal-v2.js";
pub(crate) const TERMINAL_PROTOCOL_SCRIPT_PATH: &str = "/assets/codewire/terminal-protocol-v1.js";
pub(crate) const TERMINAL_READINESS_SCRIPT_PATH: &str = "/assets/codewire/terminal-readiness-v3.js";
pub(crate) const SETUP_PROGRESS_SCRIPT_PATH: &str = "/assets/codewire/setup-progress-v1.js";
pub(crate) const SANDBOX_RESIZE_SCRIPT_PATH: &str = "/assets/codewire/sandbox-resize-v3.js";
pub(crate) const TERMINAL_RENDERER_SCRIPT_PATH: &str = "/assets/codewire/terminal-renderer-v1.js";
pub(crate) const TERMINAL_PRESENTATION_SCRIPT_PATH: &str =
    "/assets/codewire/terminal-presentation-v2.js";
pub(crate) const XTERM_SCRIPT_PATH: &str = "/assets/codewire/xterm-6.0.0.js";
pub(crate) const XTERM_FIT_SCRIPT_PATH: &str = "/assets/codewire/addon-fit-0.11.0.js";
pub(crate) const XTERM_WEB_LINKS_SCRIPT_PATH: &str = "/assets/codewire/addon-web-links-0.12.0.js";
pub(crate) const LOGO_PATH: &str = "/assets/codewire/logo-v1.svg";
pub(crate) const BRAND_WORDMARK_PATH: &str = "/assets/codewire/brand-wordmark-v1.svg";
pub(crate) const BRAND_ICON_PATH: &str = "/assets/codewire/brand-icon-v1.svg";
pub(crate) const CONSOLE_LOGO_PATH: &str = "/assets/codewire/console-logo-v1.svg";
pub(crate) const ICONS_PATH: &str = "/assets/codewire/icons-v2.svg";
pub(crate) const SPACE_GROTESK_PATH: &str = "/assets/codewire/fonts/space-grotesk-2.0.woff2";
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
const COSMOS_STYLES: &str = include_str!("../../../packages/codewire-design/cosmos.css");
const COSMOS_SCRIPT: &str = include_str!("../../../packages/codewire-design/cosmos.js");
const DEVICE_SCRIPT: &str = include_str!("../../../packages/codewire-design/device.js");
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
const DASHBOARD_SCRIPT: &str = concat!(
    include_str!("../../../packages/codewire-design/dashboard.js"),
    "\n",
    include_str!("../../../packages/codewire-design/preview-ports.js"),
);
const PUBLIC_SCRIPT: &str = include_str!("../../../packages/codewire-design/public.js");
const ORGANIZATIONS_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/organizations.js");
const ENVIRONMENTS_SCRIPT: &str = include_str!("../../../packages/codewire-design/environments.js");
const TERMINAL_SCRIPT: &str = include_str!("../../../packages/codewire-design/terminal.js");
const DURABLE_TERMINAL_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/durable-terminal.js");
const TERMINAL_PROTOCOL_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/terminal-protocol.js");
const TERMINAL_READINESS_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/terminal-readiness.js");
const SETUP_PROGRESS_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/setup-progress.js");
const SANDBOX_RESIZE_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/sandbox-resize.js");
const TERMINAL_RENDERER_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/terminal-renderer.js");
const TERMINAL_PRESENTATION_SCRIPT: &str =
    include_str!("../../../packages/codewire-design/terminal-presentation.js");
const XTERM_SCRIPT: &str = include_str!("../assets/xterm/xterm-6.0.0.js");
const XTERM_FIT_SCRIPT: &str = include_str!("../assets/xterm/addon-fit-0.11.0.js");
const XTERM_WEB_LINKS_SCRIPT: &str = include_str!("../assets/xterm/addon-web-links-0.12.0.js");
const LOGO: &str = include_str!("../../../packages/codewire-design/assets/logo.svg");
const BRAND_WORDMARK: &str =
    include_str!("../../../packages/codewire-design/assets/brand-wordmark.svg");
const BRAND_ICON: &str = include_str!("../../../packages/codewire-design/assets/brand-icon.svg");
const CONSOLE_LOGO: &str =
    include_str!("../../../packages/codewire-design/assets/console-logo.svg");
const ICONS: &str = include_str!("../../../packages/codewire-design/assets/icons.svg");
const SPACE_GROTESK: &[u8] =
    include_bytes!("../../../packages/codewire-design/fonts/space-grotesk-2.0.woff2");
const IBM_PLEX_MONO_REGULAR: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-Regular-2.5.0.woff2");
const IBM_PLEX_MONO_MEDIUM: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-Medium-2.5.0.woff2");
const IBM_PLEX_MONO_SEMIBOLD: &[u8] =
    include_bytes!("../assets/fonts/IBMPlexMono-SemiBold-2.5.0.woff2");

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            SPACE_GROTESK_PATH,
            static_binary_asset("font/woff2", SPACE_GROTESK),
        )
        .route(
            HTMX_PATH,
            static_asset("application/javascript; charset=utf-8", HTMX),
        )
        .route(STYLE_PATH, static_asset("text/css; charset=utf-8", STYLES))
        .route(
            COSMOS_STYLE_PATH,
            static_asset("text/css; charset=utf-8", COSMOS_STYLES),
        )
        .route(
            COSMOS_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", COSMOS_SCRIPT),
        )
        .route(
            DEVICE_SCRIPT_PATH,
            static_asset("application/javascript; charset=utf-8", DEVICE_SCRIPT),
        )
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
            DURABLE_TERMINAL_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                DURABLE_TERMINAL_SCRIPT,
            ),
        )
        .route(
            TERMINAL_PROTOCOL_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                TERMINAL_PROTOCOL_SCRIPT,
            ),
        )
        .route(
            SANDBOX_RESIZE_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                SANDBOX_RESIZE_SCRIPT,
            ),
        )
        .route(
            TERMINAL_READINESS_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                TERMINAL_READINESS_SCRIPT,
            ),
        )
        .route(
            SETUP_PROGRESS_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                SETUP_PROGRESS_SCRIPT,
            ),
        )
        .route(
            TERMINAL_RENDERER_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                TERMINAL_RENDERER_SCRIPT,
            ),
        )
        .route(
            TERMINAL_PRESENTATION_SCRIPT_PATH,
            static_asset(
                "application/javascript; charset=utf-8",
                TERMINAL_PRESENTATION_SCRIPT,
            ),
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
            BRAND_WORDMARK_PATH,
            static_asset("image/svg+xml", BRAND_WORDMARK),
        )
        .route(BRAND_ICON_PATH, static_asset("image/svg+xml", BRAND_ICON))
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
    fn homepage_fixtures_and_docs_share_production_assets() {
        use askama::Template;

        let html = crate::templates::HomeTemplate.render().unwrap();
        for (fixture, prefix) in [
            (
                include_str!("../../../packages/codewire-design/reference/fixtures/home.html"),
                "../../",
            ),
            (
                include_str!("../../../docs/design/story.html"),
                "../../packages/codewire-design/",
            ),
        ] {
            let mut normalized = fixture.to_owned();
            for (local, public) in [
                ("cosmos.css", COSMOS_STYLE_PATH),
                ("cosmos.js", COSMOS_SCRIPT_PATH),
                ("routes/public.css", PUBLIC_STYLE_PATH),
                ("public.js", PUBLIC_SCRIPT_PATH),
                ("assets/brand-icon.svg", BRAND_ICON_PATH),
                ("assets/brand-wordmark.svg", BRAND_WORDMARK_PATH),
            ] {
                normalized = normalized.replace(&format!("{prefix}{local}"), public);
            }
            assert_eq!(
                normalized.trim_end(),
                html,
                "homepage fixture drifted from production"
            );
        }
        assert_eq!(
            BRAND_WORDMARK,
            include_str!("../../../apps/docs/zola/static/codewire-wordmark.svg")
        );
        assert_eq!(
            BRAND_ICON,
            include_str!("../../../apps/docs/zola/static/favicon.svg")
        );
    }

    #[test]
    fn device_template_and_fixture_share_the_slot_contract() {
        let production = include_str!("../templates/device.html");
        let fixture =
            include_str!("../../../packages/codewire-design/reference/fixtures/device.html");
        for html in [production, fixture] {
            assert_eq!(html.matches("name=\"user_code_").count(), 8);
            assert_eq!(html.matches("Character ").count(), 8);
            assert!(html.contains("data-device-code-slots"));
            assert!(html.contains("cw-device-code-separator\" aria-hidden=\"true\">-"));
            assert!(!html.contains("name=\"user_code\""));
        }
        assert!(production.contains(DEVICE_SCRIPT_PATH));
        // Old auth-v1.css has no slot grid. A fresh URL keeps warm browser/CDN
        // caches from pairing those pre-eight-input bytes with new markup.
        assert_eq!(AUTH_STYLE_PATH, "/assets/codewire/routes/auth-v2.css");
        assert!(production.contains(AUTH_STYLE_PATH));
        for template in [
            production,
            include_str!("../templates/auth-form.html"),
            include_str!("../templates/auth-status.html"),
            include_str!("../templates/invitation.html"),
            include_str!("../templates/setup-two-factor.html"),
            include_str!("../templates/two-factor-recovery.html"),
        ] {
            assert!(template.contains(AUTH_STYLE_PATH));
            assert!(!template.contains("/assets/codewire/routes/auth-v1.css"));
        }
        assert!(fixture.contains("../../device.js"));
    }

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
        assert_eq!(DEVICE_SCRIPT_PATH, "/assets/codewire/device-v1.js");
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
    fn codex_provider_mark_matches_download_and_both_credential_surfaces() {
        let original = include_str!("../../../packages/codewire-design/assets/codex.svg");
        let path = original
            .split("<path ")
            .nth(1)
            .unwrap()
            .split("</path>")
            .next()
            .unwrap();
        let symbol = ICONS
            .split("id=\"icon-codex\"")
            .nth(1)
            .unwrap()
            .split("</symbol>")
            .next()
            .unwrap();
        assert!(symbol.contains(path));
        assert!(symbol.contains("viewBox=\"0 0 24 24\""));
        assert!(symbol.contains("fill=\"currentColor\""));
        assert!(symbol.contains("stroke=\"none\""));
        assert!(symbol.contains("fill-rule=\"evenodd\""));
        for html in [
            include_str!("../templates/settings-credentials.html"),
            include_str!(
                "../../../packages/codewire-design/reference/fixtures/settings-credentials.html"
            ),
        ] {
            // Inventory and provider chooser, retaining their adjacent text labels.
            assert_eq!(html.matches("#icon-codex").count(), 2);
            assert!(html.contains("aria-hidden=\"true\"><use href="));
            assert!(html.contains("id=\"connect-codex-choice-name\">Codex</strong>"));
        }
    }

    #[test]
    fn preview_copy_is_in_the_shared_asset_loaded_by_both_ports_hosts() {
        let controller = include_str!("../../../packages/codewire-design/preview-ports.js");
        assert!(DASHBOARD_SCRIPT.contains(controller));
        assert!(!ENVIRONMENTS_SCRIPT.contains("data-copy-preview"));
        for html in [
            include_str!("../templates/terminal.html"),
            include_str!("../templates/organization-environments.html"),
        ] {
            assert!(html.contains(SCRIPT_PATH));
        }
        assert!(include_str!("../templates/environment-ports.html").contains("data-copy-preview"));
        assert!(
            include_str!("../../../packages/codewire-design/reference/fixtures/terminal.html")
                .contains("../../preview-ports.js")
        );
    }

    #[test]
    fn manual_repository_entry_preserves_its_mount_contract() {
        assert!(ENVIRONMENTS_STYLES.contains(".cw-manual-repositories"));
        assert!(ENVIRONMENTS_STYLES.contains(".cw-repository-row"));
        assert!(ENVIRONMENTS_STYLES.contains(".cw-workspace-mount"));
        assert!(!ENVIRONMENTS_STYLES.contains(".cw-repository-picker"));
        assert!(!ENVIRONMENTS_STYLES.contains(".cw-github-banner"));
    }

    #[test]
    fn field_rows_put_their_action_on_the_control_line_in_templates_and_fixtures() {
        assert!(STYLES.contains(
            ".cw-field-row > .cw-field { grid-row: span 2; grid-template-rows: subgrid; }"
        ));
        for html in [
            include_str!("../templates/environment-create-form.html"),
            include_str!(
                "../../../packages/codewire-design/reference/fixtures/create-sandbox.html"
            ),
        ] {
            assert!(html.contains("class=\"cw-field-row cw-repository-row\" data-repository-row"));
            assert!(html.contains("class=\"cw-field-row cw-app-port-row\" data-app-port-row"));
            assert!(!html.contains("class=\"cw-repository-row\""));
            assert!(!html.contains("class=\"cw-app-port-row\""));
        }
        for html in [
            include_str!("../templates/environment-ports.html"),
            include_str!(
                "../../../packages/codewire-design/reference/fixtures/terminal-ports.html"
            ),
        ] {
            assert!(html.contains("<form class=\"cw-field-row cw-port-form\""));
        }
    }

    #[test]
    fn durable_terminal_template_and_fixture_share_controls_and_presentation() {
        let production = include_str!("../templates/terminal.html");
        let fixture =
            include_str!("../../../packages/codewire-design/reference/fixtures/terminal-tabs.html");
        for html in [production, fixture] {
            for marker in [
                "data-durable-terminal-page",
                "data-terminal-readiness",
                "data-terminal-new",
                "data-terminal-existing-form",
                "data-terminal-tabs",
                "data-terminal-panels",
                "data-terminal-history-gap",
                "data-terminal-close-dialog",
                "id=\"sandbox-resize-setup-note\" data-resize-setup-note",
                "Resize is available when setup finishes.",
            ] {
                assert!(html.contains(marker), "missing {marker}");
            }
            assert!(html.contains("role=\"tablist\" aria-label=\"Terminal tabs\""));
            assert!(html.contains("role=\"tabpanel\""));
            assert!(
                html.contains("Leaving this page disconnects the browser; the shell keeps running")
            );
        }
        // One tab's tab, output panel, status-bar group and menu actions. The
        // fixture reads the same icon sprite from its source path.
        let tab_parts = |html: &'static str| {
            html.split("<template data-terminal-tab-template>")
                .nth(1)
                .unwrap()
                .split("</template>")
                .next()
                .unwrap()
                .replace("../../assets/icons.svg", ICONS_PATH)
        };
        assert_eq!(tab_parts(production), tab_parts(fixture));
        for marker in [
            "data-terminal-tab-item",
            "role=\"tab\"",
            "data-terminal-close-session",
            "data-terminal-remove-tab",
            "data-terminal-session-status",
            "data-terminal-connection role=\"status\"",
            "data-terminal-tab-action-group",
        ] {
            assert!(tab_parts(production).contains(marker), "missing {marker}");
        }
        for html in [production, fixture] {
            for marker in [
                "data-terminal-statuses",
                "data-terminal-tab-actions",
                "data-terminal-menu",
                "data-sandbox-menu",
                "data-terminal-readiness-refresh",
                "data-sandbox-last-event",
                "data-sandbox-lifetime",
            ] {
                assert!(html.contains(marker), "missing {marker}");
            }
        }
        for path in [
            TERMINAL_PROTOCOL_SCRIPT_PATH,
            DURABLE_TERMINAL_SCRIPT_PATH,
            TERMINAL_READINESS_SCRIPT_PATH,
        ] {
            assert!(production.contains(path));
        }
        assert!(
            production.find(TERMINAL_PROTOCOL_SCRIPT_PATH)
                < production.find(DURABLE_TERMINAL_SCRIPT_PATH)
        );
        assert!(
            production.find(DURABLE_TERMINAL_SCRIPT_PATH)
                < production.find(TERMINAL_READINESS_SCRIPT_PATH)
        );
    }
}
