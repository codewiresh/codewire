use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::LazyLock,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use sha2::{Digest as _, Sha256};

use crate::state::AppState;

pub(crate) const HTMX_PATH: &str = "/assets/codewire/htmx-2.0.10.min.js";
pub(crate) const STYLE_PATH: &str = "/assets/codewire/design-v1.css";
pub(crate) const DASHBOARD_STYLE_PATH: &str = "/assets/codewire/routes/dashboard-v1.css";
pub(crate) const AUTH_STYLE_PATH: &str = "/assets/codewire/routes/auth-v2.css";
pub(crate) const PUBLIC_STYLE_PATH: &str = "/assets/codewire/routes/public-v2.css";
pub(crate) const DEVICE_SCRIPT_PATH: &str = "/assets/codewire/device-v1.js";
pub(crate) const SIGNUP_SCRIPT_PATH: &str = "/assets/codewire/signup-v1.js";
pub(crate) const SETTINGS_STYLE_PATH: &str = "/assets/codewire/routes/settings-v1.css";
pub(crate) const ORGANIZATIONS_STYLE_PATH: &str = "/assets/codewire/routes/organizations-v1.css";
pub(crate) const SECRET_MANAGEMENT_STYLE_PATH: &str =
    "/assets/codewire/routes/secret-management-v1.css";
pub(crate) const ENVIRONMENTS_STYLE_PATH: &str = "/assets/codewire/routes/environments-v2.css";
pub(crate) const TERMINAL_STYLE_PATH: &str = "/assets/codewire/routes/terminal-v2.css";
pub(crate) const BILLING_ADMIN_STYLE_PATH: &str = "/assets/codewire/routes/billing-admin-v1.css";
pub(crate) const OVERVIEW_STYLE_PATH: &str = "/assets/codewire/routes/overview-v1.css";
pub(crate) const XTERM_STYLE_PATH: &str = "/assets/codewire/xterm-6.0.0.css";
pub(crate) const SCRIPT_PATH: &str = "/assets/codewire/dashboard-v1.js";
pub(crate) const PUBLIC_SCRIPT_PATH: &str = "/assets/codewire/public-v2.js";
pub(crate) const PRICING_SCRIPT_PATH: &str = "/assets/codewire/pricing-v1.js";
pub(crate) const THEME_SCRIPT_PATH: &str = "/assets/codewire/theme-v1.js";
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
pub(crate) const SCHIBSTED_GROTESK_LATIN_PATH: &str =
    "/assets/codewire/fonts/schibsted-grotesk-latin-5.3.0.woff2";
pub(crate) const SCHIBSTED_GROTESK_LATIN_EXT_PATH: &str =
    "/assets/codewire/fonts/schibsted-grotesk-latin-ext-5.3.0.woff2";
pub(crate) const GEIST_MONO_PATH: &str = "/assets/codewire/fonts/geist-mono-1.9.0.woff2";

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
const DEVICE_SCRIPT: &str = include_str!("../../../packages/codewire-design/device.js");
const SIGNUP_SCRIPT: &str = include_str!("../../../packages/codewire-design/signup.js");
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
const OVERVIEW_STYLES: &str = include_str!("../../../packages/codewire-design/routes/overview.css");
const XTERM_STYLES: &str = include_str!("../assets/xterm/xterm-6.0.0.css");
const DASHBOARD_SCRIPT: &str = concat!(
    include_str!("../../../packages/codewire-design/dashboard.js"),
    "\n",
    include_str!("../../../packages/codewire-design/preview-ports.js"),
);
const PUBLIC_SCRIPT: &str = include_str!("../../../packages/codewire-design/public.js");
const PRICING_SCRIPT: &str = include_str!("../../../packages/codewire-design/pricing.js");
const THEME_SCRIPT: &str = include_str!("../../../packages/codewire-design/theme.js");
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
const SCHIBSTED_GROTESK_LATIN: &[u8] =
    include_bytes!("../assets/fonts/SchibstedGrotesk-latin-5.3.0.woff2");
const SCHIBSTED_GROTESK_LATIN_EXT: &[u8] =
    include_bytes!("../assets/fonts/SchibstedGrotesk-latin-ext-5.3.0.woff2");
const GEIST_MONO: &[u8] = include_bytes!("../assets/fonts/GeistMono-Variable-1.9.0.woff2");

const JS: &str = "application/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const SVG: &str = "image/svg+xml";
const WOFF2: &str = "font/woff2";

/// Every embedded asset at its stable path. Pages link each one with its
/// content hash (`?h=`), so browsers and the CDN keep those bytes for a year
/// and a deploy refreshes exactly the files that changed.
const ASSETS: &[(&str, &str, &[u8])] = &[
    (SCHIBSTED_GROTESK_LATIN_PATH, WOFF2, SCHIBSTED_GROTESK_LATIN),
    (
        SCHIBSTED_GROTESK_LATIN_EXT_PATH,
        WOFF2,
        SCHIBSTED_GROTESK_LATIN_EXT,
    ),
    (GEIST_MONO_PATH, WOFF2, GEIST_MONO),
    (HTMX_PATH, JS, HTMX.as_bytes()),
    (STYLE_PATH, CSS, STYLES.as_bytes()),
    (DEVICE_SCRIPT_PATH, JS, DEVICE_SCRIPT.as_bytes()),
    (SIGNUP_SCRIPT_PATH, JS, SIGNUP_SCRIPT.as_bytes()),
    (DASHBOARD_STYLE_PATH, CSS, DASHBOARD_STYLES.as_bytes()),
    (AUTH_STYLE_PATH, CSS, AUTH_STYLES.as_bytes()),
    (PUBLIC_STYLE_PATH, CSS, PUBLIC_STYLES.as_bytes()),
    (SETTINGS_STYLE_PATH, CSS, SETTINGS_STYLES.as_bytes()),
    (
        ORGANIZATIONS_STYLE_PATH,
        CSS,
        ORGANIZATIONS_STYLES.as_bytes(),
    ),
    (
        SECRET_MANAGEMENT_STYLE_PATH,
        CSS,
        SECRET_MANAGEMENT_STYLES.as_bytes(),
    ),
    (ENVIRONMENTS_STYLE_PATH, CSS, ENVIRONMENTS_STYLES.as_bytes()),
    (TERMINAL_STYLE_PATH, CSS, TERMINAL_STYLES.as_bytes()),
    (
        BILLING_ADMIN_STYLE_PATH,
        CSS,
        BILLING_ADMIN_STYLES.as_bytes(),
    ),
    (OVERVIEW_STYLE_PATH, CSS, OVERVIEW_STYLES.as_bytes()),
    (XTERM_STYLE_PATH, CSS, XTERM_STYLES.as_bytes()),
    (SCRIPT_PATH, JS, DASHBOARD_SCRIPT.as_bytes()),
    (PUBLIC_SCRIPT_PATH, JS, PUBLIC_SCRIPT.as_bytes()),
    (PRICING_SCRIPT_PATH, JS, PRICING_SCRIPT.as_bytes()),
    (THEME_SCRIPT_PATH, JS, THEME_SCRIPT.as_bytes()),
    (
        ORGANIZATIONS_SCRIPT_PATH,
        JS,
        ORGANIZATIONS_SCRIPT.as_bytes(),
    ),
    (ENVIRONMENTS_SCRIPT_PATH, JS, ENVIRONMENTS_SCRIPT.as_bytes()),
    (TERMINAL_SCRIPT_PATH, JS, TERMINAL_SCRIPT.as_bytes()),
    (
        DURABLE_TERMINAL_SCRIPT_PATH,
        JS,
        DURABLE_TERMINAL_SCRIPT.as_bytes(),
    ),
    (
        TERMINAL_PROTOCOL_SCRIPT_PATH,
        JS,
        TERMINAL_PROTOCOL_SCRIPT.as_bytes(),
    ),
    (
        SANDBOX_RESIZE_SCRIPT_PATH,
        JS,
        SANDBOX_RESIZE_SCRIPT.as_bytes(),
    ),
    (
        TERMINAL_READINESS_SCRIPT_PATH,
        JS,
        TERMINAL_READINESS_SCRIPT.as_bytes(),
    ),
    (
        SETUP_PROGRESS_SCRIPT_PATH,
        JS,
        SETUP_PROGRESS_SCRIPT.as_bytes(),
    ),
    (
        TERMINAL_RENDERER_SCRIPT_PATH,
        JS,
        TERMINAL_RENDERER_SCRIPT.as_bytes(),
    ),
    (
        TERMINAL_PRESENTATION_SCRIPT_PATH,
        JS,
        TERMINAL_PRESENTATION_SCRIPT.as_bytes(),
    ),
    (XTERM_SCRIPT_PATH, JS, XTERM_SCRIPT.as_bytes()),
    (XTERM_FIT_SCRIPT_PATH, JS, XTERM_FIT_SCRIPT.as_bytes()),
    (
        XTERM_WEB_LINKS_SCRIPT_PATH,
        JS,
        XTERM_WEB_LINKS_SCRIPT.as_bytes(),
    ),
    (LOGO_PATH, SVG, LOGO.as_bytes()),
    (BRAND_WORDMARK_PATH, SVG, BRAND_WORDMARK.as_bytes()),
    (BRAND_ICON_PATH, SVG, BRAND_ICON.as_bytes()),
    (CONSOLE_LOGO_PATH, SVG, CONSOLE_LOGO.as_bytes()),
    (ICONS_PATH, SVG, ICONS.as_bytes()),
];

const ASSET_PREFIX: &str = "/assets/codewire/";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

struct ServedAsset {
    content_type: &'static str,
    body: Bytes,
    etag: String,
    version: String,
}

/// The bytes served at each stable path. A stylesheet or script that names
/// another asset names it by its versioned URL. The fonts and icons it can
/// name name nothing themselves, so their raw hashes are already final.
static SERVED: LazyLock<HashMap<&'static str, ServedAsset>> = LazyLock::new(|| {
    let raw: HashMap<&str, String> = ASSETS
        .iter()
        .map(|&(path, _, body)| (path, content_version(body)))
        .collect();
    ASSETS
        .iter()
        .map(|&(path, content_type, body)| {
            let linked = std::str::from_utf8(body)
                .ok()
                .and_then(|text| link(text, |name| raw.get(name).map(String::as_str)));
            let body = linked.map_or(Bytes::from_static(body), Bytes::from);
            let served = ServedAsset {
                content_type,
                etag: content_etag(&body),
                version: content_version(&body),
                body,
            };
            (path, served)
        })
        .collect()
});

pub(crate) fn router() -> Router<AppState> {
    ASSETS.iter().fold(Router::new(), |router, &(path, _, _)| {
        router.route(
            path,
            get(move |headers: HeaderMap, uri: Uri| async move {
                asset_response(&headers, path, uri.query())
            }),
        )
    })
}

/// `html` with each known asset path linked by its content hash, or `None`
/// when it links no asset.
pub(crate) fn versioned(html: &str) -> Option<String> {
    link(html, |name| {
        SERVED.get(name).map(|asset| asset.version.as_str())
    })
}

fn link<'a>(text: &str, version_of: impl Fn(&str) -> Option<&'a str>) -> Option<String> {
    let mut linked = String::new();
    let mut rest = text;
    let mut changed = false;
    while let Some(start) = rest.find(ASSET_PREFIX) {
        let end = rest[start..]
            .find(|c: char| {
                matches!(c, '"' | '\'' | '`' | ')' | '#' | '?' | '<') || c.is_whitespace()
            })
            .map_or(rest.len(), |length| start + length);
        linked.push_str(&rest[..end]);
        if !rest[end..].starts_with('?')
            && let Some(version) = version_of(&rest[start..end])
        {
            linked.push_str("?h=");
            linked.push_str(version);
            changed = true;
        }
        rest = &rest[end..];
    }
    changed.then(|| linked + rest)
}

fn asset_response(headers: &HeaderMap, path: &str, query: Option<&str>) -> Response {
    let asset = &SERVED[path];
    // Only the bytes a URL's hash names may be kept for good. A stale or
    // missing hash, such as a page rendered before a deploy, gets the current
    // bytes revalidated by ETag, so no cache pins the wrong ones.
    let current = query.is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair.strip_prefix("h=") == Some(asset.version.as_str()))
    });
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|candidate| matches!(candidate.trim(), "*") || candidate.trim() == asset.etag)
        });
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Response::new(Body::from(asset.body.clone()))
    };
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if current {
            IMMUTABLE
        } else {
            "public, no-cache"
        }),
    );
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&asset.etag).expect("asset ETag is valid"),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn content_version(body: &[u8]) -> String {
    Sha256::digest(body)[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn content_etag(body: &[u8]) -> String {
    // This is a cache validator, not a security digest. Including the length
    // and a deterministic content hash makes an embedded asset change its
    // validator automatically without another build dependency or manifest.
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    format!("\"{:x}-{:016x}\"", body.len(), hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homepage_fixtures_and_docs_share_production_assets() {
        use askama::Template;

        for (fixture, html) in [
            (
                include_str!("../../../packages/codewire-design/reference/fixtures/home.html"),
                crate::templates::HomeTemplate.render().unwrap(),
            ),
            (
                include_str!("../../../packages/codewire-design/reference/fixtures/pricing.html"),
                crate::templates::PricingTemplate {
                    signup_credit: None,
                }
                .render()
                .unwrap(),
            ),
        ] {
            let prefix = "../../";
            let mut normalized = fixture.to_owned();
            for (local, public) in [
                ("routes/public.css", PUBLIC_STYLE_PATH),
                ("public.js", PUBLIC_SCRIPT_PATH),
                ("pricing.js", PRICING_SCRIPT_PATH),
                ("theme.js", THEME_SCRIPT_PATH),
                ("assets/brand-icon.svg", BRAND_ICON_PATH),
                ("assets/brand-wordmark.svg", BRAND_WORDMARK_PATH),
            ] {
                normalized = normalized.replace(&format!("{prefix}{local}"), public);
            }
            assert_eq!(
                normalized.trim_end(),
                html,
                "public page fixture drifted from production"
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
        assert_eq!(SIGNUP_SCRIPT_PATH, "/assets/codewire/signup-v1.js");
        let signup = include_str!("../templates/auth-form.html");
        assert!(signup.contains(SIGNUP_SCRIPT_PATH));
        assert_eq!(ICONS_PATH, "/assets/codewire/icons-v2.svg");
        let response = asset_response(&HeaderMap::new(), STYLE_PATH, None);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );
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
        let unchanged = asset_response(&conditional, STYLE_PATH, None);
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(unchanged.headers()[header::ETAG], etag);

        assert_ne!(content_etag(b"body{}"), content_etag(b"body{color:red}"));
    }

    #[test]
    fn only_the_current_content_hash_is_cached_for_good() {
        let version = &SERVED[PUBLIC_SCRIPT_PATH].version;
        assert_eq!(version.len(), 16);
        assert_ne!(version, &SERVED[PRICING_SCRIPT_PATH].version);
        for (query, cache_control) in [
            (Some(format!("h={version}")), IMMUTABLE),
            (Some(format!("x=1&h={version}")), IMMUTABLE),
            // A page from before a deploy names the old bytes: serve today's
            // without letting any cache keep them under that URL.
            (Some("h=0123456789abcdef".to_owned()), "public, no-cache"),
            (Some(format!("h={version}0")), "public, no-cache"),
            (None, "public, no-cache"),
        ] {
            let response = asset_response(&HeaderMap::new(), PUBLIC_SCRIPT_PATH, query.as_deref());
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                cache_control,
                "{query:?}"
            );
        }
    }

    #[test]
    fn pages_link_each_asset_by_its_content_hash() {
        use askama::Template;

        let style = &SERVED[STYLE_PATH].version;
        let icons = &SERVED[ICONS_PATH].version;
        assert_eq!(
            versioned(&format!(
                "<link rel=\"stylesheet\" href=\"{STYLE_PATH}\"><svg><use href=\"{ICONS_PATH}#icon-github\"></use></svg>"
            ))
            .unwrap(),
            format!(
                "<link rel=\"stylesheet\" href=\"{STYLE_PATH}?h={style}\"><svg><use href=\"{ICONS_PATH}?h={icons}#icon-github\"></use></svg>"
            )
        );
        // Unknown assets, URLs that already carry a query, and pages without
        // assets are left alone.
        assert_eq!(
            versioned("<a href=\"/assets/codewire/unknown.css\">x</a>"),
            None
        );
        assert_eq!(
            versioned(&format!("<link href=\"{STYLE_PATH}?h=1\">")),
            None
        );
        assert_eq!(versioned("<p>No assets here.</p>"), None);
        let home = versioned(&crate::templates::HomeTemplate.render().unwrap()).unwrap();
        for path in [PUBLIC_STYLE_PATH, PUBLIC_SCRIPT_PATH, THEME_SCRIPT_PATH] {
            assert!(home.contains(&format!("{path}?h={}", SERVED[path].version)));
        }
    }

    #[test]
    fn assets_name_the_assets_they_use_by_final_content_hash() {
        let mut references = 0;
        for &(path, _, _) in ASSETS {
            let Ok(text) = std::str::from_utf8(&SERVED[path].body) else {
                continue;
            };
            for (at, _) in text.match_indices(ASSET_PREFIX) {
                let rest = &text[at..];
                let Some((name, after)) = rest.split_once("?h=") else {
                    continue;
                };
                let Some(asset) = SERVED.get(name) else {
                    continue;
                };
                assert!(
                    after.starts_with(&asset.version),
                    "{path} names {name} by a stale hash"
                );
                references += 1;
            }
        }
        // The fonts in both stylesheets and the icon sprite in the dashboard.
        assert!(references >= 4, "{references}");
        assert!(
            std::str::from_utf8(&SERVED[PUBLIC_STYLE_PATH].body)
                .unwrap()
                .contains(&format!(
                    "{GEIST_MONO_PATH}?h={}",
                    SERVED[GEIST_MONO_PATH].version
                ))
        );
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
                // The empty state's text and the Retry beside a failure.
                "<div class=\"cw-terminal-empty\" data-terminal-empty-state><p role=\"status\" data-terminal-empty>",
                "<button class=\"cw-button cw-button--outline cw-button--small\" type=\"button\" data-terminal-retry hidden>Retry</button>",
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
