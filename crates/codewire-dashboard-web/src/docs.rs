use std::path::{Component, Path, PathBuf};

use askama::Template;
use axum::{
    Router,
    extract::{OriginalUri, Path as AxumPath, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::{analytics::Analytics, response::with_analytics_policy, state::AppState};

const DOCS_CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'";
const INSTALLER: &str = include_str!("../../../apps/cli/install.sh");
const APPLE_ASSOCIATION: &str = r#"{"webcredentials":{"apps":["PXQZM3GLP5.sh.codewire.ios"]}}"#;
// `go get codewire.sh/sdk-go` reads this page's go-import tag (#3512). The
// module lives in libs/sdk-go of the public mirror, so the tag carries Go
// 1.25's subdirectory field, and its versions are the mirror's
// libs/sdk-go/vMAJOR.MINOR.PATCH tags.
const GO_SDK_IMPORT: &str = concat!(
    "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n",
    "<meta name=\"go-import\" content=\"codewire.sh/sdk-go git https://github.com/codewiresh/codewire libs/sdk-go\">\n",
    "<meta name=\"go-source\" content=\"codewire.sh/sdk-go https://github.com/codewiresh/codewire/tree/main/libs/sdk-go https://github.com/codewiresh/codewire/tree/main/libs/sdk-go{/dir} https://github.com/codewiresh/codewire/blob/main/libs/sdk-go{/dir}/{file}#L{line}\">\n",
    "<title>codewire.sh/sdk-go</title></head>\n",
    "<body><a href=\"/docs\">The Codewire Go SDK documentation</a></body></html>\n",
);

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/docs", get(docs_index))
        .route("/docs/", get(docs_trailing_slash))
        .route("/docs/{*path}", get(docs_path))
        // The llms.txt convention looks for these at the origin root.
        .route("/llms.txt", get(llms_index))
        .route("/llms-full.txt", get(llms_full))
        .route("/install.sh", get(installer))
        .route("/sdk-go", get(go_sdk_import))
        .route("/sdk-go/{*package}", get(go_sdk_import))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_association),
        )
}

async fn docs_index(State(state): State<AppState>) -> Response {
    serve_docs_file(&state, "index.html").await
}

async fn llms_index(State(state): State<AppState>) -> Response {
    serve_docs_file(&state, "llms.txt").await
}

async fn llms_full(State(state): State<AppState>) -> Response {
    serve_docs_file(&state, "llms-full.txt").await
}

async fn docs_trailing_slash() -> Response {
    redirect_to_canonical("/docs")
}

async fn docs_path(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    AxumPath(path): AxumPath<String>,
) -> Response {
    if uri.path().ends_with('/') {
        return redirect_to_canonical(uri.path().trim_end_matches('/'));
    }
    let relative = Path::new(&path);
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let requested = if relative.extension().is_some() {
        relative.to_path_buf()
    } else {
        relative.join("index.html")
    };
    serve_docs_file(&state, &requested).await
}

async fn serve_docs_file(state: &AppState, relative: impl AsRef<Path>) -> Response {
    let relative = relative.as_ref();
    let loaded = if state.inline_docs_io {
        // The verifier deliberately uses a current-thread runtime on runners
        // that may have no spare PID for Tokio's blocking filesystem pool.
        // These files are immutable image content, so bounded inline reads are
        // safe in that constrained mode. Production retains Tokio filesystem
        // I/O on its default multi-thread runtime.
        load_docs_file_inline(&state.docs_root, relative)
    } else {
        load_docs_file_async(&state.docs_root, relative).await
    };
    let Some((target, mut body)) = loaded else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = content_type(&target);
    let tagged = state
        .analytics
        .as_ref()
        .filter(|_| content_type == HTML)
        .and_then(|analytics| Some((tag_page(&body, analytics)?, analytics.origin.as_str())));
    let connect_origin = tagged.map(|(page, origin)| {
        body = page.into_bytes();
        origin
    });
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(DOCS_CSP),
    );
    match connect_origin {
        Some(origin) => with_analytics_policy(response, StatusCode::OK, origin),
        None => response,
    }
}

#[derive(Template)]
#[template(path = "analytics.html")]
struct AnalyticsTag<'a> {
    analytics: &'a Analytics,
}

/// A docs page with the analytics tag (infra#2677). The docs are static and a
/// shared cache keeps one copy of each, so like the homepage they carry it for
/// every visitor. Each page also states its own policy in a meta tag, which
/// the browser enforces beside the header, so that policy gains the
/// tracker's one connection too. A page whose head doesn't hold exactly one
/// `connect-src 'self'`, such as a redirect, is served as built.
fn tag_page(body: &[u8], analytics: &Analytics) -> Option<String> {
    let page = std::str::from_utf8(body).ok()?;
    let (head, rest) = page.split_once("</head>")?;
    if head.matches(SELF_CONNECT).count() != 1 {
        return None;
    }
    let tag = AnalyticsTag { analytics }.render().ok()?;
    let head = head.replace(
        SELF_CONNECT,
        &format!("{SELF_CONNECT} {}", analytics.origin),
    );
    Some(format!("{head}{tag}\n  </head>{rest}"))
}

const SELF_CONNECT: &str = "connect-src 'self'";
const HTML: &str = "text/html; charset=utf-8";

async fn load_docs_file_async(root: &Path, relative: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let root = tokio::fs::canonicalize(root).await.ok()?;
    let target = match tokio::fs::canonicalize(root.join(relative)).await {
        Ok(target) if target.starts_with(&root) => target,
        _ => return None,
    };
    let body = tokio::fs::read(&target).await.ok()?;
    Some((target, body))
}

fn load_docs_file_inline(root: &Path, relative: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let root = std::fs::canonicalize(root).ok()?;
    let target = match std::fs::canonicalize(root.join(relative)) {
        Ok(target) if target.starts_with(&root) => target,
        _ => return None,
    };
    let body = std::fs::read(&target).ok()?;
    Some((target, body))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn redirect_to_canonical(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn installer() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        INSTALLER,
    )
        .into_response()
}

async fn go_sdk_import() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, DOCS_CSP),
        ],
        GO_SDK_IMPORT,
    )
        .into_response()
}

async fn apple_association() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        APPLE_ASSOCIATION,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_content_types_are_explicit() {
        assert_eq!(
            content_type(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("search.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("search_index.en.json")),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("guides/previews.md")),
            "text/markdown; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("llms-full.txt")),
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn immutable_well_known_contract_is_exact() {
        let response = apple_association().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            APPLE_ASSOCIATION,
            r#"{"webcredentials":{"apps":["PXQZM3GLP5.sh.codewire.ios"]}}"#
        );
    }

    #[tokio::test]
    async fn the_go_sdk_import_path_names_the_mirror_subdirectory() {
        let response = go_sdk_import().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert!(GO_SDK_IMPORT.contains(
            r#"<meta name="go-import" content="codewire.sh/sdk-go git https://github.com/codewiresh/codewire libs/sdk-go">"#
        ));
    }
}
