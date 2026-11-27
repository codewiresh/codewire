//! The analytics tag (infra#2677): every page carries it, signed in or not,
//! and its policy gains the one connection.

use axum::http::{StatusCode, header};
use codewire_server_core::auth::SESSION_COOKIE_NAME;

const PARTIAL: &str = include_str!("../../templates/analytics.html");
const TRACKER: &str = "/assets/codewire/umami-tracker-3.5.0.js";
const HOOK: &str = "/assets/codewire/analytics-v1.js";

/// The response layer adds the tag, so no template names its scripts: a page
/// can't carry it twice.
#[test]
fn no_template_names_the_tag_scripts_but_the_partial() {
    let templates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    for entry in std::fs::read_dir(&templates).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name == "analytics.html" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(TRACKER) && !text.contains(HOOK) && !text.contains("analytics.html"),
            "{name} names the analytics tag"
        );
    }
}

/// A tagged page sends its path, so no path may hold a secret: the
/// invitation, reset, verification and device flows carry theirs in the
/// query or the fragment, which the tag never sends. Every path parameter the
/// router names is listed here; a new one is added only once it is known to
/// be a name or an ID.
#[test]
fn every_path_parameter_is_a_name_or_an_id() {
    fn sources(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                sources(&path, files);
            } else if name.ends_with(".rs")
                && !name.ends_with("tests.rs")
                && name != "test_support.rs"
            {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut parameters = std::collections::BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for route in text.split(".route(").skip(1) {
            let path = route
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split('"').next());
            for parameter in path.unwrap_or_default().split('{').skip(1) {
                parameters.insert(parameter.split('}').next().unwrap().to_owned());
            }
        }
    }
    assert_eq!(
        parameters.into_iter().collect::<Vec<_>>(),
        [
            "*package",
            "*path",
            "*rest",
            "bucket",
            "environment_id",
            "name",
            "organization_id",
            "session_id",
            "slug",
            "user_id",
        ]
    );
}

const ORIGIN: &str = "https://umami.codewire.test";
const WEBSITE: &str = "00000000-0000-4000-8000-0000000000aa";

fn tagged_policy(policy: &str) -> bool {
    policy.contains(&format!("connect-src 'self' {ORIGIN};"))
}

async fn serve(analytics: bool) -> (String, tokio::task::JoinHandle<()>) {
    serve_docs(analytics, std::path::PathBuf::new()).await
}

async fn serve_docs(
    analytics: bool,
    docs_root: std::path::PathBuf,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut config = crate::test_support::unreachable_config();
    config.docs_root = docs_root;
    if analytics {
        config.analytics = crate::analytics::parse(
            Some(ORIGIN.into()),
            Some(WEBSITE.into()),
            &config.public_origin,
        )
        .unwrap();
    }
    let server =
        tokio::spawn(async move { axum::serve(listener, crate::app(config)).await.unwrap() });
    (origin, server)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
}

#[tokio::test]
async fn the_tag_sends_only_from_the_public_host_with_no_query_and_its_own_hook() {
    let (origin, server) = serve(true).await;
    let body = client()
        .get(format!("{origin}/privacy"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for attribute in [
        format!(r#"data-website-id="{WEBSITE}""#),
        format!(r#"data-host-url="{ORIGIN}""#),
        r#"data-domains="codewire.test""#.to_owned(),
        r#"data-exclude-search="true""#.to_owned(),
        r#"data-exclude-hash="true""#.to_owned(),
        r#"data-before-send="codewireAnalyticsBeforeSend""#.to_owned(),
    ] {
        assert!(body.contains(&attribute), "{attribute}");
    }
    // Error reports, web vitals and a client-chosen salt stay off: each is
    // on only when its attribute is present.
    for attribute in ["data-errors", "data-performance", "data-salt", "data-tag"] {
        assert!(!PARTIAL.contains(attribute), "{attribute}");
    }
    // The hook loads first: both are deferred, so they run in order.
    assert!(body.find(HOOK).unwrap() < body.find(TRACKER).unwrap());
    server.abort();
}

#[tokio::test]
async fn without_the_settings_no_page_is_tagged_or_gains_a_connection() {
    let (origin, server) = serve(false).await;
    for path in ["/", "/pricing", "/privacy", "/terms", "/login"] {
        let response = client()
            .get(format!("{origin}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(policy.contains("connect-src 'self';"), "{path}: {policy}");
        let body = response.text().await.unwrap();
        assert!(!body.contains(TRACKER) && !body.contains(HOOK), "{path}");
    }
    server.abort();
}

#[tokio::test]
async fn every_page_carries_the_tag_signed_in_or_not() {
    let (origin, server) = serve(true).await;
    let client = client();
    let session = format!("{SESSION_COOKIE_NAME}=synthetic");

    // The public pages, the sign-in and account flows and a missing page,
    // signed out and with a session, as each renders with its upstreams
    // unreachable.
    let mut tagged = Vec::new();
    for path in [
        "/",
        "/pricing",
        "/privacy",
        "/terms",
        "/login",
        "/signup",
        "/forgot-password",
        "/reset-password?token=synthetic",
        "/verify-email?token=synthetic",
        "/login/link",
        "/signup/complete",
        "/accept-invite",
        "/device",
        "/two-factor",
        "/setup-2fa",
        "/dashboard/",
        "/settings/",
        "/no-such-organization/no-such-sandbox/",
    ] {
        for cookie in [None, Some(session.as_str())] {
            let mut request = client.get(format!("{origin}{path}"));
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            let response = request.send().await.unwrap();
            let html = response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value.to_str().unwrap().starts_with("text/html"));
            let policy = response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default();
            let body = response.text().await.unwrap();
            if !html || !body.contains("</head>") {
                assert!(!body.contains(TRACKER), "{path} {cookie:?}");
                continue;
            }
            assert!(tagged_policy(&policy), "{path} {cookie:?}: {policy}");
            assert!(policy.contains("script-src 'self';"), "{policy}");
            let (head, _) = body.split_once("</head>").unwrap();
            assert_eq!(head.matches(TRACKER).count(), 1, "{path} {cookie:?}");
            assert!(head.find(HOOK).unwrap() < head.find(TRACKER).unwrap());
            // A public page keeps its address; any other names only its kind.
            let route = head
                .split(r#"data-analytics-route=""#)
                .nth(1)
                .map(|rest| &rest[..rest.find('"').unwrap()]);
            let expected = match path {
                "/" | "/pricing" | "/privacy" | "/terms" => None,
                "/no-such-organization/no-such-sandbox/" => Some("/:slug/:environment_id/"),
                _ => Some(path.split('?').next().unwrap()),
            };
            assert_eq!(route, expected, "{path} {cookie:?}");
            tagged.push((path, cookie.is_some()));
        }
    }
    // Each of these is a whole page both ways.
    for path in [
        "/",
        "/pricing",
        "/privacy",
        "/terms",
        "/login",
        "/signup",
        "/forgot-password",
    ] {
        for signed_in in [false, true] {
            assert!(tagged.contains(&(path, signed_in)), "{path} {signed_in}");
        }
    }

    // An htmx fragment is swapped into a page that already carries the tag.
    let response = client
        .get(format!("{origin}/login"))
        .header("hx-request", "true")
        .send()
        .await
        .unwrap();
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!tagged_policy(&policy), "{policy}");
    assert!(!response.text().await.unwrap().contains(TRACKER));
    server.abort();
}

/// A docs page as Zola builds it: the head states the page's own policy.
const DOCS_PAGE: &str = "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'\">\n    <script src=\"/docs/docs.js\" defer></script>\n  </head>\n  <body><p>A policy may say connect-src 'self'.</p></body>\n</html>\n";
const DOCS_REDIRECT: &str = "<!doctype html>\n<html>\n  <head>\n    <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">\n    <meta http-equiv=\"refresh\" content=\"0; url=/docs\">\n  </head>\n  <body></body>\n</html>\n";

/// A scratch docs root, removed by its exact name when dropped.
struct DocsRoot(std::path::PathBuf);

impl DocsRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "codewire-docs-analytics-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("guide")).unwrap();
        std::fs::create_dir(root.join("moved")).unwrap();
        std::fs::write(root.join("index.html"), DOCS_PAGE).unwrap();
        std::fs::write(root.join("guide/index.html"), DOCS_PAGE).unwrap();
        std::fs::write(root.join("guide.md"), "connect-src 'self' </head>\n").unwrap();
        std::fs::write(root.join("moved/index.html"), DOCS_REDIRECT).unwrap();
        Self(root)
    }
}

impl Drop for DocsRoot {
    fn drop(&mut self) {
        for file in [
            "index.html",
            "guide/index.html",
            "guide.md",
            "moved/index.html",
        ] {
            let _ = std::fs::remove_file(self.0.join(file));
        }
        for dir in ["guide", "moved", ""] {
            let _ = std::fs::remove_dir(self.0.join(dir));
        }
    }
}

#[test]
fn every_docs_page_head_holds_the_one_connection_the_tag_extends() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/docs/zola/templates/base.html");
    let base = std::fs::read_to_string(base).unwrap();
    let (head, _) = base.split_once("</head>").unwrap();
    assert_eq!(head.matches("connect-src 'self'").count(), 1);
    assert_eq!(base.matches("</head>").count(), 1);
}

#[tokio::test]
async fn the_docs_carry_the_tag_for_every_visitor_and_their_own_policy_allows_it() {
    let docs = DocsRoot::new();
    let (origin, server) = serve_docs(true, docs.0.clone()).await;
    let client = client();
    let session = format!("{SESSION_COOKIE_NAME}=synthetic");
    // A shared cache keeps one copy of each docs page, so a session changes
    // nothing.
    for path in ["/docs", "/docs/guide"] {
        for cookie in [None, Some(session.as_str())] {
            let mut request = client.get(format!("{origin}{path}"));
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .to_owned();
            assert!(tagged_policy(&policy), "{path} {cookie:?}: {policy}");
            assert!(policy.contains("script-src 'self';"), "{policy}");
            let body = response.text().await.unwrap();
            let (head, page) = body.split_once("</head>").unwrap();
            assert!(head.contains(&format!("connect-src 'self' {ORIGIN}; object-src")));
            assert!(head.find("/docs/docs.js").unwrap() < head.find(HOOK).unwrap());
            assert!(head.find(HOOK).unwrap() < head.find(TRACKER).unwrap());
            assert!(head.contains(&format!(r#"data-website-id="{WEBSITE}""#)));
            assert!(page.contains("A policy may say connect-src 'self'.</p>"));
        }
    }
    // A redirect page states no connection to extend, and a page's Markdown
    // source isn't HTML: both are served as built.
    for (path, built) in [
        ("/docs/moved", DOCS_REDIRECT),
        ("/docs/guide.md", "connect-src 'self' </head>\n"),
    ] {
        let response = client.get(format!("{origin}{path}")).send().await.unwrap();
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!tagged_policy(&policy), "{path}: {policy}");
        assert_eq!(response.text().await.unwrap(), built, "{path}");
    }
    server.abort();
}

#[tokio::test]
async fn without_the_settings_the_docs_are_served_as_built() {
    let docs = DocsRoot::new();
    let (origin, server) = serve_docs(false, docs.0.clone()).await;
    let response = client().get(format!("{origin}/docs")).send().await.unwrap();
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(policy.contains("connect-src 'self';"), "{policy}");
    assert_eq!(response.text().await.unwrap(), DOCS_PAGE);
    server.abort();
}

/// A page streamed as it is made, such as the no-JavaScript credential
/// connect page with its sign-in code, reaches the browser as it is sent:
/// the layer never holds it back to tag it.
#[tokio::test]
async fn a_streamed_page_is_sent_as_it_is_made() {
    use axum::{body::Body, response::Response, routing::get};
    use tokio_stream::wrappers::ReceiverStream;

    let mut config = crate::test_support::unreachable_config();
    config.analytics = crate::analytics::parse(
        Some(ORIGIN.into()),
        Some(WEBSITE.into()),
        &config.public_origin,
    )
    .unwrap();
    let state = crate::state::AppState::new(config);
    let (send, receive) =
        tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::convert::Infallible>>(1);
    let body = std::sync::Arc::new(std::sync::Mutex::new(Some(Body::from_stream(
        ReceiverStream::new(receive),
    ))));
    let app = axum::Router::new()
        .route(
            "/streamed",
            get(move || {
                let body = body.lock().unwrap().take().unwrap();
                async move {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(
                            header::CONTENT_SECURITY_POLICY,
                            "default-src 'self'; connect-src 'self'; script-src 'self'",
                        )
                        .body(body)
                        .unwrap()
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::analytics::tag_pages,
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let guard = crate::test_support::LOOPBACK_HANG_GUARD;
    let first = "<!doctype html><html><head></head><body><p>Code: ABCD-1234</p>";
    send.send(Ok(first.into())).await.unwrap();
    let mut response =
        tokio::time::timeout(guard, client().get(format!("{origin}/streamed")).send())
            .await
            .unwrap()
            .unwrap();
    let chunk = tokio::time::timeout(guard, response.chunk())
        .await
        .expect("the first chunk arrives while the page is still being made")
        .unwrap()
        .unwrap();
    assert_eq!(chunk, first.as_bytes());
    send.send(Ok("</body></html>".into())).await.unwrap();
    drop(send);
    server.abort();
}
