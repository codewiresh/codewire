//! The analytics tag (infra#2677): which pages carry it, for whom, and the
//! one connection their policy gains.

use axum::http::{StatusCode, header};
use codewire_server_core::auth::SESSION_COOKIE_NAME;

const PARTIAL: &str = include_str!("../../templates/analytics.html");
const TRACKER: &str = "/assets/codewire/umami-tracker-3.5.0.js";
const HOOK: &str = "/assets/codewire/analytics-v1.js";

/// The pages that include the tag. Every other template, the sign-in,
/// sign-up, reset, verification, invitation and device pages among them,
/// never names it, so a new page carries it only by being added here.
const TAGGED_TEMPLATES: [&str; 5] = [
    "home.html",
    "pricing.html",
    "privacy.html",
    "terms.html",
    "updates.html",
];

#[test]
fn only_the_public_pages_include_the_tag_and_nothing_else_names_its_scripts() {
    let templates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut including = Vec::new();
    for entry in std::fs::read_dir(&templates).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        if name == "analytics.html" {
            continue;
        }
        assert!(
            !text.contains(TRACKER) && !text.contains(HOOK),
            "{name} names an analytics script outside the partial"
        );
        if text.contains(r#"{% include "analytics.html" %}"#) {
            assert!(
                text.contains(r#"{% if let Some(analytics) = analytics %}"#),
                "{name} includes the tag without its flag"
            );
            including.push(name);
        }
    }
    including.sort();
    assert_eq!(including, TAGGED_TEMPLATES);
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
    for path in ["/", "/pricing", "/privacy", "/terms"] {
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
async fn public_pages_carry_the_tag_signed_out_and_the_homepage_for_everyone() {
    let (origin, server) = serve(true).await;
    let client = client();
    let session = format!("{SESSION_COOKIE_NAME}=synthetic");

    // The tagged pages, signed out and then with a session. Only the
    // homepage, which a shared cache keeps one copy of, stays tagged.
    for (path, tagged_with_session) in [
        ("/", true),
        ("/pricing", false),
        ("/privacy", false),
        ("/terms", false),
    ] {
        for cookie in [
            None,
            Some(session.as_str()),
            Some("a=1; codewire.session_token"),
        ] {
            let mut request = client.get(format!("{origin}{path}"));
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let expected = cookie.is_none() || tagged_with_session;
            let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(
                tagged_policy(&policy),
                expected,
                "{path} {cookie:?}: {policy}"
            );
            assert!(policy.contains("script-src 'self';"), "{policy}");
            let body = response.text().await.unwrap();
            assert_eq!(body.contains(TRACKER), expected, "{path} {cookie:?}");
            assert_eq!(body.contains(HOOK), expected, "{path} {cookie:?}");
        }
    }

    // Pages that carry a secret in their URL or form never have the tag or
    // the connection, signed out.
    for path in [
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
    ] {
        let response = client.get(format!("{origin}{path}")).send().await.unwrap();
        if let Some(policy) = response.headers().get(header::CONTENT_SECURITY_POLICY) {
            assert!(!tagged_policy(policy.to_str().unwrap()), "{path}");
        }
        assert!(!response.text().await.unwrap().contains(TRACKER), "{path}");
    }
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

#[test]
fn a_session_is_any_session_cookie_or_an_unreadable_cookie_header() {
    use axum::http::{HeaderMap, HeaderValue};

    let headers = |values: &[&[u8]]| {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::COOKIE, HeaderValue::from_bytes(value).unwrap());
        }
        headers
    };
    let carries = |values: &[&[u8]]| crate::security::carries_session(&headers(values));
    assert!(!carries(&[]));
    assert!(!carries(&[b"theme=dark; codewire.session_tokens=x"]));
    assert!(carries(&[format!("{SESSION_COOKIE_NAME}=x").as_bytes()]));
    assert!(carries(&[
        format!("a=1;  {SESSION_COOKIE_NAME}=").as_bytes()
    ]));
    assert!(carries(&[b"a=1", SESSION_COOKIE_NAME.as_bytes()]));
    assert!(carries(&[b"a=\xff"]));
}
