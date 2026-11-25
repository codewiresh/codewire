//! The public Updates page against a synthetic Liminal that checks the
//! site's bearer key and can be made to fail.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::get,
};

const KEY: &str = "lim_sk_synthetic";

struct TestServer {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    TestServer { origin, task }
}

#[derive(Clone, Default)]
struct Liminal {
    failing: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
}

async fn liminal(state: Liminal) -> TestServer {
    serve(Router::new().route(
        "/api/v1/posts",
        get(move |headers: HeaderMap| async move {
            state.reads.fetch_add(1, Ordering::SeqCst);
            if headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                != Some(&format!("Bearer {KEY}"))
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            if state.failing.load(Ordering::SeqCst) {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Json(serde_json::json!({
                "data": [
                    {
                        "id": "00000000-0000-4000-8000-000000000001",
                        "kind": "post",
                        "title": "Snapshots <and> forks",
                        "html": "<p>Fork a sandbox.</p><script>alert(1)</script><img src=\"https://media.synthetic.test/fork.png\" alt=\"Fork\"><img src=\"https://tracker.synthetic.test/pixel.gif\">",
                        "slug": "snapshots",
                        "excerpt": "",
                        "published_at": "2026-11-18T09:00:00Z",
                        "tags": [],
                        "authors": []
                    }
                ],
                "next_cursor": null
            }))
            .into_response()
        }),
    ))
    .await
}

fn config(updates_origin: Option<&str>, media_origin: Option<&str>) -> crate::Config {
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: "https://dashboard.synthetic.invalid".into(),
        api_origin: "http://127.0.0.1:9".parse().unwrap(),
        credential_origin: "http://127.0.0.1:9".parse().unwrap(),
        identity_origin_string: "http://127.0.0.1:9".into(),
        browser_api_origin: "https://dashboard.synthetic.invalid".into(),
        billing_origin: "http://127.0.0.1:9".parse().unwrap(),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
        support_email: None,
        updates_site: updates_origin.map(|origin| {
            crate::updates_connect::LiminalSite::new(
                origin.to_owned(),
                KEY.to_owned(),
                media_origin.map(str::to_owned),
            )
        }),
        analytics: Some(crate::analytics::Analytics {
            origin: "https://umami.codewire.test".into(),
            website_id: "00000000-0000-4000-8000-0000000000aa".into(),
            domain: "codewire.test".into(),
        }),
    }
}

async fn get_updates(dashboard: &TestServer) -> reqwest::Response {
    reqwest::Client::builder()
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!("{}/updates", dashboard.origin))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_page_shows_cleaned_posts_and_keeps_them_through_a_liminal_failure() {
    let state = Liminal::default();
    let upstream = liminal(state.clone()).await;
    let dashboard = serve(crate::app(config(
        Some(&upstream.origin),
        Some("https://media.synthetic.test"),
    )))
    .await;

    let response = get_updates(&dashboard).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .split(',')
            .any(|directive| directive.trim() == "no-store")
    );
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        policy.contains("img-src 'self' data: https://media.synthetic.test;"),
        "{policy}"
    );
    assert!(policy.contains("script-src 'self';"), "{policy}");
    // The analytics tag's one connection, beside the media origin (infra#2677).
    assert!(
        policy.contains("connect-src 'self' https://umami.codewire.test;"),
        "{policy}"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("/assets/codewire/umami-tracker-3.5.0.js"));
    assert!(body.contains(r#"<h2 id="update-snapshots">Snapshots &#60;and&#62; forks</h2>"#));
    assert!(body.contains(r#"<time datetime="2026-11-18">Nov 18, 2026</time>"#));
    assert!(body.contains("<p>Fork a sandbox.</p>"));
    assert!(!body.contains("alert(1)"));
    assert!(body.contains(r#"<img src="https://media.synthetic.test/fork.png" alt="Fork">"#));
    assert!(!body.contains("tracker.synthetic.test"));

    // With a session the page has no tag and keeps its connections.
    let signed_in = reqwest::Client::builder()
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!("{}/updates", dashboard.origin))
        .header(
            header::COOKIE,
            format!(
                "{}=synthetic",
                codewire_server_core::auth::SESSION_COOKIE_NAME
            ),
        )
        .send()
        .await
        .unwrap();
    let policy = signed_in.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(policy.contains("connect-src 'self';"), "{policy}");
    assert!(
        policy.contains("img-src 'self' data: https://media.synthetic.test;"),
        "{policy}"
    );
    assert!(!signed_in.text().await.unwrap().contains("umami-tracker"));

    state.failing.store(true, Ordering::SeqCst);
    let response = get_updates(&dashboard).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.text().await.unwrap().contains("Fork a sandbox."));
    assert_eq!(state.reads.load(Ordering::SeqCst), 1, "read once per TTL");
}

#[tokio::test]
async fn the_page_says_it_is_unavailable_until_liminal_first_answers() {
    let state = Liminal::default();
    state.failing.store(true, Ordering::SeqCst);
    let upstream = liminal(state.clone()).await;
    let dashboard = serve(crate::app(config(Some(&upstream.origin), None))).await;

    let response = get_updates(&dashboard).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(policy.contains("img-src 'self' data:;"), "{policy}");
    assert!(
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("Updates can’t be loaded right now.")
    );

    let again = get_updates(&dashboard).await;
    assert_eq!(again.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        state.reads.load(Ordering::SeqCst),
        1,
        "a failed read is retried only after the back-off"
    );
}

#[tokio::test]
async fn without_a_liminal_site_there_is_no_page() {
    let dashboard = serve(crate::app(config(None, None))).await;
    assert_eq!(
        get_updates(&dashboard).await.status(),
        StatusCode::NOT_FOUND
    );
}

type FieldMap = std::collections::BTreeMap<&'static str, String>;

/// The `updates.read` spans a test opened (whether trace export would build
/// each one, and the fields recorded on it), and the events the dashboard's
/// logged target emitted (each one's level and fields).
#[derive(Default)]
struct ReadSpans {
    spans: std::sync::Mutex<Vec<(bool, FieldMap)>>,
    logged: std::sync::Mutex<Vec<(tracing::Level, FieldMap)>>,
}

struct CaptureReadSpans(Arc<ReadSpans>);

struct Fields<'a>(&'a mut std::collections::BTreeMap<&'static str, String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name(), value.to_owned());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CaptureReadSpans {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.name() == "updates.read"
            || (metadata.is_event() && metadata.target() == crate::LOG_TARGETS[0].0)
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut spans = self.0.spans.lock().unwrap();
        let mut fields = FieldMap::new();
        attributes.record(&mut Fields(&mut fields));
        spans.push((
            codewire_server_core::obs::exports_span(attributes.metadata()),
            fields,
        ));
        tracing::span::Id::from_u64(spans.len() as u64)
    }
    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut spans = self.0.spans.lock().unwrap();
        let index = usize::try_from(span.into_u64()).unwrap() - 1;
        values.record(&mut Fields(&mut spans[index].1));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = FieldMap::new();
        event.record(&mut Fields(&mut fields));
        self.0
            .logged
            .lock()
            .unwrap()
            .push((*event.metadata().level(), fields));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn each_read_records_its_outcome_on_an_exported_span_and_a_failure_in_the_log() {
    let spans = Arc::new(ReadSpans::default());
    let _capture = tracing::subscriber::set_default(CaptureReadSpans(spans.clone()));
    let upstream = serve(
        Router::new()
            .route(
                "/ok/api/v1/posts",
                get(|| async { Json(serde_json::json!({ "data": [], "next_cursor": null })) }),
            )
            .route(
                "/down/api/v1/posts",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            )
            .route("/garbled/api/v1/posts", get(|| async { "not json" }))
            .route(
                "/stalled/api/v1/posts",
                get(|| async {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    "late"
                }),
            ),
    )
    .await;
    // Bound and never listening: the port stays this test's own, so no test
    // running beside it can be given it, and every connection is refused.
    let refusing = tokio::net::TcpSocket::new_v4().unwrap();
    refusing.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let closed = format!("http://{}", refusing.local_addr().unwrap());

    for origin in [
        format!("{}/ok", upstream.origin),
        format!("{}/down", upstream.origin),
        format!("{}/garbled", upstream.origin),
        format!("{}/stalled", upstream.origin),
        closed,
    ] {
        let updates = crate::updates_connect::Updates::with_timeout(
            crate::updates_connect::LiminalSite::new(origin, KEY.to_owned(), None),
            std::time::Duration::from_millis(300),
        );
        let _ = crate::updates_connect::read_traced(&updates).await;
    }

    let fields = |outcome: &str, status: Option<&str>| {
        let mut fields = std::collections::BTreeMap::from([("outcome", outcome.to_owned())]);
        if let Some(status) = status {
            fields.insert("http.response.status_code", status.to_owned());
        }
        (true, fields)
    };
    assert_eq!(
        *spans.spans.lock().unwrap(),
        vec![
            fields("ok", None),
            fields("status", Some("503")),
            fields("parse", None),
            fields("timeout", None),
            fields("connect", None),
        ],
        "one exported span per read, recording only its outcome and Liminal's status"
    );

    let warning = |outcome: &str, status: Option<&str>| {
        let (_, mut fields) = fields(outcome, status);
        fields.insert(
            "message",
            "the Updates page could not read Liminal and keeps its last posts".to_owned(),
        );
        (tracing::Level::WARN, fields)
    };
    assert_eq!(
        crate::LOG_TARGETS,
        &[(
            "codewire_dashboard_web::updates_connect",
            tracing::Level::WARN
        )],
        "the dashboard logs its Updates reader's warnings and nothing else"
    );
    assert_eq!(
        *spans.logged.lock().unwrap(),
        vec![
            warning("status", Some("503")),
            warning("parse", None),
            warning("timeout", None),
            warning("connect", None),
        ],
        "one warning per failed read, carrying only its outcome and Liminal's status"
    );
}
