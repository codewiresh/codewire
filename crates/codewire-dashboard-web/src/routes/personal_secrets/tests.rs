use super::*;
use crate::security::new_csrf_token;
use askama::Template as _;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Request,
    response::IntoResponse,
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    DeleteUserSecretRequest, DeleteUserSecretResponse, ListEnvironmentsResponse,
    ListOrganizationsResponse, ListUserSecretsRequest, ListUserSecretsResponse, Organization,
    OrganizationMembership, RenameUserSecretRequest, RenameUserSecretResponse, SecretMetadata,
    SetUserSecretRequest, SetUserSecretResponse,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
struct Source {
    identity: Arc<AtomicUsize>,
    organizations: Arc<AtomicUsize>,
    mutation: Arc<AtomicUsize>,
    inventory: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Source {
    fn reset(&self) {
        self.requests.lock().unwrap().clear();
    }
    fn calls(&self, suffix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with(suffix))
            .count()
    }
}

fn proto_response(message: impl buffa::Message) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
}

fn rpc_failure(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"code":code,"message":"synthetic-upstream-private-value"})),
    )
        .into_response()
}

async fn fixture() -> (AppState, Source, tokio::task::JoinHandle<()>) {
    let source = Source::default();
    let handle = source.clone();
    let router = Router::new().fallback(any(move |request: Request| {
        let source = handle.clone();
        async move {
            let path = request.uri().path().to_owned();
            source.requests.lock().unwrap().push(path.clone());
            assert_eq!(request.headers()[header::COOKIE], "codewire.session_token=synthetic");
            assert!(!request.headers().contains_key(header::AUTHORIZATION));
            if path == "/api/auth/get-session" {
                return Json(match source.identity.load(Ordering::SeqCst) {
                    1 => serde_json::Value::Null,
                    n => serde_json::json!({"user":{"id":"account-1","email":"owner@example.test","name":"Synthetic owner","two_factor_enabled":n != 2}}),
                }).into_response();
            }
            if path.ends_with("/ListOrganizations") {
                return match source.organizations.load(Ordering::SeqCst) {
                    1 => rpc_failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    2 => rpc_failure(StatusCode::UNAUTHORIZED, "unauthenticated"),
                    3 => rpc_failure(StatusCode::FORBIDDEN, "permission_denied"),
                    4 | 5 => proto_response(ListOrganizationsResponse {
                        organizations: vec![OrganizationMembership {
                            organization: Some(Organization { id: "org-1".into(), slug: "allowed".into(), name: "Allowed".into(), ..Default::default() }).into(),
                            ..Default::default()
                        }], ..Default::default()
                    }),
                    _ => proto_response(ListOrganizationsResponse::default()),
                };
            }
            if path.ends_with("/ListEnvironments") {
                if source.organizations.load(Ordering::SeqCst) == 5 {
                    return rpc_failure(StatusCode::FORBIDDEN, "permission_denied");
                }
                return proto_response(ListEnvironmentsResponse::default());
            }
            if path.ends_with("/ListUserSecrets") {
                let bytes = to_bytes(request.into_body(), 8192).await.unwrap();
                let body = ListUserSecretsRequest::decode_from_slice(&bytes).unwrap();
                assert_eq!(body.page_size, 0);
                assert!(body.page_token.is_empty());
                if source.inventory.load(Ordering::SeqCst) == 2 {
                    return rpc_failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
                }
                let mut secrets = vec![SecretMetadata { key: "DATABASE_URL".into(), ..Default::default() }];
                if source.inventory.load(Ordering::SeqCst) == 1 {
                    secrets.extend((0..100).map(|index| SecretMetadata { key: format!("KEY{index:03}"), ..Default::default() }));
                }
                return proto_response(ListUserSecretsResponse { secrets, ..Default::default() });
            }
            if ["/SetUserSecret", "/RenameUserSecret", "/DeleteUserSecret"].iter().any(|suffix| path.ends_with(suffix)) {
                let bytes = to_bytes(request.into_body(), 256 * 1024).await.unwrap();
                let success = if path.ends_with("/SetUserSecret") {
                    let body = SetUserSecretRequest::decode_from_slice(&bytes).unwrap();
                    assert_eq!(body.key, "DATABASE_URL");
                    assert!(!body.value.is_empty());
                    proto_response(SetUserSecretResponse::default())
                } else if path.ends_with("/RenameUserSecret") {
                    let body = RenameUserSecretRequest::decode_from_slice(&bytes).unwrap();
                    assert_eq!(body.key, "DATABASE_URL");
                    assert_eq!(body.new_key, "DATABASE_NEW");
                    proto_response(RenameUserSecretResponse::default())
                } else {
                    let body = DeleteUserSecretRequest::decode_from_slice(&bytes).unwrap();
                    assert_eq!(body.key, "DATABASE_URL");
                    proto_response(DeleteUserSecretResponse::default())
                };
                if source.mutation.load(Ordering::SeqCst) == 1 {
                    return rpc_failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
                }
                return success;
            }
            panic!("unexpected synthetic request path: {path}");
        }
    }));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let state = AppState::new(crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: "https://app.example.test".into(),
        api_origin: origin.parse().unwrap(),
        credential_origin: origin.parse().unwrap(),
        identity_origin_string: origin.clone(),
        browser_api_origin: origin.clone(),
        billing_origin: origin.parse().unwrap(),
        docs_root: Default::default(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
    });
    (state, source, server)
}

fn browser_headers() -> (HeaderMap, String) {
    let csrf = new_csrf_token();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "codewire.session_token=synthetic; codewire_ssr_csrf={csrf}"
        ))
        .unwrap(),
    );
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://app.example.test"),
    );
    (headers, csrf)
}

fn set_form(csrf: &str, account: &str, value: &str) -> Result<Form<SetForm>, FormRejection> {
    Ok(Form(SetForm {
        csrf: csrf.into(),
        account_id: account.into(),
        key: "DATABASE_URL".into(),
        value: value.into(),
        mode: "add".into(),
    }))
}

fn parsed_query(value: PageQuery) -> Result<PersonalSecretQuery, QueryRejection> {
    Ok(PersonalSecretQuery(value))
}

async fn body(response: Response) -> String {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
    String::from_utf8(
        to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn personal_context_discards_inaccessible_orgs_but_never_authentication_failures() {
    let (state, source, server) = fixture().await;
    let (headers, _) = browser_headers();
    for (case, unavailable) in [(0, false), (1, true), (4, false)] {
        source.organizations.store(case, Ordering::SeqCst);
        source.reset();
        let view =
            super::super::dashboard::personal_settings_shell_view(&state, &headers, "foreign")
                .await
                .unwrap();
        assert_eq!(view.organization_navigation_unavailable, unavailable);
        assert!(!view.has_selected_organization);
        assert_eq!(view.settings_url, "/settings/");
        assert_eq!(source.calls("/ListEnvironments"), 0);
    }
    for case in [2, 3, 5] {
        source.organizations.store(case, Ordering::SeqCst);
        assert!(
            super::super::dashboard::personal_settings_shell_view(&state, &headers, "allowed")
                .await
                .is_err()
        );
    }
    source.organizations.store(4, Ordering::SeqCst);
    let view = super::super::dashboard::personal_settings_shell_view(&state, &headers, "allowed")
        .await
        .unwrap();
    assert_eq!(view.selected_organization_slug, "allowed");
    server.abort();
}

#[tokio::test]
async fn personal_writes_pin_actor_and_cookie_without_an_organization_dependency() {
    let (state, source, server) = fixture().await;
    let (headers, csrf) = browser_headers();
    source.organizations.store(1, Ordering::SeqCst);
    let response = set_action(
        State(state.clone()),
        headers.clone(),
        parsed_query(PageQuery {
            org: "foreign".into(),
            ..Default::default()
        }),
        set_form(&csrf, "account-1", "synthetic-private-value"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(!body(response).await.contains("synthetic-private-value"));
    assert_eq!(source.calls("/SetUserSecret"), 1);
    assert_eq!(source.calls("/ListOrganizations"), 0);
    for account in ["", "account-2"] {
        source.reset();
        let response = set_action(
            State(state.clone()),
            headers.clone(),
            parsed_query(Default::default()),
            set_form(&csrf, account, "synthetic-private-value"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("account-changed")
        );
        assert_eq!(source.calls("/SetUserSecret"), 0);
        let _ = body(response).await;
    }
    for case in 0..7 {
        source.reset();
        let mut rejected = headers.clone();
        let mut submitted_csrf = csrf.clone();
        match case {
            0 => {
                rejected.append(
                    header::COOKIE,
                    HeaderValue::from_static("codewire.session_token=second"),
                );
            }
            1 => {
                rejected.insert(
                    header::ORIGIN,
                    HeaderValue::from_static("https://other.example.test"),
                );
            }
            2 => {
                submitted_csrf = new_csrf_token();
            }
            3 => {
                source.identity.store(1, Ordering::SeqCst);
            }
            4 => {
                source.identity.store(2, Ordering::SeqCst);
            }
            5 => {
                rejected.insert(header::ORIGIN, HeaderValue::from_static("null"));
            }
            _ => {
                rejected.remove(header::ORIGIN);
            }
        }
        let response = set_action(
            State(state.clone()),
            rejected,
            parsed_query(Default::default()),
            set_form(&submitted_csrf, "account-1", "synthetic-private-value"),
        )
        .await;
        assert!(response.status().is_redirection() || response.status().is_client_error());
        assert_eq!(source.calls("/SetUserSecret"), 0);
        let _ = body(response).await;
        source.identity.store(0, Ordering::SeqCst);
    }
    server.abort();
}

#[tokio::test]
async fn uncertain_writes_reload_metadata_and_never_reflect_private_values() {
    let (state, source, server) = fixture().await;
    let (headers, csrf) = browser_headers();
    source.mutation.store(1, Ordering::SeqCst);
    let response = set_action(
        State(state.clone()),
        headers.clone(),
        parsed_query(Default::default()),
        set_form(&csrf, "account-1", "synthetic-private-value"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let rendered = body(response).await;
    assert!(rendered.contains("could not be confirmed"));
    assert!(!rendered.contains("synthetic-private-value"));
    assert!(!rendered.contains("synthetic-upstream-private-value"));
    assert_eq!(source.calls("/SetUserSecret"), 1);
    assert_eq!(source.calls("/ListUserSecrets"), 1);
    source.reset();
    let response = set_action(
        State(state.clone()),
        headers,
        parsed_query(Default::default()),
        set_form(&csrf, "account-1", ""),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(source.calls("/SetUserSecret"), 0);
    let _ = body(response).await;
    server.abort();
}

#[test]
fn personal_secret_views_escape_metadata_and_keep_forms_actor_bound() {
    let page = PersonalSecretsPageView {
        account_id: "account-1".into(),
        available: true,
        csrf_token: "synthetic-csrf".into(),
        secrets: vec![crate::view::SecretRow {
            key: "DATABASE_URL".into(),
            updated: "recently".into(),
        }],
        form: SecretFormView {
            key: "<unsafe>".into(),
            ..Default::default()
        },
        active_dialog: "add-secret".into(),
        ..Default::default()
    };
    let view = crate::view::DashboardView::default();
    assert!(!format!("{page:?}").contains("synthetic-csrf"));
    let rendered = SettingsSecretsTemplate {
        view: &view,
        page: &page,
    }
    .render()
    .unwrap();
    assert!(!rendered.contains("<unsafe>"));
    assert!(rendered.contains("&#60;unsafe&#62;") || rendered.contains("&lt;unsafe&gt;"));
    assert_eq!(
        rendered
            .matches("name=\"account_id\" value=\"account-1\"")
            .count(),
        8 // Four dialog forms and four native no-JavaScript forms.
    );
    assert_eq!(rendered.matches("data-dialog-private").count(), 4);
    for form in [
        "fallback-add-secret-form",
        "fallback-secret-1-value-form",
        "fallback-secret-1-rename-form",
        "fallback-secret-1-delete-form",
    ] {
        assert!(rendered.contains(&format!("id=\"{form}\"")));
    }
    assert!(rendered.contains("/settings/secrets/_actions/rename"));
    assert!(!rendered.contains("/secrets/user/"));
}

#[test]
fn recovery_uses_current_key_identity_not_stale_row_index_or_untrusted_dialog() {
    let mut page = PersonalSecretsPageView {
        available: true,
        active_dialog: "rename".into(),
        secrets: vec![crate::view::SecretRow {
            key: "CURRENT".into(),
            updated: String::new(),
        }],
        form: SecretFormView {
            key: "OLD".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    resolve_editor(&mut page);
    assert!(page.active_dialog.is_empty());
    page.form.key = "CURRENT".into();
    page.active_dialog = "value".into();
    resolve_editor(&mut page);
    assert_eq!(page.active_dialog, "secret-1-value");
    assert_eq!(approved_error("untrusted-provider-text"), "");
    assert_eq!(
        context_query("DATABASE_URL", &DraftReturn::NoRequest),
        "?cursor=DATABASE_URL"
    );
}

#[tokio::test]
async fn registered_personal_and_legacy_routes_share_private_extractors_and_user_only_writes() {
    let (state, source, authority_server) = fixture().await;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = super::super::router().with_state(state);
    let web_server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap();
    let (headers, csrf) = browser_headers();
    let legacy = "/inaccessible/secrets/user/";
    let response = client
        .get(format!("{origin}{legacy}"))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], PATH);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(source.calls("/ListOrganizations"), 0);
    for mode in [1, 2] {
        source.identity.store(mode, Ordering::SeqCst);
        let response = client
            .get(format!("{origin}{legacy}"))
            .headers(headers.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with(if mode == 1 { "/login" } else { "/setup-2fa" }));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    source.identity.store(0, Ordering::SeqCst);
    for path in [PATH, legacy] {
        for account in ["", "account-2"] {
            source.reset();
            let response = client.post(format!("{origin}{path}_actions/set"))
                .headers(headers.clone()).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={csrf}&account_id={account}&mode=add&key=DATABASE_URL&value=synthetic-private-canary"))
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(source.calls("/SetUserSecret"), 0);
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains("synthetic-private-canary")
            );
        }
        for body in [
            format!(
                "_csrf={csrf}&account_id=account-1&mode=add&key=DATABASE_URL&key=OTHER&value=synthetic-private-canary"
            ),
            format!(
                "_csrf={csrf}&account_id=account-1&mode=add&key=DATABASE_URL&value=synthetic-private-canary&unknown=private"
            ),
            format!("_csrf={csrf}&account_id=account-1&mode=add&value=synthetic-private-canary"),
        ] {
            source.reset();
            let response = client
                .post(format!("{origin}{path}_actions/set"))
                .headers(headers.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_client_error());
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(source.calls("/SetUserSecret"), 0);
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains("synthetic-private-canary")
            );
        }
        for (action, fields, rpc) in [
            (
                "set",
                "mode=add&key=DATABASE_URL&value=synthetic-private-canary",
                "/SetUserSecret",
            ),
            (
                "rename",
                "key=DATABASE_URL&new_key=DATABASE_NEW",
                "/RenameUserSecret",
            ),
            ("delete", "key=DATABASE_URL", "/DeleteUserSecret"),
        ] {
            source.reset();
            let response = client
                .post(format!("{origin}{path}_actions/{action}"))
                .headers(headers.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={csrf}&account_id=account-1&{fields}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(source.calls(rpc), 1);
            assert_eq!(source.calls("/ListOrganizations"), 0);
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains("synthetic-private-canary")
            );
        }
    }
    source.reset();
    let response = client
        .get(format!("{origin}{PATH}?cursor=FIRST&cursor=SECOND"))
        .headers(headers)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/settings/secrets/?error=invalid-page"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(source.calls("/ListUserSecrets"), 0);
    web_server.abort();
    authority_server.abort();
}

const DRAFT: &str = "00000000-0000-4000-8000-000000000003";

#[tokio::test]
async fn draft_query_is_closed_and_independent_of_ordinary_query_rejection() {
    for (raw, expected) in [
        (
            format!("org=allowed&creation_draft={DRAFT}"),
            DraftReturn::Exact(DRAFT.into()),
        ),
        (
            format!("creation%5Fdraft={DRAFT}"),
            DraftReturn::Exact(DRAFT.into()),
        ),
        ("creation_draft=not-a-draft".into(), DraftReturn::NoRequest),
        (
            format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
            DraftReturn::NoRequest,
        ),
        (
            format!("creation_draft={DRAFT}&creation%5Fdraft={DRAFT}"),
            DraftReturn::NoRequest,
        ),
        (
            format!("creation_draft={}", "x".repeat(1100)),
            DraftReturn::NoRequest,
        ),
        (
            format!("return_to=https%3A%2F%2Fforeign.example&creation_draft={DRAFT}"),
            DraftReturn::Exact(DRAFT.into()),
        ),
    ] {
        let (mut parts, _) = Request::builder()
            .uri(format!("{PATH}?{raw}"))
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let PersonalSecretQuery(query) = PersonalSecretQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(query.draft, expected);
        let closed = context_query(&query.cursor, &query.draft);
        assert!(!closed.contains("not-a-draft"));
        assert!(!closed.contains("return_to"));
        assert!(!closed.contains("foreign.example"));
        assert!(closed.matches("creation_draft=").count() <= 1);
    }
    for raw in ["org=allowed&org=other", "cursor=FIRST&cursor=SECOND"] {
        let (mut parts, _) = Request::builder()
            .uri(format!("{PATH}?{raw}&creation_draft={DRAFT}"))
            .body(Body::empty())
            .unwrap()
            .into_parts();
        assert!(
            PersonalSecretQuery::from_request_parts(&mut parts, &())
                .await
                .is_err()
        );
    }
    assert_eq!(
        context_query("DATABASE_URL", &DraftReturn::Exact(DRAFT.into())),
        format!("?cursor=DATABASE_URL&creation_draft={DRAFT}")
    );
}

async fn draft_route_fixture() -> (
    Source,
    String,
    reqwest::Client,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (state, source, authority_server) = fixture().await;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = super::super::router().with_state(state);
    let web_server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap();
    (source, origin, client, web_server, authority_server)
}

#[tokio::test]
async fn native_draft_pages_revalidate_org_and_preserve_paging_reload_and_nonmutating_return() {
    let (source, origin, client, web_server, authority_server) = draft_route_fixture().await;
    let (headers, _) = browser_headers();
    source.organizations.store(4, Ordering::SeqCst);
    source.inventory.store(1, Ordering::SeqCst);
    let response = client
        .get(format!(
            "{origin}{PATH}?org=allowed&cursor=AAA_PREVIOUS&creation_draft={DRAFT}"
        ))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let rendered = response.text().await.unwrap();
    assert!(rendered.contains(&format!(
        "href=\"/allowed/new/?creation_draft={DRAFT}\">Return to Create Sandbox</a>"
    )));
    assert!(rendered.contains(&format!(
        "href=\"{PATH}?creation_draft={DRAFT}\">First page</a>"
    )));
    assert!(rendered.contains(&format!(
        "href=\"{PATH}?cursor=KEY098&#38;creation_draft={DRAFT}\">Next page</a>"
    )));
    assert!(rendered.contains(&format!(
        "action=\"{PATH}_actions/set?cursor=AAA_PREVIOUS&#38;creation_draft={DRAFT}\""
    )));
    // Cancel remains a local dialog dismissal; the separate return anchor is
    // usable without submitting any form, including with JavaScript disabled.
    assert!(rendered.contains("type=\"button\" data-dialog-close>Cancel</button>"));
    assert!(
        rendered.find("Return to Create Sandbox</a>").unwrap()
            < rendered.find("<noscript>").unwrap()
    );
    for rpc in ["/SetUserSecret", "/RenameUserSecret", "/DeleteUserSecret"] {
        assert_eq!(source.calls(rpc), 0);
    }
    source.inventory.store(2, Ordering::SeqCst);
    let response = client
        .get(format!(
            "{origin}{PATH}?org=allowed&cursor=AAA_PREVIOUS&creation_draft={DRAFT}"
        ))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rendered = response.text().await.unwrap();
    assert!(rendered.contains("Return to Create Sandbox"));
    assert!(rendered.contains(&format!(
        "href=\"{PATH}?cursor=AAA_PREVIOUS&#38;creation_draft={DRAFT}\">Reload secrets</a>"
    )));
    assert!(!rendered.contains("id=\"add-secret-form\""));

    source.inventory.store(0, Ordering::SeqCst);
    for (mode, org, draft) in [
        (4, "foreign", DRAFT),
        (1, "allowed", DRAFT),
        (4, "", DRAFT),
        (4, "allowed", "invalid"),
    ] {
        source.organizations.store(mode, Ordering::SeqCst);
        source.reset();
        let response = client
            .get(format!("{origin}{PATH}?org={org}&creation_draft={draft}"))
            .headers(headers.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rendered = response.text().await.unwrap();
        assert!(!rendered.contains("Return to Create Sandbox"));
        assert!(rendered.contains("id=\"add-secret-form\""));
        assert_eq!(source.calls("/ListUserSecrets"), 1);
        if mode == 1 || org != "allowed" {
            assert_eq!(source.calls("/ListEnvironments"), 0);
            assert!(!rendered.contains("_actions/set?org="));
        }
    }
    let response = client
        .get(format!(
            "{origin}/allowed/secrets/user/?org=allowed&creation_draft={DRAFT}"
        ))
        .headers(headers)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], PATH);
    web_server.abort();
    authority_server.abort();
}

#[tokio::test]
async fn native_draft_writes_preserve_closed_feedback_without_an_organization_dependency() {
    let (source, origin, client, web_server, authority_server) = draft_route_fixture().await;
    let (headers, csrf) = browser_headers();
    for (org_mode, org, raw_draft, expected_draft) in [
        (4, "allowed", format!("creation_draft={DRAFT}"), true),
        (4, "foreign", format!("creation_draft={DRAFT}"), true),
        (1, "allowed", format!("creation_draft={DRAFT}"), true),
        (
            4,
            "allowed",
            "creation_draft=synthetic-invalid-marker".into(),
            false,
        ),
        (
            4,
            "allowed",
            format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
            false,
        ),
        (
            4,
            "allowed",
            format!("creation_draft={}", "x".repeat(1100)),
            false,
        ),
    ] {
        source.organizations.store(org_mode, Ordering::SeqCst);
        for (action, fields, rpc, message) in [
            (
                "set",
                "mode=add&key=DATABASE_URL&value=synthetic-private-canary",
                "/SetUserSecret",
                "secret-saved",
            ),
            (
                "rename",
                "key=DATABASE_URL&new_key=DATABASE_NEW",
                "/RenameUserSecret",
                "secret-renamed",
            ),
            (
                "delete",
                "key=DATABASE_URL",
                "/DeleteUserSecret",
                "secret-deleted",
            ),
        ] {
            source.reset();
            let response = client.post(format!("{origin}{PATH}_actions/{action}?org={org}&cursor=AAA_PREVIOUS&{raw_draft}&return_to=https%3A%2F%2Fforeign.example"))
                .headers(headers.clone()).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={csrf}&account_id=account-1&{fields}")).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let draft = if expected_draft {
                format!("&creation_draft={DRAFT}")
            } else {
                String::new()
            };
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("{PATH}?cursor=AAA_PREVIOUS{draft}&message={message}")
            );
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains("synthetic-private-canary")
            );
            assert_eq!(source.calls(rpc), 1);
            assert_eq!(source.calls("/ListOrganizations"), 0);
            assert_eq!(source.calls("/ListEnvironments"), 0);
        }
    }
    web_server.abort();
    authority_server.abort();
}

#[tokio::test]
async fn native_draft_validation_reopens_only_owning_editor_without_private_material() {
    let (source, origin, client, web_server, authority_server) = draft_route_fixture().await;
    let (headers, csrf) = browser_headers();
    for (org_mode, org, return_visible) in [
        (4, "allowed", true),
        (4, "foreign", false),
        (1, "allowed", false),
    ] {
        source.organizations.store(org_mode, Ordering::SeqCst);
        for (action, fields, editor) in [
            (
                "set",
                "mode=add&key=INVALID-KEY&value=synthetic-private-canary",
                "add-secret",
            ),
            (
                "set",
                "mode=replace&key=DATABASE_URL&value=",
                "secret-1-value",
            ),
            (
                "rename",
                "key=DATABASE_URL&new_key=DATABASE_URL",
                "secret-1-rename",
            ),
        ] {
            source.reset();
            let response = client.post(format!("{origin}{PATH}_actions/{action}?org={org}&cursor=AAA_PREVIOUS&creation_draft={DRAFT}"))
                .headers(headers.clone()).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={csrf}&account_id=account-1&{fields}")).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let rendered = response.text().await.unwrap();
            assert!(rendered.contains(&format!(
                "id=\"{editor}\" aria-labelledby=\"{editor}-title\" data-dialog-auto-open"
            )));
            assert_eq!(
                rendered.contains("Return to Create Sandbox"),
                return_visible
            );
            assert!(rendered.contains(&format!("cursor=AAA_PREVIOUS&#38;creation_draft={DRAFT}")));
            assert!(rendered.contains("id=\"fallback-add-secret-form\""));
            assert!(rendered.contains("type=\"button\" data-dialog-close>Cancel</button>"));
            assert!(!rendered.contains("synthetic-private-canary"));
            assert!(!rendered.contains("synthetic-upstream-private-value"));
            for rpc in ["/SetUserSecret", "/RenameUserSecret", "/DeleteUserSecret"] {
                assert_eq!(source.calls(rpc), 0);
            }
        }
    }
    source.organizations.store(4, Ordering::SeqCst);
    source.mutation.store(1, Ordering::SeqCst);
    for (action, fields, rpc) in [
        (
            "set",
            "mode=add&key=DATABASE_URL&value=synthetic-private-canary",
            "/SetUserSecret",
        ),
        (
            "rename",
            "key=DATABASE_URL&new_key=DATABASE_NEW",
            "/RenameUserSecret",
        ),
        ("delete", "key=DATABASE_URL", "/DeleteUserSecret"),
    ] {
        source.reset();
        let response = client
            .post(format!(
                "{origin}{PATH}_actions/{action}?org=allowed&creation_draft={DRAFT}"
            ))
            .headers(headers.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("_csrf={csrf}&account_id=account-1&{fields}"))
            .send()
            .await
            .unwrap();
        if action == "delete" {
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("{PATH}?creation_draft={DRAFT}&error=outcome-unknown")
            );
        } else {
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        let rendered = response.text().await.unwrap();
        if action != "delete" {
            assert!(rendered.contains("could not be confirmed"));
            assert!(rendered.contains("Return to Create Sandbox"));
            assert!(rendered.contains(&format!("creation_draft={DRAFT}")));
        }
        assert!(!rendered.contains("synthetic-private-canary"));
        assert!(!rendered.contains("synthetic-upstream-private-value"));
        assert_eq!(source.calls(rpc), 1);
    }
    web_server.abort();
    authority_server.abort();
}

#[tokio::test]
async fn malformed_draft_does_not_bypass_native_write_authentication_or_form_guards() {
    let (source, origin, client, web_server, authority_server) = draft_route_fixture().await;
    let (headers, csrf) = browser_headers();
    for case in 0..8 {
        source.reset();
        let mut submitted = headers.clone();
        let mut token = csrf.clone();
        let mut account = "account-1";
        match case {
            0 => {
                submitted.append(
                    header::COOKIE,
                    HeaderValue::from_static("codewire.session_token=second"),
                );
            }
            1 => {
                submitted.insert(
                    header::ORIGIN,
                    HeaderValue::from_static("https://foreign.example"),
                );
            }
            2 => {
                token = new_csrf_token();
            }
            3 => {
                account = "account-2";
            }
            4 => {
                source.identity.store(1, Ordering::SeqCst);
            }
            5 => {
                source.identity.store(2, Ordering::SeqCst);
            }
            6 => {
                submitted.insert(header::ORIGIN, HeaderValue::from_static("null"));
            }
            _ => {
                submitted.remove(header::ORIGIN);
            }
        }
        for (action, fields, rpc) in [
            (
                "set",
                "mode=add&key=DATABASE_URL&value=synthetic-private-canary",
                "/SetUserSecret",
            ),
            (
                "rename",
                "key=DATABASE_URL&new_key=DATABASE_NEW",
                "/RenameUserSecret",
            ),
            ("delete", "key=DATABASE_URL", "/DeleteUserSecret"),
        ] {
            let response = client.post(format!("{origin}{PATH}_actions/{action}?org=allowed&creation_draft={DRAFT}&creation_draft=invalid"))
                .headers(submitted.clone()).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("_csrf={token}&account_id={account}&{fields}")).send().await.unwrap();
            assert!(response.status().is_client_error() || response.status().is_redirection());
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if let Some(location) = response.headers().get(header::LOCATION) {
                assert!(!location.to_str().unwrap().contains("creation_draft"));
            }
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains("synthetic-private-canary")
            );
            assert_eq!(source.calls(rpc), 0);
        }
        assert_eq!(source.calls("/ListOrganizations"), 0);
        source.identity.store(0, Ordering::SeqCst);
    }
    for raw in ["org=allowed&org=other", "cursor=FIRST&cursor=SECOND"] {
        source.reset();
        let response = client.post(format!("{origin}{PATH}_actions/set?{raw}&creation_draft={DRAFT}"))
            .headers(headers.clone()).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("_csrf={csrf}&account_id=account-1&mode=add&key=DATABASE_URL&value=synthetic-private-canary")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(source.calls("/SetUserSecret"), 0);
    }
    web_server.abort();
    authority_server.abort();
}
