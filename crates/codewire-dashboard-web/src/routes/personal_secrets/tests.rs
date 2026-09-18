use super::*;
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
                return proto_response(ListUserSecretsResponse { secrets: vec![SecretMetadata { key: "DATABASE_URL".into(), ..Default::default() }], ..Default::default() });
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
        confidential_admin_only: true,
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

fn parsed_query(value: PageQuery) -> Result<Query<PageQuery>, QueryRejection> {
    Ok(Query(value))
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
        assert!(view.global_context_query.is_empty());
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
        context_query("allowed", "DATABASE_URL"),
        "?org=allowed&cursor=DATABASE_URL"
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
        .timeout(std::time::Duration::from_secs(5))
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
