use super::*;
use crate::security::new_csrf_token;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Request,
    response::IntoResponse,
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    CreateApiKeyRequest, CreateApiKeyResponse, DeleteApiKeyRequest, DeleteApiKeyResponse,
    ListApiKeysRequest, ListApiKeysResponse, ListEnvironmentsResponse, ListOrganizationsResponse,
    OrgRole, Organization, OrganizationMembership, UpdateApiKeyRequest, UpdateApiKeyResponse,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
struct Source {
    identity: Arc<AtomicUsize>,
    membership: Arc<AtomicUsize>,
    role: Arc<AtomicUsize>,
    keys: Arc<AtomicUsize>,
    mutation: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl Source {
    fn count(&self, suffix: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with(suffix))
            .count()
    }
    fn reset(&self) {
        self.calls.lock().unwrap().clear();
    }
    fn mutations(&self) -> usize {
        self.count("/CreateApiKey") + self.count("/UpdateApiKey") + self.count("/DeleteApiKey")
    }
}

fn proto(message: impl buffa::Message) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
}

fn failure(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"code":code,"message":"upstream-private-canary"})),
    )
        .into_response()
}

fn key(id: &str, org: &str, user: &str) -> ApiKey {
    ApiKey {
        id: id.into(),
        org_id: org.into(),
        user_id: user.into(),
        name: format!("Name-{id}"),
        key_prefix: "12345678".into(),
        created_at: Some(Default::default()).into(),
        ..Default::default()
    }
}

async fn fixture() -> (AppState, Source, tokio::task::JoinHandle<()>) {
    let source = Source::default();
    let owner = source.clone();
    let router = Router::new().fallback(any(move |request: Request| {
        let source = owner.clone();
        async move {
            let path = request.uri().path().to_owned();
            source.calls.lock().unwrap().push(path.clone());
            assert_eq!(request.headers()[header::COOKIE], "codewire.session_token=synthetic");
            assert!(!request.headers().contains_key(header::AUTHORIZATION));
            if path == "/api/auth/get-session" {
                return Json(match source.identity.load(Ordering::SeqCst) {
                    1 => serde_json::Value::Null,
                    value => serde_json::json!({"user":{"id":"account-1","email":"owner@example.test","name":"Synthetic owner","two_factor_enabled":value != 2}}),
                }).into_response();
            }
            if path.ends_with("/ListOrganizations") {
                let count = match source.membership.load(Ordering::SeqCst) {
                    1 => return failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    2 => return failure(StatusCode::UNAUTHORIZED, "unauthenticated"),
                    3 => return failure(StatusCode::FORBIDDEN, "permission_denied"),
                    4 => 0, 5 => 21, _ => 1,
                };
                return proto(ListOrganizationsResponse { organizations: (0..count).map(|index| OrganizationMembership {
                    organization: Some(Organization { id: format!("org-{index:02}"), slug: format!("synthetic-{index:02}"), name: format!("Synthetic {index:02}"), ..Default::default() }).into(),
                    role: if source.role.load(Ordering::SeqCst) == 1 { OrgRole::Member.into() } else { OrgRole::Owner.into() },
                    ..Default::default()
                }).collect(), ..Default::default() });
            }
            if path.ends_with("/ListEnvironments") { return proto(ListEnvironmentsResponse::default()); }
            if path.ends_with("/ListApiKeys") {
                let bytes = to_bytes(request.into_body(), 8192).await.unwrap();
                let request = ListApiKeysRequest::decode_from_slice(&bytes).unwrap();
                assert_eq!(request.page_size, 0); assert!(request.page_token.is_empty());
                let active = source.active.fetch_add(1, Ordering::SeqCst) + 1;
                source.peak.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                source.active.fetch_sub(1, Ordering::SeqCst);
                let keys = match source.keys.load(Ordering::SeqCst) {
                    1 => return failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    2 => return failure(StatusCode::FORBIDDEN, "permission_denied"),
                    3 => return failure(StatusCode::UNAUTHORIZED, "unauthenticated"),
                    4 => vec![key("wrong", "foreign-org", "account-1")],
                    6 => {
                        let mut oversized = key("oversized", &request.org_id, "account-1");
                        oversized.name = "x".repeat(1024 * 1024);
                        vec![oversized]
                    }
                    5 => (0..150).map(|index| key(&format!("other-{index:03}"), &request.org_id, "account-2"))
                        .chain((0..101).map(|index| key(&format!("own-{index:03}"), &request.org_id, "account-1"))).collect(),
                    _ => vec![key("own", &request.org_id, "account-1"), key("foreign", &request.org_id, "account-2")],
                };
                return proto(ListApiKeysResponse { api_keys: keys, ..Default::default() });
            }
            if path.ends_with("/CreateApiKey") {
                let bytes = to_bytes(request.into_body(), 8192).await.unwrap();
                let request = CreateApiKeyRequest::decode_from_slice(&bytes).unwrap();
                assert_eq!(request.org_id, "org-00"); assert!(request.scopes.is_empty());
                let mut metadata = key("created", &request.org_id, "account-1");
                metadata.name = request.name;
                if request.expires_in_days.is_some() { metadata.expires_at = Some(Default::default()).into(); }
                match source.mutation.load(Ordering::SeqCst) {
                    1 => { source.membership.store(1, Ordering::SeqCst); source.keys.store(1, Ordering::SeqCst); }
                    2 => return failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    3 => metadata.user_id = "foreign-user".into(),
                    _ => {}
                }
                return proto(CreateApiKeyResponse { api_key: Some(metadata).into(), key: format!("cw_12345678{}", "a".repeat(56)), ..Default::default() });
            }
            if path.ends_with("/UpdateApiKey") {
                let bytes = to_bytes(request.into_body(), 8192).await.unwrap();
                let request = UpdateApiKeyRequest::decode_from_slice(&bytes).unwrap();
                let mut metadata = key(&request.key_id, &request.org_id, "account-1");
                if request.disabled == Some(true) { metadata.disabled_at = Some(Default::default()).into(); }
                return proto(UpdateApiKeyResponse { api_key: Some(metadata).into(), ..Default::default() });
            }
            if path.ends_with("/DeleteApiKey") {
                let bytes = to_bytes(request.into_body(), 8192).await.unwrap();
                let request = DeleteApiKeyRequest::decode_from_slice(&bytes).unwrap();
                assert_eq!(request.org_id, "org-00");
                return proto(DeleteApiKeyResponse::default());
            }
            StatusCode::NOT_FOUND.into_response()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

fn headers() -> (HeaderMap, String) {
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

fn query() -> Result<Query<PageQuery>, QueryRejection> {
    Ok(Query(PageQuery::default()))
}

fn create(csrf: &str) -> Result<Form<CreateForm>, FormRejection> {
    Ok(Form(CreateForm {
        csrf: csrf.into(),
        account_id: "account-1".into(),
        org_id: "org-00".into(),
        name: "Synthetic key".into(),
        expiration: "never".into(),
    }))
}

fn toggle(
    csrf: &str,
    account: &str,
    org: &str,
    key: &str,
) -> Result<Form<ToggleForm>, FormRejection> {
    Ok(Form(ToggleForm {
        csrf: csrf.into(),
        account_id: account.into(),
        org_id: org.into(),
        key_id: key.into(),
        disabled: true,
    }))
}

fn delete(
    csrf: &str,
    account: &str,
    org: &str,
    key: &str,
) -> Result<Form<DeleteForm>, FormRejection> {
    Ok(Form(DeleteForm {
        csrf: csrf.into(),
        account_id: account.into(),
        org_id: org.into(),
        key_id: key.into(),
    }))
}

async fn body(response: Response) -> String {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::VARY], "Cookie");
    assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
    let text = String::from_utf8(
        to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!text.contains("upstream-private-canary"));
    text
}

#[tokio::test]
async fn personal_api_keys_open_without_selected_org_and_never_render_other_actors() {
    let (state, source, server) = fixture().await;
    let (headers, _) = headers();
    let response = page(State(state.clone()), headers.clone(), query()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await;
    assert!(html.contains("Name-own"));
    assert!(!html.contains("Name-foreign"));
    assert_eq!(source.count("/ListOrganizations"), 1);
    assert_eq!(source.count("/ListEnvironments"), 0);
    for mode in [1, 4] {
        source.membership.store(mode, Ordering::SeqCst);
        source.reset();
        let response = page(State(state.clone()), headers.clone(), query()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!body(response).await.contains("Name-own"));
        assert_eq!(source.count("/ListApiKeys"), 0);
    }
    server.abort();
}

#[tokio::test]
async fn personal_api_key_auth_and_permission_errors_never_degrade_to_empty() {
    let (state, source, server) = fixture().await;
    let (headers, _) = headers();
    for membership in [2, 3] {
        source.membership.store(membership, Ordering::SeqCst);
        let response = page(State(state.clone()), headers.clone(), query()).await;
        assert!(
            response.status() == StatusCode::SEE_OTHER
                || response.status() == StatusCode::FORBIDDEN
        );
        body(response).await;
    }
    source.membership.store(0, Ordering::SeqCst);
    for mode in [2, 3] {
        source.keys.store(mode, Ordering::SeqCst);
        let response = page(State(state.clone()), headers.clone(), query()).await;
        assert!(
            response.status() == StatusCode::SEE_OTHER
                || response.status() == StatusCode::FORBIDDEN
        );
        body(response).await;
    }
    for mode in [1, 4, 6] {
        source.keys.store(mode, Ordering::SeqCst);
        let context = context(&state, &headers, &PageQuery::default(), None)
            .await
            .unwrap_or_else(|_| panic!("context"));
        let mut groups = vec![PersonalApiKeyGroupView {
            organization: context.view.organizations[0].clone(),
            keys: Vec::new(),
            available: false,
            truncated: false,
        }];
        load_groups(&state, &context.cookie, &context.account_id, &mut groups)
            .await
            .unwrap();
        assert!(!groups[0].available);
        assert!(groups[0].keys.is_empty());
    }
    server.abort();
}

#[tokio::test]
async fn personal_api_key_forms_bind_exact_origin_session_and_actor_before_product_reads() {
    let (state, source, server) = fixture().await;
    let (base, csrf) = headers();
    for mode in 0..7 {
        let mut headers = base.clone();
        match mode {
            0 => {
                headers.remove(header::ORIGIN);
            }
            1 => {
                headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
            }
            2 => {
                headers.insert(
                    header::ORIGIN,
                    HeaderValue::from_static("https://foreign.example.test"),
                );
            }
            3 => {
                headers.append(
                    header::COOKIE,
                    HeaderValue::from_static("codewire.session_token=other"),
                );
            }
            4 => {
                headers.insert(
                    header::AUTHORIZATION,
                    HeaderValue::from_static("Bearer unrelated"),
                );
            }
            _ => {}
        }
        let account = if mode == 6 { "account-2" } else { "account-1" };
        let csrf = if mode == 5 { "bad" } else { &csrf };
        source.reset();
        let response = toggle_action(
            State(state.clone()),
            headers,
            query(),
            toggle(csrf, account, "org-00", "own"),
        )
        .await;
        assert_ne!(response.status(), StatusCode::OK);
        body(response).await;
        assert_eq!(source.count("/ListOrganizations"), 0);
        assert_eq!(source.mutations(), 0);
    }
    for mode in [1, 2] {
        source.identity.store(mode, Ordering::SeqCst);
        source.reset();
        let response =
            create_action(State(state.clone()), base.clone(), query(), create(&csrf)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        body(response).await;
        assert_eq!(source.count("/ListOrganizations"), 0);
        assert_eq!(source.mutations(), 0);
    }
    server.abort();
}

#[tokio::test]
async fn personal_api_key_create_is_member_eligible_and_never_loses_key_to_post_create_reads() {
    let (state, source, server) = fixture().await;
    let (headers, csrf) = headers();
    source.role.store(1, Ordering::SeqCst);
    source.mutation.store(1, Ordering::SeqCst);
    let response = create_action(
        State(state.clone()),
        headers.clone(),
        query(),
        create(&csrf),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await;
    assert_eq!(
        html.matches(&format!("cw_12345678{}", "a".repeat(56)))
            .count(),
        1
    );
    assert!(html.contains("hx-history=\"false\""));
    assert!(html.contains("data-one-time-api-key"));
    assert_eq!(source.count("/CreateApiKey"), 1);
    assert_eq!(source.count("/ListApiKeys"), 0);
    assert_eq!(source.count("/ListOrganizations"), 1);
    assert!(
        source
            .calls
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .ends_with("/CreateApiKey")
    );
    let response = page(State(state), headers, query()).await;
    assert!(!body(response).await.contains(&"a".repeat(56)));
    server.abort();
}

#[tokio::test]
async fn personal_api_key_uncertain_create_uses_prg_without_a_resubmittable_form() {
    let (state, source, server) = fixture().await;
    let (headers, csrf) = headers();
    for mode in [2, 3] {
        source.mutation.store(mode, Ordering::SeqCst);
        source.reset();
        let response = create_action(
            State(state.clone()),
            headers.clone(),
            query(),
            create(&csrf),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .ends_with("error=create-outcome-unknown")
        );
        assert!(!body(response).await.contains("<form"));
        assert_eq!(source.count("/CreateApiKey"), 1);
        assert_eq!(source.count("/ListApiKeys"), 0);
    }
    server.abort();
}

#[tokio::test]
async fn personal_api_key_actions_recheck_membership_admin_and_full_key_ownership() {
    let (state, source, server) = fixture().await;
    let (headers, csrf) = headers();
    for (org, key) in [
        ("foreign-org", "own"),
        ("org-00", "foreign"),
        ("org-00", "../../own"),
    ] {
        source.reset();
        let response = toggle_action(
            State(state.clone()),
            headers.clone(),
            query(),
            toggle(&csrf, "account-1", org, key),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        body(response).await;
        let response = delete_action(
            State(state.clone()),
            headers.clone(),
            query(),
            delete(&csrf, "account-1", org, key),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        body(response).await;
        assert_eq!(source.mutations(), 0);
    }
    source.role.store(1, Ordering::SeqCst);
    source.reset();
    let response = delete_action(
        State(state.clone()),
        headers.clone(),
        query(),
        delete(&csrf, "account-1", "org-00", "own"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    body(response).await;
    assert_eq!(source.count("/ListApiKeys"), 0);
    assert_eq!(source.mutations(), 0);
    source.membership.store(4, Ordering::SeqCst);
    source.reset();
    let response = toggle_action(
        State(state.clone()),
        headers.clone(),
        query(),
        toggle(&csrf, "account-1", "org-00", "own"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    body(response).await;
    assert_eq!(source.count("/ListApiKeys"), 0);
    assert_eq!(source.mutations(), 0);
    source.membership.store(0, Ordering::SeqCst);
    source.role.store(0, Ordering::SeqCst);
    source.keys.store(5, Ordering::SeqCst);
    let context = context(&state, &headers, &PageQuery::default(), None)
        .await
        .unwrap_or_else(|_| panic!("context"));
    let mut groups = vec![PersonalApiKeyGroupView {
        organization: context.view.organizations[0].clone(),
        keys: Vec::new(),
        available: false,
        truncated: false,
    }];
    load_groups(&state, &context.cookie, &context.account_id, &mut groups)
        .await
        .unwrap();
    assert!(groups[0].truncated);
    assert_eq!(groups[0].keys.len(), 100);
    assert!(
        groups[0]
            .keys
            .iter()
            .all(|row| row.key.id.starts_with("own-"))
    );
    source.reset();
    let response = toggle_action(
        State(state.clone()),
        headers.clone(),
        query(),
        toggle(&csrf, "account-1", "org-00", "own-100"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    body(response).await;
    let response = delete_action(
        State(state),
        headers,
        query(),
        delete(&csrf, "account-1", "org-00", "own-100"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    body(response).await;
    assert_eq!(source.count("/UpdateApiKey"), 1);
    assert_eq!(source.count("/DeleteApiKey"), 1);
    server.abort();
}

#[tokio::test]
async fn personal_api_key_inventory_pages_organizations_and_bounds_concurrent_reads() {
    let (state, source, server) = fixture().await;
    let (headers, _) = headers();
    source.membership.store(5, Ordering::SeqCst);
    let response = page(State(state.clone()), headers.clone(), query()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body(response).await.contains("cursor=org-19"));
    assert_eq!(source.count("/ListApiKeys"), 20);
    assert!((2..=LIST_CONCURRENCY).contains(&source.peak.load(Ordering::SeqCst)));
    source.reset();
    let response = page(
        State(state),
        headers,
        Ok(Query(PageQuery {
            cursor: "org-19".into(),
            ..Default::default()
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await;
    assert_eq!(source.count("/ListApiKeys"), 1);
    server.abort();
}

#[tokio::test]
async fn personal_api_key_inventory_deadline_leaves_unfinished_groups_unavailable() {
    let (state, source, server) = fixture().await;
    let (headers, _) = headers();
    source.membership.store(5, Ordering::SeqCst);
    let context = context(&state, &headers, &PageQuery::default(), None)
        .await
        .unwrap_or_else(|_| panic!("context"));
    let mut groups: Vec<_> = context
        .view
        .organizations
        .into_iter()
        .take(20)
        .map(|organization| PersonalApiKeyGroupView {
            organization,
            keys: Vec::new(),
            available: false,
            truncated: false,
        })
        .collect();
    assert_eq!(INVENTORY_BUDGET, Duration::from_secs(10));
    load_groups_until(
        &state,
        &context.cookie,
        &context.account_id,
        &mut groups,
        Instant::now() + Duration::from_millis(1),
    )
    .await
    .unwrap();
    assert!(
        groups
            .iter()
            .all(|group| !group.available && group.keys.is_empty())
    );
    assert!(source.count("/ListApiKeys") <= LIST_CONCURRENCY);
    server.abort();
}

#[tokio::test]
async fn personal_api_key_http_forms_reject_duplicates_unknown_fields_and_oversized_bodies() {
    let (state, source, server) = fixture().await;
    let router = super::super::router().with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let dashboard = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let (headers, csrf) = headers();
    for extra in [
        "&account_id=account-2".into(),
        "&unexpected=private-canary".into(),
        format!("&padding={}", "x".repeat(9000)),
    ] {
        source.reset();
        let response = client
            .post(format!("{origin}{PATH}_actions/create"))
            .headers(headers.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "_csrf={csrf}&account_id=account-1&org_id=org-00&name=Test&expiration=never{extra}"
            ))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.text().await.unwrap().contains("private-canary"));
        assert_eq!(source.mutations(), 0);
        assert_eq!(source.count("/ListOrganizations"), 0);
    }
    dashboard.abort();
    server.abort();
}

#[tokio::test]
async fn personal_api_key_filters_narrow_rows_and_ignore_unlisted_organizations() {
    let (state, _source, server) = fixture().await;
    let (headers, _) = headers();
    let filtered = |search: &str, organization: &str| {
        Ok(Query(PageQuery {
            search: search.into(),
            organization: organization.into(),
            ..Default::default()
        }))
    };
    let html = body(
        page(
            State(state.clone()),
            headers.clone(),
            filtered("no-such-key", ""),
        )
        .await,
    )
    .await;
    assert!(!html.contains("Name-own"));
    assert!(html.contains("No API keys match these filters."));
    // An organization outside this page never narrows or widens the inventory.
    let html = body(
        page(
            State(state.clone()),
            headers.clone(),
            filtered("", "not-a-listed-organization"),
        )
        .await,
    )
    .await;
    assert!(html.contains("Name-own"));
    assert!(!html.contains("Name-foreign"));
    assert!(!html.contains("Clear filters"));
    server.abort();
}
