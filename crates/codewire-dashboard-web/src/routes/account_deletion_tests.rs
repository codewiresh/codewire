//! Registered-route proof for Account › Delete account (#3679) against a
//! synthetic identity and account service. No real account is deleted.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::console::v1::{
    AccountDeletionOrganization, DeleteAccountRequest, DeleteAccountResponse,
    GetAccountDeletionPlanResponse,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ACCOUNT: &str = "synthetic-account";
const EMAIL: &str = "synthetic.owner@example.test";
const PAGE: &str = "/settings/delete-account/";
const ACTION: &str = "/settings/_actions/delete-account";
const DELETE_RPC: &str = "/codewire.console.v1.AccountService/DeleteAccount";

type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

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

fn config(upstream: &str) -> crate::Config {
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: ORIGIN.into(),
        api_origin: upstream.parse().unwrap(),
        credential_origin: upstream.parse().unwrap(),
        identity_origin_string: upstream.into(),
        browser_api_origin: ORIGIN.into(),
        billing_origin: upstream.parse().unwrap(),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
    }
}

fn proto(message: impl buffa::Message) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
}

fn organization(
    name: &str,
    slug: &str,
    members: i64,
    environments: i64,
) -> AccountDeletionOrganization {
    AccountDeletionOrganization {
        id: format!("org-{slug}"),
        name: name.into(),
        slug: slug.into(),
        role: "owner".into(),
        member_count: members,
        environment_count: environments,
        ..Default::default()
    }
}

/// The synthetic services: an enrolled account, a deletion plan with or
/// without a blocking organization, and a DeleteAccount answer by `mode`.
async fn upstream(mode: &'static str) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push((path.clone(), body.to_vec()));
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {
                    "id": ACCOUNT, "email": EMAIL, "two_factor_enabled": true
                }}))
                .into_response();
            }
            if path.ends_with("/ListOrganizations") {
                return (
                    [(header::CONTENT_TYPE, "application/proto")],
                    Vec::<u8>::new(),
                )
                    .into_response();
            }
            if path.ends_with("/GetAccountDeletionPlan") {
                let mut plan = GetAccountDeletionPlanResponse {
                    email: EMAIL.into(),
                    personal_organizations: vec![organization("Solo Lab", "solo-lab", 1, 2)],
                    forfeited_credit_nano_eur: 37_500_000_000,
                    ..Default::default()
                };
                if mode == "blocked" {
                    plan.blocking_organizations = vec![organization("Team", "team", 3, 0)];
                }
                return proto(plan);
            }
            if path == DELETE_RPC {
                let failure = |status: StatusCode, code: &str| -> Response {
                    (
                        status,
                        Json(
                            serde_json::json!({"code": code, "message": "upstream-private-canary"}),
                        ),
                    )
                        .into_response()
                };
                return match mode {
                    "success" => proto(DeleteAccountResponse {
                        operation_id: "account-deletion/synthetic".into(),
                        ..Default::default()
                    }),
                    "blocked" => failure(StatusCode::BAD_REQUEST, "failed_precondition"),
                    "mismatch" => failure(StatusCode::BAD_REQUEST, "invalid_argument"),
                    _ => failure(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                };
            }
            (StatusCode::NOT_FOUND, "unexpected").into_response()
        }
    }));
    (serve(router).await, calls)
}

fn authority(csrf: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(
        header::COOKIE,
        format!("codewire.session_token=synthetic-session; codewire_ssr_csrf={csrf}")
            .parse()
            .unwrap(),
    );
    headers
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

struct Page {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

async fn send(request: reqwest::RequestBuilder) -> Page {
    let response = request.send().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    Page {
        status,
        headers,
        body,
    }
}

async fn post(dashboard: &TestServer, headers: HeaderMap, form: &[(&str, &str)]) -> Page {
    send(
        client()
            .post(format!("{}{ACTION}", dashboard.origin))
            .headers(headers)
            .form(form),
    )
    .await
}

fn form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("account_id", ACCOUNT),
        ("confirm_email", EMAIL),
    ]
}

fn delete_calls(calls: &Calls) -> Vec<Vec<u8>> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == DELETE_RPC)
        .map(|(_, body)| body.clone())
        .collect()
}

fn assert_private(page: &Page) {
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers[header::VARY], "Cookie");
    assert!(!page.body.contains("upstream-private-canary"));
}

#[tokio::test]
async fn the_page_lists_what_goes_and_asks_for_the_typed_email() {
    let (services, _) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = send(
        client()
            .get(format!("{}{PAGE}", dashboard.origin))
            .headers(authority(&csrf)),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    for text in [
        "Solo Lab",
        "2 environments deleted with it",
        "The remaining credit of €37.50 is forfeited.",
        "pattern=\"synthetic\\.owner@example\\.test\"",
        "action=\"/settings/_actions/delete-account\"",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }

    let (services, _) = upstream("blocked").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let page = send(
        client()
            .get(format!("{}{PAGE}", dashboard.origin))
            .headers(authority(&csrf)),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains("Transfer or delete these organizations first")
    );
    assert!(page.body.contains("href=\"/team/members/\""));
    assert!(
        !page
            .body
            .contains("action=\"/settings/_actions/delete-account\"")
    );
}

#[tokio::test]
async fn a_confirmed_deletion_ends_the_browser_session_and_says_it_started() {
    let (services, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, authority(&csrf), &form(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    assert!(page.body.contains("Your account is being deleted"));
    let cleared = page
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|cookie| {
            let cookie = cookie.to_str().unwrap();
            cookie.starts_with("codewire.session_token=") && cookie.contains("Max-Age=0")
        });
    assert!(cleared, "{:?}", page.headers);
    let deletes = delete_calls(&calls);
    assert_eq!(deletes.len(), 1);
    let request = DeleteAccountRequest::decode_from_slice(&deletes[0]).unwrap();
    assert_eq!(request.confirm_email, EMAIL);
}

#[tokio::test]
async fn refusals_return_to_the_page_and_boundaries_never_delete() {
    let csrf = crate::security::new_csrf_token();
    for (mode, location) in [
        ("blocked", PAGE.to_owned()),
        ("mismatch", format!("{PAGE}?error=email-mismatch")),
        ("unavailable", format!("{PAGE}?error=request-failed")),
    ] {
        let (services, _) = upstream(mode).await;
        let dashboard = serve(crate::app(config(&services.origin))).await;
        let page = post(&dashboard, authority(&csrf), &form(&csrf)).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER, "{mode}");
        assert_eq!(page.headers[header::LOCATION], location.as_str(), "{mode}");
        assert_private(&page);
    }

    let (services, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let mut no_origin = authority(&csrf);
    no_origin.remove(header::ORIGIN);
    let mut foreign_origin = authority(&csrf);
    foreign_origin.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
    for (case, headers) in [("no origin", no_origin), ("foreign origin", foreign_origin)] {
        let page = post(&dashboard, headers, &form(&csrf)).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{case}");
    }
    let mut wrong_csrf = form(&csrf);
    wrong_csrf[0].1 = "wrong-csrf";
    let page = post(&dashboard, authority(&csrf), &wrong_csrf).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let mut extra = form(&csrf);
    extra.push(("organization", "org-team"));
    let page = post(&dashboard, authority(&csrf), &extra).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let mut foreign_account = form(&csrf);
    foreign_account[1].1 = "another-account";
    let page = post(&dashboard, authority(&csrf), &foreign_account).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        format!("{PAGE}?error=account-changed").as_str()
    );
    let mut empty = form(&csrf);
    empty[2].1 = "  ";
    let page = post(&dashboard, authority(&csrf), &empty).await;
    assert_eq!(
        page.headers[header::LOCATION],
        format!("{PAGE}?error=email-mismatch").as_str()
    );
    assert!(
        delete_calls(&calls).is_empty(),
        "a refused request reached DeleteAccount"
    );
}
