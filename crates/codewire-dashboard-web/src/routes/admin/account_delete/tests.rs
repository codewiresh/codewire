//! Registered-route proof for an admin's "Delete account" (#4541) against a
//! synthetic identity service. No real account, password or code is used,
//! and nothing is deleted.

use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ADMIN: &str = "synthetic-admin";
const OTHER_ADMIN: &str = "synthetic-other-admin";
const MEMBER: &str = "synthetic-member";
/// An account whose deletion is already running (#5769).
const DELETING: &str = "synthetic-deleting";
const MEMBER_EMAIL: &str = "synthetic.member@example.test";
const ACTION: &str = "/admin/accounts/_actions/delete";
const CAP: &str = "at most 10 account deletions an hour; try again after 14:05:00 UTC";

/// What the synthetic IdP received: method, path, Origin and body.
type Calls = Arc<Mutex<Vec<(String, String, Option<String>, Vec<u8>)>>>;

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
        support_email: None,
        updates_site: None,
    }
}

fn account(id: &str, is_admin: bool) -> Value {
    json!({
        "id": id, "email": format!("{id}@example.test"), "name": id,
        "emailVerified": true, "enabled": true, "isAdmin": is_admin,
        "accessReason": null, "createdAt": "2026-11-15T09:00:00",
        "linkedIdentities": [],
    })
}

/// The plan for `mode`: what goes, and what the mode says is in the way.
fn plan(mode: &str) -> Value {
    json!({
        "email": MEMBER_EMAIL,
        "name": "Synthetic member",
        "isAdmin": mode == "admin",
        "personalOrganizations": [{"name": "Solo Lab", "sandboxes": 2}],
        "sharedOrganizations": ["Shared Team"],
        "blockingOrganizations": if mode == "blocked" { json!(["Owned Team"]) } else { json!([]) },
        "deletionRunning": mode == "running",
    })
}

fn failure(status: StatusCode, code: &str, detail: &str) -> Response {
    (status, Json(json!({"code": code, "detail": detail}))).into_response()
}

/// The deletion's answer for `mode`. A refusal's detail is a canary the page
/// must never show, except the hourly cap's sentence.
fn deletion(mode: &str) -> Response {
    let canary = "upstream-private-canary";
    match mode {
        "proof" => failure(StatusCode::UNPROCESSABLE_ENTITY, "proof_rejected", canary),
        "locked" => failure(StatusCode::TOO_MANY_REQUESTS, "account_locked", canary),
        "limited" => failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited", CAP),
        "address" | "admin" | "blocked" => failure(StatusCode::BAD_REQUEST, "", canary),
        "gone" => failure(StatusCode::NOT_FOUND, "", canary),
        "unavailable" => failure(StatusCode::SERVICE_UNAVAILABLE, "", canary),
        _ => Json(json!({"operationId": "account-deletion/synthetic"})).into_response(),
    }
}

/// The synthetic IdP: a signed-in, enrolled admin, three accounts, and a
/// plan and deletion answer by `mode`.
async fn upstream(mode: &'static str) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let method = request.method().to_string();
            let path = request.uri().path().to_owned();
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .map(|value| value.to_str().unwrap().to_owned());
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls
                .lock()
                .unwrap()
                .push((method, path.clone(), origin, body.to_vec()));
            if path == "/api/auth/get-session" {
                return Json(json!({"user": {
                    "id": ADMIN, "email": "synthetic.admin@example.test",
                    "is_admin": true, "two_factor_enabled": true
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
            if path == "/api/admin/accounts" {
                let mut deleting = account(DELETING, false);
                deleting["deleting"] = json!(true);
                return Json(json!({"accounts": [
                    account(ADMIN, true),
                    account(OTHER_ADMIN, true),
                    account(MEMBER, false),
                    deleting,
                ]}))
                .into_response();
            }
            if path == format!("/api/admin/accounts/{MEMBER}/deletion-plan") {
                return Json(plan(mode)).into_response();
            }
            if path == format!("/api/admin/accounts/{MEMBER}/delete") {
                return deletion(mode);
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
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
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

async fn get(dashboard: &TestServer, path: &str, csrf: &str) -> Page {
    send(
        client()
            .get(format!("{}{path}", dashboard.origin))
            .headers(authority(csrf)),
    )
    .await
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
        ("user_id", MEMBER),
        ("confirm_email", MEMBER_EMAIL),
        ("password", "synthetic-password"),
        ("proof", "123456"),
    ]
}

fn delete_calls(calls: &Calls) -> Vec<(Option<String>, Vec<u8>)> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, path, _, _)| method == "POST" && path.ends_with("/delete"))
        .map(|(_, _, origin, body)| (origin.clone(), body.clone()))
        .collect()
}

/// HTML-escaped as the template writes it.
fn escaped(text: &str) -> String {
    text.replace('\'', "&#39;")
}

fn delete_link(id: &str) -> String {
    format!("href=\"/admin/accounts/{id}/delete\"")
}

#[tokio::test]
async fn the_accounts_list_offers_delete_except_for_you_and_other_admins() {
    let (services, _) = upstream("plan").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = get(&dashboard, "/admin/accounts/", &csrf).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains("<title>Manage account access · Codewire</title>")
    );
    assert!(
        page.body
            .contains("<h1 class=\"cw-page-title\">Manage account access</h1>")
    );
    assert!(page.body.contains(&format!(
        "{}><span>Delete account</span><span class=\"cw-sr-only\"> {MEMBER}@example.test</span></a>",
        delete_link(MEMBER)
    )));
    assert!(!page.body.contains(&delete_link(ADMIN)));
    assert!(!page.body.contains(&delete_link(OTHER_ADMIN)));
    // An account already being deleted says so and offers no Delete (#5769).
    assert!(!page.body.contains(&delete_link(DELETING)));
    assert!(
        page.body
            .contains("<span class=\"cw-muted\">Deleting</span>")
    );
    assert!(
        page.body
            .contains("<span class=\"cw-muted\">Your account. Delete it in Settings.</span>")
    );
    assert!(
        page.body
            .contains("<span class=\"cw-muted\">An admin. Demote them first.</span>")
    );

    let started = get(
        &dashboard,
        &format!("/admin/accounts/?message=deletion-started&deleted={MEMBER}"),
        &csrf,
    )
    .await;
    assert!(
        started
            .body
            .contains(&format!("Deletion started for {MEMBER}@example.test."))
    );
}

#[tokio::test]
async fn the_confirmation_page_shows_what_the_deletion_does() {
    let (services, calls) = upstream("plan").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = get(
        &dashboard,
        &format!("/admin/accounts/{MEMBER}/delete"),
        &csrf,
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    for text in [
        "<title>Delete account · Codewire</title>",
        "Delete synthetic.member@example.test</h2>",
        "Sign-in stops at once: the account's sessions, API keys and CLI sign-ins stop working.",
        "<strong>Solo Lab</strong><p class=\"cw-muted\">2 sandboxes deleted with it</p>",
        "Memberships that end",
        "<strong>Shared Team</strong><p class=\"cw-muted\">The organization stays.</p>",
        "Everything listed is removed permanently. This can't be undone.",
        "action=\"/admin/accounts/_actions/delete\"",
        "pattern=\"synthetic\\.member@example\\.test\"",
        "<label class=\"cw-label\" for=\"delete-account-password\">Your password</label>",
        "<label class=\"cw-label\" for=\"delete-account-proof\">Authenticator or recovery code</label>",
        "<a class=\"cw-button cw-button--outline\" href=\"/admin/accounts/\">Cancel</a>",
        "<button class=\"cw-button cw-danger-button\" type=\"submit\">Delete account</button>",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }
    assert!(!page.body.contains(" disabled"));
    assert!(delete_calls(&calls).is_empty(), "a page view deleted");

    // An admin's own row goes to Settings.
    let own = get(
        &dashboard,
        &format!("/admin/accounts/{ADMIN}/delete"),
        &csrf,
    )
    .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER);
    assert_eq!(own.headers[header::LOCATION], "/settings/delete-account/");
}

#[tokio::test]
async fn an_organization_in_the_way_or_an_admin_disables_the_form() {
    let csrf = crate::security::new_csrf_token();
    for (mode, reason) in [
        (
            "blocked",
            "This account is the only owner of these organizations, and others are members.",
        ),
        (
            "admin",
            "This account is an admin. An admin is demoted before their account is deleted.",
        ),
    ] {
        let (services, _) = upstream(mode).await;
        let dashboard = serve(crate::app(config(&services.origin))).await;
        let page = get(
            &dashboard,
            &format!("/admin/accounts/{MEMBER}/delete"),
            &csrf,
        )
        .await;
        assert_eq!(page.status, StatusCode::OK, "{mode}");
        assert!(
            page.body
                .contains(&format!("id=\"delete-account-refused\">{reason}")),
            "{mode}"
        );
        assert!(
            page.body.contains(
                "type=\"submit\" disabled aria-describedby=\"delete-account-refused\">Delete account</button>"
            ),
            "{mode}"
        );
        assert_eq!(page.body.matches(" disabled").count(), 4, "{mode}");
    }
    let (services, _) = upstream("blocked").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let page = get(
        &dashboard,
        &format!("/admin/accounts/{MEMBER}/delete"),
        &csrf,
    )
    .await;
    assert!(
        page.body
            .contains("Transfer or delete these organizations first")
    );
    assert!(page.body.contains("<li><strong>Owned Team</strong></li>"));

    let (services, _) = upstream("running").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let page = get(
        &dashboard,
        &format!("/admin/accounts/{MEMBER}/delete"),
        &csrf,
    )
    .await;
    assert!(
        page.body
            .contains("synthetic.member@example.test is already being deleted")
    );
    assert!(
        !page
            .body
            .contains("action=\"/admin/accounts/_actions/delete\"")
    );
}

#[tokio::test]
async fn the_action_sends_the_confirmation_and_returns_to_the_list() {
    let (services, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, authority(&csrf), &form(&csrf)).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    let location = page.headers[header::LOCATION].to_str().unwrap();
    assert_eq!(
        location,
        format!("/admin/accounts/?message=deletion-started&deleted={MEMBER}")
    );
    assert!(
        !location.contains("example.test"),
        "the address is in the URL"
    );
    let deletes = delete_calls(&calls);
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].0.as_deref(), Some(ORIGIN));
    let sent: Value = serde_json::from_slice(&deletes[0].1).unwrap();
    assert_eq!(
        sent,
        json!({
            "confirm_email": MEMBER_EMAIL,
            "password": "synthetic-password",
            "proof": "123456",
        })
    );
}

#[tokio::test]
async fn each_refusal_shows_the_page_again_with_its_reason() {
    let csrf = crate::security::new_csrf_token();
    for (mode, message) in [
        (
            "proof",
            "Your password or code is incorrect. Nothing was deleted.".to_owned(),
        ),
        (
            "locked",
            "Your account is locked after too many failed attempts. Try again later. Nothing was deleted."
                .to_owned(),
        ),
        (
            "limited",
            format!("You've reached the limit: {CAP}. Nothing was deleted."),
        ),
        (
            "address",
            "The address you typed is not this account's. Nothing was deleted.".to_owned(),
        ),
        (
            "admin",
            "This account is an admin. Demote them before deleting their account.".to_owned(),
        ),
        (
            "blocked",
            "This account is the only owner of organizations with other members. Transfer or delete them first."
                .to_owned(),
        ),
        (
            "unavailable",
            "The account could not be deleted. Try again.".to_owned(),
        ),
    ] {
        let (services, calls) = upstream(mode).await;
        let dashboard = serve(crate::app(config(&services.origin))).await;
        let page = post(&dashboard, authority(&csrf), &form(&csrf)).await;
        assert_eq!(page.status, StatusCode::OK, "{mode}");
        assert!(
            page.body.contains(&format!(
                "<p class=\"cw-alert cw-alert--error\" role=\"alert\">{}</p>",
                escaped(&message)
            )),
            "{mode}: {}",
            page.body
        );
        assert!(page.body.contains("Delete synthetic.member@example.test</h2>"));
        assert!(
            page.body
                .contains(&format!("value=\"{MEMBER_EMAIL}\" required")),
            "{mode}: the typed address is kept"
        );
        assert!(!page.body.contains("synthetic-password"), "{mode}");
        assert!(!page.body.contains("upstream-private-canary"), "{mode}");
        assert_eq!(delete_calls(&calls).len(), 1, "{mode}");
    }

    let (services, _) = upstream("gone").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let page = post(&dashboard, authority(&csrf), &form(&csrf)).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        "/admin/accounts/?error=not-found"
    );
}

#[tokio::test]
async fn a_request_without_same_origin_authority_never_reaches_the_idp() {
    let (services, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let mut foreign_origin = authority(&csrf);
    foreign_origin.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
    let page = post(&dashboard, foreign_origin, &form(&csrf)).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let mut wrong_csrf = form(&csrf);
    wrong_csrf[0].1 = "wrong-csrf";
    let page = post(&dashboard, authority(&csrf), &wrong_csrf).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let mut extra = form(&csrf);
    extra.push(("organization", "org-team"));
    let page = post(&dashboard, authority(&csrf), &extra).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let mut own = form(&csrf);
    own[1].1 = ADMIN;
    let page = post(&dashboard, authority(&csrf), &own).await;
    assert_eq!(page.headers[header::LOCATION], "/settings/delete-account/");
    assert!(
        delete_calls(&calls).is_empty(),
        "a refused request reached the IdP"
    );
}

/// Every admin deletion that does not start leaves a log line with where it
/// stopped and a fixed reason, before the IdP or at it (#5770). The line has
/// only those and the target's id, so it never holds the typed address, the
/// password or the code.
#[tokio::test]
async fn every_deletion_that_does_not_start_is_logged() {
    use crate::admin_account_deletion::REFUSALS_LOGGED;
    let take = || REFUSALS_LOGGED.with(|logged| std::mem::take(&mut *logged.borrow_mut()));
    take();
    let csrf = crate::security::new_csrf_token();
    let with = |field: &'static str, value: &'static str| {
        let mut form = form(&csrf);
        match form.iter_mut().find(|(name, _)| *name == field) {
            Some(entry) => entry.1 = value,
            None => form.push((field, value)),
        }
        form
    };
    let mut foreign = authority(&csrf);
    foreign.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());

    let (services, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    for (case, headers, form, reason, target) in [
        (
            "foreign origin",
            foreign,
            form(&csrf),
            "origin_or_csrf",
            MEMBER,
        ),
        (
            "wrong token",
            authority(&csrf),
            with("_csrf", "wrong-csrf"),
            "origin_or_csrf",
            MEMBER,
        ),
        (
            "unknown field",
            authority(&csrf),
            with("organization", "org-team"),
            "form_rejected",
            "",
        ),
        (
            "not an id",
            authority(&csrf),
            with("user_id", "not an id"),
            "invalid_account_id",
            "",
        ),
        (
            "own account",
            authority(&csrf),
            with("user_id", ADMIN),
            "own_account",
            ADMIN,
        ),
        (
            "no address",
            authority(&csrf),
            with("confirm_email", " "),
            "confirm_email_unusable",
            MEMBER,
        ),
        (
            "no code",
            authority(&csrf),
            with("proof", " "),
            "proof_unusable",
            MEMBER,
        ),
    ] {
        post(&dashboard, headers, &form).await;
        assert_eq!(take(), [("dashboard", reason, target.to_owned())], "{case}");
    }
    assert!(
        delete_calls(&calls).is_empty(),
        "a refused request reached the IdP"
    );

    // The IdP's refusal is logged as the IdP's.
    let (services, _) = upstream("proof").await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    post(&dashboard, authority(&csrf), &form(&csrf)).await;
    assert_eq!(
        take(),
        [("identity_service", "proof_rejected", MEMBER.to_owned())]
    );
}
