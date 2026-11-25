//! Registered-route proof for Account › Sign-in methods (#4062) against a
//! synthetic identity service: the card in each state, the page's
//! form-action, Connect's redirect to the provider with the IdP's state
//! cookie, and Disconnect's outcomes. No real account or provider is used.
use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ACCOUNT: &str = "synthetic-account";
const AUTHORIZE: &str =
    "https://github.com/login/oauth/authorize?client_id=synthetic&state=synthetic-state";
const STATE_COOKIE: &str = "codewire_oauth_state=synthetic-state; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure";

/// What the synthetic IdP answers: the identities body (`None` answers 503),
/// and the status and body of a link start and an unlink.
#[derive(Clone)]
struct Answers {
    identities: Option<serde_json::Value>,
    link: (StatusCode, serde_json::Value),
    unlink: (StatusCode, serde_json::Value),
    add: (StatusCode, serde_json::Value),
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            identities: Some(serde_json::json!({
                "account_id": ACCOUNT, "providers": ["github", "google"], "password": true,
                "identities": [{ "provider": "github", "account": "octocat", "linked_at": "2026-11-12T09:30:00Z" }]
            })),
            link: (StatusCode::OK, serde_json::json!({ "location": AUTHORIZE })),
            unlink: (StatusCode::OK, serde_json::json!({ "provider": "github" })),
            add: (StatusCode::OK, serde_json::json!({ "added": true })),
        }
    }
}

type Calls = Arc<Mutex<Vec<(String, Option<String>, serde_json::Value)>>>;

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
        analytics: None,
    }
}

async fn upstream(answers: Answers) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        let answers = answers.clone();
        async move {
            let path = request.uri().path().to_owned();
            assert_eq!(
                request.headers()[header::COOKIE],
                "codewire.session_token=synthetic-session"
            );
            assert!(!request.headers().contains_key(header::AUTHORIZATION));
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .map(|value| value.to_str().unwrap().to_owned());
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            let json = serde_json::from_slice(&body).unwrap_or_default();
            calls.lock().unwrap().push((path.clone(), origin, json));
            match path.as_str() {
                "/api/auth/get-session" => Json(serde_json::json!({"user": {
                    "id": ACCOUNT, "email": "synthetic@example.test", "two_factor_enabled": true
                }}))
                .into_response(),
                "/api/auth/sessions" => Json(serde_json::json!({
                    "account_id": ACCOUNT,
                    "current_session": {"id": "session-current", "expires_at": "2026-11-13T00:00:00Z"},
                    "sessions": [{"id": "session-current", "created_at": null, "expires_at": "2026-11-13T00:00:00Z"}],
                    "next_cursor": null
                }))
                .into_response(),
                "/api/auth/oauth/identities" => match answers.identities {
                    Some(body) => Json(body).into_response(),
                    None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                },
                "/api/auth/oauth/identities/link" => {
                    let (status, body) = answers.link;
                    let mut response = (status, Json(body)).into_response();
                    if status == StatusCode::OK {
                        response.headers_mut().append(
                            header::SET_COOKIE,
                            STATE_COOKIE.parse().unwrap(),
                        );
                        // Any other cookie stays with the IdP.
                        response.headers_mut().append(
                            header::SET_COOKIE,
                            "codewire.session_token=minted; Path=/".parse().unwrap(),
                        );
                    }
                    response
                }
                "/api/auth/oauth/identities/unlink" => {
                    let (status, body) = answers.unlink;
                    (status, Json(body)).into_response()
                }
                "/api/auth/password/add" => {
                    let (status, body) = answers.add;
                    (status, Json(body)).into_response()
                }
                path if path.ends_with("/ListOrganizations") => {
                    ([(header::CONTENT_TYPE, "application/proto")], Vec::<u8>::new())
                        .into_response()
                }
                _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
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

async fn page(response: reqwest::Response) -> Page {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    Page {
        status,
        headers,
        body,
    }
}

async fn account_page(answers: Answers, query: &str) -> Page {
    let (identity, _calls) = upstream(answers).await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let response = client()
        .get(format!("{}/settings/{query}", dashboard.origin))
        .header(header::COOKIE, "codewire.session_token=synthetic-session")
        .send()
        .await
        .unwrap();
    page(response).await
}

/// The Sign-in methods card's markup, from its heading to the next card.
fn card(body: &str) -> &str {
    let start = body.find("id=\"sign-in-methods\"").expect("the card");
    let end = body[start..].find("</section>").unwrap();
    &body[start..start + end]
}

#[tokio::test]
async fn the_card_lists_the_password_and_each_configured_provider() {
    let page = account_page(Answers::default(), "").await;
    assert_eq!(page.status, StatusCode::OK);
    // The Connect POST redirects to the provider, so exactly those two
    // origins join form-action on this page.
    let policy = page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(
        policy.contains("form-action 'self' https://github.com https://accounts.google.com;"),
        "{policy}"
    );
    let card = card(&page.body);
    assert!(
        card.contains(
            "<h2 id=\"sign-in-methods-title\" class=\"cw-card-title\">Sign-in methods</h2>"
        )
    );
    // Each row: the name with its state, the description under it.
    assert!(
        card.contains(
            "<h3>Password <span class=\"cw-badge\" data-tone=\"success\">Set</span></h3>"
        )
    );
    assert!(card.contains(
        "<h3>GitHub <span class=\"cw-badge\" data-tone=\"success\">Connected</span></h3>"
    ));
    assert!(card.contains("<h3>Google</h3><p>Not connected.</p>"));
    assert!(card.contains("href=\"/forgot-password\">Reset password</a>"));
    // GitHub: connected as its login, with a Disconnect form.
    assert!(card.contains("id=\"sign-in-method-github\""));
    assert!(card.contains("Connected as <strong>octocat</strong>"));
    assert!(card.contains("action=\"/settings/_actions/sign-in-methods/disconnect\""));
    assert!(
        card.contains("<span>Disconnect</span><span class=\"cw-sr-only\"> GitHub</span></button>")
    );
    // Google: not connected, with a Connect form for this account.
    assert!(card.contains("id=\"sign-in-method-google\""));
    assert!(card.contains("Not connected."));
    assert!(card.contains("action=\"/settings/_actions/sign-in-methods/connect\""));
    assert!(card.contains("<input type=\"hidden\" name=\"provider\" value=\"google\">"));
    assert!(card.contains(&format!(
        "<input type=\"hidden\" name=\"account_id\" value=\"{ACCOUNT}\">"
    )));
    assert!(!card.contains(" disabled"));
    // The password row moved here from Security.
    let security = &page.body[page.body.find("id=\"security\"").unwrap()
        ..page.body.find("id=\"sign-in-methods\"").unwrap()];
    assert!(!security.contains("Password"));
}

#[tokio::test]
async fn the_last_way_in_cannot_be_disconnected_and_unconfigured_providers_hide() {
    let answers = Answers {
        identities: Some(serde_json::json!({
            "account_id": ACCOUNT, "providers": ["github"], "password": false,
            "identities": [{ "provider": "github", "account": null, "linked_at": "2026-11-12T09:30:00Z" }]
        })),
        ..Answers::default()
    };
    let page = account_page(answers, "").await;
    let card = card(&page.body);
    assert!(card.contains("No password is set. You sign in with a connected provider."));
    assert!(card.contains("<h3>Password <span class=\"cw-badge\">Not set</span></h3>"));
    assert!(!card.contains("Reset password"));
    assert!(
        !card.contains("sign-in-method-google"),
        "Google is not configured"
    );
    assert!(card.contains("<p>Connected · "));
    assert!(card.contains(
        "<span class=\"cw-security-help\" id=\"sign-in-method-github-help\">Add a password or connect another provider first.</span></p>"
    ));
    assert!(card.contains(
        "type=\"submit\" disabled aria-describedby=\"sign-in-method-github-help\"><span>Disconnect</span>"
    ));
}

#[tokio::test]
async fn an_unavailable_read_shows_a_warning_and_no_provider_controls() {
    let answers = Answers {
        identities: None,
        ..Answers::default()
    };
    let page = account_page(answers, "").await;
    assert_eq!(page.status, StatusCode::OK);
    let card = card(&page.body);
    assert!(card.contains("Connected providers are unavailable. Reload to try again."));
    assert!(card.contains("Get a reset link by email."));
    assert!(card.contains("Reset password"));
    assert!(!card.contains("_actions/sign-in-methods"));
}

#[tokio::test]
async fn outcomes_show_fixed_messages_and_unknown_ones_show_nothing() {
    for (query, alert) in [
        (
            "?sign_in_method=connected&provider=github",
            "<p class=\"cw-alert cw-alert--success\" role=\"status\">GitHub connected.</p>",
        ),
        (
            "?sign_in_method=taken&provider=github",
            "<p class=\"cw-alert cw-alert--error\" role=\"alert\">That GitHub account is already connected to another Codewire account.</p>",
        ),
        (
            "?sign_in_method=cancelled&provider=google",
            "<p class=\"cw-alert cw-alert--error\" role=\"alert\">Connecting Google was cancelled. Nothing changed.</p>",
        ),
    ] {
        let page = account_page(Answers::default(), query).await;
        assert!(card(&page.body).contains(alert), "{query}");
    }
    let page = account_page(
        Answers::default(),
        "?sign_in_method=%3Cscript%3E&provider=github",
    )
    .await;
    assert!(!card(&page.body).contains("cw-alert"));
}

async fn submit(
    path: &str,
    headers: HeaderMap,
    form: &[(&str, &str)],
    answers: Answers,
) -> (Page, Calls) {
    let (identity, calls) = upstream(answers).await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let response = client()
        .post(format!("{}{path}", dashboard.origin))
        .headers(headers)
        .form(form)
        .send()
        .await
        .unwrap();
    (page(response).await, calls)
}

const CONNECT: &str = "/settings/_actions/sign-in-methods/connect";
const DISCONNECT: &str = "/settings/_actions/sign-in-methods/disconnect";

fn idp_mutations(calls: &Calls) -> Vec<(String, Option<String>, serde_json::Value)> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _, _)| {
            path.starts_with("/api/auth/oauth/identities/") || path == "/api/auth/password/add"
        })
        .cloned()
        .collect()
}

#[tokio::test]
async fn connect_redirects_to_the_provider_with_the_state_cookie() {
    let csrf = crate::security::new_csrf_token();
    let form = [
        ("_csrf", csrf.as_str()),
        ("account_id", ACCOUNT),
        ("provider", "github"),
    ];
    let (page, calls) = submit(CONNECT, authority(&csrf), &form, Answers::default()).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(page.headers[header::LOCATION], AUTHORIZE);
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    let cookies: Vec<&str> = page
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(cookies, [STATE_COOKIE]);
    let mutations = idp_mutations(&calls);
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].0, "/api/auth/oauth/identities/link");
    assert_eq!(mutations[0].1.as_deref(), Some(ORIGIN));
    assert_eq!(
        mutations[0].2,
        serde_json::json!({ "account_id": ACCOUNT, "provider": "github" })
    );

    // A wrong CSRF token, another account's form or an unknown provider
    // never reaches the IdP.
    for form in [
        [
            ("_csrf", "wrong"),
            ("account_id", ACCOUNT),
            ("provider", "github"),
        ],
        [
            ("_csrf", csrf.as_str()),
            ("account_id", "someone-else"),
            ("provider", "github"),
        ],
        [
            ("_csrf", csrf.as_str()),
            ("account_id", ACCOUNT),
            ("provider", "gitlab"),
        ],
    ] {
        let (page, calls) = submit(CONNECT, authority(&csrf), &form, Answers::default()).await;
        assert_ne!(
            page.headers
                .get(header::LOCATION)
                .map(|value| value.to_str().unwrap()),
            Some(AUTHORIZE)
        );
        assert!(idp_mutations(&calls).is_empty(), "{form:?}");
    }
}

#[tokio::test]
async fn connect_never_follows_an_unexpected_destination_and_maps_refusals() {
    let csrf = crate::security::new_csrf_token();
    let form = [
        ("_csrf", csrf.as_str()),
        ("account_id", ACCOUNT),
        ("provider", "github"),
    ];
    for (link, code) in [
        (
            (
                StatusCode::OK,
                serde_json::json!({ "location": "https://evil.example/authorize" }),
            ),
            "failed",
        ),
        (
            (StatusCode::CONFLICT, serde_json::json!({})),
            "already_connected",
        ),
        (
            (StatusCode::NOT_FOUND, serde_json::json!({})),
            "unavailable",
        ),
        (
            (StatusCode::FORBIDDEN, serde_json::json!({})),
            "session_changed",
        ),
    ] {
        let answers = Answers {
            link,
            ..Answers::default()
        };
        let (page, _) = submit(CONNECT, authority(&csrf), &form, answers).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER);
        assert_eq!(
            page.headers[header::LOCATION],
            format!("/settings/?sign_in_method={code}&provider=github#sign-in-methods").as_str()
        );
        assert!(page.headers.get(header::SET_COOKIE).is_none(), "{code}");
    }
}

#[tokio::test]
async fn disconnect_reports_each_outcome_on_the_card() {
    let csrf = crate::security::new_csrf_token();
    let form = [
        ("_csrf", csrf.as_str()),
        ("account_id", ACCOUNT),
        ("provider", "github"),
    ];
    for (unlink, code) in [
        (
            (StatusCode::OK, serde_json::json!({ "provider": "github" })),
            "disconnected",
        ),
        ((StatusCode::CONFLICT, serde_json::json!({})), "last_method"),
        (
            (StatusCode::NOT_FOUND, serde_json::json!({})),
            "not_connected",
        ),
        (
            (StatusCode::BAD_GATEWAY, serde_json::json!({})),
            "outcome_unknown",
        ),
        // An answer for another provider is not an acknowledgement.
        (
            (StatusCode::OK, serde_json::json!({ "provider": "google" })),
            "outcome_unknown",
        ),
    ] {
        let answers = Answers {
            unlink,
            ..Answers::default()
        };
        let (page, calls) = submit(DISCONNECT, authority(&csrf), &form, answers).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER);
        assert_eq!(
            page.headers[header::LOCATION],
            format!("/settings/?sign_in_method={code}&provider=github#sign-in-methods").as_str()
        );
        let mutations = idp_mutations(&calls);
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].0, "/api/auth/oauth/identities/unlink");
        assert_eq!(mutations[0].1.as_deref(), Some(ORIGIN));
    }
}

/// A GitHub-only account (#4528).
fn provider_only() -> Answers {
    Answers {
        identities: Some(serde_json::json!({
            "account_id": ACCOUNT, "providers": ["github"], "password": false,
            "identities": [{ "provider": "github", "account": "octocat", "linked_at": "2026-11-12T09:30:00Z" }]
        })),
        ..Answers::default()
    }
}

/// The Add a password dialog's markup, if the page has one.
fn add_dialog(body: &str) -> Option<&str> {
    let start = body
        .find("<dialog class=\"cw-dialog cw-credential-dialog\" data-dialog id=\"add-password\"")?;
    let end = body[start..].find("</dialog>").unwrap();
    Some(&body[start..start + end])
}

const ADD_PASSWORD: &str = "/settings/_actions/sign-in-methods/add-password";

#[tokio::test]
async fn only_an_account_without_a_password_is_offered_one() {
    let page = account_page(provider_only(), "").await;
    assert!(card(&page.body).contains(
        "data-dialog-open=\"add-password\" aria-haspopup=\"dialog\" aria-controls=\"add-password\">Add a password</button>"
    ));
    let dialog = add_dialog(&page.body).expect("the dialog");
    assert!(!dialog.contains("data-dialog-auto-open"));
    assert!(dialog.contains(&format!("action=\"{ADD_PASSWORD}\"")));
    assert!(dialog.contains(&format!(
        "<input type=\"hidden\" name=\"account_id\" value=\"{ACCOUNT}\">"
    )));
    assert!(
        dialog.contains("name=\"new_password\" type=\"password\" autocomplete=\"new-password\"")
    );
    assert!(dialog.contains("name=\"confirm_password\" type=\"password\""));
    // The synthetic account has a second factor, so its code is asked for.
    assert!(dialog.contains("name=\"code\" autocomplete=\"one-time-code\""));
    assert!(dialog.contains("signed in within the last 10 minutes"));

    // `?dialog=add-password`, from signing in again, opens it.
    let page = account_page(provider_only(), "?dialog=add-password").await;
    assert!(
        add_dialog(&page.body)
            .unwrap()
            .contains("data-dialog-auto-open")
    );

    // An account with a password, or a card that couldn't be read, gets none.
    for answers in [
        Answers::default(),
        Answers {
            identities: None,
            ..Answers::default()
        },
    ] {
        let page = account_page(answers, "?dialog=add-password").await;
        assert!(add_dialog(&page.body).is_none());
        assert!(!card(&page.body).contains("Add a password"));
    }
}

#[tokio::test]
async fn adding_a_password_sends_it_to_the_idp_once_and_reports_it() {
    let csrf = crate::security::new_csrf_token();
    let form = [
        ("_csrf", csrf.as_str()),
        ("account_id", ACCOUNT),
        ("new_password", "Added!Pass1234"),
        ("confirm_password", "Added!Pass1234"),
        ("code", " 123456 "),
    ];
    let (page, calls) = submit(ADD_PASSWORD, authority(&csrf), &form, provider_only()).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        "/settings/?sign_in_method=password_added#sign-in-methods"
    );
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    let mutations = idp_mutations(&calls);
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].1.as_deref(), Some(ORIGIN));
    assert_eq!(
        mutations[0].2,
        serde_json::json!({ "account_id": ACCOUNT, "new_password": "Added!Pass1234", "code": "123456" })
    );

    for (add, code) in [
        (
            (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "code": "reauthentication_required" }),
            ),
            "password_reauthenticate",
        ),
        (
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "code": "code_rejected" }),
            ),
            "password_code",
        ),
        (
            (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({ "code": "account_locked" }),
            ),
            "password_locked",
        ),
        (
            (
                StatusCode::CONFLICT,
                serde_json::json!({ "code": "password_exists" }),
            ),
            "password_exists",
        ),
        (
            (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "code": "email_unverified" }),
            ),
            "password_unverified",
        ),
        (
            (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "detail": "<b>upstream</b>" }),
            ),
            "password_rules",
        ),
        (
            (StatusCode::BAD_GATEWAY, serde_json::json!({})),
            "password_outcome_unknown",
        ),
        // A 200 that doesn't say it was added is not an acknowledgement.
        (
            (StatusCode::OK, serde_json::json!({ "added": false })),
            "password_outcome_unknown",
        ),
    ] {
        let answers = Answers {
            add,
            ..provider_only()
        };
        let (page, calls) = submit(ADD_PASSWORD, authority(&csrf), &form, answers).await;
        assert_eq!(
            page.headers[header::LOCATION],
            format!("/settings/?sign_in_method={code}#sign-in-methods").as_str()
        );
        assert_eq!(idp_mutations(&calls).len(), 1);
    }
}

#[tokio::test]
async fn a_bad_form_or_request_never_reaches_the_idp() {
    let csrf = crate::security::new_csrf_token();
    let form = |password: &'static str, confirm: &'static str| {
        vec![
            ("_csrf", csrf.clone()),
            ("account_id", ACCOUNT.to_owned()),
            ("new_password", password.to_owned()),
            ("confirm_password", confirm.to_owned()),
        ]
    };
    let as_pairs = |form: &Vec<(&'static str, String)>| {
        form.iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>()
    };
    for (fields, code) in [
        (
            form("Added!Pass1234", "Added!Pass1235"),
            "password_mismatch",
        ),
        (form("short", "short"), "password_rules"),
    ] {
        let fields = as_pairs(&fields);
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (page, calls) = submit(ADD_PASSWORD, authority(&csrf), &fields, provider_only()).await;
        assert_eq!(
            page.headers[header::LOCATION],
            format!("/settings/?sign_in_method={code}#sign-in-methods").as_str()
        );
        assert!(idp_mutations(&calls).is_empty(), "{code}");
    }

    let good = as_pairs(&form("Added!Pass1234", "Added!Pass1234"));
    let good: Vec<(&str, &str)> = good.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // Another Origin, another CSRF token, and another account.
    let mut foreign = authority(&csrf);
    foreign.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let (page, calls) = submit(ADD_PASSWORD, foreign, &good, provider_only()).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(idp_mutations(&calls).is_empty());
    let other = crate::security::new_csrf_token();
    let (page, calls) = submit(ADD_PASSWORD, authority(&other), &good, provider_only()).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(idp_mutations(&calls).is_empty());
    let mut elsewhere = good.clone();
    elsewhere[1] = ("account_id", "another-account");
    let (page, calls) = submit(ADD_PASSWORD, authority(&csrf), &elsewhere, provider_only()).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert!(idp_mutations(&calls).is_empty());
}

#[tokio::test]
async fn refusals_reopen_the_dialog_with_fixed_copy() {
    let page = account_page(provider_only(), "?sign_in_method=password_reauthenticate").await;
    let dialog = add_dialog(&page.body).unwrap();
    assert!(dialog.contains("data-dialog-auto-open"));
    assert!(dialog.contains(
        "For your security, sign in again, then add your password within 10 minutes. <a href=\"/login?return_to=%2Fsettings%2F%3Fdialog%3Dadd-password\">Sign in again</a>"
    ));
    let page = account_page(provider_only(), "?sign_in_method=password_code").await;
    let dialog = add_dialog(&page.body).unwrap();
    assert!(dialog.contains("That code didn&#39;t match. Nothing changed."));
    assert!(!dialog.contains("Sign in again</a>"));

    // Added: the card now reads the password as set and says so.
    let page = account_page(Answers::default(), "?sign_in_method=password_added").await;
    assert!(card(&page.body).contains(
        "<p class=\"cw-alert cw-alert--success\" role=\"status\">Password added. You can now sign in with your email address and this password.</p>"
    ));
}
