//! Registered-route proof for Settings › Invitations and the emailed link's
//! unverified-address refusal (#3840), against a synthetic identity and
//! organization service that record each call. No real account is used.

use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    AcceptInvitationRequest, AcceptInvitationResponse, GetInvitationByTokenResponse,
    InvitationStatus, ListMyInvitationsResponse, ListOrganizationsResponse, OrgInvitation, OrgRole,
    Organization, OrganizationMembership,
};

use super::{AcceptError, rows};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const EMAIL: &str = "synthetic.invitee@example.test";
const ACCEPT_RPC: &str = "/codewire.v1.OrganizationService/AcceptInvitation";
const TOKEN: &str = "synthetic-invitation-capability-marker";

type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// What the synthetic services answer.
#[derive(Clone, Copy)]
struct Scenario {
    email_verified: bool,
    two_factor: bool,
    invitations: usize,
    /// ListMyInvitations fails with `unavailable`.
    list_unavailable: bool,
    /// AcceptInvitation's answer: `None` accepts, otherwise the Connect code.
    accept_error: Option<&'static str>,
    /// The address an invitation link names.
    invited: &'static str,
}

const VERIFIED: Scenario = Scenario {
    email_verified: true,
    two_factor: true,
    invitations: 2,
    list_unavailable: false,
    accept_error: None,
    invited: EMAIL,
};

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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn invitation(index: usize) -> OrgInvitation {
    let (name, slug, role, assignments): (&str, &str, OrgRole, &[&str]) = match index {
        0 => ("Team Alpha", "team-alpha", OrgRole::Admin, &["developer"]),
        _ => ("Beta Labs", "beta-labs", OrgRole::Member, &[]),
    };
    let mut invitation = OrgInvitation {
        id: format!("invitation-{index}"),
        org_id: format!("org-{slug}"),
        org_name: name.into(),
        org_slug: slug.into(),
        email: EMAIL.into(),
        role: role.into(),
        inviter_name: Some("Synthetic Owner".into()),
        status: InvitationStatus::Pending.into(),
        assignments: assignments
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        ..Default::default()
    };
    invitation.expires_at.get_or_insert_default().seconds = now() + 6 * 86_400;
    invitation
}

fn proto(message: impl buffa::Message) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
}

fn connect_error(code: &str) -> Response {
    let status = match code {
        "not_found" => StatusCode::NOT_FOUND,
        "unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(serde_json::json!({"code": code, "message": "upstream-private-canary"})),
    )
        .into_response()
}

async fn upstream(scenario: Scenario) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let signed_in = request
                .headers()
                .get(header::COOKIE)
                .and_then(|cookie| cookie.to_str().ok())
                .is_some_and(|cookie| cookie.contains("codewire.session_token="));
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push((path.clone(), body.to_vec()));
            if path == "/api/auth/get-session" && !signed_in {
                return Json(serde_json::Value::Null).into_response();
            }
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {
                    "id": "synthetic-account",
                    "email": EMAIL,
                    "two_factor_enabled": scenario.two_factor,
                    "email_verified": scenario.email_verified,
                }}))
                .into_response();
            }
            if path.ends_with("/ListOrganizations") {
                // After an acceptance the joined organization is a membership.
                return proto(ListOrganizationsResponse {
                    organizations: vec![OrganizationMembership {
                        organization: Some(Organization {
                            id: "org-team-alpha".into(),
                            name: "Team Alpha".into(),
                            slug: "team-alpha".into(),
                            ..Default::default()
                        })
                        .into(),
                        role: OrgRole::Admin.into(),
                        ..Default::default()
                    }]
                    .into_iter()
                    .filter(|_| scenario.accept_error.is_none())
                    .collect(),
                    ..Default::default()
                });
            }
            if path.ends_with("/ListMyInvitations") {
                if scenario.list_unavailable {
                    return connect_error("unavailable");
                }
                let invitations = if scenario.email_verified {
                    (0..scenario.invitations).map(invitation).collect()
                } else {
                    Vec::new()
                };
                return proto(ListMyInvitationsResponse {
                    invitations,
                    ..Default::default()
                });
            }
            if path.ends_with("/GetInvitationByToken") {
                // The platform answers with the invited address masked (#3840).
                let mut shown = invitation(0);
                shown.email = codewire_server_core::org::masked_email(scenario.invited);
                return proto(GetInvitationByTokenResponse {
                    invitation: Some(shown).into(),
                    ..Default::default()
                });
            }
            if path == ACCEPT_RPC {
                return match scenario.accept_error {
                    None => proto(AcceptInvitationResponse {
                        org_id: "org-team-alpha".into(),
                        ..Default::default()
                    }),
                    Some(code) => connect_error(code),
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

async fn get(dashboard: &TestServer, path: &str, headers: HeaderMap) -> Page {
    send(
        client()
            .get(format!("{}{path}", dashboard.origin))
            .headers(headers),
    )
    .await
}

async fn post(
    dashboard: &TestServer,
    path: &str,
    headers: HeaderMap,
    form: &[(&str, &str)],
) -> Page {
    send(
        client()
            .post(format!("{}{path}", dashboard.origin))
            .headers(headers)
            .form(form),
    )
    .await
}

async fn start(scenario: Scenario) -> (TestServer, TestServer, Calls) {
    let (services, calls) = upstream(scenario).await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    (services, dashboard, calls)
}

fn accept_calls(calls: &Calls) -> Vec<AcceptInvitationRequest> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == ACCEPT_RPC)
        .map(|(_, body)| AcceptInvitationRequest::decode_from_slice(body).unwrap())
        .collect()
}

fn assert_private(page: &Page) {
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers[header::VARY], "Cookie");
    assert!(!page.body.contains("upstream-private-canary"));
}

#[tokio::test]
async fn the_page_lists_each_pending_invitation_with_an_accept_by_id() {
    let (_services, dashboard, _) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();
    let page = get(&dashboard, super::PATH, authority(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    for text in [
        "<h1 class=\"cw-page-title\">Invitations</h1>",
        "Organizations that invited synthetic.invitee@example.test.",
        "Team Alpha <span class=\"cw-badge\">Admin</span> <span class=\"cw-badge\" data-tone=\"info\">Developer</span>",
        "Beta Labs <span class=\"cw-badge\">Member</span></h3>",
        "Invited by Synthetic Owner · Expires in 6 days",
        "action=\"/settings/invitations/_actions/accept\"",
        "name=\"invitation_id\" value=\"invitation-0\"",
        "name=\"invitation_id\" value=\"invitation-1\"",
        "<span>Accept</span><span class=\"cw-sr-only\"> invitation to Team Alpha</span>",
        "href=\"/settings/invitations/\" aria-current=\"page\">Invitations</a>",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }
    assert!(
        !page.body.contains("name=\"token\""),
        "the page carries no token"
    );
    assert!(!page.body.contains("Verify your email address"));
}

#[tokio::test]
async fn the_page_has_an_empty_an_unverified_and_an_unavailable_state() {
    let csrf = crate::security::new_csrf_token();

    let (_services, dashboard, _) = start(Scenario {
        invitations: 0,
        ..VERIFIED
    })
    .await;
    let page = get(&dashboard, super::PATH, authority(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("No pending invitations. When an organization invites synthetic.invitee@example.test, it appears here."));
    assert!(!page.body.contains("_actions/accept"));

    let (_services, dashboard, _) = start(Scenario {
        email_verified: false,
        ..VERIFIED
    })
    .await;
    let page = get(&dashboard, super::PATH, authority(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains("Verify your email address to see the invitations sent to it.")
    );
    assert!(page.body.contains(&format!("<form method=\"post\" action=\"/settings/_actions/send-verification\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button class=\"cw-text-action\" type=\"submit\">Send verification email</button></form>")));
    assert!(!page.body.contains("No pending invitations"));

    let (_services, dashboard, _) = start(Scenario {
        list_unavailable: true,
        ..VERIFIED
    })
    .await;
    let page = get(&dashboard, super::PATH, authority(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    assert!(
        page.body
            .contains("Your invitations are unavailable right now. Reload to try again.")
    );
}

#[tokio::test]
async fn the_page_needs_a_signed_in_account_with_two_factor() {
    let (_services, dashboard, calls) = start(VERIFIED).await;
    let page = get(&dashboard, super::PATH, HeaderMap::new()).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        "/login?return_to=%2Fsettings%2Finvitations%2F"
    );

    let (_services, dashboard, calls_without_two_factor) = start(Scenario {
        two_factor: false,
        ..VERIFIED
    })
    .await;
    let csrf = crate::security::new_csrf_token();
    let page = get(&dashboard, super::PATH, authority(&csrf)).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        "/setup-2fa?return_to=%2Fsettings%2Finvitations%2F"
    );
    for calls in [calls, calls_without_two_factor] {
        assert!(
            !calls
                .lock()
                .unwrap()
                .iter()
                .any(|(path, _)| path.ends_with("/ListMyInvitations")),
            "invitations were read without authority"
        );
    }
}

#[tokio::test]
async fn accepting_by_id_sends_no_token_and_opens_the_organization() {
    let (_services, dashboard, calls) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(
        &dashboard,
        super::ACCEPT_PATH,
        authority(&csrf),
        &[("_csrf", &csrf), ("invitation_id", "invitation-0")],
    )
    .await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(page.headers[header::LOCATION], "/team-alpha/");
    assert_private(&page);
    let accepted = accept_calls(&calls);
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].invitation_id, "invitation-0");
    assert!(accepted[0].token.is_empty());
}

#[tokio::test]
async fn refusals_return_to_the_page_with_their_reason() {
    let csrf = crate::security::new_csrf_token();
    for (code, error) in [
        ("not_found", AcceptError::NotFound),
        ("failed_precondition", AcceptError::EmailUnverified),
        ("unavailable", AcceptError::Unavailable),
    ] {
        let (_services, dashboard, _) = start(Scenario {
            accept_error: Some(code),
            ..VERIFIED
        })
        .await;
        let page = post(
            &dashboard,
            super::ACCEPT_PATH,
            authority(&csrf),
            &[("_csrf", &csrf), ("invitation_id", "invitation-0")],
        )
        .await;
        assert_eq!(page.status, StatusCode::SEE_OTHER, "{code}");
        let location = page.headers[header::LOCATION].to_str().unwrap().to_owned();
        assert_eq!(
            location,
            format!("/settings/invitations/?error={}", error.code())
        );
        assert_private(&page);
        let page = get(&dashboard, &location, authority(&csrf)).await;
        assert!(page.body.contains(error.message()), "{code}");
    }
    assert_eq!(
        AcceptError::EmailUnverified.message(),
        "Verify your email address, then accept the invitation again."
    );
}

#[tokio::test]
async fn accepting_checks_origin_csrf_form_and_two_factor_before_the_platform() {
    let (_services, dashboard, calls) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();
    let form = [("_csrf", csrf.as_str()), ("invitation_id", "invitation-0")];
    let mut no_origin = authority(&csrf);
    no_origin.remove(header::ORIGIN);
    let mut foreign_origin = authority(&csrf);
    foreign_origin.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
    for (case, headers) in [("no origin", no_origin), ("foreign origin", foreign_origin)] {
        let page = post(&dashboard, super::ACCEPT_PATH, headers, &form).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{case}");
    }
    let page = post(
        &dashboard,
        super::ACCEPT_PATH,
        authority(&csrf),
        &[("_csrf", "wrong-csrf"), ("invitation_id", "invitation-0")],
    )
    .await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let page = post(
        &dashboard,
        super::ACCEPT_PATH,
        authority(&csrf),
        &[
            ("_csrf", &csrf),
            ("invitation_id", "invitation-0"),
            ("token", TOKEN),
        ],
    )
    .await;
    assert_eq!(
        page.status,
        StatusCode::FORBIDDEN,
        "a token field is refused"
    );
    let page = post(
        &dashboard,
        super::ACCEPT_PATH,
        authority(&csrf),
        &[("_csrf", &csrf), ("invitation_id", "")],
    )
    .await;
    assert_eq!(
        page.headers[header::LOCATION],
        "/settings/invitations/?error=not-found"
    );
    let page = post(&dashboard, super::ACCEPT_PATH, HeaderMap::new(), &form).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(
        page.headers[header::LOCATION],
        "/login?return_to=%2Fsettings%2Finvitations%2F"
    );

    let (_services, without_two_factor, calls_without_two_factor) = start(Scenario {
        two_factor: false,
        ..VERIFIED
    })
    .await;
    let page = post(
        &without_two_factor,
        super::ACCEPT_PATH,
        authority(&csrf),
        &form,
    )
    .await;
    assert_eq!(
        page.headers[header::LOCATION],
        "/setup-2fa?return_to=%2Fsettings%2Finvitations%2F"
    );
    assert!(
        accept_calls(&calls).is_empty(),
        "a refused request reached AcceptInvitation"
    );
    assert!(accept_calls(&calls_without_two_factor).is_empty());
}

/// The headers every invitation page answers with (#3840).
fn assert_invitation_headers(page: &Page) {
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    // Not no-referrer, under which a browser posts the page's forms with
    // `Origin: null` and the exact-origin checks refuse them.
    assert_eq!(page.headers[header::REFERRER_POLICY], "same-origin");
    assert!(!page.body.contains("token="), "a token in a URL");
}

/// The open POST and the page as an invitation link's holder.
fn with_invitation(mut headers: HeaderMap) -> HeaderMap {
    let cookie = headers
        .get(header::COOKIE)
        .map(|cookie| cookie.to_str().unwrap().to_owned());
    let cookie = match cookie {
        Some(cookie) => format!("{cookie}; codewire.invitation={TOKEN}"),
        None => format!("codewire.invitation={TOKEN}"),
    };
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    headers
}

fn signed_out(csrf: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(
        header::COOKIE,
        format!("codewire_ssr_csrf={csrf}").parse().unwrap(),
    );
    headers
}

/// The script posts the fragment's token once: an exact same-origin request
/// sets the path-scoped invitation cookie and sends the browser to the plain
/// page; any other origin is refused.
#[tokio::test]
async fn opening_a_link_keeps_its_token_in_a_scoped_cookie_and_nowhere_else() {
    let (_services, dashboard, _) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();
    let opened = post(
        &dashboard,
        "/accept-invite/_actions/open",
        signed_out(&csrf),
        &[("_csrf", &csrf), ("t", TOKEN)],
    )
    .await;
    assert_eq!(opened.status, StatusCode::SEE_OTHER);
    assert_eq!(opened.headers[header::LOCATION], "/accept-invite");
    let cookie = opened.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        cookie.starts_with(&format!(
            "codewire.invitation={TOKEN}; Path=/accept-invite; HttpOnly; SameSite=Strict; Max-Age="
        )),
        "{cookie}"
    );
    assert_invitation_headers(&opened);

    let mut elsewhere = signed_out(&csrf);
    elsewhere.insert(header::ORIGIN, "https://elsewhere.test".parse().unwrap());
    let refused = post(
        &dashboard,
        "/accept-invite/_actions/open",
        elsewhere,
        &[("_csrf", &csrf), ("t", TOKEN)],
    )
    .await;
    assert_ne!(refused.status, StatusCode::SEE_OTHER);
    assert!(
        !refused.headers.contains_key(header::SET_COOKIE)
            || !refused.headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("codewire.invitation=")
    );
}

/// A link from before the fragment carries its token in the query: it is
/// never resolved, and the visitor is sent to ask for a new one.
#[tokio::test]
async fn an_old_query_link_is_never_resolved() {
    let (_services, dashboard, calls) = start(VERIFIED).await;
    let page = get(
        &dashboard,
        &format!("/accept-invite?token={TOKEN}"),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(page.headers[header::LOCATION], "/accept-invite/out-of-date");
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .all(|(path, _)| !path.ends_with("/GetInvitationByToken"))
    );
    let gone = get(&dashboard, "/accept-invite/out-of-date", HeaderMap::new()).await;
    assert_eq!(gone.status, StatusCode::GONE);
    assert!(gone.body.contains("This link is out of date"));
    assert_invitation_headers(&gone);
}

/// With no invitation cookie the page is the script's: it opens the link's
/// fragment, and without JavaScript it says to enable it.
#[tokio::test]
async fn the_page_without_an_invitation_runs_only_the_opening_script() {
    let (_services, dashboard, _) = start(VERIFIED).await;
    let page = get(&dashboard, "/accept-invite", HeaderMap::new()).await;
    assert_eq!(page.status, StatusCode::OK);
    // Asset URLs are versioned when served, so match the path.
    assert!(page.body.contains("/assets/codewire/accept-invite-v1.js"));
    assert!(page.body.contains("data-invitation-opening"));
    assert!(
        page.body
            .contains("Enable JavaScript to open this invitation.")
    );
    assert!(
        page.body
            .contains(r#"action="/accept-invite/_actions/open""#)
    );
    assert_invitation_headers(&page);
}

/// Each visitor sees one branch: signed out, another account, or the invited
/// account ready to accept; the token reaches the page only as the signed-out
/// Sign up form's hidden field.
#[tokio::test]
async fn the_page_shows_each_visitor_their_branch() {
    let (_services, dashboard, _) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();

    let page = get(
        &dashboard,
        "/accept-invite",
        with_invitation(signed_out(&csrf)),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Join Team Alpha"));
    assert!(page.body.contains("s\u{2022}\u{2022}\u{2022}@example.test"));
    assert!(!page.body.contains(EMAIL), "the invited address is masked");
    assert!(
        page.body
            .contains(r#"href="/login?return_to=%2Faccept-invite""#)
    );
    assert!(page.body.contains(r#"action="/signup/invited""#));
    assert!(
        page.body
            .contains(&format!(r#"name="invitation_token" value="{TOKEN}""#))
    );
    assert_invitation_headers(&page);

    let page = get(
        &dashboard,
        "/accept-invite",
        with_invitation(authority(&csrf)),
    )
    .await;
    assert!(page.body.contains("Accept invitation</button>"));
    assert!(
        !page.body.contains(TOKEN),
        "a signed-in page carries no token"
    );
    assert_invitation_headers(&page);

    let (_services, dashboard, _) = start(Scenario {
        invited: "someone.else@elsewhere.test",
        ..VERIFIED
    })
    .await;
    let page = get(
        &dashboard,
        "/accept-invite",
        with_invitation(authority(&csrf)),
    )
    .await;
    assert!(page.body.contains("This invitation is for s\u{2022}\u{2022}\u{2022}@elsewhere.test. You're signed in as synthetic.invitee@example.test."));
    assert!(
        page.body
            .contains(r#"action="/accept-invite/_actions/switch""#)
    );
    assert!(!page.body.contains("Accept invitation</button>"));
}

/// Accepting reads the token from the cookie, never a form field, clears the
/// cookie once accepted, and an unverified invitee is asked to verify first.
#[tokio::test]
async fn accepting_uses_the_cookie_and_an_unverified_invitee_verifies_first() {
    let (_services, dashboard, calls) = start(VERIFIED).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(
        &dashboard,
        "/accept-invite/_actions/accept",
        with_invitation(authority(&csrf)),
        &[("_csrf", &csrf)],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Welcome to the team"));
    let cleared = page.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        page.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|cookie| cookie
                .to_str()
                .unwrap()
                .starts_with("codewire.invitation=; Path=/accept-invite;")),
        "{cleared}"
    );
    assert_eq!(accept_calls(&calls)[0].token, TOKEN);
    assert_invitation_headers(&page);

    let (_services, dashboard, _) = start(Scenario {
        accept_error: Some("failed_precondition"),
        ..VERIFIED
    })
    .await;
    let page = post(
        &dashboard,
        "/accept-invite/_actions/accept",
        with_invitation(authority(&csrf)),
        &[("_csrf", &csrf)],
    )
    .await;
    assert!(page.body.contains("<div class=\"cw-alert cw-alert--warning\" role=\"alert\">Verify your email address, then accept the invitation again. <form class=\"cw-auth-resend\" method=\"post\" action=\"/settings/_actions/send-verification\">"));
    assert!(page.body.contains("Send a verification email</button>"));
    assert!(!page.body.contains("upstream-private-canary"));

    // Other refusals keep the generic message without the verification offer.
    let (_services, dashboard, _) = start(Scenario {
        accept_error: Some("unavailable"),
        ..VERIFIED
    })
    .await;
    let page = post(
        &dashboard,
        "/accept-invite/_actions/accept",
        with_invitation(authority(&csrf)),
        &[("_csrf", &csrf)],
    )
    .await;
    assert!(
        page.body
            .contains("The invitation could not be accepted. Try again.")
    );
    assert!(!page.body.contains("send-verification"));
}

#[test]
fn rows_keep_only_pending_unexpired_invitations_and_carry_no_token() {
    let now = now();
    let mut expired = invitation(1);
    expired.expires_at.get_or_insert_default().seconds = now - 1;
    let mut accepted = invitation(1);
    accepted.status = InvitationStatus::Accepted.into();
    let mut unnamed = invitation(1);
    unnamed.org_name = " ".into();
    unnamed.inviter_name = None;
    let rows = rows(vec![invitation(0), expired, accepted, unnamed], now);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].organization_name, "Team Alpha");
    assert_eq!(rows[0].role, "Admin");
    assert_eq!(rows[0].assignments.len(), 1);
    assert_eq!(rows[0].assignments[0].label, "Developer");
    assert_eq!(rows[1].organization_name, "beta-labs");
    assert_eq!(rows[1].inviter_name, "a team administrator");
    assert!(!format!("{rows:?}").contains("token"));
}
