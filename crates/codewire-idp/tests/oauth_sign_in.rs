//! Database proof for sign-in with GitHub or Google (#4062), against an
//! in-process fake of both providers behind `OAuthUpstream`. The fake checks
//! the exchange (client, secret, redirect URI and the PKCE verifier against
//! the challenge the start sent) and answers with the identity a test chose.
//! The integration runner rejects a missing DATABASE_URL skip.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_idp::auth_session::{SignupInvitePolicy, SignupMode};
use codewire_idp::oauth::{
    LinkConfirmationMailer, OAuthProviders, OAuthUpstream, Provider, UpstreamError,
    UpstreamRequest, UpstreamResponse, trusted_test_router,
};
use codewire_server_core::auth::hash_session_token;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tower::ServiceExt as _;

const ORIGIN: &str = "https://app.codewire.test";
const GITHUB_CLIENT: &str = "github-test-client";
const GITHUB_SECRET: &str = "github-test-secret";
const GOOGLE_CLIENT: &str = "google-test-client";
const GOOGLE_SECRET: &str = "google-test-secret";
const INVITE: &str = "synthetic-oauth-invite";

async fn pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping OAuth sign-in DB proof");
        return None;
    };
    Some(PgPool::connect(&url).await.expect("connect"))
}

/// What the fake provider answers for one authorization code.
#[derive(Clone)]
enum Answer {
    GitHub {
        id: u64,
        emails: Value,
    },
    Google {
        claims: Value,
    },
    /// The exchange fails at the provider.
    Refused,
}

#[derive(Default)]
struct Fake {
    /// code -> (expected PKCE challenge, answer)
    codes: Mutex<HashMap<String, (String, Answer)>>,
    /// access token -> GitHub answer
    tokens: Mutex<HashMap<String, Answer>>,
    exchanges: Mutex<u32>,
}

fn json_response(status: u16, body: Value) -> UpstreamResponse {
    UpstreamResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    }
}

#[async_trait]
impl OAuthUpstream for Fake {
    async fn execute(&self, request: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        match request.url() {
            "https://github.com/login/oauth/access_token"
            | "https://oauth2.googleapis.com/token" => {
                let google = request.url().contains("googleapis");
                let (client, secret, provider) = if google {
                    (GOOGLE_CLIENT, GOOGLE_SECRET, "google")
                } else {
                    (GITHUB_CLIENT, GITHUB_SECRET, "github")
                };
                assert!(request.is_post());
                assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
                assert_eq!(request.form_value("client_id"), Some(client));
                assert_eq!(request.form_value("client_secret"), Some(secret));
                assert_eq!(
                    request.form_value("redirect_uri"),
                    Some(format!("{ORIGIN}/api/auth/oauth/{provider}/callback").as_str())
                );
                *self.exchanges.lock().unwrap() += 1;
                let code = request.form_value("code").unwrap_or_default().to_owned();
                let Some((challenge, answer)) = self.codes.lock().unwrap().remove(&code) else {
                    return Ok(json_response(400, json!({ "error": "invalid_grant" })));
                };
                let verifier = request.form_value("code_verifier").unwrap_or_default();
                if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != challenge {
                    return Ok(json_response(400, json!({ "error": "invalid_grant" })));
                }
                match answer {
                    Answer::Refused => Ok(json_response(
                        200,
                        json!({ "error": "bad_verification_code" }),
                    )),
                    Answer::GitHub { .. } => {
                        let token = format!("gho_{code}");
                        self.tokens.lock().unwrap().insert(token.clone(), answer);
                        Ok(json_response(
                            200,
                            json!({ "access_token": token, "token_type": "bearer" }),
                        ))
                    }
                    Answer::Google { claims } => {
                        let id_token = format!(
                            "{}.{}.signature",
                            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
                            URL_SAFE_NO_PAD.encode(claims.to_string())
                        );
                        Ok(json_response(
                            200,
                            json!({ "access_token": "ya29.test", "id_token": id_token }),
                        ))
                    }
                }
            }
            url @ ("https://api.github.com/user" | "https://api.github.com/user/emails") => {
                assert!(!request.is_post());
                let token = request.bearer().unwrap_or_default().to_owned();
                let Some(Answer::GitHub { id, emails }) =
                    self.tokens.lock().unwrap().get(&token).cloned()
                else {
                    return Ok(json_response(401, json!({ "message": "Bad credentials" })));
                };
                if url.ends_with("/emails") {
                    Ok(json_response(200, emails))
                } else {
                    Ok(json_response(
                        200,
                        json!({ "id": id, "login": format!("user{id}"), "name": null }),
                    ))
                }
            }
            other => panic!("unexpected provider request to {other}"),
        }
    }
}

/// Records each link confirmation instead of sending it.
#[derive(Default)]
struct Mailbox {
    /// Recipient, provider, provider account and confirmation URL.
    sent: Mutex<Vec<(String, &'static str, String, String)>>,
}

#[async_trait]
impl LinkConfirmationMailer for Mailbox {
    fn is_available(&self) -> bool {
        true
    }

    async fn send(
        &self,
        to: &str,
        provider: Provider,
        account: &str,
        confirm_url: &str,
    ) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push((
            to.to_owned(),
            provider.as_str(),
            account.to_owned(),
            confirm_url.to_owned(),
        ));
        Ok(())
    }
}

impl Mailbox {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// The last confirmation's recipient, provider and token.
    fn last(&self) -> (String, &'static str, String) {
        let (to, provider, _, url) = self
            .sent
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a confirmation");
        let token = url
            .strip_prefix(&format!("{ORIGIN}/login/link?token="))
            .expect("the dashboard's confirmation page")
            .to_owned();
        (to, provider, token)
    }

    /// The provider account the last confirmation named.
    fn last_account(&self) -> String {
        self.sent
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a confirmation")
            .2
    }
}

struct Harness {
    pool: PgPool,
    fake: Arc<Fake>,
    mail: Arc<Mailbox>,
    app: Router,
    /// This test's client address, as the edge names it.
    client: String,
    /// The requester secret this test's browser holds for its latest link
    /// confirmation.
    requester: Mutex<Option<String>>,
}

impl Harness {
    async fn new(policy: SignupInvitePolicy) -> Option<Self> {
        let pool = pool().await?;
        let fake = Arc::new(Fake::default());
        let providers = OAuthProviders::with_upstream(
            Some((GITHUB_CLIENT, GITHUB_SECRET)),
            Some((GOOGLE_CLIENT, GOOGLE_SECRET)),
            fake.clone(),
        );
        let mail = Arc::new(Mailbox::default());
        let app = trusted_test_router(
            pool.clone(),
            true,
            policy,
            ORIGIN.into(),
            providers,
            mail.clone(),
        );
        let [a, b, c] = rand::random::<[u8; 3]>();
        Some(Self {
            pool,
            fake,
            mail,
            app,
            client: format!("10.{a}.{b}.{c}"),
            requester: Mutex::new(None),
        })
    }

    async fn pending_link(&self, token: &str) -> Reply {
        self.request(
            "POST",
            "/api/auth/oauth/link/pending",
            &[],
            Some(json!({ "token": token })),
        )
        .await
    }

    /// Confirm from this test's browser, which holds the requester secret of
    /// its latest link confirmation, as the dashboard forwards it.
    async fn confirm_link(&self, token: &str) -> Reply {
        let requester = self.requester.lock().unwrap().clone();
        self.confirm_link_from(token, requester.as_deref()).await
    }

    /// Confirm from a browser holding `requester`, or none.
    async fn confirm_link_from(&self, token: &str, requester: Option<&str>) -> Reply {
        let mut body = json!({ "token": token });
        if let Some(requester) = requester {
            body["requester"] = json!(requester);
        }
        self.request("POST", "/api/auth/oauth/link/confirm", &[], Some(body))
            .await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        cookies: &[String],
        body: Option<Value>,
    ) -> Reply {
        self.request_from(&self.client, method, path, cookies, body)
            .await
    }

    async fn request_from(
        &self,
        client: &str,
        method: &str,
        path: &str,
        cookies: &[String],
        body: Option<Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", client);
        if !cookies.is_empty() {
            builder = builder.header(header::COOKIE, cookies.join("; "));
        }
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned());
        let set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Reply {
            status,
            location,
            set_cookies,
            body,
        }
    }

    /// Start a round trip and return the browser's state cookie and the
    /// provider authorize URL's query.
    async fn start(&self, provider: &str, query: &str) -> Started {
        self.start_from(&self.client, provider, query).await
    }

    async fn start_from(&self, client: &str, provider: &str, query: &str) -> Started {
        let reply = self
            .request_from(
                client,
                "GET",
                &format!("/api/auth/oauth/{provider}/start{query}"),
                &[],
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "start {provider}");
        let location = reqwest::Url::parse(reply.location.as_deref().unwrap()).unwrap();
        let params: HashMap<String, String> = location.query_pairs().into_owned().collect();
        let cookie = reply.cookie("codewire_oauth_state").expect("state cookie");
        assert!(
            cookie.contains("Path=/api/auth/oauth/")
                && cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Lax")
                && cookie.contains("Secure"),
            "{cookie}"
        );
        // The cookie is sealed: it never carries the raw state.
        let state = params["state"].clone();
        let cookie = cookie_value(&cookie);
        assert!(state.len() == 64 && !cookie.contains(&state), "{cookie}");
        assert_eq!(params["code_challenge_method"], "S256");
        Started {
            state,
            cookie,
            params,
        }
    }

    /// Answer `code` with `answer` for this round trip.
    fn answer(&self, started: &Started, code: &str, answer: Answer) {
        self.fake.codes.lock().unwrap().insert(
            code.to_owned(),
            (started.params["code_challenge"].clone(), answer),
        );
    }

    async fn callback(&self, provider: &str, started: &Started, code: &str) -> Reply {
        let reply = self
            .request(
                "GET",
                &format!(
                    "/api/auth/oauth/{provider}/callback?code={code}&state={}",
                    started.state
                ),
                &[started.state_cookie()],
                None,
            )
            .await;
        // Keep the requester cookie as the browser would.
        if let Some(cookie) = reply.cookie("codewire_oauth_link_requester") {
            *self.requester.lock().unwrap() = Some(cookie_value(&cookie));
        }
        reply
    }
}

struct Started {
    /// The `state` the provider returns.
    state: String,
    /// The browser's `codewire_oauth_state` cookie: sealed for a sign-in, the
    /// raw state for a link.
    cookie: String,
    params: HashMap<String, String>,
}

impl Started {
    fn state_cookie(&self) -> String {
        format!("codewire_oauth_state={}", self.cookie)
    }
}

struct Reply {
    status: StatusCode,
    location: Option<String>,
    set_cookies: Vec<String>,
    body: Value,
}

impl Reply {
    fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies
            .iter()
            .find(|cookie| cookie.starts_with(&format!("{name}=")) && !cookie.contains("Max-Age=0"))
            .cloned()
    }

    fn assert_refused(&self, code: &str) {
        assert_eq!(self.status, StatusCode::SEE_OTHER);
        let location = self.location.as_deref().unwrap();
        assert!(
            location.starts_with(&format!("/login?oauth_error={code}")),
            "expected {code}, got {location}"
        );
        assert!(self.cookie("codewire.session_token").is_none());
        assert!(
            self.set_cookies
                .iter()
                .any(|cookie| cookie.starts_with("codewire_oauth_state=;")
                    && cookie.contains("Max-Age=0")),
            "the state cookie is cleared"
        );
    }
}

fn cookie_value(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .unwrap()
}

/// A GitHub account no other test uses. The tests run at once against one
/// database, so an identity two tests share signs one of them in to the
/// other's account (#4863): every identity is made here, never written out.
#[derive(Clone, Copy)]
struct GitHubId(u64);

impl GitHubId {
    fn new() -> Self {
        Self(10_000_000_000 + u64::from(rand::random::<u32>()))
    }

    /// The account id Codewire stores for it.
    fn subject(self) -> String {
        self.0.to_string()
    }

    /// The login the fake provider gives it.
    fn account(self) -> String {
        format!("user{}", self.0)
    }
}

/// A Google subject no other test uses, for the reason [`GitHubId`] gives.
struct GoogleSub(String);

impl GoogleSub {
    fn new() -> Self {
        Self(format!("google-sub-{:016x}", rand::random::<u64>()))
    }

    fn subject(&self) -> String {
        self.0.clone()
    }
}

fn github(id: GitHubId, email: &str, verified: bool) -> Answer {
    let GitHubId(id) = id;
    Answer::GitHub {
        id,
        emails: json!([
            { "email": format!("secondary-{id}@example.test"), "primary": false, "verified": true },
            { "email": email, "primary": true, "verified": verified },
        ]),
    }
}

fn google(started: &Started, sub: &GoogleSub, email: &str) -> Value {
    json!({
        "iss": "https://accounts.google.com",
        "aud": GOOGLE_CLIENT,
        "exp": chrono::Utc::now().timestamp() + 300,
        "nonce": started.params["nonce"],
        "sub": sub.0,
        "email": email,
        "email_verified": true,
        "name": "Google Person",
    })
}

async fn cleanup(pool: &PgPool, emails: &[&str], subjects: &[String]) {
    sqlx::query(
        "DELETE FROM accounts WHERE provider_id IN ('github','google') AND account_id = ANY($1)",
    )
    .bind(subjects)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM users WHERE lower(email) = ANY($1)")
        .bind(
            emails
                .iter()
                .map(|email| email.to_lowercase())
                .collect::<Vec<_>>(),
        )
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_user(pool: &PgPool, id: &str, email: &str, verified: bool, enabled: bool) {
    sqlx::query(
        "INSERT INTO users (id, email, email_verified, enabled, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(id)
    .bind(email)
    .bind(verified)
    .bind(enabled)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id, password) \
         VALUES ($1, $2, 'credential', $3, 'not-a-real-hash')",
    )
    .bind(format!("{id}-credential"))
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
}

async fn link_github(pool: &PgPool, user: &str, id: GitHubId) {
    link(pool, user, "github", id.subject()).await;
}

async fn link_google(pool: &PgPool, user: &str, sub: &GoogleSub) {
    link(pool, user, "google", sub.subject()).await;
}

async fn link(pool: &PgPool, user: &str, provider: &str, subject: String) {
    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(format!("{user}-{provider}"))
    .bind(user)
    .bind(provider)
    .bind(subject)
    .execute(pool)
    .await
    .unwrap();
}

async fn sessions(pool: &PgPool, user: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn audit_count(pool: &PgPool, user: &str, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE user_id = $1 AND action = $2")
        .bind(user)
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn invite_policy() -> SignupInvitePolicy {
    SignupInvitePolicy::from_sha256_hashes(Some(&format!(
        "{:x}",
        Sha256::digest(INVITE.as_bytes())
    )))
    .unwrap()
}

#[tokio::test]
async fn providers_endpoint_names_only_configured_providers() {
    let Some(pool) = pool().await else { return };
    let github_only = trusted_test_router(
        pool.clone(),
        true,
        SignupInvitePolicy::open(),
        ORIGIN.into(),
        OAuthProviders::with_upstream(
            Some((GITHUB_CLIENT, GITHUB_SECRET)),
            None,
            Arc::new(Fake::default()),
        ),
        Arc::new(Mailbox::default()),
    );
    let none = trusted_test_router(
        pool,
        true,
        SignupInvitePolicy::open(),
        ORIGIN.into(),
        OAuthProviders::disabled(),
        Arc::new(Mailbox::default()),
    );
    for (app, expected, google_start) in [
        (
            github_only,
            json!({ "providers": ["github"] }),
            "unavailable",
        ),
        (none, json!({ "providers": [] }), "unavailable"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get("/api/auth/oauth/providers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);

        // An unconfigured provider never reaches the provider.
        let response = app
            .oneshot(
                Request::get("/api/auth/oauth/google/start?return_to=%2Fdevice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            format!("/login?oauth_error={google_start}&return_to=%2Fdevice")
        );
    }
}

#[tokio::test]
async fn new_identity_completes_sign_up_pending_review_without_an_invite() {
    let Some(h) = Harness::new(invite_policy()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-pending@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;

    let started = h.start("github", "?authRequestID=oidc-request-1").await;
    h.answer(&started, "pending-code", github(github_id, email, true));
    let reply = h.callback("github", &started, "pending-code").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/signup/complete"));
    let signup = reply
        .cookie("codewire_oauth_signup")
        .expect("sign-up cookie");
    assert!(signup.contains("Path=/signup/complete") && signup.contains("SameSite=Lax"));
    let handle = cookie_value(&signup);
    assert!(reply.cookie("codewire.session_token").is_none());

    // The page reads the provider and email; the row survives a read.
    for _ in 0..2 {
        let pending = h
            .request(
                "POST",
                "/api/auth/oauth/signup/pending",
                &[],
                Some(json!({ "token": handle })),
            )
            .await;
        assert_eq!(pending.status, StatusCode::OK);
        assert_eq!(pending.body["provider"], "github");
        assert_eq!(pending.body["email"], email);
        assert_eq!(pending.body["auth_request_id"], "oidc-request-1");
    }

    // Without an invite, the same reason is required as for email sign-up.
    let missing_reason = h
        .request(
            "POST",
            "/api/auth/oauth/signup/complete",
            &[],
            Some(json!({ "token": handle, "reason": "  " })),
        )
        .await;
    assert_eq!(missing_reason.status, StatusCode::BAD_REQUEST);

    let complete = h
        .request(
            "POST",
            "/api/auth/oauth/signup/complete",
            &[],
            Some(json!({ "token": handle, "reason": "Build agents", "invite_code": "wrong" })),
        )
        .await;
    assert_eq!(complete.status, StatusCode::ACCEPTED, "{:?}", complete.body);
    assert_eq!(complete.body["accessPending"], true);
    assert!(complete.cookie("codewire.session_token").is_none());

    let (user_id, verified, enabled, reason): (String, bool, bool, Option<String>) =
        sqlx::query_as(
            "SELECT id, email_verified, enabled, access_reason FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(verified, "the provider verified the email");
    assert!(!enabled, "no invite: access review");
    assert_eq!(reason.as_deref(), Some("Build agents"));
    let methods: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT provider_id, account_id, password FROM accounts WHERE user_id = $1")
            .bind(&user_id)
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(methods, [("github".to_owned(), github_id.subject(), None)]);
    assert_eq!(
        audit_count(&h.pool, &user_id, "user.signup.access_requested").await,
        1
    );

    // The pending row was single use.
    let again = h
        .request(
            "POST",
            "/api/auth/oauth/signup/complete",
            &[],
            Some(json!({ "token": handle, "reason": "Build agents" })),
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    // Signing in again while access is pending meets the access gate.
    let started = h.start("github", "").await;
    h.answer(&started, "pending-again", github(github_id, email, true));
    h.callback("github", &started, "pending-again")
        .await
        .assert_refused("disabled");
    assert_eq!(sessions(&h.pool, &user_id).await, 0);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn new_identity_with_an_invite_signs_up_active_and_gets_a_session() {
    let Some(h) = Harness::new(invite_policy()).await else {
        return;
    };
    let google_sub = GoogleSub::new();
    let email = "oauth-active@example.test";
    cleanup(&h.pool, &[email], &[google_sub.subject()]).await;

    let started = h
        .start("google", "?return_to=%2Fdevice%3Fuser_code%3DABCD-EFGH")
        .await;
    let claims = google(&started, &google_sub, email);
    h.answer(&started, "active-code", Answer::Google { claims });
    let reply = h.callback("google", &started, "active-code").await;
    assert_eq!(reply.location.as_deref(), Some("/signup/complete"));
    // A Google round trip's marker keeps a sentinel, not the spent nonce.
    let (verifier, nonce): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT pkce_verifier, nonce FROM oauth_states WHERE token_hash = $1")
            .bind(hash_session_token(&started.state))
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(verifier.as_deref(), Some("-".repeat(43).as_str()));
    assert_eq!(nonce.as_deref(), Some("-".repeat(16).as_str()));
    let handle = cookie_value(&reply.cookie("codewire_oauth_signup").unwrap());

    let complete = h
        .request(
            "POST",
            "/api/auth/oauth/signup/complete",
            &[],
            Some(json!({ "token": handle, "reason": "Build agents", "invite_code": INVITE })),
        )
        .await;
    assert_eq!(complete.status, StatusCode::OK, "{:?}", complete.body);
    assert_eq!(complete.body["user"]["email"], email);
    assert_eq!(complete.body["user"]["email_verified"], true);
    assert_eq!(complete.body["return_to"], "/device?user_code=ABCD-EFGH");
    let session = complete.cookie("codewire.session_token").expect("session");
    assert!(session.contains("Secure") && session.contains("SameSite=Lax"));
    let (user_id, enabled, name): (String, bool, Option<String>) =
        sqlx::query_as("SELECT id, enabled, name FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(enabled);
    assert_eq!(name.as_deref(), Some("Google Person"));
    assert_eq!(sessions(&h.pool, &user_id).await, 1);
    assert_eq!(audit_count(&h.pool, &user_id, "user.signup").await, 1);
    cleanup(&h.pool, &[email], &[google_sub.subject()]).await;
}

#[tokio::test]
async fn an_open_server_signs_up_a_new_identity_active_without_an_invite_or_reason() {
    let Some(h) = Harness::new(invite_policy().with_mode(SignupMode::Open)).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-open@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;

    let started = h.start("github", "").await;
    h.answer(&started, "open-code", github(github_id, email, true));
    let reply = h.callback("github", &started, "open-code").await;
    assert_eq!(reply.location.as_deref(), Some("/signup/complete"));
    let handle = cookie_value(&reply.cookie("codewire_oauth_signup").unwrap());

    let complete = h
        .request(
            "POST",
            "/api/auth/oauth/signup/complete",
            &[],
            Some(json!({ "token": handle })),
        )
        .await;
    assert_eq!(complete.status, StatusCode::OK, "{:?}", complete.body);
    assert!(complete.body.get("accessPending").is_none());
    assert!(complete.cookie("codewire.session_token").is_some());
    let (user_id, verified, enabled, reason): (String, bool, bool, Option<String>) =
        sqlx::query_as(
            "SELECT id, email_verified, enabled, access_reason FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(verified && enabled);
    assert!(reason.is_none());
    assert_eq!(sessions(&h.pool, &user_id).await, 1);
    assert_eq!(audit_count(&h.pool, &user_id, "user.signup").await, 1);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn a_linked_identity_signs_in_and_returns_to_its_target() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-returning@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-returning", email, false, true).await;
    link_github(&h.pool, "oauth-returning", github_id).await;
    sqlx::query("UPDATE users SET failed_login_attempts = 3 WHERE id = 'oauth-returning'")
        .execute(&h.pool)
        .await
        .unwrap();

    let started = h
        .start("github", "?return_to=%2Fdevice%3Fuser_code%3DWXYZ-1234")
        .await;
    // GitHub's primary email need not match a linked account's address.
    h.answer(
        &started,
        "returning-code",
        github(github_id, "other@example.test", true),
    );
    let reply = h.callback("github", &started, "returning-code").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.location.as_deref(),
        Some("/setup-2fa?return_to=%2Fdevice%3Fuser_code%3DWXYZ-1234")
    );
    let session = reply.cookie("codewire.session_token").expect("session");
    let token = cookie_value(&session);
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE user_id = 'oauth-returning' AND token_hash = $1",
    )
    .bind(hash_session_token(&token))
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(stored, 1);
    let attempts: i32 =
        sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = 'oauth-returning'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(attempts, 0, "a completed sign-in resets the failure count");
    assert_eq!(
        audit_count(&h.pool, "oauth-returning", "user.signin").await,
        1
    );
    // No provider token is kept and no second account was made.
    let tokens: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM accounts WHERE user_id = 'oauth-returning' \
         AND (access_token IS NOT NULL OR refresh_token IS NOT NULL OR id_token IS NOT NULL)",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(tokens, 0);
    let others: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE email = 'other@example.test'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(others, 0);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn google_links_a_gmail_or_hosted_domain_match_automatically() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let gmail_sub = GoogleSub::new();
    let hosted_sub = GoogleSub::new();
    let gmail = "OAuth.Link@GMail.com";
    let hosted = "oauth-hosted@corp-oauth.example";
    cleanup(
        &h.pool,
        &[gmail, hosted],
        &[gmail_sub.subject(), hosted_sub.subject()],
    )
    .await;
    insert_user(&h.pool, "oauth-link", gmail, true, true).await;
    insert_user(&h.pool, "oauth-hd", hosted, true, true).await;

    for (user, subject, email, hd) in [
        // Google spells the address in lower case; it is the same account.
        ("oauth-link", &gmail_sub, gmail.to_lowercase(), None),
        (
            "oauth-hd",
            &hosted_sub,
            hosted.to_owned(),
            Some("corp-oauth.example"),
        ),
    ] {
        let started = h.start("google", "").await;
        let mut claims = google(&started, subject, &email);
        if let Some(hd) = hd {
            claims["hd"] = json!(hd);
        }
        let code = format!("link-{}", subject.subject());
        h.answer(&started, &code, Answer::Google { claims });
        let reply = h.callback("google", &started, &code).await;
        assert_eq!(
            reply.location.as_deref(),
            Some("/setup-2fa?return_to=%2Fdashboard%2F"),
            "{email}"
        );
        assert!(reply.cookie("codewire.session_token").is_some());

        let linked: Vec<String> = sqlx::query_scalar(
            "SELECT user_id FROM accounts WHERE provider_id = 'google' AND account_id = $1",
        )
        .bind(subject.subject())
        .fetch_all(&h.pool)
        .await
        .unwrap();
        assert_eq!(linked, [user]);
        let metadata: Value = sqlx::query_scalar(
            "SELECT metadata FROM audit_logs WHERE user_id = $1 AND action = 'user.oauth.linked'",
        )
        .bind(user)
        .fetch_one(&h.pool)
        .await
        .unwrap();
        assert_eq!(metadata["provider"], "google");
        assert_eq!(metadata["provider_email"], email);
        assert_eq!(metadata["automatic"], true);
        assert_eq!(metadata["confirmed_by"], "provider");
        // The password stays.
        let credential: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user)
        .fetch_one(&h.pool)
        .await
        .unwrap();
        assert_eq!(credential, 1);
    }
    assert_eq!(h.mail.count(), 0, "no confirmation for a vouched address");
    cleanup(
        &h.pool,
        &[gmail, hosted],
        &[gmail_sub.subject(), hosted_sub.subject()],
    )
    .await;
}

async fn link_rows(pool: &PgPool, provider: &str, subject: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM accounts WHERE provider_id = $1 AND account_id = $2")
        .bind(provider)
        .bind(subject)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn pending_confirmations(pool: &PgPool, user: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM oauth_states WHERE intent = 'link_confirm' AND user_id = $1",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

impl Reply {
    fn assert_link_sent(&self, provider: &str) {
        assert_eq!(self.status, StatusCode::SEE_OTHER);
        assert_eq!(
            self.location.as_deref(),
            Some(format!("/login?oauth_notice=link_sent&provider={provider}").as_str())
        );
        assert!(self.cookie("codewire.session_token").is_none());
        assert!(self.cookie("codewire_2fa_challenge").is_none());
        let requester = self
            .cookie("codewire_oauth_link_requester")
            .expect("the requesting browser keeps a secret");
        assert!(
            requester.contains("Path=/login/link")
                && requester.contains("HttpOnly")
                && requester.contains("SameSite=Lax")
                && requester.contains("Max-Age=1800")
                && requester.contains("Secure"),
            "{requester}"
        );
    }
}

#[tokio::test]
async fn a_github_email_match_is_linked_only_from_the_accounts_own_email() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-github-confirm@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-github-confirm", email, true, true).await;

    let started = h.start("github", "").await;
    h.answer(&started, "confirm-code", github(github_id, email, true));
    let reply = h.callback("github", &started, "confirm-code").await;
    reply.assert_link_sent("github");
    assert_eq!(
        link_rows(&h.pool, "github", &github_id.subject()).await,
        0,
        "nothing linked yet"
    );
    assert_eq!(sessions(&h.pool, "oauth-github-confirm").await, 0);
    let (to, provider, token) = h.mail.last();
    assert_eq!((to.as_str(), provider), (email, "github"));
    // Only a hash of the token is stored.
    let stored: (String, i64) = sqlx::query_as(
        "SELECT token_hash, extract(epoch FROM expires_at - created_at)::bigint          FROM oauth_states WHERE intent = 'link_confirm' AND user_id = 'oauth-github-confirm'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(stored, (hash_session_token(&token), 30 * 60));
    assert_eq!(
        audit_count(&h.pool, "oauth-github-confirm", "user.oauth.link_requested").await,
        1
    );

    // Reading the confirmation, as a mail scanner's prefetch does, uses
    // nothing up.
    for _ in 0..2 {
        let pending = h.pending_link(&token).await;
        assert_eq!(pending.status, StatusCode::OK);
        assert_eq!(pending.body["provider"], "github");
    }

    let confirmed = h.confirm_link(&token).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body);
    assert_eq!(confirmed.body["provider"], "github");
    assert!(
        confirmed.cookie("codewire.session_token").is_none(),
        "no session"
    );
    assert_eq!(sessions(&h.pool, "oauth-github-confirm").await, 0);
    let owner: String = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = 'github' AND account_id = $1",
    )
    .bind(github_id.subject())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owner, "oauth-github-confirm");
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_logs WHERE user_id = 'oauth-github-confirm'          AND action = 'user.oauth.linked'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(metadata["confirmed_by"], "email");
    assert_eq!(metadata["automatic"], false);
    assert_eq!(metadata["provider_email"], email);

    // Single use.
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.pending_link(&token).await.status, StatusCode::NOT_FOUND);

    // Now GitHub signs in through the gates.
    let started = h.start("github", "").await;
    h.answer(
        &started,
        "confirmed-sign-in",
        github(github_id, email, true),
    );
    let reply = h.callback("github", &started, "confirmed-sign-in").await;
    assert!(reply.cookie("codewire.session_token").is_some());
    assert_eq!(h.mail.count(), 1);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn a_confirmation_completes_only_in_the_browser_that_asked_for_it() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-requester@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-requester", email, true, true).await;

    let started = h.start("github", "").await;
    h.answer(&started, "requester-code", github(github_id, email, true));
    h.callback("github", &started, "requester-code")
        .await
        .assert_link_sent("github");
    let (_, _, token) = h.mail.last();
    // The email and the page name the provider account.
    assert_eq!(h.mail.last_account(), github_id.account());
    let pending = h.pending_link(&token).await;
    assert_eq!(pending.body["account"], github_id.account());
    // Only a hash of the requester secret is stored.
    let requester = h.requester.lock().unwrap().clone().expect("requester");
    let stored: String = sqlx::query_scalar(
        "SELECT requester_hash FROM oauth_states \
         WHERE intent = 'link_confirm' AND user_id = 'oauth-requester'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(stored, hash_session_token(&requester));

    // The account owner opens the emailed link in another browser: no
    // requester secret, or someone else's. Nothing is linked and the token
    // stays usable.
    for other in [None, Some("0".repeat(64)), Some("not-a-secret".to_owned())] {
        let refused = h.confirm_link_from(&token, other.as_deref()).await;
        assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED, "{other:?}");
        assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 0);
        assert_eq!(h.pending_link(&token).await.status, StatusCode::OK);
    }

    // The browser that started the sign-in confirms.
    let confirmed = h.confirm_link(&token).await;
    assert_eq!(confirmed.status, StatusCode::OK);
    assert_eq!(confirmed.body["account"], github_id.account());
    assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 1);
    assert_eq!(sessions(&h.pool, "oauth-requester").await, 0);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn a_new_confirmation_replaces_the_old_and_an_expired_one_is_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-replace@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-replace", email, true, true).await;

    let mut tokens = Vec::new();
    for code in ["replace-1", "replace-2"] {
        let started = h.start("github", "").await;
        h.answer(&started, code, github(github_id, email, true));
        h.callback("github", &started, code)
            .await
            .assert_link_sent("github");
        tokens.push(h.mail.last().2);
    }
    assert_eq!(pending_confirmations(&h.pool, "oauth-replace").await, 1);
    assert_eq!(
        h.confirm_link(&tokens[0]).await.status,
        StatusCode::NOT_FOUND
    );

    sqlx::query(
        "UPDATE oauth_states SET created_at = NOW() - interval '40 minutes',          expires_at = NOW() - interval '10 minutes'          WHERE intent = 'link_confirm' AND user_id = 'oauth-replace'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        h.pending_link(&tokens[1]).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.confirm_link(&tokens[1]).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 0);
    // Unknown and malformed tokens get the same answer.
    for token in ["0".repeat(64), "not-a-token".to_owned()] {
        assert_eq!(h.confirm_link(&token).await.status, StatusCode::NOT_FOUND);
    }
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn google_without_a_vouched_domain_is_confirmed_by_email() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let plain_sub = GoogleSub::new();
    let wrong_domain_sub = GoogleSub::new();
    let email = "oauth-google-confirm@corp-other.example";
    cleanup(
        &h.pool,
        &[email],
        &[plain_sub.subject(), wrong_domain_sub.subject()],
    )
    .await;
    insert_user(&h.pool, "oauth-google-confirm", email, true, true).await;

    for (subject, hd) in [
        (&plain_sub, None),
        (&wrong_domain_sub, Some("another-domain.example")),
    ] {
        let started = h.start("google", "").await;
        let mut claims = google(&started, subject, email);
        if let Some(hd) = hd {
            claims["hd"] = json!(hd);
        }
        let code = format!("confirm-{}", subject.subject());
        h.answer(&started, &code, Answer::Google { claims });
        h.callback("google", &started, &code)
            .await
            .assert_link_sent("google");
        assert_eq!(link_rows(&h.pool, "google", &subject.subject()).await, 0);
        let (to, provider, _) = h.mail.last();
        assert_eq!((to.as_str(), provider), (email, "google"));
        assert_eq!(h.mail.last_account(), email);
    }
    // The second replaced the first: one confirmation, for the last identity.
    let (_, _, token) = h.mail.last();
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::OK);
    assert_eq!(
        link_rows(&h.pool, "google", &wrong_domain_sub.subject()).await,
        1
    );
    assert_eq!(link_rows(&h.pool, "google", &plain_sub.subject()).await, 0);
    assert_eq!(sessions(&h.pool, "oauth-google-confirm").await, 0);
    cleanup(
        &h.pool,
        &[email],
        &[plain_sub.subject(), wrong_domain_sub.subject()],
    )
    .await;
}

#[tokio::test]
async fn a_confirmation_is_refused_when_the_account_changed_since() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let other_github_id = GitHubId::new();
    let email = "oauth-changed@example.test";
    cleanup(
        &h.pool,
        &[email],
        &[github_id.subject(), other_github_id.subject()],
    )
    .await;
    insert_user(&h.pool, "oauth-changed", email, true, true).await;

    // Disabled in between.
    let started = h.start("github", "").await;
    h.answer(&started, "changed-1", github(github_id, email, true));
    h.callback("github", &started, "changed-1")
        .await
        .assert_link_sent("github");
    let (_, _, token) = h.mail.last();
    sqlx::query("UPDATE users SET enabled = false WHERE id = 'oauth-changed'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::FORBIDDEN);
    assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 0);
    // Used up: enabling the account again does not revive it.
    sqlx::query("UPDATE users SET enabled = true WHERE id = 'oauth-changed'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::NOT_FOUND);

    // Locked in between.
    let started = h.start("github", "").await;
    h.answer(&started, "changed-2", github(github_id, email, true));
    h.callback("github", &started, "changed-2")
        .await
        .assert_link_sent("github");
    let (_, _, token) = h.mail.last();
    sqlx::query(
        "UPDATE users SET locked_until = NOW() + interval '10 minutes' WHERE id = 'oauth-changed'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::FORBIDDEN);
    assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 0);
    sqlx::query("UPDATE users SET locked_until = NULL WHERE id = 'oauth-changed'")
        .execute(&h.pool)
        .await
        .unwrap();

    // The identity was linked to someone else in between.
    let started = h.start("github", "").await;
    h.answer(&started, "changed-3", github(other_github_id, email, true));
    h.callback("github", &started, "changed-3")
        .await
        .assert_link_sent("github");
    let (_, _, token) = h.mail.last();
    let other = "oauth-changed-other@example.test";
    cleanup(&h.pool, &[other], &[]).await;
    insert_user(&h.pool, "oauth-changed-other", other, true, true).await;
    link_github(&h.pool, "oauth-changed-other", other_github_id).await;
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::CONFLICT);
    let owner: String = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = 'github' AND account_id = $1",
    )
    .bind(other_github_id.subject())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owner, "oauth-changed-other");
    cleanup(
        &h.pool,
        &[email, other],
        &[github_id.subject(), other_github_id.subject()],
    )
    .await;
}

#[tokio::test]
async fn starts_from_many_addresses_write_no_rows() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    // More starts than any per-address bound, each from its own address, and
    // past the 30 one address could once hold.
    let mut hashes = Vec::new();
    for client in 0..40u8 {
        for provider in ["github", "google"] {
            let started = h
                .start_from(
                    &format!("198.51.100.{client}"),
                    provider,
                    "?return_to=%2Fdevice",
                )
                .await;
            hashes.push(hash_session_token(&started.state));
        }
    }
    for _ in 0..40 {
        let started = h.start("github", "").await;
        hashes.push(hash_session_token(&started.state));
    }
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_states WHERE token_hash = ANY($1)")
            .bind(&hashes)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "a start writes nothing");
}

#[tokio::test]
async fn an_invite_only_server_refuses_provider_sign_up() {
    let Some(h) =
        Harness::new(SignupInvitePolicy::default().with_mode(SignupMode::InviteOnly)).await
    else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-invite-only-new@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;

    let started = h.start("github", "").await;
    h.answer(&started, "invite-only-code", github(github_id, email, true));
    h.callback("github", &started, "invite-only-code")
        .await
        .assert_refused("invite_only");
    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(created, 0);
}

/// An identity already linked to an account signs in to it on an invite-only
/// server too: that is a sign-in, not a sign-up. It is what the test above
/// met when another test's link held the identity it reused (#4863), and it
/// still makes no account for the address the provider reports.
#[tokio::test]
async fn an_invite_only_server_signs_in_an_identity_already_linked() {
    let Some(h) =
        Harness::new(SignupInvitePolicy::default().with_mode(SignupMode::InviteOnly)).await
    else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-invite-only-linked@example.test";
    let reported = "oauth-invite-only-reported@example.test";
    cleanup(&h.pool, &[email, reported], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-invite-only-linked", email, true, true).await;
    link_github(&h.pool, "oauth-invite-only-linked", github_id).await;

    let started = h.start("github", "").await;
    h.answer(
        &started,
        "invite-only-linked-code",
        github(github_id, reported, true),
    );
    let reply = h
        .callback("github", &started, "invite-only-linked-code")
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.location.as_deref(),
        Some("/setup-2fa?return_to=%2Fdashboard%2F")
    );
    assert!(reply.cookie("codewire.session_token").is_some());
    assert_eq!(sessions(&h.pool, "oauth-invite-only-linked").await, 1);
    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
        .bind(reported)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(created, 0);
    cleanup(&h.pool, &[email, reported], &[github_id.subject()]).await;
}

#[tokio::test]
async fn a_vouched_address_is_never_linked_by_a_provider_that_owns_it() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let google_sub = GoogleSub::new();
    // Google vouches for a whole @gmail.com address, the case that links at
    // once when the account's address is verified.
    let email = "oauth-vouched-owner@gmail.com";
    cleanup(&h.pool, &[email], &[google_sub.subject()]).await;
    insert_user(&h.pool, "oauth-vouched-owner", email, false, true).await;
    sqlx::query(
        "UPDATE users SET email_vouched_by = 'invitation' WHERE id = 'oauth-vouched-owner'",
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let started = h.start("google", "").await;
    let claims = google(&started, &google_sub, email);
    h.answer(&started, "vouched-code", Answer::Google { claims });
    h.callback("google", &started, "vouched-code")
        .await
        .assert_refused("link_required");
    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE user_id = 'oauth-vouched-owner' AND provider_id = 'google'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(linked, 0);
    assert_eq!(sessions(&h.pool, "oauth-vouched-owner").await, 0);
    cleanup(&h.pool, &[email], &[google_sub.subject()]).await;
}

#[tokio::test]
async fn an_unverified_codewire_email_is_never_linked() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "oauth-unverified-owner@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-unverified-owner", email, false, true).await;

    let started = h.start("github", "?authRequestID=oidc-request-2").await;
    h.answer(&started, "takeover-code", github(github_id, email, true));
    let reply = h.callback("github", &started, "takeover-code").await;
    reply.assert_refused("link_required");
    assert_eq!(
        reply.location.as_deref(),
        Some("/login?oauth_error=link_required&authRequestID=oidc-request-2")
    );
    let provider_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM accounts WHERE user_id = 'oauth-unverified-owner' AND provider_id = 'github'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(provider_rows, 0);
    assert_eq!(sessions(&h.pool, "oauth-unverified-owner").await, 0);
    // An account that never verified its address gets no confirmation either:
    // whoever registered the address first would gain the identity.
    assert_eq!(h.mail.count(), 0);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn two_factor_is_still_asked_after_a_provider_sign_in() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let other_github_id = GitHubId::new();
    let google_sub = GoogleSub::new();
    let email = "oauth-2fa@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-2fa", email, true, true).await;
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE id = 'oauth-2fa'")
        .execute(&h.pool)
        .await
        .unwrap();
    link_github(&h.pool, "oauth-2fa", github_id).await;

    let started = h.start("github", "?authRequestID=oidc-request-3").await;
    h.answer(&started, "2fa-code", github(github_id, email, true));
    let reply = h.callback("github", &started, "2fa-code").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.location.as_deref(),
        Some("/two-factor?authRequestID=oidc-request-3")
    );
    assert!(reply.cookie("codewire.session_token").is_none());
    let challenge = reply.cookie("codewire_2fa_challenge").expect("challenge");
    assert!(
        challenge.contains("Path=/two-factor")
            && challenge.contains("HttpOnly")
            && challenge.contains("SameSite=Lax")
            && challenge.contains("Max-Age=600"),
        "{challenge}"
    );
    let owner: String = sqlx::query_scalar(
        "SELECT user_id FROM two_factor_tokens WHERE token_hash = $1 AND expires_at > NOW()",
    )
    .bind(hash_session_token(&cookie_value(&challenge)))
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owner, "oauth-2fa");
    assert_eq!(sessions(&h.pool, "oauth-2fa").await, 0);
    sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = 'oauth-2fa'")
        .execute(&h.pool)
        .await
        .unwrap();

    // An unlinked identity with that verified email is never linked to an
    // account enrolled in two-factor before its second factor passes, even
    // for a Google-vouched address: the account's own address confirms it,
    // and nothing is linked until then.
    let gmail = "oauth-2fa-google@gmail.com";
    cleanup(&h.pool, &[gmail], &[google_sub.subject()]).await;
    insert_user(&h.pool, "oauth-2fa-google", gmail, true, true).await;
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE id = 'oauth-2fa-google'")
        .execute(&h.pool)
        .await
        .unwrap();
    let started = h.start("github", "").await;
    h.answer(
        &started,
        "2fa-unlinked-code",
        github(other_github_id, email, true),
    );
    h.callback("github", &started, "2fa-unlinked-code")
        .await
        .assert_link_sent("github");
    assert_eq!(
        link_rows(&h.pool, "github", &other_github_id.subject()).await,
        0
    );
    let started = h.start("google", "").await;
    let claims = google(&started, &google_sub, gmail);
    h.answer(&started, "2fa-google-code", Answer::Google { claims });
    h.callback("google", &started, "2fa-google-code")
        .await
        .assert_link_sent("google");
    assert_eq!(link_rows(&h.pool, "google", &google_sub.subject()).await, 0);
    assert_eq!(h.mail.last().0, gmail);

    // Confirming links without a session; signing in with the provider
    // then asks for the second factor.
    let (_, _, token) = h.mail.last();
    assert_eq!(h.confirm_link(&token).await.status, StatusCode::OK);
    assert_eq!(link_rows(&h.pool, "google", &google_sub.subject()).await, 1);
    assert_eq!(sessions(&h.pool, "oauth-2fa-google").await, 0);
    let started = h.start("google", "").await;
    let claims = google(&started, &google_sub, gmail);
    h.answer(&started, "2fa-google-sign-in", Answer::Google { claims });
    let reply = h.callback("google", &started, "2fa-google-sign-in").await;
    assert_eq!(reply.location.as_deref(), Some("/two-factor"));
    assert!(reply.cookie("codewire_2fa_challenge").is_some());
    assert!(reply.cookie("codewire.session_token").is_none());
    assert_eq!(sessions(&h.pool, "oauth-2fa-google").await, 0);
    sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = 'oauth-2fa-google'")
        .execute(&h.pool)
        .await
        .unwrap();
    cleanup(
        &h.pool,
        &[email, gmail],
        &[
            github_id.subject(),
            other_github_id.subject(),
            google_sub.subject(),
        ],
    )
    .await;
}

#[tokio::test]
async fn disabled_and_locked_accounts_are_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let disabled_github = GitHubId::new();
    let locked_github = GitHubId::new();
    let unlinked_disabled_github = GitHubId::new();
    let unlinked_locked_github = GitHubId::new();
    let disabled = "oauth-disabled@example.test";
    let locked = "oauth-locked@example.test";
    cleanup(
        &h.pool,
        &[disabled, locked],
        &[disabled_github.subject(), locked_github.subject()],
    )
    .await;
    insert_user(&h.pool, "oauth-disabled", disabled, true, false).await;
    link_github(&h.pool, "oauth-disabled", disabled_github).await;
    insert_user(&h.pool, "oauth-locked", locked, true, true).await;
    link_github(&h.pool, "oauth-locked", locked_github).await;
    sqlx::query(
        "UPDATE users SET locked_until = NOW() + interval '10 minutes' WHERE id = 'oauth-locked'",
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let started = h.start("github", "").await;
    h.answer(
        &started,
        "disabled-code",
        github(disabled_github, disabled, true),
    );
    h.callback("github", &started, "disabled-code")
        .await
        .assert_refused("disabled");
    assert_eq!(sessions(&h.pool, "oauth-disabled").await, 0);

    let started = h.start("github", "").await;
    h.answer(&started, "locked-code", github(locked_github, locked, true));
    h.callback("github", &started, "locked-code")
        .await
        .assert_refused("locked");
    assert_eq!(sessions(&h.pool, "oauth-locked").await, 0);
    cleanup(
        &h.pool,
        &[disabled, locked],
        &[disabled_github.subject(), locked_github.subject()],
    )
    .await;

    // An unlinked identity whose verified email matches a disabled or locked
    // account is refused as that account would be, and is not linked to it.
    cleanup(
        &h.pool,
        &[disabled, locked],
        &[
            unlinked_disabled_github.subject(),
            unlinked_locked_github.subject(),
        ],
    )
    .await;
    insert_user(&h.pool, "oauth-disabled", disabled, true, false).await;
    insert_user(&h.pool, "oauth-locked", locked, true, true).await;
    sqlx::query(
        "UPDATE users SET locked_until = NOW() + interval '10 minutes' WHERE id = 'oauth-locked'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    for (subject, email, code, refusal) in [
        (
            unlinked_disabled_github,
            disabled,
            "unlinked-disabled-code",
            "disabled",
        ),
        (
            unlinked_locked_github,
            locked,
            "unlinked-locked-code",
            "locked",
        ),
    ] {
        let started = h.start("github", "").await;
        h.answer(&started, code, github(subject, email, true));
        h.callback("github", &started, code)
            .await
            .assert_refused(refusal);
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM accounts WHERE provider_id = 'github' AND account_id = $1",
        )
        .bind(subject.subject())
        .fetch_one(&h.pool)
        .await
        .unwrap();
        assert_eq!(links, 0, "{refusal} account was linked");
    }
    assert_eq!(h.mail.count(), 0, "no confirmation for a refused account");
    cleanup(
        &h.pool,
        &[disabled, locked],
        &[
            unlinked_disabled_github.subject(),
            unlinked_locked_github.subject(),
        ],
    )
    .await;
}

#[tokio::test]
async fn state_missing_replaced_tampered_or_replayed_is_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let h = &h;
    let github_id = GitHubId::new();
    let email = "oauth-state@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "oauth-state", email, true, true).await;
    link_github(&h.pool, "oauth-state", github_id).await;
    let exchanges = || *h.fake.exchanges.lock().unwrap();
    let callback = |state: &str, cookies: Vec<String>| {
        let path = format!("/api/auth/oauth/github/callback?code=state-code&state={state}");
        async move { h.request("GET", &path, &cookies, None).await }
    };
    let resealed = |started: &Started, edit: fn(&mut Vec<u8>)| {
        let mut bytes = URL_SAFE_NO_PAD.decode(&started.cookie).unwrap();
        edit(&mut bytes);
        format!("codewire_oauth_state={}", URL_SAFE_NO_PAD.encode(bytes))
    };

    let started = h.start("github", "").await;
    h.answer(&started, "state-code", github(github_id, email, true));
    let before = exchanges();
    // No cookie: a callback in another browser.
    callback(&started.state, Vec::new())
        .await
        .assert_refused("expired");
    // A newer start in another tab replaced this browser's cookie.
    let newer = h.start("github", "").await;
    callback(&started.state, vec![newer.state_cookie()])
        .await
        .assert_refused("expired");
    // No state query.
    h.request(
        "GET",
        "/api/auth/oauth/github/callback?code=state-code",
        &[started.state_cookie()],
        None,
    )
    .await
    .assert_refused("expired");
    // Sealed for one provider, used on the other's callback.
    h.callback("google", &started, "state-code")
        .await
        .assert_refused("expired");
    // Changed, or of another version. An expired cookie is refused the same
    // way, before any exchange (the lib tests seal one).
    for edit in [
        (|bytes: &mut Vec<u8>| *bytes.last_mut().unwrap() ^= 1) as fn(&mut Vec<u8>),
        |bytes| bytes[0] = 2,
    ] {
        callback(&started.state, vec![resealed(&started, edit)])
            .await
            .assert_refused("expired");
    }
    // A sign-in the release before sealed cookies started: its raw state
    // matches its row, which only a link's callback may claim.
    let old_state = format!("{}{}", hex_token(), hex_token());
    sqlx::query(
        "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
         VALUES ($1, $2, 'github', 'sign_in', $3, NOW() + interval '10 minutes')",
    )
    .bind(format!("oauth-state-old-{}", hex_token()))
    .bind(hash_session_token(&old_state))
    .bind("v".repeat(43))
    .execute(&h.pool)
    .await
    .unwrap();
    callback(
        &old_state,
        vec![format!("codewire_oauth_state={old_state}")],
    )
    .await
    .assert_refused("expired");
    assert_eq!(exchanges(), before, "no refused state reaches the provider");
    sqlx::query("DELETE FROM oauth_states WHERE token_hash = $1")
        .bind(hash_session_token(&old_state))
        .execute(&h.pool)
        .await
        .unwrap();

    // Replayed: the first use signs in and marks the state used; the second
    // is refused even though the provider (here) accepts the code again.
    let replayed = h.start("github", "").await;
    h.answer(&replayed, "replay-code", github(github_id, email, true));
    let first = h.callback("github", &replayed, "replay-code").await;
    assert!(first.cookie("codewire.session_token").is_some());
    h.answer(&replayed, "replay-code", github(github_id, email, true));
    h.callback("github", &replayed, "replay-code")
        .await
        .assert_refused("expired");
    let markers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_states WHERE token_hash = $1 AND intent = 'sign_in' \
         AND expires_at > NOW()",
    )
    .bind(hash_session_token(&replayed.state))
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(markers, 1);
    // The marker keeps nothing of the round trip: fixed sentinels stand
    // where the schema requires a verifier.
    let (verifier, nonce): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT pkce_verifier, nonce FROM oauth_states WHERE token_hash = $1")
            .bind(hash_session_token(&replayed.state))
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(verifier.as_deref(), Some("-".repeat(43).as_str()));
    assert_eq!(nonce, None);
    assert_eq!(sessions(&h.pool, "oauth-state").await, 1);

    // The starts that never finished wrote nothing.
    let unfinished: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_states WHERE token_hash = ANY($1)")
            .bind(vec![
                hash_session_token(&started.state),
                hash_session_token(&newer.state),
            ])
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(unfinished, 0);
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn an_unverified_provider_email_is_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let google_sub = GoogleSub::new();
    let email = "oauth-provider-unverified@example.test";
    cleanup(
        &h.pool,
        &[email],
        &[github_id.subject(), google_sub.subject()],
    )
    .await;

    let started = h.start("github", "").await;
    h.answer(&started, "unverified-code", github(github_id, email, false));
    h.callback("github", &started, "unverified-code")
        .await
        .assert_refused("unverified_email");

    let started = h.start("google", "").await;
    let mut claims = google(&started, &google_sub, email);
    claims["email_verified"] = json!(false);
    h.answer(&started, "google-unverified", Answer::Google { claims });
    h.callback("google", &started, "google-unverified")
        .await
        .assert_refused("unverified_email");

    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_states WHERE intent = 'sign_up' AND provider_identity->>'email' = $1",
    )
    .bind(email)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(pending, 0);
}

#[tokio::test]
async fn a_google_nonce_or_audience_mismatch_is_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let google_sub = GoogleSub::new();
    let email = "oauth-google-mismatch@example.test";
    cleanup(&h.pool, &[email], &[google_sub.subject()]).await;

    for (field, value) in [
        ("nonce", json!("a-nonce-from-another-round-trip")),
        ("aud", json!("another-client")),
        ("iss", json!("https://issuer.example")),
        ("exp", json!(chrono::Utc::now().timestamp() - 600)),
    ] {
        let started = h.start("google", "").await;
        let mut claims = google(&started, &google_sub, email);
        claims[field] = value;
        let code = format!("mismatch-{field}");
        h.answer(&started, &code, Answer::Google { claims });
        h.callback("google", &started, &code)
            .await
            .assert_refused("failed");
    }
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[tokio::test]
async fn provider_cancel_and_exchange_failures_land_on_login() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };

    // The person cancels at GitHub: the state is still used up.
    let started = h.start("github", "?return_to=%2Fdevice").await;
    let reply = h
        .request(
            "GET",
            &format!(
                "/api/auth/oauth/github/callback?error=access_denied&error_description=The+user+has+denied&state={}",
                started.state
            ),
            &[started.state_cookie()],
            None,
        )
        .await;
    reply.assert_refused("cancelled");
    assert_eq!(
        reply.location.as_deref(),
        Some("/login?oauth_error=cancelled&return_to=%2Fdevice")
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_states WHERE token_hash = $1")
        .bind(hash_session_token(&started.state))
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);

    // The provider refuses the code.
    let started = h.start("github", "").await;
    h.answer(&started, "refused-code", Answer::Refused);
    h.callback("github", &started, "refused-code")
        .await
        .assert_refused("failed");

    // A code the provider never issued.
    let started = h.start("google", "").await;
    h.callback("google", &started, "unknown-code")
        .await
        .assert_refused("failed");
}

#[tokio::test]
async fn the_sweeper_deletes_expired_rows_and_keeps_live_ones() {
    let Some(pool) = pool().await else { return };
    let run = hex_token();
    let row = |name: &str| format!("oauth-sweep-{run}-{name}");
    for (name, created, expires) in [
        ("expired", "20 minutes", "-1 minute"),
        ("live", "0 minutes", "10 minutes"),
    ] {
        sqlx::query(
            "INSERT INTO oauth_states \
                 (id, token_hash, provider, intent, provider_identity, created_at, expires_at) \
             VALUES ($1, $2, 'github', 'sign_up', '{}'::jsonb, \
                     NOW() - $3::interval, NOW() + $4::interval)",
        )
        .bind(row(name))
        .bind(hash_session_token(&row(name)))
        .bind(created)
        .bind(expires)
        .execute(&pool)
        .await
        .unwrap();
    }

    codewire_idp::oauth::sweep_expired_states(&pool)
        .await
        .unwrap();

    let left: Vec<String> =
        sqlx::query_scalar("SELECT id FROM oauth_states WHERE id LIKE $1 ORDER BY id")
            .bind(format!("oauth-sweep-{run}-%"))
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(left, [row("live")]);
    sqlx::query("DELETE FROM oauth_states WHERE id = $1")
        .bind(row("live"))
        .execute(&pool)
        .await
        .unwrap();
}

// --- Sign-in methods in Settings: connect and disconnect ---

/// A live browser session for `user`, past the two-factor boundary when
/// `setup_skipped` (none of these accounts enrols a factor).
async fn browser_session(pool: &PgPool, user: &str, setup_skipped: bool) -> String {
    let token = format!("{user}-{}", hex_token());
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, two_factor_setup_skipped_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour', \
                 CASE WHEN $4 THEN NOW()::timestamp END)",
    )
    .bind(format!("{user}-session-{}", &hex_token()[..8]))
    .bind(user)
    .bind(hash_session_token(&token))
    .bind(setup_skipped)
    .execute(pool)
    .await
    .unwrap();
    token
}

fn hex_token() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn session_cookie(token: &str) -> String {
    format!("codewire.session_token={token}")
}

impl Harness {
    /// A same-origin JSON request as the dashboard sends it for a browser.
    async fn account_request(&self, path: &str, session: &str, body: Value) -> Reply {
        let request = Request::post(path)
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, session_cookie(session))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        self.reply(request).await
    }

    async fn reply(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            location,
            set_cookies,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn link_start_reply(&self, provider: &str, account: &str, session: &str) -> Reply {
        self.account_request(
            "/api/auth/oauth/identities/link",
            session,
            json!({ "account_id": account, "provider": provider }),
        )
        .await
    }

    /// Start a link from Settings and return the round trip it began.
    async fn link_start(&self, provider: &str, account: &str, session: &str) -> Started {
        let reply = self.link_start_reply(provider, account, session).await;
        assert_eq!(reply.status, StatusCode::OK, "link start {}", reply.body);
        let location = reqwest::Url::parse(reply.body["location"].as_str().unwrap()).unwrap();
        let params: HashMap<String, String> = location.query_pairs().into_owned().collect();
        let cookie = reply.cookie("codewire_oauth_state").expect("state cookie");
        assert!(
            cookie.contains("Path=/api/auth/oauth/")
                && cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Lax")
                && cookie.contains("Secure"),
            "{cookie}"
        );
        let state = cookie_value(&cookie);
        assert_eq!(params["state"], state);
        assert_eq!(params["code_challenge_method"], "S256");
        Started {
            cookie: state.clone(),
            state,
            params,
        }
    }

    /// The provider's redirect back, in a browser holding `session`.
    async fn link_callback(
        &self,
        provider: &str,
        started: &Started,
        code: &str,
        session: Option<&str>,
    ) -> Reply {
        let mut cookies = started.state_cookie();
        if let Some(session) = session {
            cookies.push_str("; ");
            cookies.push_str(&session_cookie(session));
        }
        let request = Request::get(format!(
            "/api/auth/oauth/{provider}/callback?code={code}&state={}",
            started.state
        ))
        .header(header::COOKIE, cookies)
        .body(Body::empty())
        .unwrap();
        self.reply(request).await
    }

    async fn methods(&self, account: &str, session: &str) -> Reply {
        let request = Request::get(format!("/api/auth/oauth/identities?account_id={account}"))
            .header(header::COOKIE, session_cookie(session))
            .body(Body::empty())
            .unwrap();
        self.reply(request).await
    }

    async fn unlink(&self, provider: &str, account: &str, session: &str) -> Reply {
        self.account_request(
            "/api/auth/oauth/identities/unlink",
            session,
            json!({ "account_id": account, "provider": provider }),
        )
        .await
    }
}

impl Reply {
    /// Back on Settings with `code`, and never a new session.
    fn assert_settings(&self, code: &str, provider: &str) {
        assert_eq!(self.status, StatusCode::SEE_OTHER);
        assert_eq!(
            self.location.as_deref(),
            Some(
                format!("/settings/?sign_in_method={code}&provider={provider}#sign-in-methods")
                    .as_str()
            )
        );
        assert!(self.cookie("codewire.session_token").is_none());
        assert!(self.cookie("codewire_2fa_challenge").is_none());
        assert!(
            self.set_cookies
                .iter()
                .any(|cookie| cookie.starts_with("codewire_oauth_state=;")
                    && cookie.contains("Max-Age=0")),
            "the state cookie is cleared"
        );
    }
}

#[tokio::test]
async fn connect_links_to_the_sessions_account_and_creates_no_session() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let google_sub = GoogleSub::new();
    let email = "settings-connect@example.test";
    let google_email = "settings-connect-google@example.test";
    cleanup(
        &h.pool,
        &[email],
        &[github_id.subject(), google_sub.subject()],
    )
    .await;
    insert_user(&h.pool, "settings-connect", email, true, true).await;
    let session = browser_session(&h.pool, "settings-connect", true).await;

    let methods = h.methods("settings-connect", &session).await;
    assert_eq!(methods.status, StatusCode::OK);
    assert_eq!(
        methods.body,
        json!({ "account_id": "settings-connect", "providers": ["github", "google"],
                "password": true, "identities": [] })
    );

    // GitHub: the emails need not match; the user proved both.
    let started = h.link_start("github", "settings-connect", &session).await;
    h.answer(
        &started,
        "connect-github",
        github(github_id, "elsewhere@example.test", true),
    );
    h.link_callback("github", &started, "connect-github", Some(&session))
        .await
        .assert_settings("connected", "github");
    // Google, with its nonce.
    let started = h.link_start("google", "settings-connect", &session).await;
    h.answer(
        &started,
        "connect-google",
        Answer::Google {
            claims: google(&started, &google_sub, google_email),
        },
    );
    h.link_callback("google", &started, "connect-google", Some(&session))
        .await
        .assert_settings("connected", "google");

    let owner: String = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = 'github' AND account_id = $1",
    )
    .bind(github_id.subject())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owner, "settings-connect");
    assert_eq!(link_rows(&h.pool, "google", &google_sub.subject()).await, 1);
    assert_eq!(
        sessions(&h.pool, "settings-connect").await,
        1,
        "no new session"
    );
    assert_eq!(
        audit_count(&h.pool, "settings-connect", "user.oauth.linked").await,
        2
    );
    let audit: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_logs WHERE user_id = 'settings-connect' \
         AND action = 'user.oauth.linked' AND metadata->>'provider' = 'github'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(audit["provider_subject"], github_id.subject());
    assert_eq!(audit["provider_email"], "elsewhere@example.test");
    assert_eq!(audit["provider_account"], github_id.account());
    assert_eq!(audit["confirmed_by"], "session");

    // Settings names each identity as it was linked.
    let methods = h.methods("settings-connect", &session).await;
    let identities = methods.body["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0]["provider"], "github");
    assert_eq!(identities[0]["account"], github_id.account());
    assert_eq!(identities[1]["provider"], "google");
    assert_eq!(identities[1]["account"], google_email);
    assert!(identities[0]["linked_at"].as_str().unwrap().ends_with('Z'));

    // A connected provider is not started again, and its state was single use.
    let again = h
        .link_start_reply("github", "settings-connect", &session)
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let replay = h
        .link_callback("github", &started, "connect-google", Some(&session))
        .await;
    replay.assert_refused("expired");
    cleanup(
        &h.pool,
        &[email],
        &[github_id.subject(), google_sub.subject()],
    )
    .await;
}

#[tokio::test]
async fn a_link_starts_only_inside_the_account_session_boundary() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let email = "settings-boundary@example.test";
    let other_email = "settings-boundary-other@example.test";
    cleanup(&h.pool, &[email, other_email], &[]).await;
    insert_user(&h.pool, "settings-boundary", email, true, true).await;
    insert_user(&h.pool, "settings-boundary-other", other_email, true, true).await;
    let session = browser_session(&h.pool, "settings-boundary", true).await;
    let before_two_factor = browser_session(&h.pool, "settings-boundary", false).await;
    let links = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_states WHERE intent = 'link' AND user_id = $1",
        )
        .bind("settings-boundary")
        .fetch_one(&h.pool)
        .await
        .unwrap()
    };

    // Before the two-factor boundary, for another account, or with no session.
    let reply = h
        .link_start_reply("github", "settings-boundary", &before_two_factor)
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = h
        .link_start_reply("github", "settings-boundary-other", &session)
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = h
        .link_start_reply("github", "settings-boundary", "not-a-session")
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // Another site's request carries its own Origin.
    let request = Request::post("/api/auth/oauth/identities/link")
        .header(header::ORIGIN, "https://elsewhere.example")
        .header(header::COOKIE, session_cookie(&session))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "account_id": "settings-boundary", "provider": "github" }).to_string(),
        ))
        .unwrap();
    assert_eq!(h.reply(request).await.status, StatusCode::FORBIDDEN);
    // No GET starts a link.
    let request = Request::get("/api/auth/oauth/identities/link")
        .header(header::COOKIE, session_cookie(&session))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        h.reply(request).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(links().await, 0);

    // A new start replaces the one in flight.
    h.link_start("github", "settings-boundary", &session).await;
    h.link_start("github", "settings-boundary", &session).await;
    assert_eq!(links().await, 1);
    cleanup(&h.pool, &[email, other_email], &[]).await;
}

#[tokio::test]
async fn a_link_callback_whose_session_changed_links_nothing() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "settings-changed@example.test";
    let other_email = "settings-changed-other@example.test";
    cleanup(&h.pool, &[email, other_email], &[github_id.subject()]).await;
    insert_user(&h.pool, "settings-changed", email, true, true).await;
    insert_user(&h.pool, "settings-changed-other", other_email, true, true).await;
    let session = browser_session(&h.pool, "settings-changed", true).await;
    let other = browser_session(&h.pool, "settings-changed-other", true).await;

    // Signed out, signed in as someone else, or the session expired.
    let expired = browser_session(&h.pool, "settings-changed", true).await;
    for (case, callback_session) in [
        ("signed out", None),
        ("another account", Some(other.as_str())),
        ("expired", Some(expired.as_str())),
    ] {
        let started = h.link_start("github", "settings-changed", &session).await;
        let code = case.replace(' ', "-");
        h.answer(&started, &code, github(github_id, email, true));
        if case == "expired" {
            sqlx::query(
                "UPDATE sessions SET expires_at = NOW() - interval '1 minute' \
                 WHERE token_hash = $1",
            )
            .bind(hash_session_token(&expired))
            .execute(&h.pool)
            .await
            .unwrap();
        }
        h.link_callback("github", &started, &code, callback_session)
            .await
            .assert_settings("session_changed", "github");
        assert_eq!(
            link_rows(&h.pool, "github", &github_id.subject()).await,
            0,
            "{case}"
        );
    }
    assert_eq!(
        audit_count(&h.pool, "settings-changed", "user.oauth.linked").await,
        0
    );
    assert_eq!(
        audit_count(&h.pool, "settings-changed-other", "user.oauth.linked").await,
        0
    );
    cleanup(&h.pool, &[email, other_email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn a_disabled_or_locked_account_links_nothing() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "settings-refused@example.test";
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
    insert_user(&h.pool, "settings-refused", email, true, true).await;
    // Disabling an account ends its sessions; a lockout keeps them.
    for (change, undo, refused) in [
        (
            "UPDATE users SET enabled = false WHERE id = 'settings-refused'",
            "UPDATE users SET enabled = true WHERE id = 'settings-refused'",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "UPDATE users SET locked_until = NOW() + interval '10 minutes' \
             WHERE id = 'settings-refused'",
            "UPDATE users SET locked_until = NULL WHERE id = 'settings-refused'",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let session = browser_session(&h.pool, "settings-refused", true).await;
        // Disabled or locked between the start and the callback.
        let started = h.link_start("github", "settings-refused", &session).await;
        h.answer(&started, "refused-code", github(github_id, email, true));
        sqlx::query(change).execute(&h.pool).await.unwrap();
        h.link_callback("github", &started, "refused-code", Some(&session))
            .await
            .assert_settings("session_changed", "github");
        assert_eq!(
            link_rows(&h.pool, "github", &github_id.subject()).await,
            0,
            "{change}"
        );
        // Nor does a new link start.
        let reply = h
            .link_start_reply("github", "settings-refused", &session)
            .await;
        assert_eq!(reply.status, refused, "{change}");
        sqlx::query(undo).execute(&h.pool).await.unwrap();
    }
    assert_eq!(
        audit_count(&h.pool, "settings-refused", "user.oauth.linked").await,
        0
    );
    cleanup(&h.pool, &[email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn an_identity_linked_to_another_account_is_refused() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "settings-taken@example.test";
    let owner_email = "settings-taken-owner@example.test";
    cleanup(&h.pool, &[email, owner_email], &[github_id.subject()]).await;
    insert_user(&h.pool, "settings-taken", email, true, true).await;
    insert_user(&h.pool, "settings-taken-owner", owner_email, true, true).await;
    link_github(&h.pool, "settings-taken-owner", github_id).await;
    let session = browser_session(&h.pool, "settings-taken", true).await;

    let started = h.link_start("github", "settings-taken", &session).await;
    h.answer(&started, "taken-code", github(github_id, owner_email, true));
    h.link_callback("github", &started, "taken-code", Some(&session))
        .await
        .assert_settings("taken", "github");
    let owner: String = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = 'github' AND account_id = $1",
    )
    .bind(github_id.subject())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owner, "settings-taken-owner");
    assert_eq!(
        audit_count(&h.pool, "settings-taken", "user.oauth.linked").await,
        0
    );

    // Cancelling at the provider lands on Settings too, and links nothing.
    let started = h.link_start("github", "settings-taken", &session).await;
    h.request(
        "GET",
        &format!(
            "/api/auth/oauth/github/callback?error=access_denied&state={}",
            started.state
        ),
        &[started.state_cookie()],
        None,
    )
    .await
    .assert_settings("cancelled", "github");
    cleanup(&h.pool, &[email, owner_email], &[github_id.subject()]).await;
}

#[tokio::test]
async fn disconnect_needs_another_way_to_sign_in() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let other_github_id = GitHubId::new();
    let google_sub = GoogleSub::new();
    let email = "settings-unlink@example.test";
    let only_email = "settings-unlink-only@example.test";
    cleanup(
        &h.pool,
        &[email, only_email],
        &[
            github_id.subject(),
            other_github_id.subject(),
            google_sub.subject(),
        ],
    )
    .await;
    insert_user(&h.pool, "settings-unlink", email, true, true).await;
    link_github(&h.pool, "settings-unlink", github_id).await;
    let session = browser_session(&h.pool, "settings-unlink", true).await;

    // A password remains.
    let reply = h.unlink("github", "settings-unlink", &session).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(link_rows(&h.pool, "github", &github_id.subject()).await, 0);
    assert_eq!(
        audit_count(&h.pool, "settings-unlink", "user.oauth.unlinked").await,
        1
    );
    let reply = h.unlink("github", "settings-unlink", &session).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // A provider-only account keeps its last way in.
    insert_user(&h.pool, "settings-unlink-only", only_email, true, true).await;
    sqlx::query("DELETE FROM accounts WHERE user_id = 'settings-unlink-only'")
        .execute(&h.pool)
        .await
        .unwrap();
    link_github(&h.pool, "settings-unlink-only", other_github_id).await;
    let only = browser_session(&h.pool, "settings-unlink-only", true).await;
    let methods = h.methods("settings-unlink-only", &only).await;
    assert_eq!(methods.body["password"], false);
    let reply = h.unlink("github", "settings-unlink-only", &only).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.body["code"], "oauth_last_sign_in_method");
    assert_eq!(
        link_rows(&h.pool, "github", &other_github_id.subject()).await,
        1
    );

    // With Google connected too, GitHub may go, and then Google may not.
    link_google(&h.pool, "settings-unlink-only", &google_sub).await;
    let reply = h.unlink("github", "settings-unlink-only", &only).await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = h.unlink("google", "settings-unlink-only", &only).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(link_rows(&h.pool, "google", &google_sub.subject()).await, 1);
    assert_eq!(
        audit_count(&h.pool, "settings-unlink-only", "user.oauth.unlinked").await,
        1
    );

    // Another site cannot disconnect.
    let request = Request::post("/api/auth/oauth/identities/unlink")
        .header(header::ORIGIN, "https://elsewhere.example")
        .header(header::COOKIE, session_cookie(&session))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "account_id": "settings-unlink", "provider": "github" }).to_string(),
        ))
        .unwrap();
    assert_eq!(h.reply(request).await.status, StatusCode::FORBIDDEN);
    cleanup(
        &h.pool,
        &[email, only_email],
        &[
            github_id.subject(),
            other_github_id.subject(),
            google_sub.subject(),
        ],
    )
    .await;
}

#[tokio::test]
async fn the_admin_account_list_names_linked_identities() {
    let Some(h) = Harness::new(SignupInvitePolicy::open()).await else {
        return;
    };
    let github_id = GitHubId::new();
    let email = "settings-admin-view@example.test";
    let admin_email = "settings-admin@example.test";
    cleanup(&h.pool, &[email, admin_email], &[github_id.subject()]).await;
    insert_user(&h.pool, "settings-admin-view", email, true, true).await;
    insert_user(&h.pool, "settings-admin", admin_email, true, true).await;
    sqlx::query("UPDATE users SET is_admin = true WHERE id = 'settings-admin'")
        .execute(&h.pool)
        .await
        .unwrap();
    let session = browser_session(&h.pool, "settings-admin-view", true).await;
    let started = h
        .link_start("github", "settings-admin-view", &session)
        .await;
    h.answer(&started, "admin-view", github(github_id, email, true));
    h.link_callback("github", &started, "admin-view", Some(&session))
        .await
        .assert_settings("connected", "github");
    // Awaiting review, so it leads the list.
    sqlx::query(
        "UPDATE users SET enabled = false, access_reason = 'Synthetic review' \
         WHERE id = 'settings-admin-view'",
    )
    .execute(&h.pool)
    .await
    .unwrap();

    let admin = codewire_idp::access_admin::router(
        h.pool.clone(),
        ORIGIN.into(),
        codewire_email::EmailClient::disabled(),
        codewire_server_core::auth::AuthState {
            pool: h.pool.clone(),
        },
    );
    let admin_session = browser_session(&h.pool, "settings-admin", true).await;
    let response = admin
        .oneshot(
            Request::get("/api/admin/accounts")
                .header(header::COOKIE, session_cookie(&admin_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .unwrap(),
    )
    .unwrap();
    let account = body["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["id"] == "settings-admin-view")
        .expect("the account is listed");
    let identities = account["linkedIdentities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["provider"], "github");
    assert_eq!(identities[0]["subject"], github_id.subject());
    assert_eq!(identities[0]["account"], github_id.account());
    assert!(identities[0]["linkedAt"].is_string());
    assert!(identities[0].get("userId").is_none());
    cleanup(&h.pool, &[email, admin_email], &[github_id.subject()]).await;
}

/// Signing in with a provider from an invitation (#3840) sends the provider
/// only a random state and our fixed callback: the return path stays in our
/// own records, so nothing of the invitation page reaches GitHub or Google.
#[tokio::test]
async fn a_provider_never_sees_where_sign_in_returns_to() {
    let Some(h) = Harness::new(invite_policy()).await else {
        return;
    };
    for provider in ["github", "google"] {
        let started = h.start(provider, "?return_to=%2Faccept-invite").await;
        for (name, value) in &started.params {
            assert!(
                !value.contains("accept-invite") && !name.contains("return"),
                "{provider} authorize URL carries {name}={value}"
            );
        }
        assert!(
            started.params["redirect_uri"]
                .ends_with(&format!("/api/auth/oauth/{provider}/callback"))
        );
    }
}
