//! Synthetic database proof for fresh-proof authenticator replacement and
//! recovery-code regeneration. Every account, password and code is generated
//! here; nothing real is loaded. The integration runner rejects a missing
//! DATABASE_URL skip.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use axum::http::{HeaderMap, Request};
use axum::{Router, body::Body};
use codewire_idp::auth_session::{
    SignupInvitePolicy, router_with_email, router_with_signup_delivery,
};
use codewire_server_core::auth::{AuthState, hash_session_token};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

const ORIGIN: &str = "https://app.codewire.test";
const SESSION_SECRET: &str = "synthetic-two-factor-replacement-secret";
const PASSWORD: &str = "Synthetic!Pass1234";
const START: &str = "/api/auth/two-factor/replace/start";
const CONFIRM: &str = "/api/auth/two-factor/replace/confirm";
const REGENERATE: &str = "/api/auth/two-factor/recovery-codes/regenerate";
/// A hang guard, not a bound under test: the replacement routes get it in
/// place of their 5 s request and 4 s statement bounds, and the test's own
/// waits for a request to reach a lock use it. On a loaded CI guest two
/// concurrent proofs spent the production bounds and answered 503 (PR runs
/// 23429, 23873); `production_bounds_are_five_second_requests_and_four_second_statements`
/// pins those bounds.
const HANG: std::time::Duration = std::time::Duration::from_secs(60);

/// The replacement routes as production mounts them, with [`HANG`] for bounds.
fn replacement_app(pool: PgPool) -> Router {
    codewire_idp::two_factor::replacement_router(
        pool,
        SESSION_SECRET.into(),
        true,
        ORIGIN.into(),
        codewire_email::EmailClient::disabled(),
    )
    .layer(axum::Extension(
        codewire_idp::two_factor::TwoFactorReplacementBounds {
            request: HANG,
            statement: HANG,
        },
    ))
}

async fn pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping two-factor replacement DB proof");
        return None;
    };
    Some(
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap(),
    )
}

struct Apps {
    signup: Router,
    account: Router,
    factor: Router,
}

fn apps(pool: &PgPool) -> Apps {
    Apps {
        signup: router_with_email(
            pool.clone(),
            true,
            SignupInvitePolicy::open(),
            ORIGIN.into(),
            codewire_email::EmailClient::recording().0,
        ),
        account: router_with_signup_delivery(
            pool.clone(),
            true,
            SignupInvitePolicy::open(),
            ORIGIN.into(),
            codewire_email::EmailClient::disabled(),
            String::new(),
            String::new(),
        ),
        factor: codewire_idp::two_factor::router(
            pool.clone(),
            SESSION_SECRET.into(),
            true,
            AuthState { pool: pool.clone() },
        )
        .merge(replacement_app(pool.clone())),
    }
}

struct Response {
    status: u16,
    body: Value,
    set_cookie: Option<String>,
    headers: HeaderMap,
}

#[derive(Default)]
struct Call<'a> {
    cookie: Option<&'a str>,
    origin: Option<&'a str>,
    bearer: Option<&'a str>,
}

async fn call(app: &Router, method: &str, path: &str, call: Call<'_>, body: Value) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = call.cookie {
        builder = builder.header("cookie", format!("codewire.session_token={cookie}"));
    }
    if let Some(origin) = call.origin {
        builder = builder.header("origin", origin);
    }
    if let Some(bearer) = call.bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let body = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let set_cookie = headers
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Response {
        status,
        body,
        set_cookie,
        headers,
    }
}

fn cookie_token(set_cookie: &str) -> String {
    set_cookie
        .strip_prefix("codewire.session_token=")
        .and_then(|value| value.split(';').next())
        .filter(|value| !value.is_empty())
        .expect("session cookie")
        .to_owned()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn totp(secret: &str, email: &str) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.to_owned()).to_bytes().unwrap(),
        Some("Codewire".into()),
        email.into(),
    )
    .unwrap()
}

/// A code for the step `offset` steps from now; the server accepts -1..=1.
fn code_at(secret: &str, email: &str, offset: i64) -> String {
    let time = unix_now() as i64 + offset * 30;
    totp(secret, email).generate(time as u64)
}

/// A six-digit code that matches none of the steps the server would accept.
fn wrong_code(secret: &str, email: &str) -> String {
    let accepted: Vec<String> = (-2..=2)
        .map(|offset| code_at(secret, email, offset))
        .collect();
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|candidate| !accepted.contains(candidate))
        .unwrap()
}

struct Enrolled {
    user_id: String,
    email: String,
    session: String,
    secret: String,
    codes: Vec<String>,
}

async fn cleanup(pool: &PgPool, email: &str) {
    sqlx::query("DELETE FROM audit_logs WHERE user_id IN (SELECT id FROM users WHERE email=$1)")
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE email=$1")
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
}

/// A credential account that signed up, verified its email, signed in, and
/// enabled and verified a factor through the real handlers. Enrollment records its verification step; clearing it
/// stands in for time passing so each test chooses its own proof steps.
async fn enrolled(pool: &PgPool, apps: &Apps, label: &str) -> Enrolled {
    let email = format!("{label}@two-factor-replacement.test");
    cleanup(pool, &email).await;
    let signed_up = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-up",
        Call::default(),
        json!({"email": email, "password": PASSWORD, "name": label}),
    )
    .await;
    assert_eq!(signed_up.status, 202, "sign up: {}", signed_up.body);
    sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
        .bind(&email)
        .execute(pool)
        .await
        .unwrap();
    let signed_in = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-in",
        Call::default(),
        json!({"email": email, "password": PASSWORD}),
    )
    .await;
    assert_eq!(signed_in.status, 200, "sign in: {}", signed_in.body);
    let session = cookie_token(signed_in.set_cookie.as_deref().unwrap());
    let enabled = call(
        &apps.factor,
        "POST",
        "/api/auth/two-factor/enable",
        Call {
            cookie: Some(&session),
            ..Default::default()
        },
        Value::Null,
    )
    .await;
    assert_eq!(enabled.status, 200, "enable: {}", enabled.body);
    let secret = enabled.body["secret"].as_str().unwrap().to_owned();
    let codes: Vec<String> = serde_json::from_value(enabled.body["backupCodes"].clone()).unwrap();
    let verified = call(
        &apps.factor,
        "POST",
        "/api/auth/two-factor/verify",
        Call {
            cookie: Some(&session),
            ..Default::default()
        },
        json!({"code": code_at(&secret, &email, 0)}),
    )
    .await;
    assert_eq!(verified.status, 200, "verify: {}", verified.body);
    let user_id: String = sqlx::query_scalar("SELECT id FROM users WHERE email=$1")
        .bind(&email)
        .fetch_one(pool)
        .await
        .unwrap();
    forget_steps(pool, &user_id).await;
    Enrolled {
        user_id,
        email,
        session,
        secret,
        codes,
    }
}

async fn forget_steps(pool: &PgPool, user_id: &str) {
    sqlx::query("UPDATE two_factor SET last_totp_step=NULL WHERE user_id=$1")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Sign in through password and second factor; returns the status and, on
/// success, the new browser session.
async fn sign_in(apps: &Apps, email: &str, code: &str) -> (u16, Option<String>) {
    let challenge = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-in",
        Call::default(),
        json!({"email": email, "password": PASSWORD}),
    )
    .await;
    assert_eq!(challenge.status, 200, "sign in: {}", challenge.body);
    let token = challenge.body["twoFactorToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let validated = call(
        &apps.factor,
        "POST",
        "/api/auth/two-factor/validate",
        Call::default(),
        json!({"code": code, "token": token}),
    )
    .await;
    (
        validated.status,
        validated.set_cookie.as_deref().map(cookie_token),
    )
}

async fn proof(
    apps: &Apps,
    path: &str,
    user: &Enrolled,
    session: &str,
    password: &str,
    proof: &str,
) -> Response {
    let response = call(
        &apps.factor,
        "POST",
        path,
        Call {
            cookie: Some(session),
            origin: Some(ORIGIN),
            ..Default::default()
        },
        json!({"account_id": user.user_id, "password": password, "proof": proof}),
    )
    .await;
    assert_eq!(response.headers["cache-control"], "no-store", "{path}");
    response
}

async fn confirm(apps: &Apps, user: &Enrolled, session: &str, id: &str, code: &str) -> Response {
    let response = call(
        &apps.factor,
        "POST",
        CONFIRM,
        Call {
            cookie: Some(session),
            origin: Some(ORIGIN),
            ..Default::default()
        },
        json!({"account_id": user.user_id, "replacement_id": id, "code": code}),
    )
    .await;
    assert_eq!(response.headers["cache-control"], "no-store");
    response
}

async fn failures(pool: &PgPool, user_id: &str) -> (i32, bool) {
    sqlx::query_as(
        "SELECT COALESCE(failed_login_attempts,0), locked_until IS NOT NULL FROM users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn pending(pool: &PgPool, user_id: &str) -> Option<(String, String, String, i32)> {
    sqlx::query_as(
        "SELECT id, session_id, secret, attempts FROM two_factor_replacements WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn factor_row(pool: &PgPool, user_id: &str) -> (String, String, Option<i64>) {
    sqlx::query_as("SELECT secret, backup_codes, last_totp_step FROM two_factor WHERE user_id=$1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn session_id(pool: &PgPool, token: &str) -> String {
    sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash=$1")
        .bind(hash_session_token(token))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn routes_refuse_bearers_foreign_origins_and_foreign_accounts_without_side_effects() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let owner = enrolled(&pool, &apps, "boundary-owner").await;
    let other = enrolled(&pool, &apps, "boundary-other").await;
    let factor_before = factor_row(&pool, &owner.user_id).await;
    let proof_body = |account: &str| json!({"account_id": account, "password": PASSWORD, "proof": owner.codes[0]});
    let confirm_body = |account: &str| json!({"account_id": account, "replacement_id": "0123456789abcdef0123456789abcdef", "code": "123456"});
    for path in [START, CONFIRM, REGENERATE] {
        let body = |account: &str| {
            if path == CONFIRM {
                confirm_body(account)
            } else {
                proof_body(account)
            }
        };
        for (case, request, expected) in [
            (
                "bearer session, no cookie",
                Call {
                    origin: Some(ORIGIN),
                    bearer: Some(&owner.session),
                    ..Default::default()
                },
                401,
            ),
            (
                "API key bearer",
                Call {
                    origin: Some(ORIGIN),
                    bearer: Some(
                        "cw_0000000000000000000000000000000000000000000000000000000000000000",
                    ),
                    ..Default::default()
                },
                401,
            ),
            (
                "cookie with a bearer",
                Call {
                    cookie: Some(&owner.session),
                    origin: Some(ORIGIN),
                    bearer: Some(&owner.session),
                },
                401,
            ),
            (
                "no origin",
                Call {
                    cookie: Some(&owner.session),
                    ..Default::default()
                },
                403,
            ),
            (
                "foreign origin",
                Call {
                    cookie: Some(&owner.session),
                    origin: Some("https://app.codewire.test.evil.test"),
                    ..Default::default()
                },
                403,
            ),
        ] {
            let response = call(&apps.factor, "POST", path, request, body(&owner.user_id)).await;
            assert_eq!(
                response.status, expected,
                "{path}: {case}: {}",
                response.body
            );
            assert_eq!(response.headers["cache-control"], "no-store");
            assert!(response.set_cookie.is_none());
        }
        // The account echo must name the session's own account.
        let response = call(
            &apps.factor,
            "POST",
            path,
            Call {
                cookie: Some(&owner.session),
                origin: Some(ORIGIN),
                ..Default::default()
            },
            body(&other.user_id),
        )
        .await;
        assert_eq!(response.status, 403, "{path}: foreign account");
    }
    for user in [&owner, &other] {
        assert_eq!(failures(&pool, &user.user_id).await, (0, false));
        assert!(pending(&pool, &user.user_id).await.is_none());
    }
    assert_eq!(factor_row(&pool, &owner.user_id).await, factor_before);
    // Direct disable stays closed for an authenticated browser session.
    let disable = call(
        &apps.factor,
        "POST",
        "/api/auth/two-factor/disable",
        Call {
            cookie: Some(&owner.session),
            origin: Some(ORIGIN),
            ..Default::default()
        },
        Value::Null,
    )
    .await;
    assert_eq!(disable.status, 400);
    assert_eq!(factor_row(&pool, &owner.user_id).await, factor_before);
    cleanup(&pool, &owner.email).await;
    cleanup(&pool, &other.email).await;
}

#[tokio::test]
async fn proof_failures_share_the_sign_in_lockout_and_a_locked_account_is_refused() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "proof-lockout").await;
    for attempt in 1..=4 {
        // A correct current code with a wrong password is still one failure,
        // and its step is not consumed.
        let response = proof(
            &apps,
            START,
            &user,
            &user.session,
            "Wrong!Password123",
            &code_at(&user.secret, &user.email, 0),
        )
        .await;
        assert_eq!(response.status, 422, "attempt {attempt}: {}", response.body);
        assert_eq!(failures(&pool, &user.user_id).await, (attempt, false));
        assert!(response.body.get("secret").is_none());
    }
    assert!(factor_row(&pool, &user.user_id).await.2.is_none());
    let wrong = proof(
        &apps,
        REGENERATE,
        &user,
        &user.session,
        PASSWORD,
        "ffffffffff",
    )
    .await;
    assert_eq!(wrong.status, 429, "fifth failure locks: {}", wrong.body);
    assert_eq!(failures(&pool, &user.user_id).await, (5, true));
    // While locked even a complete proof is refused, consumes nothing and is
    // not counted again.
    let locked = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[0]).await;
    assert_eq!(locked.status, 429);
    assert_eq!(failures(&pool, &user.user_id).await, (5, true));
    assert!(pending(&pool, &user.user_id).await.is_none());
    let signing_in = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-in",
        Call::default(),
        json!({"email": user.email, "password": PASSWORD}),
    )
    .await;
    assert_eq!(
        signing_in.status, 429,
        "the shared lock also holds at sign-in"
    );
    sqlx::query("UPDATE users SET locked_until=NOW() - interval '1 second' WHERE id=$1")
        .bind(&user.user_id)
        .execute(&pool)
        .await
        .unwrap();
    let accepted = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[0]).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(failures(&pool, &user.user_id).await, (0, false));
    let reasons: Vec<Value> = sqlx::query_scalar(
        "SELECT metadata FROM audit_logs WHERE user_id=$1 AND action='user.2fa.proof_failed' ORDER BY timestamp",
    )
    .bind(&user.user_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(reasons.len(), 6);
    assert_eq!(
        reasons.iter().filter(|m| m["reason"] == "locked").count(),
        1
    );
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn a_code_used_to_sign_in_cannot_be_replayed_as_a_fresh_proof() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "proof-replay").await;
    let signed_in_code = code_at(&user.secret, &user.email, 0);
    let (status, _) = sign_in(&apps, &user.email, &signed_in_code).await;
    assert_eq!(status, 200);
    let recorded = factor_row(&pool, &user.user_id).await.2;
    assert!(recorded.is_some(), "sign-in records its step");
    let replay = proof(
        &apps,
        START,
        &user,
        &user.session,
        PASSWORD,
        &signed_in_code,
    )
    .await;
    assert_eq!(replay.status, 422, "{}", replay.body);
    assert_eq!(failures(&pool, &user.user_id).await, (1, false));
    assert!(pending(&pool, &user.user_id).await.is_none());
    // The next step is fresh, and it is then consumed in turn.
    let next = code_at(&user.secret, &user.email, 1);
    let fresh = proof(&apps, START, &user, &user.session, PASSWORD, &next).await;
    assert_eq!(fresh.status, 200, "{}", fresh.body);
    assert!(factor_row(&pool, &user.user_id).await.2 > recorded);
    let reused = proof(&apps, REGENERATE, &user, &user.session, PASSWORD, &next).await;
    assert_eq!(reused.status, 422);
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn recovery_codes_prove_once_and_regeneration_replaces_every_code() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "recovery-codes").await;
    let (secret_before, codes_before, _) = factor_row(&pool, &user.user_id).await;
    let regenerated = proof(
        &apps,
        REGENERATE,
        &user,
        &user.session,
        PASSWORD,
        &user.codes[0],
    )
    .await;
    assert_eq!(regenerated.status, 200, "{}", regenerated.body);
    let fresh: Vec<String> =
        serde_json::from_value(regenerated.body["backup_codes"].clone()).unwrap();
    assert_eq!(fresh.len(), 10);
    assert!(fresh.iter().all(|code| {
        code.len() == 10
            && code
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }));
    assert!(fresh.iter().all(|code| !user.codes.contains(code)));
    let (secret_after, codes_after, _) = factor_row(&pool, &user.user_id).await;
    assert_eq!(
        secret_after, secret_before,
        "regeneration keeps the authenticator"
    );
    assert_ne!(codes_after, codes_before);
    for old in [&user.codes[0], &user.codes[1]] {
        let refused = proof(&apps, REGENERATE, &user, &user.session, PASSWORD, old).await;
        assert_eq!(refused.status, 422);
    }
    let (status, _) = sign_in(&apps, &user.email, &user.codes[2]).await;
    assert_eq!(status, 401, "replaced recovery codes no longer sign in");
    let (status, _) = sign_in(&apps, &user.email, &fresh[0]).await;
    assert_eq!(status, 200, "a new recovery code signs in");
    let (status, _) = sign_in(&apps, &user.email, &code_at(&user.secret, &user.email, 0)).await;
    assert_eq!(status, 200, "the authenticator still signs in");
    // Recovery codes are accepted as typed, and a proof consumes the code.
    let typed = format!("{} {}", fresh[1][..5].to_uppercase(), &fresh[1][5..]);
    let started = proof(&apps, START, &user, &user.session, PASSWORD, &typed).await;
    assert_eq!(started.status, 200, "{}", started.body);
    let (status, _) = sign_in(&apps, &user.email, &fresh[1]).await;
    assert_eq!(status, 401, "a proof consumed the recovery code");
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn the_pending_secret_belongs_to_one_session_and_the_old_factor_keeps_working() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "pending-isolation").await;
    let (_, second) = sign_in(&apps, &user.email, &user.codes[0]).await;
    let second = second.unwrap();
    let factor_before = factor_row(&pool, &user.user_id).await;

    let started = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[1]).await;
    assert_eq!(started.status, 200, "{}", started.body);
    let first_id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let first_secret = started.body["secret"].as_str().unwrap().to_owned();
    assert_eq!(first_secret.len(), 32);
    assert!(
        started.body["totp_uri"]
            .as_str()
            .unwrap()
            .contains(&format!("secret={first_secret}"))
    );
    assert!(started.body["expires_at"].as_str().unwrap().ends_with('Z'));
    // Only ciphertext is stored, bound to the session that proved the account.
    let (stored_id, owner, ciphertext, attempts) = pending(&pool, &user.user_id).await.unwrap();
    assert_eq!(stored_id, first_id);
    assert_eq!(owner, session_id(&pool, &user.session).await);
    assert!(!ciphertext.contains(&first_secret) && ciphertext.len() > first_secret.len());
    assert_eq!(attempts, 0);

    // Another browser of the same account cannot confirm it, even with the
    // correct new code, and learns nothing about it.
    let foreign = confirm(
        &apps,
        &user,
        &second,
        &first_id,
        &code_at(&first_secret, &user.email, 0),
    )
    .await;
    assert_eq!(foreign.status, 404);
    assert!(!foreign.body.to_string().contains(&first_secret));
    assert_eq!(pending(&pool, &user.user_id).await.unwrap().3, 0);

    // The enrolled factor keeps working while a replacement is pending.
    assert_eq!(factor_row(&pool, &user.user_id).await.0, factor_before.0);
    let (status, _) = sign_in(&apps, &user.email, &code_at(&user.secret, &user.email, 0)).await;
    assert_eq!(status, 200, "old authenticator while pending");
    let (status, _) = sign_in(&apps, &user.email, &user.codes[2]).await;
    assert_eq!(status, 200, "old recovery code while pending");

    // A newer start, here from the other browser, replaces the older one.
    let restarted = proof(&apps, START, &user, &second, PASSWORD, &user.codes[3]).await;
    assert_eq!(restarted.status, 200);
    let second_id = restarted.body["replacement_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let second_secret = restarted.body["secret"].as_str().unwrap().to_owned();
    assert_ne!(second_id, first_id);
    let stale = confirm(
        &apps,
        &user,
        &user.session,
        &first_id,
        &code_at(&first_secret, &user.email, 0),
    )
    .await;
    assert_eq!(stale.status, 404, "the older replacement is gone");
    let wrong_browser = confirm(
        &apps,
        &user,
        &user.session,
        &second_id,
        &code_at(&second_secret, &user.email, 0),
    )
    .await;
    assert_eq!(
        wrong_browser.status, 404,
        "only the starting browser confirms"
    );
    assert_eq!(factor_row(&pool, &user.user_id).await.0, factor_before.0);
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn confirmation_attempts_expiry_and_newer_starts_are_bounded() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "pending-bounds").await;
    let factor_before = factor_row(&pool, &user.user_id).await;
    let started = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[0]).await;
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let secret = started.body["secret"].as_str().unwrap().to_owned();
    let wrong = wrong_code(&secret, &user.email);
    for attempt in 1..=4 {
        let refused = confirm(&apps, &user, &user.session, &id, &wrong).await;
        assert_eq!(refused.status, 422, "attempt {attempt}");
        assert_eq!(pending(&pool, &user.user_id).await.unwrap().3, attempt);
    }
    let exhausted = confirm(&apps, &user, &user.session, &id, &wrong).await;
    assert_eq!(exhausted.status, 410, "the fifth wrong code ends it");
    assert!(pending(&pool, &user.user_id).await.is_none());
    let late = confirm(
        &apps,
        &user,
        &user.session,
        &id,
        &code_at(&secret, &user.email, 0),
    )
    .await;
    assert_eq!(late.status, 404);
    // Confirmation failures never count against the account lockout.
    assert_eq!(failures(&pool, &user.user_id).await, (0, false));

    let started = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[1]).await;
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let secret = started.body["secret"].as_str().unwrap().to_owned();
    sqlx::query(
        "UPDATE two_factor_replacements SET created_at=created_at - interval '11 minutes', \
         expires_at=expires_at - interval '11 minutes' WHERE user_id=$1",
    )
    .bind(&user.user_id)
    .execute(&pool)
    .await
    .unwrap();
    let expired = confirm(
        &apps,
        &user,
        &user.session,
        &id,
        &code_at(&secret, &user.email, 0),
    )
    .await;
    assert_eq!(expired.status, 410);
    assert!(pending(&pool, &user.user_id).await.is_none());
    // Proofs consumed recovery codes, but the authenticator never changed.
    assert_eq!(factor_row(&pool, &user.user_id).await.0, factor_before.0);

    let older = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[2]).await;
    let newer = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[3]).await;
    let older_id = older.body["replacement_id"].as_str().unwrap();
    let older_secret = older.body["secret"].as_str().unwrap();
    let refused = confirm(
        &apps,
        &user,
        &user.session,
        older_id,
        &code_at(older_secret, &user.email, 0),
    )
    .await;
    assert_eq!(refused.status, 404);
    let newer_id = newer.body["replacement_id"].as_str().unwrap();
    let newer_secret = newer.body["secret"].as_str().unwrap();
    let replaced = confirm(
        &apps,
        &user,
        &user.session,
        newer_id,
        &code_at(newer_secret, &user.email, 0),
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn confirmation_swaps_the_factor_revokes_every_session_and_rotates_this_browser() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "replacement-swap").await;
    let (_, other) = sign_in(&apps, &user.email, &user.codes[0]).await;
    let other = other.unwrap();
    // An unfinished sign-in challenge must not survive the swap.
    let challenge = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-in",
        Call::default(),
        json!({"email": user.email, "password": PASSWORD}),
    )
    .await;
    let challenge = challenge.body["twoFactorToken"]
        .as_str()
        .unwrap()
        .to_owned();

    let started = proof(
        &apps,
        START,
        &user,
        &user.session,
        PASSWORD,
        &code_at(&user.secret, &user.email, 0),
    )
    .await;
    assert_eq!(started.status, 200, "{}", started.body);
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let new_secret = started.body["secret"].as_str().unwrap().to_owned();
    let (_, _, pending_ciphertext, _) = pending(&pool, &user.user_id).await.unwrap();

    let new_code = code_at(&new_secret, &user.email, 0);
    let replaced = confirm(&apps, &user, &user.session, &id, &new_code).await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    assert_eq!(replaced.body["signed_out_sessions"], 1);
    let new_codes: Vec<String> =
        serde_json::from_value(replaced.body["backup_codes"].clone()).unwrap();
    assert_eq!(new_codes.len(), 10);
    assert!(new_codes.iter().all(|code| !user.codes.contains(code)));
    let set_cookie = replaced.set_cookie.clone().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
    let rotated = cookie_token(&set_cookie);
    assert_ne!(rotated, user.session);
    assert!(!replaced.body.to_string().contains(&rotated));

    // Exactly one session remains: this browser's new one.
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT token_hash FROM sessions WHERE user_id=$1")
            .bind(&user.user_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec![hash_session_token(&rotated)]);
    let challenges: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE user_id=$1")
            .bind(&user.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(challenges, 0);
    assert!(pending(&pool, &user.user_id).await.is_none());
    let (secret_after, _, step_after) = factor_row(&pool, &user.user_id).await;
    assert_eq!(
        secret_after, pending_ciphertext,
        "the verified ciphertext moved in"
    );
    assert!(step_after.is_some());

    let inventory = |token: String| {
        let account = apps.account.clone();
        let path = format!("/api/auth/sessions?account_id={}", user.user_id);
        async move {
            call(
                &account,
                "GET",
                &path,
                Call {
                    cookie: Some(&token),
                    ..Default::default()
                },
                Value::Null,
            )
            .await
        }
    };
    assert_eq!(
        inventory(user.session.clone()).await.status,
        401,
        "old cookie"
    );
    assert_eq!(inventory(other.clone()).await.status, 401, "other browser");
    let current = inventory(rotated.clone()).await;
    assert_eq!(current.status, 200);
    assert_eq!(current.body["sessions"].as_array().unwrap().len(), 1);

    let stale_challenge = call(
        &apps.factor,
        "POST",
        "/api/auth/two-factor/validate",
        Call::default(),
        json!({"code": code_at(&new_secret, &user.email, 0), "token": challenge}),
    )
    .await;
    assert_eq!(stale_challenge.status, 401);
    let (status, _) = sign_in(&apps, &user.email, &code_at(&user.secret, &user.email, 0)).await;
    assert_eq!(status, 401, "the old authenticator no longer works");
    let (status, _) = sign_in(&apps, &user.email, &user.codes[1]).await;
    assert_eq!(status, 401, "the old recovery codes no longer work");
    let (status, _) = sign_in(&apps, &user.email, &code_at(&new_secret, &user.email, 0)).await;
    assert_eq!(status, 200, "the new authenticator works");
    let (status, _) = sign_in(&apps, &user.email, &new_codes[0]).await;
    assert_eq!(status, 200, "a new recovery code works");
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn concurrent_confirmations_and_regenerations_have_exactly_one_winner() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "replacement-race").await;
    let started = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[0]).await;
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let secret = started.body["secret"].as_str().unwrap().to_owned();
    let code = code_at(&secret, &user.email, 0);
    let (first, second) = tokio::join!(
        confirm(&apps, &user, &user.session, &id, &code),
        confirm(&apps, &user, &user.session, &id, &code),
    );
    let winners: Vec<&Response> = [&first, &second]
        .into_iter()
        .filter(|response| response.status == 200)
        .collect();
    assert_eq!(winners.len(), 1, "{} {}", first.status, second.status);
    let loser = if first.status == 200 { &second } else { &first };
    // The loser waited on the account lock and found its session revoked.
    assert!(
        matches!(loser.status, 401 | 404),
        "{}: {}",
        loser.status,
        loser.body
    );
    assert!(loser.set_cookie.is_none());
    let rotated = cookie_token(winners[0].set_cookie.as_deref().unwrap());
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id=$1")
        .bind(&user.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 1);

    let codes: Vec<String> =
        serde_json::from_value(winners[0].body["backup_codes"].clone()).unwrap();
    let (first, second) = tokio::join!(
        proof(&apps, REGENERATE, &user, &rotated, PASSWORD, &codes[0]),
        proof(&apps, REGENERATE, &user, &rotated, PASSWORD, &codes[0]),
    );
    let mut statuses = [first.status, second.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 422], "one recovery code, one winner");
    assert_eq!(failures(&pool, &user.user_id).await, (1, false));
    cleanup(&pool, &user.email).await;
}

#[tokio::test]
async fn audit_records_every_change_without_secret_material() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "replacement-audit").await;
    let wrong = proof(
        &apps,
        REGENERATE,
        &user,
        &user.session,
        "Wrong!Password123",
        &user.codes[0],
    )
    .await;
    assert_eq!(wrong.status, 422);
    let regenerated = proof(
        &apps,
        REGENERATE,
        &user,
        &user.session,
        PASSWORD,
        &user.codes[1],
    )
    .await;
    let regenerated_codes: Vec<String> =
        serde_json::from_value(regenerated.body["backup_codes"].clone()).unwrap();
    let started = proof(
        &apps,
        START,
        &user,
        &user.session,
        PASSWORD,
        &code_at(&user.secret, &user.email, 1),
    )
    .await;
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let new_secret = started.body["secret"].as_str().unwrap().to_owned();
    let totp_uri = started.body["totp_uri"].as_str().unwrap().to_owned();
    let replaced = confirm(
        &apps,
        &user,
        &user.session,
        &id,
        &code_at(&new_secret, &user.email, 0),
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    let replaced_codes: Vec<String> =
        serde_json::from_value(replaced.body["backup_codes"].clone()).unwrap();
    let rotated = cookie_token(replaced.set_cookie.as_deref().unwrap());

    let rows: Vec<(String, Option<Value>, Option<String>)> = sqlx::query_as(
        "SELECT action, metadata, user_agent FROM audit_logs WHERE user_id=$1 AND action LIKE 'user.2fa.%' ORDER BY timestamp",
    )
    .bind(&user.user_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let actions: Vec<&str> = rows.iter().map(|(action, _, _)| action.as_str()).collect();
    for expected in [
        "user.2fa.proof_failed",
        "user.2fa.recovery_codes_regenerated",
        "user.2fa.replace_started",
        "user.2fa.replaced",
    ] {
        assert!(
            actions.contains(&expected),
            "{expected} missing from {actions:?}"
        );
    }
    let recorded = serde_json::to_string(&rows).unwrap();
    let mut secrets = vec![
        user.secret.clone(),
        new_secret,
        totp_uri,
        "otpauth".to_owned(),
        PASSWORD.to_owned(),
        "Wrong!Password123".to_owned(),
        user.session.clone(),
        rotated,
    ];
    secrets.extend(user.codes.iter().cloned());
    secrets.extend(regenerated_codes);
    secrets.extend(replaced_codes);
    for secret in secrets {
        assert!(!recorded.contains(&secret), "audit leaked secret material");
    }
    cleanup(&pool, &user.email).await;
}

async fn named_pool(application_name: &str) -> PgPool {
    let mut url = url::Url::parse(&std::env::var("DATABASE_URL").unwrap()).unwrap();
    url.query_pairs_mut()
        .append_pair("application_name", application_name);
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url.as_str())
        .await
        .unwrap()
}

/// Wait until the named application's backend is blocked by a lock.
async fn wait_until_blocked(pool: &PgPool, application_name: &str) {
    tokio::time::timeout(HANG, async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity \
                 WHERE application_name = $1 \
                   AND cardinality(pg_catalog.pg_blocking_pids(pid)) > 0)",
            )
            .bind(application_name)
            .fetch_one(pool)
            .await
            .unwrap();
            if blocked {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("request did not reach its account-lock barrier");
}

/// A sign-in that is completing while the authenticator is replaced must not
/// keep a session. The sign-in queues first on the account lock, so it wins:
/// it consumes its challenge and issues its session in one transaction, and
/// the replacement that takes the lock next deletes that session with every
/// other. Issuing the session after the sign-in commits would let it slip in
/// behind the revocation and survive.
#[tokio::test]
async fn a_sign_in_completing_during_a_replacement_cannot_keep_its_session() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "replacement-signin-race").await;
    let started = proof(&apps, START, &user, &user.session, PASSWORD, &user.codes[0]).await;
    assert_eq!(started.status, 200, "{}", started.body);
    let id = started.body["replacement_id"].as_str().unwrap().to_owned();
    let new_secret = started.body["secret"].as_str().unwrap().to_owned();
    let challenge = call(
        &apps.signup,
        "POST",
        "/api/auth/sign-in",
        Call::default(),
        json!({"email": user.email, "password": PASSWORD}),
    )
    .await;
    let challenge = challenge.body["twoFactorToken"]
        .as_str()
        .unwrap()
        .to_owned();

    let validate_name = format!("tfr-validate-{}", std::process::id());
    let confirm_name = format!("tfr-confirm-{}", std::process::id());
    let validate_app = codewire_idp::two_factor::router(
        named_pool(&validate_name).await,
        SESSION_SECRET.into(),
        true,
        AuthState { pool: pool.clone() },
    );
    let confirm_app = replacement_app(named_pool(&confirm_name).await);

    // Hold the account lock so both requests queue on it in a known order.
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(&user.user_id)
        .execute(&mut *holder)
        .await
        .unwrap();
    let old_code = code_at(&user.secret, &user.email, 0);
    let signing_in = tokio::spawn(async move {
        call(
            &validate_app,
            "POST",
            "/api/auth/two-factor/validate",
            Call::default(),
            json!({"code": old_code, "token": challenge}),
        )
        .await
    });
    wait_until_blocked(&pool, &validate_name).await;
    let confirm_body = json!({
        "account_id": user.user_id,
        "replacement_id": id,
        "code": code_at(&new_secret, &user.email, 0),
    });
    let session = user.session.clone();
    let replacing = tokio::spawn(async move {
        call(
            &confirm_app,
            "POST",
            CONFIRM,
            Call {
                cookie: Some(&session),
                origin: Some(ORIGIN),
                ..Default::default()
            },
            confirm_body,
        )
        .await
    });
    wait_until_blocked(&pool, &confirm_name).await;
    holder.rollback().await.unwrap();

    let signed_in = signing_in.await.unwrap();
    let replaced = replacing.await.unwrap();
    assert_eq!(signed_in.status, 200, "{}", signed_in.body);
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    let signed_in_token = cookie_token(signed_in.set_cookie.as_deref().unwrap());
    let rotated = cookie_token(replaced.set_cookie.as_deref().unwrap());
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT token_hash FROM sessions WHERE user_id=$1")
            .bind(&user.user_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining,
        vec![hash_session_token(&rotated)],
        "a sign-in session survived the replacement"
    );
    assert!(!remaining.contains(&hash_session_token(&signed_in_token)));
    cleanup(&pool, &user.email).await;
}

/// Two fresh proofs that race with the same authenticator code serialize on
/// the account: exactly one is accepted, and the other is a counted failure.
#[tokio::test]
async fn concurrent_proofs_with_one_code_have_exactly_one_winner() {
    let Some(pool) = pool().await else { return };
    let apps = apps(&pool);
    let user = enrolled(&pool, &apps, "replacement-proof-race").await;
    let code = code_at(&user.secret, &user.email, 0);
    let (started, regenerated) = tokio::join!(
        proof(&apps, START, &user, &user.session, PASSWORD, &code),
        proof(&apps, REGENERATE, &user, &user.session, PASSWORD, &code),
    );
    let mut statuses = [started.status, regenerated.status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [200, 422],
        "{}: {} / {}: {}",
        started.status,
        started.body,
        regenerated.status,
        regenerated.body
    );
    assert_eq!(failures(&pool, &user.user_id).await, (1, false));
    assert_eq!(
        pending(&pool, &user.user_id).await.is_some(),
        started.status == 200,
        "only an accepted start leaves a pending replacement"
    );
    let rejected: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE user_id=$1 AND action='user.2fa.proof_failed' \
         AND metadata->>'reason'='rejected'",
    )
    .bind(&user.user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected, 1);
    cleanup(&pool, &user.email).await;
}
