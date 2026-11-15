//! Adding a password to an account that signs in only with GitHub or Google
//! (#4528): only from a signed-in browser session that began within 10
//! minutes, only for a verified address with no password yet, and, when a
//! second factor is enrolled, only with a fresh code from it.
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use axum::http::Request;
use axum::{Router, body::Body};
use codewire_idp::password_add::{PasswordAddBounds, password_add_router};
use codewire_server_core::auth::{AuthState, hash_session_token};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

const ORIGIN: &str = "https://app.codewire.test";
const SESSION_SECRET: &str = "synthetic-password-add-secret";
const PATH: &str = "/api/auth/password/add";
const NEW_PASSWORD: &str = "Added!Pass1234";
const HANG: std::time::Duration = std::time::Duration::from_secs(60);

async fn pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping password add DB proof");
        return None;
    };
    Some(PgPool::connect(&url).await.unwrap())
}

fn app(pool: &PgPool, mail: codewire_email::EmailClient) -> Router {
    password_add_router(pool.clone(), SESSION_SECRET.into(), ORIGIN.into(), mail).layer(
        axum::Extension(PasswordAddBounds {
            request: HANG,
            statement: HANG,
        }),
    )
}

/// A verified GitHub-only account with one browser session, `age_minutes`
/// old, past the two-factor boundary by having skipped setup.
async fn account(pool: &PgPool, id: &str, verified: bool, age_minutes: i64) -> String {
    let email = format!("{id}@password-add.test");
    for statement in [
        "DELETE FROM audit_logs WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
        "DELETE FROM accounts WHERE user_id = $1",
        "DELETE FROM two_factor WHERE user_id = $1",
        "DELETE FROM users WHERE id = $1",
    ] {
        sqlx::query(statement).bind(id).execute(pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, enabled, is_admin, two_factor_enabled) \
         VALUES ($1, $2, 'Password Add', $3, true, false, false)",
    )
    .bind(id)
    .bind(&email)
    .bind(verified)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id) VALUES ($1, $2, 'github', $3)",
    )
    .bind(format!("acct-{id}"))
    .bind(id)
    .bind(format!("github-{id}"))
    .execute(pool)
    .await
    .unwrap();
    let token = format!("session-{id}");
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, two_factor_setup_skipped_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour', NOW() - ($4::bigint * interval '1 minute'), NOW())",
    )
    .bind(hash_session_token(&token)[32..].to_owned())
    .bind(id)
    .bind(hash_session_token(&token))
    .bind(age_minutes)
    .execute(pool)
    .await
    .unwrap();
    token
}

async fn add(
    app: &Router,
    token: &str,
    account_id: &str,
    origin: &str,
    bearer: bool,
    code: &str,
) -> (u16, Value) {
    add_password(app, token, account_id, origin, bearer, code, NEW_PASSWORD).await
}

async fn add_password(
    app: &Router,
    token: &str,
    account_id: &str,
    origin: &str,
    bearer: bool,
    code: &str,
    new_password: &str,
) -> (u16, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("content-type", "application/json")
        .header("origin", origin)
        .header("cookie", format!("codewire.session_token={token}"));
    if bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = json!({ "account_id": account_id, "new_password": new_password, "code": code });
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn has_password(pool: &PgPool, id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = 'credential')",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn id_for(label: &str) -> String {
    let digest = hash_session_token(label);
    digest[..32].to_owned()
}

#[tokio::test]
async fn a_fresh_session_adds_a_password_once_and_the_account_is_told() {
    let Some(pool) = pool().await else { return };
    let id = id_for("password-add-fresh");
    let token = account(&pool, &id, true, 1).await;
    let (mail, outbox) = codewire_email::EmailClient::recording();
    let app = app(&pool, mail);

    let (status, body) = add(&app, &token, &id, ORIGIN, false, "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["added"], true);
    assert!(has_password(&pool, &id).await);
    let stored_as: String = sqlx::query_scalar(
        "SELECT account_id FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_as, format!("{id}@password-add.test"));
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE user_id = $1 AND action = 'user.password.added' \
         AND metadata->>'proof' = 'session'",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
    let sent = outbox.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].subject,
        "A password was added to your Codewire account"
    );
    assert!(
        sent[0].html.contains("as well as with GitHub"),
        "{}",
        sent[0].html
    );
    assert!(!sent[0].html.contains(NEW_PASSWORD));

    // A second add finds the password and changes nothing.
    let (status, body) = add(&app, &token, &id, ORIGIN, false, "").await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "password_exists");
    assert_eq!(outbox.sent().len(), 1);
}

#[tokio::test]
async fn an_old_session_unverified_address_bearer_or_foreign_origin_adds_nothing() {
    let Some(pool) = pool().await else { return };
    let app = app(&pool, codewire_email::EmailClient::disabled());

    let old = id_for("password-add-old");
    let token = account(&pool, &old, true, 20).await;
    let (status, body) = add(&app, &token, &old, ORIGIN, false, "").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("reauthentication_required")),
        "{body}"
    );
    assert!(!has_password(&pool, &old).await);

    let unverified = id_for("password-add-unverified");
    let token = account(&pool, &unverified, false, 1).await;
    let (status, body) = add(&app, &token, &unverified, ORIGIN, false, "").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("email_unverified")),
        "{body}"
    );
    assert!(!has_password(&pool, &unverified).await);

    let other = id_for("password-add-boundary");
    let token = account(&pool, &other, true, 1).await;
    let (status, _) = add(&app, &token, &other, "https://evil.example", false, "").await;
    assert_eq!(status, 403);
    let (status, _) = add(&app, &token, &other, ORIGIN, true, "").await;
    assert!(
        status == 400 || status == 401 || status == 403,
        "a bearer must not reach it: {status}"
    );
    // Another account's id is refused too.
    let (status, _) = add(&app, &token, &old, ORIGIN, false, "").await;
    assert_eq!(status, 403);
    assert!(!has_password(&pool, &other).await);
    // A cookie that names no live session is refused before the password is
    // hashed.
    let (status, _) = add(&app, "no-such-session", &other, ORIGIN, false, "").await;
    assert_eq!(status, 401);
    assert!(!has_password(&pool, &other).await);
    // The preflight comes before any work on the password: an anonymous
    // request with a password the rules refuse gets 401, not 400.
    let (status, body) =
        add_password(&app, "no-such-session", &other, ORIGIN, false, "", "weak").await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn an_enrolled_factor_needs_a_fresh_code() {
    let Some(pool) = pool().await else { return };
    let id = id_for("password-add-factor");
    let token = account(&pool, &id, true, 1).await;
    // Enroll a factor through the real handlers.
    let factor = codewire_idp::two_factor::router(
        pool.clone(),
        SESSION_SECRET.into(),
        true,
        AuthState { pool: pool.clone() },
    );
    let call = |path: &'static str, body: Value| {
        let factor = factor.clone();
        let token = token.clone();
        async move {
            let response = factor
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .header("origin", ORIGIN)
                        .header("cookie", format!("codewire.session_token={token}"))
                        .body(Body::from(if body.is_null() {
                            String::new()
                        } else {
                            body.to_string()
                        }))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let (status, enabled) = call("/api/auth/two-factor/enable", Value::Null).await;
    assert_eq!(status, 200, "{enabled}");
    let secret = enabled["secret"].as_str().unwrap().to_owned();
    let recovery: Vec<String> = serde_json::from_value(enabled["backupCodes"].clone()).unwrap();
    let email = format!("{id}@password-add.test");
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret).to_bytes().unwrap(),
        Some("Codewire".into()),
        email,
    )
    .unwrap();
    let (status, verified) = call(
        "/api/auth/two-factor/verify",
        json!({ "code": totp.generate_current().unwrap() }),
    )
    .await;
    assert_eq!(status, 200, "{verified}");

    let app = app(&pool, codewire_email::EmailClient::disabled());
    let last_step = || async {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_totp_step FROM two_factor WHERE user_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let step_before = last_step().await;
    // No code, and a wrong one, add nothing and count against the lockout.
    for code in ["", "000000"] {
        let (status, body) = add(&app, &token, &id, ORIGIN, false, code).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (422, Some("code_rejected")),
            "{body}"
        );
        assert!(!has_password(&pool, &id).await);
    }
    let failures: i32 =
        sqlx::query_scalar("SELECT COALESCE(failed_login_attempts, 0) FROM users WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(failures, 2);
    // Each refusal is audited, and neither spends the factor's time step.
    let refused: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE user_id = $1 AND action = 'user.password.add_refused' \
         AND metadata->>'reason' = 'code'",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(refused, 2);
    assert_eq!(last_step().await, step_before);
    // An unused recovery code works once, and is spent.
    let (status, body) = add(&app, &token, &id, ORIGIN, false, &recovery[0]).await;
    assert_eq!(status, 200, "{body}");
    assert!(has_password(&pool, &id).await);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE user_id = $1 AND action = 'user.password.added' \
         AND metadata->>'proof' = 'recovery_code'",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
