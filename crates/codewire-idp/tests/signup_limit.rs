//! The site-wide sign-up limit against a real Postgres (#3297): a sign-up
//! that has passed its own checks counts against `signup`, at the admin's
//! global count; past it the IdP refuses with 429 `rate_limited`, the limit
//! and its reset in the detail and `Retry-After` in seconds, and creates no
//! account. A request refused by its own checks counts nothing.
//!
//! Skipped unless `DATABASE_URL` is set. It owns the `signup:all` counter
//! and the `signup` setting while it runs, and removes both, so it runs as its
//! own suite, never beside another that signs up.
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

/// The admin's global count for the test: two sign-ups an hour.
const MAX: i32 = 2;

async fn pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping sign-up limit DB proof");
        return None;
    };
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap(),
    )
}

struct Answer {
    status: StatusCode,
    retry_after: Option<String>,
    body: serde_json::Value,
}

async fn sign_up(app: &Router, body: serde_json::Value) -> Answer {
    let request = Request::post("/api/auth/sign-up")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    Answer {
        status,
        retry_after,
        body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    }
}

fn valid(email: &str) -> serde_json::Value {
    serde_json::json!({
        "email": email,
        "password": "CorrectHorse9#xy",
        "name": "Synthetic sign-up limit",
    })
}

async fn account_exists(pool: &PgPool, email: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn reset(pool: &PgPool, prefix: &str) {
    sqlx::query("DELETE FROM rate_limit WHERE key = 'signup:all'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rate_limit_settings WHERE name = 'signup'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE email LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await
        .unwrap();
}

/// Past the global count, an email sign-up is refused and creates no account;
/// a request refused by its own checks counts nothing.
async fn sign_ups_past_the_count_are_refused(pool: &PgPool, nonce: u128) {
    let pool = pool.clone();
    let prefix = format!("signup-limit-{nonce:x}-");
    reset(&pool, &prefix).await;
    sqlx::query(
        "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
         VALUES ('signup', $1, 'signup-limit-test')",
    )
    .bind(MAX)
    .execute(&pool)
    .await
    .unwrap();
    let (mail, _outbox) = codewire_email::EmailClient::recording();
    let app = codewire_idp::auth_session::router_with_email(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
        "https://app.codewire.test".to_owned(),
        mail,
    );

    // Refused by their own checks first, so they count nothing.
    for _ in 0..5 {
        let mut weak = valid(&format!("{prefix}weak@example.test"));
        weak["password"] = "short".into();
        let answer = sign_up(&app, weak).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{:?}", answer.body);
    }

    // The global count admits exactly MAX sign-ups.
    for n in 0..MAX {
        let email = format!("{prefix}{n}@example.test");
        let answer = sign_up(&app, valid(&email)).await;
        assert_eq!(answer.status, StatusCode::ACCEPTED, "{:?}", answer.body);
        assert!(account_exists(&pool, &email).await);
    }

    let refused_email = format!("{prefix}refused@example.test");
    let answer = sign_up(&app, valid(&refused_email)).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.body["code"], "rate_limited");
    let detail = answer.body["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(&format!("at most {MAX} sign-ups an hour; try again after ")),
        "{detail}"
    );
    let retry_after: u64 = answer.retry_after.unwrap().parse().unwrap();
    assert!((1..=3_600).contains(&retry_after), "{retry_after}");
    assert!(!account_exists(&pool, &refused_email).await);

    reset(&pool, &prefix).await;
}

/// On an invite-only server with no Turnstile, an invited sign-up never counts
/// and a token that names no live invitation is refused before counting, so
/// uninvited traffic can't use up the allowance and lock invitees out. An
/// uninvited sign-up, which creates an account that waits, still counts.
async fn invitees_are_never_locked_out(pool: &PgPool, nonce: u128) {
    let prefix = format!("signup-limit-invite-{nonce:x}-");
    let admin = format!("signup-limit-admin-{nonce:x}");
    let org = format!("signup-limit-org-{nonce:x}");
    let token = format!("signup-limit-token-{nonce:x}");
    let invited = format!("{prefix}invited@example.test");
    reset(pool, &prefix).await;
    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, is_admin, enabled) \
         VALUES ($1, $1 || '@example.test', 'Admin', true, true, true)",
    )
    .bind(&admin)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)")
        .bind(&org)
        .bind(&admin)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO org_invitations (id, org_id, email, role, invited_by, status, expires_at, \
         created_at, token_hash) VALUES ($1, $1, $2, 'member', $3, 'pending', \
         NOW() + interval '1 hour', NOW(), $4)",
    )
    .bind(&org)
    .bind(&invited)
    .bind(&admin)
    .bind(codewire_server_core::auth::hash_oauth_token(&token))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
         VALUES ('signup', 1, 'signup-limit-test')",
    )
    .execute(pool)
    .await
    .unwrap();
    let app = codewire_idp::auth_session::router_with_signup_delivery(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::default()
            .with_mode(codewire_idp::auth_session::SignupMode::InviteOnly),
        "https://app.codewire.test".to_owned(),
        codewire_email::EmailClient::disabled(),
        String::new(),
        String::new(),
    );
    let with_token = |email: &str, token: &str| {
        let mut body = valid(email);
        body["invitation_token"] = token.into();
        body
    };

    // Tokens that name no live invitation are refused and count nothing.
    for n in 0..5 {
        let answer = sign_up(
            &app,
            with_token(&format!("{prefix}bogus{n}@example.test"), "bogus"),
        )
        .await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{:?}", answer.body);
        assert_eq!(answer.body["code"], "invite_only");
    }
    // An uninvited sign-up waits for the admin and counts: the one allowed.
    let waiting = sign_up(&app, valid(&format!("{prefix}waiting@example.test"))).await;
    assert_eq!(waiting.status, StatusCode::ACCEPTED, "{:?}", waiting.body);
    let over = sign_up(&app, valid(&format!("{prefix}over@example.test"))).await;
    assert_eq!(
        over.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        over.body
    );
    // The allowance is spent, and the invitee still signs up.
    let answer = sign_up(&app, with_token(&invited, &token)).await;
    assert!(
        answer.status.is_success(),
        "{:?} {:?}",
        answer.status,
        answer.body
    );
    assert!(account_exists(pool, &invited).await);

    reset(pool, &prefix).await;
    for (sql, value) in [
        ("DELETE FROM org_invitations WHERE org_id = $1", &org),
        ("DELETE FROM organizations WHERE id = $1", &org),
        ("DELETE FROM users WHERE id = $1", &admin),
    ] {
        sqlx::query(sql).bind(value).execute(pool).await.unwrap();
    }
}

/// One test, so the two scenarios that own the signup:all counter run one
/// after the other.
#[tokio::test]
async fn the_site_wide_count_refuses_past_its_limit_and_never_locks_invitees_out() {
    let Some(pool) = pool().await else { return };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    sign_ups_past_the_count_are_refused(&pool, nonce).await;
    invitees_are_never_locked_out(&pool, nonce).await;
}
