//! The sign-up limits against a real Postgres (#3297): a sign-up that has
//! passed its own checks counts against `signup_address` for its client
//! address and then `signup`, each at the admin's global count; past either
//! the IdP refuses with 429 `rate_limited`, the limit and its reset in the
//! detail and `Retry-After` in seconds, and creates no account. A request
//! refused by its own checks counts nothing.
//!
//! Skipped unless `DATABASE_URL` is set. It owns the `signup:all` and
//! `signup_address:*` counters and both settings while it runs, and removes
//! them, so it runs as its own suite, never beside another that signs up.
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
    sign_up_from(app, body, None).await
}

/// A sign-up whose `X-Forwarded-For` is `forwarded`, as the edge or the
/// dashboard sends it.
async fn sign_up_from(app: &Router, body: serde_json::Value, forwarded: Option<&str>) -> Answer {
    let mut request =
        Request::post("/api/auth/sign-up").header(header::CONTENT_TYPE, "application/json");
    if let Some(forwarded) = forwarded {
        request = request.header("x-forwarded-for", forwarded);
    }
    let request = request.body(Body::from(body.to_string())).unwrap();
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
    sqlx::query("DELETE FROM rate_limit WHERE key = 'signup:all' OR key LIKE 'signup_address:%'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rate_limit_settings WHERE name IN ('signup', 'signup_address')")
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
        "synthetic-client-address-key".to_owned(),
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

/// The admin's global count per address for the address scenario.
const ADDRESS_MAX: i32 = 2;
/// Documentation addresses (RFC 5737).
const ADDRESS: &str = "203.0.113.7";
const OTHER_ADDRESS: &str = "198.51.100.4";

async fn set_count(pool: &PgPool, name: &str, max: i32) {
    sqlx::query(
        "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
         VALUES ($1, $2, 'signup-limit-test')",
    )
    .bind(name)
    .bind(max)
    .execute(pool)
    .await
    .unwrap();
}

/// One client address is refused past its count while another still signs
/// up. The address is the last hop, which the edge writes, so a hop the
/// client wrote before it changes nothing. One address's refusals never
/// spend the site's allowance. A sign-up with no address counts against the
/// site only. Sign-ups that wait for review count like any other.
async fn one_address_is_refused_past_its_count(pool: &PgPool, nonce: u128) {
    let prefix = format!("signup-limit-address-{nonce:x}-");
    reset(pool, &prefix).await;
    set_count(pool, "signup", 10).await;
    set_count(pool, "signup_address", ADDRESS_MAX).await;
    let (mail, _outbox) = codewire_email::EmailClient::recording();
    let app = codewire_idp::auth_session::router_with_email(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::default(),
        "https://app.codewire.test".to_owned(),
        mail,
    );
    let waiting = |email: &str| {
        let mut body = valid(email);
        body["reason"] = "Building a synthetic test".into();
        body
    };

    for n in 0..ADDRESS_MAX {
        let email = format!("{prefix}{n}@example.test");
        let answer = sign_up_from(&app, waiting(&email), Some(ADDRESS)).await;
        assert_eq!(answer.status, StatusCode::ACCEPTED, "{:?}", answer.body);
        assert_eq!(answer.body["accessPending"], true, "{:?}", answer.body);
    }

    let refused_email = format!("{prefix}refused@example.test");
    let answer = sign_up_from(&app, waiting(&refused_email), Some(ADDRESS)).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        answer.body
    );
    assert_eq!(answer.body["code"], "rate_limited");
    let detail = answer.body["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(&format!(
            "at most {ADDRESS_MAX} sign-ups from one address an hour; try again after "
        )),
        "{detail}"
    );
    let retry_after: u64 = answer.retry_after.unwrap().parse().unwrap();
    assert!((1..=3_600).contains(&retry_after), "{retry_after}");
    assert!(!account_exists(pool, &refused_email).await);

    // The client wrote the other address; the edge appended the real one.
    let spoofed_email = format!("{prefix}spoofed@example.test");
    let spoofed = format!("{OTHER_ADDRESS}, {ADDRESS}");
    let answer = sign_up_from(&app, waiting(&spoofed_email), Some(&spoofed)).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        answer.body
    );
    assert!(!account_exists(pool, &spoofed_email).await);

    let other_email = format!("{prefix}other@example.test");
    let answer = sign_up_from(&app, waiting(&other_email), Some(OTHER_ADDRESS)).await;
    assert_eq!(answer.status, StatusCode::ACCEPTED, "{:?}", answer.body);

    // Only the three admitted sign-ups reached the site-wide count.
    let site: i32 = sqlx::query_scalar("SELECT count FROM rate_limit WHERE key = 'signup:all'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(site, 3);

    for n in 0..=ADDRESS_MAX {
        let email = format!("{prefix}unaddressed{n}@example.test");
        let answer = sign_up(&app, waiting(&email)).await;
        assert_eq!(answer.status, StatusCode::ACCEPTED, "{:?}", answer.body);
    }

    reset(pool, &prefix).await;
}

/// A mailer for the provider router that never needs to send: these
/// sign-ups match no account.
struct NoLinkConfirmations;

#[async_trait::async_trait]
impl codewire_idp::oauth::LinkConfirmationMailer for NoLinkConfirmations {
    fn is_available(&self) -> bool {
        false
    }

    async fn send(
        &self,
        _to: &str,
        _provider: codewire_idp::oauth::Provider,
        _account: &str,
        _confirm_url: &str,
    ) -> anyhow::Result<()> {
        unreachable!("no sign-up here matches an account")
    }
}

/// A provider sign-up the callback left waiting, as its completion page
/// finds it: the handle the browser holds and the identity GitHub proved.
async fn pending_provider_sign_up(pool: &PgPool, handle: &str, subject: &str, email: &str) {
    sqlx::query(
        "INSERT INTO oauth_states (id, token_hash, provider, intent, provider_identity, expires_at) \
         VALUES ($1, $2, 'github', 'sign_up', $3, NOW() + interval '10 minutes')",
    )
    .bind(format!("signup-limit-{subject}"))
    .bind(codewire_server_core::auth::hash_session_token(handle))
    .bind(serde_json::json!({ "subject": subject, "email": email, "name": "Synthetic" }))
    .execute(pool)
    .await
    .unwrap();
}

/// A provider sign-up counts against its client address like an email
/// sign-up: past the count it is refused before its account is made, and its
/// pending sign-up is kept to try again.
async fn provider_sign_ups_count_against_their_address(pool: &PgPool, nonce: u128) {
    let prefix = format!("signup-limit-provider-{nonce:x}-");
    reset(pool, &prefix).await;
    set_count(pool, "signup", 10).await;
    set_count(pool, "signup_address", 1).await;
    let app = codewire_idp::oauth::trusted_test_router(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::default()
            .with_mode(codewire_idp::auth_session::SignupMode::Open),
        "https://app.codewire.test".to_owned(),
        codewire_idp::oauth::OAuthProviders::disabled(),
        std::sync::Arc::new(NoLinkConfirmations),
    );
    let complete = |handle: &str| {
        let request = Request::post("/api/auth/oauth/signup/complete")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", ADDRESS)
            .body(Body::from(
                serde_json::json!({ "token": handle }).to_string(),
            ))
            .unwrap();
        app.clone().oneshot(request)
    };
    let handles = [nonce % 1_000_000, nonce % 1_000_000 + 1].map(|n| format!("{n:064x}"));
    let emails = [0, 1].map(|n| format!("{prefix}{n}@example.test"));
    for (n, (handle, email)) in handles.iter().zip(&emails).enumerate() {
        pending_provider_sign_up(pool, handle, &format!("{nonce:x}{n}"), email).await;
    }

    let first = complete(&handles[0]).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert!(account_exists(pool, &emails[0]).await);

    let second = complete(&handles[1]).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(body["code"], "rate_limited");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .starts_with("at most 1 sign-ups from one address an hour; "),
        "{body}"
    );
    assert!(!account_exists(pool, &emails[1]).await);
    let kept: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_states WHERE token_hash = $1)")
            .bind(codewire_server_core::auth::hash_session_token(&handles[1]))
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(kept, "the refused sign-up can be completed later");

    // Only this run's rows: another run of the suite may share the database.
    sqlx::query("DELETE FROM oauth_states WHERE id LIKE $1")
        .bind(format!("signup-limit-{nonce:x}%"))
        .execute(pool)
        .await
        .unwrap();
    reset(pool, &prefix).await;
}

const OPERATOR: &str = "operator@example.test";
const FRONTEND: &str = "https://app.codewire.test";

/// The operator's notices in `outbox`, once at least `count` have been sent
/// or two seconds have passed: each is sent in its own task.
async fn operator_notices(
    outbox: &codewire_email::Outbox,
    count: usize,
) -> Vec<codewire_email::SentEmail> {
    let notices = || {
        outbox
            .sent()
            .into_iter()
            .filter(|mail| mail.to == OPERATOR)
            .collect::<Vec<_>>()
    };
    for _ in 0..20 {
        if notices().len() >= count {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    notices()
}

/// A verification link for `email`, stored as the IdP stores one.
async fn seed_verification(pool: &PgPool, id: &str, email: &str, token: &str) {
    use sha2::{Digest as _, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"codewire/idp/verification/v1\0email_verification\0");
    digest.update(token.as_bytes());
    let token_hash: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    sqlx::query(
        "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at, created_at, updated_at) \
         VALUES ($1, $2, 'email_verification', $3, NOW() + interval '1 hour', NOW(), NOW())",
    )
    .bind(id)
    .bind(email)
    .bind(token_hash)
    .execute(pool)
    .await
    .unwrap();
}

/// The token in the verification link of the last email to `email`.
fn emailed_token(outbox: &codewire_email::Outbox, email: &str) -> String {
    let sent = outbox.sent();
    let html = &sent
        .iter()
        .rev()
        .find(|mail| mail.to == email)
        .unwrap()
        .html;
    let start = html.find("/verify-email?token=").unwrap() + "/verify-email?token=".len();
    html[start..]
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect()
}

async fn verify(app: &Router, token: &str) -> StatusCode {
    let request = Request::get(format!("/api/auth/verify-email?token={token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

/// The operator hears once per new person (#5358): an email access request
/// when its address is first verified, a provider sign-up when it is made,
/// at most ten an hour and then one "more people are waiting", and nothing
/// for a second verification, the admin, or a server with no operator.
async fn the_operator_hears_once_per_new_person(pool: &PgPool, nonce: u128) {
    let prefix = format!("signup-limit-operator-{nonce:x}-");
    let forget_notices = || async {
        sqlx::query("DELETE FROM rate_limit WHERE key = 'operator_notice:all'")
            .execute(pool)
            .await
            .unwrap();
    };
    reset(pool, &prefix).await;
    forget_notices().await;

    let (user_mail, user_box) = codewire_email::EmailClient::recording();
    let sign_ups = codewire_idp::auth_session::router_with_email(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::default(),
        FRONTEND.to_owned(),
        user_mail,
    );
    let (mail, outbox) = codewire_email::EmailClient::recording();
    let links = codewire_idp::email_password::router(
        pool.clone(),
        FRONTEND.to_owned(),
        mail,
        codewire_server_core::auth::AuthState { pool: pool.clone() },
        Some(OPERATOR.to_owned()),
    );

    // An access request: nothing until its address is verified, then one
    // notice naming who, how, that they wait, and the review page.
    let requester = format!("{prefix}request@example.test");
    let mut body = valid(&requester);
    body["reason"] = "Synthetic reason the operator never reads here".into();
    assert_eq!(sign_up(&sign_ups, body).await.status, StatusCode::ACCEPTED);
    assert!(operator_notices(&outbox, 1).await.is_empty());
    let token = emailed_token(&user_box, &requester);
    assert_eq!(verify(&links, &token).await, StatusCode::OK);
    let notices = operator_notices(&outbox, 1).await;
    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].subject,
        format!("Codewire: access request from {requester}")
    );
    for line in [
        "Signed up with: email",
        "They wait for an admin to enable their account.",
        "https://app.codewire.test/admin/accounts/",
    ] {
        assert!(
            notices[0].text.contains(line),
            "{line}: {}",
            notices[0].text
        );
    }
    assert!(!notices[0].text.contains("Synthetic reason"));

    // A second verification of the same address is not a new person.
    seed_verification(pool, &format!("{prefix}again"), &requester, "again").await;
    assert_eq!(verify(&links, "again").await, StatusCode::OK);
    // The admin's own verification is not a sign-up either.
    let admin = format!("{prefix}admin@example.test");
    sqlx::query(
        "INSERT INTO users (id, email, email_verified, enabled, is_admin) VALUES ($1, $2, false, true, true)",
    )
    .bind(format!("{prefix}admin"))
    .bind(&admin)
    .execute(pool)
    .await
    .unwrap();
    seed_verification(pool, &format!("{prefix}admin"), &admin, "admin").await;
    assert_eq!(verify(&links, "admin").await, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(operator_notices(&outbox, 2).await.len(), 1);

    // With no operator address, a verified sign-up sends the operator nothing.
    let (unset_mail, unset_box) = codewire_email::EmailClient::recording();
    let unset = codewire_idp::email_password::router(
        pool.clone(),
        FRONTEND.to_owned(),
        unset_mail,
        codewire_server_core::auth::AuthState { pool: pool.clone() },
        None,
    );
    let quiet = format!("{prefix}quiet@example.test");
    let mut body = valid(&quiet);
    body["reason"] = "Synthetic".into();
    assert_eq!(sign_up(&sign_ups, body).await.status, StatusCode::ACCEPTED);
    let token = emailed_token(&user_box, &quiet);
    assert_eq!(verify(&unset, &token).await, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(operator_notices(&unset_box, 1).await.is_empty());

    // A provider sign-up is told at once; past ten in the hour one notice
    // says more are waiting, and the next says nothing.
    let (provider_mail, provider_box) = codewire_email::EmailClient::recording();
    let providers = codewire_idp::oauth::trusted_test_router_with_operator(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::default()
            .with_mode(codewire_idp::auth_session::SignupMode::Open),
        FRONTEND.to_owned(),
        codewire_idp::oauth::OAuthProviders::disabled(),
        std::sync::Arc::new(NoLinkConfirmations),
        provider_mail,
        OPERATOR.to_owned(),
    );
    let complete = |handle: String| {
        let request = Request::post("/api/auth/oauth/signup/complete")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "token": handle }).to_string(),
            ))
            .unwrap();
        providers.clone().oneshot(request)
    };
    let provider_sign_up = |n: u128| {
        let handle = format!("{:064x}", nonce % 1_000_000 + 100 + n);
        let email = format!("{prefix}provider{n}@example.test");
        let subject = format!("{nonce:x}operator{n}");
        async move {
            pending_provider_sign_up(pool, &handle, &subject, &email).await;
            assert_eq!(complete(handle).await.unwrap().status(), StatusCode::OK);
            email
        }
    };
    let first = provider_sign_up(0).await;
    let notices = operator_notices(&provider_box, 1).await;
    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].subject,
        format!("Codewire: new sign-up, {first}")
    );
    assert!(notices[0].text.contains("Signed up with: GitHub"));
    assert!(notices[0].text.contains("They can sign in now."));

    sqlx::query("UPDATE rate_limit SET count = 10 WHERE key = 'operator_notice:all'")
        .execute(pool)
        .await
        .unwrap();
    provider_sign_up(1).await;
    let notices = operator_notices(&provider_box, 2).await;
    assert_eq!(notices.len(), 2);
    assert_eq!(notices[1].subject, "Codewire: more people are waiting");
    assert!(
        notices[1].text.contains("wait for review now")
            || notices[1].text.contains("waits for review now"),
        "{}",
        notices[1].text
    );
    provider_sign_up(2).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(operator_notices(&provider_box, 3).await.len(), 2);

    sqlx::query("DELETE FROM oauth_states WHERE id LIKE $1")
        .bind(format!("signup-limit-{nonce:x}operator%"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM verifications WHERE identifier LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await
        .unwrap();
    forget_notices().await;
    reset(pool, &prefix).await;
}

/// One test, so the scenarios that own the sign-up counters run one after
/// the other.
#[tokio::test]
async fn the_sign_up_limits_refuse_past_their_counts_and_never_lock_invitees_out() {
    let Some(pool) = pool().await else { return };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    sign_ups_past_the_count_are_refused(&pool, nonce).await;
    invitees_are_never_locked_out(&pool, nonce).await;
    one_address_is_refused_past_its_count(&pool, nonce).await;
    provider_sign_ups_count_against_their_address(&pool, nonce).await;
    the_operator_hears_once_per_new_person(&pool, nonce).await;
}
