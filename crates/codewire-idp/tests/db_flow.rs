//! DB-backed end-to-end gate for the idp.
//!
//! Drives the assembled provider against a real Postgres, exercising every
//! store's SQL: the desktop public client's `authorize -> token -> userinfo`,
//! id_token signature verification against the published JWKS, and
//! revocation/introspection.
//!
//! Skipped unless `DATABASE_URL` is set (so a plain `cargo test` with no
//! database is a no-op); CI's integration job runs it against a Postgres
//! initialized through the standard SQLx migration entrypoint.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use base64::Engine;
use codewire_idp::{
    IdpConfig, PgAuthorizationStore, PgDeviceAuthorizationStore, SigningKekKeyring, build_provider,
};
use codewire_oidc::{
    AuthRequestId, AuthorizationRequest, AuthorizationStore, AuthorizeOutcome, DeviceAuthorization,
    DeviceAuthorizationStore, DeviceStatus, ErrorCode, KeyStore, RawAuthorizeParams,
    RequestContext, ResponseType, Scopes, StoredAuthRequest, Subject,
};
use codewire_server_core::auth::{
    AuthState, AuthUser, CredentialContext, api_key_prefix, generate_api_key, hash_api_key,
    hash_oauth_token, hash_session_token, require_auth,
};
use hmac::{Hmac, Mac as _};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use totp_rs::{Algorithm, Secret, TOTP};

// PKCE pair from RFC 7636 Appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const USER: &str = "u_idp_e2e";
const CLIENT: &str = "codewire-desktop";
const REDIRECT: &str = "http://localhost:9876/callback";
const IOS_CLIENT: &str = "codewire-ios";
const IOS_REDIRECT: &str = "sh.codewire.ios:/oauth/callback";
const TEST_CAPABILITY_HMAC_SECRET: &str = "synthetic-idp-capability-hmac-secret";
type PersistedNewKeyRow = (String, String, Vec<u8>, Vec<u8>, String, i16);
type PersistedEnvelopeFields = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i16>,
);

fn test_signing_keyring() -> SigningKekKeyring {
    use std::sync::OnceLock;

    static KEYRING: OnceLock<SigningKekKeyring> = OnceLock::new();
    KEYRING
        .get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("codewire-idp-db-flow-kek-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create test keyring");
            std::fs::write(
                dir.join("v1"),
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            )
            .expect("write synthetic test KEK");
            SigningKekKeyring::load(&dir, "v1").expect("load synthetic test keyring")
        })
        .clone()
}

fn test_device_user_code_digest(raw: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_CAPABILITY_HMAC_SECRET.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every size");
    mac.update(b"codewire/idp/device-user-code/v1\0");
    mac.update(raw.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn database_url_with_application_name(database_url: &str, application_name: &str) -> String {
    let mut url = url::Url::parse(database_url).expect("parse test database URL");
    url.query_pairs_mut()
        .append_pair("application_name", application_name);
    url.into()
}

/// A hang guard for the test's own waits (a worker reaching its lock barrier,
/// a completion path finishing): 3 s was spent by a loaded CI guest before
/// the worker reached the lock (PR run 23391, "completion-path worker did not
/// reach its lock barrier"). A deadlock still fails, after this long.
const HANG: std::time::Duration = std::time::Duration::from_secs(60);

async fn wait_for_application_lock_blocker(
    pool: &PgPool,
    application_name: &str,
    blocker: i32,
) -> i32 {
    tokio::time::timeout(HANG, async {
        loop {
            let pids: Vec<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_catalog.pg_stat_activity WHERE application_name = $1",
            )
            .bind(application_name)
            .fetch_all(pool)
            .await
            .expect("inspect completion-path worker");
            for pid in pids {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
                )
                .bind(pid)
                .bind(blocker)
                .fetch_one(pool)
                .await
                .expect("inspect completion-path lock blocker");
                if blocked {
                    return pid;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("completion-path worker did not reach its lock barrier")
}

async fn wait_for_pid_lock_blocker(pool: &PgPool, waiter: i32, blocker: i32) {
    tokio::time::timeout(HANG, async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
            )
            .bind(waiter)
            .bind(blocker)
            .fetch_one(pool)
            .await
            .expect("inspect completion-path lock blocker");
            if blocked {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("completion-path transaction did not reach its lock barrier");
}

async fn spawn_account_disable(
    pool: PgPool,
    user_id: String,
) -> (i32, tokio::task::JoinHandle<()>) {
    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut tx = pool
            .begin()
            .await
            .expect("begin account-disable transaction");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("read account-disable backend pid");
        pid_tx
            .send(pid)
            .expect("account-disable observer is still waiting");
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .expect("disable account");
        tx.commit().await.expect("commit account disablement");
    });
    (
        pid_rx.await.expect("receive account-disable backend pid"),
        task,
    )
}

async fn finish_completion_path_task(task: tokio::task::JoinHandle<()>, context: &str) {
    tokio::time::timeout(HANG, task)
        .await
        .expect(context)
        .expect(context);
}

fn rotation_test_keyrings(label: &str) -> (SigningKekKeyring, SigningKekKeyring) {
    let dir = std::env::temp_dir().join(format!(
        "codewire-idp-db-flow-rotation-{}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create rotation test keyring");
    std::fs::write(
        dir.join("v1"),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .expect("write synthetic v1 KEK");
    std::fs::write(
        dir.join("v2"),
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    )
    .expect("write synthetic v2 KEK");
    (
        SigningKekKeyring::load(&dir, "v1").expect("load v1 rotation keyring"),
        SigningKekKeyring::load(&dir, "v2").expect("load v2 rotation keyring"),
    )
}

async fn seed(pool: &PgPool) {
    sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin) VALUES ($1,$2,$3,true,false) ON CONFLICT (id) DO NOTHING")
        .bind(USER).bind("e2e@example.com").bind("E2E User").execute(pool).await.unwrap();
    sqlx::query(
        r#"INSERT INTO oidc_clients
            (id, name, application_type, auth_method, redirect_uris,
             grant_types, response_types, scopes, skip_consent,
             access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
           VALUES ($1,'Codewire Desktop','native','none',ARRAY[$2],
             ARRAY['authorization_code','refresh_token'],ARRAY['code'],
             ARRAY['openid'],false,
             interval '1 hour', interval '720 hours', interval '1 hour')
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             application_type = EXCLUDED.application_type,
             auth_method = EXCLUDED.auth_method,
             redirect_uris = EXCLUDED.redirect_uris,
             grant_types = EXCLUDED.grant_types,
             response_types = EXCLUDED.response_types,
             scopes = EXCLUDED.scopes,
             skip_consent = EXCLUDED.skip_consent,
             access_token_lifetime = EXCLUDED.access_token_lifetime,
             refresh_token_lifetime = EXCLUDED.refresh_token_lifetime,
             id_token_lifetime = EXCLUDED.id_token_lifetime,
             disabled = false,
             updated_at = NOW()"#,
    )
    .bind(CLIENT)
    .bind(REDIRECT)
    .execute(pool)
    .await
    .unwrap();
    // A live session for the user (the authorize bridge reads the cookie).
    sqlx::query("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3, NOW() + interval '1 hour') ON CONFLICT (id) DO NOTHING")
        .bind("s_idp_e2e").bind(USER).bind(hash_session_token("sess_tok_e2e")).execute(pool).await.unwrap();
}

fn id_token_body(jwt: &str) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    serde_json::from_slice(&b64.decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

/// Verify an EdDSA JWT against the provider's published JWKS (key by `kid`).
fn verify_against_jwks(jwt: &str, jwks: &codewire_oidc::Jwks) -> bool {
    use ed25519_dalek::{Verifier, VerifyingKey};
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = jwt.split('.').collect();
    let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
    let kid = header["kid"].as_str().unwrap();
    let jwk = jwks.keys.iter().find(|k| k.kid == kid).unwrap();
    let pk: [u8; 32] = b64.decode(&jwk.x).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let sig: [u8; 64] = b64.decode(parts[2]).unwrap().try_into().unwrap();
    vk.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .is_ok()
}

#[tokio::test]
async fn native_clients_full_flow_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp DB e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    seed(&pool).await;
    codewire_idp::provisioning::ensure_desktop_client(&pool)
        .await
        .expect("converge replacement desktop client");
    codewire_idp::provisioning::ensure_ios_client(&pool)
        .await
        .expect("provision iOS public client");
    let desktop_scopes: Vec<String> =
        sqlx::query_scalar("SELECT scopes FROM oidc_clients WHERE id = 'codewire-desktop'")
            .fetch_one(&pool)
            .await
            .expect("read converged desktop client scopes");
    assert_eq!(
        desktop_scopes,
        vec![
            "openid",
            "profile",
            "email",
            "offline_access",
            "codewire.api"
        ],
        "startup provisioning must repair the pre-replacement identity-only desktop client"
    );
    let ios_client: (String, String, Vec<String>, Vec<String>, Vec<String>, bool) = sqlx::query_as(
        "SELECT application_type, auth_method, redirect_uris, grant_types, scopes, skip_consent \
         FROM oidc_clients WHERE id = 'codewire-ios'",
    )
    .fetch_one(&pool)
    .await
    .expect("read provisioned iOS client");
    assert_eq!(ios_client.0, "native");
    assert_eq!(ios_client.1, "none");
    assert_eq!(ios_client.2, vec![IOS_REDIRECT]);
    assert_eq!(
        ios_client.3,
        vec!["authorization_code", "refresh_token"],
        "iOS must use authorization-code PKCE and refresh only"
    );
    assert_eq!(
        ios_client.4,
        vec![
            "openid",
            "profile",
            "email",
            "offline_access",
            "codewire.api"
        ]
    );
    assert!(
        ios_client.5,
        "public native iOS consent is intentionally skipped"
    );

    let cfg = IdpConfig {
        issuer: "https://idp.codewire.test".into(),
        frontend_url: "https://app.codewire.test".into(),
        turnstile_secret_key: String::new(),
        turnstile_bypass_email: String::new(),
        signup_invite_policy: codewire_idp::auth_session::SignupInvitePolicy::open(),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "codewire.api".into(),
        ],
    };
    let p = build_provider(
        pool.clone(),
        &cfg,
        test_signing_keyring(),
        TEST_CAPABILITY_HMAC_SECRET,
    )
    .await
    .unwrap();
    let published_jwks = p.jwks().await.unwrap();
    assert!(
        !published_jwks.keys.is_empty(),
        "provider startup must publish a signing key before token issuance"
    );

    // 1. authorize with a live session cookie → redirect carrying the code.
    let ctx = RequestContext {
        cookie: Some("codewire.session_token=sess_tok_e2e".into()),
    };
    let params = RawAuthorizeParams {
        client_id: Some(CLIENT.into()),
        redirect_uri: Some(REDIRECT.into()),
        response_type: Some("code".into()),
        scope: Some("openid profile email offline_access codewire.api".into()),
        state: Some("st".into()),
        nonce: Some("no".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    };
    let url = match p.authorize(&ctx, params).await.unwrap() {
        AuthorizeOutcome::Redirect(u) => u,
        other => panic!("expected redirect, got {other:?}"),
    };
    assert!(url.starts_with(REDIRECT), "got {url}");
    let code = url
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let stored_code_hash: String = sqlx::query_scalar(
        "SELECT code_hash FROM oidc_auth_requests \
         WHERE user_id = $1 AND done = true ORDER BY created_at DESC LIMIT 1",
    )
    .bind(USER)
    .fetch_one(&pool)
    .await
    .expect("authorization code digest");
    assert_eq!(stored_code_hash, hash_oauth_token(&code));
    assert_ne!(stored_code_hash, code, "raw authorization code persisted");

    // 2. exchange the code (public client + PKCE) -> tokens.
    let tokens = p
        .exchange_authorization_code(CLIENT, None, &code, REDIRECT, Some(VERIFIER))
        .await
        .unwrap();
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(
        tokens.scope, "openid profile email offline_access codewire.api",
        "replacement desktop credentials must carry the product scope"
    );
    assert!(
        tokens.refresh_token.is_some(),
        "offline_access → refresh token"
    );
    let id_token = tokens.id_token.clone().unwrap();

    // 3. id_token: correct claims + verifiable signature against the JWKS.
    let body = id_token_body(&id_token);
    assert_eq!(body["iss"], "https://idp.codewire.test");
    assert_eq!(body["sub"], USER);
    assert_eq!(body["aud"], serde_json::json!([CLIENT]));
    assert!(body.get("org_id").is_none());
    assert!(body.get("org_role").is_none());
    assert!(body.get("org_slug").is_none());
    assert!(verify_against_jwks(&id_token, &published_jwks));

    // 4. userinfo via the access token -> profile/email claims present.
    let claims = serde_json::to_value(p.userinfo(&tokens.access_token).await.unwrap()).unwrap();
    assert_eq!(claims["sub"], USER);
    assert_eq!(claims["email"], "e2e@example.com");
    assert!(claims.get("org_id").is_none());

    // 5. introspection active -> revoke -> inactive.
    assert!(
        p.introspect(CLIENT, None, &tokens.access_token, None)
            .await
            .unwrap()
            .active
    );
    p.revoke(CLIENT, None, &tokens.access_token, None)
        .await
        .unwrap();
    assert!(
        !p.introspect(CLIENT, None, &tokens.access_token, None)
            .await
            .unwrap()
            .active
    );
    // The revoked access token also fails userinfo.
    assert_eq!(
        p.userinfo(&tokens.access_token).await.unwrap_err().code,
        codewire_oidc::ErrorCode::InvalidToken
    );

    // 6. refresh rotation works against the DB.
    let rt = tokens.refresh_token.unwrap();
    assert!(
        p.introspect(CLIENT, None, &rt, Some("refresh_token"))
            .await
            .unwrap()
            .active,
        "refresh-token introspection must resolve a live grant"
    );
    let refreshed = p
        .exchange_refresh_token(CLIENT, None, &rt, None)
        .await
        .unwrap();
    assert!(refreshed.id_token.is_some());
    assert!(
        p.exchange_refresh_token(CLIENT, None, &rt, None)
            .await
            .is_err(),
        "old RT dead"
    );

    // 7. The iOS public client accepts only its exact custom callback and
    // completes the same PKCE authorization-code flow.
    let ios_params = RawAuthorizeParams {
        client_id: Some(IOS_CLIENT.into()),
        redirect_uri: Some(IOS_REDIRECT.into()),
        response_type: Some("code".into()),
        scope: Some("openid profile email offline_access codewire.api".into()),
        state: Some("ios-state".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    };
    let ios_url = match p.authorize(&ctx, ios_params).await.unwrap() {
        AuthorizeOutcome::Redirect(url) => url,
        other => panic!("expected iOS redirect, got {other:?}"),
    };
    assert!(ios_url.starts_with(IOS_REDIRECT), "got {ios_url}");
    let ios_code = ios_url
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let ios_tokens = p
        .exchange_authorization_code(IOS_CLIENT, None, &ios_code, IOS_REDIRECT, Some(VERIFIER))
        .await
        .expect("iOS public PKCE exchange");
    assert!(
        ios_tokens.refresh_token.is_some(),
        "offline_access → refresh token"
    );

    // 8. Account disablement invalidates every capability already issued to
    // the subject. Keep one code unredeemed and mint a separate access/refresh
    // pair while the account is enabled, then disable it between issuance and
    // use. This exercises the database fences rather than a cache or route
    // policy alone.
    let disabled_code_url = match p
        .authorize(
            &ctx,
            RawAuthorizeParams {
                client_id: Some(CLIENT.into()),
                redirect_uri: Some(REDIRECT.into()),
                response_type: Some("code".into()),
                scope: Some("openid profile email offline_access codewire.api".into()),
                state: Some("disabled-code".into()),
                code_challenge: Some(CHALLENGE.into()),
                code_challenge_method: Some("S256".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(url) => url,
        other => panic!("expected disabled-code redirect, got {other:?}"),
    };
    let disabled_code = disabled_code_url
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let issued_tokens_url = match p
        .authorize(
            &ctx,
            RawAuthorizeParams {
                client_id: Some(CLIENT.into()),
                redirect_uri: Some(REDIRECT.into()),
                response_type: Some("code".into()),
                scope: Some("openid profile email offline_access codewire.api".into()),
                state: Some("disabled-tokens".into()),
                code_challenge: Some(CHALLENGE.into()),
                code_challenge_method: Some("S256".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(url) => url,
        other => panic!("expected disabled-token redirect, got {other:?}"),
    };
    let issued_tokens_code = issued_tokens_url
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let issued_tokens = p
        .exchange_authorization_code(CLIENT, None, issued_tokens_code, REDIRECT, Some(VERIFIER))
        .await
        .expect("enabled account mints final access/refresh pair");
    let issued_access = issued_tokens.access_token;
    let issued_refresh = issued_tokens
        .refresh_token
        .expect("offline_access mints a refresh token");

    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(USER)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        p.exchange_authorization_code(CLIENT, None, &disabled_code, REDIRECT, Some(VERIFIER))
            .await
            .is_err(),
        "disabled account redeemed an authorization code"
    );
    let revoked_code: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_auth_requests WHERE code_hash=$1")
            .bind(hash_oauth_token(&disabled_code))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(revoked_code, 0, "disabling retained an authorization code");
    assert_eq!(
        p.userinfo(&issued_access).await.unwrap_err().code,
        ErrorCode::InvalidToken,
        "disabled account retained access-token UserInfo authority"
    );
    assert!(
        !p.introspect(CLIENT, None, &issued_access, None)
            .await
            .unwrap()
            .active,
        "disabled account retained an active access token"
    );
    assert!(
        !p.introspect(CLIENT, None, &issued_refresh, Some("refresh_token"))
            .await
            .unwrap()
            .active,
        "disabled account retained an active refresh token"
    );
    assert!(
        p.exchange_refresh_token(CLIENT, None, &issued_refresh, None)
            .await
            .is_err(),
        "disabled account redeemed a refresh token"
    );
    let revoked_refresh: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_refresh_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&issued_refresh))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        revoked_refresh, 0,
        "disabling retained a refresh capability"
    );
    assert!(
        matches!(
            p.authorize(
                &ctx,
                RawAuthorizeParams {
                    client_id: Some(CLIENT.into()),
                    redirect_uri: Some(REDIRECT.into()),
                    response_type: Some("code".into()),
                    scope: Some("openid profile email".into()),
                    state: Some("disabled-session".into()),
                    code_challenge: Some(CHALLENGE.into()),
                    code_challenge_method: Some("S256".into()),
                    ..Default::default()
                },
            )
            .await,
            Ok(AuthorizeOutcome::RedirectToLogin(_))
        ),
        "disabled account retained browser-session authorization"
    );
    sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(USER)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        p.exchange_authorization_code(CLIENT, None, &disabled_code, REDIRECT, Some(VERIFIER))
            .await
            .is_err(),
        "re-enabling revived an authorization code"
    );
    assert_eq!(
        p.userinfo(&issued_access).await.unwrap_err().code,
        ErrorCode::InvalidToken,
        "re-enabling revived access-token UserInfo authority"
    );
    assert!(
        p.exchange_refresh_token(CLIENT, None, &issued_refresh, None)
            .await
            .is_err(),
        "re-enabling revived a refresh token"
    );
    assert!(
        !p.introspect(CLIENT, None, &issued_refresh, Some("refresh_token"))
            .await
            .unwrap()
            .active,
        "re-enabling revived refresh-token introspection"
    );

    // Best-effort cleanup (CI's DB is ephemeral, but keep reruns clean).
    for sql in [
        "DELETE FROM oidc_access_tokens WHERE user_id = $1",
        "DELETE FROM oidc_refresh_tokens WHERE user_id = $1",
        "DELETE FROM oidc_auth_requests WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
    ] {
        let _ = sqlx::query(sql).bind(USER).execute(&pool).await;
    }
    let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(CLIENT)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(IOS_CLIENT)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(USER)
        .execute(&pool)
        .await;
}

/// WI-1/WI-1a contract gate (connect-rpc/15-auth-policy.md):
/// flavor-2 user bearers are opaque OIDC access tokens validated by direct
/// lookup against `oidc_access_tokens` (joined to `users` and
/// `oidc_clients`). A product-scoped token authenticates while a valid
/// identity-only token remains UserInfo-capable but receives `403` from REST
/// and Connect, including for an admin subject. Expired / revoked /
/// disabled-client tokens receive `401`. Tokens are hashed at rest, and
/// presenting the bearer never creates or slides a `sessions` row (fixed idp
/// expiry, no session mirroring). Browser session tokens remain cookie-only:
/// presenting one as an Authorization bearer must never be reinterpreted as a
/// product credential.
#[tokio::test]
async fn oidc_access_token_authenticates_product_api_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp bearer-auth e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let user = "u_bearer_wi1";
    let client = "codewire-bearer-wi1";
    let redirect = "http://localhost:9877/callback";
    let session_id = "s_bearer_wi1";
    let session_token = "sess_tok_bearer_wi1";

    let cleanup = |p: PgPool| async move {
        for sql in [
            "DELETE FROM oidc_access_tokens WHERE user_id = $1",
            "DELETE FROM oidc_refresh_tokens WHERE user_id = $1",
            "DELETE FROM oidc_auth_requests WHERE user_id = $1",
            "DELETE FROM sessions WHERE user_id = $1",
        ] {
            let _ = sqlx::query(sql).bind(user).execute(&p).await;
        }
        let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
            .bind(client)
            .execute(&p)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&p)
            .await;
    };
    cleanup(pool.clone()).await;

    sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin) VALUES ($1,$2,$3,true,false)")
        .bind(user).bind("bearer-wi1@example.com").bind("Bearer WI1").execute(&pool).await.unwrap();
    sqlx::query(
        r#"INSERT INTO oidc_clients
            (id, name, application_type, auth_method, redirect_uris,
             grant_types, response_types, scopes, skip_consent,
             access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
           VALUES ($1,'Bearer WI1','native','none',ARRAY[$2],
             ARRAY['authorization_code','refresh_token'],ARRAY['code'],
             ARRAY['openid','profile','email','offline_access','codewire.api'],true,
             interval '1 hour', interval '720 hours', interval '1 hour')"#,
    )
    .bind(client)
    .bind(redirect)
    .execute(&pool)
    .await
    .unwrap();
    // A live web session for the authorize bridge (flavor 1 stays intact
    // throughout — the bearer path below must never touch it).
    sqlx::query("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3, NOW() + interval '1 hour')")
        .bind(session_id).bind(user).bind(hash_session_token(session_token)).execute(&pool).await.unwrap();

    // 1. PKCE authorization-code flow mints an opaque access token.
    let cfg = IdpConfig {
        issuer: "https://idp.codewire.test".into(),
        frontend_url: "https://app.codewire.test".into(),
        turnstile_secret_key: String::new(),
        turnstile_bypass_email: String::new(),
        signup_invite_policy: codewire_idp::auth_session::SignupInvitePolicy::open(),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "codewire.api".into(),
        ],
    };
    let p = build_provider(
        pool.clone(),
        &cfg,
        test_signing_keyring(),
        TEST_CAPABILITY_HMAC_SECRET,
    )
    .await
    .unwrap();
    let ctx = RequestContext {
        cookie: Some(format!("codewire.session_token={session_token}")),
    };
    let params = RawAuthorizeParams {
        client_id: Some(client.into()),
        redirect_uri: Some(redirect.into()),
        response_type: Some("code".into()),
        scope: Some("openid profile email offline_access codewire.api".into()),
        state: Some("st".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    };
    let redirect_url = match p.authorize(&ctx, params).await.unwrap() {
        AuthorizeOutcome::Redirect(u) => u,
        other => panic!("expected redirect, got {other:?}"),
    };
    let code = redirect_url
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let tokens = p
        .exchange_authorization_code(client, None, &code, redirect, Some(VERIFIER))
        .await
        .unwrap();
    let access = tokens.access_token.clone();
    let refresh = tokens.refresh_token.clone().expect("offline_access → RT");

    // Mint a separate identity-only token for the same subject/client. It
    // remains valid for OIDC UserInfo but must never inherit product or admin
    // authority from the subject.
    let identity_params = RawAuthorizeParams {
        client_id: Some(client.into()),
        redirect_uri: Some(redirect.into()),
        response_type: Some("code".into()),
        scope: Some("openid profile email".into()),
        state: Some("identity-st".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    };
    let identity_redirect = match p.authorize(&ctx, identity_params).await.unwrap() {
        AuthorizeOutcome::Redirect(u) => u,
        other => panic!("expected identity redirect, got {other:?}"),
    };
    let identity_code = identity_redirect
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let identity_tokens = p
        .exchange_authorization_code(client, None, identity_code, redirect, Some(VERIFIER))
        .await
        .unwrap();
    let identity_access = identity_tokens.access_token;
    let identity_claims = p.userinfo(&identity_access).await.unwrap();
    assert_eq!(identity_claims.sub, user);

    // 2. Hashed at rest: durable rows carry the SHA-256 digest, never the
    // raw opaque token.
    let by_digest: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_access_tokens WHERE token_hash = $1")
            .bind(hash_oauth_token(&access))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(by_digest, 1, "access token stored by digest");
    let by_plaintext: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_access_tokens WHERE token_hash = $1")
            .bind(&access)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(by_plaintext, 0, "raw access token must not persist");
    let refresh_by_digest: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_refresh_tokens WHERE token_hash = $1")
            .bind(hash_oauth_token(&refresh))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(refresh_by_digest, 1, "refresh token stored by digest");

    // 3. No session mirroring: minting created no sessions row for the
    // access token.
    let mirrored: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash = $1")
        .bind(hash_session_token(&access))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        mirrored, 0,
        "access tokens must not be mirrored into sessions"
    );

    // 4. A product-API router behind require_auth accepts the bearer.
    let app = axum::Router::new()
        .route(
            "/whoami",
            axum::routing::get(|user: AuthUser, credential: CredentialContext| async move {
                let (client_id, scopes) = match credential {
                    CredentialContext::OidcAccessToken { client_id, scopes } => {
                        (Some(client_id), scopes)
                    }
                    _ => (None, Vec::new()),
                };
                axum::Json(serde_json::json!({
                    "user_id": user.user_id,
                    "via_api_key": user.via_api_key,
                    "is_admin": user.is_admin,
                    "oidc_client_id": client_id,
                    "oidc_scopes": scopes,
                }))
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            AuthState { pool: pool.clone() },
            require_auth,
        ));

    let (st, body, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 200, "PKCE-issued access token authenticates: {body}");
    assert_eq!(body["user_id"], user);
    assert_eq!(body["via_api_key"], false);
    assert_eq!(body["is_admin"], false);
    assert_eq!(body["oidc_client_id"], client);
    assert_eq!(
        body["oidc_scopes"],
        serde_json::json!([
            "openid",
            "profile",
            "email",
            "offline_access",
            "codewire.api"
        ])
    );

    let (st, body, _) = sess_req_bearer(&app, "GET", "/whoami", &identity_access, "").await;
    assert_eq!(
        st, 403,
        "identity-only access token must not authorize a product route"
    );
    assert_eq!(body["code"], "insufficient_scope");
    assert_eq!(
        body["hint"],
        "Request the codewire.api scope and re-authorize"
    );
    sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let (st, _body, _) = sess_req_bearer(&app, "GET", "/whoami", &identity_access, "").await;
    assert_eq!(
        st, 403,
        "admin subject must not turn identity scope into product authority"
    );
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();

    // 5. Fixed expiry, no sliding window: presenting the bearer leaves
    // `sessions` untouched (same row count, same expiry, same updated_at).
    let before: (chrono::NaiveDateTime, Option<chrono::NaiveDateTime>) =
        sqlx::query_as("SELECT expires_at, updated_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (st, _b, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 200);
    let after: (chrono::NaiveDateTime, Option<chrono::NaiveDateTime>) =
        sqlx::query_as("SELECT expires_at, updated_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "access-token auth must not slide session expiry"
    );
    let session_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(session_rows, 1, "bearer auth must not mint session rows");

    // 6. Expired token → 401.
    sqlx::query(
        "UPDATE oidc_access_tokens SET expires_at = NOW() - interval '1 minute' WHERE token_hash = $1",
    )
    .bind(hash_oauth_token(&access))
    .execute(&pool)
    .await
    .unwrap();
    let (st, _b, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 401, "expired access token must fail");
    sqlx::query(
        "UPDATE oidc_access_tokens SET expires_at = NOW() + interval '1 hour' WHERE token_hash = $1",
    )
    .bind(hash_oauth_token(&access))
    .execute(&pool)
    .await
    .unwrap();

    // 7. Disabled client → 401; re-enabled → authenticates again.
    sqlx::query("UPDATE oidc_clients SET disabled = true WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await
        .unwrap();
    let (st, _b, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 401, "disabled client's token must fail");
    sqlx::query("UPDATE oidc_clients SET disabled = false WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await
        .unwrap();
    let (st, _b, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 200);

    // 7b. The Connect auth layer (doc 03 WI-2) accepts the same
    // provider-minted access token: `ConnectAuthLayer` wraps the identical
    // `authenticate()` stack, so a flavor-2 bearer authenticates Connect
    // mounts too and the handler sees the same AuthUser extension.
    let connect_app = codewire_server_core::connect::ConnectAuthLayer::authenticated(AuthState {
        pool: pool.clone(),
    })
    .apply(axum::Router::new().route(
        "/codewire.testing.v1.PingService/Ping",
        axum::routing::post(|user: codewire_server_core::auth::AuthUser| async move {
            axum::Json(user)
        }),
    ));
    let (st, body, _) = sess_req_bearer(
        &connect_app,
        "POST",
        "/codewire.testing.v1.PingService/Ping",
        &access,
        "{}",
    )
    .await;
    assert_eq!(st, 200, "Connect auth layer accepts minted bearer: {body}");
    assert_eq!(body["user_id"], user);
    let (st, body, _) = sess_req_bearer(
        &connect_app,
        "POST",
        "/codewire.testing.v1.PingService/Ping",
        &identity_access,
        "{}",
    )
    .await;
    assert_eq!(st, 403, "Connect rejects identity-only bearer");
    assert_eq!(body["code"], "permission_denied");
    let (st, body, _) = sess_req_bearer(
        &connect_app,
        "POST",
        "/codewire.testing.v1.PingService/Ping",
        "not-a-real-token",
        "{}",
    )
    .await;
    assert_eq!(st, 401, "Connect auth layer rejects a bogus bearer");
    assert_eq!(body["code"], "unauthenticated", "Connect-shaped rejection");

    // 8. Revoked (row deleted) → 401.
    p.revoke(client, None, &access, None).await.unwrap();
    let (st, _b, _) = sess_req_bearer(&app, "GET", "/whoami", &access, "").await;
    assert_eq!(st, 401, "revoked access token must fail");

    // 9. A browser session token is not a product bearer. It must reject here
    // without being reinterpreted as the live session created above.
    let (st, body, _) = sess_req_bearer(&app, "GET", "/whoami", session_token, "").await;
    assert_eq!(st, 401, "raw session-token bearer must reject: {body}");
    assert_ne!(body["user_id"], user);

    cleanup(pool.clone()).await;
}

/// A clean provider must publish a usable signing key before it has issued a
/// token. This uses the real, freshly migrated application schema rather than
/// relying on a prior token-flow test to populate `jwks`.
#[tokio::test]
async fn provider_startup_publishes_jwks_before_token_issuance() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping initial JWKS readiness test");
        return;
    };
    let admin = PgPool::connect(&url).await.expect("connect admin");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_name = format!("cw_idp_jwks_ready_{}_{nanos}", std::process::id());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .expect("create JWKS readiness database");

    let mut test_url = url::Url::parse(&url).expect("parse DATABASE_URL");
    test_url.set_path(&db_name);
    let result = async {
        codewire_server_core::migrate::ensure_schema(test_url.as_str()).await?;
        let pool = PgPool::connect(test_url.as_str()).await?;
        let cfg = IdpConfig {
            issuer: "https://idp.codewire.test".into(),
            frontend_url: "https://app.codewire.test".into(),
            turnstile_secret_key: String::new(),
            turnstile_bypass_email: String::new(),
            signup_invite_policy: codewire_idp::auth_session::SignupInvitePolicy::open(),
            scopes_supported: vec!["openid".into()],
        };

        let provider = build_provider(
            pool.clone(),
            &cfg,
            test_signing_keyring(),
            TEST_CAPABILITY_HMAC_SECRET,
        )
        .await?;
        let jwks = provider.jwks().await?;
        anyhow::ensure!(jwks.keys.len() == 1, "expected one initial public key");
        let key = &jwks.keys[0];
        anyhow::ensure!(key.kty == "OKP");
        anyhow::ensure!(key.crv == "Ed25519");
        anyhow::ensure!(key.alg == "EdDSA");
        anyhow::ensure!(key.use_ == "sig");
        anyhow::ensure!(!key.kid.is_empty() && !key.x.is_empty());

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM jwks")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 1, "provider startup did not persist one signer");
        pool.close().await;
        anyhow::Ok(())
    }
    .await;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    result.expect("initial JWKS readiness");
}

/// Regression: concurrent providers starting against an empty registry must
/// create exactly one encrypted signer and every replica must adopt it. The
/// active-signer transaction lock, not a timestamp-shaped `kid`, supplies the
/// single-winner guarantee. This runs in its own throwaway database (only the
/// `jwks` table is needed) so it cannot disturb sibling tests.
#[tokio::test]
async fn first_signing_key_creation_survives_concurrent_providers() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping jwks first-key race test");
        return;
    };
    let admin = PgPool::connect(&url).await.expect("connect admin");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // pid keeps concurrent test processes from colliding on the same
    // clock tick (same class as the migrate TestDatabase name race).
    let db_name = format!("cw_idp_jwks_race_{}_{nanos}", std::process::id());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .expect("create race db");

    let mut race_url = url::Url::parse(&url).expect("parse DATABASE_URL");
    race_url.set_path(&db_name);
    let result = async {
        let pool = PgPool::connect(race_url.as_str()).await?;
        sqlx::query(
            "CREATE TABLE jwks (
                id text PRIMARY KEY,
                public_key text NOT NULL,
                private_key_ciphertext bytea,
                private_key_nonce bytea,
                private_key_kek_id text,
                private_key_format smallint,
                created_at timestamp without time zone NOT NULL,
                expires_at timestamp without time zone,
                CONSTRAINT jwks_private_key_envelope_shape_check CHECK (
                    num_nonnulls(private_key_ciphertext, private_key_nonce,
                        private_key_kek_id, private_key_format) = ANY (ARRAY[0, 4])
                )
            )",
        )
        .execute(&pool)
        .await?;

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let store = codewire_idp::keys::PgKeyStore::new(pool.clone(), test_signing_keyring());
            tasks.spawn(async move { store.active_signer().await });
        }
        let mut signers = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let signer = joined
                .expect("signer task panicked")
                .map_err(|e| anyhow::anyhow!("active_signer failed under race: {}", e.0))?;
            signers.push(signer);
        }
        anyhow::ensure!(signers.len() == 8);

        // Every replica must adopt the exact persisted winner and be able to
        // decrypt/use it. The prior test's 1-2-row allowance was weaker than
        // the rolling-replica contract.
        let rows: Vec<PersistedNewKeyRow> = sqlx::query_as(
            "SELECT id, public_key, private_key_ciphertext, \
                        private_key_nonce, private_key_kek_id, private_key_format FROM jwks",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            rows.len() == 1,
            "expected one persisted winner, got {}",
            rows.len()
        );
        anyhow::ensure!(rows[0].2.len() == 48);
        anyhow::ensure!(rows[0].3.len() == 12);
        anyhow::ensure!(rows[0].4 == "v1");
        anyhow::ensure!(rows[0].5 == 1);
        let winner = &signers[0];
        for signer in &signers {
            anyhow::ensure!(signer.kid == winner.kid);
            anyhow::ensure!(signer.public_key == winner.public_key);
            anyhow::ensure!(signer.secret_key == winner.secret_key);
        }

        use ed25519_dalek::{Signer, Verifier};
        let secret: [u8; 32] = winner.secret_key.as_slice().try_into()?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = signing.sign(b"first-key envelope winner");
        signing
            .verifying_key()
            .verify(b"first-key envelope winner", &signature)?;

        let reread = codewire_idp::keys::PgKeyStore::new(pool.clone(), test_signing_keyring())
            .active_signer()
            .await
            .map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(reread.kid == winner.kid);
        anyhow::ensure!(reread.public_key == winner.public_key);
        anyhow::ensure!(reread.secret_key == winner.secret_key);
        pool.close().await;
        anyhow::Ok(())
    }
    .await;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    result.expect("jwks first-key race");
}

/// The operator rewrap is an all-or-nothing, value-blind transform over the
/// accepted final schema. It preserves the Ed25519 identity, leaves public
/// history alone, is idempotent, rejects an invalid ledger/catalog, rolls back
/// on every invalid envelope shape, and excludes concurrent JWK writers.
#[tokio::test]
async fn signing_kek_rewrap_is_atomic_idempotent_and_writer_exclusive() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping signing KEK rewrap DB test");
        return;
    };
    let admin = PgPool::connect(&url).await.expect("connect admin");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_name = format!("cw_idp_kek_rewrap_{}_{nanos}", std::process::id());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .expect("create rewrap db");

    let mut test_url = url::Url::parse(&url).expect("parse DATABASE_URL");
    test_url.set_path(&db_name);
    let result = async {
        codewire_server_core::migrate::ensure_schema(test_url.as_str()).await?;
        let pool = PgPool::connect(test_url.as_str()).await?;
        let (v1_keyring, v2_keyring) = rotation_test_keyrings("transactional");

        let v1_seed = [31u8; 32];
        let v1_signing = ed25519_dalek::SigningKey::from_bytes(&v1_seed);
        let v1_public = v1_signing.verifying_key().to_bytes();
        let v1_public_json =
            codewire_idp::jwk::encode_public_key("codewire-rewrap-v1", &v1_public)?;
        let v1_envelope = v1_keyring.encrypt("codewire-rewrap-v1", &v1_public, &v1_seed)?;

        let v2_seed = [32u8; 32];
        let v2_signing = ed25519_dalek::SigningKey::from_bytes(&v2_seed);
        let v2_public = v2_signing.verifying_key().to_bytes();
        let v2_public_json =
            codewire_idp::jwk::encode_public_key("codewire-rewrap-v2", &v2_public)?;
        let v2_envelope = v2_keyring.encrypt("codewire-rewrap-v2", &v2_public, &v2_seed)?;

        let public_seed = [33u8; 32];
        let public_signing = ed25519_dalek::SigningKey::from_bytes(&public_seed);
        let public_json = codewire_idp::jwk::encode_public_key(
            "codewire-rewrap-public",
            &public_signing.verifying_key().to_bytes(),
        )?;

        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES \
                ('codewire-rewrap-v1', $1, $2, $3, $4, $5, \
                 NOW() - interval '3 seconds'), \
                ('codewire-rewrap-v2', $6, $7, $8, $9, $10, \
                 NOW() - interval '2 seconds'), \
                ('codewire-rewrap-public', $11, NULL, NULL, NULL, NULL, \
                 NOW() - interval '1 second')",
        )
        .bind(&v1_public_json)
        .bind(&v1_envelope.ciphertext)
        .bind(&v1_envelope.nonce)
        .bind(&v1_envelope.kek_id)
        .bind(v1_envelope.format)
        .bind(&v2_public_json)
        .bind(&v2_envelope.ciphertext)
        .bind(&v2_envelope.nonce)
        .bind(&v2_envelope.kek_id)
        .bind(v2_envelope.format)
        .bind(&public_json)
        .execute(&pool)
        .await?;

        use ed25519_dalek::{Signer, Verifier};
        let message = b"stable signing identity across KEK rewrap";
        let signature_before = v1_signing.sign(message);

        let store = codewire_idp::PgKeyStore::new(pool.clone(), v2_keyring.clone());
        let first = store
            .rewrap_signing_envelopes()
            .await
            .map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(
            first
                == codewire_idp::SigningKekRewrapReport {
                    active_kek_id: "v2".into(),
                    total: 3,
                    signing: 2,
                    rewrapped: 1,
                    already_active: 1,
                    public_only: 1,
                }
        );

        let after_first: (String, Vec<u8>, Vec<u8>, String, i16) = sqlx::query_as(
            "SELECT public_key, private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format \
             FROM jwks WHERE id = 'codewire-rewrap-v1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(after_first.0 == v1_public_json);
        anyhow::ensure!(after_first.1 != v1_envelope.ciphertext);
        anyhow::ensure!(after_first.2 != v1_envelope.nonce);
        anyhow::ensure!(after_first.3 == "v2" && after_first.4 == 1);
        let rewritten = codewire_idp::jwk_envelope::JwkEnvelope {
            ciphertext: after_first.1.clone(),
            nonce: after_first.2.clone(),
            kek_id: after_first.3.clone(),
            format: after_first.4,
        };
        let recovered = v2_keyring.decrypt("codewire-rewrap-v1", &v1_public, &rewritten)?;
        anyhow::ensure!(recovered == v1_seed);
        let recovered_signing = ed25519_dalek::SigningKey::from_bytes(&recovered);
        let signature_after = recovered_signing.sign(message);
        anyhow::ensure!(signature_after == signature_before);
        recovered_signing
            .verifying_key()
            .verify(message, &signature_before)?;

        let public_only: PersistedEnvelopeFields = sqlx::query_as(
            "SELECT private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format \
             FROM jwks WHERE id = 'codewire-rewrap-public'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(public_only == (None, None, None, None));

        let second = store
            .rewrap_signing_envelopes()
            .await
            .map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(second.rewrapped == 0 && second.already_active == 2);
        let after_second: (Vec<u8>, Vec<u8>, String, i16) = sqlx::query_as(
            "SELECT private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format \
             FROM jwks WHERE id = 'codewire-rewrap-v1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            after_second == (after_first.1.clone(), after_first.2.clone(), "v2".into(), 1,)
        );

        // Operator mode never repairs or applies missing history. Keep a local
        // copy of the value-blind ledger only for this throwaway database.
        sqlx::query("CREATE TABLE wi9a_migration_backup AS SELECT * FROM _sqlx_migrations")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM _sqlx_migrations")
            .execute(&pool)
            .await?;
        let error = store
            .rewrap_signing_envelopes()
            .await
            .expect_err("missing migration history must fail closed");
        anyhow::ensure!(error.0.contains("failure_class=migration-ledger-invalid"));
        sqlx::query("INSERT INTO _sqlx_migrations SELECT * FROM wi9a_migration_backup")
            .execute(&pool)
            .await?;
        sqlx::query("DROP TABLE wi9a_migration_backup")
            .execute(&pool)
            .await?;

        // Reset one row to v1 so each later failure has an update to roll
        // back before it reaches the intentionally invalid final row.
        sqlx::query(
            "UPDATE jwks SET private_key_ciphertext = $1, private_key_nonce = $2, \
                    private_key_kek_id = $3, private_key_format = $4 \
             WHERE id = 'codewire-rewrap-v1'",
        )
        .bind(&v1_envelope.ciphertext)
        .bind(&v1_envelope.nonce)
        .bind(&v1_envelope.kek_id)
        .bind(v1_envelope.format)
        .execute(&pool)
        .await?;

        let invalid_public =
            codewire_idp::jwk::encode_public_key("codewire-rewrap-invalid", &v1_public)?;
        let invalid_envelope =
            v1_keyring.encrypt("codewire-rewrap-invalid", &v1_public, &v1_seed)?;
        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES ('codewire-rewrap-invalid', $1, $2, $3, 'v1', 1, NOW())",
        )
        .bind(&invalid_public)
        .bind(&invalid_envelope.ciphertext)
        .bind(vec![0u8; 11])
        .execute(&pool)
        .await?;
        let error = store
            .rewrap_signing_envelopes()
            .await
            .expect_err("corrupt envelope must roll back the transaction");
        anyhow::ensure!(error.0.contains("failure_class=envelope-invalid"));
        let rolled_back: (Vec<u8>, Vec<u8>, String, i16) = sqlx::query_as(
            "SELECT private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format \
             FROM jwks WHERE id = 'codewire-rewrap-v1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            rolled_back
                == (
                    v1_envelope.ciphertext.clone(),
                    v1_envelope.nonce.clone(),
                    "v1".into(),
                    1,
                )
        );
        sqlx::query("DELETE FROM jwks WHERE id = 'codewire-rewrap-invalid'")
            .execute(&pool)
            .await?;

        let unknown_public =
            codewire_idp::jwk::encode_public_key("codewire-rewrap-unknown", &v1_public)?;
        let unknown_envelope =
            v1_keyring.encrypt("codewire-rewrap-unknown", &v1_public, &v1_seed)?;
        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES ('codewire-rewrap-unknown', $1, $2, $3, 'v3', 1, NOW())",
        )
        .bind(&unknown_public)
        .bind(&unknown_envelope.ciphertext)
        .bind(&unknown_envelope.nonce)
        .execute(&pool)
        .await?;
        let error = store
            .rewrap_signing_envelopes()
            .await
            .expect_err("unknown KEK must roll back the transaction");
        anyhow::ensure!(error.0.contains("failure_class=envelope-invalid"));
        let still_v1: String = sqlx::query_scalar(
            "SELECT private_key_kek_id FROM jwks WHERE id = 'codewire-rewrap-v1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(still_v1 == "v1");
        sqlx::query("DELETE FROM jwks WHERE id = 'codewire-rewrap-unknown'")
            .execute(&pool)
            .await?;

        sqlx::query("ALTER TABLE jwks DROP CONSTRAINT jwks_private_key_envelope_shape_check")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, created_at) \
             VALUES ('codewire-rewrap-partial', $1, $2, NOW())",
        )
        .bind(&invalid_public)
        .bind(&invalid_envelope.ciphertext)
        .execute(&pool)
        .await?;
        let error = store
            .rewrap_signing_envelopes()
            .await
            .expect_err("partial envelope catalog must fail closed");
        anyhow::ensure!(error.0.contains("failure_class=final-jwk-schema-required"));
        let still_v1: String = sqlx::query_scalar(
            "SELECT private_key_kek_id FROM jwks WHERE id = 'codewire-rewrap-v1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(still_v1 == "v1");
        sqlx::query("DELETE FROM jwks WHERE id = 'codewire-rewrap-partial'")
            .execute(&pool)
            .await?;
        sqlx::query(
            "ALTER TABLE jwks ADD CONSTRAINT jwks_private_key_envelope_shape_check \
             CHECK (num_nonnulls(private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format) = ANY (ARRAY[0, 4]))",
        )
        .execute(&pool)
        .await?;

        // Hold the operator inside its update after the table lock is granted,
        // then prove a second session cannot insert until that transaction
        // completes.
        sqlx::query(
            "CREATE FUNCTION wi9a_pause_rewrap() RETURNS trigger \
             LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TRIGGER wi9a_pause_rewrap_trigger BEFORE UPDATE ON jwks \
             FOR EACH ROW WHEN (OLD.id = 'codewire-rewrap-v1') \
             EXECUTE FUNCTION wi9a_pause_rewrap()",
        )
        .execute(&pool)
        .await?;
        let concurrent_store = store.clone();
        let rewrap = tokio::spawn(async move { concurrent_store.rewrap_signing_envelopes().await });

        let mut lock_seen = false;
        for _ in 0..200 {
            lock_seen = sqlx::query_scalar(
                "SELECT EXISTS ( \
                    SELECT 1 FROM pg_locks AS lock_row \
                    JOIN pg_class AS table_row ON table_row.oid = lock_row.relation \
                    WHERE table_row.relname = 'jwks' \
                      AND lock_row.mode = 'ShareRowExclusiveLock' \
                      AND lock_row.granted \
                )",
            )
            .fetch_one(&pool)
            .await?;
            if lock_seen {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        anyhow::ensure!(lock_seen, "rewrap transaction lock was not observed");

        let mut concurrent = pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '100ms'")
            .execute(&mut *concurrent)
            .await?;
        let blocked = sqlx::query(
            "INSERT INTO jwks (id, public_key, created_at) \
             VALUES ('codewire-rewrap-concurrent', $1, NOW())",
        )
        .bind(&public_json)
        .execute(&mut *concurrent)
        .await
        .expect_err("concurrent JWK writer must block behind rewrap");
        let code = blocked
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        anyhow::ensure!(code.as_deref() == Some("57014"));
        concurrent.rollback().await?;

        let concurrent_report = rewrap.await?.map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(concurrent_report.rewrapped == 1);
        let concurrent_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM jwks WHERE id = 'codewire-rewrap-concurrent'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(concurrent_rows == 0);
        sqlx::query("DROP TRIGGER wi9a_pause_rewrap_trigger ON jwks")
            .execute(&pool)
            .await?;
        sqlx::query("DROP FUNCTION wi9a_pause_rewrap()")
            .execute(&pool)
            .await?;

        pool.close().await;
        anyhow::Ok(())
    }
    .await;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    result.expect("transactional signing KEK rewrap");
}

/// The clean baseline contains only authenticated signing envelopes and
/// public-only history. Partial rows are rejected by the catalog and corrupt
/// envelopes fail closed without being rewritten or replaced.
#[tokio::test]
async fn jwk_final_schema_uses_only_envelopes_and_fails_closed() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping JWK final-schema DB test");
        return;
    };
    let admin = PgPool::connect(&url).await.expect("connect admin");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_name = format!("cw_idp_jwk_final_{}_{nanos}", std::process::id());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .expect("create final-schema database");

    let mut test_url = url::Url::parse(&url).expect("parse DATABASE_URL");
    test_url.set_path(&db_name);
    let result = async {
        codewire_server_core::migrate::ensure_schema(test_url.as_str()).await?;
        let pool = PgPool::connect(test_url.as_str()).await?;

        let raw_columns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'jwks' \
               AND column_name = 'private_key'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(raw_columns == 0);

        let seed = [12u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        let public_json = codewire_idp::jwk::encode_public_key("codewire-final", &public_key)?;
        let keyring = test_signing_keyring();
        let envelope = keyring.encrypt("codewire-final", &public_key, &seed)?;
        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES ('codewire-final', $1, $2, $3, $4, $5, NOW())",
        )
        .bind(&public_json)
        .bind(&envelope.ciphertext)
        .bind(&envelope.nonce)
        .bind(&envelope.kek_id)
        .bind(envelope.format)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO jwks (id, public_key, created_at) \
             VALUES ('codewire-retired', $1, NOW() - interval '1 second')",
        )
        .bind(&public_json)
        .execute(&pool)
        .await?;

        let store = codewire_idp::keys::PgKeyStore::new(pool.clone(), keyring);
        anyhow::ensure!(
            store
                .validate_envelopes()
                .await
                .map_err(|error| anyhow::anyhow!(error.0))?
                == 1
        );
        let active = store
            .active_signer()
            .await
            .map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(active.kid == "codewire-final");
        anyhow::ensure!(active.public_key == public_key && active.secret_key == seed);
        let public = store
            .public_jwks()
            .await
            .map_err(|error| anyhow::anyhow!(error.0))?;
        anyhow::ensure!(public.iter().any(|key| key.kid == "codewire-retired"));

        sqlx::query("DELETE FROM jwks WHERE id = 'codewire-final'")
            .execute(&pool)
            .await?;
        let cfg = IdpConfig {
            issuer: "https://idp.codewire.test".into(),
            frontend_url: "https://app.codewire.test".into(),
            turnstile_secret_key: String::new(),
            turnstile_bypass_email: String::new(),
            signup_invite_policy: codewire_idp::auth_session::SignupInvitePolicy::open(),
            scopes_supported: vec!["openid".into()],
        };
        let error = build_provider(
            pool.clone(),
            &cfg,
            test_signing_keyring(),
            TEST_CAPABILITY_HMAC_SECRET,
        )
        .await
        .expect_err("public-only registry must stop provider startup");
        anyhow::ensure!(
            error
                .to_string()
                .contains("failure_class=no-signing-capable-row")
        );

        let partial = sqlx::query(
            "INSERT INTO jwks (id, public_key, private_key_ciphertext, created_at) \
             VALUES ('codewire-partial', $1, $2, NOW())",
        )
        .bind(&public_json)
        .bind(&envelope.ciphertext)
        .execute(&pool)
        .await;
        anyhow::ensure!(partial.is_err());

        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES ('codewire-corrupt', $1, $2, $3, 'v1', 1, NOW() + interval '1 second')",
        )
        .bind(&public_json)
        .bind(&envelope.ciphertext)
        .bind(vec![0u8; 11])
        .execute(&pool)
        .await?;
        let error = store
            .active_signer()
            .await
            .expect_err("corrupt envelope must fail closed");
        anyhow::ensure!(error.0.contains("failure_class=invalid-nonce-length"));
        let error = build_provider(
            pool.clone(),
            &cfg,
            test_signing_keyring(),
            TEST_CAPABILITY_HMAC_SECRET,
        )
        .await
        .expect_err("unreadable registry must stop provider startup");
        anyhow::ensure!(
            error
                .to_string()
                .contains("failure_class=invalid-nonce-length")
        );
        let unchanged: PersistedEnvelopeFields = sqlx::query_as(
            "SELECT private_key_ciphertext, private_key_nonce, \
                    private_key_kek_id, private_key_format \
             FROM jwks WHERE id = 'codewire-corrupt'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(unchanged.0.as_deref() == Some(envelope.ciphertext.as_slice()));
        anyhow::ensure!(unchanged.1.as_deref() == Some([0u8; 11].as_slice()));
        anyhow::ensure!(unchanged.2.as_deref() == Some("v1") && unchanged.3 == Some(1));

        pool.close().await;
        anyhow::Ok(())
    }
    .await;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    result.expect("JWK final-schema DB contract");
}

/// The public `codewire-cli` registration converges stale state, the
/// session-only browser verification route approves the standard RFC 8628
/// store, and the result is a flavor-2 token pair. The retired bespoke route
/// family remains absent throughout.
#[tokio::test]
async fn standard_cli_device_grant_uses_browser_approval_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping standard CLI device-flow e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let user = format!("u_cli_device_{}", std::process::id());
    let session = format!("sess_cli_device_{}", std::process::id());
    let session_id = format!("s_cli_device_{}", std::process::id());

    for sql in [
        "DELETE FROM oidc_access_tokens WHERE user_id = $1",
        "DELETE FROM oidc_refresh_tokens WHERE user_id = $1",
        "DELETE FROM oidc_device_authorizations WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
    ] {
        let _ = sqlx::query(sql).bind(&user).execute(&pool).await;
    }
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user)
        .execute(&pool)
        .await;

    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, is_admin) \
         VALUES ($1, $2, $3, true, false)",
    )
    .bind(&user)
    .bind(format!("{user}@example.com"))
    .bind("CLI Device")
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(&session_id)
    .bind(&user)
    .bind(hash_session_token(&session))
    .execute(&pool)
    .await
    .unwrap();

    // Start from deliberately wrong built-in client state. Provisioning must
    // converge it instead of relying on a one-time bootstrap side effect.
    sqlx::query(
        r#"
        INSERT INTO oidc_clients
            (id, name, application_type, auth_method, redirect_uris,
             grant_types, response_types, scopes, skip_consent,
             access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
        VALUES (
            'codewire-cli', 'stale CLI', 'web', 'client_secret_basic',
            ARRAY['https://stale.invalid/callback'], ARRAY['authorization_code'],
            ARRAY['code'], ARRAY['openid'], false,
            interval '1 minute', interval '1 minute', interval '1 minute'
        )
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            application_type = EXCLUDED.application_type,
            auth_method = EXCLUDED.auth_method,
            redirect_uris = EXCLUDED.redirect_uris,
            grant_types = EXCLUDED.grant_types,
            response_types = EXCLUDED.response_types,
            scopes = EXCLUDED.scopes,
            skip_consent = EXCLUDED.skip_consent
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    codewire_idp::provisioning::ensure_cli_client(&pool)
        .await
        .expect("provision CLI client");
    let client_row: (String, String, Vec<String>, Vec<String>, bool) = sqlx::query_as(
        "SELECT application_type, auth_method, grant_types, scopes, skip_consent \
         FROM oidc_clients WHERE id = 'codewire-cli'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(client_row.0, "native");
    assert_eq!(client_row.1, "none");
    assert_eq!(
        client_row.2,
        vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "refresh_token".to_string(),
        ]
    );
    assert_eq!(
        client_row.3,
        vec![
            "openid",
            "profile",
            "email",
            "offline_access",
            "codewire.api"
        ]
    );
    assert!(client_row.4);

    let cfg = IdpConfig {
        issuer: "https://idp.codewire.test".into(),
        frontend_url: "https://app.codewire.test".into(),
        turnstile_secret_key: String::new(),
        turnstile_bypass_email: String::new(),
        signup_invite_policy: codewire_idp::auth_session::SignupInvitePolicy::open(),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "codewire.api".into(),
        ],
    };
    let provider = build_provider(
        pool.clone(),
        &cfg,
        test_signing_keyring(),
        TEST_CAPABILITY_HMAC_SECRET,
    )
    .await
    .expect("build provider");
    assert_eq!(
        provider
            .discovery()
            .device_authorization_endpoint
            .as_deref(),
        Some("https://idp.codewire.test/api/oauth/device_authorization")
    );
    let device = provider
        .authorize_device(
            "codewire-cli",
            None,
            Some("openid profile email offline_access codewire.api"),
        )
        .await
        .expect("authorize device");
    assert_eq!(device.verification_uri, "https://app.codewire.test/device");
    let stored_codes: (String, String) = sqlx::query_as(
        "SELECT device_code_hash, user_code_hash \
         FROM oidc_device_authorizations WHERE client_id = 'codewire-cli'",
    )
    .fetch_one(&pool)
    .await
    .expect("stored device authorization digests");
    assert_eq!(stored_codes.0, hash_oauth_token(&device.device_code));
    assert_eq!(
        stored_codes.1,
        test_device_user_code_digest(&device.user_code)
    );
    assert_ne!(stored_codes.1, hash_oauth_token(&device.user_code));
    assert_ne!(stored_codes.0, device.device_code);
    assert_ne!(stored_codes.1, device.user_code);
    assert!(
        provider
            .lookup_user_code(&device.user_code)
            .await
            .expect("lookup device")
            .is_some()
    );

    let app = codewire_idp::device_verification::router(
        provider.clone(),
        AuthState { pool: pool.clone() },
    );
    let approve_body = format!(
        r#"{{"user_code":"{}"}}"#,
        device.user_code.replace('-', "").to_lowercase()
    );

    let (status, _) =
        device_post(&app, "/api/oauth/device_verification", None, &approve_body).await;
    assert_eq!(status, 401, "browser approval requires a session cookie");

    let (status, _) = device_post(
        &app,
        "/api/oauth/device_verification",
        Some(&session),
        r#"{"user_code":"NOPE-0000"}"#,
    )
    .await;
    assert_eq!(status, 404, "unknown user code must fail closed");

    let (status, body) = device_post(
        &app,
        "/api/oauth/device_verification",
        Some(&session),
        &approve_body,
    )
    .await;
    assert_eq!(status, 200, "standard approval: {body}");
    assert_eq!(body["approved"], true);
    let (status, _) = device_post(
        &app,
        "/api/oauth/device_verification",
        Some(&session),
        &approve_body,
    )
    .await;
    assert_eq!(status, 400, "resolved user code must remain single-use");
    for path in [
        "/api/auth/device/authorize",
        "/api/auth/device/token",
        "/api/auth/device/approve",
    ] {
        let (status, _) = device_post(&app, path, None, "{}").await;
        assert_eq!(status, 404, "retired route remains mounted: {path}");
    }

    // Until the CLI redeems a device grant, the account has not signed in
    // with it, and get-session says so.
    let sessions = codewire_idp::auth_session::router(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    );
    let (status, body, _) = sess_req(
        &sessions,
        "GET",
        "/api/auth/get-session",
        Some(&session),
        "",
    )
    .await;
    assert_eq!(status, 200, "get-session before redemption: {body}");
    assert_eq!(body["user"]["cli_signed_in"], false);

    let (first_exchange, second_exchange) = tokio::join!(
        provider.exchange_device_code("codewire-cli", None, &device.device_code),
        provider.exchange_device_code("codewire-cli", None, &device.device_code),
    );
    assert_eq!(
        usize::from(first_exchange.is_ok()) + usize::from(second_exchange.is_ok()),
        1,
        "one concurrent device redemption succeeds; first error: {:?}; second error: {:?}",
        first_exchange.as_ref().err(),
        second_exchange.as_ref().err(),
    );
    let replay = first_exchange
        .as_ref()
        .err()
        .or_else(|| second_exchange.as_ref().err())
        .expect("one concurrent device redemption is rejected");
    assert_eq!(replay.code, ErrorCode::ExpiredToken);
    let tokens = first_exchange
        .ok()
        .or_else(|| second_exchange.ok())
        .expect("exchange device code");
    assert_eq!(tokens.token_type, "Bearer");
    assert!(
        tokens.refresh_token.is_some(),
        "offline_access grants refresh"
    );
    assert_eq!(
        tokens.scope,
        "openid profile email offline_access codewire.api"
    );
    assert_eq!(
        provider
            .userinfo(&tokens.access_token)
            .await
            .expect("userinfo")
            .sub,
        user
    );
    let pending_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oidc_device_authorizations WHERE device_code_hash = $1",
    )
    .bind(hash_oauth_token(&device.device_code))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending_rows, 0, "device code is single-use");
    // The redemption recorded the account's first CLI sign-in.
    let marked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT cli_signed_in_at FROM users WHERE id = $1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(marked.is_some(), "redemption marks the CLI sign-in");
    let (status, body, _) = sess_req(
        &sessions,
        "GET",
        "/api/auth/get-session",
        Some(&session),
        "",
    )
    .await;
    assert_eq!(status, 200, "get-session after redemption: {body}");
    assert_eq!(body["user"]["cli_signed_in"], true);

    // Disabling before browser approval removes the session that proves the
    // user identity, so a pending device grant cannot be approved. The
    // pending row has no owner yet and is cleaned explicitly below.
    let before_approval = provider
        .authorize_device(
            "codewire-cli",
            None,
            Some("openid profile email offline_access codewire.api"),
        )
        .await
        .expect("start pre-disable device grant");
    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    let (status, _) = device_post(
        &app,
        "/api/oauth/device_verification",
        Some(&session),
        &format!(r#"{{"user_code":"{}"}}"#, before_approval.user_code),
    )
    .await;
    assert_eq!(status, 401, "disabled account approved a device grant");
    let before_approval_state: (String, Option<String>) = sqlx::query_as(
        "SELECT status, user_id FROM oidc_device_authorizations WHERE device_code_hash=$1",
    )
    .bind(hash_oauth_token(&before_approval.device_code))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        before_approval_state,
        ("pending".to_string(), None),
        "disabled browser approval bound a user to the device grant"
    );
    sqlx::query("DELETE FROM oidc_device_authorizations WHERE device_code_hash=$1")
        .bind(hash_oauth_token(&before_approval.device_code))
        .execute(&pool)
        .await
        .unwrap();

    // A fresh post-reenable login can approve a new request, but disabling
    // between approval and redemption deletes the bound grant. Re-enabling
    // must not make its original device code redeemable.
    sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    let renewed_session = format!("sess_cli_device_after_reenable_{}", std::process::id());
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(format!(
        "s_cli_device_after_reenable_{}",
        std::process::id()
    ))
    .bind(&user)
    .bind(hash_session_token(&renewed_session))
    .execute(&pool)
    .await
    .unwrap();
    let after_approval = provider
        .authorize_device(
            "codewire-cli",
            None,
            Some("openid profile email offline_access codewire.api"),
        )
        .await
        .expect("start post-reenable device grant");
    let (status, body) = device_post(
        &app,
        "/api/oauth/device_verification",
        Some(&renewed_session),
        &format!(r#"{{"user_code":"{}"}}"#, after_approval.user_code),
    )
    .await;
    assert_eq!(status, 200, "fresh account approved device grant: {body}");
    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        provider
            .exchange_device_code("codewire-cli", None, &after_approval.device_code)
            .await
            .is_err(),
        "disabled account redeemed an approved device grant"
    );
    let after_approval_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oidc_device_authorizations WHERE device_code_hash=$1",
    )
    .bind(hash_oauth_token(&after_approval.device_code))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        after_approval_rows, 0,
        "disabling retained an approved device grant"
    );
    sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        provider
            .exchange_device_code("codewire-cli", None, &after_approval.device_code)
            .await
            .is_err(),
        "re-enabling revived an approved device grant"
    );

    for sql in [
        "DELETE FROM oidc_access_tokens WHERE user_id = $1",
        "DELETE FROM oidc_refresh_tokens WHERE user_id = $1",
        "DELETE FROM oidc_device_authorizations WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
    ] {
        let _ = sqlx::query(sql).bind(&user).execute(&pool).await;
    }
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user)
        .execute(&pool)
        .await;
}

/// Account disablement and browser-side grant completion use the same
/// user-before-capability lock order. These barriers prove both orders for
/// the current device store: approval first is purged by disablement, while
/// disablement first cannot bind a pending grant or deadlock the worker.
/// Device redemption, which also records the first CLI sign-in, takes the
/// same order (`device_redemption_marks_the_first_cli_sign_in_in_both_orders`).
#[tokio::test]
async fn account_access_completion_paths_serialize_in_both_orders_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping account-access completion-path e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let suffix = std::process::id();
    let client_id = format!("account-access-completion-client-{suffix}");

    for statement in [
        "DELETE FROM oidc_device_authorizations WHERE client_id = $1",
        "DELETE FROM oidc_auth_requests WHERE client_id = $1",
        "DELETE FROM oidc_clients WHERE id = $1",
    ] {
        let _ = sqlx::query(statement).bind(&client_id).execute(&pool).await;
    }
    sqlx::query(
        "INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris) \
         VALUES ($1, 'Account access completion', 'native', 'none', ARRAY['https://example.test/callback'])",
    )
    .bind(&client_id)
    .execute(&pool)
    .await
    .expect("create completion-path client");

    for (label, approval_first) in [("approval-first", true), ("disable-first", false)] {
        let user_id = format!("account-access-device-{label}-{suffix}");
        let device_code = format!("account-access-device-code-{label}-{suffix}");
        let user_code = format!("ACCT-{label}-{suffix}");
        let worker_name = format!("codewire-account-device-{label}-{suffix}");
        let _ = sqlx::query("DELETE FROM oidc_device_authorizations WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .expect("create completion-path user");

        let worker_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url_with_application_name(&url, &worker_name))
            .await
            .expect("connect device completion worker");
        let store =
            PgDeviceAuthorizationStore::new(worker_pool.clone(), TEST_CAPABILITY_HMAC_SECRET)
                .expect("create device completion store");
        let pending = DeviceAuthorization {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client_id.clone(),
            scopes: Scopes(vec!["openid".into()]),
            status: DeviceStatus::Pending,
        };
        store
            .store_device(pending.clone(), 3600)
            .await
            .expect("store pending device authorization");
        let approved = DeviceAuthorization {
            status: DeviceStatus::Approved {
                subject: Subject(user_id.clone()),
                auth_time: Some(1),
            },
            ..pending
        };

        if approval_first {
            let mut row_locker = pool.begin().await.expect("begin device row locker");
            let locker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *row_locker)
                .await
                .expect("read device row-lock backend pid");
            sqlx::query(
                "SELECT device_code_hash FROM oidc_device_authorizations \
                 WHERE device_code_hash = $1 FOR UPDATE",
            )
            .bind(hash_oauth_token(&device_code))
            .fetch_one(&mut *row_locker)
            .await
            .expect("lock pending device authorization");

            let update_store = store.clone();
            let update_auth = approved.clone();
            let update_task = tokio::spawn(async move { update_store.update(&update_auth).await });
            let update_pid =
                wait_for_application_lock_blocker(&pool, &worker_name, locker_pid).await;
            let (disable_pid, disable_task) =
                spawn_account_disable(pool.clone(), user_id.clone()).await;
            wait_for_pid_lock_blocker(&pool, disable_pid, update_pid).await;

            row_locker.commit().await.expect("release device row lock");
            let update_result = tokio::time::timeout(HANG, update_task)
                .await
                .expect("device approval deadlocked")
                .expect("device approval task panicked");
            assert!(
                update_result.is_ok(),
                "approval first should complete before disablement purges it: {update_result:?}"
            );
            finish_completion_path_task(
                disable_task,
                "account disablement deadlocked device approval",
            )
            .await;
            let retained: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM oidc_device_authorizations WHERE user_id = $1",
            )
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .expect("read disabled device grants");
            assert_eq!(retained, 0, "disablement retained an approved device grant");
        } else {
            let mut disable = pool.begin().await.expect("begin device disablement");
            let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *disable)
                .await
                .expect("read device-disable backend pid");
            sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(&user_id)
                .fetch_one(&mut *disable)
                .await
                .expect("lock device user before disablement");

            let update_store = store.clone();
            let update_auth = approved.clone();
            let update_task = tokio::spawn(async move { update_store.update(&update_auth).await });
            let _ = wait_for_application_lock_blocker(&pool, &worker_name, disable_pid).await;
            sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                .bind(&user_id)
                .execute(&mut *disable)
                .await
                .expect("disable device user");
            disable.commit().await.expect("commit device disablement");

            let update_result = tokio::time::timeout(HANG, update_task)
                .await
                .expect("device approval did not finish after disablement")
                .expect("device approval task panicked");
            assert!(
                update_result.is_err(),
                "disablement first bound a pending device grant"
            );
            let state: (String, Option<String>) = sqlx::query_as(
                "SELECT status, user_id FROM oidc_device_authorizations WHERE device_code_hash = $1",
            )
            .bind(hash_oauth_token(&device_code))
            .fetch_one(&pool)
            .await
            .expect("read unbound device grant after disablement");
            assert_eq!(state, ("pending".into(), None));
        }

        worker_pool.close().await;
        let _ = sqlx::query("DELETE FROM oidc_device_authorizations WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
    }

    for (label, completion_first) in [("completion-first", true), ("disable-first", false)] {
        let user_id = format!("account-access-authorize-{label}-{suffix}");
        let request_id = format!("account-access-auth-request-{label}-{suffix}");
        let worker_name = format!("codewire-account-authorize-{label}-{suffix}");
        let _ = sqlx::query("DELETE FROM oidc_auth_requests WHERE id = $1")
            .bind(&request_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .expect("create authorization-completion user");
        sqlx::query(
            "INSERT INTO oidc_auth_requests (id, client_id, scopes, redirect_uri, expires_at) \
             VALUES ($1, $2, ARRAY['openid'], 'https://example.test/callback', \
                     NOW() + interval '10 minutes')",
        )
        .bind(&request_id)
        .bind(&client_id)
        .execute(&pool)
        .await
        .expect("create pending authorization request");

        let worker_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url_with_application_name(&url, &worker_name))
            .await
            .expect("connect authorization completion worker");
        let store = PgAuthorizationStore::new(worker_pool.clone());
        let completed = StoredAuthRequest {
            id: AuthRequestId(request_id.clone()),
            request: AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: "https://example.test/callback".into(),
                response_type: ResponseType::Code,
                scopes: Scopes(vec!["openid".into()]),
                state: None,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                prompt: None,
                max_age: None,
            },
            subject: Some(Subject(user_id.clone())),
        };

        if completion_first {
            let mut row_locker = pool.begin().await.expect("begin authorization row locker");
            let locker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *row_locker)
                .await
                .expect("read authorization row-lock backend pid");
            sqlx::query("SELECT id FROM oidc_auth_requests WHERE id = $1 FOR UPDATE")
                .bind(&request_id)
                .fetch_one(&mut *row_locker)
                .await
                .expect("lock pending authorization request");

            let update_store = store.clone();
            let update_request = completed.clone();
            let update_task =
                tokio::spawn(async move { update_store.update(&update_request).await });
            let update_pid =
                wait_for_application_lock_blocker(&pool, &worker_name, locker_pid).await;
            let (disable_pid, disable_task) =
                spawn_account_disable(pool.clone(), user_id.clone()).await;
            wait_for_pid_lock_blocker(&pool, disable_pid, update_pid).await;

            row_locker
                .commit()
                .await
                .expect("release authorization row lock");
            let update_result = tokio::time::timeout(HANG, update_task)
                .await
                .expect("authorization completion deadlocked")
                .expect("authorization completion task panicked");
            assert!(
                update_result.is_ok(),
                "completion first should finish before disablement purges it: {update_result:?}"
            );
            finish_completion_path_task(
                disable_task,
                "account disablement deadlocked authorization completion",
            )
            .await;
            let retained: i64 =
                sqlx::query_scalar("SELECT count(*) FROM oidc_auth_requests WHERE user_id = $1")
                    .bind(&user_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read disabled authorization requests");
            assert_eq!(retained, 0, "disablement retained an authorization request");
        } else {
            let mut disable = pool.begin().await.expect("begin authorization disablement");
            let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *disable)
                .await
                .expect("read authorization-disable backend pid");
            sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(&user_id)
                .fetch_one(&mut *disable)
                .await
                .expect("lock authorization user before disablement");

            let update_store = store.clone();
            let update_request = completed.clone();
            let update_task =
                tokio::spawn(async move { update_store.update(&update_request).await });
            let _ = wait_for_application_lock_blocker(&pool, &worker_name, disable_pid).await;
            sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                .bind(&user_id)
                .execute(&mut *disable)
                .await
                .expect("disable authorization user");
            disable
                .commit()
                .await
                .expect("commit authorization disablement");

            let update_result = tokio::time::timeout(HANG, update_task)
                .await
                .expect("authorization completion did not finish after disablement")
                .expect("authorization completion task panicked");
            assert!(
                update_result.is_err(),
                "disablement first bound a pending authorization request"
            );
            let subject: Option<String> =
                sqlx::query_scalar("SELECT user_id FROM oidc_auth_requests WHERE id = $1")
                    .bind(&request_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read unbound authorization request after disablement");
            assert!(
                subject.is_none(),
                "disablement first bound an authorization request"
            );
        }

        worker_pool.close().await;
        let _ = sqlx::query("DELETE FROM oidc_auth_requests WHERE id = $1")
            .bind(&request_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
    }

    for (label, validation_first) in [("validation-first", true), ("disable-first", false)] {
        let user_id = format!("account-access-two-factor-{label}-{suffix}");
        let token_id = format!("account-access-two-factor-token-id-{label}-{suffix}");
        let token = format!("account-access-two-factor-token-{label}-{suffix}");
        let worker_name = format!("codewire-account-two-factor-{label}-{suffix}");
        let _ = sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        sqlx::query("INSERT INTO users (id, email, two_factor_enabled) VALUES ($1, $2, true)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .expect("create two-factor completion user");
        // An intentionally invalid encrypted value drives the normal
        // failed-attempt path after the one-use challenge is claimed, without
        // using a real TOTP credential in this lock-order proof.
        sqlx::query(
            "INSERT INTO two_factor (id, user_id, secret, backup_codes) \
             VALUES ($1, $2, 'not-an-encrypted-totp-secret', NULL)",
        )
        .bind(format!("account-access-two-factor-config-{label}-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .expect("create two-factor completion configuration");
        insert_two_factor_token(&pool, &token_id, &user_id, &token).await;

        let worker_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url_with_application_name(&url, &worker_name))
            .await
            .expect("connect two-factor completion worker");
        let app = codewire_idp::two_factor::router(
            worker_pool.clone(),
            "account-access-completion-session-secret".into(),
            false,
            AuthState {
                pool: worker_pool.clone(),
            },
        );
        let body = format!(r#"{{"code":"000000","token":"{token}"}}"#);

        if validation_first {
            let mut row_locker = pool.begin().await.expect("begin two-factor row locker");
            let locker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *row_locker)
                .await
                .expect("read two-factor row-lock backend pid");
            sqlx::query("SELECT id FROM two_factor_tokens WHERE id = $1 FOR UPDATE")
                .bind(&token_id)
                .fetch_one(&mut *row_locker)
                .await
                .expect("lock two-factor challenge");

            let validate_app = app.clone();
            let validate_body = body.clone();
            let validate_task = tokio::spawn(async move {
                sess_req(
                    &validate_app,
                    "POST",
                    "/api/auth/two-factor/validate",
                    None,
                    &validate_body,
                )
                .await
            });
            let validate_pid =
                wait_for_application_lock_blocker(&pool, &worker_name, locker_pid).await;
            let (disable_pid, disable_task) =
                spawn_account_disable(pool.clone(), user_id.clone()).await;
            wait_for_pid_lock_blocker(&pool, disable_pid, validate_pid).await;

            row_locker
                .commit()
                .await
                .expect("release two-factor row lock");
            let (status, _, cookie) = tokio::time::timeout(HANG, validate_task)
                .await
                .expect("two-factor validation deadlocked")
                .expect("two-factor validation task panicked");
            assert_eq!(status, 401, "invalid synthetic TOTP should fail normally");
            assert!(
                cookie.is_none(),
                "failed two-factor validation minted a session"
            );
            finish_completion_path_task(
                disable_task,
                "account disablement deadlocked two-factor validation",
            )
            .await;
        } else {
            let mut disable = pool.begin().await.expect("begin two-factor disablement");
            let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *disable)
                .await
                .expect("read two-factor-disable backend pid");
            sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(&user_id)
                .fetch_one(&mut *disable)
                .await
                .expect("lock two-factor user before disablement");

            let validate_app = app.clone();
            let validate_body = body.clone();
            let validate_task = tokio::spawn(async move {
                sess_req(
                    &validate_app,
                    "POST",
                    "/api/auth/two-factor/validate",
                    None,
                    &validate_body,
                )
                .await
            });
            let _ = wait_for_application_lock_blocker(&pool, &worker_name, disable_pid).await;
            sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                .bind(&user_id)
                .execute(&mut *disable)
                .await
                .expect("disable two-factor user");
            disable
                .commit()
                .await
                .expect("commit two-factor disablement");

            let (status, _, cookie) = tokio::time::timeout(HANG, validate_task)
                .await
                .expect("two-factor validation did not finish after disablement")
                .expect("two-factor validation task panicked");
            assert_ne!(
                status, 200,
                "disablement first completed a two-factor login"
            );
            assert!(
                cookie.is_none(),
                "disabled two-factor validation minted a session"
            );
        }

        let challenges: i64 =
            sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE user_id = $1")
                .bind(&user_id)
                .fetch_one(&pool)
                .await
                .expect("read disabled two-factor challenges");
        assert_eq!(challenges, 0, "disablement retained a two-factor challenge");
        worker_pool.close().await;
        let _ = sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
    }

    let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(&client_id)
        .execute(&pool)
        .await;

    device_redemption_marks_the_first_cli_sign_in_in_both_orders(&pool, &url, suffix).await;
}

/// Redeeming an approved device grant records the account's first CLI sign-in
/// in the same statement (the dashboard's Get started checklist), once: a
/// later redemption keeps the first time. Writing the account takes its lock,
/// so redemption locks the account before the grant, in the order account
/// disablement takes them. These barriers prove both orders: redemption first
/// finishes and then disablement proceeds; disablement first leaves nothing
/// redeemed and nothing marked. Neither deadlocks.
async fn device_redemption_marks_the_first_cli_sign_in_in_both_orders(
    pool: &PgPool,
    url: &str,
    suffix: u32,
) {
    let pool = pool.clone();
    let client_id = format!("device-redemption-marker-client-{suffix}");
    for statement in [
        "DELETE FROM oidc_device_authorizations WHERE client_id = $1",
        "DELETE FROM oidc_clients WHERE id = $1",
    ] {
        let _ = sqlx::query(statement).bind(&client_id).execute(&pool).await;
    }
    sqlx::query(
        "INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris, grant_types) \
         VALUES ($1, 'Device redemption marker', 'native', 'none', ARRAY[]::text[], \
                 ARRAY['urn:ietf:params:oauth:grant-type:device_code'])",
    )
    .bind(&client_id)
    .execute(&pool)
    .await
    .expect("create redemption client");
    let marked_at = |user_id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>(
                "SELECT extract(epoch FROM cli_signed_in_at)::bigint FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("read CLI sign-in marker")
        }
    };

    for label in ["already-marked", "redemption-first", "disable-first"] {
        let user_id = format!("device-redemption-{label}-{suffix}");
        let device_code = format!("device-redemption-code-{label}-{suffix}");
        let worker_name = format!("codewire-device-redemption-{label}-{suffix}");
        let _ = sqlx::query("DELETE FROM oidc_device_authorizations WHERE user_id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .expect("create redemption user");
        if label == "already-marked" {
            sqlx::query("UPDATE users SET cli_signed_in_at = to_timestamp(1) WHERE id = $1")
                .bind(&user_id)
                .execute(&pool)
                .await
                .expect("mark an earlier CLI sign-in");
        }

        let worker_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url_with_application_name(url, &worker_name))
            .await
            .expect("connect redemption worker");
        let store =
            PgDeviceAuthorizationStore::new(worker_pool.clone(), TEST_CAPABILITY_HMAC_SECRET)
                .expect("create redemption store");
        let pending = DeviceAuthorization {
            device_code: device_code.clone(),
            user_code: format!("REDEEM-{label}-{suffix}"),
            client_id: client_id.clone(),
            scopes: Scopes(vec!["openid".into()]),
            status: DeviceStatus::Pending,
        };
        store
            .store_device(pending.clone(), 3600)
            .await
            .expect("store pending device authorization");
        store
            .update(&DeviceAuthorization {
                status: DeviceStatus::Approved {
                    subject: Subject(user_id.clone()),
                    auth_time: Some(1),
                },
                ..pending
            })
            .await
            .expect("approve device authorization");

        match label {
            "already-marked" => {
                let redeemed = store
                    .consume_approved(&device_code)
                    .await
                    .expect("redeem device authorization");
                assert!(redeemed.is_some(), "an approved grant is redeemed");
                assert_eq!(
                    marked_at(user_id.clone()).await,
                    Some(1),
                    "a later redemption keeps the first CLI sign-in"
                );
            }
            "redemption-first" => {
                // Hold the grant's row so redemption stops after taking the
                // account; disablement then waits for redemption.
                let mut row_locker = pool.begin().await.expect("begin grant row locker");
                let locker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *row_locker)
                    .await
                    .expect("read grant row-lock backend pid");
                sqlx::query(
                    "SELECT device_code_hash FROM oidc_device_authorizations \
                     WHERE device_code_hash = $1 FOR UPDATE",
                )
                .bind(hash_oauth_token(&device_code))
                .fetch_one(&mut *row_locker)
                .await
                .expect("lock approved device authorization");
                let redeem_store = store.clone();
                let redeem_code = device_code.clone();
                let redeem =
                    tokio::spawn(async move { redeem_store.consume_approved(&redeem_code).await });
                let redeem_pid =
                    wait_for_application_lock_blocker(&pool, &worker_name, locker_pid).await;
                let (disable_pid, disable_task) =
                    spawn_account_disable(pool.clone(), user_id.clone()).await;
                wait_for_pid_lock_blocker(&pool, disable_pid, redeem_pid).await;
                row_locker.commit().await.expect("release grant row lock");
                let redeemed = tokio::time::timeout(HANG, redeem)
                    .await
                    .expect("device redemption deadlocked")
                    .expect("device redemption task panicked")
                    .expect("redeem device authorization");
                assert!(
                    redeemed.is_some(),
                    "redemption first completes before disablement"
                );
                finish_completion_path_task(
                    disable_task,
                    "account disablement deadlocked device redemption",
                )
                .await;
                assert!(
                    marked_at(user_id.clone()).await.is_some(),
                    "redemption marks the CLI sign-in"
                );
            }
            _ => {
                let mut disable = pool.begin().await.expect("begin disablement");
                let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *disable)
                    .await
                    .expect("read disablement backend pid");
                sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                    .bind(&user_id)
                    .fetch_one(&mut *disable)
                    .await
                    .expect("lock the account before disablement");
                let redeem_store = store.clone();
                let redeem_code = device_code.clone();
                let redeem =
                    tokio::spawn(async move { redeem_store.consume_approved(&redeem_code).await });
                let _ = wait_for_application_lock_blocker(&pool, &worker_name, disable_pid).await;
                sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
                    .bind(&user_id)
                    .execute(&mut *disable)
                    .await
                    .expect("disable the account");
                disable.commit().await.expect("commit disablement");
                let redeemed = tokio::time::timeout(HANG, redeem)
                    .await
                    .expect("device redemption did not finish after disablement")
                    .expect("device redemption task panicked")
                    .expect("redemption after disablement answers");
                assert!(
                    redeemed.is_none(),
                    "a disabled account redeemed a device grant"
                );
                assert_eq!(
                    marked_at(user_id.clone()).await,
                    None,
                    "nothing redeemed, nothing marked"
                );
            }
        }
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oidc_device_authorizations WHERE user_id = $1",
        )
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .expect("read remaining device grants");
        assert_eq!(remaining, 0, "{label}: the grant is gone");

        worker_pool.close().await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(&client_id)
        .execute(&pool)
        .await;
}

async fn device_post(
    app: &axum::Router,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (u16, serde_json::Value) {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("codewire.session_token={c}"));
    }
    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// End-to-end session-core credential flow against Postgres: sign-up →
/// get-session(cookie) → conflict → sign-in → bad-password(401) → lockout
/// after 5 fails(429) → sign-out → get-session(null). Mirrors
/// `auth_routes.go`'s signUp/signIn/signOut/getSession contract, including
/// the Argon2id round-trip and the failed-attempt lockout.
#[tokio::test]
async fn session_auth_flow_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp session-auth e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let email = "sess-flow@example.com";
    let pw = "Sup3rStrong!Pass";
    let invite_code = "synthetic-db-flow-invite";
    let cleanup = |p: PgPool| async move {
        sqlx::query("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email=$1)")
            .bind(email)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM accounts WHERE account_id=$1")
            .bind(email)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM verifications WHERE identifier=$1 OR identifier IN (SELECT id FROM users WHERE email=$1)")
            .bind(email)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE email=$1")
            .bind(email)
            .execute(&p)
            .await
            .ok();
    };
    cleanup(pool.clone()).await;

    let invite_hash = format!("{:x}", Sha256::digest(invite_code.as_bytes()));
    let invite_policy =
        codewire_idp::auth_session::SignupInvitePolicy::from_sha256_hashes(Some(&invite_hash))
            .unwrap();
    let app = codewire_idp::auth_session::router(pool.clone(), false, invite_policy);

    // 1. A wrong configured invite enters review and fails closed when review
    // email delivery is unavailable, before any user is inserted.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-up",
        None,
        &format!(
            r#"{{"email":"{email}","password":"{pw}","name":"Sess Flow","invite_code":"synthetic-wrong-invite","reason":"Evaluate session persistence"}}"#
        ),
    )
    .await;
    assert_eq!(st, 503, "review request without email delivery: {body}");
    let inserted: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email=$1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        inserted, 0,
        "undeliverable review request must not create an account"
    );

    // 2. A configured valid invite signs up and returns a session.
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-up",
        None,
        &format!(
            r#"{{"email":"{email}","password":"{pw}","name":"Sess Flow","invite_code":"{invite_code}"}}"#
        ),
    )
    .await;
    assert_eq!(st, 200, "signup: {body}");
    assert_eq!(body["user"]["email"], email);
    assert!(body["session"].get("token").is_none());
    assert!(
        cookie
            .as_deref()
            .unwrap()
            .starts_with("codewire.session_token=")
    );
    assert!(cookie.as_deref().unwrap().contains("HttpOnly"));
    let token = session_token_from_set_cookie(cookie.as_deref().unwrap());
    let created: String =
        sqlx::query_scalar("SELECT token_hash FROM sessions WHERE token_hash = $1")
            .bind(hash_session_token(&token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(created, hash_session_token(&token));

    // 3. get-session with the cookie → AuthResponse.
    let (st, body, _) = sess_req(&app, "GET", "/api/auth/get-session", Some(&token), "").await;
    assert_eq!(st, 200);
    assert_eq!(body["user"]["email"], email);
    assert!(body["session"].get("token").is_none());

    // 4. duplicate sign-up → 409.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-up",
        None,
        &format!(
            r#"{{"email":"{email}","password":"{pw}","name":"x","invite_code":"{invite_code}"}}"#
        ),
    )
    .await;
    assert_eq!(st, 409, "duplicate signup: {body}");

    // 5. sign-in (correct) → 200 + cookie. (Proves Argon2id verify of the
    //    stored hash.)
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-in",
        None,
        &format!(r#"{{"email":"{email}","password":"{pw}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "signin: {body}");
    assert!(cookie.is_some());
    assert_eq!(body["user"]["email"], email);
    assert!(body["session"].get("token").is_none());

    // 6. sign-in (wrong) → 401, then four more wrong → lockout (429).
    let bad = format!(r#"{{"email":"{email}","password":"nope"}}"#);
    let (st, _b, _) = sess_req(&app, "POST", "/api/auth/sign-in", None, &bad).await;
    assert_eq!(st, 401);
    for _ in 0..4 {
        sess_req(&app, "POST", "/api/auth/sign-in", None, &bad).await;
    }
    let (st, _b, _) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-in",
        None,
        &format!(r#"{{"email":"{email}","password":"{pw}"}}"#),
    )
    .await;
    assert_eq!(st, 429, "should be locked after 5 failures");

    // unlock so the sign-out path is reachable.
    sqlx::query("UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE email=$1")
        .bind(email)
        .execute(&pool)
        .await
        .unwrap();

    // 7. Disabling an account invalidates its existing session without
    // refreshing it, and prevents a correct password from minting another.
    sqlx::query("UPDATE users SET enabled=false WHERE email=$1")
        .bind(email)
        .execute(&pool)
        .await
        .unwrap();
    let (st, body, _) = sess_req(&app, "GET", "/api/auth/get-session", Some(&token), "").await;
    assert_eq!(st, 200);
    assert!(
        body.is_null(),
        "disabled account retained a browser session"
    );
    let sign_in = format!(r#"{{"email":"{email}","password":"{pw}"}}"#);
    // It never verified its email, so sign-in says that, and only after the
    // password matched, with a single-use token that asks for a new link.
    sqlx::query("DELETE FROM verifications WHERE identifier=$1")
        .bind(email)
        .execute(&pool)
        .await
        .unwrap();
    let unverified_sign_in = || async {
        let (st, body, cookie) = sess_req(&app, "POST", "/api/auth/sign-in", None, &sign_in).await;
        assert_eq!(st, 403, "disabled account signed in: {body}");
        assert_eq!(body["code"], "email_unverified");
        assert!(
            cookie.is_none(),
            "disabled account received a session cookie"
        );
        let token = body["resendToken"].as_str().unwrap().to_owned();
        assert_eq!(token.len(), 64);
        token
    };
    let resend_token = unverified_sign_in().await;

    let mail = codewire_idp::email_password::router(
        pool.clone(),
        "https://app.codewire.test".to_string(),
        codewire_email::EmailClient::disabled(),
        AuthState { pool: pool.clone() },
    );
    let resend = |token: String| {
        let mail = mail.clone();
        async move {
            let (st, body, _) = sess_req(
                &mail,
                "POST",
                "/api/auth/resend-verification",
                None,
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
            (st, body)
        }
    };
    let links = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM verifications WHERE identifier=$1 AND purpose='email_verification'",
        )
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    // The token sends one new link, once.
    assert_eq!(
        resend(resend_token.clone()).await,
        (202, serde_json::json!({ "sent": true }))
    );
    assert_eq!(links().await, 1);
    let (st, _) = resend(resend_token).await;
    assert_eq!(st, 400, "a resend token is single-use");
    // A second sign-in's token within five minutes counts the link just sent.
    assert_eq!(
        resend(unverified_sign_in().await).await,
        (202, serde_json::json!({ "sent": true }))
    );
    assert_eq!(links().await, 1);
    let (st, _) = resend("0".repeat(64)).await;
    assert_eq!(st, 400);
    // A new sign-in replaces the account's unused token instead of adding one.
    let replaced = unverified_sign_in().await;
    let latest = unverified_sign_in().await;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM verifications WHERE purpose='resend_verification' AND identifier=(SELECT id FROM users WHERE email=$1)",
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 1);
    assert_eq!(resend(replaced).await.0, 400);
    assert_eq!(resend(latest).await.0, 202);
    let resent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action='user.verification.resent' AND user_id=(SELECT id FROM users WHERE email=$1)",
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(resent, 1);

    // Once verified, a disabled account gets the plain refusal, with no token.
    sqlx::query("UPDATE users SET email_verified=true WHERE email=$1")
        .bind(email)
        .execute(&pool)
        .await
        .unwrap();
    let (st, body, cookie) = sess_req(&app, "POST", "/api/auth/sign-in", None, &sign_in).await;
    assert_eq!(st, 403, "disabled account signed in: {body}");
    assert_eq!(body["code"], "account_disabled");
    assert!(body.get("resendToken").is_none());
    assert!(cookie.is_none());
    sqlx::query("UPDATE users SET enabled=true WHERE email=$1")
        .bind(email)
        .execute(&pool)
        .await
        .unwrap();

    // 8. sign-out → {success:true} + clear-cookie (Max-Age=0).
    let (st, body, clear) = sess_req(&app, "POST", "/api/auth/sign-out", Some(&token), "").await;
    assert_eq!(st, 200);
    assert_eq!(body["success"], true);
    assert!(clear.unwrap().contains("Max-Age=0"));

    // 9. get-session after sign-out → null (session deleted).
    let (st, body, _) = sess_req(&app, "GET", "/api/auth/get-session", Some(&token), "").await;
    assert_eq!(st, 200);
    assert!(body.is_null());

    cleanup(pool.clone()).await;
}

#[tokio::test]
async fn get_session_accepts_codewire_api_key_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp api-key get-session e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let user_id = "u_idp_api_key_session";
    let org_id = "org_idp_api_key_session";
    let member_id = "m_idp_api_key_session";
    let key_id = "ak_idp_api_key_session";
    let email = "api-key-session@example.com";
    let raw_key = generate_api_key();

    let cleanup = |p: PgPool| async move {
        sqlx::query("DELETE FROM api_keys WHERE id=$1 OR user_id=$2")
            .bind(key_id)
            .bind(user_id)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM org_members WHERE id=$1 OR user_id=$2 OR org_id=$3")
            .bind(member_id)
            .bind(user_id)
            .bind(org_id)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org_id)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE id=$1 OR email=$2")
            .bind(user_id)
            .bind(email)
            .execute(&p)
            .await
            .ok();
    };
    cleanup(pool.clone()).await;

    sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin) VALUES ($1,$2,$3,true,false)")
        .bind(user_id)
        .bind(email)
        .bind("API Key Session")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1,$2,$3,$4)")
        .bind(org_id)
        .bind("API Key Session Org")
        .bind("api-key-session-org")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1,$2,$3,'owner')")
        .bind(member_id)
        .bind(org_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix, scopes) VALUES ($1,$2,$3,$4,$5,$6,ARRAY[]::text[])")
        .bind(key_id)
        .bind(user_id)
        .bind(org_id)
        .bind("db-flow")
        .bind(hash_api_key(&raw_key))
        .bind(api_key_prefix(&raw_key))
        .execute(&pool)
        .await
        .unwrap();

    let app = codewire_idp::auth_session::router(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    );
    let (st, body, _) = sess_req_bearer(&app, "GET", "/api/auth/get-session", &raw_key, "").await;
    assert_eq!(st, 200, "api-key get-session: {body}");
    assert_eq!(body["user"]["email"], email);
    assert_eq!(body["session"]["id"], "");
    assert!(body["session"].get("token").is_none());
    // An API key is not a CLI sign-in.
    assert_eq!(body["user"]["cli_signed_in"], false);

    // Usage is recorded best-effort and detached (#1851): each request's
    // touch gives up after 250 ms, so on a loaded host one can be dropped.
    // Repeating the same API-key get-session schedules another; a key whose
    // usage is never recorded still fails within the deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let last_used: Option<chrono::NaiveDateTime> = loop {
        let last_used: Option<chrono::NaiveDateTime> =
            sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id=$1")
                .bind(key_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        if last_used.is_some() || std::time::Instant::now() >= deadline {
            break last_used;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (st, body, _) =
            sess_req_bearer(&app, "GET", "/api/auth/get-session", &raw_key, "").await;
        assert_eq!(st, 200, "repeated api-key get-session: {body}");
    };
    assert!(
        last_used.is_some(),
        "api-key get-session should bump last_used_at"
    );

    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let (st, body, _) = sess_req_bearer(&app, "GET", "/api/auth/get-session", &raw_key, "").await;
    assert_eq!(st, 200);
    assert!(body.is_null(), "disabled account retained API-key access");

    sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    // This is the state transition the normal key-management endpoint uses
    // for `disabled=false`. Account disablement has already retired the key by
    // expiring it, so clearing the administrative flag cannot revive its raw
    // bearer value.
    sqlx::query("UPDATE api_keys SET disabled_at=NULL WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let retired: bool = sqlx::query_scalar(
        "SELECT expires_at IS NOT NULL AND expires_at <= NOW() FROM api_keys WHERE id=$1",
    )
    .bind(key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        retired,
        "account disablement did not retire the API key expiry"
    );
    let (st, body, _) = sess_req_bearer(&app, "GET", "/api/auth/get-session", &raw_key, "").await;
    assert_eq!(st, 200);
    assert!(
        body.is_null(),
        "re-enabling and reactivating revived an API key"
    );

    cleanup(pool).await;
}

/// End-to-end email verification and password-reset flow against Postgres:
/// send-verification-email → verify-email → already-verified no-op →
/// forget-password non-enumerating response → reset invalid/expired/weak
/// branches → reset success, with the replacement hash proven by sign-in.
#[tokio::test]
async fn email_password_flow_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp email/password e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let user = "u_email_password_e2e";
    let email = "email-password-e2e@example.com";
    let session = "sess_email_password_e2e_token";
    let new_pw = "N3wStrong!Password";

    let cleanup = |p: PgPool| async move {
        sqlx::query("DELETE FROM verifications WHERE identifier IN ($1, $2)")
            .bind(email)
            .bind("missing-email-password-e2e@example.com")
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM accounts WHERE user_id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
    };
    cleanup(pool.clone()).await;

    sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin, two_factor_enabled) VALUES ($1,$2,$3,false,false,false)")
        .bind(user)
        .bind(email)
        .bind("Email Password E2E")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO accounts (id, user_id, provider_id, account_id, password) VALUES ($1,$2,'credential',$3,$4)")
        .bind("acct_email_password_e2e")
        .bind(user)
        .bind(email)
        .bind("not-a-valid-phc")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW() + interval '1 hour')")
        .bind("s_email_password_e2e")
        .bind(user)
        .bind(hash_session_token(session))
        .execute(&pool)
        .await
        .unwrap();

    let app = codewire_idp::email_password::router(
        pool.clone(),
        "https://app.codewire.test".to_string(),
        codewire_email::EmailClient::disabled(),
        AuthState { pool: pool.clone() },
    );

    // 1. Authenticated send-verification-email creates a 24h token but
    // succeeds without SES delivery configuration.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/send-verification-email",
        Some(session),
        "",
    )
    .await;
    assert_eq!(st, 200, "send verification: {body}");
    assert_eq!(body["sent"], true);
    let (purpose, stored_hash): (String, String) = sqlx::query_as(
        "SELECT purpose, token_hash FROM verifications \
         WHERE identifier=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(purpose, "email_verification");
    assert_eq!(stored_hash.len(), 64);
    assert!(!stored_hash.contains("email-password-e2e"));

    let verify_token = "synthetic-email-verification-capability";
    sqlx::query(
        "INSERT INTO verifications \
         (id, identifier, purpose, token_hash, expires_at) \
         VALUES ($1,$2,'email_verification',$3,NOW() + interval '1 hour')",
    )
    .bind("ver_email_password_known")
    .bind(email)
    .bind(verification_token_hash("email_verification", verify_token))
    .execute(&pool)
    .await
    .unwrap();

    // 2. verify-email flips users.email_verified and consumes the token.
    let (st, body, _) = sess_req(
        &app,
        "GET",
        &format!("/api/auth/verify-email?token={verify_token}"),
        None,
        "",
    )
    .await;
    assert_eq!(st, 200, "verify email: {body}");
    assert_eq!(body["verified"], true);
    let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(verified);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM verifications WHERE token_hash=$1")
            .bind(verification_token_hash("email_verification", verify_token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);

    // 3. Already verified users get the Go omitempty shape:
    // {"already_verified":true}, no new token.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM verifications WHERE identifier=$1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/send-verification-email",
        Some(session),
        "",
    )
    .await;
    assert_eq!(st, 200, "send already verified: {body}");
    assert_eq!(body["already_verified"], true);
    assert!(body.get("sent").is_none());
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM verifications WHERE identifier=$1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, before);

    // 4. forget-password never leaks existence. Missing email returns
    // success without inserting a verification row.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/forget-password",
        None,
        r#"{"email":"missing-email-password-e2e@example.com"}"#,
    )
    .await;
    assert_eq!(st, 200, "forget missing: {body}");
    assert_eq!(body["sent"], true);
    let missing_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM verifications WHERE identifier=$1")
            .bind("missing-email-password-e2e@example.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(missing_rows, 0);

    // 5. Existing email creates a 1h reset token and still returns
    // {sent:true} without SES delivery configuration.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/forget-password",
        None,
        &format!(r#"{{"email":"{email}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "forget existing: {body}");
    assert_eq!(body["sent"], true);
    let (purpose, stored_hash): (String, String) = sqlx::query_as(
        "SELECT purpose, token_hash FROM verifications \
         WHERE identifier=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(purpose, "password_reset");
    assert_eq!(stored_hash.len(), 64);

    let reset_token = "synthetic-password-reset-capability";
    sqlx::query(
        "INSERT INTO verifications \
         (id, identifier, purpose, token_hash, expires_at) \
         VALUES ($1,$2,'password_reset',$3,NOW() + interval '1 hour')",
    )
    .bind("ver_email_password_reset_known")
    .bind(email)
    .bind(verification_token_hash("password_reset", reset_token))
    .execute(&pool)
    .await
    .unwrap();

    // 6. Password validation happens before token consumption.
    let (st, _body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/reset-password",
        None,
        &format!(r#"{{"token":"{reset_token}","newPassword":"weak"}}"#),
    )
    .await;
    assert_eq!(st, 400);
    let still_there: i64 =
        sqlx::query_scalar("SELECT count(*) FROM verifications WHERE token_hash=$1")
            .bind(verification_token_hash("password_reset", reset_token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still_there, 1);

    // 7. Invalid and expired reset tokens return 400; expired tokens are
    // consumed.
    let (st, _body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/reset-password",
        None,
        &format!(r#"{{"token":"missing-reset-token","newPassword":"{new_pw}"}}"#),
    )
    .await;
    assert_eq!(st, 400);

    sqlx::query(
        "INSERT INTO verifications \
         (id, identifier, purpose, token_hash, expires_at) \
         VALUES ($1,$2,'password_reset',$3,NOW() - interval '1 minute')",
    )
    .bind("ver_email_password_expired")
    .bind(email)
    .bind(verification_token_hash(
        "password_reset",
        "expired-reset-token",
    ))
    .execute(&pool)
    .await
    .unwrap();
    let (st, _body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/reset-password",
        None,
        &format!(r#"{{"token":"expired-reset-token","newPassword":"{new_pw}"}}"#),
    )
    .await;
    assert_eq!(st, 400);
    let expired_remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM verifications WHERE token_hash=$1")
            .bind(verification_token_hash(
                "password_reset",
                "expired-reset-token",
            ))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expired_remaining, 0);

    // 8. Purpose binding prevents an email-verification capability from being
    // accepted by the password-reset route, while the intended route can
    // still claim it.
    let cross_purpose_token = "synthetic-cross-purpose-capability";
    sqlx::query(
        "INSERT INTO verifications \
         (id, identifier, purpose, token_hash, expires_at) \
         VALUES ($1,$2,'email_verification',$3,NOW() + interval '1 hour')",
    )
    .bind("ver_email_password_cross_purpose")
    .bind(email)
    .bind(verification_token_hash(
        "email_verification",
        cross_purpose_token,
    ))
    .execute(&pool)
    .await
    .unwrap();
    let (st, _, _) = sess_req(
        &app,
        "POST",
        "/api/auth/reset-password",
        None,
        &format!(r#"{{"token":"{cross_purpose_token}","newPassword":"{new_pw}"}}"#),
    )
    .await;
    assert_eq!(st, 400, "wrong-purpose capability must fail closed");
    let (st, _, _) = sess_req(
        &app,
        "GET",
        &format!("/api/auth/verify-email?token={cross_purpose_token}"),
        None,
        "",
    )
    .await;
    assert_eq!(st, 200, "wrong-purpose attempt must not consume capability");

    // 9. Concurrent successful resets have exactly one claimant. The winner
    // writes a credential hash which Rust sign-in can verify.
    let reset_body = format!(r#"{{"token":"{reset_token}","newPassword":"{new_pw}"}}"#);
    let (first, second) = tokio::join!(
        sess_req(&app, "POST", "/api/auth/reset-password", None, &reset_body),
        sess_req(&app, "POST", "/api/auth/reset-password", None, &reset_body),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [200, 400],
        "one reset claim wins: {first:?} {second:?}"
    );
    let reset_remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM verifications WHERE token_hash=$1")
            .bind(verification_token_hash("password_reset", reset_token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reset_remaining, 0);

    let session_app = codewire_idp::auth_session::router(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    );
    let (st, body, cookie) = sess_req(
        &session_app,
        "POST",
        "/api/auth/sign-in",
        None,
        &format!(r#"{{"email":"{email}","password":"{new_pw}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "signin after reset: {body}");
    assert_eq!(body["user"]["email"], email);
    assert!(cookie.is_some());

    cleanup(pool.clone()).await;
}

/// End-to-end TOTP two-factor auth flow against Postgres: enable →
/// verify → sign-in challenge validation with a TOTP → challenge
/// validation with a backup code → backup code is single-use → disable.
/// This locks in the Go-compatible `two_factor` / `two_factor_tokens`
/// schema and AES-GCM encrypted secret/backup-code storage.
#[tokio::test]
async fn two_factor_flow_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp 2FA e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let user = "u_2fa_e2e";
    let email = "twofactor-e2e@example.com";
    let session = "sess_2fa_e2e_token";
    let session_secret = "two-factor-e2e-session-secret";

    let cleanup = |p: PgPool| async move {
        sqlx::query("DELETE FROM two_factor_tokens WHERE user_id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM two_factor WHERE user_id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&p)
            .await
            .ok();
    };
    cleanup(pool.clone()).await;

    sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin, two_factor_enabled) VALUES ($1,$2,$3,true,false,false)")
        .bind(user)
        .bind(email)
        .bind("2FA E2E")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW() + interval '1 hour')")
        .bind("s_2fa_e2e")
        .bind(user)
        .bind(hash_session_token(session))
        .execute(&pool)
        .await
        .unwrap();

    let app = codewire_idp::two_factor::router(
        pool.clone(),
        session_secret.to_string(),
        false,
        AuthState { pool: pool.clone() },
    );

    // 1. enable → stores encrypted secret/backup codes but does not
    // flip users.two_factor_enabled until verify.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/enable",
        Some(session),
        "",
    )
    .await;
    assert_eq!(st, 200, "enable: {body}");
    let secret = body["secret"].as_str().unwrap().to_string();
    assert_eq!(secret.len(), 32);
    assert_eq!(body["backupCodes"].as_array().unwrap().len(), 10);
    assert!(
        body["totpUri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Codewire:twofactor-e2e%40example.com?")
    );
    let backup_code = body["backupCodes"][0].as_str().unwrap().to_string();
    let retained_backup_code = body["backupCodes"][1].as_str().unwrap().to_string();

    // A pending setup is idempotent. SSR retries and rejected form posts must
    // never rotate the secret out from under the authenticator the user just
    // scanned.
    let first_uri = body["totpUri"].clone();
    let first_codes = body["backupCodes"].clone();
    let (st, repeated, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/enable",
        Some(session),
        "",
    )
    .await;
    assert_eq!(st, 200, "repeat enable: {repeated}");
    assert_eq!(repeated["secret"], secret);
    assert_eq!(repeated["totpUri"], first_uri);
    assert_eq!(repeated["backupCodes"], first_codes);

    let uri = url::Url::parse(repeated["totpUri"].as_str().unwrap()).unwrap();
    let qr_secret = uri
        .query_pairs()
        .find_map(|(key, value)| (key == "secret").then(|| value.into_owned()))
        .expect("QR URI secret");
    assert_eq!(qr_secret, secret, "QR payload and server secret diverged");

    let enabled: bool = sqlx::query_scalar("SELECT two_factor_enabled FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!enabled);

    // 2. verify with a current TOTP → user is 2FA-enabled.
    let code = current_totp_code(&qr_secret, email);
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/verify",
        Some(session),
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "verify: {body}");
    assert_eq!(body["enabled"], true);

    let enabled: bool = sqlx::query_scalar("SELECT two_factor_enabled FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(enabled);

    // 3. validate a sign-in challenge token with TOTP → session cookie +
    // AuthResponse, token consumed.
    insert_two_factor_token(&pool, "tf_2fa_e2e_1", user, "tf-token-e2e-1").await;
    let code = current_totp_code(&secret, email);
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{code}","token":"tf-token-e2e-1"}}"#),
    )
    .await;
    assert_eq!(st, 200, "validate totp: {body}");
    assert_eq!(body["user"]["email"], email);
    assert_eq!(body["user"]["two_factor_enabled"], true);
    assert!(body["session"].get("token").is_none());
    assert!(cookie.unwrap().starts_with("codewire.session_token="));
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE id='tf_2fa_e2e_1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);

    // 4. validate with a backup code → session minted and backup code is
    // consumed, so the same code cannot be used with a fresh challenge.
    insert_two_factor_token(&pool, "tf_2fa_e2e_2", user, "tf-token-e2e-2").await;
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{backup_code}","token":"tf-token-e2e-2"}}"#),
    )
    .await;
    assert_eq!(st, 200, "validate backup: {body}");
    assert_eq!(body["user"]["email"], email);
    assert!(body["session"].get("token").is_none());
    assert!(cookie.is_some());
    let (session_count, digest_count): (i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE token_hash ~ '^[0-9a-f]{64}$') \
           FROM sessions WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(session_count > 0, "2FA completion must mint a session");
    assert_eq!(
        session_count, digest_count,
        "every 2FA session must persist only a valid digest"
    );

    insert_two_factor_token(&pool, "tf_2fa_e2e_3", user, "tf-token-e2e-3").await;
    let (st, _body, _cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{backup_code}","token":"tf-token-e2e-3"}}"#),
    )
    .await;
    assert_eq!(st, 401);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE id='tf_2fa_e2e_3'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining, 0,
        "failed backup-code attempt consumes challenge"
    );

    // 5. Disabling removes both a valid TOTP challenge and an unconsumed
    // backup-code challenge. It also revokes all sessions; re-enabling cannot
    // make either raw challenge usable again.
    insert_two_factor_token(
        &pool,
        "tf_2fa_e2e_disabled_totp",
        user,
        "tf-token-e2e-disabled-totp",
    )
    .await;
    insert_two_factor_token(
        &pool,
        "tf_2fa_e2e_disabled-backup",
        user,
        "tf-token-e2e-disabled-backup",
    )
    .await;
    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let challenge_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE user_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        challenge_count, 0,
        "disabled account retained a 2FA challenge"
    );
    let session_count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(session_count, 0, "disabled account retained a 2FA session");
    for (token, code) in [
        (
            "tf-token-e2e-disabled-totp",
            current_totp_code(&secret, email),
        ),
        ("tf-token-e2e-disabled-backup", retained_backup_code.clone()),
    ] {
        let (st, _body, cookie) = sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &format!(r#"{{"code":"{code}","token":"{token}"}}"#),
        )
        .await;
        assert_eq!(st, 401, "disabled account completed a 2FA challenge");
        assert!(cookie.is_none(), "disabled 2FA completion minted a session");
    }
    sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let (st, _body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(
            r#"{{"code":"{}","token":"tf-token-e2e-disabled-totp"}}"#,
            current_totp_code(&secret, email)
        ),
    )
    .await;
    assert_eq!(st, 401, "re-enabling revived a 2FA challenge");
    assert!(cookie.is_none(), "revived 2FA challenge minted a session");

    // Even a fresh post-reenable session cannot remove the factor; the
    // original challenge/session also remain unusable.
    let renewed_session = "sess_2fa_e2e_after_reenable";
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ('s_2fa_e2e_after_reenable', $1, $2, NOW() + interval '1 hour')",
    )
    .bind(user)
    .bind(hash_session_token(renewed_session))
    .execute(&pool)
    .await
    .unwrap();

    // 6. A session alone must not disable the enrolled factor.
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/disable",
        Some(renewed_session),
        "",
    )
    .await;
    assert_eq!(st, 400, "session-only disable: {body}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM two_factor WHERE user_id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let enabled: bool = sqlx::query_scalar("SELECT two_factor_enabled FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(enabled);

    cleanup(pool.clone()).await;
}

/// Regression for account-level 2FA lockout and atomic challenge claims.
/// Correct passwords may mint fresh challenges, but cannot reset failures;
/// each challenge is single-use even under concurrent validation, and a full
/// password+TOTP success is the only point that resets the account counter.
#[tokio::test]
async fn two_factor_attempts_lock_account_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping idp 2FA lockout e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    let email = "twofactor-lockout-e2e@example.com";
    let password = "Sup3rStrong!Pass";
    let session_secret = "two-factor-lockout-e2e-session-secret";

    let cleanup = |p: PgPool| async move {
        sqlx::query(
            "DELETE FROM two_factor_tokens WHERE user_id IN (SELECT id FROM users WHERE email=$1)",
        )
        .bind(email)
        .execute(&p)
        .await
        .ok();
        sqlx::query(
            "DELETE FROM two_factor WHERE user_id IN (SELECT id FROM users WHERE email=$1)",
        )
        .bind(email)
        .execute(&p)
        .await
        .ok();
        sqlx::query("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email=$1)")
            .bind(email)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM accounts WHERE account_id=$1")
            .bind(email)
            .execute(&p)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE email=$1")
            .bind(email)
            .execute(&p)
            .await
            .ok();
    };
    cleanup(pool.clone()).await;

    let app = codewire_idp::auth_session::router(
        pool.clone(),
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    )
    .merge(codewire_idp::two_factor::router(
        pool.clone(),
        session_secret.to_string(),
        false,
        AuthState { pool: pool.clone() },
    ));

    // Create a real credential account, then enable and verify 2FA through
    // the same HTTP handlers used by the login page.
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/sign-up",
        None,
        &format!(r#"{{"email":"{email}","password":"{password}","name":"2FA Lockout"}}"#),
    )
    .await;
    assert_eq!(st, 200, "sign up: {body}");
    assert!(body["session"].get("token").is_none());
    let session = session_token_from_set_cookie(cookie.as_deref().unwrap());
    let user: String = sqlx::query_scalar("SELECT id FROM users WHERE email=$1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();

    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/enable",
        Some(&session),
        "",
    )
    .await;
    assert_eq!(st, 200, "enable: {body}");
    let secret = body["secret"].as_str().unwrap().to_string();
    let backup_code = body["backupCodes"][0].as_str().unwrap().to_string();
    let code = current_totp_code(&secret, email);
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/verify",
        Some(&session),
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "verify: {body}");

    let sign_in_body = format!(r#"{{"email":"{email}","password":"{password}"}}"#);
    let sign_in = || sess_req(&app, "POST", "/api/auth/sign-in", None, &sign_in_body);

    // Two concurrent validations of one challenge permit exactly one
    // claimant. The loser sees the existing invalid/expired-token 401.
    let (st, body, _) = sign_in().await;
    assert_eq!(st, 200, "sign in for concurrent claim: {body}");
    let token = body["twoFactorToken"].as_str().unwrap().to_string();
    let persisted_token_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM two_factor_tokens WHERE token_hash = $1")
            .bind(hash_session_token(&token))
            .fetch_one(&pool)
            .await
            .expect("persisted two-factor challenge digest");
    assert_ne!(persisted_token_hash, token);
    let code = current_totp_code(&secret, email);
    let validate_body = format!(r#"{{"code":"{code}","token":"{token}"}}"#);
    let (first, second) = tokio::join!(
        sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &validate_body,
        ),
        sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &validate_body,
        ),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [200, 401],
        "one concurrent claimant: {first:?} {second:?}"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE token_hash=$1")
            .bind(hash_session_token(&token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);

    let (st, body, _) = sign_in().await;
    assert_eq!(st, 200, "sign in for empty-code claim: {body}");
    let token = body["twoFactorToken"].as_str().unwrap().to_string();
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"","token":"{token}"}}"#),
    )
    .await;
    assert_eq!(
        st, 400,
        "empty code keeps the required-fields response: {body}"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE token_hash=$1")
            .bind(hash_session_token(&token))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "empty-code attempt consumes challenge");

    // Two distinct challenges using the same backup code serialize on the
    // user + two_factor rows. Exactly one consumes the backup code; the other
    // is a failed second-factor attempt, and both challenges stay consumed.
    insert_two_factor_token(
        &pool,
        "tf_2fa_lockout_backup_a",
        &user,
        "tf-token-2fa-lockout-backup-a",
    )
    .await;
    insert_two_factor_token(
        &pool,
        "tf_2fa_lockout_backup_b",
        &user,
        "tf-token-2fa-lockout-backup-b",
    )
    .await;
    let first_body =
        format!(r#"{{"code":"{backup_code}","token":"tf-token-2fa-lockout-backup-a"}}"#);
    let second_body =
        format!(r#"{{"code":"{backup_code}","token":"tf-token-2fa-lockout-backup-b"}}"#);
    let (first, second) = tokio::join!(
        sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &first_body,
        ),
        sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &second_body,
        ),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [200, 401],
        "backup code has one concurrent winner: {first:?} {second:?}"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE token_hash IN ($1, $2)")
            .bind(hash_session_token("tf-token-2fa-lockout-backup-a"))
            .bind(hash_session_token("tf-token-2fa-lockout-backup-b"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "both backup-code challenges are consumed");
    let failed: i32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(failed, 1, "the losing backup-code validation is counted");

    insert_two_factor_token(
        &pool,
        "tf_2fa_lockout_reset",
        &user,
        "tf-token-2fa-lockout-reset",
    )
    .await;
    let code = current_totp_code(&secret, email);
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{code}","token":"tf-token-2fa-lockout-reset"}}"#),
    )
    .await;
    assert_eq!(st, 200, "TOTP success resets backup-race failure: {body}");
    let failed: i32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(failed, 0);

    // A password failure and a second-factor failure can arrive together.
    // Both paths must atomically contribute to the shared account counter;
    // the password verifier is deliberately slower, which regresses the old
    // stale-read absolute write that could overwrite the 2FA increment.
    insert_two_factor_token(
        &pool,
        "tf_2fa_lockout_mixed",
        &user,
        "tf-token-2fa-lockout-mixed",
    )
    .await;
    let mixed_2fa_body = r#"{"code":"wrong-code","token":"tf-token-2fa-lockout-mixed"}"#;
    let wrong_password_body =
        format!(r#"{{"email":"{email}","password":"definitely-wrong-password"}}"#);
    let (two_factor_failure, password_failure) = tokio::join!(
        sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            mixed_2fa_body,
        ),
        sess_req(
            &app,
            "POST",
            "/api/auth/sign-in",
            None,
            &wrong_password_body,
        ),
    );
    assert_eq!(
        two_factor_failure.0, 401,
        "mixed 2FA failure: {two_factor_failure:?}"
    );
    assert_eq!(
        password_failure.0, 401,
        "mixed password failure: {password_failure:?}"
    );
    let failed: i32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(failed, 2, "mixed concurrent failures must not be lost");

    let (st, body, _) = sign_in().await;
    assert_eq!(st, 200, "sign in after mixed failures: {body}");
    let token = body["twoFactorToken"].as_str().unwrap().to_string();
    let code = current_totp_code(&secret, email);
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{code}","token":"{token}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "TOTP success resets mixed failures: {body}");
    let failed: i32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(failed, 0);

    let mut locked_probe_token = None;
    for attempt in 1..=5 {
        let (st, body, _) = sign_in().await;
        assert_eq!(st, 200, "correct password attempt {attempt}: {body}");
        let token = body["twoFactorToken"].as_str().unwrap().to_string();

        let attempts_before: i32 =
            sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
                .bind(&user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            attempts_before,
            attempt - 1,
            "correct password must not reset prior 2FA failures"
        );

        // Keep a second valid challenge from the pre-lock state. Once the
        // fifth failure locks the account, validation must consume and reject
        // this challenge even when its TOTP is correct.
        if attempt == 5 {
            let (st, body, _) = sign_in().await;
            assert_eq!(st, 200, "mint active-lock probe: {body}");
            locked_probe_token = Some(body["twoFactorToken"].as_str().unwrap().to_string());
        }

        let (st, body, _) = sess_req(
            &app,
            "POST",
            "/api/auth/two-factor/validate",
            None,
            &format!(r#"{{"code":"wrong-code","token":"{token}"}}"#),
        )
        .await;
        let expected = if attempt < 5 { 401 } else { 429 };
        assert_eq!(st, expected, "failed 2FA attempt {attempt}: {body}");

        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE token_hash=$1")
                .bind(hash_session_token(&token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "failed attempt consumes challenge");
        let (failed, locked): (i32, Option<chrono::NaiveDateTime>) =
            sqlx::query_as("SELECT failed_login_attempts, locked_until FROM users WHERE id=$1")
                .bind(&user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(failed, attempt);
        assert_eq!(locked.is_some(), attempt == 5);
    }

    let probe = locked_probe_token.unwrap();
    let code = current_totp_code(&secret, email);
    let (st, body, _) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{code}","token":"{probe}"}}"#),
    )
    .await;
    assert_eq!(st, 429, "active lock rejects valid TOTP: {body}");
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_tokens WHERE token_hash=$1")
            .bind(hash_session_token(&probe))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "active-lock validation consumes challenge");

    let (st, body, _) = sign_in().await;
    assert_eq!(st, 429, "active lock rejects correct password: {body}");

    // Expire the lock without touching the counter. Correct password still
    // leaves five failures in place; the successful second factor resets it.
    sqlx::query("UPDATE users SET locked_until=NOW() - interval '1 second' WHERE id=$1")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    let (st, body, _) = sign_in().await;
    assert_eq!(st, 200, "sign in after lock expiry: {body}");
    let token = body["twoFactorToken"].as_str().unwrap().to_string();
    let failed: i32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        failed, 5,
        "password success still must not reset 2FA failures"
    );

    let code = current_totp_code(&secret, email);
    let (st, body, cookie) = sess_req(
        &app,
        "POST",
        "/api/auth/two-factor/validate",
        None,
        &format!(r#"{{"code":"{code}","token":"{token}"}}"#),
    )
    .await;
    assert_eq!(st, 200, "full 2FA success: {body}");
    assert!(cookie.is_some());
    assert!(body["session"].get("token").is_none());
    let (failed, locked): (i32, Option<chrono::NaiveDateTime>) =
        sqlx::query_as("SELECT failed_login_attempts, locked_until FROM users WHERE id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(failed, 0);
    assert!(locked.is_none());

    cleanup(pool).await;
}

async fn insert_two_factor_token(pool: &PgPool, id: &str, user: &str, token: &str) {
    sqlx::query(
        "INSERT INTO two_factor_tokens (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW() + interval '10 minutes')",
    )
    .bind(id)
    .bind(user)
    .bind(hash_session_token(token))
    .execute(pool)
    .await
    .unwrap();
}

fn verification_token_hash(purpose: &str, token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codewire/idp/verification/v1\0");
    digest.update(purpose.as_bytes());
    digest.update(b"\0");
    digest.update(token.as_bytes());
    format!("{:x}", digest.finalize())
}

fn session_token_from_set_cookie(set_cookie: &str) -> String {
    set_cookie
        .strip_prefix("codewire.session_token=")
        .and_then(|value| value.split(';').next())
        .filter(|value| !value.is_empty())
        .expect("non-empty HttpOnly session cookie")
        .to_owned()
}

fn current_totp_code(secret: &str, account_name: &str) -> String {
    let bytes = Secret::Encoded(secret.to_string()).to_bytes().unwrap();
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("Codewire".to_string()),
        account_name.to_string(),
    )
    .unwrap()
    .generate_current()
    .unwrap()
}

async fn sess_req(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (u16, serde_json::Value, Option<String>) {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("codewire.session_token={c}"));
    }
    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json, set_cookie)
}

async fn sess_req_bearer(
    app: &axum::Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: &str,
) -> (u16, serde_json::Value, Option<String>) {
    use tower::ServiceExt;
    let req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json, set_cookie)
}

#[tokio::test]
async fn admin_resends_verification_only_for_an_unverified_account_against_postgres() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping admin verification resend e2e");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    // (id, email, email_verified, is_admin, enabled)
    let users = [
        (
            "u_admin_resend",
            "admin-resend@example.com",
            true,
            true,
            true,
        ),
        (
            "u_member_resend",
            "member-resend@example.com",
            true,
            false,
            true,
        ),
        (
            "u_waiting_resend",
            "waiting-resend@example.com",
            false,
            false,
            false,
        ),
        (
            "u_verified_resend",
            "verified-resend@example.com",
            true,
            false,
            false,
        ),
    ];
    let cleanup = |p: PgPool| async move {
        for (id, email, ..) in users {
            for statement in [
                "DELETE FROM verifications WHERE identifier=$2",
                "DELETE FROM audit_logs WHERE user_id=$1 OR target_user_id=$1",
                "DELETE FROM sessions WHERE user_id=$1",
                "DELETE FROM users WHERE id=$1",
            ] {
                sqlx::query(statement)
                    .bind(id)
                    .bind(email)
                    .execute(&p)
                    .await
                    .ok();
            }
        }
    };
    cleanup(pool.clone()).await;
    for (id, email, verified, admin, enabled) in users {
        sqlx::query("INSERT INTO users (id, email, name, email_verified, is_admin, enabled) VALUES ($1,$2,$1,$3,$4,$5)")
            .bind(id)
            .bind(email)
            .bind(verified)
            .bind(admin)
            .bind(enabled)
            .execute(&pool)
            .await
            .unwrap();
    }
    for (user, session) in [
        ("u_admin_resend", "sess_admin_resend_token"),
        ("u_member_resend", "sess_member_resend_token"),
    ] {
        sqlx::query("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW() + interval '1 hour')")
            .bind(format!("s_{user}"))
            .bind(user)
            .bind(hash_session_token(session))
            .execute(&pool)
            .await
            .unwrap();
    }
    let app = codewire_idp::access_admin::router(
        pool.clone(),
        "https://app.codewire.test".to_string(),
        codewire_email::EmailClient::disabled(),
        AuthState { pool: pool.clone() },
    );
    let resend = |session: &'static str, user: &'static str| {
        let app = app.clone();
        async move {
            sess_req(
                &app,
                "POST",
                &format!("/api/admin/accounts/{user}/resend-verification"),
                Some(session),
                "{}",
            )
            .await
            .0
        }
    };
    // Only a global administrator may ask.
    assert_eq!(
        resend("sess_member_resend_token", "u_waiting_resend").await,
        403
    );
    assert_eq!(
        resend("sess_admin_resend_token", "u_no_such_account").await,
        404
    );
    assert_eq!(
        resend("sess_admin_resend_token", "u_verified_resend").await,
        409
    );
    // Without email delivery nothing is issued or audited.
    assert_eq!(
        resend("sess_admin_resend_token", "u_waiting_resend").await,
        503
    );
    let issued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM verifications WHERE identifier='waiting-resend@example.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action='admin.account.verification_resent'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((issued, audited), (0, 0));
    // A link sent within five minutes counts as this one: 202, nothing new.
    sqlx::query("INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at) VALUES ('v_admin_resend_recent', 'waiting-resend@example.com', 'email_verification', repeat('b', 64), NOW() + interval '1 day')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        resend("sess_admin_resend_token", "u_waiting_resend").await,
        202
    );
    let issued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM verifications WHERE identifier='waiting-resend@example.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(issued, 1);
    cleanup(pool.clone()).await;
}
