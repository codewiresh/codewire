//! Contract tests for the browser-session-only identity boundary.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Router};
use codewire_server_core::auth::{
    AuthState, AuthUser, SESSION_COOKIE_NAME, hash_session_token, require_account_auth,
    require_session_auth,
};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn app(pool: sqlx::PgPool) -> Router {
    Router::new()
        .route(
            "/identity-operation",
            get(|user: AuthUser| async move { user.user_id }),
        )
        .route_layer(middleware::from_fn_with_state(
            AuthState { pool },
            require_session_auth,
        ))
}

fn request(header_name: header::HeaderName, header_value: &str) -> Request<Body> {
    Request::builder()
        .uri("/identity-operation")
        .header(header_name, header_value)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn session_only_boundary_rejects_every_bearer_species_without_database_lookup() {
    // Deliberately unreachable. A bearer-only request must be rejected before
    // the middleware attempts any credential lookup.
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://codewire:codewire@127.0.0.1:1/codewire")
        .unwrap();

    for bearer in [
        "session-token-presented-as-bearer",
        "cw_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "opaque-oidc-access-token",
    ] {
        let response = app(pool.clone())
            .oneshot(request(header::AUTHORIZATION, &format!("Bearer {bearer}")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "bearer-only identity request must reject: {bearer}"
        );
    }
}

#[tokio::test]
async fn session_only_boundary_accepts_a_live_cookie() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping session-only cookie contract test");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.expect("connect");
    let suffix = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let user_id = format!("u_session_only_{suffix}");
    let session_id = format!("s_session_only_{suffix}");
    let session_token = format!("session_only_{suffix}");

    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, is_admin) \
         VALUES ($1, $2, 'Session Only', true, false)",
    )
    .bind(&user_id)
    .bind(format!("session-only-{suffix}@example.com"))
    .execute(&pool)
    .await
    .unwrap();
    // Hash-only session rows never retain the presented credential.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(hash_session_token(&session_token))
    .execute(&pool)
    .await
    .unwrap();

    let response = app(pool.clone())
        .oneshot(request(
            header::COOKIE,
            &format!("{SESSION_COOKIE_NAME}={session_token}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), user_id.as_bytes());
    let raw_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'sessions' AND column_name = 'token'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        raw_columns, 0,
        "final schema must not expose sessions.token"
    );

    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&session_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn session_only_boundary_uses_only_digest_on_final_schema() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping session hash-only contract test");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.expect("connect");
    let suffix = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let user_id = format!("u_session_digest_{suffix}");
    let valid_id = format!("s_session_digest_valid_{suffix}");
    let mismatch_id = format!("s_session_digest_mismatch_{suffix}");
    let presented = format!("session_digest_{suffix}");

    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, is_admin) \
         VALUES ($1, $2, 'Session Digest', true, false)",
    )
    .bind(&user_id)
    .bind(format!("session-digest-{suffix}@example.com"))
    .execute(&pool)
    .await
    .unwrap();

    // Authentication succeeds through the only durable credential
    // representation: the digest.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(&valid_id)
    .bind(&user_id)
    .bind(hash_session_token(&presented))
    .execute(&pool)
    .await
    .unwrap();

    let response = app(pool.clone())
        .oneshot(request(
            header::COOKIE,
            &format!("{SESSION_COOKIE_NAME}={presented}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A row with a different digest cannot authenticate; there is no raw
    // column through which a fallback could occur.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(&mismatch_id)
    .bind(&user_id)
    .bind(hash_session_token("different-token"))
    .execute(&pool)
    .await
    .unwrap();

    let response = app(pool.clone())
        .oneshot(request(
            header::COOKIE,
            &format!("{SESSION_COOKIE_NAME}=mismatch-{suffix}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn account_boundary_rejects_org_scoped_api_keys() {
    async fn ok() -> &'static str {
        "ok"
    }

    let user = AuthUser {
        user_id: "admin-user".into(),
        org_id: Some("org-one".into()),
        is_admin: true,
        via_api_key: true,
    };
    let app = Router::new()
        .route("/account-operation", get(ok))
        .route_layer(middleware::from_fn(require_account_auth))
        .layer(Extension(user));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/account-operation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "api_key_scope_violation");
    assert_eq!(
        body["hint"],
        "Use a user credential for account-level or global admin operations"
    );
}
