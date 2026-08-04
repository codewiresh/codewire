use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use codewire_server_core::auth::AuthState;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

fn lazy_pool() -> PgPool {
    PgPool::connect_lazy("postgres://codewire:codewire@127.0.0.1:1/codewire")
        .expect("lazy postgres pool")
}

async fn post_json(app: Router, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

#[tokio::test]
async fn sign_up_type_errors_use_rust_validation_envelope() {
    let pool = lazy_pool();
    let app = codewire_idp::auth_session::router(
        pool,
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    );

    let (status, body) = post_json(
        app,
        "/api/auth/sign-up",
        r#"{"email":7,"password":"long-enough-password"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["status"], 422);
    assert_eq!(body["title"], "Unprocessable Entity");
    assert_eq!(body["detail"], "validation failed");
    assert_eq!(body["errors"].as_array().unwrap()[0]["path"], "/email");
}

#[tokio::test]
async fn sign_up_missing_required_fields_uses_rust_validation_envelope() {
    let pool = lazy_pool();
    let app = codewire_idp::auth_session::router(
        pool,
        false,
        codewire_idp::auth_session::SignupInvitePolicy::open(),
    );

    let (status, body) = post_json(app, "/api/auth/sign-up", r#"{"email":"n@example.com"}"#).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["status"], 422);
    assert_eq!(body["title"], "Unprocessable Entity");
    assert_eq!(body["detail"], "validation failed");
    assert!(
        body["errors"].as_array().unwrap()[0]["message"]
            .as_str()
            .unwrap()
            .contains("password")
    );
}

#[tokio::test]
async fn configured_signup_invite_policy_rejects_before_database_access() {
    let pool = lazy_pool();
    let accepted_hash = format!("{:x}", Sha256::digest(b"synthetic-accepted-invite"));
    let policy =
        codewire_idp::auth_session::SignupInvitePolicy::from_sha256_hashes(Some(&accepted_hash))
            .unwrap();
    let app = codewire_idp::auth_session::router(pool, false, policy);

    for invite_code in ["", "synthetic-rejected-invite"] {
        let body = format!(
            r#"{{"email":"n@example.com","password":"CorrectHorse9#xy","invite_code":"{invite_code}"}}"#
        );
        let (status, body) = post_json(app.clone(), "/api/auth/sign-up", &body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["detail"], "Invalid invitation code");
    }
}

#[tokio::test]
async fn reset_password_missing_token_uses_rust_validation_envelope() {
    let pool = lazy_pool();
    let app = codewire_idp::email_password::router(
        pool.clone(),
        "https://app.codewire.test".to_string(),
        String::new(),
        AuthState { pool },
    );

    let (status, body) = post_json(
        app,
        "/api/auth/reset-password",
        r#"{"newPassword":"long-enough-password"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["status"], 422);
    assert_eq!(body["detail"], "validation failed");
    assert!(
        body["errors"].as_array().unwrap()[0]["message"]
            .as_str()
            .unwrap()
            .contains("token")
    );
}

#[tokio::test]
async fn two_factor_validate_missing_token_uses_rust_validation_envelope() {
    let pool = lazy_pool();
    let app = codewire_idp::two_factor::router(
        pool.clone(),
        "validation-test-secret".to_string(),
        false,
        AuthState { pool },
    );

    let (status, body) =
        post_json(app, "/api/auth/two-factor/validate", r#"{"code":"123456"}"#).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["status"], 422);
    assert_eq!(body["detail"], "validation failed");
    assert!(
        body["errors"].as_array().unwrap()[0]["message"]
            .as_str()
            .unwrap()
            .contains("token")
    );
}
