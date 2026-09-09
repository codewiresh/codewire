//! Explicit OAuth-only Connect policy. All credentials and login roles below
//! are synthetic; the ignored case creates and removes one exact test database.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::{Router, middleware, routing::get};
use codewire_server_core::auth::{
    AuthState, AuthUser, SESSION_COOKIE_NAME, api_key_prefix, hash_api_key, hash_oauth_token,
    hash_session_token, require_session_auth,
};
use codewire_server_core::connect::{ConnectAuthLayer, connect_unary_router_with_auth};
use codewire_server_core::connect_testing::ProbePingService;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const SERVICE: &str = "/codewire.testing.v1.PingService";
const SYNTHETIC_PASSWORD: &str = "synthetic-oauth-identity-reader-test-only";

#[path = "oauth_bearer_auth/authority.rs"]
mod authority;

fn app(policy: ConnectAuthLayer) -> Router {
    connect_unary_router_with_auth(
        connectrpc::Router::new().add_service(Arc::new(ProbePingService)),
        policy,
    )
}

fn headers(authorization: Option<&str>, cookie: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(value) = authorization {
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
    }
    if let Some(value) = cookie {
        headers.insert(header::COOKIE, value.parse().unwrap());
    }
    headers
}

async fn call(
    app: Router,
    method: &str,
    headers: HeaderMap,
    body: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{SERVICE}/{method}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1")
        .body(Body::from(body.to_owned()))?;
    request.headers_mut().extend(headers);
    let response = app.oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn closed_pool() -> PgPool {
    // No listener or network access is needed. Any attempted lookup fails with
    // PoolClosed, which the OAuth policy would render unavailable, not 401.
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
        .unwrap();
    pool.close().await;
    pool
}

#[tokio::test]
async fn oauth_only_rejects_unadmitted_credentials_before_lookup_or_dispatch() -> Result<()> {
    let pool = closed_pool().await;
    let api_key = format!("Bearer cw_{}", "0123456789abcdef".repeat(4));
    let cookie = format!("{SESSION_COOKIE_NAME}=synthetic-cookie-must-not-be-used");
    let mut candidates = vec![headers(None, None), headers(None, Some(&cookie))];
    for value in [
        "",
        "Basic synthetic-malformed",
        "Bearer",
        "Bearer ",
        "Bearer  synthetic-extra-space",
        "Bearer synthetic trailing-data",
        "Bearer synthetic\ttab",
        "Bearer synthetic,second",
        "Bearer synthetic=interior-padding",
        "Bearer ===",
        &api_key,
    ] {
        candidates.push(headers(Some(value), Some(&cookie)));
    }
    let mut duplicate = headers(Some("Bearer synthetic-first"), Some(&cookie));
    duplicate.append(header::AUTHORIZATION, "Bearer synthetic-second".parse()?);
    candidates.push(duplicate);

    let mut expected = None;
    for candidate in candidates {
        // Invalid credentials must not enumerate methods or parse their bodies.
        // Even the probe's ordinarily public handler is protected on this mount.
        for method in ["Ping", "PublicPing", "NotARealMethod"] {
            let (status, body) = call(
                app(ConnectAuthLayer::oauth_bearer_only(AuthState {
                    pool: pool.clone(),
                })),
                method,
                candidate.clone(),
                "{deliberately malformed JSON",
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED);
            ensure!(body["code"] == "unauthenticated");
            ensure!(!body.to_string().contains("synthetic"));
            if let Some(expected) = &expected {
                ensure!(
                    &body == expected,
                    "credential rejection enumerated a method"
                );
            } else {
                expected = Some(body);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn oauth_only_lookup_failure_is_closed_and_value_blind() -> Result<()> {
    let pool = closed_pool().await;
    for method in ["Ping", "NotARealMethod"] {
        let (status, body) = call(
            app(ConnectAuthLayer::oauth_bearer_only(AuthState {
                pool: pool.clone(),
            })),
            method,
            headers(
                Some("Bearer synthetic-opaque-token-never-rendered"),
                Some("codewire.session_token=synthetic-cookie-never-rendered"),
            ),
            "{deliberately malformed JSON",
        )
        .await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE);
        ensure!(body["code"] == "unavailable");
        ensure!(body["message"] == "OAuth credential lookup unavailable");
        let rendered = body.to_string();
        for forbidden in ["synthetic", "PoolClosed", "postgres", "127.0.0.1"] {
            ensure!(!rendered.contains(forbidden));
        }
    }
    Ok(())
}

struct TestDatabase {
    admin: PgPool,
    pool: PgPool,
    name: String,
    role: String,
    url: url::Url,
}

impl TestDatabase {
    async fn create() -> Result<Self> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for the isolated OAuth identity test")?;
        ensure!(!admin_url.is_empty(), "TEST_DATABASE_URL must not be empty");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("cw_oauth_identity_{suffix}");
        let role = format!("cw_oauth_reader_{suffix}");
        let mut url = url::Url::parse(&admin_url)?;
        url.set_path(&name);
        sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
            .execute(&admin)
            .await?;
        let setup = async {
            codewire_server_core::migrate::ensure_schema(url.as_str()).await?;
            Ok::<_, anyhow::Error>(
                PgPoolOptions::new()
                    .max_connections(4)
                    .connect(url.as_str())
                    .await?,
            )
        }
        .await;
        match setup {
            Ok(pool) => Ok(Self {
                admin,
                pool,
                name,
                role,
                url,
            }),
            Err(error) => {
                sqlx::query(&format!(
                    "DROP DATABASE {} WITH (FORCE)",
                    quote_ident(&name)
                ))
                .execute(&admin)
                .await?;
                admin.close().await;
                Err(error)
            }
        }
    }

    async fn reader(&self) -> Result<PgPool> {
        let role = quote_ident(&self.role);
        sqlx::query(&format!(
            "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS \
             PASSWORD '{SYNTHETIC_PASSWORD}'"
        ))
        .execute(&self.admin)
        .await?;
        for grant in [
            format!("CONNECT ON DATABASE {}", quote_ident(&self.name)),
            "USAGE ON SCHEMA public".to_owned(),
            "SELECT (token_hash,user_id,client_id,scopes,expires_at) ON public.oidc_access_tokens"
                .to_owned(),
            "SELECT (id,is_admin,enabled) ON public.users".to_owned(),
            "SELECT (id,disabled) ON public.oidc_clients".to_owned(),
        ] {
            sqlx::query(&format!("GRANT {grant} TO {role}"))
                .execute(&self.pool)
                .await?;
        }
        // Authenticate as the restricted login itself, never admin + SET ROLE.
        let mut url = self.url.clone();
        url.set_username(&self.role)
            .map_err(|_| anyhow::anyhow!("set synthetic OAuth reader username"))?;
        url.set_password(Some(SYNTHETIC_PASSWORD))
            .map_err(|_| anyhow::anyhow!("set synthetic OAuth reader password"))?;
        Ok(PgPoolOptions::new()
            .max_connections(2)
            .connect(url.as_str())
            .await?)
    }

    async fn finish(self, result: Result<()>) -> Result<()> {
        self.pool.close().await;
        let cleanup = async {
            sqlx::query(&format!(
                "DROP DATABASE {} WITH (FORCE)",
                quote_ident(&self.name)
            ))
            .execute(&self.admin)
            .await?;
            sqlx::query(&format!("DROP ROLE IF EXISTS {}", quote_ident(&self.role)))
                .execute(&self.admin)
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        self.admin.close().await;
        cleanup.context("clean exact OAuth identity test database and role")?;
        result
    }
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

async fn denied(pool: &PgPool, sql: &str) -> Result<()> {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .err()
        .context("restricted identity login unexpectedly gained authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501"),
        "expected insufficient_privilege, not a fixture or syntax failure"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn oauth_only_restricted_identity_login_preserves_shared_policy() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        sqlx::query(
            "INSERT INTO users (id,email,is_admin) VALUES \
             ('oauth-owner','oauth-owner@example.test',false), \
             ('cookie-owner','cookie-owner@example.test',true)",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO oidc_clients (id,name,application_type,auth_method,redirect_uris) \
             VALUES ('oauth-client','Synthetic OAuth','native','none','{}')",
        )
        .execute(&db.pool)
        .await?;
        let token = "synthetic-live-opaque-oauth-token";
        let expired = "synthetic-expired-opaque-oauth-token";
        let wrong_scope = "synthetic-identity-only-oauth-token";
        let scope_prefix = "synthetic-scope-prefix-is-not-product";
        let key_prefix_token = format!("cw_{}", "A".repeat(40));
        for (raw, scopes, lifetime) in [
            (token, vec!["openid", "codewire.api"], 3600_i32),
            (expired, vec!["codewire.api"], -60),
            (wrong_scope, vec!["openid", "profile"], 3600),
            (scope_prefix, vec!["codewire.api.extra"], 3600),
            (key_prefix_token.as_str(), vec!["codewire.api"], 3600),
        ] {
            sqlx::query(
                "INSERT INTO oidc_access_tokens (token_hash,client_id,user_id,scopes,expires_at) \
                 VALUES ($1,'oauth-client','oauth-owner',$2,now()+$3*interval '1 second')",
            )
            .bind(hash_oauth_token(raw))
            .bind(scopes)
            .bind(lifetime)
            .execute(&db.pool)
            .await?;
        }
        let cookie_token = "synthetic-live-cookie-token";
        let cookie = format!("{SESSION_COOKIE_NAME}={cookie_token}");
        sqlx::query(
            "INSERT INTO sessions (id,user_id,token_hash,expires_at) \
             VALUES ('synthetic-session','cookie-owner',$1,now()+interval '1 hour')",
        )
        .bind(hash_session_token(cookie_token))
        .execute(&db.pool)
        .await?;
        let api_key = format!("cw_{}", "a".repeat(64));
        sqlx::query(
            "INSERT INTO organizations (id,name,slug,created_by) \
             VALUES ('cookie-owner-org','Cookie Owner Org','cookie-owner-org','cookie-owner')",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO api_keys (id,user_id,org_id,name,key_hash,key_prefix,scopes) \
             VALUES ('cookie-owner-api-key','cookie-owner','cookie-owner-org','Synthetic', \
                     $1,$2,ARRAY[]::text[])",
        )
        .bind(hash_api_key(&api_key))
        .bind(api_key_prefix(&api_key))
        .execute(&db.pool)
        .await?;
        let reader = db.reader().await?;
        let test = async {
            let identity: (String, String) =
                sqlx::query_as("SELECT current_user::text,session_user::text")
                    .fetch_one(&reader)
                    .await?;
            ensure!(identity == (db.role.clone(), db.role.clone()));
            let fixture_owner: String = sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(&db.pool)
                .await?;
            ensure!(fixture_owner != db.role);
            denied(
                &reader,
                &format!("SET ROLE {}", quote_ident(&fixture_owner)),
            )
            .await?;
            sqlx::query("RESET ROLE").execute(&reader).await?;
            for sql in [
                "SELECT email FROM public.users LIMIT 0",
                "SELECT secret FROM public.oidc_clients LIMIT 0",
                "SELECT created_at FROM public.oidc_access_tokens LIMIT 0",
                "SELECT * FROM public.sessions LIMIT 0",
                "SELECT * FROM public.api_keys LIMIT 0",
                "SELECT * FROM public.oidc_refresh_tokens LIMIT 0",
                "SELECT * FROM public.jwks LIMIT 0",
                "SELECT * FROM public.platform_credential_material LIMIT 0",
                "SELECT id FROM public.users FOR SHARE",
                "UPDATE public.users SET is_admin=true WHERE false",
                "UPDATE public.oidc_clients SET disabled=false WHERE false",
                "UPDATE public.oidc_access_tokens SET expires_at=now() WHERE false",
                "UPDATE public.sessions SET expires_at=now() WHERE false",
                "UPDATE public.api_keys SET last_used_at=now() WHERE false",
            ] {
                denied(&reader, sql).await?;
            }
            let session_before: (chrono::NaiveDateTime, Option<chrono::NaiveDateTime>) =
                sqlx::query_as(
                    "SELECT expires_at,updated_at FROM sessions WHERE id='synthetic-session'",
                )
                .fetch_one(&db.pool)
                .await?;
            let restricted = || {
                app(ConnectAuthLayer::oauth_bearer_only(AuthState {
                    pool: reader.clone(),
                }))
            };
            for cookie_value in [
                None,
                Some(cookie.as_str()),
                Some("codewire.session_token=irrelevant-invalid-cookie"),
            ] {
                let (status, body) = call(
                    restricted(),
                    "Ping",
                    headers(Some(&format!("Bearer {token}")), cookie_value),
                    r#"{"message":"whoami"}"#,
                )
                .await?;
                ensure!(status == StatusCode::OK && body["message"] == "oauth-owner");
            }
            // A valid random opaque token beginning cw_ is not a 64-hex API key.
            let (status, body) = call(
                restricted(),
                "Ping",
                headers(Some(&format!("bEaReR {key_prefix_token}")), Some(&cookie)),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::OK && body["message"] == "oauth-owner");
            let session_after: (chrono::NaiveDateTime, Option<chrono::NaiveDateTime>) =
                sqlx::query_as(
                    "SELECT expires_at,updated_at FROM sessions WHERE id='synthetic-session'",
                )
                .fetch_one(&db.pool)
                .await?;
            ensure!(
                session_before == session_after,
                "OAuth-only auth touched the irrelevant session"
            );

            for (raw, expected_status, expected_code) in [
                (expired, StatusCode::UNAUTHORIZED, "unauthenticated"),
                (
                    "synthetic-unknown-token",
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                ),
                (cookie_token, StatusCode::UNAUTHORIZED, "unauthenticated"),
                (wrong_scope, StatusCode::FORBIDDEN, "permission_denied"),
                (scope_prefix, StatusCode::FORBIDDEN, "permission_denied"),
            ] {
                for method in ["Ping", "NotARealMethod"] {
                    let (status, body) = call(
                        restricted(),
                        method,
                        headers(Some(&format!("Bearer {raw}")), Some(&cookie)),
                        "{malformed",
                    )
                    .await?;
                    ensure!(status == expected_status && body["code"] == expected_code);
                    ensure!(!body.to_string().contains(raw));
                }
            }
            sqlx::query("UPDATE oidc_clients SET disabled=true WHERE id='oauth-client'")
                .execute(&db.pool)
                .await?;
            let (status, body) = call(
                restricted(),
                "Ping",
                headers(Some(&format!("Bearer {token}")), Some(&cookie)),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated");
            sqlx::query("UPDATE oidc_clients SET disabled=false WHERE id='oauth-client'")
                .execute(&db.pool)
                .await?;

            // The existing general policy still prioritizes a valid session.
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(Some(&format!("Bearer {token}")), Some(&cookie)),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::OK && body["message"] == "cookie-owner");
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(
                    Some(&format!("Bearer {token}")),
                    Some("codewire.session_token=stale"),
                ),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::OK && body["message"] == "oauth-owner");
            let (status, body) = call(
                app(ConnectAuthLayer::admin(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(Some(&format!("Bearer {token}")), None),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::FORBIDDEN && body["code"] == "permission_denied");
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(Some(&format!("Bearer {api_key}")), None),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::OK && body["message"] == "cookie-owner");
            let session_app = Router::new()
                .route(
                    "/session",
                    get(|user: AuthUser| async move { user.user_id }),
                )
                .route_layer(middleware::from_fn_with_state(
                    AuthState {
                        pool: db.pool.clone(),
                    },
                    require_session_auth,
                ));
            let response = session_app
                .oneshot(
                    Request::builder()
                        .uri("/session")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(response.status() == StatusCode::UNAUTHORIZED);

            // Disabling is durable revocation: the existing browser session
            // and API key are removed or retired, and re-enabling must not
            // make either presented credential valid again.
            sqlx::query("UPDATE users SET enabled=false WHERE id='cookie-owner'")
                .execute(&db.pool)
                .await?;
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(None, Some(&cookie)),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated");
            let sessions_after_disable: i64 =
                sqlx::query_scalar("SELECT count(*) FROM sessions WHERE id='synthetic-session'")
                    .fetch_one(&db.pool)
                    .await?;
            ensure!(
                sessions_after_disable == 0,
                "disabled account retained a browser session"
            );
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(Some(&format!("Bearer {api_key}")), None),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated");
            sqlx::query("UPDATE users SET enabled=true WHERE id='cookie-owner'")
                .execute(&db.pool)
                .await?;
            let (status, body) = call(
                app(ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                })),
                "Ping",
                headers(Some(&format!("Bearer {api_key}")), None),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(
                status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated",
                "re-enabling an account revived its old API key"
            );

            sqlx::query("UPDATE users SET enabled=false WHERE id='oauth-owner'")
                .execute(&db.pool)
                .await?;
            for policy in [
                ConnectAuthLayer::oauth_bearer_only(AuthState {
                    pool: reader.clone(),
                }),
                ConnectAuthLayer::authenticated(AuthState {
                    pool: db.pool.clone(),
                }),
            ] {
                let (status, body) = call(
                    app(policy),
                    "Ping",
                    headers(Some(&format!("Bearer {token}")), None),
                    r#"{"message":"whoami"}"#,
                )
                .await?;
                ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated");
            }
            sqlx::query("UPDATE users SET enabled=true WHERE id='oauth-owner'")
                .execute(&db.pool)
                .await?;
            let (status, body) = call(
                restricted(),
                "Ping",
                headers(Some(&format!("Bearer {token}")), None),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(
                status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated",
                "re-enabling an account revived its old OAuth bearer"
            );

            // Revocation is observed on the next request, not cached identity.
            sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
                .bind(hash_oauth_token(token))
                .execute(&db.pool)
                .await?;
            let (status, body) = call(
                restricted(),
                "Ping",
                headers(Some(&format!("Bearer {token}")), Some(&cookie)),
                r#"{"message":"whoami"}"#,
            )
            .await?;
            ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "unauthenticated");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        reader.close().await;
        test
    }
    .await;
    db.finish(result).await
}
