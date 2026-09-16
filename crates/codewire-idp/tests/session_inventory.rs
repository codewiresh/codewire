//! Synthetic database proof for browser-session inventory/revocation.
//! The integration runner rejects a missing DATABASE_URL skip.

use axum::http::{HeaderMap, Request};
use axum::{Router, body::Body};
use codewire_idp::auth_session::{SignupInvitePolicy, router_with_signup_delivery};
use codewire_server_core::auth::hash_session_token;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

const ORIGIN: &str = "https://app.codewire.test";

async fn pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping session inventory DB proof");
        return None;
    };
    Some(
        PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap(),
    )
}

fn app(pool: PgPool) -> Router {
    router_with_signup_delivery(
        pool,
        true,
        SignupInvitePolicy::open(),
        ORIGIN.into(),
        codewire_email::EmailClient::disabled(),
        String::new(),
        String::new(),
    )
}

async fn user(pool: &PgPool, id: &str) {
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id,email,enabled,two_factor_enabled) VALUES ($1,$2,true,true)")
        .bind(id)
        .bind(format!("{id}@synthetic.test"))
        .execute(pool)
        .await
        .unwrap();
}

async fn session(pool: &PgPool, owner: &str, id: &str, token: &str, active: bool) {
    sqlx::query("INSERT INTO sessions (id,user_id,token_hash,expires_at,ip_address,user_agent) \
        VALUES ($1,$2,$3,clock_timestamp()+($4::bigint * interval '1 hour'),'ip-canary','ua-canary')")
        .bind(id).bind(owner).bind(hash_session_token(token)).bind(if active { 8_i64 } else { -1 })
        .execute(pool).await.unwrap();
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
    origins: &[&str],
    bearer: bool,
) -> (u16, Value, HeaderMap) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("cookie", format!("codewire.session_token={token}"));
    }
    for origin in origins {
        builder = builder.header("origin", *origin);
    }
    if bearer {
        builder = builder.header("authorization", "Bearer synthetic-bearer");
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap(), headers)
}

async fn revoke(app: &Router, owner: &str, token: &str, target: &str) -> (u16, Value, HeaderMap) {
    request(
        app,
        "POST",
        "/api/auth/sessions/revoke",
        Some(token),
        json!({"account_id":owner,"session_id":target}),
        &[ORIGIN],
        false,
    )
    .await
}

async fn count(pool: &PgPool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn inventory_pages_all_active_sessions_without_capabilities() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_pages_owner";
    let foreign = "inventory_pages_foreign";
    user(&pool, owner).await;
    user(&pool, foreign).await;
    for i in 0..57 {
        session(
            &pool,
            owner,
            &format!("inventory_page_{i:03}"),
            &format!("page-token-{i}"),
            true,
        )
        .await;
    }
    session(
        &pool,
        owner,
        "inventory_page_expired",
        "expired-token",
        false,
    )
    .await;
    session(
        &pool,
        foreign,
        "inventory_page_foreign",
        "foreign-token",
        true,
    )
    .await;
    let app = app(pool.clone());
    let mut cursor = None;
    let mut ids = Vec::new();
    loop {
        let path = format!(
            "/api/auth/sessions?account_id={owner}{}",
            cursor
                .as_ref()
                .map(|c| format!("&cursor={c}"))
                .unwrap_or_default()
        );
        let (status, body, _) = request(
            &app,
            "GET",
            &path,
            Some("page-token-56"),
            Value::Null,
            &[],
            false,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body["account_id"], owner);
        assert_eq!(body["current_session"]["id"], "inventory_page_056");
        assert!(
            body["current_session"]["expires_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        assert_eq!(body.as_object().unwrap().len(), 4);
        let page = body["sessions"].as_array().unwrap();
        assert!(page.len() <= 50);
        for row in page {
            assert_eq!(row.as_object().unwrap().len(), 3);
            assert!(row["expires_at"].as_str().unwrap().ends_with('Z'));
            ids.push(row["id"].as_str().unwrap().to_string());
        }
        let text = body.to_string();
        for forbidden in [
            "token",
            "ip-canary",
            "ua-canary",
            "inventory_page_foreign",
            "inventory_page_expired",
        ] {
            assert!(!text.contains(forbidden), "disclosed {forbidden}");
        }
        cursor = body["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 57);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 57);
    assert_eq!(count(&pool, "inventory_page_foreign").await, 1);
    session(&pool, owner, &"x".repeat(129), "oversized-id-token", true).await;
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/auth/sessions?account_id={owner}&cursor=inventory_page_056"),
            Some("page-token-56"),
            Value::Null,
            &[],
            false
        )
        .await
        .0,
        503
    );
}

#[tokio::test]
async fn inventory_keyset_is_byte_ordered_even_when_session_ids_have_icu_collation() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_collation_owner";
    user(&pool, owner).await;
    // A test-owned table with the exact migrated shape but a non-byte column
    // collation. Public/migrated tables and concurrent fixtures are untouched.
    sqlx::query("CREATE SCHEMA idp_inventory_collation_regression")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE idp_inventory_collation_regression.sessions (LIKE public.sessions INCLUDING ALL)").execute(&pool).await.unwrap();
    sqlx::query("ALTER TABLE idp_inventory_collation_regression.sessions ALTER COLUMN id TYPE TEXT COLLATE \"en-x-icu\"").execute(&pool).await.unwrap();
    let url = std::env::var("DATABASE_URL").unwrap();
    let scoped = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO idp_inventory_collation_regression, public")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let mut expected = Vec::new();
    for prefix in ["A", "a", "-", "_", "0", "9"] {
        for i in 0..10 {
            let id = format!("{prefix}_collation_{i:02}");
            session(
                &scoped,
                owner,
                &id,
                &format!("collation-token-{prefix}-{i}"),
                true,
            )
            .await;
            expected.push(id);
        }
    }
    expected.sort();
    let default_order: Vec<String> = sqlx::query_scalar("SELECT id FROM sessions ORDER BY id")
        .fetch_all(&scoped)
        .await
        .unwrap();
    assert_ne!(
        default_order, expected,
        "fixture must actually distinguish ICU from byte order"
    );
    let router = app(scoped.clone());
    let mut cursor = None;
    let mut actual = Vec::new();
    let mut page_sizes = Vec::new();
    loop {
        let path = format!(
            "/api/auth/sessions?account_id={owner}{}",
            cursor
                .as_ref()
                .map(|cursor| format!("&cursor={cursor}"))
                .unwrap_or_default()
        );
        let (status, body, _) = request(
            &router,
            "GET",
            &path,
            Some("collation-token-A-0"),
            Value::Null,
            &[],
            false,
        )
        .await;
        assert_eq!(status, 200);
        let rows = body["sessions"].as_array().unwrap();
        page_sizes.push(rows.len());
        actual.extend(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap().to_owned()),
        );
        cursor = body["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
        assert!(page_sizes.len() < 3, "keyset must advance");
    }
    scoped.close().await;
    sqlx::query("DROP SCHEMA idp_inventory_collation_regression CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(page_sizes, [50, 10]);
    assert_eq!(
        actual, expected,
        "IdP pages must preserve the BFF byte-order contract across the cursor boundary"
    );
}

#[tokio::test]
async fn authority_and_target_scope_are_closed_and_revocation_is_acknowledged() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_auth_owner";
    let foreign = "inventory_auth_foreign";
    user(&pool, owner).await;
    user(&pool, foreign).await;
    session(&pool, owner, "inventory_auth_actor", "auth-token", true).await;
    session(&pool, owner, "inventory_auth_other", "other-token", true).await;
    session(
        &pool,
        owner,
        "inventory_auth_expired",
        "expired-auth-token",
        false,
    )
    .await;
    session(
        &pool,
        foreign,
        "inventory_auth_foreign_target",
        "foreign-auth-token",
        true,
    )
    .await;
    let app = app(pool.clone());
    let body = json!({"account_id":owner,"session_id":"inventory_auth_other"});
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/auth/sessions/revoke",
            Some("auth-token"),
            json!({"account_id":owner,"session_id":"inventory_auth_other","token":"not-accepted"}),
            &[ORIGIN],
            false
        )
        .await
        .0,
        400
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/auth/sessions?account_id={foreign}"),
            Some("auth-token"),
            Value::Null,
            &[],
            false
        )
        .await
        .0,
        403
    );
    for (token, origins, bearer, expected) in [
        (None, vec![ORIGIN], false, 401),
        (None, vec![ORIGIN], true, 401),
        (Some("auth-token"), vec![], false, 403),
        (Some("auth-token"), vec![ORIGIN, ORIGIN], false, 403),
        (Some("auth-token"), vec!["https://foreign.test"], false, 403),
        (Some("auth-token"), vec![ORIGIN], true, 401),
        (Some("expired-auth-token"), vec![ORIGIN], false, 401),
    ] {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/auth/sessions/revoke",
                token,
                body.clone(),
                &origins,
                bearer
            )
            .await
            .0,
            expected
        );
        assert_eq!(count(&pool, "inventory_auth_other").await, 1);
    }
    assert_eq!(
        revoke(&app, foreign, "auth-token", "inventory_auth_foreign_target")
            .await
            .0,
        403
    );
    let missing = revoke(&app, owner, "auth-token", "missing-target").await;
    let other = revoke(&app, owner, "auth-token", "inventory_auth_foreign_target").await;
    assert_eq!(missing.0, 404);
    assert_eq!((missing.0, missing.1), (other.0, other.1));
    assert_eq!(count(&pool, "inventory_auth_foreign_target").await, 1);
    for factor in [Some(false), None] {
        sqlx::query("UPDATE users SET two_factor_enabled=$2 WHERE id=$1")
            .bind(owner)
            .bind(factor)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            revoke(&app, owner, "auth-token", "inventory_auth_other")
                .await
                .0,
            403
        );
    }
    sqlx::query("UPDATE users SET two_factor_enabled=true WHERE id=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    let other = revoke(&app, owner, "auth-token", "inventory_auth_other").await;
    assert_eq!(other.0, 200);
    assert_eq!(
        other.1,
        json!({"revoked":true,"current_session_revoked":false})
    );
    assert!(other.2.get("set-cookie").is_none());
    assert_eq!(count(&pool, "inventory_auth_other").await, 0);
    let current = revoke(&app, owner, "auth-token", "inventory_auth_actor").await;
    assert_eq!(current.0, 200);
    assert_eq!(
        current.1,
        json!({"revoked":true,"current_session_revoked":true})
    );
    assert!(
        current
            .2
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        revoke(&app, owner, "auth-token", "inventory_auth_actor")
            .await
            .0,
        401
    );
    // Existing account disablement deliberately revokes all browser sessions.
    session(
        &pool,
        owner,
        "inventory_auth_disabled",
        "disabled-token",
        true,
    )
    .await;
    sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        revoke(&app, owner, "disabled-token", "inventory_auth_disabled")
            .await
            .0,
        401
    );
    assert_eq!(count(&pool, "inventory_auth_disabled").await, 0);
}

async fn wait_blocked(pool: &PgPool, worker_pid: i32, owner_pid: i32) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
                .bind(worker_pid)
                .bind(owner_pid)
                .fetch_one(pool)
                .await
                .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker must reach owner lock before actor mutation");
}

#[tokio::test]
async fn actor_is_revalidated_after_lock_wait_not_from_stale_request_identity() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_race_owner";
    for expire in [false, true] {
        user(&pool, owner).await;
        session(&pool, owner, "inventory_race_actor", "race-token", true).await;
        session(
            &pool,
            owner,
            "inventory_race_target",
            "race-target-token",
            true,
        )
        .await;
        let url = std::env::var("DATABASE_URL").unwrap();
        let worker = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let worker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&worker)
            .await
            .unwrap();
        let mut lock = pool.begin().await.unwrap();
        let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(owner)
            .execute(&mut *lock)
            .await
            .unwrap();
        let app = app(worker.clone());
        let task = tokio::spawn(async move {
            revoke(&app, owner, "race-token", "inventory_race_target").await
        });
        wait_blocked(&pool, worker_pid, owner_pid).await;
        if expire {
            sqlx::query(
                "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
            )
            .bind("inventory_race_actor")
            .execute(&mut *lock)
            .await
            .unwrap();
        } else {
            sqlx::query("DELETE FROM sessions WHERE id=$1")
                .bind("inventory_race_actor")
                .execute(&mut *lock)
                .await
                .unwrap();
        }
        lock.commit().await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.0, 401);
        assert_eq!(count(&pool, "inventory_race_target").await, 1);
        worker.close().await;
    }
}

#[tokio::test]
async fn reciprocal_session_revocation_has_no_deadlock_and_only_one_winner() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_reciprocal_owner";
    user(&pool, owner).await;
    session(&pool, owner, "inventory_reciprocal_a", "reciprocal-a", true).await;
    session(&pool, owner, "inventory_reciprocal_b", "reciprocal-b", true).await;
    let app = app(pool.clone());
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(
            revoke(&app, owner, "reciprocal-a", "inventory_reciprocal_b"),
            revoke(&app, owner, "reciprocal-b", "inventory_reciprocal_a")
        )
    })
    .await
    .expect("owner-first serialization must not deadlock");
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [200, 401]);
    assert_eq!(
        count(&pool, "inventory_reciprocal_a").await + count(&pool, "inventory_reciprocal_b").await,
        1
    );
}

#[tokio::test]
async fn unchanged_actor_or_target_lock_wait_cannot_extend_expired_authority() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_expiry_owner";
    for target_lock in [false, true] {
        user(&pool, owner).await;
        session(&pool, owner, "inventory_expiry_actor", "expiry-token", true).await;
        session(
            &pool,
            owner,
            "inventory_expiry_target",
            "expiry-target-token",
            true,
        )
        .await;
        sqlx::query(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
        )
        .bind("inventory_expiry_actor")
        .execute(&pool)
        .await
        .unwrap();
        let worker = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let worker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&worker)
            .await
            .unwrap();
        let mut lock = pool.begin().await.unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE")
            .bind(if target_lock {
                "inventory_expiry_target"
            } else {
                "inventory_expiry_actor"
            })
            .execute(&mut *lock)
            .await
            .unwrap();
        let app = app(worker.clone());
        let task = tokio::spawn(async move {
            revoke(&app, owner, "expiry-token", "inventory_expiry_target").await
        });
        wait_blocked(&pool, worker_pid, blocker_pid).await;
        // Release an unchanged row only after PostgreSQL's clock proves expiry.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let expired: bool = sqlx::query_scalar(
                    "SELECT expires_at <= clock_timestamp() FROM sessions WHERE id=$1",
                )
                .bind("inventory_expiry_actor")
                .fetch_one(&pool)
                .await
                .unwrap();
                if expired {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        lock.commit().await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.0, 401);
        assert_eq!(count(&pool, "inventory_expiry_target").await, 1);
        worker.close().await;
    }
}

#[tokio::test]
async fn server_lock_timeout_releases_abandoned_authority_and_does_not_claim_success() {
    let Some(pool) = pool().await else { return };
    let owner = "inventory_timeout_owner";
    user(&pool, owner).await;
    session(
        &pool,
        owner,
        "inventory_timeout_actor",
        "timeout-token",
        true,
    )
    .await;
    session(
        &pool,
        owner,
        "inventory_timeout_target",
        "timeout-target-token",
        true,
    )
    .await;
    let worker = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    // The route must preserve this stricter server policy instead of increasing it.
    sqlx::query("SET statement_timeout='500ms'")
        .execute(&worker)
        .await
        .unwrap();
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE")
        .bind("inventory_timeout_target")
        .execute(&mut *lock)
        .await
        .unwrap();
    let app = app(worker.clone());
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        revoke(&app, owner, "timeout-token", "inventory_timeout_target"),
    )
    .await
    .unwrap();
    assert_eq!(response.0, 503);
    assert_eq!(count(&pool, "inventory_timeout_target").await, 1);
    // While the original target remains locked, a different connection can lock
    // the owner: canceled/failed work must not retain its transaction authority.
    let mut probe = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(owner)
        .execute(&mut *probe)
        .await
        .unwrap();
    probe.rollback().await.unwrap();
    lock.rollback().await.unwrap();
    worker.close().await;
}
