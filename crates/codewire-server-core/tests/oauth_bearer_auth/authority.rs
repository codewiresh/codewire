//! Synthetic original-token publication fences, through the real shared policy.

use super::*;
use std::sync::Mutex;
use std::time::Duration;

use codewire_proto::codewire::testing::v1::{
    AdminPingRequest, AdminPingResponse, PingRequest, PingResponse, PingService, PublicPingRequest,
    PublicPingResponse, StreamPingRequest, StreamPingResponse,
};
use codewire_server_core::auth::{OAuthBearerAuthority, OAuthBearerAuthorityError};
use codewire_server_core::connect::{auth_user, oauth_bearer_authority};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use sqlx::Acquire;
use tokio::sync::oneshot;

const LOCK_SIGNATURE: &str =
    "public.codewire_lock_oauth_bearer_authority(text,text,text,timestamptz)";

struct CaptureService(Arc<Mutex<Option<OAuthBearerAuthority>>>);

#[allow(refining_impl_trait)]
impl PingService for CaptureService {
    async fn ping(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, PingRequest>,
    ) -> ServiceResult<PingResponse> {
        let authority = oauth_bearer_authority(&ctx)?.clone();
        if authority.user_id() != auth_user(&ctx)?.user_id {
            return Err(connectrpc::ConnectError::unauthenticated("owner mismatch"));
        }
        *self.0.lock().unwrap() = Some(authority);
        // Only the opaque authority leaves this handler: no RequestContext,
        // headers, raw token, or authentication parser is retained by a worker.
        connectrpc::Response::ok(PingResponse::default())
    }

    async fn public_ping(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PublicPingRequest>,
    ) -> ServiceResult<PublicPingResponse> {
        ProbePingService.public_ping(ctx, request).await
    }

    async fn admin_ping(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AdminPingRequest>,
    ) -> ServiceResult<AdminPingResponse> {
        ProbePingService.admin_ping(ctx, request).await
    }

    async fn stream_ping(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StreamPingRequest>,
    ) -> ServiceResult<ServiceStream<StreamPingResponse>> {
        ProbePingService.stream_ping(ctx, request).await
    }
}

async fn capture(pool: &PgPool, raw: &str) -> Result<OAuthBearerAuthority> {
    let captured = Arc::new(Mutex::new(None));
    let app = connect_unary_router_with_auth(
        connectrpc::Router::new().add_service(Arc::new(CaptureService(captured.clone()))),
        ConnectAuthLayer::oauth_bearer_only(AuthState { pool: pool.clone() }),
    );
    let (status, _) = call(
        app,
        "Ping",
        headers(
            Some(&format!("Bearer {raw}")),
            Some("codewire.session_token=irrelevant-synthetic-cookie"),
        ),
        "{}",
    )
    .await?;
    ensure!(status == StatusCode::OK, "OAuth authority capture denied");
    let authority = captured
        .lock()
        .unwrap()
        .take()
        .context("missing authority")?;
    Ok(authority)
}

async fn fixture(pool: &PgPool, label: &str, lifetime_ms: i64) -> Result<(String, String, String)> {
    let user = format!("oauth-authority-user-{label}");
    let client = format!("oauth-authority-client-{label}");
    let token = format!("synthetic-original-token-{label}");
    sqlx::query("INSERT INTO users (id,email) VALUES ($1,$2)")
        .bind(&user)
        .bind(format!("{user}@example.test"))
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO oidc_clients (id,name,application_type,auth_method,redirect_uris) \
         VALUES ($1,'Synthetic authority fixture','native','none','{}')",
    )
    .bind(&client)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO oidc_access_tokens (token_hash,user_id,client_id,scopes,expires_at) \
         VALUES ($1,$2,$3,ARRAY['openid','codewire.api'],clock_timestamp()+$4*interval '1 millisecond')",
    )
    .bind(hash_oauth_token(&token))
    .bind(&user)
    .bind(&client)
    .bind(lifetime_ms)
    .execute(pool)
    .await?;
    Ok((token, user, client))
}

async fn grant_helper(db: &TestDatabase) -> Result<()> {
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION {LOCK_SIGNATURE} TO {}",
        quote_ident(&db.role)
    ))
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn admission(
    pool: &PgPool,
    authority: &OAuthBearerAuthority,
) -> Result<Result<(), OAuthBearerAuthorityError>> {
    let mut tx = pool.begin().await?;
    let result = authority.lock_for_publication(&mut tx).await;
    tx.rollback().await?;
    Ok(result)
}

async fn blocked_by(pool: &PgPool, waiter: i32, blocker: i32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))",
            )
            .bind(waiter)
            .bind(blocker)
            .fetch_one(pool)
            .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("expected transaction lock barrier")?
}

fn allow_pending_statement_timeout(result: Result<(), sqlx::Error>) -> Result<()> {
    if let Err(error) = result {
        // Dropping SQLx's fetch future does not consume its ErrorResponse. If
        // the Rust deadline won first, rollback may surface that pending 57014
        // before ReadyForQuery. The caller below must then drain the SAME
        // connection (including SQLx's queued rollback), not claim an ACK from
        // this error or switch to an unrelated spare pool connection.
        ensure!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("57014"),
            "unexpected rollback failure"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_authority_uses_restricted_login_and_separate_connect_extension() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let (raw, user, _) = fixture(&db.pool, "restricted", 60_000).await?;
        let reader = db.reader().await?;
        let test = async {
            let authority = capture(&reader, &raw).await?;
            ensure!(authority.user_id() == user);
            let expected_expiry: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT expires_at FROM oidc_access_tokens WHERE token_hash=$1")
                    .bind(hash_oauth_token(&raw))
                    .fetch_one(&reader)
                    .await?;
            ensure!(authority.expires_at() == expected_expiry);
            ensure!(format!("{authority:?}") == "OAuthBearerAuthority([redacted])");
            // SELECT-only admission works, but PUBLIC has no lock authority.
            ensure!(
                admission(&reader, &authority).await?
                    == Err(OAuthBearerAuthorityError::Unavailable)
            );
            grant_helper(&db).await?;
            ensure!(admission(&reader, &authority).await?.is_ok());
            let identity: (String, String) =
                sqlx::query_as("SELECT current_user::text,session_user::text")
                    .fetch_one(&reader)
                    .await?;
            ensure!(identity == (db.role.clone(), db.role.clone()));
            let admin: String = sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(&db.pool)
                .await?;
            denied(&reader, &format!("SET ROLE {}", quote_ident(&admin))).await?;
            sqlx::query("RESET ROLE").execute(&reader).await?;
            for sql in [
                "SELECT token_hash FROM public.oidc_access_tokens FOR SHARE",
                "SELECT id FROM public.oidc_clients FOR SHARE",
                "SELECT id FROM public.users FOR SHARE",
                "UPDATE public.oidc_access_tokens SET expires_at=now() WHERE false",
                "UPDATE public.oidc_clients SET disabled=false WHERE false",
                "UPDATE public.users SET is_admin=true WHERE false",
                "UPDATE public.users SET enabled=false WHERE false",
                "SELECT secret FROM public.oidc_clients LIMIT 0",
                "SELECT * FROM public.oidc_refresh_tokens LIMIT 0",
                "SELECT * FROM public.platform_credential_material LIMIT 0",
            ] {
                denied(&reader, sql).await?;
            }
            denied(
                &reader,
                &format!("ALTER FUNCTION {LOCK_SIGNATURE} RESET ALL"),
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        reader.close().await;
        test
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_authority_rejects_revocation_identity_scope_and_expiry_changes() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let reader = db.reader().await?;
        let test = async {
            grant_helper(&db).await?;
            fixture(&db.pool, "other", 60_000).await?;
            for (label, mutation) in [
                ("revoke", "DELETE FROM oidc_access_tokens WHERE token_hash=$1"),
                ("scope", "UPDATE oidc_access_tokens SET scopes=ARRAY['openid'] WHERE token_hash=$1"),
                ("expiry", "UPDATE oidc_access_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1"),
                ("extension", "UPDATE oidc_access_tokens SET expires_at=expires_at+interval '1 hour' WHERE token_hash=$1"),
                ("changed-user", "UPDATE oidc_access_tokens SET user_id='oauth-authority-user-other' WHERE token_hash=$1"),
                ("changed-client", "UPDATE oidc_access_tokens SET client_id='oauth-authority-client-other' WHERE token_hash=$1"),
                ("disable", "UPDATE oidc_clients SET disabled=true WHERE id=$1"),
                ("delete-client", "DELETE FROM oidc_clients WHERE id=$1"),
                ("disable-user", "UPDATE users SET enabled=false WHERE id=$1"),
                ("delete-user", "DELETE FROM users WHERE id=$1"),
            ] {
                let (raw, user, client) = fixture(&db.pool, label, 60_000).await?;
                let authority = capture(&reader, &raw).await?;
                let target = match label {
                    "disable" | "delete-client" => client,
                    "disable-user" | "delete-user" => user,
                    _ => hash_oauth_token(&raw),
                };
                sqlx::query(mutation).bind(target).execute(&db.pool).await?;
                ensure!(
                    admission(&reader, &authority).await? == Err(OAuthBearerAuthorityError::Denied),
                    "original authority survived {label}"
                );
            }
            let (raw, user, client) = fixture(&db.pool, "newer", 60_000).await?;
            let original = capture(&reader, &raw).await?;
            sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
                .bind(hash_oauth_token(&raw)).execute(&db.pool).await?;
            let newer = "synthetic-newer-token-same-owner-and-client";
            sqlx::query(
                "INSERT INTO oidc_access_tokens (token_hash,user_id,client_id,scopes,expires_at) \
                 VALUES ($1,$2,$3,ARRAY['codewire.api'],clock_timestamp()+interval '1 hour')",
            ).bind(hash_oauth_token(newer)).bind(user).bind(client)
                .execute(&db.pool).await?;
            let new_authority = capture(&reader, newer).await?;
            ensure!(admission(&reader, &new_authority).await?.is_ok());
            ensure!(admission(&reader, &original).await? == Err(OAuthBearerAuthorityError::Denied));
            Ok::<_, anyhow::Error>(())
        }.await;
        reader.close().await;
        test
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_authority_fences_both_orders_of_token_client_and_account_revocation() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let reader = db.reader().await?;
        let test = async {
            grant_helper(&db).await?;
            for (label, mutation) in [
                (
                    "token",
                    "DELETE FROM oidc_access_tokens WHERE token_hash=$1",
                ),
                (
                    "client",
                    "UPDATE oidc_clients SET disabled=true WHERE id=$1",
                ),
                ("owner", "DELETE FROM users WHERE id=$1"),
                ("disable-user", "UPDATE users SET enabled=false WHERE id=$1"),
                (
                    "scope",
                    "UPDATE oidc_access_tokens SET scopes=ARRAY['openid'] WHERE token_hash=$1",
                ),
            ] {
                for publication_first in [false, true] {
                    let suffix = format!("{label}-{publication_first}");
                    let (raw, user, client) = fixture(&db.pool, &suffix, 60_000).await?;
                    let authority = capture(&reader, &raw).await?;
                    let target = match label {
                        "client" => client,
                        "owner" | "disable-user" => user,
                        _ => hash_oauth_token(&raw),
                    };
                    if publication_first {
                        let mut publication = reader.begin().await?;
                        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *publication)
                            .await?;
                        authority.lock_for_publication(&mut publication).await?;
                        let pool = db.pool.clone();
                        let (pid_tx, pid_rx) = oneshot::channel();
                        let revoke = tokio::spawn(async move {
                            let mut tx = pool.begin().await?;
                            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                                .fetch_one(&mut *tx)
                                .await?;
                            let _ = pid_tx.send(pid);
                            sqlx::query(mutation).bind(target).execute(&mut *tx).await?;
                            tx.commit().await?;
                            Ok::<_, anyhow::Error>(())
                        });
                        blocked_by(&db.pool, pid_rx.await?, blocker).await?;
                        ensure!(!revoke.is_finished());
                        publication.commit().await?;
                        revoke.await??;
                    } else {
                        let mut revocation = db.pool.begin().await?;
                        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                            .fetch_one(&mut *revocation)
                            .await?;
                        sqlx::query(mutation)
                            .bind(target)
                            .execute(&mut *revocation)
                            .await?;
                        let pool = reader.clone();
                        let original = authority.clone();
                        let (pid_tx, pid_rx) = oneshot::channel();
                        let publish = tokio::spawn(async move {
                            let mut tx = pool.begin().await?;
                            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                                .fetch_one(&mut *tx)
                                .await?;
                            let _ = pid_tx.send(pid);
                            let outcome = original.lock_for_publication(&mut tx).await;
                            tx.rollback().await?;
                            Ok::<_, anyhow::Error>(outcome)
                        });
                        blocked_by(&db.pool, pid_rx.await?, blocker).await?;
                        revocation.commit().await?;
                        ensure!(publish.await?? == Err(OAuthBearerAuthorityError::Denied));
                    }
                    ensure!(
                        admission(&reader, &authority).await?
                            == Err(OAuthBearerAuthorityError::Denied)
                    );
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        reader.close().await;
        test
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_authority_deadline_and_database_clock_fence_expiry_during_lock_wait() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let reader = db.reader().await?;
        let test = async {
            grant_helper(&db).await?;
            let (raw, user, client) = fixture(&db.pool, "clock-wait", 4_000).await?;
            let authority = capture(&reader, &raw).await?;
            let expiry = authority.expires_at();
            let mut blocker = db.pool.begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker).await?;
            sqlx::query("SELECT id FROM oidc_clients WHERE id=$1 FOR UPDATE")
                .bind(&client).execute(&mut *blocker).await?;
            let pool = reader.clone();
            let original = authority.clone();
            let (pid_tx, pid_rx) = oneshot::channel();
            let guarded = tokio::spawn(async move {
                let mut connection = pool.acquire().await?;
                let mut tx = connection.begin().await?;
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx).await?;
                let _ = pid_tx.send(pid);
                let outcome = original.lock_for_publication(&mut tx).await;
                allow_pending_statement_timeout(tx.rollback().await)?;
                let ready: i32 = sqlx::query_scalar("SELECT 1")
                    .fetch_one(&mut *connection).await?;
                ensure!(ready == 1);
                Ok::<_, anyhow::Error>(outcome)
            });
            blocked_by(&db.pool, pid_rx.await?, blocker_pid).await?;
            // Also queue the fixed SQL helper directly: its own final clock
            // check must reject after the wait even though transaction NOW()
            // predates expiry. This cannot be proved by the Rust timer alone.
            let pool = reader.clone();
            let digest = hash_oauth_token(&raw);
            let (pid_tx, pid_rx) = oneshot::channel();
            let helper = tokio::spawn(async move {
                let mut tx = pool.begin().await?;
                let (pid, began): (i32, chrono::DateTime<chrono::Utc>) =
                    sqlx::query_as("SELECT pg_backend_pid(),now()")
                        .fetch_one(&mut *tx).await?;
                ensure!(began < expiry);
                let _ = pid_tx.send(pid);
                let accepted: bool = sqlx::query_scalar(
                    "SELECT public.codewire_lock_oauth_bearer_authority($1::text,$2::text,$3::text,$4::timestamptz)",
                ).bind(digest).bind(user).bind(client).bind(expiry)
                    .fetch_one(&mut *tx).await?;
                tx.rollback().await?;
                Ok::<_, anyhow::Error>(accepted)
            });
            blocked_by(&db.pool, pid_rx.await?, blocker_pid).await?;
            sqlx::query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.02)")
                .bind(expiry).execute(&db.pool).await?;
            // The server's conservatively floored millisecond timer can reject
            // just before exact expiry. Either closed failure must complete its
            // rollback without depending on release of the original blocker.
            let guarded_outcome = tokio::time::timeout(Duration::from_secs(2), guarded).await???;
            ensure!(guarded_outcome.is_err());
            blocker.rollback().await?;
            ensure!(!helper.await??);
            ensure!(admission(&reader, &authority).await? == Err(OAuthBearerAuthorityError::Denied));
            Ok::<_, anyhow::Error>(())
        }.await;
        reader.close().await;
        test
    }.await;
    db.finish(result).await
}

async fn timeouts(connection: &mut sqlx::PgConnection) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='statement_timeout'), \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='lock_timeout'), \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='idle_in_transaction_session_timeout')",
    ).fetch_one(connection).await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_authority_server_timeouts_bound_rollback_preserve_shorter_settings_and_do_not_leak()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let reader = db.reader().await?;
        let test = async {
            grant_helper(&db).await?;
            let (raw, user, client) = fixture(&db.pool, "server-timeouts", 60_000).await?;
            let authority = capture(&reader, &raw).await?;
            let mut connection = reader.acquire().await?;
            let baseline = timeouts(&mut connection).await?;
            // Real restricted LOGIN: SET LOCAL must neither require broader
            // table authority nor escape through COMMIT/ROLLBACK into the pool.
            for commit in [false, true] {
                let mut tx = connection.begin().await?;
                authority.lock_for_publication(&mut tx).await?;
                let bounded = timeouts(&mut tx).await?;
                ensure!((1..=5_000).contains(&bounded.0));
                ensure!((1..=5_000).contains(&bounded.2));
                ensure!(bounded.1 == baseline.1, "existing lock timeout changed");
                if baseline.0 != 0 {
                    ensure!(bounded.0 <= baseline.0);
                }
                if baseline.2 != 0 {
                    ensure!(bounded.2 <= baseline.2);
                }
                if commit {
                    tx.commit().await?;
                } else {
                    tx.rollback().await?;
                }
                ensure!(timeouts(&mut connection).await? == baseline);

                let mut tx = connection.begin().await?;
                sqlx::raw_sql(
                    "SET LOCAL statement_timeout='750ms'; \
                     SET LOCAL lock_timeout='500ms'; \
                     SET LOCAL idle_in_transaction_session_timeout='1000ms'",
                )
                .execute(&mut *tx)
                .await?;
                authority.lock_for_publication(&mut tx).await?;
                ensure!(timeouts(&mut tx).await? == (750, 500, 1000));
                // Repeated checks cannot raise already-shorter settings.
                authority.lock_for_publication(&mut tx).await?;
                ensure!(timeouts(&mut tx).await? == (750, 500, 1000));
                if commit {
                    tx.commit().await?;
                } else {
                    tx.rollback().await?;
                }
                ensure!(timeouts(&mut connection).await? == baseline);
            }
            drop(connection);

            for shorter in [false, true] {
                let mut blocker = db.pool.begin().await?;
                let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *blocker)
                    .await?;
                sqlx::query("SELECT id FROM oidc_clients WHERE id=$1 FOR UPDATE")
                    .bind(&client)
                    .execute(&mut *blocker)
                    .await?;
                let pool = reader.clone();
                let original = authority.clone();
                let (pid_tx, pid_rx) = oneshot::channel();
                let guarded = tokio::spawn(async move {
                    let mut connection = pool.acquire().await?;
                    let mut tx = connection.begin().await?;
                    if shorter {
                        sqlx::query("SET LOCAL statement_timeout='150ms'")
                            .execute(&mut *tx)
                            .await?;
                    }
                    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *tx)
                        .await?;
                    let _ = pid_tx.send(pid);
                    let outcome = original.lock_for_publication(&mut tx).await;
                    allow_pending_statement_timeout(tx.rollback().await)?;
                    let ready: i32 = sqlx::query_scalar("SELECT 1")
                        .fetch_one(&mut *connection)
                        .await?;
                    ensure!(ready == 1);
                    Ok::<_, anyhow::Error>(outcome)
                });
                blocked_by(&db.pool, pid_rx.await?, blocker_pid).await?;
                let budget = if shorter {
                    Duration::from_secs(2)
                } else {
                    Duration::from_secs(7)
                };
                let outcome = tokio::time::timeout(budget, guarded).await???;
                ensure!(outcome == Err(OAuthBearerAuthorityError::Unavailable));
                // Keep the client lock held: successful rollback must come from
                // the server-enforced timeout, not from releasing our barrier.
                let still_owner: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *blocker)
                    .await?;
                ensure!(still_owner == blocker_pid);
                let mut probe = db.pool.begin().await?;
                sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT")
                    .bind(&user)
                    .execute(&mut *probe)
                    .await?;
                probe.rollback().await?;
                blocker.rollback().await?;
            }
            ensure!(admission(&reader, &authority).await?.is_ok());
            Ok::<_, anyhow::Error>(())
        }
        .await;
        reader.close().await;
        test
    }
    .await;
    db.finish(result).await
}
