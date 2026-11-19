//! The fence against the database: each loss ends its streams through the
//! log, expiry ends none, and admission can't race a revocation (#3586;
//! AUTH-POLICY "Account access revocation"; `docs/journeys/account-access.md`
//! `access-streams`). Run with `--ignored` against a database migrated
//! through `credential_revocations`.

use super::*;

use sqlx::postgres::PgPoolOptions;

fn session(user: &str, session: &str) -> Admitted {
    Admitted::session(user, session)
}

pub(super) fn revoked_now(watch: &Watch) -> Option<Revocation> {
    *watch.revoked.borrow()
}

pub(super) async fn database() -> PgPool {
    let url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect")
}

/// A user with one live session, one OAuth access token and one API key.
pub(super) struct Account {
    pub(super) user_id: String,
    pub(super) session_id: String,
    pub(super) token_hash: String,
    pub(super) key_id: String,
}

pub(super) async fn account(pool: &PgPool, name: &str) -> Account {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let user_id = format!("user_fence_{name}_{suffix}");
    let account = Account {
        session_id: format!("session_fence_{suffix}"),
        token_hash: format!("{:0>64}", suffix),
        key_id: format!("key_fence_{suffix}"),
        user_id,
    };
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $1 || '@example.test')")
        .bind(&account.user_id)
        .execute(pool)
        .await
        .expect("user");
    add_session(pool, &account.user_id, &account.session_id, "1 hour").await;
    sqlx::query(
        "INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at) \
         VALUES ($1, 'codewire-cli', $2, ARRAY['openid'], NOW() + interval '1 hour')",
    )
    .bind(&account.token_hash)
    .bind(&account.user_id)
    .execute(pool)
    .await
    .expect("token");
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $2, $3)")
        .bind(format!("org_fence_{suffix}"))
        .bind(format!("fence-{suffix}"))
        .bind(&account.user_id)
        .execute(pool)
        .await
        .expect("org");
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, 'fence', $1, 'cw_fence')",
    )
    .bind(&account.key_id)
    .bind(&account.user_id)
    .bind(format!("org_fence_{suffix}"))
    .execute(pool)
    .await
    .expect("api key");
    account
}

async fn add_session(pool: &PgPool, user_id: &str, session_id: &str, lifetime: &str) {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
         VALUES ($1, $2, NOW() + $3::interval, encode(sha256($1::bytea), 'hex'))",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(lifetime)
    .execute(pool)
    .await
    .expect("session");
}

pub(super) async fn execute(pool: &PgPool, sql: &str, id: &str) {
    sqlx::query(sql).bind(id).execute(pool).await.expect(sql);
}

/// Admits with a re-read that passes, as a live credential's would.
pub(super) async fn admitted(fence: &Fence, pool: &PgPool, admitted: &Admitted) -> Watch {
    fence
        .admit(pool, admitted, async { Ok(()) })
        .await
        .expect("admitted")
}

/// Reads the log as the backstop does, with no wake-up.
pub(super) async fn backstop(fence: &Fence, pool: &PgPool, cursor: &mut LogCursor) {
    fence.read_log(pool, cursor).await.expect("read the log");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn each_loss_ends_its_streams_through_the_backstop_alone() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let a = account(&pool, "each").await;
    let by_session = admitted(&fence, &pool, &session(&a.user_id, &a.session_id)).await;
    let by_token = admitted(
        &fence,
        &pool,
        &Admitted {
            user_id: a.user_id.clone(),
            credential: AdmittedCredential::OAuthToken {
                token_hash: a.token_hash.clone(),
                client_id: "codewire-cli".into(),
            },
        },
    )
    .await;
    let by_key = admitted(
        &fence,
        &pool,
        &Admitted {
            user_id: a.user_id.clone(),
            credential: AdmittedCredential::ApiKey {
                key_id: a.key_id.clone(),
            },
        },
    )
    .await;

    execute(&pool, "DELETE FROM sessions WHERE id = $1", &a.session_id).await;
    execute(
        &pool,
        "DELETE FROM oidc_access_tokens WHERE token_hash = $1",
        &a.token_hash,
    )
    .await;
    execute(
        &pool,
        "UPDATE api_keys SET disabled_at = NOW() WHERE id = $1",
        &a.key_id,
    )
    .await;
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&by_session), Some(Revocation::Session));
    assert_eq!(revoked_now(&by_token), Some(Revocation::OAuthToken));
    assert_eq!(revoked_now(&by_key), Some(Revocation::ApiKey));

    // A disable ends a stream that no other loss touched.
    let second = format!("{}_second", a.session_id);
    add_session(&pool, &a.user_id, &second, "1 hour").await;
    let by_second = admitted(&fence, &pool, &session(&a.user_id, &second)).await;
    execute(
        &pool,
        "UPDATE users SET enabled = false WHERE id = $1",
        &a.user_id,
    )
    .await;
    backstop(&fence, &pool, &mut cursor).await;
    assert!(matches!(
        revoked_now(&by_second),
        Some(Revocation::User | Revocation::Session)
    ));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_revoked_grant_ends_streams_of_its_client_only() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let a = account(&pool, "grant").await;
    let token = |client: &str| Admitted {
        user_id: a.user_id.clone(),
        credential: AdmittedCredential::OAuthToken {
            token_hash: format!("expired_{client}"),
            client_id: client.into(),
        },
    };
    let cli = admitted(&fence, &pool, &token("codewire-cli")).await;
    let desktop = admitted(&fence, &pool, &token("codewire-desktop")).await;
    sqlx::query("SELECT codewire_revoke_oauth_grant($1, 'codewire-cli')")
        .bind(&a.user_id)
        .execute(&pool)
        .await
        .expect("revoke the grant");
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&cli), Some(Revocation::OAuthGrant));
    assert_eq!(revoked_now(&desktop), None);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn expiry_ends_nothing_and_a_sign_out_leaves_other_sessions_streams() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let a = account(&pool, "expiry").await;
    let expired = format!("{}_expired", a.session_id);
    add_session(&pool, &a.user_id, &expired, "-1 minute").await;
    let by_expired = admitted(&fence, &pool, &session(&a.user_id, &expired)).await;
    let other_machine = admitted(&fence, &pool, &session(&a.user_id, &a.session_id)).await;

    // Cleanup of an expired session writes no row.
    execute(&pool, "DELETE FROM sessions WHERE id = $1", &expired).await;
    let logged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_revocations WHERE kind = 'session' AND credential_id = $1",
    )
    .bind(&expired)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(logged, 0);

    // Signing out a third session ends only its own streams.
    let signed_out = format!("{}_signed_out", a.session_id);
    add_session(&pool, &a.user_id, &signed_out, "1 hour").await;
    let by_signed_out = admitted(&fence, &pool, &session(&a.user_id, &signed_out)).await;
    execute(&pool, "DELETE FROM sessions WHERE id = $1", &signed_out).await;
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&by_signed_out), Some(Revocation::Session));
    assert_eq!(revoked_now(&by_expired), None);
    assert_eq!(revoked_now(&other_machine), None);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_row_the_re_read_already_saw_never_ends_a_later_stream() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let a = account(&pool, "reenabled").await;
    execute(
        &pool,
        "UPDATE users SET enabled = false WHERE id = $1",
        &a.user_id,
    )
    .await;
    execute(
        &pool,
        "UPDATE users SET enabled = true WHERE id = $1",
        &a.user_id,
    )
    .await;
    let fresh = format!("{}_fresh", a.session_id);
    add_session(&pool, &a.user_id, &fresh, "1 hour").await;

    // The listener had read nothing since; the backstop now reads the
    // disable's row after the new stream registered.
    let stream = admitted(&fence, &pool, &session(&a.user_id, &fresh)).await;
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&stream), None);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_revocation_on_either_side_of_the_re_read_is_never_missed() {
    let pool = database().await;
    let fence = Fence::new();
    let a = account(&pool, "race").await;
    let live = |session_id: String| {
        let pool = pool.clone();
        async move {
            let found: Option<String> =
                sqlx::query_scalar("SELECT id FROM sessions WHERE id = $1 AND expires_at > NOW()")
                    .bind(session_id)
                    .fetch_optional(&pool)
                    .await
                    .map_err(|_| Refused::Unavailable)?;
            found.map(|_| ()).ok_or(Refused::Revoked)
        }
    };

    // Committed after the snapshot but before the re-read: refused.
    let before = format!("{}_before", a.session_id);
    add_session(&pool, &a.user_id, &before, "1 hour").await;
    let refused = fence
        .admit(&pool, &session(&a.user_id, &before), async {
            execute(&pool, "DELETE FROM sessions WHERE id = $1", &before).await;
            live(before.clone()).await
        })
        .await;
    assert_eq!(refused.err(), Some(Refused::Revoked));

    // Committed after the re-read: the wake-up ends it, with the backstop
    // far off.
    let listener = fence.spawn_listener_every(pool.clone(), Duration::from_secs(3600));
    let after = format!("{}_after", a.session_id);
    add_session(&pool, &a.user_id, &after, "1 hour").await;
    let mut stream = fence
        .admit(&pool, &session(&a.user_id, &after), live(after.clone()))
        .await
        .expect("admitted");
    // Give the listener its subscription before the revocation.
    tokio::time::sleep(Duration::from_millis(500)).await;
    execute(&pool, "DELETE FROM sessions WHERE id = $1", &after).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), stream.revoked()).await;
    listener.abort();
    assert_eq!(ended.ok(), Some(Revocation::Session));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_revocation_inside_a_savepoint_is_judged_by_its_whole_transaction() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let a = account(&pool, "savepoint").await;

    // The revoking transaction is still open when the stream registers, so
    // its snapshot can't see it, and its row ends the stream once committed.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SAVEPOINT revoke")
        .execute(&mut *tx)
        .await
        .expect("savepoint");
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&a.session_id)
        .execute(&mut *tx)
        .await
        .expect("delete");
    sqlx::query("RELEASE SAVEPOINT revoke")
        .execute(&mut *tx)
        .await
        .expect("release");
    let stream = admitted(&fence, &pool, &session(&a.user_id, &a.session_id)).await;
    tx.commit().await.expect("commit");
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&stream), Some(Revocation::Session));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_admission_that_cannot_be_checked_is_refused_as_unavailable() {
    let pool = database().await;
    let fence = Fence::new();
    let a = account(&pool, "unavailable").await;
    let failed = fence
        .admit(&pool, &session(&a.user_id, &a.session_id), async {
            Err(Refused::Unavailable)
        })
        .await;
    assert_eq!(failed.err(), Some(Refused::Unavailable));

    pool.close().await;
    let closed = fence
        .admit(&pool, &session(&a.user_id, &a.session_id), async { Ok(()) })
        .await;
    assert_eq!(closed.err(), Some(Refused::Unavailable));
    let registry = fence
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    assert!(registry.entries.is_empty());
}

/// Answers a stream once, then holds it until its fence ends it.
struct FencedPing {
    fence: Fence,
    pool: PgPool,
}

#[allow(refining_impl_trait)]
impl codewire_proto::codewire::testing::v1::PingService for FencedPing {
    async fn public_ping(
        &self,
        _ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<
            '_,
            codewire_proto::codewire::testing::v1::PublicPingRequest,
        >,
    ) -> connectrpc::ServiceResult<codewire_proto::codewire::testing::v1::PublicPingResponse> {
        Err(connectrpc::ConnectError::internal("not under test"))
    }

    async fn ping(
        &self,
        _ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<
            '_,
            codewire_proto::codewire::testing::v1::PingRequest,
        >,
    ) -> connectrpc::ServiceResult<codewire_proto::codewire::testing::v1::PingResponse> {
        Err(connectrpc::ConnectError::internal("not under test"))
    }

    async fn admin_ping(
        &self,
        _ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<
            '_,
            codewire_proto::codewire::testing::v1::AdminPingRequest,
        >,
    ) -> connectrpc::ServiceResult<codewire_proto::codewire::testing::v1::AdminPingResponse> {
        Err(connectrpc::ConnectError::internal("not under test"))
    }

    async fn stream_ping(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<
            '_,
            codewire_proto::codewire::testing::v1::StreamPingRequest,
        >,
    ) -> connectrpc::ServiceResult<
        connectrpc::ServiceStream<codewire_proto::codewire::testing::v1::StreamPingResponse>,
    > {
        use futures::StreamExt as _;

        let (admitted, watch) = crate::connect::admit_stream(&ctx, &self.fence).await?;
        let end = watch.into_connect_end(
            self.pool.clone(),
            admitted,
            StreamSite {
                surface: "test",
                environment_id: None,
            },
        );
        let first = futures::stream::once(async {
            Ok(codewire_proto::codewire::testing::v1::StreamPingResponse {
                sequence: 0,
                total: 1,
                ..Default::default()
            })
        });
        let ended = futures::stream::once(async move { Err(end.await) });
        connectrpc::Response::stream_ok(first.chain(ended))
    }
}

/// Reads Connect frames from `response` until one whose flags match
/// `end_stream`, and returns its JSON payload.
async fn next_frame(
    response: &mut reqwest::Response,
    buffer: &mut Vec<u8>,
) -> (u8, serde_json::Value) {
    loop {
        if buffer.len() >= 5 {
            let length = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
            let length = usize::try_from(length).unwrap();
            if buffer.len() >= 5 + length {
                let flags = buffer[0];
                let payload: serde_json::Value =
                    serde_json::from_slice(&buffer[5..5 + length]).unwrap();
                buffer.drain(..5 + length);
                return (flags, payload);
            }
        }
        let chunk = response
            .chunk()
            .await
            .unwrap()
            .expect("the stream ended early");
        buffer.extend_from_slice(&chunk);
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_connect_stream_ends_when_the_session_that_admitted_it_signs_out() {
    let pool = database().await;
    let a = account(&pool, "connect").await;
    let fence = Fence::new();
    let listener = fence.spawn_listener_every(pool.clone(), Duration::from_secs(3600));
    let connect = connectrpc::Router::new().add_service(std::sync::Arc::new(FencedPing {
        fence: fence.clone(),
        pool: pool.clone(),
    }));
    let app = crate::connect::connect_router_with_auth(
        connect,
        crate::connect::ConnectAuthLayer::authenticated(crate::auth::AuthState {
            pool: pool.clone(),
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(socket, app).await });

    let payload = b"{}";
    let mut frame = vec![0u8];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    let mut response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!(
            "http://{address}/{}/StreamPing",
            codewire_proto::codewire::testing::v1::PING_SERVICE_SERVICE_NAME
        ))
        .header("content-type", "application/connect+json")
        .header("connect-protocol-version", "1")
        .header(
            "cookie",
            format!("{}={}", crate::auth::SESSION_COOKIE_NAME, a.session_id),
        )
        .body(frame)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let mut buffer = Vec::new();
    let (flags, first) = tokio::time::timeout(
        Duration::from_secs(10),
        next_frame(&mut response, &mut buffer),
    )
    .await
    .expect("the first message");
    assert_eq!((flags, first["total"].as_i64()), (0, Some(1)));

    // Give the listener its subscription, then sign the session out.
    tokio::time::sleep(Duration::from_millis(500)).await;
    execute(&pool, "DELETE FROM sessions WHERE id = $1", &a.session_id).await;
    let (flags, end) = tokio::time::timeout(
        Duration::from_secs(10),
        next_frame(&mut response, &mut buffer),
    )
    .await
    .expect("the stream ended within the bound, through the wake-up");
    assert_eq!(flags & 0x02, 0x02, "an end-of-stream frame: {end}");
    assert_eq!(end["error"]["code"], "permission_denied");
    assert_eq!(end["error"]["message"], "access revoked");

    let audited: Vec<(String, String)> = sqlx::query_as(
        "SELECT metadata->>'revocation', metadata->>'surface' FROM audit_logs \
         WHERE action = 'stream.revoked' AND user_id = $1",
    )
    .bind(&a.user_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audited, vec![("session".to_owned(), "test".to_owned())]);
    listener.abort();
    server.abort();
}
