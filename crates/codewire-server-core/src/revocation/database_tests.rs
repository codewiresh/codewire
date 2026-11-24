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
            organization: None,
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
            organization: None,
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
        organization: None,
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
    organization: Option<String>,
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

        let (admitted, watch) =
            crate::connect::admit_stream(&ctx, &self.fence, self.organization.as_deref()).await?;
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
    let session = a.session_id.clone();
    fenced_connect_stream(
        &pool,
        &a,
        None,
        "session",
        "permission_denied",
        "access revoked",
        || async {
            execute(&pool, "DELETE FROM sessions WHERE id = $1", &session).await;
        },
    )
    .await;
}

/// A stream into one of its organization's environments is admitted through
/// the request's admission run again, which knows no organization, and ends
/// when its user is removed from the organization.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_connect_stream_into_an_organization_is_admitted_and_ends_on_its_users_removal() {
    let pool = database().await;
    let a = account(&pool, "connect_org").await;
    let org_id = organization_of(&pool, &[&a]).await;
    let (member_org, member_user) = (org_id.clone(), a.user_id.clone());
    fenced_connect_stream(
        &pool,
        &a,
        Some(org_id),
        "membership",
        "permission_denied",
        "access revoked",
        || async {
            sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
                .bind(&member_org)
                .bind(&member_user)
                .execute(&pool)
                .await
                .expect("remove the member");
        },
    )
    .await;
}

/// Opens a fenced Connect stream as `a`'s session, into `organization` when
/// given, checks it is admitted, runs `revoke`, and checks the stream ends
/// with `code` and `message`, audited as `revocation`.
async fn fenced_connect_stream<F, R>(
    pool: &PgPool,
    a: &Account,
    organization: Option<String>,
    revocation: &str,
    code: &str,
    message: &str,
    revoke: F,
) where
    F: FnOnce() -> R,
    R: std::future::Future<Output = ()>,
{
    let fence = Fence::new();
    let listener = fence.spawn_listener_every(pool.clone(), Duration::from_secs(3600));
    let connect = connectrpc::Router::new().add_service(std::sync::Arc::new(FencedPing {
        fence: fence.clone(),
        pool: pool.clone(),
        organization,
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

    // Give the listener its subscription, then revoke.
    tokio::time::sleep(Duration::from_millis(500)).await;
    revoke().await;
    let (flags, end) = tokio::time::timeout(
        Duration::from_secs(10),
        next_frame(&mut response, &mut buffer),
    )
    .await
    .expect("the stream ended within the bound, through the wake-up");
    assert_eq!(flags & 0x02, 0x02, "an end-of-stream frame: {end}");
    assert_eq!(end["error"]["code"], code);
    assert_eq!(end["error"]["message"], message);

    let audited: Vec<(String, String)> = sqlx::query_as(
        "SELECT metadata->>'revocation', metadata->>'surface' FROM audit_logs \
         WHERE action = 'stream.revoked' AND user_id = $1",
    )
    .bind(&a.user_id)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(audited, vec![(revocation.to_owned(), "test".to_owned())]);
    listener.abort();
    server.abort();
}

/// A stream's admission into an organization answers as the request's own
/// access check does when it reads the membership first: a non-member is
/// told the organization isn't found, and a member of an organization being
/// deleted is told so, never "access revoked".
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_connect_stream_into_an_organization_is_refused_as_its_access_check_would_be() {
    let pool = database().await;
    let a = account(&pool, "connect_refused").await;
    let b = account(&pool, "connect_other").await;
    let others = organization_of(&pool, &[&b]).await;
    let end = fenced_connect_refusal(&pool, &a, others).await;
    assert_eq!(end["error"]["code"], "not_found", "{end}");
    assert_eq!(end["error"]["message"], "organization not found");

    let own = organization_of(&pool, &[&a]).await;
    start_deletion(&pool, &own).await;
    let end = fenced_connect_refusal(&pool, &a, own).await;
    let expected = crate::revocation::ended_error(Revocation::Organization);
    assert_eq!(end["error"]["code"], expected.code.as_str(), "{end}");
    assert_eq!(end["error"]["message"], crate::org::ORGANIZATION_DELETING);
}

/// Opens a fenced Connect stream as `a`'s session into `organization` and
/// returns the end that refuses it.
async fn fenced_connect_refusal(
    pool: &PgPool,
    a: &Account,
    organization: String,
) -> serde_json::Value {
    let connect = connectrpc::Router::new().add_service(std::sync::Arc::new(FencedPing {
        fence: Fence::new(),
        pool: pool.clone(),
        organization: Some(organization),
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
    let mut buffer = Vec::new();
    let (flags, end) = tokio::time::timeout(
        Duration::from_secs(10),
        next_frame(&mut response, &mut buffer),
    )
    .await
    .expect("the refusal");
    assert_eq!(flags & 0x02, 0x02, "an end-of-stream frame: {end}");
    server.abort();
    end
}

/// An organization with these accounts as members, the first its owner.
pub(super) async fn organization_of(pool: &PgPool, members: &[&Account]) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let org_id = format!("org_members_{suffix}");
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $2, $3)")
        .bind(&org_id)
        .bind(format!("members-{suffix}"))
        .bind(&members[0].user_id)
        .execute(pool)
        .await
        .expect("org");
    for (index, member) in members.iter().enumerate() {
        add_member(
            pool,
            &org_id,
            &member.user_id,
            if index == 0 { "owner" } else { "member" },
        )
        .await;
    }
    org_id
}

pub(super) async fn add_member(pool: &PgPool, org_id: &str, user_id: &str, role: &str) {
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(uuid::Uuid::new_v4().simple().to_string())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .expect("member");
}

pub(super) async fn remove_member(pool: &PgPool, org_id: &str, user_id: &str) {
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("removal");
}

pub(super) async fn start_deletion(pool: &PgPool, org_id: &str) {
    execute(
        pool,
        "UPDATE organizations SET deletion_state = 'deleting', deletion_generation = 1, \
         deletion_operation_id = 'synthetic-operation', deletion_workflow_id = 'synthetic-workflow', \
         deletion_requested_at = NOW(), deletion_phase = 'synthetic_phase' WHERE id = $1",
        org_id,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_removal_ends_only_that_members_streams_into_that_organization() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let owner = account(&pool, "removal_owner").await;
    let member = account(&pool, "removal_member").await;
    let shared = organization_of(&pool, &[&owner, &member]).await;
    let other = organization_of(&pool, &[&member]).await;
    let removed = admitted(
        &fence,
        &pool,
        &session(&member.user_id, &member.session_id).in_organization(&shared),
    )
    .await;
    let elsewhere = admitted(
        &fence,
        &pool,
        &session(&member.user_id, &member.session_id).in_organization(&other),
    )
    .await;
    let owners = admitted(
        &fence,
        &pool,
        &session(&owner.user_id, &owner.session_id).in_organization(&shared),
    )
    .await;

    remove_member(&pool, &shared, &member.user_id).await;
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&removed), Some(Revocation::Membership));
    assert_eq!(
        revoked_now(&elsewhere),
        None,
        "the member's other organization runs on"
    );
    assert_eq!(
        revoked_now(&owners),
        None,
        "another member's stream runs on"
    );

    // Removed, the member is refused at admission; invited back, admitted at
    // once, and the old row ends nothing.
    assert_eq!(
        fence
            .admit(
                &pool,
                &session(&member.user_id, &member.session_id).in_organization(&shared),
                async { Ok(()) },
            )
            .await
            .err(),
        Some(Refused::NotMember)
    );
    add_member(&pool, &shared, &member.user_id, "member").await;
    let back = admitted(
        &fence,
        &pool,
        &session(&member.user_id, &member.session_id).in_organization(&shared),
    )
    .await;
    let mut fresh = LogCursor::default();
    backstop(&fence, &pool, &mut fresh).await;
    assert_eq!(
        revoked_now(&back),
        None,
        "a row the admission saw never ends it"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_deletion_start_ends_every_members_streams_into_the_organization() {
    let pool = database().await;
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, &pool, &mut cursor).await;
    let owner = account(&pool, "deletion_owner").await;
    let member = account(&pool, "deletion_member").await;
    let deleted = organization_of(&pool, &[&owner, &member]).await;
    let other = organization_of(&pool, &[&member]).await;
    let owners = admitted(
        &fence,
        &pool,
        &session(&owner.user_id, &owner.session_id).in_organization(&deleted),
    )
    .await;
    let members = admitted(
        &fence,
        &pool,
        &Admitted {
            user_id: member.user_id.clone(),
            credential: AdmittedCredential::ApiKey {
                key_id: member.key_id.clone(),
            },
            organization: Some(deleted.clone()),
        },
    )
    .await;
    let elsewhere = admitted(
        &fence,
        &pool,
        &session(&member.user_id, &member.session_id).in_organization(&other),
    )
    .await;

    start_deletion(&pool, &deleted).await;
    backstop(&fence, &pool, &mut cursor).await;
    assert_eq!(revoked_now(&owners), Some(Revocation::Organization));
    assert_eq!(revoked_now(&members), Some(Revocation::Organization));
    assert_eq!(revoked_now(&elsewhere), None);
    assert_eq!(
        fence
            .admit(
                &pool,
                &session(&owner.user_id, &owner.session_id).in_organization(&deleted),
                async { Ok(()) },
            )
            .await
            .err(),
        Some(Refused::OrganizationDeleting),
        "an organization being deleted admits no stream"
    );
}

/// A removal committed between the caller's admission and the stream's
/// registration is seen by the registration's re-read (cw-security, ruling
/// (c)), on the pool the admission registers with.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_removal_between_admission_and_registration_refuses_the_stream() {
    let pool = database().await;
    let fence = Fence::new();
    let owner = account(&pool, "race_owner").await;
    let member = account(&pool, "race_member").await;
    let shared = organization_of(&pool, &[&owner, &member]).await;
    // The caller's own check admitted the member; the removal commits while
    // the stream's credential is read again.
    let refused = fence
        .admit(
            &pool,
            &session(&member.user_id, &member.session_id).in_organization(&shared),
            async {
                remove_member(&pool, &shared, &member.user_id).await;
                Ok(())
            },
        )
        .await;
    assert_eq!(refused.err(), Some(Refused::NotMember));
}
