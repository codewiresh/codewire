//! LiveService.Watch through the mount `main` uses (#4762): it refuses a
//! caller with no credential, scopes an API key to its own organization, and
//! is a stream, not a unary call, so a watch outlives the unary dispatcher's
//! 60-second deadline.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::http::header::AUTHORIZATION;
use codewire_proto::codewire::console::v1::{
    LiveServiceClient, WatchRequest, WatchResponse, watch_response::Event,
};
use codewire_server_core::auth::{AuthState, api_key_prefix, generate_api_key, hash_api_key};
use connectrpc::ErrorCode;
use connectrpc::client::{ClientConfig, HttpClient};

use super::*;
use crate::api::live::start;
use crate::test_database_support::TestDatabase;

/// Past the unary dispatcher's 60-second cap, with a heartbeat to spare.
const PAST_THE_UNARY_DEADLINE: Duration = Duration::from_secs(65);
/// The longest any one wait may take.
const HANG: Duration = Duration::from_secs(30);

async fn serve(db: &TestDatabase) -> anyhow::Result<SocketAddr> {
    let router = router_for(db.pool.clone(), start(db.pool.clone()), Drain::default());
    let app = AppBuilder::new("live-watch-test")
        .with_live_watch(
            router,
            ConnectAuthLayer::authenticated(AuthState {
                pool: db.pool.clone(),
            }),
        )
        .into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    Ok(addr)
}

fn client(addr: SocketAddr, api_key: Option<&str>) -> LiveServiceClient<HttpClient> {
    let mut config = ClientConfig::new(format!("http://{addr}").parse().expect("base URI"));
    if let Some(key) = api_key {
        config = config.with_default_header(AUTHORIZATION, format!("Bearer {key}"));
    }
    LiveServiceClient::new(HttpClient::plaintext_http2_only(), config)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_watch_is_an_authenticated_scoped_stream_that_outlives_the_unary_deadline()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user("live-mount-user").await?;
        for org in ["live-mount-a", "live-mount-b"] {
            db.organization(org).await?;
            sqlx::query(
                "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, 'live-mount-user', 'member')",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(org)
            .execute(&db.pool)
            .await?;
        }
        let api_key = generate_api_key();
        sqlx::query(
            "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
             VALUES ('live-mount-key', 'live-mount-user', 'live-mount-a', 'live', $1, $2)",
        )
        .bind(hash_api_key(&api_key))
        .bind(api_key_prefix(&api_key))
        .execute(&db.pool)
        .await?;
        let addr = serve(&db).await?;

        // No credential: refused before any watch opens.
        let refused = tokio::time::timeout(HANG, async {
            let mut stream = client(addr, None).watch(WatchRequest::default()).await?;
            stream.message::<WatchResponse>().await.map(|_| ())
        })
        .await?
        .expect_err("a watch without a credential must be refused");
        anyhow::ensure!(refused.code == ErrorCode::Unauthenticated, "{refused:?}");

        // An API key for organization A: its stream carries A, never B, and
        // keeps going past the unary deadline.
        let mut stream =
            tokio::time::timeout(HANG, client(addr, Some(&api_key)).watch(WatchRequest::default()))
                .await??;
        let opened = Instant::now();
        let mut heartbeats = 0;
        let mut credited = Vec::new();
        let mut notified = false;
        while opened.elapsed() < PAST_THE_UNARY_DEADLINE {
            let Some(message) = tokio::time::timeout(HANG, stream.message::<WatchResponse>())
                .await??
            else {
                anyhow::bail!("the watch ended after {:?}", opened.elapsed());
            };
            match message.to_owned_message().event {
                Some(Event::Resync(_)) if !notified => {
                    // Notices go out once the watch has started.
                    for org in ["live-mount-b", "live-mount-a"] {
                        sqlx::query("SELECT pg_notify('credit_changes', $1)")
                            .bind(org)
                            .execute(&db.pool)
                            .await?;
                    }
                    notified = true;
                }
                Some(Event::Credit(credit)) => credited.push(credit.org_id),
                Some(Event::Heartbeat(_)) => heartbeats += 1,
                _ => {}
            }
        }
        anyhow::ensure!(credited.iter().all(|org| org == "live-mount-a"), "{credited:?}");
        anyhow::ensure!(credited.iter().any(|org| org == "live-mount-a"), "{credited:?}");
        anyhow::ensure!(heartbeats >= 4, "{heartbeats} heartbeats in {PAST_THE_UNARY_DEADLINE:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
