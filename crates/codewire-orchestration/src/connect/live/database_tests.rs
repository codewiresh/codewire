//! LiveService.Watch through the mount `main` uses (#4762): it refuses a
//! caller with no credential, scopes an API key to its own organization, and
//! is a stream, not a unary call, so a watch outlives the unary dispatcher's
//! 60-second deadline.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::header::AUTHORIZATION;
use codewire_proto::codewire::console::v1::{
    LiveServiceClient, WatchRequest, WatchResponse, watch_response::Event,
};
use codewire_server_core::auth::{AuthState, api_key_prefix, generate_api_key, hash_api_key};
use codewire_server_core::connect::CONNECT_UNARY_SERVER_TIMEOUT;
use connectrpc::ErrorCode;
use connectrpc::client::{ClientConfig, HttpClient};

use super::*;
use crate::api::live::start;
use crate::test_database_support::TestDatabase;

/// Short test heartbeat so the watch proves multiple heartbeats in under a second.
const TEST_HEARTBEAT: Duration = Duration::from_millis(150);
/// Window long enough for >= 4 heartbeats at `TEST_HEARTBEAT`.
const WATCH_WINDOW: Duration = Duration::from_millis(700);
/// The longest any one wait may take.
const HANG: Duration = Duration::from_secs(30);

type ObservedDeadline = Arc<Mutex<Option<Option<Duration>>>>;

async fn serve(db: &TestDatabase) -> anyhow::Result<(SocketAddr, ObservedDeadline)> {
    let observed = Arc::new(Mutex::new(None));
    let router = router_for_test(
        db.pool.clone(),
        start(db.pool.clone()),
        Drain::default(),
        TEST_HEARTBEAT,
        Arc::clone(&observed),
    );
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
    Ok((addr, observed))
}

async fn serve_on_unary_mount(db: &TestDatabase) -> anyhow::Result<(SocketAddr, ObservedDeadline)> {
    let observed = Arc::new(Mutex::new(None));
    let router = router_for_test(
        db.pool.clone(),
        start(db.pool.clone()),
        Drain::default(),
        TEST_HEARTBEAT,
        Arc::clone(&observed),
    );
    let app = AppBuilder::new("live-watch-unary-control")
        .with_unary_connect_routes_auth(
            router,
            ConnectAuthLayer::authenticated(AuthState {
                pool: db.pool.clone(),
            }),
        )
        .into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    Ok((addr, observed))
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
        let (addr, live_deadline) = serve(&db).await?;
        let (unary_addr, unary_deadline) = serve_on_unary_mount(&db).await?;

        // Negative control: mounting `LiveService` via
        // `with_unary_connect_routes_auth` attaches the 60-second server
        // deadline to the request context.
        let mut unary_stream = tokio::time::timeout(
            HANG,
            client(unary_addr, Some(&api_key)).watch(WatchRequest::default()),
        )
        .await??;
        let first = tokio::time::timeout(HANG, unary_stream.message::<WatchResponse>()).await??;
        anyhow::ensure!(
            matches!(
                first.map(|m| m.to_owned_message().event),
                Some(Some(Event::Resync(_)))
            ),
            "unary control watch did not open"
        );
        drop(unary_stream);
        let unary_seen = *unary_deadline.lock().expect("unary deadline slot");
        anyhow::ensure!(
            matches!(unary_seen, Some(Some(remaining)) if remaining <= CONNECT_UNARY_SERVER_TIMEOUT),
            "expected unary control mount to attach a <= 60s server deadline, got {unary_seen:?}"
        );

        // No credential: refused before any watch opens.
        let refused = tokio::time::timeout(HANG, async {
            let mut stream = client(addr, None).watch(WatchRequest::default()).await?;
            stream.message::<WatchResponse>().await.map(|_| ())
        })
        .await?
        .expect_err("a watch without a credential must be refused");
        anyhow::ensure!(refused.code == ErrorCode::Unauthenticated, "{refused:?}");

        // An API key for organization A: its stream carries A, never B, has no
        // server-applied unary deadline, and keeps heartbeating across the window.
        let mut stream =
            tokio::time::timeout(HANG, client(addr, Some(&api_key)).watch(WatchRequest::default()))
                .await??;
        let opened = Instant::now();
        let mut heartbeats = 0;
        let mut credited = Vec::new();
        let mut notified = false;
        while opened.elapsed() < WATCH_WINDOW {
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
        let live_seen = *live_deadline.lock().expect("live deadline slot");
        anyhow::ensure!(
            live_seen == Some(None),
            "with_live_watch must not attach a server deadline, got {live_seen:?}"
        );
        anyhow::ensure!(credited.iter().all(|org| org == "live-mount-a"), "{credited:?}");
        anyhow::ensure!(credited.iter().any(|org| org == "live-mount-a"), "{credited:?}");
        anyhow::ensure!(heartbeats >= 4, "{heartbeats} heartbeats in {WATCH_WINDOW:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
