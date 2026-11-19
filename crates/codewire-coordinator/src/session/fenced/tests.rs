//! An environment's replica drops a client peer from another replica on its
//! own read of the revocation log, with no remove message from the replica
//! that admitted it (#3586, step 3; cw-security's bound 3, 2026-11-18).

use std::time::Duration;

use codewire_server_core::revocation::{Admitted, Fence};

use super::*;

const REVOCATION_BOUND: Duration = Duration::from_secs(35);

/// A replica's fence with its listener running, once it has read the log.
async fn replica(pool: &PgPool, probe: &Admitted) -> (Revocations, tokio::task::JoinHandle<()>) {
    let fence = Fence::new();
    let listener = fence.spawn_listener(pool.clone());
    let watch = fence
        .admit(pool, probe, async { Ok(()) })
        .await
        .expect("probe admitted");
    for _ in 0..100 {
        if fence.carry(probe, &watch).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (
        Revocations {
            fence,
            pool: pool.clone(),
        },
        listener,
    )
}

#[tokio::test]
async fn a_remote_client_is_dropped_by_the_serving_replica_alone() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping remote client revocation");
        return;
    };
    let pool = PgPool::connect(&database_url).await.unwrap();
    let ns = Uuid::new_v4().simple().to_string();
    let user_id = format!("u_coord_fenced_{ns}");
    let session_id = format!("s_coord_fenced_{ns}");
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $1 || '@coordinator-fenced.test')")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
         VALUES ($1, $2, NOW() + interval '1 hour', encode(sha256($1::bytea), 'hex'))",
    )
    .bind(&session_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let admitted = Admitted::session(&user_id, &session_id);

    // The replica that admitted the client, and the one serving its
    // environment. Nothing passes between them but the carried admission.
    let (origin, origin_listener) = replica(&pool, &admitted).await;
    let (serving, serving_listener) = replica(&pool, &admitted).await;
    let at_origin = origin
        .fence
        .admit(&pool, &admitted, async { Ok(()) })
        .await
        .unwrap();
    let carried = origin
        .fence
        .carry(&admitted, &at_origin)
        .expect("the origin has read the log");

    let peer_id = Uuid::new_v4();
    let mut clients = RemoteClients::default();
    assert!(clients.admit(&serving, peer_id, Some(&carried)).await);

    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&session_id)
        .execute(&pool)
        .await
        .unwrap();
    let dropped = tokio::time::timeout(REVOCATION_BOUND, clients.next_revoked())
        .await
        .expect("dropped within the bound");
    assert_eq!(dropped, peer_id);
    assert!(
        !clients.admit(&serving, peer_id, Some(&carried)).await,
        "a later node of the dropped peer is not forwarded"
    );
    origin_listener.abort();
    serving_listener.abort();
}

#[tokio::test]
async fn a_remote_client_without_an_admission_is_forwarded_and_counted_once() {
    let revocations = crate::test_revocations();
    let mut clients = RemoteClients::default();
    let peer_id = Uuid::new_v4();
    assert!(clients.admit(&revocations, peer_id, None).await);
    assert!(clients.admit(&revocations, peer_id, None).await);
    assert_eq!(clients.unfenced.len(), 1, "logged once per peer");
    clients.remove(peer_id);
    assert!(clients.unfenced.is_empty());
}
