//! A carried admission against the database: the receiving replica refuses a
//! peer whose credential was revoked before it arrived, fences it from then
//! on with no remove message, and refuses a position the log can't vouch for
//! (#3586, step 3; `docs/journeys/account-access.md` `access-tailnet`). Run
//! with `--ignored` against a database migrated through
//! `credential_revocations`.

use super::super::database_tests::{
    Account, account, admitted, backstop, database, execute, organization_of, revoked_now,
    start_deletion,
};
use super::*;
use crate::revocation::{LogCursor, Revocation};

fn by_token(a: &Account) -> Admitted {
    Admitted {
        user_id: a.user_id.clone(),
        credential: AdmittedCredential::OAuthToken {
            token_hash: a.token_hash.clone(),
            client_id: "codewire-cli".into(),
        },
        organization: None,
    }
}

/// One replica's fence and its own read of the log, read once.
async fn replica(pool: &PgPool) -> (Fence, LogCursor) {
    let fence = Fence::new();
    let mut cursor = LogCursor::default();
    backstop(&fence, pool, &mut cursor).await;
    (fence, cursor)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_serving_replica_ends_a_carried_peer_on_its_own_read_of_the_log() {
    let pool = database().await;
    let (origin, _) = replica(&pool).await;
    let (serving, mut serving_cursor) = replica(&pool).await;
    let a = account(&pool, "carried_live").await;
    let token = by_token(&a);
    let at_origin = admitted(&origin, &pool, &token).await;
    let carried = origin
        .carry(&token, &at_origin)
        .expect("the origin has read the log");

    let (_, peer) = serving
        .admit_carried(&pool, &carried)
        .await
        .expect("nothing names the token after the carried position");

    // No remove message reaches the serving replica: only its own read.
    execute(
        &pool,
        "DELETE FROM oidc_access_tokens WHERE token_hash = $1",
        &a.token_hash,
    )
    .await;
    backstop(&serving, &pool, &mut serving_cursor).await;
    assert_eq!(revoked_now(&peer), Some(Revocation::OAuthToken));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_revocation_before_the_peer_arrives_refuses_it() {
    let pool = database().await;
    let (origin, _) = replica(&pool).await;
    let (serving, _) = replica(&pool).await;
    let a = account(&pool, "carried_late").await;
    let token = by_token(&a);
    let at_origin = admitted(&origin, &pool, &token).await;
    let carried = origin
        .carry(&token, &at_origin)
        .expect("the origin has read the log");

    // Revoked after the origin carried it, before the serving replica
    // registered it: that registration's snapshot already sees the row, so
    // only the look-back past the carried position can refuse the peer.
    execute(
        &pool,
        "UPDATE users SET enabled = false WHERE id = $1",
        &a.user_id,
    )
    .await;
    assert_eq!(
        serving.admit_carried(&pool, &carried).await.err(),
        Some(Refused::Revoked)
    );

    // Another user's revocation after the position names nothing here.
    let b = account(&pool, "carried_other").await;
    let other = by_token(&b);
    let b_at_origin = admitted(&origin, &pool, &other).await;
    let b_carried = origin.carry(&other, &b_at_origin).expect("carried");
    execute(&pool, "DELETE FROM sessions WHERE id = $1", &a.session_id).await;
    assert!(serving.admit_carried(&pool, &b_carried).await.is_ok());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_position_beyond_the_log_is_refused() {
    let pool = database().await;
    let (origin, _) = replica(&pool).await;
    let (serving, _) = replica(&pool).await;
    let a = account(&pool, "carried_ahead").await;
    let token = by_token(&a);
    let at_origin = admitted(&origin, &pool, &token).await;
    let mut carried = origin
        .carry(&token, &at_origin)
        .expect("the origin has read the log");
    carried.through = i64::MAX;
    assert_eq!(
        serving.admit_carried(&pool, &carried).await.err(),
        Some(Refused::Revoked)
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_carried_peer_whose_organization_started_deletion_after_the_position_is_refused() {
    let pool = database().await;
    let (origin, _) = replica(&pool).await;
    let (serving, mut serving_cursor) = replica(&pool).await;
    let a = account(&pool, "carried_org").await;
    let org_id = organization_of(&pool, &[&a]).await;
    let token = by_token(&a).in_organization(&org_id);
    let at_origin = admitted(&origin, &pool, &token).await;
    let carried = origin.carry(&token, &at_origin).expect("carried");
    let (_, peer) = serving
        .admit_carried(&pool, &carried)
        .await
        .expect("nothing names the organization yet");

    start_deletion(&pool, &org_id).await;
    backstop(&serving, &pool, &mut serving_cursor).await;
    assert_eq!(revoked_now(&peer), Some(Revocation::Organization));
    assert_eq!(
        serving.admit_carried(&pool, &carried).await.err(),
        Some(Refused::Revoked),
        "the carried organization travels with the peer"
    );
}
