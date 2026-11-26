//! A hello naming a suspended Sandbox asks for its wake, only once the hello
//! is authorized for that Sandbox (#5529, `docs/dev/IDLE-STOP.md`,
//! "Suspend"): a refused hello sends nothing.

use codewire_server_core::environment_wake::CHANNEL;
use sqlx::postgres::PgListener;

use super::*;

async fn nothing_sent(listener: &mut PgListener) -> bool {
    tokio::time::timeout(std::time::Duration::from_millis(300), listener.try_recv())
        .await
        .is_err()
}

#[tokio::test]
async fn only_an_authorized_hello_for_a_suspended_sandbox_asks_for_its_wake() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping coordinator hello wake");
        return;
    };
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let fixtures = seed_production_auth_fixtures(&pool).await;
    for environment_id in [fixtures.env_a, fixtures.env_b] {
        sqlx::query("UPDATE environments SET suspended_at = NOW() WHERE id = $1")
            .bind(environment_id.to_string())
            .execute(&pool)
            .await
            .unwrap();
    }
    // The user isn't a member of the second organization.
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&fixtures.org_b)
        .bind(&fixtures.user_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut listener = PgListener::connect_with(&pool).await.unwrap();
    listener.listen(CHANNEL).await.unwrap();

    // Refused: no wake is asked for, though the Sandbox is suspended.
    let refused = production_auth_outcome(
        pool.clone(),
        Protocol::Connect,
        session_headers(&fixtures.session_token),
        &fixtures.org_b,
        fixtures.env_b,
    )
    .await;
    assert!(
        !matches!(refused, ProductionAuthOutcome::DerpMap),
        "{refused:?}"
    );
    assert!(nothing_sent(&mut listener).await);

    // Authorized: its own Sandbox's wake, and nothing else.
    let admitted = production_auth_outcome(
        pool.clone(),
        Protocol::Connect,
        session_headers(&fixtures.session_token),
        &fixtures.org_a,
        fixtures.env_a,
    )
    .await;
    assert!(matches!(admitted, ProductionAuthOutcome::DerpMap));
    let sent = tokio::time::timeout(std::time::Duration::from_secs(5), listener.try_recv())
        .await
        .expect("a wake was asked for")
        .unwrap()
        .expect("the listener kept its connection");
    assert_eq!(sent.payload(), fixtures.env_a.to_string());
    assert!(nothing_sent(&mut listener).await);
}
