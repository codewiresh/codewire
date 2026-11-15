use std::sync::Arc;

use sqlx::PgPool;

use super::*;
use codewire_server_core::credit_enforcement::CreditEnforcement;

async fn test_pool() -> Option<PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL unset; skipping the credit changes database flow");
            return None;
        }
    };
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect credit changes test database"),
    )
}

/// An organization on the regular card with no card and no credit.
async fn organization(pool: &PgPool) -> (String, String) {
    let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(pool)
        .await
        .unwrap();
    let (organization_id, user_id) = (
        format!("org_changes_{namespace}"),
        format!("u_changes_{namespace}"),
    );
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(format!("{namespace}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, 'Changes', $2, $3)",
    )
    .bind(&organization_id)
    .bind(format!("changes-{}", &namespace[..8]))
    .bind(&user_id)
    .execute(pool)
    .await
    .unwrap();
    (organization_id, user_id)
}

/// An administrator's adjustment of −€1, as on Dev (#4754).
async fn adjust_below_zero(pool: &PgPool, (organization_id, actor): &(String, String)) {
    sqlx::query(
        "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, \
         idempotency_key, actor_user_id, reason) \
         VALUES ($1, 'adjustment', -1000000000, gen_random_uuid()::text, $2, 'test')",
    )
    .bind(organization_id)
    .bind(actor)
    .execute(pool)
    .await
    .unwrap();
}

async fn marked(pool: &PgPool, organization_id: &str) -> bool {
    sqlx::query_scalar("SELECT credit_exhausted_at IS NOT NULL FROM organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn db_a_credit_change_names_its_organization_and_settling_it_marks_it_at_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let deps = MeteringDeps {
        pool: pool.clone(),
        stripe: Arc::new(crate::stripe_client::StripeHandle::default()),
        email: Arc::new(crate::email::EmailClient::disabled()),
        database_url: String::new(),
        credit_enforcement: CreditEnforcement::On,
        webhook_self_url: String::new(),
    };
    let (first_fixture, second_fixture) = (organization(&pool).await, organization(&pool).await);
    let (first, second) = (first_fixture.0.clone(), second_fixture.0.clone());
    let mut listener = PgListener::connect_with(&pool).await.unwrap();
    listener.listen(CHANNEL).await.unwrap();

    // Two organizations' changes in quick succession are gathered into one
    // pass. Other tests' changes may arrive too; only these two are settled.
    adjust_below_zero(&pool, &first_fixture).await;
    adjust_below_zero(&pool, &second_fixture).await;
    let ours = BTreeSet::from([first.clone(), second.clone()]);
    let mut due = BTreeSet::new();
    // Generous: the notices come in milliseconds; this only stops a hang.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !ours.is_subset(&due) {
        let first = tokio::time::timeout_at(deadline, listener.try_recv())
            .await
            .expect("both organizations' changes are notified")
            .unwrap()
            .expect("the listener's connection stays up");
        due.extend(gather(&mut listener, first).await.unwrap());
    }
    assert!(!marked(&pool, &first).await && !marked(&pool, &second).await);

    // Settling them marks both out of credit at once (no card, so nothing
    // to charge), rather than at the minute's tick.
    settle(&deps, &ours).await;
    assert!(marked(&pool, &first).await && marked(&pool, &second).await);
}
