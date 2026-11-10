//! A new organization gets the sign-up credit current at its creation, once,
//! and nothing while the setting is 0 (#3381, owner, 2026-11-10).

use sqlx::PgPool;

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

async fn set_signup_credit(pool: &PgPool, cents: i32) {
    sqlx::query(
        "UPDATE billing_catalog_settings SET int_value = $1 \
          WHERE setting_key = 'signup_credit_cents'",
    )
    .bind(cents)
    .execute(pool)
    .await
    .unwrap();
}

/// Creates an organization the way `create_organization_core` does and
/// returns what it was granted.
async fn create(pool: &PgPool, owner: &str, id: &str) -> Option<i64> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)")
        .bind(id)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .unwrap();
    let granted = grant_signup_credit(&mut tx, id).await.unwrap();
    tx.commit().await.unwrap();
    granted
}

async fn credit(pool: &PgPool, id: &str) -> (i64, Vec<(String, i64, String)>) {
    let balance: Option<i64> = sqlx::query_scalar(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap();
    let rows = sqlx::query_as(
        "SELECT entry_kind, amount_nano_eur, idempotency_key FROM billing_credit_ledger \
          WHERE organization_id = $1",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .unwrap();
    (balance.unwrap_or(0), rows)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_new_organization_gets_the_current_signup_credit_once() {
    let fixture = LeaseFixture::seed("synthetic-signup-credit").await;
    let pool = &fixture.pool;
    let (off, on, later) = (
        format!("{}-off", fixture.id),
        format!("{}-on", fixture.id),
        format!("{}-later", fixture.id),
    );

    // Off by default: no row, no balance.
    set_signup_credit(pool, 0).await;
    assert_eq!(create(pool, &fixture.id, &off).await, None);
    assert_eq!(credit(pool, &off).await, (0, Vec::new()));

    // EUR 10 at creation is one grant of EUR 10.
    set_signup_credit(pool, 1_000).await;
    assert_eq!(create(pool, &fixture.id, &on).await, Some(10_000_000_000));
    let granted = (
        10_000_000_000,
        vec![(
            "grant".to_owned(),
            10_000_000_000,
            "signup_credit".to_owned(),
        )],
    );
    assert_eq!(credit(pool, &on).await, granted);

    // A second grant for the same organization is refused, not doubled.
    let mut tx = pool.begin().await.unwrap();
    assert!(grant_signup_credit(&mut tx, &on).await.is_err());
    tx.rollback().await.unwrap();
    assert_eq!(credit(pool, &on).await, granted);

    // A later change applies to organizations created after it, never before.
    set_signup_credit(pool, 2_500).await;
    assert_eq!(
        create(pool, &fixture.id, &later).await,
        Some(25_000_000_000)
    );
    assert_eq!(credit(pool, &on).await, granted);
    assert_eq!(credit(pool, &off).await, (0, Vec::new()));

    set_signup_credit(pool, 0).await;
    for id in [&off, &on, &later] {
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
}
