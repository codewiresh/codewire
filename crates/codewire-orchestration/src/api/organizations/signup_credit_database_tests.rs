//! A new organization gets the sign-up credit current at its creation, once,
//! and nothing while the setting is 0 (#3381, owner, 2026-11-10). Only a
//! sign-in creates one; an API key is refused (#5863).

use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use sqlx::PgPool;

use super::CreateOrgBody;
use super::create::{create_organization_core, grant_signup_credit};
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

async fn slug_exists(pool: &PgPool, slug: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)")
        .bind(slug)
        .fetch_one(pool)
        .await
        .unwrap()
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

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_api_key_cannot_create_an_organization_and_a_sign_in_can() {
    let fixture = LeaseFixture::seed("synthetic-org-create-credential").await;
    let state = crate::api::test_state::offline(fixture.pool.clone()).await;
    let body = |slug: &str| CreateOrgBody {
        name: "Scratch organization".into(),
        slug: slug.into(),
    };
    let session = AuthUser {
        user_id: fixture.id.clone(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    let api_key = AuthUser {
        org_id: Some(fixture.id.clone()),
        via_api_key: true,
        ..session.clone()
    };
    let keyed = format!("key-{}", &fixture.id[6..18]);
    let signed_in = format!("signed-in-{}", &fixture.id[6..18]);

    let refused = create_organization_core(state.clone(), api_key, body(&keyed)).await;
    match refused {
        Err(AppError::Coded { code, detail, .. }) => {
            assert_eq!(code, "api_key_scope_violation");
            assert!(
                detail.contains("organizations are made from a sign-in"),
                "{detail}"
            );
        }
        other => panic!("an API key's create must be refused, got {other:?}"),
    }
    assert!(!slug_exists(&fixture.pool, &keyed).await);

    let created = create_organization_core(state, session, body(&signed_in))
        .await
        .unwrap();
    assert!(slug_exists(&fixture.pool, &signed_in).await);

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&created.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
}
