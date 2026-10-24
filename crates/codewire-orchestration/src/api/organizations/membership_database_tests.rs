//! An organization's API keys act only for its current members (#3254).
//! Removal disables the member's keys for that organization, and
//! authentication also refuses a key whose membership was deleted earlier.

use codewire_server_core::auth::{
    AuthState, api_key_prefix, authenticate, generate_api_key, hash_api_key,
};

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

async fn execute(fixture: &LeaseFixture, sql: &str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    query.execute(&fixture.pool).await.unwrap();
}

/// Inserts an API key for `user_id` bound to `org_id` and returns it.
async fn insert_key(fixture: &LeaseFixture, id: &str, user_id: &str, org_id: &str) -> String {
    let key = generate_api_key();
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, $1, $4, $5)",
    )
    .bind(id)
    .bind(user_id)
    .bind(org_id)
    .bind(hash_api_key(&key))
    .bind(api_key_prefix(&key))
    .execute(&fixture.pool)
    .await
    .unwrap();
    key
}

async fn authenticates(fixture: &LeaseFixture, key: &str) -> bool {
    let state = AuthState {
        pool: fixture.pool.clone(),
    };
    match authenticate(&state, None, Some(key)).await {
        Ok(_) => true,
        Err(AppError::Unauthorized) => false,
        Err(error) => panic!("unexpected authentication error: {error:?}"),
    }
}

async fn key_disabled(fixture: &LeaseFixture, id: &str) -> bool {
    sqlx::query_scalar("SELECT disabled_at IS NOT NULL FROM api_keys WHERE id = $1")
        .bind(id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_removed_member_keys_stop_working_and_stay_disabled() {
    // The fixture's ID names its owner user and organization. The member
    // also belongs to a second organization, whose key must keep working.
    let fixture = LeaseFixture::seed("synthetic-membership-credentials").await;
    let org = fixture.id.clone();
    let member = format!("{org}-member");
    let other_org = format!("{org}-other");
    let (org, member, other_org) = (org.as_str(), member.as_str(), other_org.as_str());
    execute(
        &fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Membership credential member', true)",
        &[member],
    )
    .await;
    execute(
        &fixture,
        "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)",
        &[other_org, org],
    )
    .await;
    let join = "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1 || '-' || $2, $1, $2, 'member')";
    execute(&fixture, join, &[org, member]).await;
    execute(&fixture, join, &[other_org, member]).await;
    let key_id = format!("{member}-key");
    let other_key_id = format!("{member}-other-key");
    let key = insert_key(&fixture, &key_id, member, org).await;
    let other_key = insert_key(&fixture, &other_key_id, member, other_org).await;
    assert!(authenticates(&fixture, &key).await);

    // A membership deleted without disabling the key, as removal did before
    // this fix, no longer authenticates the key.
    let leave = "DELETE FROM org_members WHERE org_id = $1 AND user_id = $2";
    execute(&fixture, leave, &[org, member]).await;
    assert!(!key_disabled(&fixture, &key_id).await);
    assert!(!authenticates(&fixture, &key).await);
    execute(&fixture, join, &[org, member]).await;
    assert!(authenticates(&fixture, &key).await);

    // Removal disables the member's keys for that organization only, and a
    // later re-add does not revive them.
    delete_membership(&fixture.pool, org, member).await.unwrap();
    assert!(key_disabled(&fixture, &key_id).await);
    assert!(!key_disabled(&fixture, &other_key_id).await);
    assert!(authenticates(&fixture, &other_key).await);
    execute(&fixture, join, &[org, member]).await;
    assert!(!authenticates(&fixture, &key).await);

    for (sql, binds) in [
        ("DELETE FROM api_keys WHERE user_id = $1", &[member][..]),
        ("DELETE FROM org_members WHERE user_id = $1", &[member]),
        ("DELETE FROM organizations WHERE id = $1", &[other_org]),
        ("DELETE FROM users WHERE id = $1", &[member]),
    ] {
        execute(&fixture, sql, binds).await;
    }
    fixture.cleanup().await;
}
