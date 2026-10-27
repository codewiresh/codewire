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

/// Listing returns each organization with the caller's role and only the
/// caller's own assignments there, from one statement, and an
/// organization-scoped API key sees only its organization.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_listing_reads_every_membership_and_its_assignments_at_once() {
    let fixture = LeaseFixture::seed("synthetic-membership-listing").await;
    let org = fixture.id.clone();
    let member = format!("{org}-member");
    let other_org = format!("{org}-other");
    let (org, member, other_org) = (org.as_str(), member.as_str(), other_org.as_str());
    execute(
        &fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Membership listing member', true)",
        &[member],
    )
    .await;
    execute(
        &fixture,
        "INSERT INTO organizations (id, name, slug, created_by, created_at) \
         VALUES ($1, $1, $1, $2, NOW() + interval '1 minute')",
        &[other_org, org],
    )
    .await;
    let join =
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1 || '-' || $2, $1, $2, $3)";
    execute(&fixture, join, &[org, member, "member"]).await;
    execute(&fixture, join, &[other_org, member, "admin"]).await;
    let assign = "INSERT INTO org_member_assignments (org_member_id, assignment) \
                  VALUES ($1 || '-' || $2, $3)";
    execute(&fixture, assign, &[org, member, "super_admin"]).await;
    execute(&fixture, assign, &[org, member, "auditor"]).await;
    // Another member's assignment in the same organization is not the caller's.
    execute(&fixture, "INSERT INTO org_member_assignments (org_member_id, assignment) VALUES ($1, 'billing_admin')", &[org]).await;

    let user = |org_id: Option<&str>| AuthUser {
        user_id: member.to_owned(),
        org_id: org_id.map(str::to_owned),
        is_admin: false,
        via_api_key: org_id.is_some(),
    };
    let listed = list_memberships(&fixture.pool, &user(None)).await.unwrap();
    let rows: Vec<_> = listed
        .iter()
        .map(|row| {
            let mut assignments = row.assignments.clone();
            assignments.sort();
            (row.id.as_str(), row.role.as_str(), assignments)
        })
        .collect();
    assert_eq!(
        rows,
        [
            (other_org, "admin", Vec::<String>::new()),
            (
                org,
                "member",
                vec!["auditor".to_owned(), "super_admin".to_owned()]
            ),
        ]
    );
    let scoped = list_memberships(&fixture.pool, &user(Some(other_org)))
        .await
        .unwrap();
    assert_eq!(
        scoped.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        [other_org]
    );

    for (sql, binds) in [
        (
            "DELETE FROM org_member_assignments WHERE org_member_id LIKE $1 || '%'",
            &[org][..],
        ),
        ("DELETE FROM org_members WHERE user_id = $1", &[member]),
        ("DELETE FROM organizations WHERE id = $1", &[other_org]),
        ("DELETE FROM users WHERE id = $1", &[member]),
    ] {
        execute(&fixture, sql, binds).await;
    }
    fixture.cleanup().await;
}
