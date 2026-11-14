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
    // Each membership says when the caller joined (#4519).
    assert!(
        listed
            .iter()
            .all(|membership| membership.joined_at.is_some())
    );
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

    // #3747: a create's organization comes from these same memberships. The
    // member has two, so choosing needs a selector; a key sees only its own.
    assert_eq!(
        resolve_create_organization(&fixture.pool, &user(Some(other_org)), "")
            .await
            .unwrap(),
        other_org
    );
    assert_eq!(
        resolve_create_organization(&fixture.pool, &user(None), org)
            .await
            .unwrap(),
        org
    );
    for (caller, selector) in [(user(None), ""), (user(Some(other_org)), org)] {
        resolve_create_organization(&fixture.pool, &caller, selector)
            .await
            .unwrap_err();
    }

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

async fn is_member(fixture: &LeaseFixture, org_id: &str, user_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap()
}

/// Whether listing says `user_id` is `org_id`'s only owner.
async fn listed_as_only_owner(fixture: &LeaseFixture, org_id: &str, user_id: &str) -> bool {
    let caller = AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    list_memberships(&fixture.pool, &caller)
        .await
        .unwrap()
        .into_iter()
        .find(|membership| membership.id == org_id)
        .unwrap()
        .only_owner
}

fn is_last_owner_refusal(result: &AppResult<()>) -> bool {
    matches!(
        result,
        Err(AppError::Coded {
            code: "last_owner",
            ..
        })
    )
}

/// Adds a second owner to the fixture's organization and returns its id.
async fn second_owner(fixture: &LeaseFixture) -> String {
    let owner = format!("{}-co-owner", fixture.id);
    execute(
        fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Second owner', true)",
        &[owner.as_str()],
    )
    .await;
    execute(
        fixture,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1 || '-' || $2, $1, $2, 'owner')",
        &[fixture.id.as_str(), owner.as_str()],
    )
    .await;
    owner
}

async fn remove_user(fixture: &LeaseFixture, user_id: &str) {
    execute(
        fixture,
        "DELETE FROM org_members WHERE user_id = $1",
        &[user_id],
    )
    .await;
    execute(fixture, "DELETE FROM users WHERE id = $1", &[user_id]).await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_owner_leaves_while_another_owner_remains_and_the_last_is_refused() {
    let fixture = LeaseFixture::seed("synthetic-membership-leave").await;
    let org = fixture.id.clone();
    let owner = second_owner(&fixture).await;
    assert!(!listed_as_only_owner(&fixture, &org, &org).await);

    leave_as_owner(&fixture.pool, &org, &owner).await.unwrap();
    assert!(!is_member(&fixture, &org, &owner).await);
    assert!(listed_as_only_owner(&fixture, &org, &org).await);

    // The fixture's owner is now the only one: refused, and still a member.
    let refused = leave_as_owner(&fixture.pool, &org, &org).await;
    assert!(is_last_owner_refusal(&refused), "{refused:?}");
    assert!(is_member(&fixture, &org, &org).await);

    remove_user(&fixture, &owner).await;
    fixture.cleanup().await;
}

async fn owner_count(fixture: &LeaseFixture, org_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'")
        .bind(org_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

/// Runs `contender` while `leaver` is part-way through leaving: its owner
/// check has run and its membership is deleted, but nothing is committed. The
/// contender must wait on the organization's row lock until the leave
/// commits, then count no other owner and be refused, leaving one owner.
async fn contend_with_a_leave_in_progress(
    fixture: &LeaseFixture,
    leaver: &str,
    contender: impl std::future::Future<Output = AppResult<()>> + Send + 'static,
) {
    let org = fixture.id.as_str();
    let mut leave = fixture.pool.begin().await.unwrap();
    lock_organization(&mut leave, org).await.unwrap();
    refuse_only_owner(&mut leave, org, leaver, "")
        .await
        .unwrap();
    delete_membership_in(&mut leave, org, leaver).await.unwrap();

    let mut contender = tokio::spawn(contender);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut contender)
            .await
            .is_err(),
        "the contender went ahead without waiting for the organization's row lock"
    );
    leave.commit().await.unwrap();
    let refused = contender.await.unwrap();
    assert!(is_last_owner_refusal(&refused), "{refused:?}");
    assert_eq!(owner_count(fixture, org).await, 1);
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_owner_leaving_while_the_other_leaves_leaves_one_owner() {
    let fixture = LeaseFixture::seed("synthetic-membership-leave-race").await;
    let org = fixture.id.clone();
    let owner = second_owner(&fixture).await;

    let (pool, org_id) = (fixture.pool.clone(), org.clone());
    contend_with_a_leave_in_progress(&fixture, &owner, async move {
        leave_as_owner(&pool, &org_id, &org_id).await
    })
    .await;
    assert!(is_member(&fixture, &org, &org).await);

    remove_user(&fixture, &owner).await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_owner_leaving_while_the_other_is_demoted_leaves_one_owner() {
    let fixture = LeaseFixture::seed("synthetic-membership-leave-demote-race").await;
    let org = fixture.id.clone();
    let owner = second_owner(&fixture).await;

    let (pool, org_id) = (fixture.pool.clone(), org.clone());
    contend_with_a_leave_in_progress(&fixture, &owner, async move {
        set_member_role(&pool, &org_id, &org_id, "admin", "owner").await
    })
    .await;

    remove_user(&fixture, &owner).await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_only_owner_is_never_demoted() {
    let fixture = LeaseFixture::seed("synthetic-membership-demote").await;
    let org = fixture.id.clone();

    let refused = set_member_role(&fixture.pool, &org, &org, "admin", "owner").await;
    assert!(is_last_owner_refusal(&refused), "{refused:?}");
    assert_eq!(owner_count(&fixture, &org).await, 1);

    let owner = second_owner(&fixture).await;
    set_member_role(&fixture.pool, &org, &owner, "member", "owner")
        .await
        .unwrap();
    assert_eq!(owner_count(&fixture, &org).await, 1);

    remove_user(&fixture, &owner).await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_admin_never_changes_an_owners_or_an_admins_role() {
    let fixture = LeaseFixture::seed("synthetic-membership-admin-role").await;
    let org = fixture.id.clone();
    let owner = second_owner(&fixture).await;
    let forbidden = |result: &AppResult<()>| matches!(result, Err(AppError::Coded { status, .. }) if *status == axum::http::StatusCode::FORBIDDEN);

    // The admin rules read the role the update replaces, inside its
    // transaction, so a promotion that lands first is seen.
    for role in ["member", "admin"] {
        let refused = set_member_role(&fixture.pool, &org, &owner, role, "admin").await;
        assert!(forbidden(&refused), "{refused:?}");
    }
    set_member_role(&fixture.pool, &org, &owner, "admin", "owner")
        .await
        .unwrap();
    let refused = set_member_role(&fixture.pool, &org, &owner, "member", "admin").await;
    assert!(forbidden(&refused), "{refused:?}");
    assert_eq!(owner_count(&fixture, &org).await, 1);

    remove_user(&fixture, &owner).await;
    fixture.cleanup().await;
}
