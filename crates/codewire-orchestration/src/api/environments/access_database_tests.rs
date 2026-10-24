//! `require_environment_access` grants access only to current members of the
//! environment's organization. Removing a member deletes only their membership
//! row, so the creator shortcut and any old grant must not outlive it (#3254).

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_string(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn api_key(user_id: &str, org_id: &str) -> AuthUser {
    AuthUser {
        org_id: Some(org_id.to_string()),
        via_api_key: true,
        ..session(user_id)
    }
}

async fn allowed(fixture: &LeaseFixture, user: &AuthUser, min_permission: &str) -> bool {
    match require_environment_access(
        &fixture.pool,
        user,
        &fixture.id,
        &fixture.id,
        min_permission,
        "access denied",
    )
    .await
    {
        Ok(()) => true,
        Err(error) => {
            assert!(error.is_forbidden(), "unexpected error: {error:?}");
            false
        }
    }
}

async fn execute(fixture: &LeaseFixture, sql: &str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    query.execute(&fixture.pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_only_current_members_reach_an_environment() {
    // The fixture's user created the environment and owns the organization.
    // Its ID is also the organization's, the environment's and the
    // membership row's.
    let fixture = LeaseFixture::seed("synthetic-environment-access").await;
    let id = fixture.id.clone();
    let peer = format!("{id}-peer");
    let (id, peer) = (id.as_str(), peer.as_str());
    execute(
        &fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Environment access peer', true)",
        &[peer],
    )
    .await;
    let creator = [session(id), api_key(id, id)];

    // A creator who is a current member keeps the creator shortcut at any role.
    execute(
        &fixture,
        "UPDATE org_members SET role = 'viewer' WHERE id = $1",
        &[id],
    )
    .await;
    for user in &creator {
        assert!(allowed(&fixture, user, "owner").await);
    }

    // Once removed, the creator is denied over a session and an org-bound key,
    // even with a grant left behind.
    execute(&fixture, "DELETE FROM org_members WHERE id = $1", &[id]).await;
    execute(
        &fixture,
        "INSERT INTO environment_access (id, environment_id, user_id, permission, granted_by) \
         VALUES ($1 || '-creator-grant', $1, $1, 'owner', $2)",
        &[id, peer],
    )
    .await;
    for user in &creator {
        assert!(!allowed(&fixture, user, "viewer").await);
    }
    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT metadata->>'reason' FROM audit_logs \
         WHERE action = 'environment.access.denied' AND user_id = $1",
    )
    .bind(id)
    .fetch_all(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(reasons, ["not a member", "not a member"]);

    // A non-creator member reaches it as an admin or through a sufficient grant.
    execute(
        &fixture,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($2, $1, $2, 'admin')",
        &[id, peer],
    )
    .await;
    let peer_key = api_key(peer, id);
    assert!(allowed(&fixture, &peer_key, "owner").await);
    execute(
        &fixture,
        "UPDATE org_members SET role = 'member' WHERE id = $1",
        &[peer],
    )
    .await;
    assert!(!allowed(&fixture, &peer_key, "viewer").await);
    execute(
        &fixture,
        "INSERT INTO environment_access (id, environment_id, user_id, permission, granted_by) \
         VALUES ($2 || '-grant', $1, $2, 'operator', $1)",
        &[id, peer],
    )
    .await;
    assert!(allowed(&fixture, &peer_key, "operator").await);
    assert!(!allowed(&fixture, &peer_key, "owner").await);

    for (sql, binds) in [
        (
            "DELETE FROM environment_access WHERE environment_id = $1",
            &[id][..],
        ),
        ("DELETE FROM org_members WHERE id = $1", &[peer]),
        (
            "DELETE FROM audit_logs WHERE user_id IN ($1, $2)",
            &[id, peer],
        ),
        ("DELETE FROM users WHERE id = $1", &[peer]),
    ] {
        execute(&fixture, sql, binds).await;
    }
    fixture.cleanup().await;
}
