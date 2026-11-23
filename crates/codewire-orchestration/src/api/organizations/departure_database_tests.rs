//! A saved startup script runs only for its creator (#5949, SPEC.md "The
//! rules for the startup script after create"): when the creator leaves or
//! is removed, the scripts of the Sandboxes they created there are cleared
//! with the departure, whether create or a later update saved them.

use std::time::Duration;

use super::*;
use crate::api::environment_startup_script::set_startup_script_in;
use crate::api::runtime_lease_test_support::LeaseFixture;

const HANG: Duration = Duration::from_secs(60);
const AT_CREATE: &str = "echo saved-at-create";
const UPDATED: &str = "echo saved-by-update";

async fn execute(fixture: &LeaseFixture, sql: &str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    query.execute(&fixture.pool).await.unwrap();
}

/// A user in the fixture's organization with `role`.
async fn join(fixture: &LeaseFixture, user_id: &str, role: &str) {
    execute(
        fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Departing creator', true)",
        &[user_id],
    )
    .await;
    execute(
        fixture,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($2, $1, $2, $3)",
        &[&fixture.id, user_id, role],
    )
    .await;
}

/// A stopped Sandbox `creator` created in `org`, with `script` saved at
/// create when it is not empty.
async fn sandbox(fixture: &LeaseFixture, id: &str, org: &str, creator: &str, script: &str) {
    let mut spec = serde_json::json!({"schema_version": 1, "working_directory": "/workspace"});
    if !script.is_empty() {
        spec["startup_script"] = script.into();
    }
    execute(
        fixture,
        "INSERT INTO environments \
             (id, org_id, created_by, type, state, desired_state, preset_id, project_spec, \
              environment_operation_generation) \
         VALUES ($1, $2, $3, 'sandbox', 'stopped', 'stopped', $4, $5::text::jsonb, 1)",
        &[id, org, creator, &fixture.id, &spec.to_string()],
    )
    .await;
}

async fn script(fixture: &LeaseFixture, environment: &str) -> Option<String> {
    sqlx::query_scalar("SELECT project_spec->>'startup_script' FROM environments WHERE id = $1")
        .bind(environment)
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

/// `creator` saves `UPDATED` on `environment` through the one writer.
async fn update(fixture: &LeaseFixture, creator: &str, environment: &str) {
    let user = AuthUser {
        user_id: creator.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    let mut tx = fixture.pool.begin().await.unwrap();
    let saved = set_startup_script_in(&mut tx, &user, &fixture.id, environment, UPDATED)
        .await
        .unwrap();
    assert!(saved.changed);
    tx.commit().await.unwrap();
}

/// The departing creator's two Sandboxes, one scripted at create and one by
/// an update; the organization owner's own scripted Sandbox; and the
/// departing creator's scripted Sandbox in another organization.
struct Scene {
    created: String,
    updated: String,
    owners: String,
    elsewhere: String,
    other_org: String,
}

async fn scene(fixture: &LeaseFixture, creator: &str) -> Scene {
    let scene = Scene {
        created: format!("{creator}-created"),
        updated: format!("{creator}-updated"),
        owners: format!("{creator}-owners"),
        elsewhere: format!("{creator}-elsewhere"),
        other_org: format!("{}-other", fixture.id),
    };
    let org = fixture.id.as_str();
    sandbox(fixture, &scene.created, org, creator, AT_CREATE).await;
    sandbox(fixture, &scene.updated, org, creator, "").await;
    update(fixture, creator, &scene.updated).await;
    sandbox(fixture, &scene.owners, org, org, AT_CREATE).await;
    execute(
        fixture,
        "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)",
        &[&scene.other_org, creator],
    )
    .await;
    execute(
        fixture,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $1, $2, 'owner')",
        &[&scene.other_org, creator],
    )
    .await;
    sandbox(
        fixture,
        &scene.elsewhere,
        &scene.other_org,
        creator,
        AT_CREATE,
    )
    .await;
    assert_eq!(
        script(fixture, &scene.created).await.as_deref(),
        Some(AT_CREATE)
    );
    assert_eq!(
        script(fixture, &scene.updated).await.as_deref(),
        Some(UPDATED)
    );
    scene
}

async fn assert_cleared_with_the_departure(fixture: &LeaseFixture, scene: &Scene) {
    assert_eq!(script(fixture, &scene.created).await, None);
    assert_eq!(script(fixture, &scene.updated).await, None);
    assert_eq!(
        script(fixture, &scene.owners).await.as_deref(),
        Some(AT_CREATE)
    );
    assert_eq!(
        script(fixture, &scene.elsewhere).await.as_deref(),
        Some(AT_CREATE)
    );
}

async fn cleanup(fixture: LeaseFixture, creator: &str, scene: Scene) {
    for environment in [
        &scene.created,
        &scene.updated,
        &scene.owners,
        &scene.elsewhere,
    ] {
        execute(
            &fixture,
            "DELETE FROM environments WHERE id = $1",
            &[environment],
        )
        .await;
    }
    for (sql, binds) in [
        ("DELETE FROM audit_logs WHERE user_id = $1", &[creator][..]),
        ("DELETE FROM org_members WHERE user_id = $1", &[creator]),
        (
            "DELETE FROM organizations WHERE id = $1",
            &[&scene.other_org],
        ),
        ("DELETE FROM users WHERE id = $1", &[creator]),
    ] {
        execute(&fixture, sql, binds).await;
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_removed_or_leaving_member_s_scripts_are_cleared_with_the_membership() {
    let fixture = LeaseFixture::seed("synthetic-departure-member").await;
    let creator = format!("{}-member", fixture.id);
    join(&fixture, &creator, "member").await;
    let scene = tokio::time::timeout(HANG, async {
        let scene = scene(&fixture, &creator).await;
        // Removal by an admin and `cw org leave` by a member both end the
        // membership here.
        delete_membership(&fixture.pool, &fixture.id, &creator)
            .await
            .unwrap();
        assert_cleared_with_the_departure(&fixture, &scene).await;
        scene
    })
    .await
    .expect("the test finished within its bound");
    cleanup(fixture, &creator, scene).await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_leaving_owner_s_scripts_are_cleared_with_the_membership() {
    let fixture = LeaseFixture::seed("synthetic-departure-owner").await;
    let creator = format!("{}-co-owner", fixture.id);
    join(&fixture, &creator, "owner").await;
    let scene = tokio::time::timeout(HANG, async {
        let scene = scene(&fixture, &creator).await;
        leave_as_owner(&fixture.pool, &fixture.id, &creator)
            .await
            .unwrap();
        assert_cleared_with_the_departure(&fixture, &scene).await;
        scene
    })
    .await
    .expect("the test finished within its bound");
    cleanup(fixture, &creator, scene).await;
}
