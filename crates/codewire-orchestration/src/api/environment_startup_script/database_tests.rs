//! The startup script after create, against the disposable database (#5949,
//! SPEC.md "The rules for the startup script after create").

use std::time::Duration;

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

/// Bounds each test: a lock that never comes free fails it instead of
/// holding a build slot.
const HANG: Duration = Duration::from_secs(60);
const SCRIPT: &str = "echo synthetic-startup-canary > /workspace/started";

fn user(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn save(
    fixture: &LeaseFixture,
    user: &AuthUser,
    script: &str,
) -> AppResult<StartupScriptUpdate> {
    let mut tx = fixture.pool.begin().await.unwrap();
    let result = set_startup_script_in(&mut tx, user, &fixture.id, &fixture.id, script).await;
    match &result {
        Ok(_) => tx.commit().await.unwrap(),
        Err(_) => tx.rollback().await.unwrap(),
    }
    result
}

async fn execute(fixture: &LeaseFixture, sql: &str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    query.execute(&fixture.pool).await.unwrap();
}

async fn saved_spec(fixture: &LeaseFixture) -> serde_json::Value {
    sqlx::query_scalar("SELECT project_spec FROM environments WHERE id = $1")
        .bind(&fixture.id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

/// Every audit row of this action for the fixture's Sandbox, whole, as text.
async fn audit_rows(fixture: &LeaseFixture) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(a)::text FROM audit_logs a \
         WHERE action = $1 AND metadata->>'environment_id' = $2 ORDER BY timestamp",
    )
    .bind(AUDIT_ACTION)
    .bind(&fixture.id)
    .fetch_all(&fixture.pool)
    .await
    .unwrap()
}

async fn setup_marks(fixture: &LeaseFixture) -> (bool, i32) {
    sqlx::query_as(
        "SELECT setup_complete, setup_phase FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(&fixture.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap()
}

/// A member of the fixture's organization with `role`.
async fn member(fixture: &LeaseFixture, suffix: &str, role: &str) -> String {
    let id = format!("{}-{suffix}", fixture.id);
    execute(
        fixture,
        "INSERT INTO users (id, email, name, email_verified) \
         VALUES ($1, $1 || '@example.test', 'Startup script member', true)",
        &[&id],
    )
    .await;
    execute(
        fixture,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($2, $1, $2, $3)",
        &[&fixture.id, &id, role],
    )
    .await;
    id
}

async fn cleanup(fixture: LeaseFixture, users: &[&str]) {
    execute(
        &fixture,
        "DELETE FROM audit_logs WHERE metadata->>'environment_id' = $1",
        &[&fixture.id],
    )
    .await;
    for id in users {
        execute(
            &fixture,
            "DELETE FROM org_members WHERE user_id = $1",
            &[id],
        )
        .await;
        execute(&fixture, "DELETE FROM users WHERE id = $1", &[id]).await;
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_creator_adds_changes_and_removes_only_the_script() {
    let fixture = LeaseFixture::seed("synthetic-startup-script").await;
    tokio::time::timeout(HANG, async {
        let creator = user(&fixture.id);
        let mut others = serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace",
            "install_command": "npm ci",
            "secrets": {"organization": true},
        });
        execute(
            &fixture,
            "UPDATE environments SET project_spec = $2::text::jsonb WHERE id = $1",
            &[&fixture.id, &others.to_string()],
        )
        .await;
        let before = setup_marks(&fixture).await;

        let added = save(&fixture, &creator, SCRIPT).await.unwrap();
        assert_eq!(
            added,
            StartupScriptUpdate {
                changed: true,
                state: ScriptableState::Running
            }
        );
        others["startup_script"] = SCRIPT.into();
        assert_eq!(saved_spec(&fixture).await, others);

        // The same script again writes and audits nothing.
        let same = save(&fixture, &creator, SCRIPT).await.unwrap();
        assert!(!same.changed);
        assert_eq!(audit_rows(&fixture).await.len(), 1);

        let changed = "npm run dev";
        assert!(save(&fixture, &creator, changed).await.unwrap().changed);
        others["startup_script"] = changed.into();
        assert_eq!(saved_spec(&fixture).await, others);

        assert!(save(&fixture, &creator, "").await.unwrap().changed);
        others.as_object_mut().unwrap().remove("startup_script");
        assert_eq!(saved_spec(&fixture).await, others);

        // Setup stays complete at its phase, so install doesn't run again.
        assert_eq!(setup_marks(&fixture).await, before);

        // Each change is audited by the creator, with the script's hash and
        // length, never its text.
        let rows = audit_rows(&fixture).await;
        assert_eq!(rows.len(), 3);
        let first: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(first["user_id"], fixture.id.as_str());
        assert_eq!(first["metadata"]["environment_id"], fixture.id.as_str());
        assert_eq!(
            first["metadata"]["startup_script_sha256"],
            format!("{:x}", Sha256::digest(SCRIPT.as_bytes()))
        );
        assert_eq!(first["metadata"]["startup_script_bytes"], SCRIPT.len());
        for row in &rows {
            assert!(!row.contains("synthetic-startup-canary"), "{row}");
            assert!(!row.contains("npm run dev"), "{row}");
        }
    })
    .await
    .expect("the test finished within its bound");
    cleanup(fixture, &[]).await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_no_one_but_the_creator_changes_the_script() {
    let fixture = LeaseFixture::seed("synthetic-startup-script-others").await;
    let admin = member(&fixture, "admin", "admin").await;
    let plain = member(&fixture, "member", "member").await;
    tokio::time::timeout(HANG, async {
        let before = saved_spec(&fixture).await;
        let platform_admin = AuthUser {
            is_admin: true,
            ..user(&admin)
        };
        for caller in [user(&admin), user(&plain), platform_admin] {
            let refused = save(&fixture, &caller, SCRIPT).await;
            assert!(
                matches!(
                    refused,
                    Err(AppError::Coded {
                        status: StatusCode::FORBIDDEN,
                        ..
                    })
                ),
                "{refused:?}"
            );
        }
        // An organization API key for another organization is refused too.
        let key = AuthUser {
            org_id: Some(format!("{}-other", fixture.id)),
            via_api_key: true,
            ..user(&fixture.id)
        };
        assert!(save(&fixture, &key, SCRIPT).await.is_err());
        assert_eq!(saved_spec(&fixture).await, before);
        assert!(audit_rows(&fixture).await.is_empty());
    })
    .await
    .expect("the test finished within its bound");
    cleanup(fixture, &[&admin, &plain]).await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_script_changes_only_while_running_with_setup_done_or_stopped() {
    let fixture = LeaseFixture::seed("synthetic-startup-script-states").await;
    tokio::time::timeout(HANG, async {
        let creator = user(&fixture.id);
        let state = "UPDATE environments SET state = $2, desired_state = $3 WHERE id = $1";
        for (current, desired) in [("stopping", "stopped"), ("starting", "started")] {
            execute(&fixture, state, &[&fixture.id, current, desired]).await;
            let refused = save(&fixture, &creator, SCRIPT).await;
            assert!(matches!(refused, Err(AppError::Precondition(_))), "{refused:?}");
        }

        execute(&fixture, state, &[&fixture.id, "running", "started"]).await;
        execute(
            &fixture,
            "UPDATE sandbox_environment_backend SET setup_complete = false WHERE environment_id = $1",
            &[&fixture.id],
        )
        .await;
        let refused = save(&fixture, &creator, SCRIPT).await;
        assert!(matches!(refused, Err(AppError::Precondition(_))), "{refused:?}");
        assert!(saved_spec(&fixture).await.get("startup_script").is_none());

        execute(&fixture, state, &[&fixture.id, "stopped", "stopped"]).await;
        let saved = save(&fixture, &creator, SCRIPT).await.unwrap();
        assert_eq!(saved.state, ScriptableState::Stopped);
        assert_eq!(saved_spec(&fixture).await["startup_script"], SCRIPT);

        let refused = save(&fixture, &creator, "echo trailing\n").await;
        assert!(matches!(refused, Err(AppError::Validation { .. })), "{refused:?}");
        assert_eq!(saved_spec(&fixture).await["startup_script"], SCRIPT);
    })
    .await
    .expect("the test finished within its bound");
    cleanup(fixture, &[]).await;
}
