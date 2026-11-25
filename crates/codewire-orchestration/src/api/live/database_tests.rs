//! What a live watch promises against a real database (#4762): a notice
//! reaches every watch over the process-wide listener, a watch passes on only
//! its caller's organizations, an API key only its own, and a member removed
//! from an organization no longer gets it on their next watch.

use std::time::Duration;

use codewire_server_core::auth::AuthUser;

use super::*;
use crate::test_database_support::TestDatabase;

/// Only stops a hang: a notice comes in milliseconds.
const HANG: Duration = Duration::from_secs(30);

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn member(db: &TestDatabase, user_id: &str, org_id: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'member')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(org_id)
    .bind(user_id)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn notify(db: &TestDatabase, org_id: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_notify('credit_changes', $1)")
        .bind(org_id)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// The next change a watch passes on, past its resyncs and heartbeats.
async fn next_change(
    events: &mut tokio::sync::mpsc::Receiver<LiveEvent>,
) -> anyhow::Result<LiveEvent> {
    loop {
        match tokio::time::timeout(HANG, events.recv()).await? {
            Some(LiveEvent::Resync | LiveEvent::Heartbeat(_)) => continue,
            Some(event) => return Ok(event),
            None => anyhow::bail!("the watch ended"),
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_watch_passes_on_only_its_callers_organizations() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user("live-user").await?;
        for org in ["live-org-a", "live-org-b", "live-org-c"] {
            db.organization(org).await?;
        }
        member(&db, "live-user", "live-org-a").await?;
        member(&db, "live-user", "live-org-c").await?;
        let notifications =
            LiveNotifications::new(MAX_WATCHES_PER_ACCOUNT, MAX_WATCHES_PER_PROCESS);
        // The listener sends a resync once it is listening; wait for that
        // rather than a fixed delay.
        let mut probe = notifications.signals.subscribe();
        let listener = spawn_live_listener(db.pool.clone(), notifications.clone());
        loop {
            match tokio::time::timeout(HANG, probe.recv()).await?? {
                LiveSignal::Resync => break,
                _ => continue,
            }
        }

        let mut watch = open_live_watch(&db.pool, &notifications, &session("live-user")).await?;
        anyhow::ensure!(tokio::time::timeout(HANG, watch.recv()).await? == Some(LiveEvent::Resync));

        // Another organization's change never reaches this watch: the next
        // change it passes on is the caller's own.
        notify(&db, "live-org-b").await?;
        notify(&db, "live-org-c").await?;
        anyhow::ensure!(
            next_change(&mut watch).await?
                == LiveEvent::Credit {
                    org: "live-org-c".into()
                }
        );

        // An API key sees only its own organization, though its user is a
        // member of two.
        let key = AuthUser {
            org_id: Some("live-org-c".into()),
            via_api_key: true,
            ..session("live-user")
        };
        let mut keyed = open_live_watch(&db.pool, &notifications, &key).await?;
        notify(&db, "live-org-a").await?;
        notify(&db, "live-org-c").await?;
        anyhow::ensure!(
            next_change(&mut keyed).await?
                == LiveEvent::Credit {
                    org: "live-org-c".into()
                }
        );

        // A member removed from an organization keeps its notices on the
        // watch already open, until it ends; their next watch has none.
        sqlx::query(
            "DELETE FROM org_members WHERE user_id = 'live-user' AND org_id = 'live-org-a'",
        )
        .execute(&db.pool)
        .await?;
        let mut renewed = open_live_watch(&db.pool, &notifications, &session("live-user")).await?;
        notify(&db, "live-org-a").await?;
        notify(&db, "live-org-c").await?;
        anyhow::ensure!(
            next_change(&mut watch).await?
                == LiveEvent::Credit {
                    org: "live-org-a".into()
                }
        );
        anyhow::ensure!(
            next_change(&mut renewed).await?
                == LiveEvent::Credit {
                    org: "live-org-c".into()
                }
        );

        listener.abort();
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// An audit notice for `environment`, as the audit log's writer sends it.
async fn audit_notice(db: &TestDatabase, org_id: &str, environment: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_notify('audit_changes', $1)")
        .bind(format!("{org_id}:{environment}"))
        .execute(&db.pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_audit_notice_reaches_only_those_who_may_read_that_log() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        // The organization's owner is the fixture admin; two members, one
        // granted the Sandbox `audit-env-a`.
        db.organization("audit-org").await?;
        for user in ["audit-granted", "audit-plain"] {
            db.user(user).await?;
            member(&db, user, "audit-org").await?;
        }
        sqlx::raw_sql(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ('audit-preset', 'audit-org', 'P', 'p', \
               '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, preset_id, name, type, state, \
               desired_state, project_spec) VALUES \
             ('audit-env-a', 'audit-org', 'fixture-admin', 'audit-preset', 'a', 'sandbox', \
               'running', 'started', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
             ('audit-env-b', 'audit-org', 'fixture-admin', 'audit-preset', 'b', 'sandbox', \
               'running', 'started', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environment_access (id, environment_id, user_id, permission, granted_by) \
             VALUES ('g-1', 'audit-env-a', 'audit-granted', 'operator', 'fixture-admin');",
        )
        .execute(&db.pool)
        .await?;
        let notifications =
            LiveNotifications::new(MAX_WATCHES_PER_ACCOUNT, MAX_WATCHES_PER_PROCESS);
        let mut probe = notifications.signals.subscribe();
        let listener = spawn_live_listener(db.pool.clone(), notifications.clone());
        loop {
            match tokio::time::timeout(HANG, probe.recv()).await?? {
                LiveSignal::Resync => break,
                _ => continue,
            }
        }
        let mut owner = open_live_watch(&db.pool, &notifications, &session("fixture-admin")).await?;
        let mut granted = open_live_watch(&db.pool, &notifications, &session("audit-granted")).await?;
        let mut plain = open_live_watch(&db.pool, &notifications, &session("audit-plain")).await?;

        audit_notice(&db, "audit-org", "audit-env-b").await?;
        audit_notice(&db, "audit-org", "audit-env-a").await?;
        notify(&db, "audit-org").await?;
        let audit = |environment: &str| LiveEvent::Audit {
            org: "audit-org".into(),
            environment: environment.into(),
        };
        let credit = LiveEvent::Credit {
            org: "audit-org".into(),
        };
        for expected in [audit("audit-env-b"), audit("audit-env-a"), credit.clone()] {
            anyhow::ensure!(next_change(&mut owner).await? == expected, "the owner reads both");
        }
        for expected in [audit("audit-env-a"), credit.clone()] {
            anyhow::ensure!(
                next_change(&mut granted).await? == expected,
                "a member reads the Sandbox they can open"
            );
        }
        anyhow::ensure!(
            next_change(&mut plain).await? == credit,
            "a member who can open neither hears of neither"
        );

        listener.abort();
        Ok(())
    }
    .await;
    db.finish(result).await
}
