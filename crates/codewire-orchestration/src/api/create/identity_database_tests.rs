//! A fork keeps its source's identity groups only when an organization owner
//! or admin makes it (docs/dev/SANDBOX-IDENTITY.md, "Groups"): a create from
//! a hosted snapshot, through the create's own transaction.

use super::*;
use crate::api::environments::get_org_quota;
use crate::api::identity::groups::{get_groups, set_groups};
use crate::test_database_support::TestDatabase;

async fn member(db: &TestDatabase, user_id: &str, org_id: &str, role: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&db.pool)
        .await?;
    Ok(())
}

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

/// A ready snapshot of `source` that `created_by` made; snapshots are private
/// to their creator.
async fn snapshot(
    db: &TestDatabase,
    id: &str,
    created_by: &str,
    source: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO hosted_snapshots (id, org_id, created_by, source_environment_id, name, \
         state, size_bytes) VALUES ($1, 'fork-org', $2, $3, $1, 'ready', 1024)",
    )
    .bind(id)
    .bind(created_by)
    .bind(source)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn fork(db: &TestDatabase, actor: &str, snapshot_id: &str, name: &str) -> AppResult<String> {
    let user = session(actor);
    let body = CreateEnvironmentBody {
        name: Some(name.to_owned()),
        source_snapshot_id: Some(snapshot_id.to_owned()),
        ..Default::default()
    };
    let quota = get_org_quota(&db.pool, "fork-org").await?;
    let create = insert_environment(
        &db.pool,
        InsertEnvironmentParams {
            credit_enforcement: Default::default(),
            org_id: "fork-org",
            user: &user,
            preset_id: "fork-preset",
            env_type: "sandbox",
            name: body.name.clone(),
            cpu_millicores: 1_000,
            memory_mb: 1_024,
            disk_gb: 10,
            isolation_tier: "standard",
            ttl_seconds: None,
            body: &body,
            quota,
            runtime: super::RecordedRuntime {
                systemd_workspace: false,
                profile: "commodity".into(),
            },
        },
    );
    let environment = tokio::time::timeout(std::time::Duration::from_secs(60), create)
        .await
        .map_err(|_| AppError::InternalMsg("the create took longer than 60 s".into()))??;
    Ok(environment.id)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_fork_keeps_its_sources_groups_only_when_an_admin_makes_it() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("fork-org").await?;
        member(&db, "fork-admin", "fork-org", "admin").await?;
        member(&db, "fork-alice", "fork-org", "member").await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ('fork-preset', 'fork-org', 'Fork', 'ready', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments \
             (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
             VALUES ('fork-source', 'fork-org', 'fork-alice', 'fork-preset', 'sandbox', 'source', \
             'stopped', 'stopped', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .execute(&db.pool)
        .await?;
        let admin = session("fork-admin");
        set_groups(
            &db.pool,
            &admin,
            "fork-org",
            "fork-source",
            &["data-readers".to_owned()],
        )
        .await?;
        snapshot(&db, "snap-admin", "fork-admin", "fork-source").await?;
        snapshot(&db, "snap-alice", "fork-alice", "fork-source").await?;

        let by_admin = fork(&db, "fork-admin", "snap-admin", "by-admin").await?;
        let groups = get_groups(&db.pool, &admin, "fork-org", &by_admin).await?;
        anyhow::ensure!(groups.groups == ["data-readers"] && groups.version == 1);
        let audit: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT metadata FROM audit_logs WHERE action = 'identity.groups.changed' \
             AND user_id = 'fork-admin' AND metadata->>'environment_id' = $1",
        )
        .bind(&by_admin)
        .fetch_optional(&db.pool)
        .await?;
        anyhow::ensure!(
            audit
                == Some(serde_json::json!({
                    "org_id": "fork-org",
                    "environment_id": by_admin,
                    "before": [],
                    "after": ["data-readers"],
                    "version": 1,
                    "source_environment_id": "fork-source",
                })),
            "{audit:?}"
        );

        // A member's fork of the same Sandbox starts with none.
        let by_member = fork(&db, "fork-alice", "snap-alice", "by-member").await?;
        let groups = get_groups(&db.pool, &admin, "fork-org", &by_member).await?;
        anyhow::ensure!(groups.groups.is_empty() && groups.version == 0);

        // Once the source has none, an admin's fork has none either.
        set_groups(&db.pool, &admin, "fork-org", "fork-source", &[]).await?;
        let cleared = fork(&db, "fork-admin", "snap-admin", "after-clearing").await?;
        let groups = get_groups(&db.pool, &admin, "fork-org", &cleared).await?;
        anyhow::ensure!(groups.groups.is_empty() && groups.version == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}
