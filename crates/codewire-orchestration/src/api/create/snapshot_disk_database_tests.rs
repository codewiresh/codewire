//! A create from a snapshot gets a disk at least as large as the snapshot
//! unless its request names a smaller one, which is refused with the
//! snapshot's size (#6276), through the whole create.

use super::*;
use crate::test_database_support::TestDatabase;

const GIB: i64 = 1 << 30;

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

/// A ready snapshot of `size_bytes` that `created_by` made.
async fn snapshot(
    db: &TestDatabase,
    id: &str,
    created_by: &str,
    size_bytes: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO hosted_snapshots (id, org_id, created_by, source_environment_id, name, \
         state, size_bytes) VALUES ($1, 'disk-org', $2, 'disk-source', $1, 'ready', $3)",
    )
    .bind(id)
    .bind(created_by)
    .bind(size_bytes)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// A create from `snapshot_id`, and the disk its environment row holds. The
/// offline Temporal can't start the environment, so the create ends in
/// "failed to start environment lifecycle" after its row is written.
async fn fork(
    state: &ApiState,
    preset_id: &str,
    snapshot_id: &str,
    name: &str,
    disk_gib: Option<u64>,
) -> AppResult<i32> {
    let mut body = CreateEnvironmentBody {
        name: Some(name.to_owned()),
        preset_id: Some(preset_id.to_owned()),
        source_snapshot_id: Some(snapshot_id.to_owned()),
        ..Default::default()
    };
    body.project_spec.resources.disk_gib = disk_gib;
    let user = session("disk-alice");
    // The whole create's future is too large for a test thread's stack.
    let create = Box::pin(create_environment_core(state, &user, "disk-org", body));
    let created = tokio::time::timeout(std::time::Duration::from_secs(60), create)
        .await
        .map_err(|_| AppError::InternalMsg("the create took longer than 60 s".into()))?;
    if let Err(error) = created {
        let detail = error.to_string();
        if !detail.contains("failed to start environment lifecycle") {
            return Err(error);
        }
    }
    Ok(
        sqlx::query_scalar("SELECT disk_gb FROM environments WHERE name = $1")
            .bind(name)
            .fetch_one(&state.pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_restore_without_a_disk_gets_the_snapshots_size() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.organization("disk-org").await?;
        db.user("disk-alice").await?;
        db.user("disk-bob").await?;
        for user_id in ["disk-alice", "disk-bob"] {
            sqlx::query(
                "INSERT INTO org_members (id, org_id, user_id, role) \
                 VALUES ($1, 'disk-org', $2, 'member')",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(user_id)
            .execute(&db.pool)
            .await?;
        }
        // One preset names no disk, so the create default (80 GiB) applies;
        // the other names 50 GiB.
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) VALUES \
             ('disk-default', 'disk-org', 'Default', 'ready', \
              '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
             ('disk-50', 'disk-org', 'Fifty', 'ready', \
              '{\"schema_version\":1,\"working_directory\":\"/workspace\",\
                \"resources\":{\"disk_gib\":50}}'::jsonb)",
        )
        .execute(&db.pool)
        .await?;
        snapshot(&db, "snap-100", "disk-alice", 100 * GIB).await?;
        snapshot(&db, "snap-over-100", "disk-alice", 100 * GIB + 1).await?;
        snapshot(&db, "snap-60", "disk-alice", 60 * GIB).await?;
        snapshot(&db, "snap-bob", "disk-bob", 150 * GIB).await?;

        let mut state = crate::api::test_state::offline(db.pool.clone()).await;
        state.sandbox_cfg.volume_snapshot_class = "snapshots".to_owned();

        // No disk named: the snapshot's size, rounded up to a whole GiB,
        // over the create default and a preset's smaller disk alike.
        anyhow::ensure!(fork(&state, "disk-default", "snap-100", "plain", None).await? == 100);
        anyhow::ensure!(fork(&state, "disk-50", "snap-100", "preset", None).await? == 100);
        anyhow::ensure!(
            fork(&state, "disk-default", "snap-over-100", "rounded", None).await? == 101
        );
        // A default already larger than the snapshot stays.
        anyhow::ensure!(fork(&state, "disk-default", "snap-60", "larger", None).await? == 80);
        // A named disk is the request's: at least the snapshot works...
        anyhow::ensure!(fork(&state, "disk-default", "snap-100", "named", Some(120)).await? == 120);
        // ...and smaller is refused with the snapshot's size.
        let refused = fork(&state, "disk-default", "snap-100", "small", Some(80))
            .await
            .expect_err("a named disk smaller than the snapshot is refused");
        anyhow::ensure!(
            matches!(&refused, AppError::Coded { code, .. } if *code == "snapshot_disk_too_small"),
            "unexpected refusal: {refused:?}"
        );
        anyhow::ensure!(
            refused
                .to_string()
                .contains("the disk must be at least as large as the snapshot, 100 GiB"),
            "unexpected refusal: {refused}"
        );
        // Another member's snapshot reads as absent, and its size isn't used.
        let absent = fork(&state, "disk-default", "snap-bob", "other", None)
            .await
            .expect_err("another member's snapshot is refused");
        anyhow::ensure!(
            matches!(&absent, AppError::Coded { code, .. } if *code == "snapshot_not_found"),
            "unexpected refusal: {absent:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
