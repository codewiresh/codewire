//! Live changes (0045, #4762): a Sandbox's state, resources or schedule, its
//! setup, and its resize operations notify `environment_changes` or
//! `resize_changes` with `<organization>:<environment>`, once per transaction
//! and only at commit. The minute's billing counters, the activity clock and
//! generation bumps stay quiet.

use std::time::Duration;

use sqlx::postgres::PgListener;

use super::*;

/// Only stops a hang: a notice comes in milliseconds.
const HANG: Duration = Duration::from_secs(60);
const SENTINEL: &str = "live-changes-sentinel";
const ENV: &str = "live-org:live-env";

/// The next notice, as `channel payload`.
async fn next(listener: &mut PgListener) -> anyhow::Result<String> {
    let notice = tokio::time::timeout(HANG, listener.recv()).await??;
    Ok(format!("{} {}", notice.channel(), notice.payload()))
}

/// Proves nothing was notified since the last notice read: a sentinel sent
/// now is the next notice only if nothing came before it.
async fn quiet(pool: &PgPool, listener: &mut PgListener) -> anyhow::Result<bool> {
    sqlx::query("SELECT pg_notify('environment_changes', $1)")
        .bind(SENTINEL)
        .execute(pool)
        .await?;
    Ok(next(listener).await? == format!("environment_changes {SENTINEL}"))
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn live_changes_notify_once_at_commit_and_only_for_what_pages_show() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        MIGRATOR.run(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES ('live-owner', 'live@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) \
               VALUES ('live-org', 'Live', 'live-org', 'live-owner'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
               VALUES ('live-preset', 'live-org', 'Preset', 'ready', '{}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let mut listener = PgListener::connect(&db.url).await?;
        listener.listen_all(["environment_changes", "resize_changes"]).await?;

        // A new Sandbox, and its removal, each notify.
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) \
             VALUES ('live-env', 'live-org', 'live-owner', 'sandbox', 'live-preset', '{}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("environment_changes {ENV}"));

        // A state change notifies once at commit, even when the transaction
        // writes several shown columns, and never before commit.
        let mut transaction = pool.begin().await?;
        sqlx::query("UPDATE environments SET state = 'running' WHERE id = 'live-env'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE environments SET cpu_millicores = 2000 WHERE id = 'live-env'")
            .execute(&mut *transaction)
            .await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified before commit");
        transaction.commit().await?;
        anyhow::ensure!(next(&mut listener).await? == format!("environment_changes {ENV}"));
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified twice in one transaction");

        // A rolled-back change sends nothing.
        let mut transaction = pool.begin().await?;
        sqlx::query("UPDATE environments SET state = 'stopped' WHERE id = 'live-env'")
            .execute(&mut *transaction)
            .await?;
        transaction.rollback().await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified a rolled-back change");

        // The minute's metering, the generation and a same-value write stay quiet.
        sqlx::query(
            "UPDATE environments SET total_running_seconds = total_running_seconds + 60, \
             last_billing_event_at = now(), \
             environment_operation_generation = environment_operation_generation + 1, \
             state = state WHERE id = 'live-env'",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "metering woke the pages");

        // Setup moving on notifies; a pod address does not.
        sqlx::query(
            "INSERT INTO sandbox_environment_backend (environment_id, namespace) \
             VALUES ('live-env', 'live')",
        )
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE sandbox_environment_backend SET pod_ip = '10.0.0.1' WHERE environment_id = 'live-env'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "a pod address woke the pages");
        sqlx::query("UPDATE sandbox_environment_backend SET setup_phase = 2 WHERE environment_id = 'live-env'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("environment_changes {ENV}"));
        sqlx::query("UPDATE sandbox_environment_backend SET setup_complete = true WHERE environment_id = 'live-env'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("environment_changes {ENV}"));

        // A resize is requested and moves on, each on its own channel.
        sqlx::query(
            "INSERT INTO environment_resize_operations (id, org_id, environment_id, request_id, \
               previous_cpu_millicores, previous_memory_mb, previous_disk_gb, \
               desired_cpu_millicores, desired_memory_mb, desired_disk_gb, \
               last_applied_cpu_millicores, last_applied_memory_mb, last_applied_disk_gb, \
               previous_state, previous_desired_state, state, disruption_policy, planned_mode) \
             VALUES ('live-resize', 'live-org', 'live-env', 'live-request', 1000, 2048, 10, \
               2000, 4096, 10, 1000, 2048, 10, 'running', 'started', 'pending', 'allow_restart', \
               'restart')",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("resize_changes {ENV}"));
        sqlx::query("UPDATE environment_resize_operations SET state = 'applying' WHERE id = 'live-resize'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("resize_changes {ENV}"));

        sqlx::query("DELETE FROM environment_resize_operations WHERE id = 'live-resize'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM sandbox_environment_backend WHERE environment_id = 'live-env'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM environments WHERE id = 'live-env'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(next(&mut listener).await? == format!("environment_changes {ENV}"));
        anyhow::ensure!(quiet(&pool, &mut listener).await?);
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
