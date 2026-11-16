//! Hosted egress reports (0030, #4000): an upgrade from the shape before it
//! adds the per-Pod enforcement and per-environment record tables and changes
//! no existing row; the constraints refuse what the service never stores;
//! deleting an environment deletes its reports; and the rollback (drop both
//! tables) restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0030 from the shape before it after later migrations land.
fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.constraint().unwrap_or("?").to_owned()),
        Err(error) => Some(error.to_string()),
    }
}

const DIGEST: &str = "'\\x0101010101010101010101010101010101010101010101010101010101010101'::bytea";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sandbox_egress_upgrade_constrains_reports_cascades_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(29).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email) VALUES ('owner', 'owner@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('org', 'Org', 'org', 'owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ('preset', 'org', 'Preset', 'preset', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments \
             (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
             VALUES ('env', 'org', 'owner', 'preset', 'sandbox', 'env', 'running', 'started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(30).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous, "0030 changes the schema");
        let environments: i64 = sqlx::query_scalar("SELECT count(*) FROM environments")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(environments == 1, "the upgrade keeps the environment");

        // What the service stores is accepted.
        for sql in [
            format!(
                "INSERT INTO sandbox_egress_enforcement (pod_uid, environment_id, node, state, revision, digest) \
                 VALUES ('pod-a', 'env', 'runtime-a', 'enforced', 2, {DIGEST})"
            ),
            "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state) \
             VALUES ('warm', 'runtime-a', 'disconnected')"
                .to_owned(),
            "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state, detail) \
             VALUES ('failed', 'runtime-a', 'failed_closed', 'self_check_failed')"
                .to_owned(),
            format!(
                "INSERT INTO environment_egress_records \
                 (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                  policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                 VALUES ('env', 'example.com', true, 'tcp', 443, 'refused', 'name_not_allowed', \
                  'platform:web', 2, {DIGEST}, now(), now(), 3)"
            ),
            format!(
                "INSERT INTO environment_egress_records \
                 (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                  policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                 VALUES ('env', 'github.com', true, 'dns', 0, 'passed', '', \
                  'platform:web', 2, {DIGEST}, now(), now(), 1)"
            ),
        ] {
            anyhow::ensure!(refused(&pool, &sql).await.is_none(), "{sql}");
        }

        // What it never stores is refused.
        for (sql, constraint) in [
            (
                "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state) \
                 VALUES ('x', 'n', 'enforced')"
                    .to_owned(),
                "sandbox_egress_enforcement_revision_check",
            ),
            (
                format!(
                    "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state, revision, digest) \
                     VALUES ('x', 'n', 'disconnected', 1, {DIGEST})"
                ),
                "sandbox_egress_enforcement_revision_check",
            ),
            (
                "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state) \
                 VALUES ('x', 'n', 'unknown')"
                    .to_owned(),
                "sandbox_egress_enforcement_state_check",
            ),
            (
                format!(
                    "INSERT INTO environment_egress_records \
                     (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                      policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                     VALUES ('env', 'a.example', true, 'dns', 53, 'passed', '', 'locked', 0, {DIGEST}, now(), now(), 1)"
                ),
                "environment_egress_records_port_check",
            ),
            (
                format!(
                    "INSERT INTO environment_egress_records \
                     (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                      policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                     VALUES ('env', 'a.example', true, 'tcp', 443, 'refused', '', 'locked', 0, {DIGEST}, now(), now(), 1)"
                ),
                "environment_egress_records_outcome_check",
            ),
            (
                format!(
                    "INSERT INTO environment_egress_records \
                     (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                      policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                     VALUES ('env', 'a.example', true, 'tcp', 443, 'passed', '', 'locked', 0, {DIGEST}, \
                      now(), now() - interval '1 hour', 1)"
                ),
                "environment_egress_records_seen_check",
            ),
            (
                "INSERT INTO environment_egress_records \
                 (environment_id, destination, destination_is_name, transport, port, outcome, reason, \
                  policy_reference, policy_revision, policy_digest, first_seen, last_seen, count) \
                 VALUES ('env', 'a.example', true, 'tcp', 443, 'passed', '', 'locked', 0, '\\x01'::bytea, \
                  now(), now(), 1)"
                    .to_owned(),
                "environment_egress_records_digest_check",
            ),
        ] {
            let refusal = refused(&pool, &sql).await;
            anyhow::ensure!(refusal.as_deref() == Some(constraint), "{sql}: {refusal:?}");
        }

        // Deleting the environment deletes its reports; an unbound member's
        // row stays for the sweep.
        sqlx::query("DELETE FROM environments WHERE id = 'env'")
            .execute(&pool)
            .await?;
        let (enforcement, records): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM sandbox_egress_enforcement WHERE environment_id IS NOT NULL), \
                    (SELECT count(*) FROM environment_egress_records)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(enforcement == 0 && records == 0, "{enforcement} {records}");
        let unbound: i64 =
            sqlx::query_scalar("SELECT count(*) FROM sandbox_egress_enforcement")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(unbound == 2, "unbound and failed rows stay: {unbound}");

        // Rollback: drop both tables to restore the previous shape.
        sqlx::query("DROP TABLE environment_egress_records")
            .execute(&pool)
            .await?;
        sqlx::query("DROP TABLE sandbox_egress_enforcement")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
