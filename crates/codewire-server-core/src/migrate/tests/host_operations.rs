//! Host operations (0026, #3609 slice 2): an upgrade keeps every
//! existing host and environment, at session generation 0 and on the
//! Kubernetes backend; the constraints refuse what the service never
//! stores, including a second open operation for one environment; inserting
//! and finishing an operation notify; deleting a host deletes its operations
//! and reports and clears its environments' host; a create's request ID
//! names one environment per organization; and the rollback restores the
//! shape before 0026.

use sqlx::postgres::PgListener;

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn constraint<T>(result: Result<T, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
        _ => None,
    }
}

/// Inserts an operation for `environment` from extra columns and values.
async fn operation(
    pool: &PgPool,
    id: &str,
    environment: &str,
    columns: &str,
    values: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "INSERT INTO host_operations (operation_id, host_id, environment_id, \
         expected_generation, kind, payload{columns}) \
         VALUES ($1, (SELECT id FROM hosts WHERE name = 'ops-box'), $2, 0, 'create', \
         '\\x0a00'::bytea{values}) \
         RETURNING operation_id"
    ))
    .bind(id)
    .bind(environment)
    .fetch_one(pool)
    .await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn host_operations_upgrade_keeps_rows_constrains_new_ones_notifies_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0026: an account, an organization, a host and two
        // environments.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 26)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email) VALUES ('ops-owner', 'ops@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('ops-org', 'Ops', 'ops-org', 'ops-owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
             public_key) VALUES ('ops-org', 'ops-owner', 'ops-box', 'linux-x86_64-kvm', 1, \
             decode(repeat('07', 32), 'hex'))",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ('ops-preset', 'ops-org', 'Preset', 'ready', '{}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        for id in ["ops-env-1", "ops-env-2"] {
            sqlx::query(
                "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) \
                 VALUES ($1, 'ops-org', 'ops-owner', 'sandbox', 'ops-preset', '{}'::jsonb)",
            )
            .bind(id)
            .execute(&pool)
            .await?;
        }
        let previous = fingerprint(&pool).await?;

        sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 26)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        }
        .run(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Existing rows are kept, on generation 0 and the Kubernetes backend.
        let generation: i64 =
            sqlx::query_scalar("SELECT session_generation FROM hosts WHERE name = 'ops-box'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(generation == 0, "{generation}");
        let backends: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT runtime_backend, host_id FROM environments WHERE org_id = 'ops-org' ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            backends == [("kubernetes".to_owned(), None), ("kubernetes".to_owned(), None)],
            "{backends:?}"
        );

        // A create's request ID names one environment per organization; any
        // number of environments have none.
        sqlx::query("UPDATE environments SET create_request_id = 'req-ops-1' WHERE id = 'ops-env-1'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            constraint(
                sqlx::query(
                    "UPDATE environments SET create_request_id = 'req-ops-1' WHERE id = 'ops-env-2'"
                )
                .execute(&pool)
                .await
            )
            .as_deref()
                == Some("environments_org_create_request_id_key")
        );
        sqlx::query("UPDATE environments SET create_request_id = NULL WHERE id = 'ops-env-1'")
            .execute(&pool)
            .await?;

        // An environment on a host names it, and only a host environment may.
        anyhow::ensure!(
            constraint(
                sqlx::query(
                    "UPDATE environments SET host_id = (SELECT id FROM hosts WHERE name = 'ops-box') \
                     WHERE id = 'ops-env-1'"
                )
                .execute(&pool)
                .await
            )
            .as_deref()
                == Some("environments_host_id_needs_host_backend")
        );
        anyhow::ensure!(
            constraint(
                sqlx::query("UPDATE environments SET runtime_backend = 'docker' WHERE id = 'ops-env-1'")
                    .execute(&pool)
                    .await
            )
            .as_deref()
                == Some("environments_runtime_backend_check")
        );
        sqlx::query(
            "UPDATE environments SET runtime_backend = 'host', \
             host_id = (SELECT id FROM hosts WHERE name = 'ops-box') WHERE org_id = 'ops-org'",
        )
        .execute(&pool)
        .await?;

        // An environment is only ever placed on a host of its own
        // organization.
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('ops-other-org', 'Other', 'ops-other', 'ops-owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ('ops-other-preset', 'ops-other-org', 'Preset', 'ready', '{}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            constraint(
                sqlx::query(
                    "INSERT INTO environments (id, org_id, created_by, type, preset_id, \
                     project_spec, runtime_backend, host_id) VALUES ('ops-env-crossed', \
                     'ops-other-org', 'ops-owner', 'sandbox', 'ops-other-preset', '{}'::jsonb, \
                     'host', (SELECT id FROM hosts WHERE name = 'ops-box'))"
                )
                .execute(&pool)
                .await
            )
            .as_deref()
                == Some("environments_host_id_fkey")
        );

        // A new operation is pending and notifies its host.
        let mut listener = PgListener::connect(&db.url).await?;
        listener.listen("host_operation").await?;
        operation(&pool, "op-1", "ops-env-1", "", "").await?;
        let inserted = listener.recv().await?;
        let host_id: String = sqlx::query_scalar("SELECT id FROM hosts WHERE name = 'ops-box'")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            (inserted.channel(), inserted.payload()) == ("host_operation", host_id.as_str()),
            "{inserted:?}"
        );
        let (state, payload): (String, Vec<u8>) =
            sqlx::query_as("SELECT state, payload FROM host_operations WHERE operation_id = 'op-1'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(state == "pending" && payload == [0x0a, 0x00], "{state} {payload:?}");

        // One open operation per environment: a second waits for the first.
        anyhow::ensure!(
            constraint(operation(&pool, "op-2", "ops-env-1", "", "").await).as_deref()
                == Some("host_operations_one_open_per_environment")
        );
        sqlx::query(
            "UPDATE host_operations SET state = 'sent', session_generation = 1, sent_at = now() \
             WHERE operation_id = 'op-1'",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE host_operations SET state = 'done', completed_at = now(), \
             result = '\\x0800'::bytea WHERE operation_id = 'op-1'",
        )
        .execute(&pool)
        .await?;
        operation(&pool, "op-2", "ops-env-1", "", "").await?;

        // What the service never stores is refused, naming the constraint.
        for (id, columns, values, expected) in [
            ("bad-kind", "", "", "host_operations_kind_check"),
            (
                "bad-state",
                ", state, sent_at, session_generation",
                ", 'lost', now(), 1",
                "host_operations_state_check",
            ),
            (
                "sent-unnamed",
                ", state, sent_at",
                ", 'sent', now()",
                "host_operations_sent_check",
            ),
            (
                "pending-sent",
                ", session_generation",
                ", 1",
                "host_operations_sent_check",
            ),
            (
                "done-untimed",
                ", state, sent_at, session_generation",
                ", 'done', now(), 1",
                "host_operations_completed_check",
            ),
            (
                "failed-silent",
                ", state, sent_at, session_generation, completed_at",
                ", 'failed', now(), 1, now()",
                "host_operations_failure_check",
            ),
            (
                "negative-session",
                ", state, sent_at, session_generation",
                ", 'sent', now(), -1",
                "host_operations_session_generation_check",
            ),
        ] {
            let kind = if id == "bad-kind" { "'resize'" } else { "'create'" };
            let refused = sqlx::query_scalar::<_, String>(&format!(
                "INSERT INTO host_operations (operation_id, host_id, environment_id, \
                 expected_generation, kind, payload{columns}) \
                 VALUES ($1, $2, 'ops-env-2', 0, {kind}, '\\x0a00'::bytea{values}) \
                 RETURNING operation_id"
            ))
            .bind(id)
            .bind(&host_id)
            .fetch_one(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{id} was not refused by {expected}"
            );
        }

        // The host's report of an environment, including one the control
        // plane does not know.
        sqlx::query(
            "INSERT INTO host_environments (host_id, environment_id, local_environment_id, \
             generation, state) VALUES \
             ($1, 'ops-env-1', gen_random_uuid(), 1, 'running'), \
             ($1, 'forgotten', gen_random_uuid(), 3, 'stopped')",
        )
        .bind(&host_id)
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            constraint(
                sqlx::query(
                    "INSERT INTO host_environments (host_id, environment_id, \
                     local_environment_id, generation, state) \
                     VALUES ($1, 'ops-env-2', gen_random_uuid(), 0, 'paused')"
                )
                .bind(&host_id)
                .execute(&pool)
                .await
            )
            .as_deref()
                == Some("host_environments_state_check")
        );
        for (columns, values, expected) in [
            (", error_code", ", ''", "host_environments_error_code_check"),
            (", error_code", ", repeat('x', 65)", "host_environments_error_code_check"),
            (", vcpus", ", -1", "host_environments_shape_check"),
            (", disk_bytes", ", -1", "host_environments_shape_check"),
        ] {
            let refused = sqlx::query(&format!(
                "INSERT INTO host_environments (host_id, environment_id, local_environment_id, \
                 generation, state{columns}) \
                 VALUES ($1, 'ops-env-2', gen_random_uuid(), 0, 'error'{values})"
            ))
            .bind(&host_id)
            .execute(&pool)
            .await;
            anyhow::ensure!(
                constraint(refused).as_deref() == Some(expected),
                "{columns} {values} was not refused by {expected}"
            );
        }

        // An operation belongs to its host, not to its environment: one
        // whose environment row is gone stays until its host goes, so a
        // Destroy can still name that environment's VM.
        sqlx::query("DELETE FROM environments WHERE id = 'ops-env-1'")
            .execute(&pool)
            .await?;
        let kept: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM host_operations WHERE environment_id = 'ops-env-1'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(kept == 2, "{kept}");

        // Deleting the host deletes its operations and reports, and leaves
        // its environments' rows with no host.
        sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(&host_id)
            .execute(&pool)
            .await?;
        let left: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM host_operations), \
                    (SELECT count(*) FROM host_environments), \
                    (SELECT count(*) FROM environments WHERE org_id = 'ops-org' AND host_id IS NULL)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(left == (0, 0, 1), "{left:?}");

        // Rollback restores the shape before 0026.
        sqlx::raw_sql(
            "DROP TRIGGER host_operations_notify ON host_operations; \
             DROP FUNCTION codewire_notify_host_operation(); \
             DROP TABLE host_environments, host_operations; \
             DROP INDEX environments_org_create_request_id_key, environments_host_id_idx; \
             ALTER TABLE environments DROP COLUMN create_request_id, DROP COLUMN host_id, \
                 DROP COLUMN runtime_backend; \
             ALTER TABLE hosts DROP CONSTRAINT hosts_org_id_id_key, \
                 DROP COLUMN session_generation",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        listener.unlisten_all().await?;
        drop(listener);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
