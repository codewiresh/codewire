//! Host-bound secrets at a hosted Pod's first bind (0070, #4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door"):
//! the upgrade leaves every existing report serving no bound-secret
//! routes and unrefused, and every existing binding with no record; a
//! refusal takes one of its three codes with a sentence; a record is an
//! array of at most 16; the binding's trigger lets a record be written only
//! with the interception decision and never changed after; and the rollback
//! restores the earlier schema.

use super::*;

/// This migration's version.
const VERSION: i64 = 70;

const POD_A: &str = "3f0c6a1e-8b2d-4c5e-9a7f-1d2b3c4e5f61";
const POD_B: &str = "3f0c6a1e-8b2d-4c5e-9a7f-1d2b3c4e5f62";

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// the migration from the shape before it after later migrations land.
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

/// The SQLSTATE of a refused statement, or `None` when it succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(error) => Some(error.to_string()),
    }
}

/// A live binding with no decision yet (A) and a released one whose decision
/// the credential relay stored alone (B), each with a front-door report, as
/// version-69 code wrote them.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    sqlx::raw_sql(&format!(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('first-bind-preset',\
         'credential-org-a','First bind','first-bind','{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
         VALUES('first-bind-env','credential-org-a','credential-user-a','sandbox','first-bind-preset','running','started',3,\
         '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid,\
         operation_generation,managed_credential_clients,credential_scope,released_at,interception) VALUES \
         ('{POD_B}','first-bind-env','codewire-sandboxes','sandbox-b','6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c41',\
         '6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c42',2,'','pod',now(),false), \
         ('{POD_A}','first-bind-env','codewire-sandboxes','sandbox-a','6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c41',\
         '6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c42',3,'','pod',NULL,NULL); \
         INSERT INTO sandbox_pod_front_door_hosts(pod_uid,hosts) VALUES \
         ('{POD_A}',ARRAY['api.anthropic.com:443']), ('{POD_B}',ARRAY['api.anthropic.com:443']);"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn first_bind_bound_secrets_upgrade_checks_records_once_and_rolls_back() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        let previous = fingerprint(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Every existing report serves no bound-secret routes and is
        // unrefused, and every existing binding has no record.
        let untouched: bool = sqlx::query_scalar(
            "SELECT bool_and(NOT bound_routes AND refusal_code IS NULL AND refusal_reason IS NULL) \
             FROM sandbox_pod_front_door_hosts",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(untouched, "an existing report changed");
        let unrecorded: bool =
            sqlx::query_scalar("SELECT bool_and(bound_secrets IS NULL) FROM sandbox_workspace_bindings")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(unrecorded, "an existing binding gained a record");

        // A refusal is one of the three codes with its sentence.
        let refusal = |code: &str, reason: &str| {
            format!(
                "UPDATE sandbox_pod_front_door_hosts SET refusal_code = {code}, \
                 refusal_reason = {reason} WHERE pod_uid = '{POD_A}'"
            )
        };
        for (code, reason, why) in [
            ("'something_else'", "'a sentence'", "an unknown code"),
            ("'bound_host_conflict'", "NULL", "a code without its sentence"),
            ("NULL", "'a sentence'", "a sentence without its code"),
            ("'bound_host_conflict'", "''", "an empty sentence"),
            ("'too_many_bound_hosts'", "repeat('x', 4097)", "an overlong sentence"),
        ] {
            anyhow::ensure!(
                refused(&pool, &refusal(code, reason)).await.as_deref() == Some("23514"),
                "{why} was not refused"
            );
        }
        for code in [
            "'bound_host_reserved'",
            "'bound_host_conflict'",
            "'too_many_bound_hosts'",
        ] {
            anyhow::ensure!(
                refused(&pool, &refusal(code, "'a sentence naming hosts and keys'"))
                    .await
                    .is_none(),
                "{code} was refused"
            );
        }
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "UPDATE sandbox_pod_front_door_hosts SET bound_routes = true WHERE pod_uid = '{POD_A}'"
                )
            )
            .await
            .is_none()
        );

        // A record is an array of at most 16.
        let record = |pod: &str, value: &str| {
            format!(
                "UPDATE sandbox_workspace_bindings SET bound_secrets = {value} WHERE pod_uid = '{pod}'"
            )
        };
        for (value, why) in [
            ("'{}'::jsonb", "an object"),
            ("'\"text\"'::jsonb", "a string"),
            (
                "(SELECT jsonb_agg(n) FROM generate_series(1, 17) AS n)",
                "seventeen entries",
            ),
        ] {
            anyhow::ensure!(
                refused(&pool, &record(POD_A, value)).await.as_deref() == Some("23514"),
                "{why} was not refused"
            );
        }

        // Written with the decision, then never changed.
        let entry = "'[{\"path\":\"/org-secrets/credential-org-a\",\"key\":\"FANCY_TOKEN\",\
                     \"binding_id\":\"7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6\",\
                     \"binding_generation\":1,\"hosts\":[\"api.fancy.example\"]}]'::jsonb";
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "UPDATE sandbox_workspace_bindings SET interception = true, bound_secrets = {entry} \
                     WHERE pod_uid = '{POD_A}' AND interception IS NULL"
                )
            )
            .await
            .is_none(),
            "the first decision stores its record"
        );
        for value in ["'[]'::jsonb", "NULL"] {
            anyhow::ensure!(
                refused(&pool, &record(POD_A, value)).await.as_deref() == Some("23514"),
                "a recorded binding took {value}"
            );
        }
        anyhow::ensure!(
            refused(&pool, &record(POD_B, "'[]'::jsonb")).await.as_deref() == Some("23514"),
            "a decision stored alone gained a record"
        );
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "UPDATE sandbox_workspace_bindings SET interception = false WHERE pod_uid = '{POD_A}'"
                )
            )
            .await
            .as_deref()
                == Some("23514"),
            "the trigger keeps the decision's own rule"
        );

        // Rollback: drop the columns and the checks, and restore 0042's
        // trigger function.
        let earlier = include_str!("../../../migrations/0042_workspace_binding_interception.sql");
        let function = earlier
            .find("CREATE OR REPLACE FUNCTION")
            .map(|start| &earlier[start..])
            .ok_or_else(|| anyhow::anyhow!("0042 defines the trigger function"))?;
        sqlx::raw_sql(
            "ALTER TABLE sandbox_pod_front_door_hosts \
               DROP CONSTRAINT sandbox_pod_front_door_hosts_refusal_check, \
               DROP COLUMN bound_routes, DROP COLUMN refusal_code, DROP COLUMN refusal_reason; \
             ALTER TABLE sandbox_workspace_bindings \
               DROP CONSTRAINT sandbox_workspace_bindings_bound_secrets_check, \
               DROP COLUMN bound_secrets;",
        )
        .execute(&pool)
        .await?;
        sqlx::raw_sql(function).execute(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
