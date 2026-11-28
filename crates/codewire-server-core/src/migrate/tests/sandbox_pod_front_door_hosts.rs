//! A Pod's reported front-door hosts (0069, #6290;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception"): the upgrade
//! adds one empty table; a row's Pod UID is a UID, a report holds at most 64
//! names, a Pod has one row that each admission replaces, and a DELETE goes
//! through; the rollback restores the earlier shape. Orchestration's use of it
//! is in its `egress::front_door_hosts` module.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

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

const POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae8";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pod_front_door_hosts_are_replaced_per_admission_and_roll_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(68).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;

        through(69).run(&pool).await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sandbox_pod_front_door_hosts")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0, "the table starts empty");

        anyhow::ensure!(
            refused(
                &pool,
                "INSERT INTO sandbox_pod_front_door_hosts (pod_uid, hosts) \
                 VALUES ('workspace-1', ARRAY['api.anthropic.com:443'])"
            )
            .await
            .as_deref()
                == Some("23514"),
            "a Pod UID is a UID"
        );
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "INSERT INTO sandbox_pod_front_door_hosts (pod_uid, hosts) \
                     VALUES ('{POD}', array_fill('a.example.com:443'::text, ARRAY[65]))"
                )
            )
            .await
            .as_deref()
                == Some("23514"),
            "a report holds at most 64 names"
        );
        let upsert = |hosts: &'static str| {
            format!(
                "INSERT INTO sandbox_pod_front_door_hosts (pod_uid, hosts) VALUES ('{POD}', {hosts}) \
                 ON CONFLICT (pod_uid) DO UPDATE SET hosts = EXCLUDED.hosts, reported_at = now()"
            )
        };
        sqlx::query(&upsert("ARRAY['api.anthropic.com:443', 'github.com:443']"))
            .execute(&pool)
            .await?;
        sqlx::query(&upsert("ARRAY['api.anthropic.com:443']"))
            .execute(&pool)
            .await?;
        let hosts: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT hosts FROM sandbox_pod_front_door_hosts WHERE pod_uid = '{POD}'"
        ))
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(hosts == ["api.anthropic.com:443"], "each admission replaces the set");
        let unserved = |names: &str| {
            format!(
                "UPDATE sandbox_pod_front_door_hosts SET unserved = {names} WHERE pod_uid = '{POD}'"
            )
        };
        anyhow::ensure!(
            refused(&pool, &unserved("'{}'")).await.as_deref() == Some("23514"),
            "a refusal names at least one host"
        );
        sqlx::query(&unserved("ARRAY['github.com']"))
            .execute(&pool)
            .await?;
        sqlx::query(&upsert("ARRAY['api.anthropic.com:443', 'github.com:443']"))
            .execute(&pool)
            .await?;
        let kept: Option<Vec<String>> = sqlx::query_scalar(&format!(
            "SELECT unserved FROM sandbox_pod_front_door_hosts WHERE pod_uid = '{POD}'"
        ))
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            kept.as_deref() == Some(&["github.com".to_owned()][..]),
            "an admission never clears a refusal"
        );
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "INSERT INTO sandbox_pod_front_door_hosts (pod_uid, hosts) VALUES ('{POD}', '{{}}')"
                )
            )
            .await
            .as_deref()
                == Some("23505"),
            "a Pod has one row"
        );
        anyhow::ensure!(
            refused(
                &pool,
                &format!("DELETE FROM sandbox_pod_front_door_hosts WHERE pod_uid = '{POD}'")
            )
            .await
            .is_none(),
            "the sweep's DELETE goes through"
        );

        sqlx::raw_sql("DROP TABLE public.sandbox_pod_front_door_hosts;")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
