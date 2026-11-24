//! A Pod's interception trust (0052, #6200; docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Hosted interception"): the upgrade keeps every binding and adds one empty
//! table; a row's Pod UID is a UID, a Pod has one row, the trigger refuses
//! every UPDATE while a DELETE goes through; the rollback restores the earlier
//! shape. Orchestration's use of it is in its `egress::interception_trust`
//! database suite.

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
async fn pod_interception_trust_is_recorded_once_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(51).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;

        through(52).run(&pool).await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sandbox_pod_interception_trust")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0, "the table starts empty");

        anyhow::ensure!(
            refused(
                &pool,
                "INSERT INTO sandbox_pod_interception_trust (pod_uid, ca_given) \
                 VALUES ('workspace-1', true)"
            )
            .await
            .as_deref()
                == Some("23514"),
            "a Pod UID is a UID"
        );
        sqlx::query(&format!(
            "INSERT INTO sandbox_pod_interception_trust (pod_uid, ca_given) VALUES ('{POD}', true)"
        ))
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "INSERT INTO sandbox_pod_interception_trust (pod_uid, ca_given) \
                     VALUES ('{POD}', false)"
                )
            )
            .await
            .as_deref()
                == Some("23505"),
            "a Pod has one row"
        );
        for set in ["ca_given = false", "ca_given = true", "recorded_at = now()"] {
            anyhow::ensure!(
                refused(
                    &pool,
                    &format!(
                        "UPDATE sandbox_pod_interception_trust SET {set} WHERE pod_uid = '{POD}'"
                    )
                )
                .await
                .as_deref()
                    == Some("23514"),
                "UPDATE {set} is refused"
            );
        }
        anyhow::ensure!(
            refused(
                &pool,
                &format!("DELETE FROM sandbox_pod_interception_trust WHERE pod_uid = '{POD}'")
            )
            .await
            .is_none(),
            "the sweep's DELETE goes through"
        );

        sqlx::raw_sql(
            "DROP TABLE public.sandbox_pod_interception_trust; \
             DROP FUNCTION public.codewire_pod_interception_trust_immutable();",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
