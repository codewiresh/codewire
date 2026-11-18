//! Hosted egress lockdown refusals (0033, #5068): an upgrade from the shape
//! before it keeps every enforcement row and leaves it unrefused; the column
//! takes each of the lockdown check's refusals and nothing else; and the
//! rollback (drop the column) restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0033 from the shape before it after later migrations land.
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn egress_lockdown_refusal_upgrade_keeps_reports_takes_only_refusals_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(32).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query(
            "INSERT INTO sandbox_egress_enforcement (pod_uid, node, state, detail) \
             VALUES ('failed', 'runtime-a', 'failed_closed', 'self_check_failed'), \
                    ('warm', 'runtime-a', 'disconnected', '')",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(33).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0033 changes the schema"
        );
        let kept: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT pod_uid, state, lockdown_refusal FROM sandbox_egress_enforcement \
             ORDER BY pod_uid",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            kept == [
                ("failed".to_owned(), "failed_closed".to_owned(), None),
                ("warm".to_owned(), "disconnected".to_owned(), None),
            ],
            "the upgrade keeps every report, unrefused: {kept:?}"
        );

        // Every refusal the lockdown check names is accepted.
        for refusal in [
            "not_broker_mode",
            "not_labelled_for_its_binding",
            "policy_unmanaged",
            "policy_missing",
            "policy_differs",
            "policy_does_not_select",
        ] {
            sqlx::query(
                "UPDATE sandbox_egress_enforcement SET lockdown_refusal = $1 \
                 WHERE pod_uid = 'warm'",
            )
            .bind(refusal)
            .execute(&pool)
            .await?;
        }
        // The public code and anything else are refused.
        for refusal in ["not_applied", "lockdown_not_applied", ""] {
            let refused = sqlx::query(
                "UPDATE sandbox_egress_enforcement SET lockdown_refusal = $1 \
                 WHERE pod_uid = 'warm'",
            )
            .bind(refusal)
            .execute(&pool)
            .await;
            let constraint = match refused {
                Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
                _ => None,
            };
            anyhow::ensure!(
                constraint.as_deref() == Some("sandbox_egress_enforcement_lockdown_refusal_check"),
                "{refusal:?}: {constraint:?}"
            );
        }

        // Rollback: drop the column to restore the previous shape.
        sqlx::query("ALTER TABLE sandbox_egress_enforcement DROP COLUMN lockdown_refusal")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
