//! Rate card storage (0046, #5782): an upgrade from the migration before it
//! gives every existing card a storage rate of 0, Unlimited still charges
//! nothing at any of its four rates, and no rate is negative. Its rollback
//! (drop the column, restore the three-rate Unlimited check) restores the
//! earlier schema.

use super::*;

const VERSION: i64 = 46;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to, or through, this migration, chosen by version so the
/// test does not depend on how many migrations come before it.
fn history(through: bool) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .take_while(|migration| {
                    migration.version < VERSION || (through && migration.version == VERSION)
                })
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_card_storage_upgrade_starts_every_card_at_zero_and_keeps_unlimited_free()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        anyhow::ensure!(
            MIGRATOR
                .iter()
                .any(|migration| migration.version == VERSION),
            "migration {VERSION} is not embedded"
        );
        // The shape before 0046, with its three cards.
        let mut connection = PgConnection::connect(&db.url).await?;
        history(false).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        let cards: i64 = sqlx::query_scalar("SELECT count(*) FROM billing_rate_cards")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(cards == 3, "the upgrade needs the three existing cards");

        // Through 0046 only, so its rollback restores the earlier shape; later
        // migrations prove their own upgrade and rollback.
        history(true).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let storage: Vec<(String, i64)> = sqlx::query_as(
            "SELECT rate_card, parked_storage_nano_eur_per_gib_hour \
             FROM billing_rate_cards ORDER BY rate_card",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            storage
                == [
                    ("discounted".to_owned(), 0),
                    ("regular".to_owned(), 0),
                    ("unlimited".to_owned(), 0),
                ],
            "{storage:?}"
        );
        // A charging card takes a storage rate; Unlimited takes none at any
        // of its four rates, and no card takes a negative or null one.
        sqlx::query(
            "UPDATE billing_rate_cards SET parked_storage_nano_eur_per_gib_hour = 1 \
             WHERE rate_card = 'regular'",
        )
        .execute(&pool)
        .await?;
        for (sql, code) in [
            (
                "UPDATE billing_rate_cards SET parked_storage_nano_eur_per_gib_hour = 1 \
                 WHERE rate_card = 'unlimited'",
                "23514",
            ),
            (
                "UPDATE billing_rate_cards SET cpu_nano_eur_per_vcpu_hour = 1 \
                 WHERE rate_card = 'unlimited'",
                "23514",
            ),
            (
                "UPDATE billing_rate_cards SET parked_storage_nano_eur_per_gib_hour = -1 \
                 WHERE rate_card = 'discounted'",
                "23514",
            ),
            (
                "UPDATE billing_rate_cards SET parked_storage_nano_eur_per_gib_hour = NULL \
                 WHERE rate_card = 'discounted'",
                "23502",
            ),
        ] {
            let error = sqlx::query(sql)
                .execute(&pool)
                .await
                .expect_err("invalid rate accepted");
            anyhow::ensure!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref()
                    == Some(code),
                "{sql}: {error}"
            );
        }

        // Rollback: dropping the column drops both checks that name it, and
        // the earlier Unlimited check comes back, restoring the earlier schema.
        sqlx::raw_sql(
            "ALTER TABLE billing_rate_cards \
             DROP COLUMN parked_storage_nano_eur_per_gib_hour, \
             ADD CONSTRAINT billing_rate_cards_unlimited_charges_nothing_check CHECK ( \
             rate_card <> 'unlimited' \
             OR (cpu_nano_eur_per_vcpu_hour = 0 \
             AND memory_nano_eur_per_gib_hour = 0 \
             AND disk_nano_eur_per_gib_hour = 0));",
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
