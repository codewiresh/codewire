//! The credit ledger outlives its organization (0031, #4823). An upgrade from
//! 0029 keeps every ledger row and balance. Deleting an organization then
//! keeps its ledger, immutable even to a trigger, and drops only its
//! balance; an entry for it is refused. A `forfeited` entry must draw credit
//! and name who deleted the organization. The deletion fence is exercised
//! through the real deletion phase in `codewire-billing`.

use super::*;

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

async fn ledger_rows(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM billing_credit_ledger WHERE organization_id = 'kept-org'",
    )
    .fetch_one(pool)
    .await?)
}

async fn balance(pool: &PgPool) -> anyhow::Result<Option<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = 'kept-org'",
    )
    .fetch_optional(pool)
    .await?)
}

async fn forfeit(pool: &PgPool, amount: i64, actor: Option<&str>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, \
         idempotency_key, actor_user_id, provider_object_id) \
         VALUES ('kept-org', 'forfeited', $1, 'forfeit:op-1', $2, 'cus_kept')",
    )
    .bind(amount)
    .bind(actor)
    .execute(pool)
    .await
    .map(drop)
}

fn has_code(result: &Result<(), sqlx::Error>, code: &str) -> bool {
    matches!(result, Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some(code))
}

fn is_check_violation(result: Result<(), sqlx::Error>, constraint: &str) -> bool {
    matches!(
        result,
        Err(sqlx::Error::Database(error))
            if error.code().as_deref() == Some("23514")
                && error.constraint() == Some(constraint)
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_deleted_organization_keeps_its_credit_ledger() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0031, with credit granted and partly used.
        let mut connection = PgConnection::connect(&db.url).await?;
        through(29).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email) VALUES ('kept-owner', 'kept@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('kept-org', 'Kept', 'kept-org', 'kept-owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, \
             idempotency_key) VALUES ('kept-org', 'grant', 12400000000, 'grant-1')",
        )
        .execute(&pool)
        .await?;

        // The upgrade keeps the ledger and the balance.
        through(31).run(&pool).await?;
        anyhow::ensure!(ledger_rows(&pool).await? == 1);
        anyhow::ensure!(balance(&pool).await? == Some(12_400_000_000));

        // A forfeit draws credit and names who deleted the organization.
        anyhow::ensure!(is_check_violation(
            forfeit(&pool, 12_400_000_000, Some("kept-owner")).await,
            "billing_credit_ledger_amount_check"
        ));
        anyhow::ensure!(is_check_violation(
            forfeit(&pool, -12_400_000_000, None).await,
            "billing_credit_ledger_forfeited_check"
        ));
        forfeit(&pool, -12_400_000_000, Some("kept-owner")).await?;
        anyhow::ensure!(balance(&pool).await? == Some(0));

        // Deleting the organization keeps its ledger and drops its balance.
        sqlx::query("DELETE FROM organizations WHERE id = 'kept-org'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(ledger_rows(&pool).await? == 2, "the ledger went with the organization");
        anyhow::ensure!(balance(&pool).await?.is_none());
        let (amount, customer): (i64, String) = sqlx::query_as(
            "SELECT amount_nano_eur, provider_object_id FROM billing_credit_ledger \
             WHERE organization_id = 'kept-org' AND entry_kind = 'forfeited'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(amount == -12_400_000_000 && customer == "cus_kept");

        // An entry for the deleted organization is refused: its balance row
        // is gone, and the balance's foreign key is what stops it.
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('other-org', 'Other', 'other-org', 'kept-owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query("DELETE FROM organizations WHERE id = 'other-org'")
            .execute(&pool)
            .await?;
        let orphan = sqlx::query(
            "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, \
             idempotency_key) VALUES ('other-org', 'grant', 1000000000, 'orphan')",
        )
        .execute(&pool)
        .await
        .map(drop);
        anyhow::ensure!(has_code(&orphan, "23503"), "an orphan ledger entry was kept: {orphan:?}");

        // The kept rows refuse a delete, also from inside another trigger,
        // which the old cascade exception would have let through.
        let deleted = sqlx::query("DELETE FROM billing_credit_ledger WHERE organization_id = 'kept-org'")
            .execute(&pool)
            .await
            .map(drop);
        anyhow::ensure!(has_code(&deleted, "23514"), "a kept ledger row was deleted: {deleted:?}");
        sqlx::raw_sql(
            "CREATE TABLE ledger_cleaner (id int); \
             CREATE FUNCTION ledger_cleaner_delete() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN DELETE FROM billing_credit_ledger WHERE organization_id = 'kept-org'; RETURN NEW; END; $$; \
             CREATE TRIGGER ledger_cleaner AFTER INSERT ON ledger_cleaner \
             FOR EACH ROW EXECUTE FUNCTION ledger_cleaner_delete();",
        )
        .execute(&pool)
        .await?;
        let nested = sqlx::query("INSERT INTO ledger_cleaner VALUES (1)")
            .execute(&pool)
            .await
            .map(drop);
        anyhow::ensure!(has_code(&nested, "23514"), "a trigger deleted ledger rows: {nested:?}");
        anyhow::ensure!(ledger_rows(&pool).await? == 2);

        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
