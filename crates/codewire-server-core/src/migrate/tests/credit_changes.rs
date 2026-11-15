//! Credit changes (0029, #4754): a ledger row and a change to an
//! organization's top-up setting or out-of-credit mark notify
//! `credit_changes` with the organization's ID, once per transaction and only
//! at commit; an unrelated update of the organization stays quiet. An upgrade
//! from 0028 keeps every balance and the ledger's roll-up.

use std::time::Duration;

use sqlx::postgres::PgListener;

use super::*;

/// Only stops a hang: a notice comes in milliseconds.
const HANG: Duration = Duration::from_secs(60);
const SENTINEL: &str = "credit-changes-sentinel";

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

async fn grant(executor: impl sqlx::PgExecutor<'_>, key: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, \
         idempotency_key) VALUES ('credit-org', 'grant', 1000000000, $1)",
    )
    .bind(key)
    .execute(executor)
    .await?;
    Ok(())
}

async fn balance(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = 'credit-org'",
    )
    .fetch_one(pool)
    .await?)
}

/// The next notice's payload.
async fn next(listener: &mut PgListener) -> anyhow::Result<String> {
    let notice = tokio::time::timeout(HANG, listener.recv()).await??;
    anyhow::ensure!(notice.channel() == "credit_changes", "{notice:?}");
    Ok(notice.payload().to_owned())
}

/// Proves nothing was notified since the last notice read: a sentinel sent
/// now is the next notice only if nothing came before it.
async fn quiet(pool: &PgPool, listener: &mut PgListener) -> anyhow::Result<bool> {
    sqlx::query("SELECT pg_notify('credit_changes', $1)")
        .bind(SENTINEL)
        .execute(pool)
        .await?;
    Ok(next(listener).await? == SENTINEL)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn credit_changes_notify_once_at_commit_and_only_for_credit() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0029, with credit already granted.
        let mut connection = PgConnection::connect(&db.url).await?;
        through(28).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email) VALUES ('credit-owner', 'credit@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('credit-org', 'Credit', 'credit-org', 'credit-owner')",
        )
        .execute(&pool)
        .await?;
        grant(&pool, "before-0029").await?;

        // The upgrade keeps the balance and the ledger's roll-up.
        through(29).run(&pool).await?;
        anyhow::ensure!(balance(&pool).await? == 1_000_000_000);
        let mut listener = PgListener::connect(&db.url).await?;
        listener.listen("credit_changes").await?;

        // A ledger row moves the balance and notifies, with the organization's
        // ID.
        grant(&pool, "grant-1").await?;
        anyhow::ensure!(balance(&pool).await? == 2_000_000_000);
        anyhow::ensure!(next(&mut listener).await? == "credit-org");
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified twice");

        // Many rows in one transaction notify once, and only at commit.
        let mut transaction = pool.begin().await?;
        grant(&mut *transaction, "grant-2").await?;
        grant(&mut *transaction, "grant-3").await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified before commit");
        transaction.commit().await?;
        anyhow::ensure!(next(&mut listener).await? == "credit-org");
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "notified twice");

        // A rolled-back row notifies nothing.
        let mut transaction = pool.begin().await?;
        grant(&mut *transaction, "grant-4").await?;
        transaction.rollback().await?;
        anyhow::ensure!(quiet(&pool, &mut listener).await?, "a rollback notified");

        // The top-up setting and the out-of-credit mark notify; another
        // column, or the same value again, doesn't.
        for (update, notifies) in [
            ("SET name = 'Renamed'", false),
            ("SET auto_top_up_enabled = NOT auto_top_up_enabled", true),
            ("SET auto_top_up_enabled = auto_top_up_enabled", false),
            ("SET auto_top_up_cents = 5000", true),
            ("SET credit_exhausted_at = now()", true),
            ("SET credit_exhausted_at = NULL", true),
        ] {
            sqlx::query(&format!(
                "UPDATE organizations {update} WHERE id = 'credit-org'"
            ))
            .execute(&pool)
            .await?;
            if notifies {
                anyhow::ensure!(next(&mut listener).await? == "credit-org", "{update}");
            }
            anyhow::ensure!(
                quiet(&pool, &mut listener).await?,
                "{update}: another notice"
            );
        }
        listener.unlisten_all().await?;
        drop(listener);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
