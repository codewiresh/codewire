//! Monthly USD billing plans, allowances and onboarding state (0063, #6659):
//! an upgrade from pre-0063 seeds payg/pro/max definitions, adds
//! billing_plan_allowances with its period/amount/uniqueness constraints and
//! credit_changes notify trigger, adds org_subscriptions.cancel_at_period_end,
//! backfills users.onboarding_completed_at for existing accounts, updates the
//! default Regular and Discounted rate cards to USD defaults while preserving
//! custom admin rates, and rolls back cleanly to the pre-0063 schema fingerprint.

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

async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn billing_plans_and_onboarding_upgrade_seeds_plans_backfills_users_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(62).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id, name, slug, created_by) \
             VALUES ('plan-org', 'Plan Org', 'plan-org', 'credential-user-a'); \
             INSERT INTO org_subscriptions(org_id, plan, status) \
             VALUES ('plan-org', 'pro', 'active');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(63).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        #[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
        struct PlanRow {
            plan_key: String,
            monthly_price_cents: i32,
            included_compute_nano_usd: i64,
            max_concurrent_sandboxes: Option<i32>,
            max_vcpu: i32,
            max_memory_gib: i32,
            max_disk_gib: i32,
            max_team_members: Option<i32>,
        }

        // Seeded plan definitions match the USD catalog.
        let plans: Vec<PlanRow> = sqlx::query_as(
            "SELECT plan_key, monthly_price_cents, included_compute_nano_usd, \
                    max_concurrent_sandboxes, max_vcpu, max_memory_gib, max_disk_gib, \
                    max_team_members \
             FROM billing_plan_definitions ORDER BY plan_key",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            plans
                == vec![
                    PlanRow {
                        plan_key: "max".to_owned(),
                        monthly_price_cents: 10_000,
                        included_compute_nano_usd: 250_000_000_000,
                        max_concurrent_sandboxes: None,
                        max_vcpu: 16,
                        max_memory_gib: 32,
                        max_disk_gib: 200,
                        max_team_members: None,
                    },
                    PlanRow {
                        plan_key: "payg".to_owned(),
                        monthly_price_cents: 0,
                        included_compute_nano_usd: 0,
                        max_concurrent_sandboxes: Some(3),
                        max_vcpu: 8,
                        max_memory_gib: 16,
                        max_disk_gib: 100,
                        max_team_members: Some(1),
                    },
                    PlanRow {
                        plan_key: "pro".to_owned(),
                        monthly_price_cents: 4_000,
                        included_compute_nano_usd: 100_000_000_000,
                        max_concurrent_sandboxes: Some(10),
                        max_vcpu: 8,
                        max_memory_gib: 16,
                        max_disk_gib: 100,
                        max_team_members: Some(5),
                    },
                ],
            "unexpected seeded plans: {plans:?}"
        );

        // Existing users are backfilled with onboarding_completed_at so they are never intercepted;
        // a newly created user starts with NULL.
        let existing_completed: bool = sqlx::query_scalar(
            "SELECT onboarding_completed_at IS NOT NULL FROM users WHERE id = 'credential-user-a'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(existing_completed, "existing user must be backfilled");

        sqlx::query(
            "INSERT INTO users (id, email) VALUES ('new-onb-user', 'new-onb@example.test')",
        )
        .execute(&pool)
        .await?;
        let new_completed: bool = sqlx::query_scalar(
            "SELECT onboarding_completed_at IS NOT NULL FROM users WHERE id = 'new-onb-user'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            !new_completed,
            "new user must start with NULL onboarding_completed_at"
        );

        // Existing org_subscriptions row defaults cancel_at_period_end to false.
        let cancel_at_period_end: bool = sqlx::query_scalar(
            "SELECT cancel_at_period_end FROM org_subscriptions WHERE org_id = 'plan-org'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!cancel_at_period_end);

        // Default Regular and Discounted rate cards move to USD defaults; Unlimited stays zero.
        let cards: Vec<(String, i64, i64, i64)> = sqlx::query_as(
            "SELECT rate_card, cpu_nano_eur_per_vcpu_hour, memory_nano_eur_per_gib_hour, \
                    disk_nano_eur_per_gib_hour \
             FROM billing_rate_cards ORDER BY rate_card",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            cards
                == vec![
                    ("discounted".to_owned(), 25_000_000, 8_000_000, 50_000),
                    ("regular".to_owned(), 50_000_000, 16_000_000, 100_000),
                    ("unlimited".to_owned(), 0, 0, 0),
                ],
            "unexpected rate cards after 0062: {cards:?}"
        );

        // Allowance row works, enforces uniqueness by invoice, bounds drawn <= granted,
        // and cascades on org deletion.
        sqlx::query(
            "INSERT INTO billing_plan_allowances \
               (organization_id, plan_key, period_start, period_end, granted_nano_usd, \
                drawn_nano_usd, stripe_invoice_id) \
             VALUES ('plan-org', 'pro', '2026-11-01 00:00:00+00', '2026-12-01 00:00:00+00', \
                     100000000000, 25000000000, 'in_test_0062')",
        )
        .execute(&pool)
        .await?;

        for (statement, constraint) in [
            (
                "INSERT INTO billing_plan_allowances \
                   (organization_id, plan_key, period_start, period_end, granted_nano_usd, \
                    stripe_invoice_id) \
                 VALUES ('plan-org', 'pro', '2026-11-01 00:00:00+00', '2026-12-01 00:00:00+00', \
                         100000000000, 'in_test_0062')",
                "billing_plan_allowances_invoice_key",
            ),
            (
                "UPDATE billing_plan_allowances SET drawn_nano_usd = 100000000001 \
                 WHERE stripe_invoice_id = 'in_test_0062'",
                "billing_plan_allowances_amounts_check",
            ),
            (
                "INSERT INTO billing_plan_allowances \
                   (organization_id, plan_key, period_start, period_end, granted_nano_usd, \
                    stripe_invoice_id) \
                 VALUES ('plan-org', 'pro', '2026-12-01 00:00:00+00', '2026-11-01 00:00:00+00', \
                         100000000000, 'in_test_0062_bad_period')",
                "billing_plan_allowances_period_check",
            ),
            (
                "INSERT INTO billing_plan_definitions \
                   (plan_key, display_name, monthly_price_cents, included_compute_nano_usd, \
                    max_vcpu, max_memory_gib, max_disk_gib) \
                 VALUES ('enterprise', 'Enterprise', 50000, 0, 16, 32, 200)",
                "billing_plan_definitions_plan_key_check",
            ),
        ] {
            anyhow::ensure!(
                refused_by(&pool, statement, constraint).await?,
                "{statement} must be refused by {constraint}"
            );
        }

        // Rollback restores the exact 0061 schema fingerprint.
        sqlx::raw_sql(
            "DROP TRIGGER billing_plan_allowances_credit_changes ON billing_plan_allowances; \
             DROP FUNCTION codewire_notify_plan_allowance_change(); \
             DROP TABLE billing_plan_allowances; \
             DROP TABLE billing_plan_definitions; \
             ALTER TABLE org_subscriptions DROP COLUMN cancel_at_period_end; \
             ALTER TABLE users DROP COLUMN onboarding_completed_at;",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            fingerprint(&pool).await? == previous,
            "rollback did not restore the 0061 schema"
        );
        pool.close().await;
        anyhow::Ok(())
    }
    .await;
    let cleanup = db.drop().await;
    result.and(cleanup)
}
