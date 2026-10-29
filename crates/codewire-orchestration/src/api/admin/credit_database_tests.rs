//! Disposable-PostgreSQL proof for the audited rate card and credit writes
//! (#3381). Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::credit::{
    adjust_organization_credit_core, organization_credit, set_organization_rate_card_core,
};
use super::*;

use crate::test_database_support::TestDatabase;

const ADMIN: &str = "credit-admin";
const ORGANIZATION: &str = "credit-organization";
const EURO: i64 = 1_000_000_000;

fn app_error(error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

async fn audit_entries(pool: &PgPool, action: &str) -> Result<Vec<serde_json::Value>> {
    Ok(sqlx::query_scalar(
        "SELECT metadata FROM audit_logs WHERE action = $1 AND user_id = $2 \
         AND severity = 'warn' ORDER BY timestamp, id",
    )
    .bind(action)
    .bind(ADMIN)
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_rate_card_switch_is_audited_and_unlimited_lifts_the_quota() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;

        let overview = get_organization_overview_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(overview.credit.rate_card == "regular");
        ensure!(overview.credit.balance_nano_eur == 0);
        ensure!(get_org_quota(pool, ORGANIZATION).await?.max_cpu_millicores == 32_000);

        let change = set_organization_rate_card_core(pool, ADMIN, ORGANIZATION, "unlimited")
            .await
            .map_err(app_error)?;
        ensure!(change.previous == "regular" && change.rate_card == "unlimited");
        let quota = get_org_quota(pool, ORGANIZATION).await?;
        ensure!(
            (
                quota.max_concurrent_environments,
                quota.max_concurrent_sandbox,
                quota.max_cpu_millicores,
                quota.max_memory_mb
            ) == (-1, -1, -1, -1),
            "{quota:?}"
        );
        // The same card again changes nothing and audits nothing.
        set_organization_rate_card_core(pool, ADMIN, ORGANIZATION, "unlimited")
            .await
            .map_err(app_error)?;
        set_organization_rate_card_core(pool, ADMIN, ORGANIZATION, "discounted")
            .await
            .map_err(app_error)?;
        let entries = audit_entries(pool, "admin.organization.rate_card").await?;
        ensure!(entries.len() == 2, "{entries:?}");
        ensure!(entries[0]["previous"] == "regular" && entries[0]["rate_card"] == "unlimited");
        ensure!(entries[1]["previous"] == "unlimited" && entries[1]["rate_card"] == "discounted");
        ensure!(entries[1]["organization_id"] == ORGANIZATION);

        let unknown = set_organization_rate_card_core(pool, ADMIN, ORGANIZATION, "gold").await;
        ensure!(
            matches!(unknown, Err(AppError::Validation { .. })),
            "{unknown:?}"
        );
        let missing = set_organization_rate_card_core(pool, ADMIN, "missing", "regular").await;
        ensure!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        ensure!(
            organization_credit(pool, ORGANIZATION)
                .await
                .map_err(app_error)?
                .rate_card
                == "discounted"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_credit_adjustments_move_the_balance_once_and_are_audited() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;

        let granted =
            adjust_organization_credit_core(pool, ADMIN, ORGANIZATION, 25 * EURO, "goodwill", "k1")
                .await
                .map_err(app_error)?;
        ensure!(granted.applied && granted.balance_nano_eur == 25 * EURO);
        // A resubmitted form applies nothing again.
        let repeated =
            adjust_organization_credit_core(pool, ADMIN, ORGANIZATION, 25 * EURO, "goodwill", "k1")
                .await
                .map_err(app_error)?;
        ensure!(!repeated.applied && repeated.balance_nano_eur == 25 * EURO);
        let removed =
            adjust_organization_credit_core(pool, ADMIN, ORGANIZATION, -10 * EURO, " fix ", "k2")
                .await
                .map_err(app_error)?;
        ensure!(removed.applied && removed.balance_nano_eur == 15 * EURO);

        let credit = organization_credit(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(credit.balance_nano_eur == 15 * EURO);
        let recent: Vec<(&str, i64, &str, &str)> = credit
            .recent
            .iter()
            .map(|entry| {
                (
                    entry.kind.as_str(),
                    entry.amount_nano_eur,
                    entry.reason.as_str(),
                    entry.actor_user_id.as_str(),
                )
            })
            .collect();
        ensure!(
            recent
                == [
                    ("adjustment", -10 * EURO, "fix", ADMIN),
                    ("adjustment", 25 * EURO, "goodwill", ADMIN),
                ],
            "{recent:?}"
        );
        let entries = audit_entries(pool, "admin.organization.credit_adjustment").await?;
        ensure!(entries.len() == 2, "{entries:?}");
        ensure!(entries[1]["amount_nano_eur"] == -10 * EURO);
        ensure!(entries[1]["reason"] == "fix");
        ensure!(entries[1]["balance_nano_eur"] == 15 * EURO);

        // Invalid requests and unknown organizations change nothing.
        for (organization, amount, reason, key) in [
            (ORGANIZATION, 0, "r", "k3"),
            (ORGANIZATION, 1, "", "k3"),
            (ORGANIZATION, 1, "r", "bad key"),
        ] {
            let outcome =
                adjust_organization_credit_core(pool, ADMIN, organization, amount, reason, key)
                    .await;
            ensure!(
                matches!(outcome, Err(AppError::Validation { .. })),
                "{outcome:?}"
            );
        }
        let missing = adjust_organization_credit_core(pool, ADMIN, "missing", 1, "r", "k3").await;
        ensure!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        ensure!(
            organization_credit(pool, ORGANIZATION)
                .await
                .map_err(app_error)?
                .balance_nano_eur
                == 15 * EURO
        );
        ensure!(
            audit_entries(pool, "admin.organization.credit_adjustment")
                .await?
                .len()
                == 2
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
