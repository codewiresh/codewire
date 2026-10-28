//! Disposable-PostgreSQL proof for the audited organization environment-quota
//! writes. Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;

use crate::test_database_support::TestDatabase;

const ADMIN: &str = "quota-admin";
const ORGANIZATION: &str = "quota-organization";

const RAISED: AdminEnvironmentQuota = AdminEnvironmentQuota {
    max_concurrent_environments: 200,
    max_concurrent_sandbox: 200,
    max_cpu_millicores: 400_000,
    max_memory_mb: 1_600_000,
};

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(ADMIN).await?;
    db.organization(ORGANIZATION).await?;
    Ok(())
}

/// The quota audit entries, oldest first, as (action, user, metadata).
async fn audit_entries(pool: &PgPool) -> Result<Vec<(String, String, serde_json::Value)>> {
    Ok(sqlx::query_as(
        "SELECT action, user_id, metadata FROM audit_logs \
         WHERE action LIKE 'admin.organization.environment_quota_%' AND severity = 'warn' \
         ORDER BY timestamp, id",
    )
    .fetch_all(pool)
    .await?)
}

fn app_error(error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_quota_set_overwrites_and_is_what_creates_are_checked_against() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;

        let before = get_organization_environment_quota_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(before.explicit.is_none());
        // Without a row, the plan fallback's fixed CPU and memory caps apply.
        ensure!(before.effective.max_cpu_millicores == 32_000);
        ensure!(before.effective.max_memory_mb == 65_536);

        set_organization_environment_quota_core(pool, ADMIN, ORGANIZATION, RAISED)
            .await
            .map_err(app_error)?;
        let unlimited = AdminEnvironmentQuota {
            max_concurrent_environments: -1,
            ..RAISED
        };
        set_organization_environment_quota_core(pool, ADMIN, ORGANIZATION, unlimited)
            .await
            .map_err(app_error)?;

        let after = get_organization_environment_quota_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(after.explicit == Some(unlimited), "{after:?}");
        ensure!(after.effective == unlimited, "{after:?}");
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, ORGANIZATION).await) == unlimited);

        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 2, "{entries:?}");
        let (action, user, first) = &entries[0];
        ensure!(action == "admin.organization.environment_quota_set");
        ensure!(user == ADMIN);
        ensure!(first["organization_id"] == ORGANIZATION);
        ensure!(first["previous"].is_null(), "{first}");
        ensure!(first["quota"]["max_memory_mb"] == 1_600_000);
        let (_, _, second) = &entries[1];
        ensure!(second["previous"]["max_concurrent_environments"] == 200);
        ensure!(second["quota"]["max_concurrent_environments"] == -1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_quota_clear_restores_the_plan_fallback_and_audits_only_a_removal() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;

        ensure!(
            !clear_organization_environment_quota_core(pool, ADMIN, ORGANIZATION)
                .await
                .map_err(app_error)?
        );
        ensure!(audit_entries(pool).await?.is_empty());

        set_organization_environment_quota_core(pool, ADMIN, ORGANIZATION, RAISED)
            .await
            .map_err(app_error)?;
        ensure!(
            clear_organization_environment_quota_core(pool, ADMIN, ORGANIZATION)
                .await
                .map_err(app_error)?
        );

        let after = get_organization_environment_quota_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(after.explicit.is_none());
        ensure!(after.effective.max_cpu_millicores == 32_000);

        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 2, "{entries:?}");
        let (action, user, cleared) = &entries[1];
        ensure!(action == "admin.organization.environment_quota_clear");
        ensure!(user == ADMIN);
        ensure!(cleared["organization_id"] == ORGANIZATION);
        ensure!(cleared["previous"]["max_cpu_millicores"] == 400_000);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_quota_writes_refuse_an_unknown_organization_and_invalid_limits() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;

        for outcome in [
            get_organization_environment_quota_core(pool, "missing")
                .await
                .map(|_| ()),
            set_organization_environment_quota_core(pool, ADMIN, "missing", RAISED)
                .await
                .map(|_| ()),
            clear_organization_environment_quota_core(pool, ADMIN, "missing")
                .await
                .map(|_| ()),
        ] {
            ensure!(matches!(outcome, Err(AppError::NotFound(_))), "{outcome:?}");
        }

        for invalid in [
            AdminEnvironmentQuota {
                max_concurrent_sandbox: 0,
                ..RAISED
            },
            AdminEnvironmentQuota {
                max_memory_mb: -2,
                ..RAISED
            },
        ] {
            let outcome =
                set_organization_environment_quota_core(pool, ADMIN, ORGANIZATION, invalid).await;
            ensure!(
                matches!(outcome, Err(AppError::Validation { .. })),
                "{outcome:?}"
            );
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM environment_quotas")
            .fetch_one(pool)
            .await?;
        ensure!(count == 0, "{count}");
        ensure!(audit_entries(pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
