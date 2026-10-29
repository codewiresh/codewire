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
        // Without a row, the defaults' CPU and memory caps apply.
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
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, ORGANIZATION).await?) == unlimited);

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
async fn db_quota_clear_restores_the_defaults_and_audits_only_a_removal() -> Result<()> {
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

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_organization_overview_reports_members_billing_quota_usage_and_key_names() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ('overview-member', $1, $2, 'admin')",
        )
        .bind(ORGANIZATION)
        .bind(ADMIN)
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE organizations SET billing_plan = 'team', billing_status = 'active', \
             billing_exempt = true WHERE id = $1",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_subscriptions (org_id, plan, status, updated_at) \
             VALUES ($1, 'unlimited', 'active', NOW())",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO org_subscriptions (org_id, plan, status, updated_at) \
             VALUES ($1, 'starter', 'canceled', NOW())",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets(id, org_id, name, slug, project_spec) \
             VALUES ('overview-preset', $1, 'Overview', 'overview', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        // A stopped environment that is meant to stay stopped consumes nothing.
        for (id, state, desired) in [
            ("overview-running", "running", "started"),
            ("overview-stopped", "stopped", "stopped"),
        ] {
            sqlx::query(
                "INSERT INTO environments \
                 (id, org_id, created_by, preset_id, type, state, desired_state, project_spec, \
                  cpu_millicores, memory_mb) \
                 VALUES ($1, $2, $3, 'overview-preset', 'sandbox', $4, $5, \
                 '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb, 2000, 8192)",
            )
            .bind(id)
            .bind(ORGANIZATION)
            .bind(ADMIN)
            .bind(state)
            .bind(desired)
            .execute(pool)
            .await?;
        }
        sqlx::query(
            "INSERT INTO api_keys (user_id, org_id, name, key_hash, key_prefix, disabled_at) VALUES \
             ($1, $2, 'load-tool', 'hash-must-not-appear', 'cw_prefix', NULL), \
             ($1, $2, 'retired', 'hash-must-not-appear-either', 'cw_old', NOW())",
        )
        .bind(ADMIN)
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        set_organization_environment_quota_core(pool, ADMIN, ORGANIZATION, RAISED)
            .await
            .map_err(app_error)?;

        let overview = get_organization_overview_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(overview.id == ORGANIZATION);
        ensure!(
            overview
                .members
                .iter()
                .any(|member| member.user_id == ADMIN
                    && member.role == "admin"
                    && member.email == format!("{ADMIN}@example.test")),
            "{:?}",
            overview.members
        );
        ensure!(overview.billing.billing_plan == "team");
        ensure!(overview.billing.billing_status == "active");
        ensure!(overview.billing.billing_exempt);
        // The live environment subscription wins over billing_plan.
        ensure!(overview.billing.effective_plan == "unlimited");
        ensure!(overview.billing.subscriptions.len() == 1, "{:?}", overview.billing);
        ensure!(overview.billing.subscriptions[0].kind == "environment");
        ensure!(overview.quota.explicit == Some(RAISED));
        // Only the running environment consumes compute.
        ensure!(
            overview.usage
                == AdminOrganizationUsage {
                    active_environments: 1,
                    active_sandboxes: 1,
                    cpu_millicores: 2000,
                    memory_mb: 8192,
                },
            "{:?}",
            overview.usage
        );
        let mut names: Vec<_> = overview
            .api_keys
            .iter()
            .map(|key| (key.name.as_str(), key.disabled))
            .collect();
        names.sort_unstable();
        ensure!(names == [("load-tool", false), ("retired", true)], "{names:?}");
        ensure!(!format!("{overview:?}").contains("hash-must-not-appear"));
        ensure!(!format!("{overview:?}").contains("cw_prefix"));

        let missing = get_organization_overview_core(pool, "missing").await;
        ensure!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_quota_defaults_apply_to_organizations_without_their_own_quota() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        db.organization("quota-planned").await?;
        db.organization("quota-own").await?;
        db.organization("quota-unlimited").await?;
        let pool = &db.pool;
        // A plan with a workspace limit, which no longer sets any limit
        // (#3381).
        sqlx::query(
            "INSERT INTO billing_catalog_plans \
             (resource_type, plan_key, display_name, price_cents, max_concurrent_ws, \
              cpu_overage_cents, mem_overage_cents) \
             VALUES ('sandbox', 'quota-seven', 'Seven', 0, 7, 1, 1)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE organizations SET billing_plan = 'quota-seven', billing_status = 'active' \
             WHERE id = 'quota-planned'",
        )
        .execute(pool)
        .await?;
        set_organization_environment_quota_core(pool, ADMIN, "quota-own", RAISED)
            .await
            .map_err(app_error)?;
        // The Unlimited card has no quota, even with its own quota stored.
        sqlx::query(
            "UPDATE organizations SET rate_card = 'unlimited' WHERE id = 'quota-unlimited'",
        )
        .execute(pool)
        .await?;
        set_organization_environment_quota_core(pool, ADMIN, "quota-unlimited", RAISED)
            .await
            .map_err(app_error)?;

        // The migration's seed is today's constants.
        let seeded = AdminEnvironmentQuota {
            max_concurrent_environments: 10,
            max_concurrent_sandbox: 50,
            max_cpu_millicores: 32_000,
            max_memory_mb: 65_536,
        };
        ensure!(
            get_default_environment_quota_core(pool)
                .await
                .map_err(app_error)?
                == (seeded, true)
        );
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, ORGANIZATION).await?) == seeded);

        let defaults = AdminEnvironmentQuota {
            max_concurrent_environments: 120,
            max_concurrent_sandbox: -1,
            max_cpu_millicores: 256_000,
            max_memory_mb: 1_048_576,
        };
        set_default_environment_quota_core(pool, ADMIN, defaults)
            .await
            .map_err(app_error)?;
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, ORGANIZATION).await?) == defaults);
        // A plan changes nothing: the defaults apply.
        ensure!(
            AdminEnvironmentQuota::from(get_org_quota(pool, "quota-planned").await?) == defaults
        );
        // An organization with its own quota is unaffected.
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, "quota-own").await?) == RAISED);
        // Unlimited has no limit at all.
        ensure!(
            AdminEnvironmentQuota::from(get_org_quota(pool, "quota-unlimited").await?)
                == AdminEnvironmentQuota::from(crate::api::environments::NO_QUOTA)
        );

        let entries: Vec<(String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT action, user_id, metadata FROM audit_logs \
             WHERE action = 'admin.environment_quota_defaults_set' AND severity = 'warn'",
        )
        .fetch_all(pool)
        .await?;
        ensure!(entries.len() == 1, "{entries:?}");
        let (_, user, metadata) = &entries[0];
        ensure!(user == ADMIN);
        ensure!(
            metadata["previous"] == serde_json::to_value(seeded)?,
            "{metadata}"
        );
        ensure!(
            metadata["quota"] == serde_json::to_value(defaults)?,
            "{metadata}"
        );

        // Invalid limits change nothing and write no audit entry.
        let outcome = set_default_environment_quota_core(
            pool,
            ADMIN,
            AdminEnvironmentQuota {
                max_cpu_millicores: 0,
                ..defaults
            },
        )
        .await;
        ensure!(
            matches!(outcome, Err(AppError::Validation { .. })),
            "{outcome:?}"
        );
        ensure!(
            get_default_environment_quota_core(pool)
                .await
                .map_err(app_error)?
                == (defaults, true)
        );

        // Without a stored row the built-in constants apply, and a write
        // stores the row again.
        sqlx::query("DELETE FROM environment_quota_defaults")
            .execute(pool)
            .await?;
        ensure!(
            get_default_environment_quota_core(pool)
                .await
                .map_err(app_error)?
                == (seeded, false)
        );
        ensure!(AdminEnvironmentQuota::from(get_org_quota(pool, ORGANIZATION).await?) == seeded);
        set_default_environment_quota_core(pool, ADMIN, seeded)
            .await
            .map_err(app_error)?;
        ensure!(
            get_default_environment_quota_core(pool)
                .await
                .map_err(app_error)?
                == (seeded, true)
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
