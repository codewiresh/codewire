//! Disposable-PostgreSQL proof for suspending an account (#3297 item 4). Only
//! synthetic rows in an isolated test database are used.
use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::suspension::{suspend_account_core, unsuspend_account_core};
use super::*;
use crate::api::environments::{OrgQuota, check_quota_in};
use crate::test_database_support::TestDatabase;
use crate::worker::suspension_stop::suspended_environment_ids;
use codewire_server_core::credit_enforcement::CreditEnforcement;

const ADMIN: &str = "suspend-admin";
const TARGET: &str = "suspend-target";
const PARTNER: &str = "suspend-partner";
/// Owned by the target alone.
const SOLE: &str = "suspend-sole-org";
/// Owned by the target and the partner.
const SHARED: &str = "suspend-shared-org";

fn app_error(error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

async fn execute(pool: &PgPool, sql: &str, binds: &[&str]) -> Result<()> {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    query.execute(pool).await?;
    Ok(())
}

async fn seed(pool: &PgPool) -> Result<()> {
    for user in [ADMIN, TARGET, PARTNER] {
        execute(
            pool,
            "INSERT INTO users (id, email, enabled) VALUES ($1, $1 || '@example.test', true)",
            &[user],
        )
        .await?;
    }
    for (org, owners) in [(SOLE, &[TARGET][..]), (SHARED, &[TARGET, PARTNER][..])] {
        execute(
            pool,
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)",
            &[org, TARGET],
        )
        .await?;
        for owner in owners {
            execute(
                pool,
                "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1 || $2, $1, $2, 'owner')",
                &[org, owner],
            )
            .await?;
        }
        execute(
            pool,
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
            &[org],
        )
        .await?;
        execute(
            pool,
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, \
             desired_state, project_spec) \
             VALUES ($1 || '-running', $1, $2, 'sandbox', $1, 'running', 'started', '{}'::jsonb)",
            &[org, TARGET],
        )
        .await?;
        execute(
            pool,
            "INSERT INTO environment_ports (environment_id, port, label, access) \
             VALUES ($1 || '-running', 3000, 'web', 'public')",
            &[org],
        )
        .await?;
    }
    // The partner's own environment in the shared organization.
    execute(
        pool,
        "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, \
         desired_state, project_spec) \
         VALUES ($1 || '-partner', $1, $2, 'sandbox', $1, 'running', 'started', '{}'::jsonb)",
        &[SHARED, PARTNER],
    )
    .await?;
    execute(
        pool,
        "INSERT INTO environment_ports (environment_id, port, label, access) \
         VALUES ($1 || '-partner', 3000, 'web', 'public')",
        &[SHARED],
    )
    .await?;
    execute(
        pool,
        "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
         VALUES ('suspend-session', $1, now() + interval '1 hour', repeat('a', 64))",
        &[TARGET],
    )
    .await?;
    execute(
        pool,
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ('suspend-key', $1, $2, 'key', 'suspend-key-hash', 'cw_susp')",
        &[TARGET, SOLE],
    )
    .await
}

async fn suspended_organizations(pool: &PgPool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM organizations WHERE suspended_at IS NOT NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

async fn port_access(pool: &PgPool, org: &str) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT access FROM environment_ports WHERE environment_id = $1 || '-running'",
    )
    .bind(org)
    .fetch_one(pool)
    .await?)
}

async fn audit_actions(pool: &PgPool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT action FROM audit_logs WHERE user_id = $1 AND target_user_id = $2 \
         ORDER BY timestamp, action",
    )
    .bind(ADMIN)
    .bind(TARGET)
    .fetch_all(pool)
    .await?)
}

async fn refusal(pool: &PgPool, org: &str) -> Result<Option<String>> {
    let mut transaction = pool.begin().await?;
    // The admission every create and start goes through, with room to spare.
    let quota = OrgQuota {
        max_concurrent_environments: 100,
        max_concurrent_sandbox: 100,
        max_cpu_millicores: 1_000_000,
        max_memory_mb: 1_000_000,
    };
    let outcome = check_quota_in(
        &mut transaction,
        org,
        crate::api::environments::QuotaRequest {
            credit_enforcement: CreditEnforcement::Off,
            quota,
            env_type: "sandbox",
            backend: crate::runtime::RuntimeBackend::Kubernetes,
            cpu_millicores: 1_000,
            memory_mb: 1_024,
            disk_gb: 10,
        },
    )
    .await;
    transaction.rollback().await?;
    Ok(match outcome {
        Ok(()) => None,
        Err(AppError::Coded { code, .. }) => Some(code.to_owned()),
        Err(other) => Some(format!("{other:?}")),
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_suspension_stops_the_sole_owned_organization_and_unsuspension_restores_only_the_marks()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        seed(pool).await?;

        // Refusals change nothing.
        let own = suspend_account_core(pool, ADMIN, ADMIN, "self").await;
        ensure!(matches!(own, Err(AppError::BadRequest(_))), "{own:?}");
        let blank = suspend_account_core(pool, ADMIN, TARGET, "  ").await;
        ensure!(
            matches!(blank, Err(AppError::Validation { .. })),
            "{blank:?}"
        );
        let missing = suspend_account_core(pool, ADMIN, "nobody", "spam").await;
        ensure!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        ensure!(suspended_organizations(pool).await?.is_empty());

        let suspension = suspend_account_core(pool, ADMIN, TARGET, "mining on a stolen card")
            .await
            .map_err(app_error)?;
        ensure!(
            suspension.suspended_organizations == [SOLE],
            "{suspension:?}"
        );
        ensure!(
            suspension.shared_organizations == [SHARED],
            "{suspension:?}"
        );
        ensure!(
            suspension.created_environments == [format!("{SHARED}-running")],
            "{suspension:?}"
        );
        ensure!(suspension.ports_restricted == 2, "{suspension:?}");

        // The account can't sign in and its credentials are revoked.
        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM users WHERE id = $1")
            .bind(TARGET)
            .fetch_one(pool)
            .await?;
        ensure!(!enabled);
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1")
            .bind(TARGET)
            .fetch_one(pool)
            .await?;
        ensure!(sessions == 0, "{sessions}");
        let key_disabled: bool = sqlx::query_scalar(
            "SELECT disabled_at IS NOT NULL FROM api_keys WHERE id = 'suspend-key'",
        )
        .fetch_one(pool)
        .await?;
        ensure!(key_disabled);

        // Only the sole-owned organization is suspended, refused and stopped.
        ensure!(suspended_organizations(pool).await? == [SOLE]);
        ensure!(refusal(pool, SOLE).await?.as_deref() == Some("organization_suspended"));
        ensure!(refusal(pool, SHARED).await?.is_none());
        // Stopped: everything in the suspended organization, and what the
        // account created in the shared one; the partner's own keeps running.
        ensure!(
            suspended_environment_ids(pool).await?
                == [format!("{SHARED}-running"), format!("{SOLE}-running")]
        );
        ensure!(port_access(pool, SOLE).await? == "creator");
        ensure!(port_access(pool, SHARED).await? == "creator");
        let partner_port: String = sqlx::query_scalar(
            "SELECT access FROM environment_ports WHERE environment_id = $1 || '-partner'",
        )
        .bind(SHARED)
        .fetch_one(pool)
        .await?;
        ensure!(partner_port == "public", "{partner_port}");
        // No path enables a suspended account.
        let enabled = sqlx::query("UPDATE users SET enabled = true WHERE id = $1")
            .bind(TARGET)
            .execute(pool)
            .await;
        ensure!(
            matches!(&enabled, Err(sqlx::Error::Database(error))
                if error.constraint() == Some("users_suspended_disabled_check")),
            "{enabled:?}"
        );
        ensure!(
            audit_actions(pool).await?
                == ["admin.account.suspended", "admin.organization.suspended"]
        );

        let again = suspend_account_core(pool, ADMIN, TARGET, "again").await;
        ensure!(matches!(again, Err(AppError::Conflict(_))), "{again:?}");

        // A second owner added meanwhile doesn't strand the organization.
        execute(
            pool,
            "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1 || $2, $1, $2, 'owner')",
            &[SOLE, PARTNER],
        )
        .await?;
        let unsuspension = unsuspend_account_core(pool, ADMIN, TARGET)
            .await
            .map_err(app_error)?;
        ensure!(
            unsuspension.unsuspended_organizations == [SOLE],
            "{unsuspension:?}"
        );
        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM users WHERE id = $1")
            .bind(TARGET)
            .fetch_one(pool)
            .await?;
        ensure!(enabled);
        ensure!(suspended_organizations(pool).await?.is_empty());
        ensure!(refusal(pool, SOLE).await?.is_none());
        ensure!(suspended_environment_ids(pool).await?.is_empty());
        // Nothing suspension revoked or narrowed comes back.
        let key_disabled: bool = sqlx::query_scalar(
            "SELECT disabled_at IS NOT NULL FROM api_keys WHERE id = 'suspend-key'",
        )
        .fetch_one(pool)
        .await?;
        ensure!(key_disabled);
        ensure!(port_access(pool, SOLE).await? == "creator");
        ensure!(
            audit_actions(pool).await?.last().map(String::as_str)
                == Some("admin.account.unsuspended")
        );

        let not_suspended = unsuspend_account_core(pool, ADMIN, TARGET).await;
        ensure!(
            matches!(not_suspended, Err(AppError::Conflict(_))),
            "{not_suspended:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_account_being_deleted_is_not_suspended() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        seed(pool).await?;
        execute(
            pool,
            "INSERT INTO account_deletion_operations (id, user_id, workflow_id, email) \
             VALUES ('account-deletion/suspend-test', $1, 'account-deletion/suspend-test', \
                     $1 || '@example.test')",
            &[TARGET],
        )
        .await?;
        let refused = suspend_account_core(pool, ADMIN, TARGET, "spam").await;
        ensure!(matches!(refused, Err(AppError::Conflict(_))), "{refused:?}");
        let suspended: bool =
            sqlx::query_scalar("SELECT suspended_at IS NOT NULL FROM users WHERE id = $1")
                .bind(TARGET)
                .fetch_one(pool)
                .await?;
        ensure!(!suspended, "an account being deleted was suspended");
        ensure!(suspended_organizations(pool).await?.is_empty());
        ensure!(audit_actions(pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
