//! Durable billing phase for organization deletion.
//!
//! This is deliberately dark until the organization workflow lands in WI-5.
//! It captures provider identifiers before local rows can disappear, waits for
//! pre-fence billing mutations to reach their server-selected deadline,
//! re-enumerates Stripe, expires Checkout entrypoints, and verifies every
//! subscription terminal before returning success.

use std::collections::BTreeSet;

use chrono::Datelike;
use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    mark_organization_mutation_resolution_required, resolve_organization_mutation_lease,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::metering::aggregate_monthly_usage;
use crate::stripe_client::StripeHandle;

const BILLING_LEASE_DEADLINE_CODE: &str = "billing_provider_deadline_elapsed";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationBillingTeardownInput {
    pub operation_id: String,
    pub organization_id: String,
    pub generation: i64,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationBillingTeardownResult {
    pub state: String,
    pub terminal_subscription_count: u32,
}

#[derive(Debug, FromRow)]
struct BillingPhase {
    stripe_customer_id: Option<String>,
    state: String,
}

#[derive(Debug, FromRow)]
struct BillingLease {
    id: String,
    state: String,
    deadline_elapsed: bool,
}

/// Execute or resume one generation's billing phase.
pub async fn finalize_organization_billing(
    pool: &PgPool,
    stripe: &StripeHandle,
    input: &OrganizationBillingTeardownInput,
) -> Result<OrganizationBillingTeardownResult, AppError> {
    let mut phase = prepare_phase(pool, input).await?;
    if phase.state == "completed" {
        return completed_result(pool, input).await;
    }

    let leases = prepare_billing_leases(pool, input).await?;
    finalize_usage(pool, input).await?;

    let mut captured = captured_subscription_ids(pool, input).await?;
    let needs_provider = phase
        .stripe_customer_id
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || !captured.is_empty()
        || !leases.is_empty();

    if needs_provider && !stripe.is_configured() {
        return Err(AppError::Precondition(
            "billing provider is required to verify organization teardown".into(),
        ));
    }

    if stripe.is_configured() {
        if phase
            .stripe_customer_id
            .as_deref()
            .is_none_or(|value| value.is_empty())
            && !leases.is_empty()
        {
            let (name, owner_email): (String, String) = sqlx::query_as(
                r#"SELECT o.name, u.email
                   FROM organizations o
                   JOIN org_members member
                     ON member.org_id = o.id AND member.role = 'owner'
                   JOIN users u ON u.id = member.user_id
                   WHERE o.id = $1
                   ORDER BY member.created_at ASC
                   LIMIT 1"#,
            )
            .bind(&input.organization_id)
            .fetch_one(pool)
            .await
            .map_err(AppError::from)?;
            let key = idempotency_key("recover-customer", &[&input.organization_id]);
            let customer_id = stripe
                .ensure_customer(pool, &input.organization_id, &name, &owner_email, &key)
                .await?;
            sqlx::query(
                r#"UPDATE organization_deletion_billing_phases
                   SET stripe_customer_id = $2, updated_at = NOW()
                   WHERE operation_id = $1"#,
            )
            .bind(&input.operation_id)
            .bind(&customer_id)
            .execute(pool)
            .await
            .map_err(AppError::from)?;
            phase.stripe_customer_id = Some(customer_id);
        }

        if let Some(customer_id) = phase
            .stripe_customer_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            expire_checkout_sessions(stripe, input, customer_id).await?;
            mark_checkout_sessions_expired(pool, input).await?;

            for subscription_id in stripe
                .list_nonterminal_subscription_ids(customer_id)
                .await?
            {
                captured.insert(subscription_id);
            }
            persist_captured_subscriptions(pool, input, &captured).await?;
        } else {
            mark_checkout_sessions_expired(pool, input).await?;
        }

        for subscription_id in &captured {
            if !stripe.subscription_is_terminal(subscription_id).await? {
                let key = idempotency_key(
                    "delete-subscription",
                    &[&input.operation_id, subscription_id],
                );
                stripe.cancel_subscription(subscription_id, &key).await?;
            }
            if !stripe.subscription_is_terminal(subscription_id).await? {
                return Err(AppError::ServiceUnavailable(
                    "billing subscription is not terminal".into(),
                ));
            }
            mark_subscription_terminal(pool, input, subscription_id).await?;
        }

        if let Some(customer_id) = phase
            .stripe_customer_id
            .as_deref()
            .filter(|value| !value.is_empty())
            && !stripe
                .list_nonterminal_subscription_ids(customer_id)
                .await?
                .is_empty()
        {
            return Err(AppError::ServiceUnavailable(
                "billing subscription re-enumeration is not empty".into(),
            ));
        }
    } else {
        mark_checkout_sessions_expired(pool, input).await?;
    }

    mark_subscriptions_verified(pool, input).await?;
    for lease in &leases {
        resolve_organization_mutation_lease(pool, &lease.id).await?;
    }
    complete_phase(pool, input).await?;
    completed_result(pool, input).await
}

async fn prepare_phase(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<BillingPhase, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let current: Option<(String, i64, String, String, Option<String>)> = sqlx::query_as(
        r#"SELECT org.deletion_operation_id, org.deletion_generation,
                  org.deletion_state, operation.state, org.stripe_customer_id
           FROM organizations org
           JOIN organization_deletion_operations operation
             ON operation.id = org.deletion_operation_id
           WHERE org.id = $1 AND operation.id = $2
           FOR UPDATE OF org, operation"#,
    )
    .bind(&input.organization_id)
    .bind(&input.operation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?;
    let Some((operation_id, generation, deletion_state, operation_state, customer_id)) = current
    else {
        return Err(AppError::NotFound(
            "organization deletion generation not found".into(),
        ));
    };
    if operation_id != input.operation_id
        || generation != input.generation
        || deletion_state != "deleting"
        || operation_state != "started"
    {
        return Err(AppError::Conflict(
            "organization deletion generation is no longer current".into(),
        ));
    }

    sqlx::query(
        r#"INSERT INTO organization_deletion_billing_phases
               (operation_id, organization_id, generation, stripe_customer_id, state)
           VALUES ($1, $2, $3, $4, 'running')
           ON CONFLICT (operation_id) DO UPDATE
           SET state = CASE
                   WHEN organization_deletion_billing_phases.state = 'pending'
                   THEN 'running'
                   ELSE organization_deletion_billing_phases.state
               END,
               stripe_customer_id = COALESCE(
                   organization_deletion_billing_phases.stripe_customer_id,
                   EXCLUDED.stripe_customer_id
               ),
               updated_at = NOW()
           WHERE organization_deletion_billing_phases.organization_id = EXCLUDED.organization_id
             AND organization_deletion_billing_phases.generation = EXCLUDED.generation"#,
    )
    .bind(&input.operation_id)
    .bind(&input.organization_id)
    .bind(input.generation)
    .bind(customer_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    sqlx::query(
        r#"INSERT INTO organization_deletion_billing_subscriptions
               (operation_id, organization_id, generation, stripe_subscription_id)
           SELECT $1, $2, $3, subscription_id
           FROM (
               SELECT stripe_subscription_id AS subscription_id
               FROM org_subscriptions
               WHERE org_id = $2 AND stripe_subscription_id IS NOT NULL
                 AND stripe_subscription_id <> ''
               UNION
               SELECT stripe_subscription_id AS subscription_id
               FROM environment_subscriptions
               WHERE org_id = $2 AND stripe_subscription_id IS NOT NULL
                 AND stripe_subscription_id <> ''
           ) captured
           ON CONFLICT (operation_id, stripe_subscription_id) DO NOTHING"#,
    )
    .bind(&input.operation_id)
    .bind(&input.organization_id)
    .bind(input.generation)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    let phase = sqlx::query_as::<_, BillingPhase>(
        r#"SELECT stripe_customer_id, state
           FROM organization_deletion_billing_phases
           WHERE operation_id = $1"#,
    )
    .bind(&input.operation_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(phase)
}

async fn prepare_billing_leases(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<Vec<BillingLease>, AppError> {
    let leases = sqlx::query_as::<_, BillingLease>(
        r#"SELECT id, state, deadline_at <= NOW() AS deadline_elapsed
           FROM organization_mutation_leases
           WHERE organization_id = $1
             AND mutation_class = 'billing_provider'
             AND state IN ('active', 'resolution_required')
           ORDER BY admitted_at, id"#,
    )
    .bind(&input.organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;

    if leases
        .iter()
        .any(|lease| lease.state == "active" && !lease.deadline_elapsed)
    {
        return Err(AppError::Conflict(
            "billing mutation deadline has not elapsed".into(),
        ));
    }
    for lease in &leases {
        if lease.state == "active" {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                BILLING_LEASE_DEADLINE_CODE,
            )
            .await?;
        }
    }
    Ok(leases)
}

async fn finalize_usage(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<(), AppError> {
    let open_sessions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM sandbox_running_sessions
           WHERE organization_id = $1 AND ended_at IS NULL"#,
    )
    .bind(&input.organization_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;
    if open_sessions != 0 {
        return Err(AppError::Conflict(
            "billing usage sessions are still open".into(),
        ));
    }

    let now = chrono::Utc::now();
    let period_start =
        chrono::NaiveDate::from_ymd_opt(now.date_naive().year(), now.date_naive().month(), 1)
            .expect("valid month start")
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight")
            .and_utc();
    let mut usage_by_tier = Vec::with_capacity(2);
    for runtime_tier in ["standard", "confidential"] {
        usage_by_tier.push((
            runtime_tier,
            aggregate_monthly_usage(pool, &input.organization_id, period_start, runtime_tier)
                .await
                .map_err(AppError::Internal)?,
        ));
    }

    let mut tx = pool.begin().await.map_err(AppError::from)?;
    for (runtime_tier, (cpu_hours, mem_gb_hours, disk_gb_hours)) in usage_by_tier {
        sqlx::query(
            r#"INSERT INTO environment_usage_billing_tiers
                   (org_id, billing_period_start, runtime_tier, last_cpu_hours, last_mem_gb_hours,
                    last_disk_gb_hours, last_overage_cents, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())
               ON CONFLICT (org_id, billing_period_start, runtime_tier) DO UPDATE
               SET last_cpu_hours = EXCLUDED.last_cpu_hours,
                   last_mem_gb_hours = EXCLUDED.last_mem_gb_hours,
                   last_disk_gb_hours = EXCLUDED.last_disk_gb_hours,
                   updated_at = NOW()"#,
        )
        .bind(&input.organization_id)
        .bind(period_start)
        .bind(runtime_tier)
        .bind(cpu_hours)
        .bind(mem_gb_hours)
        .bind(disk_gb_hours)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    }
    sqlx::query(
        r#"UPDATE organization_deletion_billing_phases
           SET final_usage_completed_at = COALESCE(final_usage_completed_at, NOW()),
               updated_at = NOW()
           WHERE operation_id = $1 AND organization_id = $2 AND generation = $3"#,
    )
    .bind(&input.operation_id)
    .bind(&input.organization_id)
    .bind(input.generation)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(())
}

async fn expire_checkout_sessions(
    stripe: &StripeHandle,
    input: &OrganizationBillingTeardownInput,
    customer_id: &str,
) -> Result<(), AppError> {
    for session_id in stripe.list_open_checkout_session_ids(customer_id).await? {
        let key = idempotency_key("expire-checkout", &[&input.operation_id, &session_id]);
        stripe.expire_checkout_session(&session_id, &key).await?;
    }
    if !stripe
        .list_open_checkout_session_ids(customer_id)
        .await?
        .is_empty()
    {
        return Err(AppError::ServiceUnavailable(
            "billing checkout-session re-enumeration is not empty".into(),
        ));
    }
    Ok(())
}

async fn captured_subscription_ids(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<BTreeSet<String>, AppError> {
    let rows: Vec<String> = sqlx::query_scalar(
        r#"SELECT stripe_subscription_id
           FROM organization_deletion_billing_subscriptions
           WHERE operation_id = $1
           ORDER BY stripe_subscription_id"#,
    )
    .bind(&input.operation_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;
    Ok(rows.into_iter().collect())
}

async fn persist_captured_subscriptions(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
    subscriptions: &BTreeSet<String>,
) -> Result<(), AppError> {
    for subscription_id in subscriptions {
        sqlx::query(
            r#"INSERT INTO organization_deletion_billing_subscriptions
                   (operation_id, organization_id, generation, stripe_subscription_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (operation_id, stripe_subscription_id) DO NOTHING"#,
        )
        .bind(&input.operation_id)
        .bind(&input.organization_id)
        .bind(input.generation)
        .bind(subscription_id)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
    }
    Ok(())
}

async fn mark_subscription_terminal(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
    subscription_id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE organization_deletion_billing_subscriptions
           SET state = 'terminal',
               verified_terminal_at = COALESCE(verified_terminal_at, NOW()),
               updated_at = NOW()
           WHERE operation_id = $1 AND stripe_subscription_id = $2"#,
    )
    .bind(&input.operation_id)
    .bind(subscription_id)
    .execute(pool)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

async fn mark_checkout_sessions_expired(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<(), AppError> {
    mark_phase_timestamp(pool, input, "checkout_sessions_expired_at").await
}

async fn mark_subscriptions_verified(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<(), AppError> {
    mark_phase_timestamp(pool, input, "subscriptions_verified_at").await
}

async fn mark_phase_timestamp(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
    column: &str,
) -> Result<(), AppError> {
    let statement = match column {
        "checkout_sessions_expired_at" => {
            "UPDATE organization_deletion_billing_phases SET checkout_sessions_expired_at = COALESCE(checkout_sessions_expired_at, NOW()), updated_at = NOW() WHERE operation_id = $1 AND organization_id = $2 AND generation = $3"
        }
        "subscriptions_verified_at" => {
            "UPDATE organization_deletion_billing_phases SET subscriptions_verified_at = COALESCE(subscriptions_verified_at, NOW()), updated_at = NOW() WHERE operation_id = $1 AND organization_id = $2 AND generation = $3"
        }
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "unknown billing phase timestamp"
            )));
        }
    };
    sqlx::query(statement)
        .bind(&input.operation_id)
        .bind(&input.organization_id)
        .bind(input.generation)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

async fn complete_phase(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"UPDATE organization_deletion_billing_phases
           SET state = 'completed', completed_at = COALESCE(completed_at, NOW()),
               failure_code = NULL, updated_at = NOW()
           WHERE operation_id = $1 AND organization_id = $2 AND generation = $3
             AND final_usage_completed_at IS NOT NULL
             AND checkout_sessions_expired_at IS NOT NULL
             AND subscriptions_verified_at IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1 FROM organization_deletion_billing_subscriptions subscription
                 WHERE subscription.operation_id = organization_deletion_billing_phases.operation_id
                   AND subscription.state <> 'terminal'
             )"#,
    )
    .bind(&input.operation_id)
    .bind(&input.organization_id)
    .bind(input.generation)
    .execute(pool)
    .await
    .map_err(AppError::from)?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "billing teardown evidence is incomplete".into(),
        ));
    }
    Ok(())
}

async fn completed_result(
    pool: &PgPool,
    input: &OrganizationBillingTeardownInput,
) -> Result<OrganizationBillingTeardownResult, AppError> {
    let terminal_subscription_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM organization_deletion_billing_subscriptions
           WHERE operation_id = $1 AND state = 'terminal'"#,
    )
    .bind(&input.operation_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;
    Ok(OrganizationBillingTeardownResult {
        state: "completed".into(),
        terminal_subscription_count: terminal_subscription_count
            .try_into()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("billing count overflow")))?,
    })
}

fn idempotency_key(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("cw-{kind}-{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::Json;
    use axum::Router;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use codewire_server_core::auth::AuthUser;
    use codewire_server_core::org_deletion::{
        OrganizationMutationClass, acquire_organization_mutation_lease,
        begin_organization_deletion, mark_organization_deletion_started,
    };
    use serde_json::{Value, json};
    use sqlx::postgres::PgPoolOptions;
    use tokio::task::JoinHandle;

    use super::*;

    struct Fixture {
        owner_id: String,
        organization_id: String,
        operation_id: String,
        generation: i64,
        environment_id: String,
        preset_id: String,
        billing_lease_id: Option<String>,
    }

    #[derive(Clone, Copy)]
    enum ProviderMode {
        Cancel,
        Gone,
        Failure,
        Empty,
    }

    struct FakeStripeState {
        pool: PgPool,
        operation_id: String,
        subscription_id: String,
        mode: ProviderMode,
        canceled: AtomicBool,
        cancel_calls: AtomicUsize,
        usage_was_finalized: AtomicBool,
        local_subscription_was_absent: AtomicBool,
    }

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                eprintln!("DATABASE_URL unset — skipping organization billing teardown DB flow");
                return None;
            }
        };
        Some(
            PgPoolOptions::new()
                .max_connections(10)
                .connect(&url)
                .await
                .expect("connect organization billing teardown test database"),
        )
    }

    async fn seed(
        pool: &PgPool,
        customer_id: Option<&str>,
        subscription_id: Option<&str>,
        create_billing_lease: bool,
    ) -> Fixture {
        let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(pool)
            .await
            .unwrap();
        let owner_id = format!("u_billdel_{namespace}");
        let organization_id = format!("org_billdel_{namespace}");
        let environment_id = format!("env_billdel_{namespace}");
        let preset_id = format!("preset_billdel_{namespace}");

        sqlx::query(
            r#"INSERT INTO users (id, email, name, email_verified, is_admin)
               VALUES ($1, $2, 'Billing deletion owner', true, false)"#,
        )
        .bind(&owner_id)
        .bind(format!("{namespace}@example.test"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO organizations (id, name, slug, created_by, stripe_customer_id)
               VALUES ($1, 'Billing deletion', $2, $3, $4)"#,
        )
        .bind(&organization_id)
        .bind(format!("billdel-{namespace}"))
        .bind(&owner_id)
        .bind(customer_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO org_members (id, org_id, user_id, role)
               VALUES ($1, $2, $3, 'owner')"#,
        )
        .bind(format!("om_billdel_{namespace}"))
        .bind(&organization_id)
        .bind(&owner_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO environment_presets (id, org_id, name)
               VALUES ($1, $2, 'Billing deletion preset')"#,
        )
        .bind(&preset_id)
        .bind(&organization_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO environments
                   (id, org_id, created_by, type, state, desired_state, preset_id)
               VALUES ($1, $2, $3, 'sandbox', 'destroyed', 'destroyed', $4)"#,
        )
        .bind(&environment_id)
        .bind(&organization_id)
        .bind(&owner_id)
        .bind(&preset_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO sandbox_running_sessions
                   (id, environment_id, organization_id, runtime_uid, runtime_name,
                    runtime_namespace, cpu_millicores, memory_mib, disk_gib,
                    started_at, last_observed_at, ended_at, end_reason)
               VALUES ($1, $2, $3, $4, $5, 'codewire-sandboxes', 1000, 1024, 2,
                       NOW() - INTERVAL '20 minutes', NOW() - INTERVAL '10 minutes',
                       NOW() - INTERVAL '10 minutes', 'destroyed')"#,
        )
        .bind(format!("srs_billdel_{namespace}"))
        .bind(&environment_id)
        .bind(&organization_id)
        .bind(format!("uid-{namespace}"))
        .bind(format!("sandbox-{namespace}"))
        .execute(pool)
        .await
        .unwrap();
        if let Some(subscription_id) = subscription_id {
            sqlx::query(
                r#"INSERT INTO org_subscriptions
                       (id, org_id, plan, status, stripe_subscription_id)
                   VALUES ($1, $2, 'starter', 'active', $3)"#,
            )
            .bind(format!("os_billdel_{namespace}"))
            .bind(&organization_id)
            .bind(subscription_id)
            .execute(pool)
            .await
            .unwrap();
        }

        let billing_lease_id = if create_billing_lease {
            Some(
                acquire_organization_mutation_lease(
                    pool,
                    &organization_id,
                    OrganizationMutationClass::BillingProvider,
                )
                .await
                .unwrap()
                .id,
            )
        } else {
            None
        };
        let owner = AuthUser {
            user_id: owner_id.clone(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let operation = begin_organization_deletion(pool, &owner, &organization_id)
            .await
            .unwrap();
        mark_organization_deletion_started(pool, &operation.id, operation.generation)
            .await
            .unwrap();

        Fixture {
            owner_id,
            organization_id,
            operation_id: operation.id,
            generation: operation.generation,
            environment_id,
            preset_id,
            billing_lease_id,
        }
    }

    async fn cleanup(pool: &PgPool, fixture: &Fixture) {
        let _ = sqlx::query("DELETE FROM environment_usage_billing_tiers WHERE org_id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM sandbox_running_sessions WHERE organization_id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(&fixture.environment_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&fixture.preset_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM org_subscriptions WHERE org_id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM org_members WHERE org_id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM organization_mutation_leases WHERE organization_id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM organization_deletion_operations WHERE id = $1")
            .bind(&fixture.operation_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM audit_logs WHERE metadata->>'organization_id' = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&fixture.owner_id)
            .execute(pool)
            .await;
    }

    fn input(fixture: &Fixture) -> OrganizationBillingTeardownInput {
        OrganizationBillingTeardownInput {
            operation_id: fixture.operation_id.clone(),
            organization_id: fixture.organization_id.clone(),
            generation: fixture.generation,
        }
    }

    fn stripe_error(status: StatusCode, message: &str) -> Response {
        (
            status,
            Json(json!({
                "error": {
                    "message": message,
                    "type": "api_error"
                }
            })),
        )
            .into_response()
    }

    fn empty_list(path: &str) -> Value {
        json!({
            "object": "list",
            "data": [],
            "has_more": false,
            "url": path
        })
    }

    fn subscription(id: &str, status: &str) -> Value {
        json!({
            "object": "subscription",
            "id": id,
            "automatic_tax": {"enabled": false},
            "billing_cycle_anchor": 1_700_000_000,
            "billing_mode": {"type": "classic"},
            "cancel_at_period_end": false,
            "collection_method": "charge_automatically",
            "created": 1_700_000_000,
            "currency": "usd",
            "customer": "cus_codewire",
            "discounts": [],
            "invoice_settings": {"issuer": {"type": "self"}},
            "items": {
                "object": "list",
                "data": [],
                "has_more": false,
                "url": "/v1/subscription_items"
            },
            "livemode": false,
            "metadata": {},
            "start_date": 1_700_000_000,
            "status": status
        })
    }

    async fn list_checkout_sessions() -> Json<Value> {
        Json(empty_list("/v1/checkout/sessions"))
    }

    async fn list_subscriptions() -> Json<Value> {
        Json(empty_list("/v1/subscriptions"))
    }

    async fn retrieve_subscription(
        State(state): State<Arc<FakeStripeState>>,
        Path(id): Path<String>,
    ) -> Response {
        if id != state.subscription_id {
            return stripe_error(StatusCode::NOT_FOUND, "subscription not found");
        }
        match state.mode {
            ProviderMode::Cancel => Json(subscription(
                &id,
                if state.canceled.load(Ordering::SeqCst) {
                    "canceled"
                } else {
                    "active"
                },
            ))
            .into_response(),
            ProviderMode::Gone => stripe_error(StatusCode::NOT_FOUND, "subscription not found"),
            ProviderMode::Failure => stripe_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "injected provider failure",
            ),
            ProviderMode::Empty => stripe_error(StatusCode::NOT_FOUND, "subscription not found"),
        }
    }

    async fn cancel_subscription(
        State(state): State<Arc<FakeStripeState>>,
        Path(id): Path<String>,
    ) -> Response {
        state.cancel_calls.fetch_add(1, Ordering::SeqCst);
        let usage_ready: bool = sqlx::query_scalar(
            r#"SELECT final_usage_completed_at IS NOT NULL
               FROM organization_deletion_billing_phases
               WHERE operation_id = $1"#,
        )
        .bind(&state.operation_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);
        state
            .usage_was_finalized
            .store(usage_ready, Ordering::SeqCst);
        let local_subscription_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM org_subscriptions WHERE stripe_subscription_id = $1",
        )
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(-1);
        state
            .local_subscription_was_absent
            .store(local_subscription_count == 0, Ordering::SeqCst);

        if !matches!(state.mode, ProviderMode::Cancel) {
            return stripe_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected cancellation");
        }
        state.canceled.store(true, Ordering::SeqCst);
        Json(subscription(&id, "canceled")).into_response()
    }

    async fn fake_stripe(
        pool: &PgPool,
        operation_id: &str,
        subscription_id: &str,
        mode: ProviderMode,
    ) -> (StripeHandle, Arc<FakeStripeState>, JoinHandle<()>) {
        let state = Arc::new(FakeStripeState {
            pool: pool.clone(),
            operation_id: operation_id.to_string(),
            subscription_id: subscription_id.to_string(),
            mode,
            canceled: AtomicBool::new(false),
            cancel_calls: AtomicUsize::new(0),
            usage_was_finalized: AtomicBool::new(false),
            local_subscription_was_absent: AtomicBool::new(false),
        });
        let app = Router::new()
            .route("/v1/checkout/sessions", get(list_checkout_sessions))
            .route("/v1/subscriptions", get(list_subscriptions))
            .route(
                "/v1/subscriptions/{id}",
                get(retrieve_subscription).delete(cancel_subscription),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            StripeHandle::for_test(&format!("http://{address}")),
            state,
            task,
        )
    }

    #[test]
    fn teardown_input_rejects_unknown_fields() {
        let error = serde_json::from_str::<OrganizationBillingTeardownInput>(
            r#"{"operation_id":"op","organization_id":"org","generation":1,"secret":"no"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn idempotency_keys_are_stable_bounded_and_generation_sensitive() {
        let first = idempotency_key("delete-subscription", &["op/1", "sub_1"]);
        assert_eq!(
            first,
            idempotency_key("delete-subscription", &["op/1", "sub_1"])
        );
        assert_ne!(
            first,
            idempotency_key("delete-subscription", &["op/2", "sub_1"])
        );
        assert!(first.len() <= 255);
    }

    #[tokio::test]
    async fn db_disabled_provider_finalizes_exact_usage() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, None, None, false).await;

        let result =
            finalize_organization_billing(&pool, &StripeHandle::default(), &input(&fixture))
                .await
                .unwrap();
        assert_eq!(result.state, "completed");
        assert_eq!(result.terminal_subscription_count, 0);
        let usage: (f64, f64, f64) = sqlx::query_as(
            r#"SELECT last_cpu_hours, last_mem_gb_hours, last_disk_gb_hours
               FROM environment_usage_billing_tiers
               WHERE org_id = $1 AND runtime_tier = 'standard'"#,
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!((usage.0 - (10.0 / 60.0)).abs() < 0.01);
        assert!((usage.1 - (10.0 / 60.0)).abs() < 0.01);
        assert!((usage.2 - (20.0 / 60.0)).abs() < 0.01);

        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_captured_subscription_is_canceled_after_local_row_disappears() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let subscription_id = "sub_billdel_cancel";
        let fixture = seed(
            &pool,
            Some("cus_billdel_cancel"),
            Some(subscription_id),
            false,
        )
        .await;
        prepare_phase(&pool, &input(&fixture)).await.unwrap();
        sqlx::query("DELETE FROM org_subscriptions WHERE org_id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();
        let (stripe, state, task) = fake_stripe(
            &pool,
            &fixture.operation_id,
            subscription_id,
            ProviderMode::Cancel,
        )
        .await;

        let result = finalize_organization_billing(&pool, &stripe, &input(&fixture))
            .await
            .unwrap();
        assert_eq!(result.terminal_subscription_count, 1);
        assert_eq!(state.cancel_calls.load(Ordering::SeqCst), 1);
        assert!(state.usage_was_finalized.load(Ordering::SeqCst));
        assert!(state.local_subscription_was_absent.load(Ordering::SeqCst));

        task.abort();
        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_already_gone_subscription_is_terminal_success() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let subscription_id = "sub_billdel_gone";
        let fixture = seed(
            &pool,
            Some("cus_billdel_gone"),
            Some(subscription_id),
            false,
        )
        .await;
        let (stripe, state, task) = fake_stripe(
            &pool,
            &fixture.operation_id,
            subscription_id,
            ProviderMode::Gone,
        )
        .await;

        let result = finalize_organization_billing(&pool, &stripe, &input(&fixture))
            .await
            .unwrap();
        assert_eq!(result.terminal_subscription_count, 1);
        assert_eq!(state.cancel_calls.load(Ordering::SeqCst), 0);

        task.abort();
        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_provider_failure_retains_organization_and_capture() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let subscription_id = "sub_billdel_failure";
        let fixture = seed(
            &pool,
            Some("cus_billdel_failure"),
            Some(subscription_id),
            false,
        )
        .await;
        let (stripe, state, task) = fake_stripe(
            &pool,
            &fixture.operation_id,
            subscription_id,
            ProviderMode::Failure,
        )
        .await;

        assert!(
            finalize_organization_billing(&pool, &stripe, &input(&fixture))
                .await
                .is_err()
        );
        let organization_state: String =
            sqlx::query_scalar("SELECT deletion_state FROM organizations WHERE id = $1")
                .bind(&fixture.organization_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(organization_state, "deleting");
        let captured: (String, String) = sqlx::query_as(
            r#"SELECT phase.state, subscription.state
               FROM organization_deletion_billing_phases phase
               JOIN organization_deletion_billing_subscriptions subscription
                 ON subscription.operation_id = phase.operation_id
               WHERE phase.operation_id = $1 AND subscription.stripe_subscription_id = $2"#,
        )
        .bind(&fixture.operation_id)
        .bind(subscription_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(captured, ("running".into(), "captured".into()));
        assert_eq!(state.cancel_calls.load(Ordering::SeqCst), 0);

        task.abort();
        cleanup(&pool, &fixture).await;
    }

    #[tokio::test]
    async fn db_expired_ambiguous_lease_requires_provider_reenumeration() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, Some("cus_billdel_lease"), None, true).await;
        let lease_id = fixture
            .billing_lease_id
            .clone()
            .expect("billing lease fixture");
        let (stripe, _state, task) = fake_stripe(
            &pool,
            &fixture.operation_id,
            "sub_unused",
            ProviderMode::Empty,
        )
        .await;

        assert!(matches!(
            finalize_organization_billing(&pool, &stripe, &input(&fixture)).await,
            Err(AppError::Conflict(_))
        ));
        sqlx::query(
            "UPDATE organization_mutation_leases \
             SET admitted_at = NOW() - INTERVAL '31 seconds', \
                 deadline_at = NOW() - INTERVAL '1 second' \
             WHERE id = $1",
        )
        .bind(&lease_id)
        .execute(&pool)
        .await
        .unwrap();
        let result = finalize_organization_billing(&pool, &stripe, &input(&fixture))
            .await
            .unwrap();
        assert_eq!(result.state, "completed");
        let lease: (String, Option<String>) = sqlx::query_as(
            "SELECT state, recovery_code FROM organization_mutation_leases WHERE id = $1",
        )
        .bind(&lease_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            lease,
            ("resolved".into(), Some(BILLING_LEASE_DEADLINE_CODE.into()))
        );

        task.abort();
        cleanup(&pool, &fixture).await;
    }
}
