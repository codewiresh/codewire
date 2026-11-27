//! Admission: whether an organization's quota and compute credit let a create,
//! start or resize go ahead. A host environment (#3609) needs no credit and
//! no CPU or memory headroom, but counts as an environment.

use super::*;

/// Mirrors `evaluateQuota` — pure comparison, no DB.
pub(super) fn evaluate_quota(
    quota: OrgQuota,
    usage: OrgEnvironmentUsage,
    env_type: &str,
    backend: crate::runtime::RuntimeBackend,
    cpu: i32,
    mem: i32,
) -> Result<(), AppError> {
    if env_type == "sandbox"
        && quota.max_concurrent_sandbox != -1
        && usage.active_sandbox >= i64::from(quota.max_concurrent_sandbox)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "quota_exceeded",
            format!(
                "sandbox environment limit reached ({}/{})",
                usage.active_sandbox, quota.max_concurrent_sandbox
            ),
        ));
    }
    if quota.max_concurrent_environments != -1
        && usage.active_total >= i64::from(quota.max_concurrent_environments)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "quota_exceeded",
            format!(
                "environment limit reached ({}/{})",
                usage.active_total, quota.max_concurrent_environments
            ),
        ));
    }
    if !backend.platform_compute() {
        return Ok(());
    }
    if quota.max_cpu_millicores != -1
        && usage.total_cpu + i64::from(cpu) > i64::from(quota.max_cpu_millicores)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "CPU limit would be exceeded ({}+{} > {} millicores)",
                usage.total_cpu, cpu, quota.max_cpu_millicores
            ),
        ));
    }
    if quota.max_memory_mb != -1
        && usage.total_memory_mb + i64::from(mem) > i64::from(quota.max_memory_mb)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "memory limit would be exceeded ({}+{} > {} MB)",
                usage.total_memory_mb, mem, quota.max_memory_mb
            ),
        ));
    }
    Ok(())
}

/// The quota cannot be enforced because the organization's usage could not
/// be read. The request is refused rather than admitted unchecked; it is
/// safe to retry.
pub(crate) fn quota_unavailable(org_id: &str, error: &sqlx::Error) -> AppError {
    tracing::warn!(org_id, %error, "quota check: failed to count active environments");
    coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "quota_unavailable",
        "the environment quota could not be checked; retry in a moment",
    )
}

/// Refuses a create, start or snapshot capture when the organization's rate
/// card draws credit and its balance is zero or below (#3381, #4370). An
/// organization on the Unlimited card is never refused. A card or balance that
/// cannot be read refuses (fail closed); the request is safe to retry.
pub(super) fn evaluate_credit(rate_card: &str, balance_nano_eur: i64) -> Result<(), AppError> {
    if rate_card == UNLIMITED_RATE_CARD || balance_nano_eur > 0 {
        return Ok(());
    }
    Err(coded(
        StatusCode::PAYMENT_REQUIRED,
        "credit_exhausted",
        "this organization has no compute credit left; add a card or credit on its billing page",
    ))
}

pub(crate) async fn check_credit_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
) -> Result<(), AppError> {
    let credit: Option<(String, i64, i64)> = sqlx::query_as(
        r#"SELECT o.rate_card,
                  COALESCE(b.balance_nano_eur, 0),
                  CASE
                      WHEN EXISTS (
                          SELECT 1 FROM org_subscriptions os
                          WHERE os.org_id = o.id
                            AND os.status IN ('active', 'trialing', 'past_due')
                      )
                      THEN COALESCE((
                          SELECT GREATEST(a.granted_nano_usd - a.drawn_nano_usd, 0)
                          FROM billing_plan_allowances a
                          WHERE a.organization_id = o.id
                            AND a.period_start <= now()
                            AND a.period_end > now()
                          ORDER BY a.period_end DESC, a.id DESC
                          LIMIT 1
                      ), 0)
                      ELSE 0
                  END
           FROM organizations o
           LEFT JOIN billing_credit_balances b ON b.organization_id = o.id
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        tracing::warn!(org_id, %error, "credit check: failed to read the balance");
        coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "credit_unavailable",
            "the organization's compute credit could not be checked; retry in a moment",
        )
    })?;
    let Some((rate_card, balance, allowance_remaining)) = credit else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    };
    if allowance_remaining > 0 {
        return Ok(());
    }
    evaluate_credit(&rate_card, balance)
}

#[derive(Debug, sqlx::FromRow)]
struct OrgPlanEnforcementRow {
    rate_card: String,
    slug: String,
    sub_status: Option<String>,
    plan_display_name: Option<String>,
    max_concurrent_sandboxes: Option<i32>,
    max_vcpu: Option<i32>,
    max_memory_gib: Option<i32>,
    max_disk_gib: Option<i32>,
}

fn check_plan_shape_limits(
    row: &OrgPlanEnforcementRow,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
) -> Result<(), AppError> {
    if let (Some(display_name), Some(max_vcpu), Some(max_memory_gib), Some(max_disk_gib)) = (
        row.plan_display_name.as_deref(),
        row.max_vcpu,
        row.max_memory_gib,
        row.max_disk_gib,
    ) && (cpu_millicores > max_vcpu.saturating_mul(1_000)
        || memory_mb > max_memory_gib.saturating_mul(1_024)
        || disk_gb > max_disk_gib)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "plan_vm_size_exceeded",
            format!(
                "{display_name} allows up to {max_vcpu} vCPU, {max_memory_gib} GB RAM, and {max_disk_gib} GB disk per sandbox; upgrade your plan on Billing for larger sizes"
            ),
        ));
    }
    Ok(())
}

fn check_plan_status(
    row: &OrgPlanEnforcementRow,
    credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
) -> Result<(), AppError> {
    if credit_enforcement.is_on()
        && matches!(
            row.sub_status.as_deref(),
            Some("canceled" | "unpaid" | "incomplete" | "incomplete_expired" | "paused")
        )
    {
        return Err(coded_owned(
            StatusCode::PAYMENT_REQUIRED,
            "plan_required",
            format!(
                "this organization's plan is not active; choose a plan at https://codewire.sh/{}/onboarding/plan (local sandboxes with cw create --local are always free)",
                row.slug
            ),
        ));
    }
    Ok(())
}

async fn load_org_plan_enforcement(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
) -> Result<Option<OrgPlanEnforcementRow>, AppError> {
    sqlx::query_as(
        r#"SELECT o.rate_card,
                  o.slug,
                  os.status AS sub_status,
                  d.display_name AS plan_display_name,
                  d.max_concurrent_sandboxes,
                  d.max_vcpu,
                  d.max_memory_gib,
                  d.max_disk_gib
           FROM organizations o
           LEFT JOIN org_subscriptions os ON os.org_id = o.id
           LEFT JOIN billing_plan_definitions d ON d.plan_key = os.plan
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| quota_unavailable(org_id, &error))
}

/// Enforces monthly plan active status and per-sandbox VM shape limits
/// (`max_vcpu`, `max_memory_gib`, `max_disk_gib`) on in-place and restart
/// resizes (#6659). Unlimited rate-card organizations and non-cloud
/// (local/host) runtimes are never restricted.
pub(crate) async fn check_plan_vm_size_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
    credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    backend: crate::runtime::RuntimeBackend,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
) -> Result<(), AppError> {
    if !backend.platform_compute() {
        return Ok(());
    }
    let Some(row) = load_org_plan_enforcement(transaction, org_id).await? else {
        return Ok(());
    };
    if row.rate_card == UNLIMITED_RATE_CARD {
        return Ok(());
    }
    check_plan_status(&row, credit_enforcement)?;
    check_plan_shape_limits(&row, cpu_millicores, memory_mb, disk_gb)
}

/// Enforces monthly plan gating and per-sandbox VM shape / concurrency caps
/// from `billing_plan_definitions` (#6659). Unlimited rate-card organizations
/// and non-cloud (local/host) runtimes are never restricted.
pub(crate) async fn check_plan_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
    usage: OrgEnvironmentUsage,
    request: &QuotaRequest<'_>,
) -> Result<(), AppError> {
    if !request.backend.platform_compute() {
        return Ok(());
    }
    let Some(row) = load_org_plan_enforcement(transaction, org_id).await? else {
        return Ok(());
    };
    if row.rate_card == UNLIMITED_RATE_CARD {
        return Ok(());
    }
    check_plan_status(&row, request.credit_enforcement)?;
    check_plan_shape_limits(
        &row,
        request.cpu_millicores,
        request.memory_mb,
        request.disk_gb,
    )?;
    if let Some(display_name) = row.plan_display_name.as_deref()
        && request.env_type == "sandbox"
        && let Some(limit) = row.max_concurrent_sandboxes
        && usage.active_sandbox >= i64::from(limit)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "plan_sandbox_limit_reached",
            format!(
                "{display_name} allows up to {limit} concurrent sandboxes; stop one or upgrade your plan on Billing"
            ),
        ));
    }
    Ok(())
}

/// Refuses anything that would use compute or storage in a suspended
/// organization (#3297 item 4): a create, a start or a snapshot. A failed read
/// refuses as the quota check does (#3256).
pub(crate) async fn check_not_suspended_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
) -> Result<(), AppError> {
    let suspended: Option<bool> =
        sqlx::query_scalar("SELECT suspended_at IS NOT NULL FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| quota_unavailable(org_id, &error))?;
    match suspended {
        Some(true) => Err(coded(
            StatusCode::FORBIDDEN,
            "organization_suspended",
            "this organization is suspended; write to hello@codewire.sh if you think this is a mistake",
        )),
        _ => Ok(()),
    }
}

/// Mirrors `checkQuota`, with usage counted inside `transaction`, after the
/// organization's credit where this deployment enforces it (#3381). The
/// caller holds the organization row lock
/// and records the create or start in the same transaction, so concurrent
/// requests in one organization are counted one after another, and a
/// refused or failed one leaves nothing behind. A failed usage count or
/// balance read refuses the request (#3256).
pub(crate) async fn check_quota_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
    request: QuotaRequest<'_>,
) -> Result<(), AppError> {
    check_not_suspended_in(transaction, org_id).await?;
    let usage = count_active_environments(&mut **transaction, org_id)
        .await
        .map_err(|error| quota_unavailable(org_id, &error))?;
    // Check plan gating before credit balance so an inactive-plan org with $0
    // credit receives `plan_required` (with the plan URL and local hint)
    // instead of `credit_exhausted` (#6659).
    check_plan_in(transaction, org_id, usage, &request).await?;
    // A host's compute is its owner's: it needs no credit (owner,
    // 2026-11-13, #3609) and no CPU or memory headroom, but still counts as
    // an environment (design §10 Q1).
    if request.backend.platform_compute() && request.credit_enforcement.is_on() {
        check_credit_in(transaction, org_id).await?;
    }
    evaluate_quota(
        request.quota,
        usage,
        request.env_type,
        request.backend,
        request.cpu_millicores,
        request.memory_mb,
    )
}

/// One create's or start's demand on its organization's limits.
pub(crate) struct QuotaRequest<'a> {
    pub credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    pub quota: OrgQuota,
    pub env_type: &'a str,
    pub backend: crate::runtime::RuntimeBackend,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
}
