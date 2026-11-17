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
    let credit: Option<(String, i64)> = sqlx::query_as(
        r#"SELECT o.rate_card, COALESCE(b.balance_nano_eur, 0)
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
    let Some((rate_card, balance)) = credit else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    };
    evaluate_credit(&rate_card, balance)
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
    // A host's compute is its owner's: it needs no credit (owner,
    // 2026-11-13, #3609) and no CPU or memory headroom, but still counts as
    // an environment (design §10 Q1).
    if request.backend.platform_compute() && request.credit_enforcement.is_on() {
        check_credit_in(transaction, org_id).await?;
    }
    let usage = count_active_environments(&mut **transaction, org_id)
        .await
        .map_err(|error| quota_unavailable(org_id, &error))?;
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
}
