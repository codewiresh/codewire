//! An organization's rate card and compute credit, as a global administrator
//! sees and changes them (#3381). Every change is audited in the same
//! transaction as the change itself.

use codewire_server_core::{AppError, AppResult, ValidationIssue};

/// The three rate cards, in the order the admin page offers them.
pub const RATE_CARDS: [&str; 3] = ["regular", "discounted", "unlimited"];

/// The most an administrator moves in one adjustment: EUR 100,000.
pub const MAX_ADJUSTMENT_NANO_EUR: i64 = 100_000 * 1_000_000_000;

/// How many ledger entries the overview shows, newest first.
pub const RECENT_CREDIT_ENTRIES: i64 = 20;

/// One credit ledger entry, for the admin overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCreditEntry {
    /// grant, usage, top_up or adjustment.
    pub kind: String,
    pub amount_nano_eur: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reason: String,
    pub actor_user_id: String,
}

/// An organization's card, balance and newest ledger entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationCredit {
    pub rate_card: String,
    pub balance_nano_eur: i64,
    pub recent: Vec<AdminCreditEntry>,
}

/// The card before and after a switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRateCardChange {
    pub previous: String,
    pub rate_card: String,
}

/// The balance after an adjustment, and whether this request applied it (a
/// repeated idempotency key applies nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCreditAdjustment {
    pub balance_nano_eur: i64,
    pub applied: bool,
}

fn failure(action: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |error| {
        tracing::error!(error = %error, action, "admin: organization credit query failed");
        AppError::InternalMsg(format!("failed to {action}").into())
    }
}

fn invalid(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: path.into(),
            message: message.into(),
        }],
    }
}

async fn lock_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> AppResult<String> {
    sqlx::query_scalar::<_, String>("SELECT rate_card FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(failure("read organization"))?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

async fn audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: &str,
    actor_user_id: &str,
    metadata: serde_json::Value,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, 'warn')"#,
    )
    .bind(action)
    .bind(actor_user_id)
    .bind(metadata)
    .execute(&mut **transaction)
    .await
    .map_err(failure("record organization billing audit"))?;
    Ok(())
}

async fn balance<'e>(executor: impl sqlx::PgExecutor<'e>, organization_id: &str) -> AppResult<i64> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_optional(executor)
    .await
    .map_err(failure("read credit balance"))?
    .unwrap_or(0))
}

/// The organization's card, balance and newest ledger entries.
pub(crate) async fn organization_credit(
    pool: &sqlx::PgPool,
    organization_id: &str,
) -> AppResult<AdminOrganizationCredit> {
    let rate_card: String = sqlx::query_scalar("SELECT rate_card FROM organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(pool)
        .await
        .map_err(failure("read rate card"))?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    let recent = sqlx::query_as::<
        _,
        (
            String,
            i64,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
            Option<String>,
        ),
    >(
        r#"SELECT entry_kind, amount_nano_eur, created_at, reason, actor_user_id
           FROM billing_credit_ledger WHERE organization_id = $1
           ORDER BY id DESC LIMIT $2"#,
    )
    .bind(organization_id)
    .bind(RECENT_CREDIT_ENTRIES)
    .fetch_all(pool)
    .await
    .map_err(failure("read credit ledger"))?
    .into_iter()
    .map(
        |(kind, amount_nano_eur, created_at, reason, actor)| AdminCreditEntry {
            kind,
            amount_nano_eur,
            created_at,
            reason: reason.unwrap_or_default(),
            actor_user_id: actor.unwrap_or_default(),
        },
    )
    .collect();
    Ok(AdminOrganizationCredit {
        rate_card,
        balance_nano_eur: balance(pool, organization_id).await?,
        recent,
    })
}

/// Assigns the organization's rate card. A switch to the card it already has
/// changes nothing and writes no audit entry.
pub(crate) async fn set_organization_rate_card_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    organization_id: &str,
    rate_card: &str,
) -> AppResult<AdminRateCardChange> {
    if !RATE_CARDS.contains(&rate_card) {
        return Err(invalid(
            "/rate_card",
            "must be regular, discounted or unlimited",
        ));
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(failure("start rate card change"))?;
    let previous = lock_organization(&mut transaction, organization_id).await?;
    if previous != rate_card {
        sqlx::query("UPDATE organizations SET rate_card = $2, updated_at = NOW() WHERE id = $1")
            .bind(organization_id)
            .bind(rate_card)
            .execute(&mut *transaction)
            .await
            .map_err(failure("update rate card"))?;
        audit(
            &mut transaction,
            "admin.organization.rate_card",
            actor_user_id,
            serde_json::json!({
                "organization_id": organization_id,
                "previous": previous,
                "rate_card": rate_card,
            }),
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .map_err(failure("commit rate card change"))?;
    Ok(AdminRateCardChange {
        previous,
        rate_card: rate_card.to_owned(),
    })
}

/// Validates an administrator's adjustment: a non-zero amount of at most
/// EUR 100,000 either way, a reason, and an idempotency key of 1 to 128
/// letters, digits, '-' or '_'. Returns the trimmed reason.
pub(crate) fn validate_adjustment<'a>(
    amount_nano_eur: i64,
    reason: &'a str,
    idempotency_key: &str,
) -> AppResult<&'a str> {
    if amount_nano_eur == 0 || amount_nano_eur.unsigned_abs() > MAX_ADJUSTMENT_NANO_EUR as u64 {
        return Err(invalid(
            "/amount_nano_eur",
            "must be non-zero and at most EUR 100,000 either way",
        ));
    }
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(invalid("/reason", "must be 1 to 500 characters"));
    }
    if idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid(
            "/idempotency_key",
            "must be 1 to 128 letters, digits, '-' or '_'",
        ));
    }
    Ok(reason)
}

/// Adds or removes compute credit as an `adjustment` ledger entry naming the
/// administrator and the reason, and audits it, in one transaction. A
/// repeated idempotency key for the organization applies nothing again.
pub(crate) async fn adjust_organization_credit_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    organization_id: &str,
    amount_nano_eur: i64,
    reason: &str,
    idempotency_key: &str,
) -> AppResult<AdminCreditAdjustment> {
    let reason = validate_adjustment(amount_nano_eur, reason, idempotency_key)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(failure("start credit adjustment"))?;
    lock_organization(&mut transaction, organization_id).await?;
    let ledger_key = format!("admin:{idempotency_key}");
    let applied = sqlx::query_scalar::<_, i64>(
        r#"INSERT INTO billing_credit_ledger
               (organization_id, entry_kind, amount_nano_eur, idempotency_key,
                actor_user_id, reason)
           VALUES ($1, 'adjustment', $2, $3, $4, $5)
           ON CONFLICT (organization_id, idempotency_key) DO NOTHING
           RETURNING id"#,
    )
    .bind(organization_id)
    .bind(amount_nano_eur)
    .bind(&ledger_key)
    .bind(actor_user_id)
    .bind(reason)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(failure("record credit adjustment"))?
    .is_some();
    let balance_nano_eur = balance(&mut *transaction, organization_id).await?;
    if applied {
        audit(
            &mut transaction,
            "admin.organization.credit_adjustment",
            actor_user_id,
            serde_json::json!({
                "organization_id": organization_id,
                "amount_nano_eur": amount_nano_eur,
                "reason": reason,
                "balance_nano_eur": balance_nano_eur,
            }),
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .map_err(failure("commit credit adjustment"))?;
    Ok(AdminCreditAdjustment {
        balance_nano_eur,
        applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjustments_need_an_amount_a_reason_and_a_safe_key() {
        assert_eq!(
            validate_adjustment(1, "  refund  ", "k-1_A").unwrap(),
            "refund"
        );
        assert!(validate_adjustment(-MAX_ADJUSTMENT_NANO_EUR, "r", "k").is_ok());
        for (amount, reason, key) in [
            (0, "r", "k"),
            (MAX_ADJUSTMENT_NANO_EUR + 1, "r", "k"),
            (-MAX_ADJUSTMENT_NANO_EUR - 1, "r", "k"),
            (i64::MIN, "r", "k"),
            (1, "   ", "k"),
            (1, &"x".repeat(501), "k"),
            (1, "r", ""),
            (1, "r", "has space"),
            (1, "r", &"k".repeat(129)),
        ] {
            assert!(
                matches!(
                    validate_adjustment(amount, reason, key),
                    Err(AppError::Validation { .. })
                ),
                "{amount} {reason:?} {key:?}"
            );
        }
    }
}
