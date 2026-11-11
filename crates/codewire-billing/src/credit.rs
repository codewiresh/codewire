//! Prepaid compute credit (#3381). Metering draws each running sandbox
//! session's allocated vCPU, memory and disk from its organization's credit,
//! per second, at the organization's rate card.
//!
//! Each session carries a watermark (`credit_drawn_through`). One draw locks
//! an organization's due sessions, writes one `usage` ledger entry for the
//! time since their watermarks, and moves the watermarks, in one
//! transaction: a failed or concurrent draw never charges the same second
//! twice. An organization on the Unlimited card is never charged, but its
//! watermarks still move, so a later switch to another card charges only
//! from the switch.
//!
//! An open session draws only through its last observation. A session whose
//! runtime vanishes closes at that time, and metering stops counting there,
//! so credit drawn past it could never be earned (#3898).

use std::time::Duration;

use chrono::{DateTime, Utc};
use codewire_server_core::credit_enforcement::CreditEnforcement;
use sqlx::PgPool;

/// How often the leader draws usage.
pub const CREDIT_METERING_INTERVAL: Duration = Duration::from_secs(60);

/// The rate card that is never charged.
pub const UNLIMITED_RATE_CARD: &str = "unlimited";

/// A rate card's prices, in nano-euros per unit-hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rates {
    pub cpu_per_vcpu_hour: i64,
    pub memory_per_gib_hour: i64,
    pub disk_per_gib_hour: i64,
}

/// One session's allocated size and the time to draw for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionWindow {
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub microseconds: i64,
}

const HOUR_MICROSECONDS: i128 = 3_600_000_000;
// Millicores per vCPU, MiB per GiB, and one hour in microseconds share one
// denominator, so the sum is divided, and rounded down, once.
const DENOMINATOR: i128 = 1_000 * 1_024 * HOUR_MICROSECONDS;

/// What the windows cost at `rates`, in nano-euros, rounded down.
pub fn usage_nano_eur(rates: Rates, windows: &[SessionWindow]) -> i64 {
    let numerator: i128 = windows
        .iter()
        .map(|window| {
            let time = i128::from(window.microseconds.max(0));
            let cpu = i128::from(window.cpu_millicores.max(0))
                * 1_024
                * i128::from(rates.cpu_per_vcpu_hour);
            let memory = i128::from(window.memory_mib.max(0))
                * 1_000
                * i128::from(rates.memory_per_gib_hour);
            let disk = i128::from(window.disk_gib.max(0))
                * 1_024_000
                * i128::from(rates.disk_per_gib_hour);
            (cpu + memory + disk) * time
        })
        .sum();
    i64::try_from(numerator / DENOMINATOR).unwrap_or(i64::MAX)
}

/// One run of the draw.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrawSummary {
    pub organizations: usize,
    pub failed: usize,
    pub drawn_nano_eur: i64,
}

/// Draws every organization with due sessions. A failed organization is
/// logged and drawn again on the next run, from the same watermarks.
pub async fn draw_due_usage(pool: &PgPool) -> anyhow::Result<DrawSummary> {
    let organizations: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT organization_id FROM sandbox_running_sessions
           WHERE ended_at IS NULL OR credit_drawn_through IS NULL
              OR credit_drawn_through < ended_at"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|error| anyhow::anyhow!("list organizations with due usage: {error}"))?;
    let mut summary = DrawSummary::default();
    for organization_id in organizations {
        match draw_organization(pool, &organization_id).await {
            Ok(drawn) => {
                summary.organizations += 1;
                summary.drawn_nano_eur = summary.drawn_nano_eur.saturating_add(drawn);
            }
            Err(error) => {
                summary.failed += 1;
                tracing::error!(organization_id, %error, "credit metering: draw failed");
            }
        }
    }
    Ok(summary)
}

/// Draws one organization's due sessions, each through its end or, while it
/// is open, its last observation, and returns the amount drawn, in nano-euros.
pub async fn draw_organization(pool: &PgPool, organization_id: &str) -> anyhow::Result<i64> {
    let mut transaction = pool.begin().await?;
    let card: Option<(String, i64, i64, i64)> = sqlx::query_as(
        r#"SELECT o.rate_card, r.cpu_nano_eur_per_vcpu_hour,
                  r.memory_nano_eur_per_gib_hour, r.disk_nano_eur_per_gib_hour
           FROM organizations o
           JOIN billing_rate_cards r ON r.rate_card = o.rate_card
           WHERE o.id = $1"#,
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((rate_card, cpu, memory, disk)) = card else {
        // Deleted since it was listed; its sessions went with it.
        return Ok(0);
    };
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *transaction)
        .await?;
    type Row = (String, i32, i32, i32, DateTime<Utc>, DateTime<Utc>);
    let due: Vec<Row> = sqlx::query_as(
        r#"SELECT id, cpu_millicores, memory_mib, disk_gib,
                  COALESCE(credit_drawn_through, started_at),
                  LEAST(COALESCE(ended_at, last_observed_at), $2)
           FROM sandbox_running_sessions
           WHERE organization_id = $1
             AND (ended_at IS NULL OR credit_drawn_through IS NULL
                  OR credit_drawn_through < ended_at)
           ORDER BY id
           FOR UPDATE"#,
    )
    .bind(organization_id)
    .bind(now)
    .fetch_all(&mut *transaction)
    .await?;
    let due: Vec<Row> = due
        .into_iter()
        .filter(|(_, _, _, _, from, to)| to > from)
        .collect();
    if due.is_empty() {
        transaction.commit().await?;
        return Ok(0);
    }

    let windows: Vec<SessionWindow> = due
        .iter()
        .map(|(_, cpu, memory, disk, from, to)| SessionWindow {
            cpu_millicores: *cpu,
            memory_mib: *memory,
            disk_gib: *disk,
            microseconds: (*to - *from).num_microseconds().unwrap_or(i64::MAX),
        })
        .collect();
    let amount = if rate_card == UNLIMITED_RATE_CARD {
        0
    } else {
        usage_nano_eur(
            Rates {
                cpu_per_vcpu_hour: cpu,
                memory_per_gib_hour: memory,
                disk_per_gib_hour: disk,
            },
            &windows,
        )
    };
    if amount > 0 {
        let started = due.iter().map(|row| row.4).min().unwrap_or(now);
        let ended = due.iter().map(|row| row.5).max().unwrap_or(now);
        sqlx::query(
            r#"INSERT INTO billing_credit_ledger
                   (organization_id, entry_kind, amount_nano_eur, idempotency_key,
                    rate_card, usage_started_at, usage_ended_at)
               VALUES ($1, 'usage', $2, $3, $4, $5, $6)"#,
        )
        .bind(organization_id)
        .bind(-amount)
        .bind(format!(
            "usage:{}",
            now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        ))
        .bind(&rate_card)
        .bind(started)
        .bind(ended)
        .execute(&mut *transaction)
        .await?;
    }
    let ids: Vec<String> = due.iter().map(|row| row.0.clone()).collect();
    let through: Vec<DateTime<Utc>> = due.iter().map(|row| row.5).collect();
    sqlx::query(
        r#"UPDATE sandbox_running_sessions s
           SET credit_drawn_through = d.through
           FROM UNNEST($1::text[], $2::timestamptz[]) AS d(id, through)
           WHERE s.id = d.id"#,
    )
    .bind(&ids)
    .bind(&through)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(amount)
}

const NANO_EUR_PER_EURO: i64 = 1_000_000_000;
const NANO_EUR_PER_CENT: i64 = 10_000_000;

async fn clear_exhausted_if_funded(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"UPDATE organizations o SET credit_exhausted_at = NULL
           WHERE o.id = $1 AND o.credit_exhausted_at IS NOT NULL
             AND (o.rate_card = 'unlimited' OR EXISTS (
                 SELECT 1 FROM billing_credit_balances b
                 WHERE b.organization_id = o.id AND b.balance_nano_eur > 0))"#,
    )
    .bind(organization_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn mark_exhausted(pool: &PgPool, organization_id: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE organizations SET credit_exhausted_at = COALESCE(credit_exhausted_at, now()) \
         WHERE id = $1",
    )
    .bind(organization_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a paid top-up and its credit, once, whether the charge or its
/// `invoice.paid` webhook gets here first.
pub async fn complete_top_up(
    pool: &PgPool,
    top_up_id: &str,
    invoice_id: &str,
) -> anyhow::Result<bool> {
    let mut transaction = pool.begin().await?;
    let top_up: Option<(String, i32)> = sqlx::query_as(
        r#"UPDATE billing_top_ups SET state = 'paid', stripe_invoice_id = $2,
               completed_at = now(), failure_code = NULL
           WHERE id = $1 AND state <> 'paid'
           RETURNING organization_id, amount_cents"#,
    )
    .bind(top_up_id)
    .bind(invoice_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((organization_id, amount_cents)) = top_up else {
        transaction.commit().await?;
        return Ok(false);
    };
    sqlx::query(
        r#"INSERT INTO billing_credit_ledger
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, provider_object_id)
           VALUES ($1, 'top_up', $2, $3, $4)
           ON CONFLICT (organization_id, idempotency_key) DO NOTHING"#,
    )
    .bind(&organization_id)
    .bind(i64::from(amount_cents) * NANO_EUR_PER_CENT)
    .bind(format!("top_up:{top_up_id}"))
    .bind(invoice_id)
    .execute(&mut *transaction)
    .await?;
    clear_exhausted_if_funded(&mut transaction, &organization_id).await?;
    transaction.commit().await?;
    Ok(true)
}

/// Records a declined top-up, and that the organization has no credit and
/// no way to get it, which starts the 24-hour clock on its running
/// sandboxes.
pub async fn fail_top_up(
    pool: &PgPool,
    top_up_id: &str,
    invoice_id: Option<&str>,
    code: &str,
) -> anyhow::Result<()> {
    let organization_id: Option<String> = sqlx::query_scalar(
        r#"UPDATE billing_top_ups SET state = 'failed', completed_at = now(),
               failure_code = $2, stripe_invoice_id = COALESCE(stripe_invoice_id, $3)
           WHERE id = $1 AND state = 'pending'
           RETURNING organization_id"#,
    )
    .bind(top_up_id)
    .bind(crate::stripe_client::failure_code(Some(code)))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await?;
    if let Some(organization_id) = organization_id {
        mark_exhausted(pool, &organization_id).await?;
    }
    Ok(())
}

/// Where an organization's credit stands after settling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// Unlimited, or a positive balance.
    Funded,
    /// The card was charged.
    ToppedUp,
    /// A charge is under way; the next run resumes it.
    Pending,
    /// No credit and no way to get it: no card, top-up off, or a refusal.
    Exhausted,
    /// This deployment does not enforce credit, so nothing was done.
    NotEnforced,
}

/// Settles one organization: tops it up from its card when it charges, has
/// no credit and allows it, else records it as exhausted. `after_new_card`
/// tries again even after a recent refusal.
pub async fn settle_organization(
    pool: &PgPool,
    stripe: &crate::stripe_client::StripeHandle,
    enforcement: CreditEnforcement,
    organization_id: &str,
    after_new_card: bool,
) -> anyhow::Result<Settlement> {
    if !enforcement.is_on() {
        return Ok(Settlement::NotEnforced);
    }
    type State = (String, i64, bool, i32, Option<String>);
    let Some((rate_card, balance, auto_top_up, top_up_cents, customer)): Option<State> =
        sqlx::query_as(
            r#"SELECT o.rate_card, COALESCE(b.balance_nano_eur, 0), o.auto_top_up_enabled,
                      o.auto_top_up_cents, o.stripe_customer_id
               FROM organizations o
               LEFT JOIN billing_credit_balances b ON b.organization_id = o.id
               WHERE o.id = $1"#,
        )
        .bind(organization_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(Settlement::Funded);
    };
    let pending: Option<(String, i32)> = sqlx::query_as(
        "SELECT id, amount_cents FROM billing_top_ups WHERE organization_id = $1 AND state = 'pending'",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;
    if pending.is_none() && (rate_card == UNLIMITED_RATE_CARD || balance > 0) {
        let mut transaction = pool.begin().await?;
        clear_exhausted_if_funded(&mut transaction, organization_id).await?;
        transaction.commit().await?;
        return Ok(Settlement::Funded);
    }
    let customer = customer.filter(|customer| !customer.is_empty());
    let (top_up_id, amount_cents) = match pending {
        Some(pending) => pending,
        None => {
            let recently_refused: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM billing_top_ups WHERE organization_id = $1 \
                 AND state = 'failed' AND completed_at > now() - interval '24 hours')",
            )
            .bind(organization_id)
            .fetch_one(pool)
            .await?;
            if customer.is_none()
                || !auto_top_up
                || stripe.enabled().is_none()
                || (recently_refused && !after_new_card)
                || !stripe.org_has_payment_method(pool, organization_id).await
            {
                mark_exhausted(pool, organization_id).await?;
                return Ok(Settlement::Exhausted);
            }
            let created: Option<String> = sqlx::query_scalar(
                r#"INSERT INTO billing_top_ups (organization_id, amount_cents)
                   VALUES ($1, $2)
                   ON CONFLICT (organization_id) WHERE state = 'pending' DO NOTHING
                   RETURNING id"#,
            )
            .bind(organization_id)
            .bind(top_up_cents)
            .fetch_optional(pool)
            .await?;
            match created {
                Some(id) => (id, top_up_cents),
                // Another settle created it first; it charges.
                None => return Ok(Settlement::Pending),
            }
        }
    };
    let Some(customer) = customer else {
        fail_top_up(pool, &top_up_id, None, "no_customer").await?;
        return Ok(Settlement::Exhausted);
    };
    match stripe
        .charge_top_up(
            &customer,
            organization_id,
            &top_up_id,
            i64::from(amount_cents),
        )
        .await
    {
        Ok(crate::stripe_client::TopUpCharge::Paid { invoice_id }) => {
            complete_top_up(pool, &top_up_id, &invoice_id).await?;
            Ok(Settlement::ToppedUp)
        }
        Ok(crate::stripe_client::TopUpCharge::Declined { invoice_id, code }) => {
            fail_top_up(pool, &top_up_id, invoice_id.as_deref(), &code).await?;
            Ok(Settlement::Exhausted)
        }
        Err(error) => {
            tracing::warn!(
                organization_id,
                top_up_id,
                ?error,
                "credit top-up: charge unconfirmed; resuming next run"
            );
            Ok(Settlement::Pending)
        }
    }
}

/// Settles every organization that charges and has no credit, has a charge
/// under way, or was exhausted and is funded again.
pub async fn settle_due(
    pool: &PgPool,
    stripe: &crate::stripe_client::StripeHandle,
    enforcement: CreditEnforcement,
) -> anyhow::Result<usize> {
    if !enforcement.is_on() {
        return Ok(0);
    }
    let organizations = organizations_due(pool).await?;
    let count = organizations.len();
    for organization_id in organizations {
        if let Err(error) =
            settle_organization(pool, stripe, enforcement, &organization_id, false).await
        {
            tracing::error!(organization_id, %error, "credit settlement failed");
        }
    }
    Ok(count)
}

/// The organizations [`settle_due`] settles. Reading them changes nothing, so
/// a test can check one organization is due without settling everyone else's.
async fn organizations_due(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        r#"SELECT b.organization_id FROM billing_credit_balances b
           JOIN organizations o ON o.id = b.organization_id
           WHERE o.rate_card <> 'unlimited' AND b.balance_nano_eur <= 0
             AND o.credit_exhausted_at IS NULL
           UNION
           SELECT organization_id FROM billing_top_ups WHERE state = 'pending'
           UNION
           SELECT o.id FROM organizations o
           LEFT JOIN billing_credit_balances b ON b.organization_id = o.id
           WHERE o.credit_exhausted_at IS NOT NULL
             AND (o.rate_card = 'unlimited' OR COALESCE(b.balance_nano_eur, 0) > 0
                  -- A refused card is tried again a day later. One that was
                  -- never charged (no card) waits for a new card, which
                  -- settles at once, so nothing asks Stripe every minute.
                  OR (o.auto_top_up_enabled AND o.stripe_customer_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1 FROM billing_top_ups t WHERE t.organization_id = o.id
                            AND t.state = 'failed')
                      AND NOT EXISTS (
                          SELECT 1 FROM billing_top_ups t WHERE t.organization_id = o.id
                            AND t.state = 'failed'
                            AND t.completed_at > now() - interval '24 hours')))"#,
    )
    .fetch_all(pool)
    .await?)
}

/// Below this, an organization that nothing will top up hears about it.
pub const LOW_BALANCE_NANO_EUR: i64 = 5 * NANO_EUR_PER_EURO;

const LOW_NOTICE: &str = "credit_low_notice";
const EXHAUSTED_NOTICE: &str = "credit_exhausted_notice";

/// An email an organization's owner is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditNotice {
    Low {
        organization_id: String,
        balance_nano_eur: i64,
    },
    Exhausted {
        organization_id: String,
    },
}

/// Who is due a notice. Each is sent once per spell: running out once since
/// `credit_exhausted_at`, and running low once since credit last came in. An
/// organization with automatic top-up and a Stripe customer needs no low
/// notice: if the charge fails, it hears that it ran out.
pub async fn credit_notices_due(pool: &PgPool) -> anyhow::Result<Vec<CreditNotice>> {
    let exhausted: Vec<String> = sqlx::query_scalar(
        r#"SELECT o.id FROM organizations o
           WHERE o.credit_exhausted_at IS NOT NULL AND o.rate_card <> 'unlimited'
             AND NOT EXISTS (
                 SELECT 1 FROM billing_events e
                 WHERE e.org_id = o.id AND e.event_type = $1
                   AND e.created_at >= o.credit_exhausted_at)
           ORDER BY o.id"#,
    )
    .bind(EXHAUSTED_NOTICE)
    .fetch_all(pool)
    .await?;
    let low: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT o.id, b.balance_nano_eur FROM billing_credit_balances b
           JOIN organizations o ON o.id = b.organization_id
           WHERE b.balance_nano_eur > 0 AND b.balance_nano_eur < $1
             AND o.rate_card <> 'unlimited' AND o.credit_exhausted_at IS NULL
             AND NOT (o.auto_top_up_enabled AND o.stripe_customer_id IS NOT NULL)
             AND NOT EXISTS (
                 SELECT 1 FROM billing_events e
                 WHERE e.org_id = o.id AND e.event_type = $2
                   AND e.created_at > COALESCE(
                       (SELECT max(l.created_at) FROM billing_credit_ledger l
                        WHERE l.organization_id = o.id AND l.amount_nano_eur > 0),
                       '-infinity'::timestamptz))
           ORDER BY o.id"#,
    )
    .bind(LOW_BALANCE_NANO_EUR)
    .bind(LOW_NOTICE)
    .fetch_all(pool)
    .await?;
    Ok(exhausted
        .into_iter()
        .map(|organization_id| CreditNotice::Exhausted { organization_id })
        .chain(
            low.into_iter()
                .map(|(organization_id, balance_nano_eur)| CreditNotice::Low {
                    organization_id,
                    balance_nano_eur,
                }),
        )
        .collect())
}

async fn record_notice(pool: &PgPool, organization_id: &str, kind: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO billing_events (event_type, org_id, currency) VALUES ($1, $2, 'eur')")
        .bind(kind)
        .bind(organization_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Emails each due notice to the organization's owner, where this deployment
/// enforces credit. A failed send is logged and is due again on the next run.
pub async fn send_credit_notices(
    pool: &PgPool,
    email: &crate::email::EmailClient,
    enforcement: CreditEnforcement,
) -> anyhow::Result<usize> {
    if !enforcement.is_on() || !email.is_configured() {
        return Ok(0);
    }
    let mut sent = 0;
    for notice in credit_notices_due(pool).await? {
        let (organization_id, kind) = match &notice {
            CreditNotice::Low {
                organization_id, ..
            } => (organization_id, LOW_NOTICE),
            CreditNotice::Exhausted { organization_id } => (organization_id, EXHAUSTED_NOTICE),
        };
        let Some(owner) = crate::webhook::org_owner_email_by_id(pool, organization_id).await else {
            tracing::warn!(
                organization_id,
                "credit notice: the organization has no owner"
            );
            continue;
        };
        let result = match &notice {
            CreditNotice::Low {
                balance_nano_eur, ..
            } => {
                email
                    .send_credit_low(&owner, balance_nano_eur / NANO_EUR_PER_CENT)
                    .await
            }
            CreditNotice::Exhausted { .. } => email.send_credit_exhausted(&owner).await,
        };
        match result {
            Ok(()) => {
                record_notice(pool, organization_id, kind).await?;
                sent += 1;
            }
            Err(error) => {
                tracing::error!(organization_id, kind, %error, "credit notice: send failed");
            }
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGULAR: Rates = Rates {
        cpu_per_vcpu_hour: 43_800_000,
        memory_per_gib_hour: 14_100_000,
        disk_per_gib_hour: 87_000,
    };
    const HOUR: i64 = 3_600_000_000;

    fn window(cpu: i32, memory: i32, disk: i32, microseconds: i64) -> SessionWindow {
        SessionWindow {
            cpu_millicores: cpu,
            memory_mib: memory,
            disk_gib: disk,
            microseconds,
        }
    }

    #[test]
    fn an_hour_of_each_unit_costs_its_rate() {
        assert_eq!(
            usage_nano_eur(REGULAR, &[window(1_000, 0, 0, HOUR)]),
            43_800_000
        );
        assert_eq!(
            usage_nano_eur(REGULAR, &[window(0, 1_024, 0, HOUR)]),
            14_100_000
        );
        assert_eq!(usage_nano_eur(REGULAR, &[window(0, 0, 1, HOUR)]), 87_000);
    }

    #[test]
    fn the_default_sandbox_costs_about_twenty_cents_an_hour() {
        // 2 vCPU, 8 GiB and 10 GiB (owner, 2026-10-24: "about EUR 0.20").
        let hour = usage_nano_eur(REGULAR, &[window(2_000, 8_192, 10, HOUR)]);
        assert_eq!(hour, 2 * 43_800_000 + 8 * 14_100_000 + 10 * 87_000);
        assert_eq!(hour, 201_270_000);
        // Per second, summed over a minute of windows, it rounds down only
        // once per draw.
        let minute = usage_nano_eur(REGULAR, &[window(2_000, 8_192, 10, 60_000_000)]);
        assert_eq!(minute, 201_270_000 / 60);
        let seconds: Vec<_> = (0..60)
            .map(|_| window(2_000, 8_192, 10, 1_000_000))
            .collect();
        assert_eq!(usage_nano_eur(REGULAR, &seconds), minute);
    }

    #[test]
    fn discounted_and_unlimited_rates_scale_and_nothing_negative_is_charged() {
        let half = Rates {
            cpu_per_vcpu_hour: 21_900_000,
            memory_per_gib_hour: 7_050_000,
            disk_per_gib_hour: 43_500,
        };
        assert_eq!(
            usage_nano_eur(half, &[window(2_000, 8_192, 10, HOUR)]),
            201_270_000 / 2
        );
        let zero = Rates {
            cpu_per_vcpu_hour: 0,
            memory_per_gib_hour: 0,
            disk_per_gib_hour: 0,
        };
        assert_eq!(
            usage_nano_eur(zero, &[window(16_000, 32_768, 200, HOUR)]),
            0
        );
        assert_eq!(
            usage_nano_eur(REGULAR, &[window(2_000, 8_192, 10, -HOUR)]),
            0
        );
        assert_eq!(usage_nano_eur(REGULAR, &[window(-2_000, -1, -1, HOUR)]), 0);
        assert_eq!(usage_nano_eur(REGULAR, &[]), 0);
    }

    #[test]
    fn the_largest_sandbox_for_a_year_fits() {
        let year = 365 * 24 * HOUR;
        let amount = usage_nano_eur(REGULAR, &[window(16_000, 32_768, 200, year)]);
        assert_eq!(
            amount,
            365 * 24 * (16 * 43_800_000 + 32 * 14_100_000 + 200 * 87_000)
        );
    }

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                eprintln!("DATABASE_URL unset; skipping the credit metering database flow");
                return None;
            }
        };
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
                .connect(&url)
                .await
                .expect("connect credit metering test database"),
        )
    }

    struct Fixture {
        organization_id: String,
        user_id: String,
    }

    async fn seed(pool: &PgPool, rate_card: &str) -> Fixture {
        let namespace: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(pool)
            .await
            .unwrap();
        let fixture = Fixture {
            organization_id: format!("org_credit_{namespace}"),
            user_id: format!("u_credit_{namespace}"),
        };
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&fixture.user_id)
            .bind(format!("{namespace}@example.test"))
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by, rate_card) \
             VALUES ($1, 'Credit', $2, $3, $4)",
        )
        .bind(&fixture.organization_id)
        .bind(format!("credit-{}", &namespace[..8]))
        .bind(&fixture.user_id)
        .bind(rate_card)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
        )
        .bind(&fixture.organization_id)
        .execute(pool)
        .await
        .unwrap();
        fixture
    }

    /// A session of the default size that started `ago` and, when `ended`
    /// is set, ended that long ago.
    async fn session(pool: &PgPool, fixture: &Fixture, name: &str, ago: &str, ended: Option<&str>) {
        let environment_id = format!("{}-{name}", fixture.organization_id);
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) \
             VALUES ($1, $2, $3, 'sandbox', $2, '{}'::jsonb)",
        )
        .bind(&environment_id)
        .bind(&fixture.organization_id)
        .bind(&fixture.user_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sandbox_running_sessions \
               (id, environment_id, organization_id, runtime_uid, runtime_name, \
                runtime_namespace, cpu_millicores, memory_mib, disk_gib, started_at, \
                last_observed_at, ended_at) \
             VALUES ($1, $1, $2, $1, $1, 'ns', 2000, 8192, 10, \
                     now() - $3::interval, now(), now() - $4::interval)",
        )
        .bind(&environment_id)
        .bind(&fixture.organization_id)
        .bind(ago)
        .bind(ended)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn ledger(pool: &PgPool, fixture: &Fixture) -> Vec<(String, i64, Option<String>)> {
        sqlx::query_as(
            "SELECT entry_kind, amount_nano_eur, rate_card FROM billing_credit_ledger \
             WHERE organization_id = $1 ORDER BY id",
        )
        .bind(&fixture.organization_id)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn cleanup(pool: &PgPool, fixture: Fixture) {
        for table in ["environments", "environment_presets"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE org_id = $1"))
                .bind(&fixture.organization_id)
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&fixture.user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn db_draw_charges_each_second_once_at_the_organizations_card() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        // One hour ended half an hour ago, and one still running for an hour.
        session(&pool, &fixture, "ended", "90 minutes", Some("30 minutes")).await;
        session(&pool, &fixture, "open", "1 hour", None).await;

        let first = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        // Two hours of the default sandbox: the open one was last observed an
        // hour after it started.
        assert_eq!(first, 2 * 201_270_000);
        let entries = ledger(&pool, &fixture).await;
        assert_eq!(
            entries,
            [("usage".to_owned(), -first, Some("regular".to_owned()))]
        );
        let balance: i64 = sqlx::query_scalar(
            "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(balance, -first);

        // The ended session is done, and the open one has no new observation.
        let second = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert_eq!(second, 0);
        let due: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sandbox_running_sessions WHERE organization_id = $1 \
             AND (ended_at IS NULL OR credit_drawn_through < ended_at)",
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(due, 1);
        cleanup(&pool, fixture).await;
    }

    /// The fixture's sessions were last observed `minutes` after they started.
    async fn observe(pool: &PgPool, fixture: &Fixture, minutes: i32) {
        sqlx::query(
            "UPDATE sandbox_running_sessions \
             SET last_observed_at = started_at + make_interval(mins => $2) \
             WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .bind(minutes)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn db_a_session_closed_at_its_last_observation_draws_what_metering_counts() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        // Started two hours ago, and last seen an hour after that (#3898).
        session(&pool, &fixture, "open", "2 hours", None).await;
        observe(&pool, &fixture, 60).await;
        draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();

        // The sweep finds its Sandbox gone and closes it when it was last
        // observed, so metering counts that one hour.
        sqlx::query(
            "UPDATE sandbox_running_sessions \
             SET ended_at = last_observed_at, end_reason = 'controller_lost_track' \
             WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
        draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();

        let balance: i64 = sqlx::query_scalar(
            "SELECT balance_nano_eur FROM billing_credit_balances WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(balance, -201_270_000);
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn db_an_open_session_draws_through_its_last_observation_then_its_end() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        session(&pool, &fixture, "open", "2 hours", None).await;
        let draw = || draw_organization(&pool, &fixture.organization_id);

        observe(&pool, &fixture, 60).await;
        assert_eq!(draw().await.unwrap(), 201_270_000);
        // No new observation, nothing more to draw.
        assert_eq!(draw().await.unwrap(), 0);
        // Heartbeats resume: the time since the last draw is drawn, once.
        observe(&pool, &fixture, 90).await;
        assert_eq!(draw().await.unwrap(), 201_270_000 / 2);
        assert_eq!(draw().await.unwrap(), 0);

        // A close later than the last observation draws through the close.
        sqlx::query(
            "UPDATE sandbox_running_sessions SET ended_at = started_at + interval '2 hours' \
             WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(draw().await.unwrap(), 201_270_000 / 2);
        assert_eq!(draw().await.unwrap(), 0);
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn db_concurrent_draws_never_charge_a_second_twice() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        session(&pool, &fixture, "ended", "2 hours", Some("1 hour")).await;
        let (left, right) = tokio::join!(
            draw_organization(&pool, &fixture.organization_id),
            draw_organization(&pool, &fixture.organization_id),
        );
        let (left, right) = (left.unwrap(), right.unwrap());
        assert_eq!(left + right, 201_270_000, "{left} {right}");
        assert_eq!(ledger(&pool, &fixture).await.len(), 1);
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn db_unlimited_is_never_charged_and_a_switch_charges_from_the_switch() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "unlimited").await;
        session(&pool, &fixture, "open", "3 hours", None).await;
        assert_eq!(
            draw_organization(&pool, &fixture.organization_id)
                .await
                .unwrap(),
            0
        );
        assert!(ledger(&pool, &fixture).await.is_empty());

        // After a switch to Discounted, the next draw covers only the time
        // observed since the Unlimited draw, which is none.
        sqlx::query("UPDATE organizations SET rate_card = 'discounted' WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();
        let since = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert_eq!(since, 0);
        // An hour on Discounted costs half of Regular.
        sqlx::query(
            "UPDATE sandbox_running_sessions \
             SET credit_drawn_through = now() - interval '1 hour', last_observed_at = now() \
             WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
        let drawn = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert_eq!(drawn, 201_270_000 / 2);
        let entries = ledger(&pool, &fixture).await;
        assert_eq!(
            entries.last(),
            Some(&("usage".to_owned(), -drawn, Some("discounted".to_owned())))
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.2.as_deref() == Some("discounted"))
        );
        cleanup(&pool, fixture).await;
    }

    async fn balance(pool: &PgPool, fixture: &Fixture) -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE((SELECT balance_nano_eur FROM billing_credit_balances \
             WHERE organization_id = $1), 0)",
        )
        .bind(&fixture.organization_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn exhausted(pool: &PgPool, fixture: &Fixture) -> bool {
        sqlx::query_scalar(
            "SELECT credit_exhausted_at IS NOT NULL FROM organizations WHERE id = $1",
        )
        .bind(&fixture.organization_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn db_only_an_owner_changes_automatic_top_up_and_each_change_is_audited() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        let user = codewire_server_core::auth::AuthUser {
            user_id: fixture.user_id.clone(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let change = |enabled, cents| {
            crate::overview::update_auto_top_up(
                &pool,
                &user,
                &fixture.organization_id,
                enabled,
                cents,
            )
        };
        let audited = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM audit_logs \
                 WHERE action = 'organization.billing.auto_top_up' \
                 AND metadata->>'organization_id' = $1",
            )
            .bind(&fixture.organization_id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        // Not a member yet: the organization stays hidden.
        change(false, 1000).await.unwrap_err();
        sqlx::query(
            "INSERT INTO org_members (id, org_id, user_id, role) \
             VALUES (gen_random_uuid()::text, $1, $2, 'owner')",
        )
        .bind(&fixture.organization_id)
        .bind(&fixture.user_id)
        .execute(&pool)
        .await
        .unwrap();
        change(true, 499).await.unwrap_err();
        change(true, 100_001).await.unwrap_err();
        assert_eq!(audited().await, 0);

        assert_eq!(change(false, 1000).await.unwrap(), (false, 1000));
        assert_eq!(audited().await, 1);
        // The same values again change nothing, so nothing is audited.
        assert_eq!(change(false, 1000).await.unwrap(), (false, 1000));
        assert_eq!(audited().await, 1);
        assert_eq!(change(true, 2000).await.unwrap(), (true, 2000));
        assert_eq!(audited().await, 2);
        sqlx::query("DELETE FROM org_members WHERE org_id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn db_each_notice_is_due_once_per_spell() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fixture = seed(&pool, "regular").await;
        let organization_id = fixture.organization_id.clone();
        let due = || async {
            credit_notices_due(&pool)
                .await
                .unwrap()
                .into_iter()
                .filter(|notice| match notice {
                    CreditNotice::Low {
                        organization_id: id,
                        ..
                    }
                    | CreditNotice::Exhausted {
                        organization_id: id,
                    } => id == &organization_id,
                })
                .collect::<Vec<_>>()
        };
        let adjust = |key: &'static str, amount: i64| {
            let (pool, organization_id) = (pool.clone(), organization_id.clone());
            async move {
                sqlx::query(
                    "INSERT INTO billing_credit_ledger \
                     (organization_id, entry_kind, amount_nano_eur, idempotency_key, \
                      actor_user_id, reason) VALUES ($1, 'adjustment', $2, $3, 'test', 'test')",
                )
                .bind(&organization_id)
                .bind(amount)
                .bind(key)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
        assert!(due().await.is_empty(), "no credit yet means nothing is low");

        // Plenty, then low with top-up on and a customer: not due.
        adjust("plenty", 6 * NANO_EUR_PER_EURO).await;
        assert!(due().await.is_empty());
        adjust("spend", -2 * NANO_EUR_PER_EURO).await;
        sqlx::query(
            "UPDATE organizations SET stripe_customer_id = 'cus_notice_' || id WHERE id = $1",
        )
        .bind(&organization_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(due().await.is_empty());

        // Top-up off: due once, whatever the balance does next.
        sqlx::query("UPDATE organizations SET auto_top_up_enabled = false WHERE id = $1")
            .bind(&organization_id)
            .execute(&pool)
            .await
            .unwrap();
        let low = CreditNotice::Low {
            organization_id: organization_id.clone(),
            balance_nano_eur: 4 * NANO_EUR_PER_EURO,
        };
        assert_eq!(due().await, [low]);
        record_notice(&pool, &organization_id, LOW_NOTICE)
            .await
            .unwrap();
        assert!(due().await.is_empty());

        // New credit starts a new spell: low again later is due again.
        adjust("back", NANO_EUR_PER_EURO / 2).await;
        assert_eq!(due().await.len(), 1);
        record_notice(&pool, &organization_id, LOW_NOTICE)
            .await
            .unwrap();

        // Running out is due once, and replaces the low notice.
        adjust("gone", -5 * NANO_EUR_PER_EURO).await;
        mark_exhausted(&pool, &organization_id).await.unwrap();
        let exhausted = CreditNotice::Exhausted {
            organization_id: organization_id.clone(),
        };
        assert_eq!(due().await, std::slice::from_ref(&exhausted));
        record_notice(&pool, &organization_id, EXHAUSTED_NOTICE)
            .await
            .unwrap();
        assert!(due().await.is_empty());

        // Running out again, after credit came back, is due again.
        sqlx::query("UPDATE organizations SET credit_exhausted_at = now() WHERE id = $1")
            .bind(&organization_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(due().await, [exhausted]);

        // Unlimited hears nothing.
        sqlx::query("UPDATE organizations SET rate_card = 'unlimited' WHERE id = $1")
            .bind(&organization_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(due().await.is_empty());
        sqlx::query("DELETE FROM billing_events WHERE org_id = $1")
            .bind(&organization_id)
            .execute(&pool)
            .await
            .unwrap();
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn with_enforcement_off_no_notice_is_even_looked_for() {
        // Never connected: looking would fail.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://codewire@127.0.0.1:1/codewire")
            .unwrap();
        let email = crate::email::EmailClient::disabled();
        assert_eq!(
            send_credit_notices(&pool, &email, CreditEnforcement::Off)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn with_enforcement_off_settling_does_nothing_at_all() {
        // Neither the database nor Stripe is reachable, so anything but
        // returning at once would fail.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://codewire@127.0.0.1:1/codewire")
            .unwrap();
        let stripe = crate::stripe_client::StripeHandle::for_test("http://127.0.0.1:1");
        assert_eq!(
            settle_due(&pool, &stripe, CreditEnforcement::Off)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            settle_organization(&pool, &stripe, CreditEnforcement::Off, "org", true)
                .await
                .unwrap(),
            Settlement::NotEnforced
        );
        settle_due(&pool, &stripe, CreditEnforcement::On)
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn db_with_enforcement_off_an_empty_balance_with_a_card_is_left_alone() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let stripe = crate::stripe_client::StripeHandle::for_test("http://127.0.0.1:1");
        let fixture = seed(&pool, "regular").await;
        session(&pool, &fixture, "ended", "2 hours", Some("1 hour")).await;
        draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert!(balance(&pool, &fixture).await < 0);
        sqlx::query("UPDATE organizations SET stripe_customer_id = 'cus_off_' || id WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();

        settle_due(&pool, &stripe, CreditEnforcement::Off)
            .await
            .unwrap();
        let top_ups: i64 =
            sqlx::query_scalar("SELECT count(*) FROM billing_top_ups WHERE organization_id = $1")
                .bind(&fixture.organization_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(top_ups, 0);
        assert!(!exhausted(&pool, &fixture).await);

        // The same organization with enforcement on is marked out of credit:
        // the unreachable Stripe cannot confirm a card.
        assert_eq!(
            settle_organization(
                &pool,
                &stripe,
                CreditEnforcement::On,
                &fixture.organization_id,
                false
            )
            .await
            .unwrap(),
            Settlement::Exhausted
        );
        assert!(exhausted(&pool, &fixture).await);
        cleanup(&pool, fixture).await;
    }

    #[tokio::test]
    async fn db_top_ups_credit_once_and_a_refusal_or_no_card_exhausts() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let stripe = crate::stripe_client::StripeHandle::default();
        let fixture = seed(&pool, "regular").await;
        // Another organization out of credit at the same time, as other tests'
        // fixtures are while this one runs (#4098).
        let bystander = seed(&pool, "regular").await;
        for organization in [&fixture, &bystander] {
            session(&pool, organization, "ended", "2 hours", Some("1 hour")).await;
            draw_organization(&pool, &organization.organization_id)
                .await
                .unwrap();
            assert!(balance(&pool, organization).await < 0);
        }
        // Usage overran: the sweep finds the organization, and with no card,
        // settling it records the exhaustion. Only this organization is
        // settled: settling every due one would change other tests' fixtures.
        assert!(
            organizations_due(&pool)
                .await
                .unwrap()
                .contains(&fixture.organization_id)
        );
        assert_eq!(
            settle_organization(
                &pool,
                &stripe,
                CreditEnforcement::On,
                &fixture.organization_id,
                false
            )
            .await
            .unwrap(),
            Settlement::Exhausted
        );
        assert!(exhausted(&pool, &fixture).await);
        assert!(!exhausted(&pool, &bystander).await);
        cleanup(&pool, bystander).await;

        // A pending top-up whose charge cannot be confirmed stays pending.
        let top_up: String = sqlx::query_scalar(
            "INSERT INTO billing_top_ups (organization_id, amount_cents) VALUES ($1, 2000) \
             RETURNING id",
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE organizations SET stripe_customer_id = 'cus_test_' || id WHERE id = $1",
        )
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            settle_organization(
                &pool,
                &stripe,
                CreditEnforcement::On,
                &fixture.organization_id,
                false
            )
            .await
            .unwrap(),
            Settlement::Pending
        );

        // Its invoice is paid (here, by the webhook): EUR 20 once, and the
        // organization is no longer exhausted once the balance is positive.
        let before = balance(&pool, &fixture).await;
        let invoice = format!("in_{top_up}");
        assert!(complete_top_up(&pool, &top_up, &invoice).await.unwrap());
        assert!(!complete_top_up(&pool, &top_up, &invoice).await.unwrap());
        assert_eq!(
            balance(&pool, &fixture).await,
            before + 20 * NANO_EUR_PER_EURO
        );
        assert!(!exhausted(&pool, &fixture).await);
        assert_eq!(
            settle_organization(
                &pool,
                &stripe,
                CreditEnforcement::On,
                &fixture.organization_id,
                false
            )
            .await
            .unwrap(),
            Settlement::Funded
        );

        // A refused charge exhausts the organization.
        let refused: String = sqlx::query_scalar(
            "INSERT INTO billing_top_ups (organization_id, amount_cents) VALUES ($1, 2000) \
             RETURNING id",
        )
        .bind(&fixture.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        fail_top_up(
            &pool,
            &refused,
            Some(&format!("in_{refused}")),
            "Insufficient Funds",
        )
        .await
        .unwrap();
        let state: (String, Option<String>) =
            sqlx::query_as("SELECT state, failure_code FROM billing_top_ups WHERE id = $1")
                .bind(&refused)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            state,
            ("failed".to_owned(), Some("insufficientfunds".to_owned()))
        );
        assert!(exhausted(&pool, &fixture).await);

        // Unlimited is never exhausted.
        sqlx::query("UPDATE organizations SET rate_card = 'unlimited' WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            settle_organization(
                &pool,
                &stripe,
                CreditEnforcement::On,
                &fixture.organization_id,
                false
            )
            .await
            .unwrap(),
            Settlement::Funded
        );
        assert!(!exhausted(&pool, &fixture).await);
        cleanup(&pool, fixture).await;
    }
}
