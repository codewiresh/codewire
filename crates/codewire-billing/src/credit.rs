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

use std::time::Duration;

use chrono::{DateTime, Utc};
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

/// Draws one organization's due sessions up to now and returns the amount
/// drawn, in nano-euros.
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
                  LEAST(COALESCE(ended_at, $2), $2)
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
        // About two hours of the default sandbox; the open one ran a little
        // longer by the time it was drawn.
        assert!(
            (2 * 201_270_000..2 * 201_270_000 + 201_270_000 / 60).contains(&first),
            "{first}"
        );
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

        // The ended session is done; the open one is drawn only for the time
        // since, which is a fraction of a minute.
        let second = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert!(second < 201_270_000 / 60, "{second}");
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

        // After a switch to Discounted, the next draw covers only the
        // seconds since the Unlimited draw.
        sqlx::query("UPDATE organizations SET rate_card = 'discounted' WHERE id = $1")
            .bind(&fixture.organization_id)
            .execute(&pool)
            .await
            .unwrap();
        let since = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert!(since < 201_270_000 / 120, "{since}");
        // An hour on Discounted costs half of Regular.
        sqlx::query(
            "UPDATE sandbox_running_sessions SET credit_drawn_through = now() - interval '1 hour' \
             WHERE organization_id = $1",
        )
        .bind(&fixture.organization_id)
        .execute(&pool)
        .await
        .unwrap();
        let drawn = draw_organization(&pool, &fixture.organization_id)
            .await
            .unwrap();
        assert!(
            (201_270_000 / 2..201_270_000 / 2 + 201_270_000 / 120).contains(&drawn),
            "{drawn}"
        );
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
}
