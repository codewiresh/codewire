//! What the Billing page shows each sandbox and each hour cost (#3954).
//!
//! The credit draw charges each running session's allocated size, through
//! its end or, while it is open, its last observation, at the organization's
//! rate card (`credit::draw_organization`). These figures read the same
//! windows and price them with the same function, so a sandbox's cost here
//! adds up to what its sessions drew, and Unlimited shows nothing.
//!
//! The rate card is the organization's current one: a month in which an
//! administrator changed it shows the whole month at the new card here,
//! while the month's total (`month_usage_nano_eur`) is what was drawn.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use crate::credit::{Rates, SessionWindow, UNLIMITED_RATE_CARD, usage_nano_eur};

const MICROSECONDS_PER_HOUR: f64 = 3_600_000_000.0;

/// One sandbox's usage this month.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCost {
    pub id: String,
    pub name: String,
    pub running_seconds: i32,
    /// Its largest size this month.
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub cost_nano_eur: i64,
    /// An hour at its largest size.
    pub hourly_nano_eur: i64,
}

/// One hour of the organization's usage.
#[derive(Debug, Clone, PartialEq)]
pub struct HourCost {
    pub hour: DateTime<Utc>,
    pub cpu_hours: f64,
    pub mem_gb_hours: f64,
    pub cost_nano_eur: i64,
}

/// The rates the organization is charged now; zero on Unlimited.
pub async fn charged_rates(pool: &PgPool, org_id: &str) -> AppResult<Rates> {
    let (rate_card, cpu, memory, disk): (String, i64, i64, i64) = sqlx::query_as(
        r#"SELECT o.rate_card, r.cpu_nano_eur_per_vcpu_hour,
                  r.memory_nano_eur_per_gib_hour, r.disk_nano_eur_per_gib_hour
           FROM organizations o
           JOIN billing_rate_cards r ON r.rate_card = o.rate_card
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    if rate_card == UNLIMITED_RATE_CARD {
        return Ok(Rates {
            cpu_per_vcpu_hour: 0,
            memory_per_gib_hour: 0,
            disk_per_gib_hour: 0,
        });
    }
    Ok(Rates {
        cpu_per_vcpu_hour: cpu,
        memory_per_gib_hour: memory,
        disk_per_gib_hour: disk,
    })
}

/// What the organization's usage drew from credit since `month_start`, in
/// nano-euros: the Billing page's month figure.
pub async fn month_usage_nano_eur(
    pool: &PgPool,
    org_id: &str,
    month_start: DateTime<Utc>,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        r#"SELECT COALESCE(-SUM(amount_nano_eur), 0)::int8 FROM billing_credit_ledger
           WHERE organization_id = $1 AND entry_kind = 'usage' AND usage_ended_at >= $2"#,
    )
    .bind(org_id)
    .bind(month_start)
    .fetch_one(pool)
    .await?)
}

/// Each sandbox that ran between `month_start` and `now`, longest first.
pub async fn sandbox_costs(
    pool: &PgPool,
    org_id: &str,
    rates: Rates,
    month_start: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<Vec<SandboxCost>> {
    type Row = (String, String, i32, i32, i32, i64);
    let rows: Vec<Row> = sqlx::query_as(
        r#"WITH bounded AS (
               SELECT s.environment_id,
                      COALESCE(e.name, s.runtime_name, s.environment_id) AS name,
                      s.cpu_millicores, s.memory_mib, s.disk_gib,
                      GREATEST(s.started_at, $2) AS bill_start,
                      LEAST(COALESCE(s.ended_at, s.last_observed_at), $3,
                            $2 + interval '1 month') AS bill_end
               FROM sandbox_running_sessions s
               LEFT JOIN environments e ON e.id = s.environment_id
               WHERE s.organization_id = $1
                 AND s.started_at < $3
                 AND COALESCE(s.ended_at, s.last_observed_at) > $2
           )
           SELECT environment_id, name, cpu_millicores, memory_mib, disk_gib,
                  (EXTRACT(EPOCH FROM (bill_end - bill_start)) * 1000000)::int8
           FROM bounded
           WHERE bill_end > bill_start
           ORDER BY environment_id, bill_start"#,
    )
    .bind(org_id)
    .bind(month_start)
    .bind(now)
    .fetch_all(pool)
    .await?;

    let mut order: Vec<String> = Vec::new();
    let mut sandboxes: HashMap<String, (String, Vec<SessionWindow>)> = HashMap::new();
    for (id, name, cpu_millicores, memory_mib, disk_gib, microseconds) in rows {
        let entry = sandboxes.entry(id.clone()).or_insert_with(|| {
            order.push(id);
            (name, Vec::new())
        });
        entry.1.push(SessionWindow {
            cpu_millicores,
            memory_mib,
            disk_gib,
            microseconds,
        });
    }
    let mut costs: Vec<SandboxCost> = order
        .into_iter()
        .filter_map(|id| {
            let (name, windows) = sandboxes.remove(&id)?;
            Some(sandbox_cost(id, name, rates, &windows))
        })
        .collect();
    costs.sort_by(|a, b| {
        b.running_seconds
            .cmp(&a.running_seconds)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(costs)
}

fn sandbox_cost(id: String, name: String, rates: Rates, windows: &[SessionWindow]) -> SandboxCost {
    let microseconds: i64 = windows.iter().map(|window| window.microseconds).sum();
    let largest = SessionWindow {
        cpu_millicores: windows.iter().map(|w| w.cpu_millicores).max().unwrap_or(0),
        memory_mib: windows.iter().map(|w| w.memory_mib).max().unwrap_or(0),
        disk_gib: windows.iter().map(|w| w.disk_gib).max().unwrap_or(0),
        microseconds: 3_600_000_000,
    };
    SandboxCost {
        id,
        name,
        running_seconds: i32::try_from(microseconds / 1_000_000).unwrap_or(i32::MAX),
        cpu_millicores: largest.cpu_millicores,
        memory_mib: largest.memory_mib,
        cost_nano_eur: usage_nano_eur(rates, windows),
        hourly_nano_eur: usage_nano_eur(rates, &[largest]),
    }
}

/// Each hour from `since`'s hour through `now`'s that had usage, oldest
/// first.
pub async fn hourly_costs(
    pool: &PgPool,
    org_id: &str,
    rates: Rates,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<Vec<HourCost>> {
    type Row = (DateTime<Utc>, i32, i32, i32, i64);
    let rows: Vec<Row> = sqlx::query_as(
        r#"WITH hours AS (
               SELECT generate_series(date_trunc('hour', $2::timestamptz),
                                      date_trunc('hour', $3::timestamptz),
                                      interval '1 hour') AS hour
           ),
           bounded AS (
               SELECT h.hour, s.cpu_millicores, s.memory_mib, s.disk_gib,
                      GREATEST(s.started_at, h.hour) AS bill_start,
                      LEAST(COALESCE(s.ended_at, s.last_observed_at), $3,
                            h.hour + interval '1 hour') AS bill_end
               FROM hours h
               JOIN sandbox_running_sessions s
                 ON s.organization_id = $1
                AND s.started_at < h.hour + interval '1 hour'
                AND COALESCE(s.ended_at, s.last_observed_at) > h.hour
           )
           SELECT hour, cpu_millicores, memory_mib, disk_gib,
                  (EXTRACT(EPOCH FROM (bill_end - bill_start)) * 1000000)::int8
           FROM bounded
           WHERE bill_end > bill_start
           ORDER BY hour"#,
    )
    .bind(org_id)
    .bind(since)
    .bind(now)
    .fetch_all(pool)
    .await?;

    let mut hours: Vec<(DateTime<Utc>, Vec<SessionWindow>)> = Vec::new();
    for (hour, cpu_millicores, memory_mib, disk_gib, microseconds) in rows {
        let window = SessionWindow {
            cpu_millicores,
            memory_mib,
            disk_gib,
            microseconds,
        };
        match hours.last_mut() {
            Some((last, windows)) if *last == hour => windows.push(window),
            _ => hours.push((hour, vec![window])),
        }
    }
    Ok(hours
        .into_iter()
        .map(|(hour, windows)| HourCost {
            hour,
            cpu_hours: windows
                .iter()
                .map(|w| {
                    w.microseconds as f64 / MICROSECONDS_PER_HOUR * f64::from(w.cpu_millicores)
                        / 1000.0
                })
                .sum(),
            mem_gb_hours: windows
                .iter()
                .map(|w| {
                    w.microseconds as f64 / MICROSECONDS_PER_HOUR * f64::from(w.memory_mib) / 1024.0
                })
                .sum(),
            cost_nano_eur: usage_nano_eur(rates, &windows),
        })
        .collect())
}

#[cfg(test)]
mod tests;
