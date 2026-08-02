//! Org-scoped billing reads for the Connect service.
//!
//! Both require an authenticated org member (`require_org_member`,
//! 404 "organization not found" otherwise — non-members can't probe org
//! IDs for existence).
//!
//! ### Deliberate fixes vs. the retired Go handlers (verified against the
//! migration oracle on the contract fixture, 2026-06-11):
//!
//! 1. Go's invoice loop scans `period_start`/`period_end` (timestamp
//!    columns) into `*string` and `created_at` into `interface{}`; pgx
//!    can't do the former, the row Scan errors, and the `continue`
//!    SILENTLY DROPS every invoice that has billing periods set — i.e.
//!    most real invoices. `created_at` never arrives as a string, so the
//!    field is always `""`. Here: periods and created_at are RFC3339
//!    (same `formatTime` convention the Go events handler uses), and no
//!    rows are dropped.
//! 2. `billing_events` no longer carries resource-model columns; the Rust
//!    response shape only exposes the current append-only event fields.
//!
//! The Connect contract pins the corrected behavior.

use chrono::{DateTime, NaiveDateTime, Utc};
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::require_org_member;
use sqlx::PgPool;

/// Mirrors `billing.go::InvoiceResponse` (all fields, same JSON names).
#[derive(Debug)]
pub struct InvoiceResponse {
    pub id: String,
    pub stripe_invoice_id: String,
    pub status: String,
    pub amount_due: i32,
    pub amount_paid: i32,
    pub currency: String,
    pub hosted_invoice_url: Option<String>,
    pub invoice_pdf: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct InvoiceRow {
    id: String,
    stripe_invoice_id: String,
    status: String,
    amount_due: i32,
    amount_paid: i32,
    currency: String,
    hosted_invoice_url: Option<String>,
    invoice_pdf: Option<String>,
    // `timestamp without time zone` in the schema; stored values are UTC.
    period_start: Option<NaiveDateTime>,
    period_end: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
}

/// RFC3339 with UTC `Z`, matching the Go side's
/// `t.UTC().Format(time.RFC3339)` (`organizations.go::formatTime`).
fn fmt_naive_utc(t: NaiveDateTime) -> String {
    DateTime::<Utc>::from_naive_utc_and_offset(t, Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Shared invoice-list operation used by the Connect adapter.
pub async fn list_invoices_core(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<InvoiceResponse>> {
    require_org_member(pool, user, org_id).await?;

    let rows = sqlx::query_as::<_, InvoiceRow>(
        r#"
        SELECT id, stripe_invoice_id, status, amount_due, amount_paid, currency,
               hosted_invoice_url, invoice_pdf, period_start, period_end, created_at
        FROM stripe_invoices
        WHERE org_id = $1
        ORDER BY created_at DESC
        LIMIT 50
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    let invoices = rows
        .into_iter()
        .map(|r| InvoiceResponse {
            id: r.id,
            stripe_invoice_id: r.stripe_invoice_id,
            status: r.status,
            amount_due: r.amount_due,
            amount_paid: r.amount_paid,
            currency: r.currency,
            hosted_invoice_url: r.hosted_invoice_url,
            invoice_pdf: r.invoice_pdf,
            period_start: r.period_start.map(fmt_naive_utc),
            period_end: r.period_end.map(fmt_naive_utc),
            created_at: r.created_at.map(fmt_naive_utc).unwrap_or_default(),
        })
        .collect();

    Ok(invoices)
}

/// Billing event data mapped into the Connect response.
#[derive(Debug)]
pub struct BillingEventResponse {
    pub id: i64,
    pub event_type: String,
    pub org_id: Option<String>,
    pub amount_cents: Option<i32>,
    pub currency: String,
    pub stripe_item_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct BillingEventRow {
    id: i64,
    event_type: String,
    org_id: Option<String>,
    amount_cents: Option<i32>,
    currency: String,
    stripe_item_id: Option<String>,
    metadata: Option<serde_json::Value>,
    // `timestamp with time zone` in the schema.
    created_at: DateTime<Utc>,
}

/// Shared billing-event list operation used by the Connect adapter.
pub async fn list_events_core(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<BillingEventResponse>> {
    require_org_member(pool, user, org_id).await?;

    let rows = sqlx::query_as::<_, BillingEventRow>(
        r#"
        SELECT id, event_type, org_id, amount_cents, currency, stripe_item_id,
               metadata, created_at
        FROM billing_events
        WHERE org_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    let events = rows
        .into_iter()
        .map(|r| BillingEventResponse {
            id: r.id,
            event_type: r.event_type,
            org_id: r.org_id,
            amount_cents: r.amount_cents,
            currency: r.currency,
            stripe_item_id: r.stripe_item_id,
            metadata: r.metadata,
            created_at: r
                .created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
        .collect();

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formatting_matches_go_formattime() {
        // Go: t.UTC().Format(time.RFC3339) → "2026-06-02T10:30:00Z".
        let t = NaiveDateTime::parse_from_str("2026-06-02 10:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(fmt_naive_utc(t), "2026-06-02T10:30:00Z");
    }
}
