use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::console::v1::{
    BillingServiceClient, CreatePortalSessionRequest, CreateSetupSessionRequest,
    GetBillingOverviewRequest, GetEnvironmentUsageRequest, ListBillingEventsRequest,
    ListInvoicesRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    dependency::{DependencyResult, PageDependency, resolve_connect},
    state::AppState,
    time_display::calendar_date,
    transport::BrowserTransport,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct BillingUsageRow {
    pub(crate) name: String,
    pub(crate) cost: String,
}

#[derive(Debug)]
pub(crate) struct BillingInvoiceRow {
    pub(crate) period: String,
    pub(crate) amount: String,
    pub(crate) status: String,
    pub(crate) hosted_url: String,
    pub(crate) has_hosted_url: bool,
    pub(crate) pdf_url: String,
    pub(crate) has_pdf_url: bool,
}

#[derive(Debug)]
pub(crate) struct BillingEventRow {
    pub(crate) event_type: String,
    pub(crate) occurred: String,
    pub(crate) amount: String,
    pub(crate) has_amount: bool,
}

#[derive(Debug)]
pub(crate) struct BillingUsageBar {
    pub(crate) x: usize,
    pub(crate) y: usize,
    pub(crate) height: usize,
    pub(crate) label: String,
}

#[derive(Debug, Default)]
pub(crate) struct BillingPageView {
    pub(crate) billing_enabled: bool,
    pub(crate) has_payment_method: bool,
    pub(crate) plan_name: String,
    pub(crate) status: String,
    pub(crate) status_tone: &'static str,
    pub(crate) trial_end: String,
    pub(crate) has_trial_end: bool,
    pub(crate) period_end: String,
    pub(crate) has_period_end: bool,
    pub(crate) can_manage: bool,
    pub(crate) usage_available: bool,
    pub(crate) has_current_month: bool,
    pub(crate) current_cost: String,
    pub(crate) cpu_hours: String,
    pub(crate) included_cpu_hours: String,
    pub(crate) has_included_cpu_hours: bool,
    pub(crate) memory_hours: String,
    pub(crate) included_memory_hours: String,
    pub(crate) has_included_memory_hours: bool,
    pub(crate) usage: Vec<BillingUsageRow>,
    pub(crate) usage_bars: Vec<BillingUsageBar>,
    pub(crate) invoices_available: bool,
    pub(crate) invoices: Vec<BillingInvoiceRow>,
    pub(crate) events_available: bool,
    pub(crate) events: Vec<BillingEventRow>,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

fn client(state: &AppState, cookie: HeaderValue) -> BillingServiceClient<BrowserTransport> {
    BillingServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(CLIENT_TIMEOUT),
    )
}

pub(crate) async fn billing_page(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    can_manage: bool,
    csrf_token: String,
    message: String,
    error: String,
) -> Result<BillingPageView, ConnectError> {
    let overview_client = client(state, cookie.clone());
    let usage_client = client(state, cookie.clone());
    let invoices_client = client(state, cookie.clone());
    let events_client = client(state, cookie);
    let (overview, usage, invoices, events) = tokio::join!(
        overview_client.get_billing_overview(GetBillingOverviewRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        usage_client.get_environment_usage(GetEnvironmentUsageRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        invoices_client.list_invoices(ListInvoicesRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        events_client.list_billing_events(ListBillingEventsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
    );
    let overview = match resolve_connect(PageDependency::BillingOverview, overview)? {
        DependencyResult::Available(overview) => overview.into_owned(),
        DependencyResult::Unavailable => {
            unreachable!("required billing overview cannot degrade")
        }
    };
    let usage = resolve_connect(PageDependency::BillingUsage, usage)?
        .into_option()
        .map(|response| response.into_owned());
    let invoices = resolve_connect(PageDependency::BillingInvoices, invoices)?
        .into_option()
        .map(|response| response.into_owned());
    let events = resolve_connect(PageDependency::BillingEvents, events)?
        .into_option()
        .map(|response| response.into_owned());

    let trial_end = overview.trial_end.into_option().map(|value| value.seconds);
    let period_end = overview
        .current_period_end
        .into_option()
        .map(|value| value.seconds);
    let usage_available = usage.is_some();
    let (current_month, hourly, usage_rows) = usage.map_or_else(
        || (None, Vec::new(), Vec::new()),
        |usage| {
            (
                usage.current_month.into_option(),
                usage.hourly_breakdown,
                usage.per_environment,
            )
        },
    );
    let hourly = hourly
        .into_iter()
        .rev()
        .take(24)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let max_cost = hourly
        .iter()
        .map(|entry| entry.cost_cents.max(0))
        .max()
        .unwrap_or(0);
    let usage_bars = hourly
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let height = if max_cost == 0 {
                2
            } else {
                ((entry.cost_cents.max(0) as usize * 72) / max_cost as usize).max(2)
            };
            let occurred = entry
                .hour
                .into_option()
                .map(|value| relative_time(value.seconds))
                .unwrap_or_else(|| "Unknown hour".to_owned());
            BillingUsageBar {
                x: 8 + index * 12,
                y: 80usize.saturating_sub(height),
                height,
                label: format!("{occurred}: {}", money(entry.cost_cents, "usd")),
            }
        })
        .collect();
    let (
        has_current_month,
        current_cost,
        cpu_hours,
        included_cpu_hours,
        has_included_cpu_hours,
        memory_hours,
        included_memory_hours,
        has_included_memory_hours,
    ) = current_month.map_or_else(
        || {
            (
                false,
                money(0, "usd"),
                "0.0".to_owned(),
                String::new(),
                false,
                "0.0".to_owned(),
                String::new(),
                false,
            )
        },
        |month| {
            (
                true,
                money(month.cost_cents, "usd"),
                format!("{:.1}", month.cpu_hours),
                month.included_cpu_hours.to_string(),
                month.included_cpu_hours > 0,
                format!("{:.1}", month.mem_gb_hours),
                month.included_mem_gb_hours.to_string(),
                month.included_mem_gb_hours > 0,
            )
        },
    );

    Ok(BillingPageView {
        billing_enabled: overview.billing_enabled,
        has_payment_method: overview.has_payment_method,
        plan_name: nonempty(overview.plan_display_name, "No plan"),
        status_tone: status_tone(&overview.status),
        status: overview.status,
        trial_end: trial_end.map(calendar_date).unwrap_or_default(),
        has_trial_end: trial_end.is_some(),
        period_end: period_end.map(calendar_date).unwrap_or_default(),
        has_period_end: period_end.is_some(),
        can_manage,
        usage_available,
        has_current_month,
        current_cost,
        cpu_hours,
        included_cpu_hours,
        has_included_cpu_hours,
        memory_hours,
        included_memory_hours,
        has_included_memory_hours,
        usage: usage_rows
            .into_iter()
            .map(|entry| BillingUsageRow {
                name: entry.name,
                cost: money(entry.cost_cents, "usd"),
            })
            .collect(),
        usage_bars,
        invoices_available: invoices.is_some(),
        invoices: invoices
            .into_iter()
            .flat_map(|response| response.invoices)
            .map(|invoice| {
                let start = invoice
                    .period_start
                    .into_option()
                    .map(|value| calendar_date(value.seconds))
                    .unwrap_or_else(|| "Unknown start".to_owned());
                let end = invoice
                    .period_end
                    .into_option()
                    .map(|value| calendar_date(value.seconds))
                    .unwrap_or_else(|| "Unknown end".to_owned());
                let hosted_url = safe_stripe_url(invoice.hosted_invoice_url.unwrap_or_default());
                let pdf_url = safe_stripe_url(invoice.invoice_pdf.unwrap_or_default());
                BillingInvoiceRow {
                    period: format!("{start} – {end}"),
                    amount: money(invoice.amount_paid, &invoice.currency),
                    status: invoice.status,
                    has_hosted_url: !hosted_url.is_empty(),
                    hosted_url,
                    has_pdf_url: !pdf_url.is_empty(),
                    pdf_url,
                }
            })
            .collect(),
        events_available: events.is_some(),
        events: events
            .into_iter()
            .flat_map(|response| response.events)
            .take(10)
            .map(|event| BillingEventRow {
                event_type: event.event_type,
                occurred: event
                    .created_at
                    .into_option()
                    .map(|value| calendar_date(value.seconds))
                    .unwrap_or_else(|| "Unknown time".to_owned()),
                amount: event
                    .amount_cents
                    .map(|value| money(value, &event.currency))
                    .unwrap_or_default(),
                has_amount: event.amount_cents.is_some(),
            })
            .collect(),
        csrf_token,
        message,
        error,
    })
}

pub(crate) async fn create_portal_session(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    return_url: String,
) -> Result<String, ConnectError> {
    Ok(client(state, cookie)
        .create_portal_session(CreatePortalSessionRequest {
            org_id,
            return_url,
            ..Default::default()
        })
        .await?
        .into_owned()
        .portal_url)
}

pub(crate) async fn create_setup_session(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    return_url: String,
) -> Result<String, ConnectError> {
    Ok(client(state, cookie)
        .create_setup_session(CreateSetupSessionRequest {
            org_id,
            success_url: return_url.clone(),
            cancel_url: return_url,
            ..Default::default()
        })
        .await?
        .into_owned()
        .checkout_url)
}

pub(crate) fn safe_stripe_url(raw: String) -> String {
    let Ok(url) = url::Url::parse(&raw) else {
        return String::new();
    };
    let host = url.host_str().unwrap_or_default();
    if url.scheme() == "https"
        && (host == "stripe.com" || host.ends_with(".stripe.com"))
        && url.username().is_empty()
        && url.password().is_none()
    {
        raw
    } else {
        String::new()
    }
}

fn nonempty(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn status_tone(status: &str) -> &'static str {
    match status {
        "active" => "success",
        "trialing" => "warning",
        "past_due" | "unpaid" | "incomplete" => "danger",
        _ => "muted",
    }
}

fn money(cents: i32, currency: &str) -> String {
    let cents = i64::from(cents);
    let sign = if cents < 0 { "-" } else { "" };
    let absolute = cents.abs();
    if currency.eq_ignore_ascii_case("usd") || currency.trim().is_empty() {
        format!("{sign}${}.{:02}", absolute / 100, absolute % 100)
    } else {
        format!(
            "{sign}{}.{:02} {}",
            absolute / 100,
            absolute % 100,
            currency.to_uppercase()
        )
    }
}

fn relative_time(seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let elapsed = now.saturating_sub(seconds);
    match elapsed {
        ..=59 => "Just now".to_owned(),
        60..=3_599 => format!("{}m ago", elapsed / 60),
        3_600..=86_399 => format!("{}h ago", elapsed / 3_600),
        _ => format!("{}d ago", elapsed / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use askama::Template as _;

    use super::*;
    use crate::{
        templates::OrganizationBillingTemplate,
        view::{DashboardView, OrganizationContext, OrganizationRow},
    };

    type BillingOutage = (&'static str, fn(&mut BillingPageView), &'static str);

    fn dashboard_view() -> DashboardView {
        DashboardView {
            account_id: "synthetic-account".to_owned(),
            user_name: "Dashboard User".into(),
            csrf_token: Default::default(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            organization_navigation_unavailable: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: "/settings/".into(),
            has_selected_organization: false,
            selected_organization_name: String::new(),
            selected_organization_slug: String::new(),
            selected_organization_url: String::new(),
            sandboxes: Vec::new(),
            recent_sandboxes: Vec::new(),
            sandbox_rail_available: false,
            sandbox_rail_loading: false,
            sandbox_total: 0,
            sandbox_running: 0,
            sandbox_stopped: 0,
            sandbox_attention: 0,
            provisioned_cpu_millicores: 0,
            provisioned_memory_mb: 0,
            provisioned_disk_gb: 0,
            sidebar_collapsed: false,
        }
    }

    #[test]
    fn stripe_redirects_fail_closed() {
        assert_eq!(
            safe_stripe_url("https://checkout.stripe.com/session/test".into()),
            "https://checkout.stripe.com/session/test"
        );
        for unsafe_url in [
            "http://checkout.stripe.com/session",
            "https://stripe.com.evil.test/session",
            "https://user:password@billing.stripe.com/session",
            "javascript:alert(1)",
        ] {
            assert!(safe_stripe_url(unsafe_url.into()).is_empty());
        }
    }

    #[test]
    fn money_formatting_is_bounded_and_currency_aware() {
        assert_eq!(money(1234, "usd"), "$12.34");
        assert_eq!(money(-50, "eur"), "-0.50 EUR");
    }

    #[test]
    fn optional_outages_keep_plan_and_payment_controls() {
        let organization = OrganizationContext::from_row(&OrganizationRow {
            id: "org-test".into(),
            name: "Test organization".into(),
            slug: "test".into(),
            role: "Owner",
            can_admin: true,
            billing_plan: "paid".into(),
            url: "/test/".into(),
        });
        let outages: [BillingOutage; 3] = [
            (
                "usage",
                |billing| billing.usage_available = false,
                "Usage is temporarily unavailable",
            ),
            (
                "invoices",
                |billing| billing.invoices_available = false,
                "Invoice history is temporarily unavailable",
            ),
            (
                "events",
                |billing| billing.events_available = false,
                "Recent billing activity is temporarily unavailable",
            ),
        ];

        for (name, inject, notice) in outages {
            let mut billing = BillingPageView {
                billing_enabled: true,
                can_manage: true,
                plan_name: "Team".into(),
                usage_available: true,
                invoices_available: true,
                events_available: true,
                csrf_token: "csrf".into(),
                ..Default::default()
            };
            inject(&mut billing);
            let body = OrganizationBillingTemplate {
                view: &dashboard_view(),
                organization: &organization,
                billing: &billing,
                active_tab: "billing",
            }
            .render()
            .expect("render degraded billing");

            assert!(body.contains(notice), "{name}");
            assert!(body.contains("Team"), "{name}");
            assert!(body.contains("/test/billing/_actions/setup"), "{name}");
            assert!(!body.contains("upstream-sensitive-detail"), "{name}");
        }
    }
}
