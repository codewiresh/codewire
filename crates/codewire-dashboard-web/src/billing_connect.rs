use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::console::v1::{
    BillingServiceClient, CreatePortalSessionRequest, CreateSetupSessionRequest,
    GetBillingOverviewRequest, GetEnvironmentUsageRequest, GetSignupCreditRequest,
    ListBillingEventsRequest, ListInvoicesRequest, UpdateAutoTopUpRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    admin_connect::euro_text,
    billing_banner::CreditFacts,
    dependency::{DependencyResult, PageDependency, resolve_connect},
    state::AppState,
    time_display::calendar_date,
    transport::BrowserTransport,
    view::SandboxStartView,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the pricing page keeps the sign-up credit it read, and how long
/// it waits for billing before saying nothing about one.
const SIGNUP_CREDIT_TTL: Duration = Duration::from_secs(60);
const SIGNUP_CREDIT_TIMEOUT: Duration = Duration::from_secs(1);

/// The sign-up credit the pricing page last read, and when.
#[derive(Default)]
pub(crate) struct SignupCreditCache(tokio::sync::Mutex<Option<(std::time::Instant, i64)>>);

/// The credit a new organization is granted now, in nano-euros, for the
/// signed-out pricing page. Read through billing's one public method and kept
/// for a minute. When billing doesn't answer it is 0, so the page promises
/// nothing.
pub(crate) async fn signup_credit_nano_eur(state: &AppState) -> i64 {
    let mut cached = state.signup_credit.0.lock().await;
    if let Some((read_at, amount)) = *cached
        && read_at.elapsed() < SIGNUP_CREDIT_TTL
    {
        return amount;
    }
    let client = BillingServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: None,
            origin: None,
        },
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(SIGNUP_CREDIT_TIMEOUT),
    );
    let amount = match client
        .get_signup_credit(GetSignupCreditRequest::default())
        .await
    {
        Ok(response) => response.into_owned().amount_nano_eur.max(0),
        Err(_) => 0,
    };
    *cached = Some((std::time::Instant::now(), amount));
    amount
}

/// The sign-up credit as the pricing page says it: whole euros without
/// cents ("€10"), otherwise to the cent ("€7.50"). `None` when there is none.
pub(crate) fn signup_credit_text(nano_eur: i64) -> Option<String> {
    const NANO_EUR_PER_CENT: i64 = 10_000_000;
    let cents = nano_eur / NANO_EUR_PER_CENT;
    (cents > 0).then(|| {
        if cents % 100 == 0 {
            format!("€{}", cents / 100)
        } else {
            format!("€{}.{:02}", cents / 100, cents % 100)
        }
    })
}

/// How long the billing banner and Create Sandbox wait for the overview
/// before saying nothing about credit.
const CREDIT_FACTS_TIMEOUT: Duration = Duration::from_secs(2);

/// The organization's credit, as the billing banner and Create Sandbox read
/// it. `None` when billing does not answer within its budget, which shows no
/// banner and leaves Create as it is.
pub(crate) async fn credit_facts(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Option<CreditFacts> {
    let billing = client(state, cookie);
    let request = billing.get_billing_overview(GetBillingOverviewRequest {
        org_id: org_id.to_owned(),
        ..Default::default()
    });
    let Ok(Ok(overview)) = tokio::time::timeout(CREDIT_FACTS_TIMEOUT, request).await else {
        return None;
    };
    let overview = overview.into_owned();
    let rates = overview.rates.into_option().unwrap_or_default();
    Some(CreditFacts {
        balance_nano_eur: overview.credit_balance_nano_eur,
        has_card: overview.has_payment_method,
        auto_top_up: overview.auto_top_up_enabled,
        billing_enabled: overview.billing_enabled,
        unmetered: overview.unmetered,
        cpu_nano_eur_per_vcpu_hour: rates.cpu_nano_eur_per_vcpu_hour,
        memory_nano_eur_per_gib_hour: rates.memory_nano_eur_per_gib_hour,
        disk_nano_eur_per_gib_hour: rates.disk_nano_eur_per_gib_hour,
        exhausted_at: overview
            .credit_exhausted_at
            .into_option()
            .map(|value| value.seconds),
    })
}

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
    /// Prepaid compute credit (#3381), in euros.
    pub(crate) credit_balance: String,
    pub(crate) credit_negative: bool,
    /// No charge at all: the rates are zero and there is no quota.
    pub(crate) unmetered: bool,
    pub(crate) cpu_rate: String,
    pub(crate) memory_rate: String,
    pub(crate) disk_rate: String,
    pub(crate) auto_top_up_enabled: bool,
    /// The automatic top-up in euros, as the form shows it ("20").
    pub(crate) auto_top_up_euros: String,
    pub(crate) credit_exhausted: bool,
    pub(crate) credit_exhausted_since: String,
    pub(crate) can_manage: bool,
    pub(crate) usage_available: bool,
    pub(crate) has_current_month: bool,
    pub(crate) current_cost: String,
    pub(crate) cpu_hours: String,
    pub(crate) memory_hours: String,
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

/// The standard cloud size the empty Sandboxes page prices, as the pricing
/// page shows it: 2 vCPU, 8 GB of memory and 100 GB of disk.
const START_VCPU: i64 = 2;
const START_MEMORY_GIB: i64 = 8;
const START_DISK_GIB: i64 = 100;
/// The empty Sandboxes page waits this long for billing, then shows its
/// panel without a price.
const START_TIMEOUT: Duration = Duration::from_secs(2);

/// What the empty Sandboxes page says about the cloud: the standard size's
/// hourly price on this organization's rate card and whether a card is on
/// file. Billing that is off, unmetered or unavailable gives no price.
pub(crate) async fn sandbox_start(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> SandboxStartView {
    let billing = client(state, cookie);
    let request = billing.get_billing_overview(GetBillingOverviewRequest {
        org_id: org_id.to_owned(),
        ..Default::default()
    });
    let Ok(Ok(overview)) = tokio::time::timeout(START_TIMEOUT, request).await else {
        return SandboxStartView::default();
    };
    let overview = overview.into_owned();
    let metered = overview.billing_enabled && !overview.unmetered;
    let rates = overview.rates.into_option().unwrap_or_default();
    let hourly = START_VCPU
        .saturating_mul(rates.cpu_nano_eur_per_vcpu_hour)
        .saturating_add(START_MEMORY_GIB.saturating_mul(rates.memory_nano_eur_per_gib_hour))
        .saturating_add(START_DISK_GIB.saturating_mul(rates.disk_nano_eur_per_gib_hour));
    SandboxStartView {
        hourly: (metered && hourly > 0).then(|| euro_text(hourly)),
        has_card: overview.has_payment_method,
        metered,
    }
}

/// What the account home shows of an organization's billing overview.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BillingSummary {
    pub(crate) has_card: bool,
    /// The organization pays for cloud use: billing on and not unmetered.
    pub(crate) metered: bool,
    pub(crate) balance_nano_eur: i64,
    /// Drawn from credit since the start of the month.
    pub(crate) month_nano_eur: i64,
}

/// One hour of an organization's Sandbox cost, as the Billing page's chart
/// reads it: the hour's start in Unix seconds and its cost in cents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HourCost {
    pub(crate) hour: i64,
    pub(crate) cost_cents: i32,
}

pub(crate) async fn account_home_overview(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<BillingSummary, ConnectError> {
    let overview = client(state, cookie)
        .get_billing_overview(GetBillingOverviewRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(BillingSummary {
        has_card: overview.has_payment_method,
        metered: overview.billing_enabled && !overview.unmetered,
        balance_nano_eur: overview.credit_balance_nano_eur,
        month_nano_eur: overview.month_usage_nano_eur,
    })
}

/// The hourly cost billing reports for the organization's recent hours (the
/// last 72; hours without usage may be left out).
pub(crate) async fn account_home_hourly(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
) -> Result<Vec<HourCost>, ConnectError> {
    let usage = client(state, cookie)
        .get_environment_usage(GetEnvironmentUsageRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(usage
        .hourly_breakdown
        .into_iter()
        .filter_map(|entry| {
            Some(HourCost {
                hour: entry.hour.into_option()?.seconds,
                cost_cents: entry.cost_cents,
            })
        })
        .collect())
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

    let exhausted_at = overview
        .credit_exhausted_at
        .into_option()
        .map(|value| value.seconds);
    let rates = overview.rates.into_option().unwrap_or_default();
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
                label: format!("{occurred}: {}", money(entry.cost_cents, "eur")),
            }
        })
        .collect();
    let (has_current_month, cpu_hours, memory_hours) = current_month.map_or_else(
        || (false, "0.0".to_owned(), "0.0".to_owned()),
        |month| {
            (
                true,
                format!("{:.1}", month.cpu_hours),
                format!("{:.1}", month.mem_gb_hours),
            )
        },
    );
    // The month's cost is what was drawn from credit, not an estimate.
    let current_cost = euro_text(overview.month_usage_nano_eur);

    Ok(BillingPageView {
        billing_enabled: overview.billing_enabled,
        has_payment_method: overview.has_payment_method,
        credit_balance: euro_text(overview.credit_balance_nano_eur),
        credit_negative: overview.credit_balance_nano_eur < 0,
        unmetered: overview.unmetered,
        cpu_rate: euro_text(rates.cpu_nano_eur_per_vcpu_hour),
        memory_rate: euro_text(rates.memory_nano_eur_per_gib_hour),
        disk_rate: euro_text(rates.disk_nano_eur_per_gib_hour),
        auto_top_up_enabled: overview.auto_top_up_enabled,
        auto_top_up_euros: top_up_euros(overview.auto_top_up_cents),
        credit_exhausted: exhausted_at.is_some(),
        credit_exhausted_since: exhausted_at.map(calendar_date).unwrap_or_default(),
        can_manage,
        usage_available,
        has_current_month,
        current_cost,
        cpu_hours,
        memory_hours,
        usage: usage_rows
            .into_iter()
            .map(|entry| BillingUsageRow {
                name: entry.name,
                cost: money(entry.cost_cents, "eur"),
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
                    // A one-off invoice, such as a top-up, covers one day.
                    period: if start == end {
                        start
                    } else {
                        format!("{start} – {end}")
                    },
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

/// Turns automatic top-up on or off and sets its amount, in cents.
pub(crate) async fn update_auto_top_up(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    enabled: bool,
    amount_cents: i32,
) -> Result<(), ConnectError> {
    client(state, cookie)
        .update_auto_top_up(UpdateAutoTopUpRequest {
            org_id,
            enabled,
            amount_cents,
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// A top-up amount in whole euros, or with cents when it has them.
fn top_up_euros(cents: i32) -> String {
    if cents % 100 == 0 {
        (cents / 100).to_string()
    } else {
        format!("{}.{:02}", cents / 100, cents % 100)
    }
}

/// A submitted top-up amount in euros ("20", "7.50") in cents: EUR 5 to
/// EUR 1,000 with at most two decimals.
pub(crate) fn top_up_cents(text: &str) -> Option<i32> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || whole.len() > 4
        || fraction.len() > 2
        || (text.contains('.') && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let cents = whole.parse::<i32>().ok()? * 100 + format!("{fraction:0<2}").parse::<i32>().ok()?;
    (500..=100_000).contains(&cents).then_some(cents)
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

fn money(cents: i32, currency: &str) -> String {
    let cents = i64::from(cents);
    let sign = if cents < 0 { "-" } else { "" };
    let absolute = cents.abs();
    if currency.eq_ignore_ascii_case("eur") || currency.trim().is_empty() {
        format!("{sign}€{}.{:02}", absolute / 100, absolute % 100)
    } else if currency.eq_ignore_ascii_case("usd") {
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
        assert_eq!(money(-50, "eur"), "-€0.50");
        assert_eq!(money(50, "gbp"), "0.50 GBP");
    }

    #[test]
    fn top_up_amounts_are_euros_between_five_and_a_thousand() {
        assert_eq!(top_up_cents("20"), Some(2000));
        assert_eq!(top_up_cents(" 7.5 "), Some(750));
        assert_eq!(top_up_cents("1000"), Some(100_000));
        for invalid in ["", "4.99", "1000.01", "20.", "1e3", "-20", "20,00", "abc"] {
            assert_eq!(top_up_cents(invalid), None, "{invalid:?}");
        }
        assert_eq!(top_up_euros(2000), "20");
        assert_eq!(top_up_euros(750), "7.50");
    }

    fn test_organization() -> OrganizationContext {
        OrganizationContext::from_row(&OrganizationRow {
            id: "org-test".into(),
            name: "Test organization".into(),
            slug: "test".into(),
            billing_plan: "none".into(),
            role: "Owner",
            can_admin: true,
            url: "/test/".into(),
        })
    }

    fn render(billing: &BillingPageView) -> String {
        OrganizationBillingTemplate {
            view: &dashboard_view(),
            organization: &test_organization(),
            billing,
            active_tab: "billing",
        }
        .render()
        .expect("render billing")
    }

    #[test]
    fn compute_credit_shows_balance_rates_top_up_and_exhaustion() {
        let billing = BillingPageView {
            billing_enabled: true,
            can_manage: true,
            credit_balance: "-€0.25".into(),
            credit_negative: true,
            cpu_rate: "€0.0438".into(),
            memory_rate: "€0.0141".into(),
            disk_rate: "€0.000087".into(),
            auto_top_up_enabled: true,
            auto_top_up_euros: "20".into(),
            credit_exhausted: true,
            credit_exhausted_since: "Oct 28, 2026".into(),
            csrf_token: "csrf".into(),
            ..Default::default()
        };
        let body = render(&billing);
        assert!(body.contains(r#"<h2 id="credit-heading">Compute credit</h2>"#));
        assert!(body.contains(
            r#"<dt>Balance</dt><dd><span class="cw-badge" data-tone="warning">-€0.25</span></dd>"#
        ));
        assert!(body.contains("<dt>vCPU</dt><dd>€0.0438 <small>per hour</small></dd>"));
        assert!(body.contains("ran out of compute credit on Oct 28, 2026"));
        // No card yet: the setup action, and no credit is promised for one.
        assert!(body.contains(r#"action="/test/billing/_actions/setup""#));
        assert!(body.contains("<p class=\"cw-muted\">No payment method yet.</p>"));
        assert!(!body.contains("grants"));
        // The top-up form is labelled and starts at the stored values.
        assert!(body.contains(r#"action="/test/billing/_actions/auto-top-up""#));
        assert!(body.contains(
            r#"<label class="cw-choice"><input class="cw-checkbox" type="checkbox" name="enabled" value="true" checked><span>Top up automatically</span></label>"#
        ));
        assert!(body.contains(r#"name="amount" inputmode="decimal""#));
        assert!(body.contains(r#"value="20" required"#));
        // No plan, seat or trial language is left.
        for retired in ["Plan", "trial", "Trial", "seat"] {
            assert!(!body.contains(retired), "{retired}");
        }

        // An Unlimited organization sees no rates or top-up.
        let body = render(&BillingPageView {
            billing_enabled: true,
            can_manage: true,
            unmetered: true,
            // Switched to Unlimited a moment ago: billing clears this on its
            // next pass, and the page never claims creates are refused.
            credit_exhausted: true,
            credit_exhausted_since: "Oct 28, 2026".into(),
            csrf_token: "csrf".into(),
            ..Default::default()
        });
        assert!(body.contains("not charged for compute"));
        assert!(!body.contains("ran out of compute credit"));
        assert!(!body.contains("auto-top-up"));
        assert!(!body.contains("<dt>vCPU</dt>"));
    }

    #[test]
    fn the_signup_credit_reads_as_euros_and_none_is_silent() {
        assert_eq!(signup_credit_text(0), None);
        assert_eq!(signup_credit_text(-1), None);
        assert_eq!(signup_credit_text(10_000_000_000).as_deref(), Some("€10"));
        assert_eq!(signup_credit_text(7_500_000_000).as_deref(), Some("€7.50"));
        assert_eq!(signup_credit_text(10_000_000).as_deref(), Some("€0.01"));
    }

    #[test]
    fn the_pricing_page_promises_a_signup_credit_only_while_there_is_one() {
        use askama::Template;

        let render = |signup_credit: Option<&str>| {
            crate::templates::PricingTemplate {
                signup_credit: signup_credit.map(str::to_owned),
            }
            .render()
            .unwrap()
        };
        let off = render(None);
        for promise in ["of compute", "sign up", "€50"] {
            assert!(!off.contains(promise), "{promise}");
        }
        assert!(off.contains("<p class=\"copy\">Pay only while your sandboxes run.</p>"));
        assert!(off.contains("<h2 id=\"access-title\">Start building.</h2>"));
        assert!(off.contains("Local sandboxes are always free."));

        let on = render(Some("€10"));
        assert!(
            on.contains("€10 of compute when you sign up. Then pay only while your sandboxes run.")
        );
        assert!(on.contains("Start with €10 of compute <span"));
        assert!(on.contains("<h2 id=\"access-title\">Start with €10 of compute.</h2>"));
        assert!(
            on.contains("€10 of compute when you sign up, and local sandboxes are always free.")
        );
    }

    #[test]
    fn optional_outages_keep_credit_and_payment_controls() {
        let organization = test_organization();
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
                credit_balance: "€42.50".into(),
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
            assert!(body.contains("€42.50"), "{name}");
            assert!(body.contains("/test/billing/_actions/setup"), "{name}");
            assert!(!body.contains("upstream-sensitive-detail"), "{name}");
        }
    }
}
