use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use codewire_proto::codewire::console::v1::{
    AddCreditRequest, AddCreditResponse, BeginCardSetupRequest, BillingServiceClient,
    CardSetupSettlement, FinishCardSetupRequest, GetBillingOverviewRequest,
    GetBillingOverviewResponse, GetEnvironmentUsageRequest, GetSignupCreditRequest,
    ListBillingEventsRequest, ListInvoicesRequest, ListPaymentMethodsRequest,
    RemovePaymentMethodRequest, SavedPaymentMethod, SetDefaultPaymentMethodRequest,
    UpdateAutoTopUpRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{
    admin_connect::euro_text,
    billing_banner::{CreditFacts, SandboxLoad, runway_text},
    dependency::{DependencyResult, PageDependency, resolve_connect},
    state::AppState,
    time_display::calendar_date,
    transport::BrowserTransport,
    usage_scale::{UsageScale, ZERO_Y},
    view::SandboxStartView,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the Billing page waits for the Sandboxes its runway reads.
const RUNWAY_SANDBOXES_TIMEOUT: Duration = Duration::from_secs(2);
/// A purchase charges the card through several Stripe calls, which billing
/// bounds at 30 seconds.
const ADD_CREDIT_TIMEOUT: Duration = Duration::from_secs(40);

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
    Some(facts_of(&overview.into_owned()))
}

/// The credit facts an overview states.
fn facts_of(overview: &GetBillingOverviewResponse) -> CreditFacts {
    let rates = overview.rates.as_option().cloned().unwrap_or_default();
    CreditFacts {
        balance_nano_eur: overview.credit_balance_nano_eur,
        has_card: overview.has_payment_method,
        card: overview
            .default_card
            .as_option()
            .map(|card| format!("{} •••• {}", card_brand_name(&card.brand), card.last4)),
        auto_top_up: overview.auto_top_up_enabled,
        auto_top_up_cents: overview.auto_top_up_cents,
        top_up_charging_cents: overview.top_up_charging_cents,
        enforced: overview.credit_enforced,
        billing_enabled: overview.billing_enabled,
        unmetered: overview.unmetered,
        cpu_nano_eur_per_vcpu_hour: rates.cpu_nano_eur_per_vcpu_hour,
        memory_nano_eur_per_gib_hour: rates.memory_nano_eur_per_gib_hour,
        disk_nano_eur_per_gib_hour: rates.disk_nano_eur_per_gib_hour,
        exhausted_at: overview
            .credit_exhausted_at
            .as_option()
            .map(|value| value.seconds),
    }
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

/// The default card as its row on the Billing page shows it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PaymentCardView {
    /// The brand as people name it, such as "American Express".
    pub(crate) brand: &'static str,
    pub(crate) last4: String,
    /// Month and year, such as "11/2026".
    pub(crate) expiry: String,
    /// The card's expiry month has ended.
    pub(crate) expired: bool,
}

impl PaymentCardView {
    /// A card is valid through the last day of its expiry month, so it is
    /// expired only once a later month has started (UTC).
    pub(crate) fn new(
        card: &codewire_proto::codewire::console::v1::PaymentCard,
        today: chrono::NaiveDate,
    ) -> Self {
        use chrono::Datelike as _;
        let now = (today.year(), today.month() as i32);
        Self {
            brand: card_brand_name(&card.brand),
            last4: card.last4.clone(),
            expiry: format!("{:02}/{}", card.exp_month, card.exp_year),
            expired: (card.exp_year, card.exp_month) < now,
        }
    }
}

/// One saved card as its row on the Billing page shows it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SavedCardView {
    /// Stripe's PaymentMethod id, which the card's actions name.
    pub(crate) id: String,
    pub(crate) card: PaymentCardView,
    pub(crate) default: bool,
    /// The card as the page names it: "Visa •••• 4242".
    pub(crate) label: String,
    /// The id of its Remove dialog, unique on the page.
    pub(crate) dialog_id: String,
}

impl SavedCardView {
    /// `None` for a payment method Stripe gave no card details for.
    pub(crate) fn new(
        saved: &SavedPaymentMethod,
        default_id: &str,
        index: usize,
        today: chrono::NaiveDate,
    ) -> Option<Self> {
        let card = PaymentCardView::new(saved.card.as_option()?, today);
        Some(Self {
            id: saved.id.clone(),
            default: !default_id.is_empty() && saved.id == default_id,
            label: format!("{} •••• {}", card.brand, card.last4),
            dialog_id: format!("remove-card-{index}"),
            card,
        })
    }
}

/// One amount the automatic top-up offers, in euros.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TopUpChoice {
    pub(crate) euros: String,
    pub(crate) selected: bool,
}

/// The amounts automatic top-up offers (v4, owner 2026-11-14, #4750), and
/// the organization's own amount when it is none of them.
const TOP_UP_EUROS: [i32; 4] = [10, 20, 50, 100];

pub(crate) fn top_up_choices(cents: i32) -> Vec<TopUpChoice> {
    let mut amounts: Vec<i32> = TOP_UP_EUROS.iter().map(|euros| euros * 100).collect();
    if !amounts.contains(&cents) && (500..=100_000).contains(&cents) {
        amounts.push(cents);
        amounts.sort_unstable();
    }
    amounts
        .into_iter()
        .map(|amount| TopUpChoice {
            euros: top_up_euros(amount),
            selected: amount == cents,
        })
        .collect()
}

/// Stripe's card brand codes as people name them; any other is "Card".
pub(crate) fn card_brand_name(code: &str) -> &'static str {
    match code {
        "amex" => "American Express",
        "cartes_bancaires" => "Cartes Bancaires",
        "diners" => "Diners Club",
        "discover" => "Discover",
        "eftpos_au" => "eftpos Australia",
        "interac" => "Interac",
        "jcb" => "JCB",
        "link" => "Link",
        "mastercard" => "Mastercard",
        "unionpay" => "UnionPay",
        "visa" => "Visa",
        _ => "Card",
    }
}

#[derive(Debug, Default)]
pub(crate) struct BillingPageView {
    pub(crate) billing_enabled: bool,
    pub(crate) has_payment_method: bool,
    /// The organization's saved cards, newest first (#4750).
    pub(crate) cards: Vec<SavedCardView>,
    /// Billing answered with the cards; otherwise the list says it is
    /// unavailable.
    pub(crate) cards_available: bool,
    /// Stripe's publishable key, which the card form mounts with; empty when
    /// the form is not configured or the cards are unavailable, and then the
    /// form says adding a card isn't available.
    pub(crate) card_key: String,
    /// The default card as the page names it ("Visa •••• 4242"), or empty.
    pub(crate) default_card: String,
    /// Prepaid compute credit (#3381), in euros.
    pub(crate) credit_balance: String,
    pub(crate) credit_negative: bool,
    /// No credit left: saving a card with top-up on charges it at once, so
    /// the button names the charge.
    pub(crate) balance_empty: bool,
    /// How long the credit lasts at the running Sandboxes' rate ("About 2
    /// days at current use"), or empty when nothing runs or it is unknown.
    pub(crate) runway: String,
    /// No charge at all: the rates are zero and there is no quota.
    pub(crate) unmetered: bool,
    pub(crate) cpu_rate: String,
    pub(crate) memory_rate: String,
    pub(crate) disk_rate: String,
    pub(crate) auto_top_up_enabled: bool,
    /// The automatic top-up in euros, as the form shows it ("20").
    pub(crate) auto_top_up_euros: String,
    pub(crate) top_up_choices: Vec<TopUpChoice>,
    /// The key of this page's Add credit attempt: a resubmitted form never
    /// charges twice.
    pub(crate) add_credit_request: String,
    pub(crate) can_manage: bool,
    pub(crate) usage_available: bool,
    pub(crate) has_current_month: bool,
    pub(crate) current_cost: String,
    pub(crate) cpu_hours: String,
    pub(crate) memory_hours: String,
    pub(crate) usage: Vec<BillingUsageRow>,
    pub(crate) usage_bars: Vec<BillingUsageBar>,
    /// The euro scale the bars are drawn against; `None` when no hour cost
    /// anything.
    pub(crate) usage_scale: Option<UsageScale>,
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
/// reads it: the hour's start in Unix seconds and its cost in nano-euros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HourCost {
    pub(crate) hour: i64,
    pub(crate) cost_nano_eur: i64,
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
                cost_nano_eur: entry.cost_nano_eur,
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
    let events_client = client(state, cookie.clone());
    let cards_client = client(state, cookie.clone());
    let (overview, usage, invoices, events, cards, sandboxes) = tokio::join!(
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
        cards_client.list_payment_methods(ListPaymentMethodsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        }),
        // Only the balance's runway reads them; without them it says nothing.
        tokio::time::timeout(
            RUNWAY_SANDBOXES_TIMEOUT,
            crate::environment_connect::environments(state, cookie, org_id, false),
        ),
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
    let cards = resolve_connect(PageDependency::BillingCards, cards)?
        .into_option()
        .map(|response| response.into_owned());
    let facts = facts_of(&overview);
    let runway = sandboxes
        .ok()
        .and_then(Result::ok)
        .and_then(|rows| {
            let loads: Vec<SandboxLoad> = rows.iter().map(SandboxLoad::from).collect();
            runway_text(&facts, &loads)
        })
        .unwrap_or_default();
    let today = chrono::Utc::now().date_naive();
    let cards_available = cards.is_some();
    let card_key = cards
        .as_ref()
        .map(|list| list.publishable_key.clone())
        .unwrap_or_default();
    let cards: Vec<SavedCardView> = cards
        .map(|list| {
            list.payment_methods
                .iter()
                .enumerate()
                .filter_map(|(index, saved)| {
                    SavedCardView::new(saved, &list.default_id, index, today)
                })
                .collect()
        })
        .unwrap_or_default();
    let default_card = cards
        .iter()
        .find(|card| card.default)
        .map(|card| card.label.clone())
        .unwrap_or_default();

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
    let usage_scale = UsageScale::for_max(
        hourly
            .iter()
            .map(|entry| entry.cost_nano_eur.max(0))
            .max()
            .unwrap_or(0),
    );
    let usage_bars = hourly
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let height = usage_scale
                .as_ref()
                .map_or(0, |scale| scale.height(entry.cost_nano_eur))
                .max(2) as usize;
            let occurred = entry
                .hour
                .into_option()
                .map(|value| relative_time(value.seconds))
                .unwrap_or_else(|| "Unknown hour".to_owned());
            BillingUsageBar {
                x: 8 + index * 12,
                y: (ZERO_Y as usize).saturating_sub(height),
                height,
                label: format!("{occurred}: {}", euro_text(entry.cost_nano_eur)),
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
        cards,
        cards_available,
        card_key,
        default_card,
        credit_balance: euro_text(overview.credit_balance_nano_eur),
        credit_negative: overview.credit_balance_nano_eur < 0,
        balance_empty: overview.credit_balance_nano_eur <= 0,
        runway,
        unmetered: overview.unmetered,
        cpu_rate: euro_text(rates.cpu_nano_eur_per_vcpu_hour),
        memory_rate: euro_text(rates.memory_nano_eur_per_gib_hour),
        disk_rate: euro_text(rates.disk_nano_eur_per_gib_hour),
        auto_top_up_enabled: overview.auto_top_up_enabled,
        auto_top_up_euros: top_up_euros(overview.auto_top_up_cents),
        top_up_choices: top_up_choices(overview.auto_top_up_cents),
        add_credit_request: crate::security::new_csrf_token(),
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
                cost: euro_text(entry.cost_nano_eur),
            })
            .collect(),
        usage_bars,
        usage_scale,
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

/// What saving a card chooses beside it. Billing keeps them in the
/// SetupIntent and reads them back only from there when it finishes.
pub(crate) struct CardSetupChoice {
    pub(crate) auto_top_up_enabled: bool,
    pub(crate) auto_top_up_cents: i32,
    /// Add credit with no card yet: the amount in cents.
    pub(crate) credit_cents: Option<i32>,
}

/// Starts adding a card once it is saved: the client secret the card form
/// confirms with. `client_hop` is the last `X-Forwarded-For` hop of the page
/// request, which the edge wrote; it is sent as the call's only
/// `X-Forwarded-For`, so billing counts its per-address cap under it and a
/// browser's own entries never reach billing (#4901). No other billing call
/// sends one.
pub(crate) async fn begin_card_setup(
    state: &AppState,
    cookie: HeaderValue,
    client_hop: Option<&str>,
    org_id: String,
    choice: CardSetupChoice,
) -> Result<String, ConnectError> {
    let transport = crate::transport::ForwardingTransport {
        inner: BrowserTransport {
            http: state.http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        forwarded_for: client_hop.and_then(|hop| HeaderValue::from_str(hop).ok()),
    };
    let client = BillingServiceClient::new(
        transport,
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(CLIENT_TIMEOUT),
    );
    let response = client
        .begin_card_setup(BeginCardSetupRequest {
            org_id,
            auto_top_up_enabled: choice.auto_top_up_enabled,
            auto_top_up_cents: choice.auto_top_up_cents,
            credit_cents: choice.credit_cents.unwrap_or_default(),
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response.client_secret)
}

/// What finishing a card setup did.
pub(crate) struct CardSetupDone {
    pub(crate) settlement: CardSetupSettlement,
    /// How the credit chosen ended, when there was one.
    pub(crate) credit: Option<AddCreditResponse>,
    /// The top-up setting billing saved.
    pub(crate) auto_top_up_enabled: bool,
}

pub(crate) async fn finish_card_setup(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    setup_intent_id: String,
) -> Result<CardSetupDone, ConnectError> {
    // Settling can charge the card through several Stripe calls.
    let client = BillingServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(ADD_CREDIT_TIMEOUT),
    );
    let response = client
        .finish_card_setup(FinishCardSetupRequest {
            org_id,
            setup_intent_id,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(CardSetupDone {
        settlement: response
            .settlement
            .as_known()
            .unwrap_or(CardSetupSettlement::Unspecified),
        credit: response.credit.into_option(),
        auto_top_up_enabled: response.auto_top_up_enabled,
    })
}

pub(crate) async fn set_default_card(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    payment_method_id: String,
) -> Result<(), ConnectError> {
    client(state, cookie)
        .set_default_payment_method(SetDefaultPaymentMethodRequest {
            org_id,
            payment_method_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn remove_card(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    payment_method_id: String,
) -> Result<(), ConnectError> {
    client(state, cookie)
        .remove_payment_method(RemovePaymentMethodRequest {
            org_id,
            payment_method_id,
            ..Default::default()
        })
        .await?;
    Ok(())
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

/// Buys a one-time amount of credit, in cents. `return_url` is the Billing
/// page Stripe's payment page returns to, without its query.
pub(crate) async fn add_credit(
    state: &AppState,
    cookie: HeaderValue,
    org_id: String,
    amount_cents: i32,
    request_id: String,
    return_url: &str,
) -> Result<AddCreditResponse, ConnectError> {
    let client = BillingServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(ADD_CREDIT_TIMEOUT),
    );
    Ok(client
        .add_credit(AddCreditRequest {
            org_id,
            amount_cents,
            request_id,
            success_url: format!("{return_url}?message=credit-paid&amount={amount_cents}"),
            cancel_url: format!("{return_url}?error=credit-cancelled"),
            ..Default::default()
        })
        .await?
        .into_owned())
}

/// A top-up amount in whole euros, or with cents when it has them.
pub(crate) fn top_up_euros(cents: i32) -> String {
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
            support_mailto: String::new(),
            updates_enabled: false,
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
            joined: String::new(),
            only_owner: false,
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

    fn credit_view(has_payment_method: bool) -> BillingPageView {
        BillingPageView {
            billing_enabled: true,
            can_manage: true,
            has_payment_method,
            cards_available: true,
            card_key: "pk_test_synthetic".into(),
            credit_balance: "€4.20".into(),
            auto_top_up_enabled: true,
            auto_top_up_euros: "20".into(),
            top_up_choices: top_up_choices(2000),
            add_credit_request: "add-credit-request-synthetic".into(),
            csrf_token: "csrf".into(),
            ..Default::default()
        }
    }

    /// One of the page's parts, from its opening tag to the next `</section>`.
    fn part<'a>(body: &'a str, opening: &str) -> &'a str {
        let start = body.find(opening).unwrap_or_else(|| panic!("{opening}"));
        let end = start + body[start..].find("</section>").unwrap();
        &body[start..end]
    }

    #[test]
    fn billing_reads_balance_cards_top_up_add_credit_then_invoices() {
        let body = render(&BillingPageView {
            runway: "About 2 days at current use".into(),
            ..credit_view(true)
        });
        let order: Vec<usize> = [
            r#"<header class="cw-balance-head" aria-label="Compute credit">"#,
            r#"<h2 id="payment-methods-heading" class="cw-section-title">Payment methods</h2>"#,
            r#"<h2 id="top-up-heading" class="cw-section-title">Automatic top-up</h2>"#,
            r#"<h2 id="add-credit-heading" class="cw-section-title">Add credit</h2>"#,
            r#"<h2 id="invoices-heading" class="cw-section-title">Invoices</h2>"#,
            r#"<h2 id="usage-heading" class="cw-section-title">Sandbox Usage</h2>"#,
        ]
        .iter()
        .map(|part| body.find(part).unwrap_or_else(|| panic!("{part}")))
        .collect();
        assert!(order.is_sorted(), "{order:?}");
        assert!(body.contains(r#"<p class="cw-balance">€4.20</p>"#));
        assert!(body.contains(r#"<p class="cw-muted">About 2 days at current use</p>"#));
        // Add card is the page's first action, at primary weight.
        assert!(body.contains(
            r#"<button class="cw-button" type="button" data-dialog-open="add-card-dialog">Add card</button>"#
        ));
        // The stack re-renders itself when the credit changes (#4762).
        assert!(body.contains(
            r#"hx-get="/test/_fragments/billing" hx-trigger="codewire:live:credit from:body, codewire:live:resync from:body""#
        ));
        // No plan, seat or trial language is left, and no hosted setup.
        for retired in [
            "Plan",
            "trial",
            "Trial",
            "seat",
            "_actions/setup",
            "_actions/portal",
            "Manage in Stripe",
        ] {
            assert!(!body.contains(retired), "{retired}");
        }
    }

    #[test]
    fn automatic_top_up_is_one_line_with_its_card_and_amount() {
        let mut view = credit_view(true);
        view.default_card = "Visa •••• 4242".into();
        let on = render(&view);
        let line = part(
            &on,
            r#"<section class="cw-section" aria-labelledby="top-up-heading">"#,
        );
        assert!(line.contains(r#"action="/test/billing/_actions/auto-top-up""#));
        assert!(line.contains(
            r#"<input class="cw-switch" type="checkbox" role="switch" id="top-up-enabled" name="enabled" value="true" aria-describedby="top-up-help" data-submit-on-change checked>"#
        ));
        assert!(line.contains("Charge Visa •••• 4242 when the balance reaches €0"));
        assert!(
            line.contains(
                r#"aria-label="About automatic top-up" data-field-help-trigger>i</button>"#
            )
        );
        for (euros, selected) in [("10", ""), ("20", " selected"), ("50", ""), ("100", "")] {
            assert!(
                line.contains(&format!(
                    r#"<option value="{euros}"{selected}>€{euros}</option>"#
                )),
                "{euros}"
            );
        }
        // No card yet: the setting shows, ready for the first card, and its
        // help says saving one charges at once when the balance is empty.
        let mut none = credit_view(false);
        none.balance_empty = true;
        none.credit_balance = "€0.00".into();
        let none = render(&none);
        let line = part(
            &none,
            r#"<section class="cw-section" aria-labelledby="top-up-heading">"#,
        );
        assert!(line.contains("Charge your card when the balance reaches €0"));
        assert!(line.contains("Starts when you save a card. With the balance at €0.00, saving the card charges €20 at once."));
        assert!(!line.contains("disabled"));
        // An amount of its own is offered beside the presets.
        let choices = top_up_choices(2_500);
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.euros.as_str())
                .collect::<Vec<_>>(),
            ["10", "20", "25", "50", "100"]
        );
        assert!(choices[2].selected);
    }

    #[test]
    fn add_card_names_the_charge_only_when_the_balance_is_empty() {
        let mut empty = credit_view(false);
        empty.balance_empty = true;
        empty.credit_balance = "€0.00".into();
        let body = render(&empty);
        let dialog = &body[body
            .find(r#"<dialog class="cw-dialog" id="add-card-dialog""#)
            .unwrap()..];
        let dialog = &dialog[..dialog.find("</dialog>").unwrap()];
        assert!(dialog.contains(r#"<div class="cw-card-element" data-card-element></div>"#));
        assert!(dialog.contains(
            r#"<input class="cw-switch" type="checkbox" role="switch" id="add-card-top-up" name="top_up" value="true" checked"#
        ));
        assert!(dialog.contains("<strong>Your balance is €0.00, so saving charges"));
        assert!(dialog.contains(r#"data-card-submit data-card-pays>Save card</button>"#));
        let funded = render(&credit_view(true));
        let dialog = &funded[funded.find(r#"id="add-card-dialog""#).unwrap()..];
        let dialog = &dialog[..dialog.find("</dialog>").unwrap()];
        assert!(dialog.contains("Nothing is charged now."));
        assert!(dialog.contains(r#"data-card-submit>Save card</button>"#));
        // The card form's script, its endpoints and Stripe.js's address; the
        // script fetches Stripe only once a card form opens.
        assert!(
            funded
                .contains(r#"<script src="/assets/codewire/billing-cards-v1.js" defer></script>"#)
        );
        assert!(funded.contains(r#"data-card-begin="/test/billing/_actions/card-setup""#));
        // The key the form mounts with, before any SetupIntent exists.
        assert!(funded.contains(r#"data-card-key="pk_test_synthetic""#));
        assert!(funded.contains(r#"data-card-finish="/test/billing/_actions/card-setup/finish""#));
        assert!(!funded.contains(r#"<script src="https://js.stripe.com"#));
    }

    #[test]
    fn add_credit_offers_chips_other_and_pay() {
        let body = render(&credit_view(true));
        let add = part(
            &body,
            r#"<section class="cw-section" aria-labelledby="add-credit-heading">"#,
        );
        assert!(add.contains(
            r#"<form class="cw-add-credit" method="post" action="/test/billing/_actions/add-credit" aria-labelledby="add-credit-heading" data-add-credit>"#
        ));
        assert!(add.contains(
            r#"<input type="hidden" name="request" value="add-credit-request-synthetic">"#
        ));
        for (value, checked) in [("50", ""), ("100", " checked"), ("250", ""), ("500", "")] {
            assert!(add.contains(&format!(
                r#"<label class="cw-toggle-chip"><input class="cw-radio" type="radio" name="choice" value="{value}"{checked}><span>€{value}</span></label>"#
            )), "{value}");
        }
        assert!(add.contains(r#"placeholder="Other €" data-add-credit-other>"#));
        // Without script the button says what it does without an amount.
        assert!(add.contains(
            r#"<button class="cw-button" type="submit" data-add-credit-submit>Pay</button>"#
        ));
        assert!(!add.contains("data-card-form"));
        // With no card yet, Stripe's form opens under it in the page.
        let none = render(&credit_view(false));
        let add = part(
            &none,
            r#"<section class="cw-section" aria-labelledby="add-credit-heading">"#,
        );
        assert!(add.contains(r#"data-add-credit data-add-credit-new-card="add-credit-card">"#));
        assert!(
            add.contains(
                r#"<div class="cw-card-form" id="add-credit-card" data-card-form hidden>"#
            )
        );
        assert!(add.contains("The card is saved for next time."));
    }

    #[test]
    fn add_credit_and_cards_are_only_for_those_who_manage_a_charged_organization() {
        for (name, view) in [
            (
                "member",
                BillingPageView {
                    can_manage: false,
                    ..credit_view(true)
                },
            ),
            (
                "unmetered",
                BillingPageView {
                    unmetered: true,
                    ..credit_view(true)
                },
            ),
            (
                "billing off",
                BillingPageView {
                    billing_enabled: false,
                    ..credit_view(true)
                },
            ),
        ] {
            let body = render(&view);
            assert!(!body.contains("add-credit"), "{name}");
            assert!(!body.contains("auto-top-up"), "{name}");
        }
        let member = render(&BillingPageView {
            can_manage: false,
            ..credit_view(true)
        });
        assert!(!member.contains("add-card-dialog"));
        assert!(!member.contains("billing-cards-v1.js"));
        assert!(member.contains("No card yet. An owner or admin can add one."));
        let unmetered = render(&BillingPageView {
            unmetered: true,
            ..credit_view(true)
        });
        assert!(unmetered.contains("not charged for compute"));
        assert!(!unmetered.contains("cw-balance-head"));
    }

    fn card(brand: &str, exp_month: i32, exp_year: i32) -> PaymentCardView {
        PaymentCardView::new(
            &codewire_proto::codewire::console::v1::PaymentCard {
                brand: brand.into(),
                last4: "4242".into(),
                exp_month,
                exp_year,
                ..Default::default()
            },
            chrono::NaiveDate::from_ymd_opt(2026, 11, 11).unwrap(),
        )
    }

    #[test]
    fn a_card_reads_by_brand_and_expires_after_its_month() {
        assert_eq!(
            card("visa", 11, 2026),
            PaymentCardView {
                brand: "Visa",
                last4: "4242".into(),
                expiry: "11/2026".into(),
                expired: false,
            }
        );
        assert!(card("visa", 10, 2026).expired);
        assert!(card("visa", 12, 2025).expired);
        assert!(!card("visa", 1, 2027).expired);
        assert_eq!(card("mastercard", 3, 2030).expiry, "03/2030");
        for (code, name) in [
            ("amex", "American Express"),
            ("mastercard", "Mastercard"),
            ("diners", "Diners Club"),
            ("unionpay", "UnionPay"),
            ("unknown", "Card"),
            ("", "Card"),
            ("<visa>", "Card"),
        ] {
            assert_eq!(card_brand_name(code), name, "{code}");
        }
    }

    fn saved(id: &str, brand: &str, last4: &str, default: bool, index: usize) -> SavedCardView {
        SavedCardView::new(
            &SavedPaymentMethod {
                id: id.into(),
                card: codewire_proto::codewire::console::v1::PaymentCard {
                    brand: brand.into(),
                    last4: last4.into(),
                    exp_month: 8,
                    exp_year: 2028,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            },
            if default { id } else { "" },
            index,
            chrono::NaiveDate::from_ymd_opt(2026, 11, 11).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn saved_cards_show_the_default_and_a_menu_to_change_or_remove_one() {
        let billing = BillingPageView {
            cards: vec![
                saved("pm_visa", "visa", "4242", true, 0),
                saved("pm_mc", "mastercard", "5454", false, 1),
            ],
            default_card: "Visa •••• 4242".into(),
            ..credit_view(true)
        };
        let body = render(&billing);
        let list = part(
            &body,
            r#"<section class="cw-section" aria-labelledby="payment-methods-heading">"#,
        );
        assert!(list.contains(
            r#"<p class="cw-badge-row"><strong>Visa</strong> <span class="cw-mono"><span aria-hidden="true">•••• </span><span class="cw-sr-only">ending in </span>4242</span><span class="cw-badge" data-tone="info">Default</span></p>"#
        ));
        assert!(list.contains(r#"<p class="cw-muted">Expires 08/2028</p>"#));
        assert!(list.contains(r#"aria-label="Actions for Visa ending in 4242""#));
        // Make default is offered only for a card that isn't the default.
        assert_eq!(list.matches(">Make default</button>").count(), 1);
        assert!(list.contains(r#"<input type="hidden" name="payment_method" value="pm_mc"><button class="cw-menu-item" type="submit" role="menuitem">Make default</button>"#));
        assert!(list.contains(r#"action="/test/billing/_actions/cards/default""#));
        // Removing says what changes.
        assert!(list.contains(r#"<h2 id="remove-card-0-title">Remove Visa •••• 4242?</h2>"#));
        assert!(list.contains(
            "It's your default card. Your most recently added other card becomes the default"
        ));
        assert!(list.contains(r#"action="/test/billing/_actions/cards/remove""#));
        let only = render(&BillingPageView {
            cards: vec![saved("pm_visa", "visa", "4242", true, 0)],
            ..credit_view(true)
        });
        assert!(only.contains("Automatic top-up stops until you add another card."));
        // A member sees the cards and no actions.
        let member = render(&BillingPageView {
            can_manage: false,
            ..billing
        });
        let list = part(
            &member,
            r#"<section class="cw-section" aria-labelledby="payment-methods-heading">"#,
        );
        assert!(list.contains("4242"));
        assert!(!list.contains("<button") && !list.contains("<form"));
        // Billing couldn't list them: said, and Add card still works.
        let down = render(&BillingPageView {
            cards_available: false,
            ..credit_view(true)
        });
        assert!(
            down.contains("Saved cards are temporarily unavailable. Adding a card still works.")
        );
        assert!(down.contains(r#"data-dialog-open="add-card-dialog""#));
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
                public_origin: "https://codewire.sh".into(),
                analytics: None,
                signup_credit: signup_credit.map(str::to_owned),
                rates: Some(crate::public_rates::fixture_rates()),
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
                cards_available: true,
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
            assert!(body.contains("/test/billing/_actions/card-setup"), "{name}");
            assert!(!body.contains("upstream-sensitive-detail"), "{name}");
        }
    }

    /// Billing's per-address card-setup cap counts the hop the dashboard sends
    /// (#4901): the page request's last hop, which the edge wrote, as the
    /// call's only `X-Forwarded-For`, on BeginCardSetup and no other call.
    #[tokio::test]
    async fn only_begin_card_setup_carries_the_edge_hop_never_the_browser_chain() {
        use std::sync::{Arc, Mutex};

        use axum::{Router, body::Body, http::header, response::Response, routing::any};
        use buffa::Message as _;
        use codewire_proto::codewire::console::v1::BeginCardSetupResponse;

        type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;
        let seen: Seen = Arc::default();
        let captured = seen.clone();
        let router = Router::new().fallback(any(move |request: axum::extract::Request| {
            let captured = captured.clone();
            async move {
                let path = request.uri().path().to_owned();
                let forwarded = request
                    .headers()
                    .get_all("x-forwarded-for")
                    .iter()
                    .map(|value| value.to_str().unwrap().to_owned())
                    .reduce(|all, next| format!("{all} | {next}"));
                captured.lock().unwrap().push((path.clone(), forwarded));
                let body = if path.ends_with("/BeginCardSetup") {
                    BeginCardSetupResponse {
                        client_secret: "seti_synthetic_secret".into(),
                        ..Default::default()
                    }
                    .encode_to_vec()
                } else {
                    Vec::new()
                };
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/proto")
                    .body(Body::from(body))
                    .unwrap()
            }
        }));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let state = AppState::new(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: origin.parse().unwrap(),
            credential_origin: origin.parse().unwrap(),
            identity_origin_string: origin.clone(),
            browser_api_origin: origin.clone(),
            billing_origin: origin.parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
            support_email: None,
            updates_site: None,
            analytics: None,
        });
        let cookie = HeaderValue::from_static("codewire.session_token=synthetic");
        // The browser wrote its own entries; the edge appended the last one.
        let mut page = axum::http::HeaderMap::new();
        page.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.66, 192.0.2.1, 203.0.113.7"),
        );
        let hop = codewire_server_core::client_address::forwarded_client_hop(&page);
        let choice = || CardSetupChoice {
            auto_top_up_enabled: true,
            auto_top_up_cents: 2_000,
            credit_cents: None,
        };
        let secret = begin_card_setup(&state, cookie.clone(), hop, "org-1".into(), choice())
            .await
            .unwrap();
        assert_eq!(secret, "seti_synthetic_secret");
        // No hop at all sends none, for billing to refuse.
        begin_card_setup(&state, cookie.clone(), None, "org-1".into(), choice())
            .await
            .unwrap();
        set_default_card(&state, cookie, "org-1".into(), "pm_1".into())
            .await
            .unwrap();
        server.abort();

        let seen = seen.lock().unwrap();
        let begin = "/codewire.console.v1.BillingService/BeginCardSetup";
        assert_eq!(
            *seen,
            [
                (begin.to_owned(), Some("203.0.113.7".to_owned())),
                (begin.to_owned(), None),
                (
                    "/codewire.console.v1.BillingService/SetDefaultPaymentMethod".to_owned(),
                    None
                ),
            ]
        );
    }
}
