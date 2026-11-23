//! Regular's rates on the public pricing page (#5782), read through billing's
//! public `GetPublicRates`. The page never shows a copied number: it shows the
//! last rates billing answered, or none.

use std::{
    future::Future,
    time::{Duration, Instant},
};

use codewire_proto::codewire::console::v1::{BillingServiceClient, GetPublicRatesRequest};
use connectrpc::client::ClientConfig;

use crate::{state::AppState, transport::BrowserTransport};

/// How long the pricing page keeps the rates it read before asking billing
/// again, and how long it waits for billing's answer.
const PUBLIC_RATES_TTL: Duration = Duration::from_secs(60);
const PUBLIC_RATES_TIMEOUT: Duration = Duration::from_secs(1);

const NANO_EUR_PER_EURO: u64 = 1_000_000_000;
const NANO_EUR_PER_CENT: u64 = 10_000_000;

/// The calculator's default size, which the page prices per hour before its
/// script runs: 2 vCPU, 8 GB of memory and 100 GB of disk.
const DEFAULT_CPU: u64 = 2;
const DEFAULT_MEMORY_GB: u64 = 8;
const DEFAULT_DISK_GB: u64 = 100;

/// Regular's running rates, in nano-euros per unit-hour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rates {
    cpu: u64,
    memory: u64,
    disk: u64,
}

/// The one entry the pricing page keeps: when it last asked billing, and the
/// last rates billing answered, if it ever has.
#[derive(Default)]
pub(crate) struct PublicRatesCache(tokio::sync::Mutex<Option<(Instant, Option<Rates>)>>);

impl PublicRatesCache {
    /// The rates to show at `now`. Asks `read` at most once a minute; when it
    /// fails, keeps the last rates it answered.
    async fn rates<F>(&self, now: Instant, read: impl FnOnce() -> F) -> Option<Rates>
    where
        F: Future<Output = Option<Rates>>,
    {
        let mut cached = self.0.lock().await;
        let last = match *cached {
            Some((asked_at, rates)) if now.duration_since(asked_at) < PUBLIC_RATES_TTL => {
                return rates;
            }
            Some((_, rates)) => rates,
            None => None,
        };
        let rates = read().await.or(last);
        *cached = Some((now, rates));
        rates
    }
}

/// Regular's rates for the pricing page, or `None` when billing has never
/// answered since the dashboard started.
pub(crate) async fn public_rates(state: &AppState) -> Option<PricingRatesView> {
    state
        .public_rates
        .rates(Instant::now(), || read(state))
        .await
        .map(PricingRatesView::of)
}

async fn read(state: &AppState) -> Option<Rates> {
    let client = BillingServiceClient::new(
        BrowserTransport {
            http: state.http.clone(),
            cookie: None,
            origin: None,
        },
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(PUBLIC_RATES_TIMEOUT),
    );
    let response = client
        .get_public_rates(GetPublicRatesRequest::default())
        .await
        .ok()?
        .into_owned();
    Some(Rates {
        cpu: u64::try_from(response.cpu_nano_eur_per_vcpu_hour).ok()?,
        memory: u64::try_from(response.memory_nano_eur_per_gib_hour).ok()?,
        disk: u64::try_from(response.disk_nano_eur_per_gib_hour).ok()?,
    })
}

/// Regular's rates as the pricing page shows them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PricingRatesView {
    /// Each rate in euros per unit-hour, exactly, for the calculator
    /// ("0.0438").
    pub(crate) cpu: String,
    pub(crate) memory: String,
    pub(crate) disk: String,
    /// The default size's hourly cost of each resource and their total, as
    /// the calculator writes them ("€0.0876").
    pub(crate) cpu_cost: String,
    pub(crate) memory_cost: String,
    pub(crate) disk_cost: String,
    pub(crate) total: String,
}

impl PricingRatesView {
    fn of(rates: Rates) -> Self {
        let cpu_cost = rates.cpu * DEFAULT_CPU;
        let memory_cost = rates.memory * DEFAULT_MEMORY_GB;
        let disk_cost = rates.disk * DEFAULT_DISK_GB;
        Self {
            cpu: rate_euros(rates.cpu),
            memory: rate_euros(rates.memory),
            disk: rate_euros(rates.disk),
            cpu_cost: cost_text(cpu_cost),
            memory_cost: cost_text(memory_cost),
            disk_cost: cost_text(disk_cost),
            total: cost_text(cpu_cost + memory_cost + disk_cost),
        }
    }
}

/// A rate in euros, exactly, with at least two decimals: "0.0438" for
/// 43,800,000 nano-euros.
fn rate_euros(nano_eur: u64) -> String {
    let fraction = format!("{:09}", nano_eur % NANO_EUR_PER_EURO);
    let fraction = fraction.trim_end_matches('0');
    format!("{}.{fraction:0<2}", nano_eur / NANO_EUR_PER_EURO)
}

/// A cost as `pricing.js` writes it: two decimals from one euro up, and
/// below that four significant digits without trailing zeros.
fn cost_text(nano_eur: u64) -> String {
    if nano_eur >= NANO_EUR_PER_EURO {
        let cents = (nano_eur + NANO_EUR_PER_CENT / 2) / NANO_EUR_PER_CENT;
        return format!("€{}.{:02}", cents / 100, cents % 100);
    }
    if nano_eur == 0 {
        return "€0".into();
    }
    // The fourth significant digit of an amount under €1 is decimal
    // 12 - floor(log10(nano-euros)), from the fourth to the twelfth.
    let decimals = 12 - nano_eur.ilog10();
    let digits = if decimals >= 9 {
        format!("{nano_eur:09}")
    } else {
        let step = 10u64.pow(9 - decimals);
        let rounded = (nano_eur + step / 2) / step;
        if rounded == 10u64.pow(decimals) {
            return "€1".into();
        }
        format!("{rounded:0width$}", width = decimals as usize)
    };
    format!("€0.{}", digits.trim_end_matches('0'))
}

/// The rates the `pricing.html` design fixture shows, as an example.
#[cfg(test)]
pub(crate) fn fixture_rates() -> PricingRatesView {
    PricingRatesView::of(Rates {
        cpu: 43_800_000,
        memory: 14_100_000,
        disk: 87_000,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use codewire_proto::codewire::console::v1::GetPublicRatesResponse;

    use super::*;

    const REGULAR: Rates = Rates {
        cpu: 43_800_000,
        memory: 14_100_000,
        disk: 87_000,
    };
    const RAISED: Rates = Rates {
        cpu: 50_000_000,
        memory: 14_100_000,
        disk: 87_000,
    };

    #[test]
    fn rates_read_exactly_in_euros() {
        assert_eq!(rate_euros(43_800_000), "0.0438");
        assert_eq!(rate_euros(87_000), "0.000087");
        assert_eq!(rate_euros(1), "0.000000001");
        assert_eq!(rate_euros(0), "0.00");
        assert_eq!(rate_euros(10_000_000_000), "10.00");
        assert_eq!(rate_euros(1_250_000_000), "1.25");
    }

    #[test]
    fn costs_read_as_the_calculator_writes_them() {
        assert_eq!(cost_text(87_600_000), "€0.0876");
        assert_eq!(cost_text(112_800_000), "€0.1128");
        assert_eq!(cost_text(8_700_000), "€0.0087");
        assert_eq!(cost_text(209_100_000), "€0.2091");
        assert_eq!(cost_text(123_456_789), "€0.1235");
        assert_eq!(cost_text(87), "€0.000000087");
        assert_eq!(cost_text(999_960_000), "€1");
        assert_eq!(cost_text(298_935_000_000), "€298.94");
        assert_eq!(cost_text(1_005_000_000), "€1.01");
        assert_eq!(cost_text(0), "€0");
    }

    #[test]
    fn the_default_size_is_priced_per_hour() {
        let view = fixture_rates();
        assert_eq!(
            (view.cpu.as_str(), view.memory.as_str(), view.disk.as_str()),
            ("0.0438", "0.0141", "0.000087")
        );
        assert_eq!(
            [view.cpu_cost, view.memory_cost, view.disk_cost, view.total],
            ["€0.0876", "€0.1128", "€0.0087", "€0.2091"]
        );
    }

    /// A read that answers `answer` and counts its calls.
    fn reader(
        calls: &Arc<AtomicUsize>,
        answer: Option<Rates>,
    ) -> impl FnOnce() -> std::future::Ready<Option<Rates>> {
        let calls = calls.clone();
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(answer)
        }
    }

    #[tokio::test]
    async fn the_page_shows_no_rates_until_billing_first_answers() {
        let cache = PublicRatesCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();

        assert_eq!(cache.rates(start, reader(&calls, None)).await, None);
        // A failure is kept for a minute too, so an outage costs billing one
        // call a minute, not one a page view.
        assert_eq!(
            cache
                .rates(
                    start + Duration::from_secs(59),
                    reader(&calls, Some(REGULAR))
                )
                .await,
            None
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            cache
                .rates(start + PUBLIC_RATES_TTL, reader(&calls, Some(REGULAR)))
                .await,
            Some(REGULAR)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_page_keeps_the_last_rates_while_billing_is_down_and_follows_a_change() {
        let cache = PublicRatesCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let minute = |n: u32| start + PUBLIC_RATES_TTL * n;

        assert_eq!(
            cache.rates(start, reader(&calls, Some(REGULAR))).await,
            Some(REGULAR)
        );
        assert_eq!(
            cache
                .rates(
                    start + Duration::from_secs(30),
                    reader(&calls, Some(RAISED))
                )
                .await,
            Some(REGULAR)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for n in 1..=3 {
            assert_eq!(
                cache.rates(minute(n), reader(&calls, None)).await,
                Some(REGULAR)
            );
        }
        assert_eq!(
            cache.rates(minute(4), reader(&calls, Some(RAISED))).await,
            Some(RAISED)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    /// The pricing page from a dashboard whose billing answers
    /// `GetPublicRates` with `answer`, or with 503 when it is `None`.
    async fn pricing_page(answer: Option<GetPublicRatesResponse>) -> String {
        use axum::{Router, http::header, response::IntoResponse as _, routing::any};
        use buffa::Message as _;

        async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            (origin, task)
        }

        let billing = Router::new().fallback(any(move |request: axum::extract::Request| {
            let answer = answer.clone();
            async move {
                match answer {
                    Some(rates) if request.uri().path().ends_with("/GetPublicRates") => (
                        [(header::CONTENT_TYPE, "application/proto")],
                        rates.encode_to_vec(),
                    )
                        .into_response(),
                    _ => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            }
        }));
        let (billing_origin, billing_task) = serve(billing).await;
        let mut config = crate::test_support::unreachable_config();
        config.billing_origin = billing_origin.parse().unwrap();
        let (dashboard, dashboard_task) = serve(crate::app(config)).await;
        let html = reqwest::Client::builder()
            .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
            .build()
            .unwrap()
            .get(format!("{dashboard}/pricing"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        dashboard_task.abort();
        billing_task.abort();
        html
    }

    #[tokio::test]
    async fn the_pricing_page_shows_billings_rates_or_none() {
        let html = pricing_page(Some(GetPublicRatesResponse {
            cpu_nano_eur_per_vcpu_hour: 50_000_000,
            memory_nano_eur_per_gib_hour: 14_100_000,
            disk_nano_eur_per_gib_hour: 87_000,
            ..Default::default()
        }))
        .await;
        assert!(html.contains(
            r#"data-rate-cpu="0.05" data-rate-memory="0.0141" data-rate-disk="0.000087""#
        ));
        assert!(html.contains("€0.05 per vCPU-hour"));
        assert!(html.contains(r#"data-pricing-cost="total">€0.2215</output>"#));
        assert!(!html.contains("Prices can’t be shown right now."));

        let html = pricing_page(None).await;
        assert!(html.contains("<p class=\"copy\">Prices can’t be shown right now.</p>"));
        for price in ["data-pricing-estimator", "per vCPU-hour", "€0."] {
            assert!(!html.contains(price), "{price}");
        }
    }
}
