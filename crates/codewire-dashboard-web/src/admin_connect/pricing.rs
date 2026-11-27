//! The admin Pricing page's rate cards (docs/dev/BILLING.md "Prices",
//! #5782): reading them, saving one card's rates, and the euro amounts the
//! page shows and reads back.

use axum::http::HeaderValue;
use codewire_admin_proto::codewire::admin::v1::{
    ListRateCardsRequest, RateCard, UpdateRateCardRequest,
};
use connectrpc::ConnectError;

use super::{bounded, catalog_client};
use crate::{state::AppState, time_display::calendar_datetime};

/// The most a rate may be: EUR 10 a unit-hour. It mirrors
/// `codewire_billing::catalog_admin::MAX_RATE_NANO_EUR_PER_UNIT_HOUR`, which
/// the call and the database enforce; the dashboard does not depend on that
/// crate.
pub(crate) const MAX_RATE_NANO_EUR: i64 = 10_000_000_000;
const NANO_EUR_PER_EURO: i64 = 1_000_000_000;
/// The card that is never charged; the call refuses any rate above 0 on it.
const UNLIMITED: &str = "unlimited";

/// One of a card's four rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rate {
    Cpu,
    Memory,
    Disk,
    Storage,
}

impl Rate {
    pub(crate) const ALL: [Self; 4] = [Self::Cpu, Self::Memory, Self::Disk, Self::Storage];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Cpu => "vCPU, per hour",
            Self::Memory => "Memory, per GiB-hour",
            Self::Disk => "Disk, per GiB-hour",
            Self::Storage => "Storage while suspended or hibernated, per GiB-hour",
        }
    }

    /// The form field that carries it.
    pub(crate) fn field(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Disk => "disk",
            Self::Storage => "storage",
        }
    }
}

/// A card's four rates, in nano-euros per unit-hour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rates {
    pub(crate) cpu: i64,
    pub(crate) memory: i64,
    pub(crate) disk: i64,
    pub(crate) storage: i64,
}

impl Rates {
    pub(crate) fn get(self, rate: Rate) -> i64 {
        match rate {
            Rate::Cpu => self.cpu,
            Rate::Memory => self.memory,
            Rate::Disk => self.disk,
            Rate::Storage => self.storage,
        }
    }

    /// Every rate is one a card may hold.
    pub(crate) fn valid(self) -> bool {
        Rate::ALL
            .into_iter()
            .all(|rate| (0..=MAX_RATE_NANO_EUR).contains(&self.get(rate)))
    }
}

/// A card's `updated_at` exactly as the server sent it, which the page sends
/// back as `expected_updated_at` so a save from a stale read is refused.
/// Written `<seconds>.<nine-digit nanoseconds>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CardVersion {
    seconds: i64,
    nanos: i32,
}

impl CardVersion {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (seconds, nanos) = text.split_once('.')?;
        if !(1..=19).contains(&seconds.len())
            || nanos.len() != 9
            || !seconds
                .bytes()
                .chain(nanos.bytes())
                .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        Some(Self {
            seconds: seconds.parse().ok()?,
            nanos: nanos.parse().ok()?,
        })
    }

    pub(crate) fn token(self) -> String {
        format!("{}.{:09}", self.seconds, self.nanos)
    }

    /// As the dashboard shows a time.
    pub(crate) fn display(self) -> String {
        calendar_datetime(self.seconds)
    }

    /// RFC 3339, for a `<time>` element.
    pub(crate) fn datetime(self) -> String {
        chrono::DateTime::from_timestamp(self.seconds, 0)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default()
    }
}

/// One rate's input, or its line on Unlimited.
#[derive(Debug)]
pub(crate) struct RateFieldView {
    pub(crate) field: &'static str,
    pub(crate) label: &'static str,
    /// In euros: as stored, or as the administrator typed it.
    pub(crate) value: String,
    pub(crate) invalid: bool,
}

/// One rate card as the page shows it.
#[derive(Debug)]
pub(crate) struct RateCardView {
    pub(crate) rate_card: String,
    pub(crate) display_name: String,
    pub(crate) version: CardVersion,
    /// As stored: what the review compares the new rates with.
    pub(crate) rates: Rates,
    pub(crate) fields: Vec<RateFieldView>,
}

impl RateCardView {
    pub(crate) fn new(
        rate_card: String,
        display_name: String,
        version: CardVersion,
        rates: Rates,
    ) -> Self {
        let fields = Rate::ALL
            .into_iter()
            .map(|rate| RateFieldView {
                field: rate.field(),
                label: rate.label(),
                value: rate_euros(rates.get(rate)),
                invalid: false,
            })
            .collect();
        Self {
            rate_card,
            display_name,
            version,
            rates,
            fields,
        }
    }

    /// Unlimited is never charged, so it has no form.
    pub(crate) fn charged(&self) -> bool {
        self.rate_card != UNLIMITED
    }

    pub(crate) fn version_token(&self) -> String {
        self.version.token()
    }

    pub(crate) fn updated(&self) -> String {
        self.version.display()
    }

    pub(crate) fn updated_at(&self) -> String {
        self.version.datetime()
    }
}

/// One changed rate in a review.
#[derive(Debug)]
pub(crate) struct PriceChangeView {
    pub(crate) label: &'static str,
    pub(crate) now: String,
    pub(crate) new: String,
    /// More than double, or up from 0: saving it needs the confirmation.
    pub(crate) large: bool,
}

/// A card's new rates beside its current ones, before they are saved.
#[derive(Debug)]
pub(crate) struct PriceReviewView {
    pub(crate) rate_card: String,
    pub(crate) display_name: String,
    pub(crate) version: CardVersion,
    pub(crate) new: Rates,
    pub(crate) changes: Vec<PriceChangeView>,
}

impl PriceReviewView {
    /// The review of `new` against `card`'s rates, or `None` when nothing
    /// changed.
    pub(crate) fn new(card: &RateCardView, new: Rates) -> Option<Self> {
        let changes: Vec<_> = Rate::ALL
            .into_iter()
            .filter(|rate| card.rates.get(*rate) != new.get(*rate))
            .map(|rate| PriceChangeView {
                label: rate.label(),
                now: format!("${}", rate_euros(card.rates.get(rate))),
                new: format!("${}", rate_euros(new.get(rate))),
                large: large_increase(card.rates.get(rate), new.get(rate)),
            })
            .collect();
        (!changes.is_empty()).then(|| Self {
            rate_card: card.rate_card.clone(),
            display_name: card.display_name.clone(),
            version: card.version,
            new,
            changes,
        })
    }

    pub(crate) fn needs_confirmation(&self) -> bool {
        self.changes.iter().any(|change| change.large)
    }

    pub(crate) fn version_token(&self) -> String {
        self.version.token()
    }

    /// The hidden fields that carry the new rates, in nano-euros.
    pub(crate) fn new_fields(&self) -> Vec<(&'static str, i64)> {
        Rate::ALL
            .into_iter()
            .map(|rate| (rate.field(), self.new.get(rate)))
            .collect()
    }
}

/// More than double, which includes any rise from 0.
pub(crate) fn large_increase(now: i64, new: i64) -> bool {
    new > now.saturating_mul(2)
}

/// Any rate of `new` that is a large increase on `now`'s.
pub(crate) fn has_large_increase(now: Rates, new: Rates) -> bool {
    Rate::ALL
        .into_iter()
        .any(|rate| large_increase(now.get(rate), new.get(rate)))
}

/// What the Pricing page shows.
#[derive(Debug, Default)]
pub(crate) struct PricingPageView {
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
    /// The cards could not be read, so there is nothing to edit.
    pub(crate) unavailable: bool,
    pub(crate) cards: Vec<RateCardView>,
    pub(crate) review: Option<PriceReviewView>,
}

/// Every rate card, Regular first and Unlimited last; the call returns them
/// in key order.
pub(crate) async fn rate_cards(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<RateCardView>, ConnectError> {
    let response = catalog_client(state, cookie)
        .list_rate_cards(ListRateCardsRequest::default())
        .await?
        .into_owned();
    let mut cards: Vec<_> = response.rate_cards.into_iter().map(card_view).collect();
    cards.sort_by_key(|card| card_rank(&card.rate_card));
    Ok(cards)
}

fn card_rank(rate_card: &str) -> u8 {
    match rate_card {
        "regular" => 0,
        "discounted" => 1,
        UNLIMITED => 3,
        _ => 2,
    }
}

/// Save one card's rates, unless it changed since `version`.
pub(crate) async fn update_rate_card(
    state: &AppState,
    cookie: HeaderValue,
    rate_card: String,
    rates: Rates,
    version: CardVersion,
) -> Result<(), ConnectError> {
    let mut request = UpdateRateCardRequest {
        rate_card,
        cpu_nano_eur_per_vcpu_hour: rates.cpu,
        memory_nano_eur_per_gib_hour: rates.memory,
        disk_nano_eur_per_gib_hour: rates.disk,
        parked_storage_nano_eur_per_gib_hour: rates.storage,
        ..Default::default()
    };
    let expected = request.expected_updated_at.get_or_insert_default();
    expected.seconds = version.seconds;
    expected.nanos = version.nanos;
    catalog_client(state, cookie)
        .update_rate_card(request)
        .await?;
    Ok(())
}

fn card_view(card: RateCard) -> RateCardView {
    let version = card
        .updated_at
        .into_option()
        .map(|value| CardVersion {
            seconds: value.seconds,
            nanos: value.nanos,
        })
        .unwrap_or(CardVersion {
            seconds: 0,
            nanos: 0,
        });
    RateCardView::new(
        card.rate_card,
        bounded(card.display_name, 128),
        version,
        Rates {
            cpu: card.cpu_nano_eur_per_vcpu_hour,
            memory: card.memory_nano_eur_per_gib_hour,
            disk: card.disk_nano_eur_per_gib_hour,
            storage: card.parked_storage_nano_eur_per_gib_hour,
        },
    )
}

/// A nano-euro rate in euros, exactly, with no trailing zeros: 43,800,000
/// is "0.0438" and 0 is "0". The inverse of [`rate_nano`].
pub(crate) fn rate_euros(nano_eur: i64) -> String {
    let sign = if nano_eur < 0 { "-" } else { "" };
    let magnitude = nano_eur.unsigned_abs();
    let whole = magnitude / NANO_EUR_PER_EURO.unsigned_abs();
    let fraction = format!("{:09}", magnitude % NANO_EUR_PER_EURO.unsigned_abs());
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{fraction}")
    }
}

/// An administrator's euro rate ("0.0438", "€ 1", "10.000000000") in
/// nano-euros, exactly: an optional leading "€", surrounding spaces, digits,
/// and at most one "." followed by at most nine digits, from 0 to
/// [`MAX_RATE_NANO_EUR`]. Anything else is `None`.
pub(crate) fn rate_nano(text: &str) -> Option<i64> {
    let text = text.trim();
    let text = text
        .strip_prefix('$')
        .or_else(|| text.strip_prefix('€'))
        .unwrap_or(text)
        .trim_start();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return None,
        None => (text, ""),
    };
    if whole.is_empty()
        || whole.len() > 9
        || fraction.len() > 9
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let nano = whole
        .parse::<i64>()
        .ok()?
        .checked_mul(NANO_EUR_PER_EURO)?
        .checked_add(format!("{fraction:0<9}").parse::<i64>().ok()?)?;
    (nano <= MAX_RATE_NANO_EUR).then_some(nano)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_comes_first_and_unlimited_last_whatever_the_call_order() {
        let mut keys = vec!["discounted", "regular", "unlimited"];
        keys.sort_by_key(|key| card_rank(key));
        assert_eq!(keys, ["regular", "discounted", "unlimited"]);
    }

    #[test]
    fn euro_rates_read_exactly_from_0_to_10() {
        for (text, nano) in [
            ("0", 0),
            ("0.0", 0),
            ("€0", 0),
            (" € 0.0438 ", 43_800_000),
            ("0.000000001", 1),
            ("0.123456789", 123_456_789),
            ("10", MAX_RATE_NANO_EUR),
            ("10.000000000", MAX_RATE_NANO_EUR),
            ("9.999999999", MAX_RATE_NANO_EUR - 1),
            ("007", 7_000_000_000),
        ] {
            assert_eq!(rate_nano(text), Some(nano), "{text:?}");
        }
        for refused in [
            "",
            " ",
            "€",
            ".",
            "1.",
            ".5",
            "10.000000001",
            "10.1",
            "11",
            "0.0000000001",
            "-1",
            "-0",
            "+1",
            "0,0438",
            "1.2.3",
            "1 000",
            "€€1",
            "1€",
            "EUR 1",
            "١",
            "999999999999999999999",
        ] {
            assert_eq!(rate_nano(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn euro_rates_print_exactly_and_read_back() {
        assert_eq!(rate_euros(0), "0");
        assert_eq!(rate_euros(43_800_000), "0.0438");
        assert_eq!(rate_euros(14_100_000), "0.0141");
        assert_eq!(rate_euros(87_000), "0.000087");
        assert_eq!(rate_euros(1), "0.000000001");
        assert_eq!(rate_euros(MAX_RATE_NANO_EUR), "10");
        assert_eq!(rate_euros(2_500_000_000), "2.5");
        assert_eq!(rate_euros(-43_800_000), "-0.0438");
        // Regular's current rates, then every edge, round-trip.
        for nano in [
            43_800_000,
            14_100_000,
            87_000,
            0,
            1,
            123_456_789,
            MAX_RATE_NANO_EUR,
        ] {
            assert_eq!(rate_nano(&rate_euros(nano)), Some(nano), "{nano}");
        }
    }

    #[test]
    fn a_large_increase_more_than_doubles_or_rises_from_zero() {
        assert!(!large_increase(43_800_000, 87_600_000));
        assert!(large_increase(43_800_000, 87_600_001));
        assert!(large_increase(0, 1));
        assert!(!large_increase(0, 0));
        assert!(!large_increase(43_800_000, 0));
        assert!(!large_increase(i64::MAX, i64::MAX));
    }

    #[test]
    fn a_card_version_round_trips_exactly() {
        let version = CardVersion::parse("1795392000.123456000").unwrap();
        assert_eq!(version.token(), "1795392000.123456000");
        assert_eq!(version.datetime(), "2026-11-23T00:00:00Z");
        for refused in ["", "1", "1.1", "a.123456789", "1.12345678a", "-1.000000000"] {
            assert_eq!(CardVersion::parse(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn a_review_lists_only_the_changed_rates() {
        let card = RateCardView::new(
            "regular".into(),
            "Regular".into(),
            CardVersion {
                seconds: 1,
                nanos: 0,
            },
            Rates {
                cpu: 43_800_000,
                memory: 14_100_000,
                disk: 87_000,
                storage: 0,
            },
        );
        assert!(PriceReviewView::new(&card, card.rates).is_none());
        let review = PriceReviewView::new(
            &card,
            Rates {
                cpu: 53_800_000,
                storage: 1,
                ..card.rates
            },
        )
        .unwrap();
        let rows: Vec<_> = review
            .changes
            .iter()
            .map(|change| {
                (
                    change.label,
                    change.now.as_str(),
                    change.new.as_str(),
                    change.large,
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("vCPU, per hour", "$0.0438", "$0.0538", false),
                (
                    "Storage while suspended or hibernated, per GiB-hour",
                    "$0",
                    "$0.000000001",
                    true
                ),
            ]
        );
        assert!(review.needs_confirmation());
    }
}
