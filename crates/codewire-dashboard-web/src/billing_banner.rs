//! What the console says about an organization's credit: the banner across
//! the top of its pages, and whether Create Sandbox can run in the cloud.
//! Everything here is a pure function of the billing overview, the
//! organization's Sandboxes and the time, so each state is tested without a
//! billing service.

use crate::{
    admin_connect::{NANO_EUR_PER_CENT, euro_text},
    time_display::calendar_datetime,
    view::EnvironmentRow,
};

/// Running Sandboxes of an organization that ran out of credit stop this long
/// after it ran out (`CREDIT_EXHAUSTED_GRACE_HOURS` in orchestration).
const STOP_AFTER_SECONDS: i64 = 24 * 3_600;
/// Credit that lasts less than this many hours at the current rate is low.
const LOW_HOURS: i128 = 24;
/// Credit under $5 is low whatever runs, as for the low-credit email
/// (`credit_notices_due` in billing).
const LOW_BALANCE_NANO_EUR: i64 = 500 * NANO_EUR_PER_CENT;
/// How a member reads the card, whose brand and last four only owners and
/// admins see.
const SAVED_CARD: &str = "the saved card";
/// Millicores per vCPU times MiB per GiB: a size times a rate per hour, over
/// this, is nano-euros per hour (`usage_nano_eur` in billing).
const SIZE_DENOMINATOR: i128 = 1_000 * 1_024;
const SECONDS_PER_DAY: i64 = 86_400;

/// The billing overview's facts the console acts on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CreditFacts {
    pub(crate) balance_nano_eur: i64,
    pub(crate) has_card: bool,
    /// The default card as it reads, such as "Visa •••• 4242".
    pub(crate) card: Option<String>,
    pub(crate) auto_top_up: bool,
    pub(crate) auto_top_up_cents: i32,
    /// What automatic top-up is charging while the organization is out of
    /// credit; 0 when nothing is.
    pub(crate) top_up_charging_cents: i32,
    /// This deployment refuses work and charges cards for credit.
    pub(crate) enforced: bool,
    pub(crate) billing_enabled: bool,
    pub(crate) unmetered: bool,
    pub(crate) cpu_nano_eur_per_vcpu_hour: i64,
    pub(crate) memory_nano_eur_per_gib_hour: i64,
    pub(crate) disk_nano_eur_per_gib_hour: i64,
    /// When the organization ran out, in Unix seconds. Billing reports it
    /// from the live balance, and only while it enforces credit, so it means
    /// creates and starts are refused.
    pub(crate) exhausted_at: Option<i64>,
}

impl CreditFacts {
    /// Credit is drawn, and running out of it matters.
    fn metered(&self) -> bool {
        self.billing_enabled && !self.unmetered && self.enforced
    }

    /// A card with automatic top-up refills the balance when it reaches $0.
    fn tops_up(&self) -> bool {
        self.has_card && self.auto_top_up
    }

    /// Credit that can run low: metered, and some left.
    fn can_run_low(&self) -> bool {
        self.metered() && self.balance_nano_eur > 0
    }

    /// When the organization ran out, while it is out: billing's report,
    /// unless the balance shows credit came back since (#4758). A positive
    /// balance is never out of credit, as orchestration admits creates on it.
    fn out_of_credit_since(&self) -> Option<i64> {
        self.exhausted_at.filter(|_| self.balance_nano_eur <= 0)
    }

    /// The banner needs the organization's Sandboxes only when it may show.
    pub(crate) fn banner_needs_sandboxes(&self) -> bool {
        self.out_of_credit_since().is_some() || self.can_run_low()
    }

    /// Create Sandbox in the cloud is refused: the organization ran out.
    pub(crate) fn create_refusal(&self) -> Option<CreditRefusal> {
        self.out_of_credit_since().map(|_| CreditRefusal {
            has_card: self.has_card,
            top_up_charging: self.top_up_charging_cents > 0,
        })
    }
}

/// A Sandbox's size and whether it is running, the only things its cost
/// depends on. A stopped Sandbox costs nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SandboxLoad {
    pub(crate) running: bool,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mib: i32,
    pub(crate) disk_gib: i32,
}

impl From<&EnvironmentRow> for SandboxLoad {
    fn from(row: &EnvironmentRow) -> Self {
        Self {
            running: row.state == "running",
            cpu_millicores: row.cpu_millicores,
            memory_mib: row.memory_mb,
            disk_gib: row.disk_gb,
        }
    }
}

/// Why Create Sandbox cannot run in the cloud, for its drawer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreditRefusal {
    pub(crate) has_card: bool,
    /// Automatic top-up is charging the card, so credit is on its way.
    pub(crate) top_up_charging: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BannerAction {
    pub(crate) label: &'static str,
    pub(crate) url: String,
}

/// One `.cw-banner`: its tone, its sentence and, for an organization admin,
/// its action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BillingBannerView {
    pub(crate) tone: &'static str,
    pub(crate) text: String,
    pub(crate) action: Option<BannerAction>,
}

/// The viewer's side of the banner: whether they may act on billing, and
/// where.
pub(crate) struct BannerViewer<'a> {
    pub(crate) can_admin: bool,
    pub(crate) billing_url: &'a str,
}

/// The banner, first match wins (private-docs `designs/billing-compute-credits.md`,
/// "What the console says about credit"):
///
/// 1. Out of credit while automatic top-up charges the card: warning, and the
///    charge and the card; it settles in seconds.
/// 2. Out of credit: danger, and when Sandboxes are running, when they stop.
/// 3. Low: metered, some credit, and under $5 or under 24 hours at the
///    running Sandboxes' rate. Warning; with automatic top-up, the charge it
///    makes and when.
/// 4. Otherwise none, as where credit isn't enforced.
///
/// The card is named to owners and admins only. `sandboxes` is `None` when
/// the inventory could not be read: out of credit then has no stop time, and
/// low goes by the $5 line alone.
pub(crate) fn billing_banner(
    facts: &CreditFacts,
    sandboxes: Option<&[SandboxLoad]>,
    viewer: &BannerViewer<'_>,
    now: i64,
) -> Option<BillingBannerView> {
    let action = |label: &'static str| {
        viewer.can_admin.then(|| BannerAction {
            label,
            url: viewer.billing_url.to_owned(),
        })
    };
    let refill = || {
        action(if facts.has_card {
            "Add credit"
        } else {
            "Add a card"
        })
    };
    let card = facts
        .card
        .as_deref()
        .filter(|_| viewer.can_admin)
        .unwrap_or(SAVED_CARD);
    if let Some(exhausted_at) = facts.out_of_credit_since() {
        if facts.top_up_charging_cents > 0 {
            return Some(BillingBannerView {
                tone: "warning",
                text: format!(
                    "Out of compute credit: new Sandboxes and starts are refused until automatic top-up charges {} to {card}.",
                    cents_text(facts.top_up_charging_cents)
                ),
                action: None,
            });
        }
        let any_running = sandboxes.is_some_and(|loads| loads.iter().any(|load| load.running));
        let text = if any_running {
            format!(
                "Out of compute credit. New Sandboxes and starts are refused, and running Sandboxes stop {}. Their storage is kept.",
                stop_time(exhausted_at.saturating_add(STOP_AFTER_SECONDS), now)
            )
        } else {
            "Out of compute credit. New Sandboxes and starts are refused.".to_owned()
        };
        return Some(BillingBannerView {
            tone: "danger",
            text,
            action: refill(),
        });
    }
    if !facts.can_run_low() {
        return None;
    }
    // Whole hours left at the running Sandboxes' rate, when anything runs.
    let hours = sandboxes
        .map(|loads| hourly_cost_scaled(facts, loads))
        .filter(|hourly| *hourly > 0)
        .map(|hourly| i128::from(facts.balance_nano_eur) * SIZE_DENOMINATOR / hourly);
    let low_by_time = hours.is_some_and(|hours| hours < LOW_HOURS);
    if facts.balance_nano_eur >= LOW_BALANCE_NANO_EUR && !low_by_time {
        return None;
    }
    let left = format!(
        "{} of compute credit left",
        euro_text(facts.balance_nano_eur)
    );
    let (text, action) = if facts.tops_up() {
        let charge = cents_text(facts.auto_top_up_cents);
        let when = hours.map_or("when it reaches $0".to_owned(), |hours| {
            format!("in {} at current use", hours_text(hours))
        });
        (
            format!("{left}. Automatic top-up charges {charge} to {card} {when}."),
            None,
        )
    } else {
        let text = match hours {
            Some(hours) => format!("{left}, {} at current use.", hours_text(hours)),
            None => format!("{left}."),
        };
        (text, refill())
    };
    Some(BillingBannerView {
        tone: "warning",
        text,
        action,
    })
}

/// Whole hours as the banner says them.
fn hours_text(hours: i128) -> String {
    match hours {
        0 => "less than an hour".to_owned(),
        1 => "about 1 hour".to_owned(),
        hours @ 2..48 => format!("about {hours} hours"),
        hours => format!("about {} days", hours / 24),
    }
}

fn cents_text(cents: i32) -> String {
    euro_text(i64::from(cents) * NANO_EUR_PER_CENT)
}

/// How long the credit lasts at the running Sandboxes' rate, as the Billing
/// page's balance says it ("About 2 days at current use"). `None` when
/// nothing runs, nothing is charged, or no credit is left.
pub(crate) fn runway_text(facts: &CreditFacts, sandboxes: &[SandboxLoad]) -> Option<String> {
    let hourly = hourly_cost_scaled(facts, sandboxes);
    let balance = i128::from(facts.balance_nano_eur) * SIZE_DENOMINATOR;
    if hourly <= 0 || balance <= 0 {
        return None;
    }
    Some(match balance / hourly {
        0 => "Less than an hour at current use".to_owned(),
        1 => "About 1 hour at current use".to_owned(),
        hours @ 2..48 => format!("About {hours} hours at current use"),
        hours => format!("About {} days at current use", hours / 24),
    })
}

/// A Sandbox's rate, and what its running time has cost, at the
/// organization's rate card (#5186): its row menu's usage and its page's
/// rate. Both stay empty where nothing is charged.
pub(crate) fn price_sandbox(facts: &CreditFacts, row: &mut EnvironmentRow) {
    if !facts.billing_enabled || facts.unmetered {
        return;
    }
    let size = SandboxLoad {
        running: true,
        cpu_millicores: row.cpu_millicores,
        memory_mib: row.memory_mb,
        disk_gib: row.disk_gb,
    };
    let hourly = hourly_cost_scaled(facts, &[size]);
    row.hourly_rate = format!("{}/h", euro_text((hourly / SIZE_DENOMINATOR) as i64));
    let spent = hourly * i128::from(row.running_seconds.max(0)) / (3_600 * SIZE_DENOMINATOR);
    row.cost = euro_text(spent as i64);
}

/// What the running Sandboxes cost per hour, in nano-euros times
/// `SIZE_DENOMINATOR`, so nothing is rounded before the comparison.
fn hourly_cost_scaled(facts: &CreditFacts, sandboxes: &[SandboxLoad]) -> i128 {
    sandboxes
        .iter()
        .filter(|load| load.running)
        .map(|load| {
            i128::from(load.cpu_millicores.max(0))
                * 1_024
                * i128::from(facts.cpu_nano_eur_per_vcpu_hour)
                + i128::from(load.memory_mib.max(0))
                    * 1_000
                    * i128::from(facts.memory_nano_eur_per_gib_hour)
                + i128::from(load.disk_gib.max(0))
                    * SIZE_DENOMINATOR
                    * i128::from(facts.disk_nano_eur_per_gib_hour)
        })
        .sum()
}

/// When running Sandboxes stop, in UTC: "today at 09:12 UTC", "tomorrow at
/// 09:12 UTC", or a date further off; "now" once the time has passed.
fn stop_time(at: i64, now: i64) -> String {
    if at <= now {
        return "now".to_owned();
    }
    let seconds_in_day = at.rem_euclid(SECONDS_PER_DAY);
    let clock = format!(
        "{:02}:{:02} UTC",
        seconds_in_day / 3_600,
        seconds_in_day % 3_600 / 60
    );
    match at.div_euclid(SECONDS_PER_DAY) - now.div_euclid(SECONDS_PER_DAY) {
        0 => format!("today at {clock}"),
        1 => format!("tomorrow at {clock}"),
        _ => format!("on {}", calendar_datetime(at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-10 08:00 UTC.
    const NOW: i64 = 1_794_297_600;
    const BILLING: &str = "/example-org/billing/";
    const OUT: &str = "Out of compute credit. New Sandboxes and starts are refused.";
    /// The regular rate card, enforced: 2 vCPU, 8 GiB and 10 GiB cost about
    /// $0.20 an hour. No card yet.
    fn facts() -> CreditFacts {
        CreditFacts {
            balance_nano_eur: 50_000_000_000,
            has_card: false,
            card: None,
            auto_top_up: true,
            auto_top_up_cents: 2_000,
            top_up_charging_cents: 0,
            enforced: true,
            billing_enabled: true,
            unmetered: false,
            cpu_nano_eur_per_vcpu_hour: 43_800_000,
            memory_nano_eur_per_gib_hour: 14_100_000,
            disk_nano_eur_per_gib_hour: 87_000,
            exhausted_at: None,
        }
    }
    /// A Visa with automatic top-up at $20.
    fn topped_up(balance_nano_eur: i64) -> CreditFacts {
        CreditFacts {
            balance_nano_eur,
            has_card: true,
            card: Some("Visa •••• 4242".into()),
            ..facts()
        }
    }
    /// 2 vCPU, 8 GiB and 10 GiB: 0.20127 $/h at the rates above.
    fn standard(running: bool) -> SandboxLoad {
        SandboxLoad {
            running,
            cpu_millicores: 2_000,
            memory_mib: 8_192,
            disk_gib: 10,
        }
    }
    const HOURLY: i64 = 2 * 43_800_000 + 8 * 14_100_000 + 10 * 87_000;
    const EURO: i64 = 1_000_000_000;
    fn admin() -> BannerViewer<'static> {
        BannerViewer {
            can_admin: true,
            billing_url: BILLING,
        }
    }
    fn member() -> BannerViewer<'static> {
        BannerViewer {
            can_admin: false,
            billing_url: BILLING,
        }
    }
    fn banner(facts: &CreditFacts, loads: &[SandboxLoad]) -> Option<BillingBannerView> {
        billing_banner(facts, Some(loads), &admin(), NOW)
    }
    fn text(facts: &CreditFacts, loads: &[SandboxLoad]) -> String {
        banner(facts, loads).expect("a banner").text
    }
    fn action(label: &'static str) -> Option<BannerAction> {
        Some(BannerAction {
            label,
            url: BILLING.to_owned(),
        })
    }

    #[test]
    fn out_of_credit_is_danger_and_says_when_running_sandboxes_stop() {
        // Ran out yesterday at 09:12: running Sandboxes stop today at 09:12.
        let out = CreditFacts {
            balance_nano_eur: 0,
            exhausted_at: Some(NOW + 3_600 + 12 * 60 - SECONDS_PER_DAY),
            ..facts()
        };
        assert_eq!(
            banner(&out, &[standard(true)]),
            Some(BillingBannerView {
                tone: "danger",
                text: "Out of compute credit. New Sandboxes and starts are refused, and running Sandboxes stop today at 09:12 UTC. Their storage is kept.".into(),
                action: action("Add a card"),
            })
        );
        let tomorrow = CreditFacts {
            exhausted_at: Some(NOW + 3_600 + 12 * 60),
            ..out.clone()
        };
        assert!(text(&tomorrow, &[standard(true)]).contains("stop tomorrow at 09:12 UTC."));
        // A clock behind billing's still names the day.
        let later = CreditFacts {
            exhausted_at: Some(NOW + 2 * SECONDS_PER_DAY),
            ..out.clone()
        };
        assert!(text(&later, &[standard(true)]).contains("stop on Nov 13, 2026, 08:00 UTC."));
        let past = CreditFacts {
            exhausted_at: Some(NOW - 2 * SECONDS_PER_DAY),
            ..out.clone()
        };
        assert!(text(&past, &[standard(true)]).contains("Sandboxes stop now."));
        // Nothing running, or an inventory that could not be read: no stop time.
        for loads in [Some(&[standard(false)][..]), Some(&[][..]), None] {
            assert_eq!(
                billing_banner(&out, loads, &admin(), NOW).unwrap().text,
                OUT
            );
        }
    }

    #[test]
    fn out_of_credit_asks_for_a_card_or_for_credit_and_only_admins_get_the_action() {
        let out = CreditFacts {
            balance_nano_eur: 0,
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert_eq!(banner(&out, &[]).unwrap().action, action("Add a card"));
        // A declined top-up: billing marked it, so nothing is charging.
        let declined = CreditFacts {
            exhausted_at: Some(NOW),
            ..topped_up(0)
        };
        assert_eq!(
            banner(&declined, &[]),
            Some(BillingBannerView {
                tone: "danger",
                text: OUT.into(),
                action: action("Add credit"),
            })
        );
        let seen_by_member = billing_banner(&out, Some(&[]), &member(), NOW).unwrap();
        assert_eq!(seen_by_member.tone, "danger");
        assert_eq!(seen_by_member.action, None);
    }

    #[test]
    fn out_of_credit_while_top_up_charges_names_the_charge_and_the_card() {
        // -$27.14 with $20 top-ups: billing charges $40 (#3381).
        let charging = CreditFacts {
            top_up_charging_cents: 4_000,
            exhausted_at: Some(NOW),
            ..topped_up(-27_140_000_000)
        };
        assert_eq!(
            banner(&charging, &[standard(true)]),
            Some(BillingBannerView {
                tone: "warning",
                text: "Out of compute credit: new Sandboxes and starts are refused until automatic top-up charges $40.00 to Visa •••• 4242.".into(),
                action: None,
            })
        );
        // A member reads "the saved card", never its digits.
        assert_eq!(
            billing_banner(&charging, Some(&[]), &member(), NOW)
                .unwrap()
                .text,
            "Out of compute credit: new Sandboxes and starts are refused until automatic top-up charges $40.00 to the saved card."
        );
        assert_eq!(
            charging.create_refusal(),
            Some(CreditRefusal {
                has_card: true,
                top_up_charging: true,
            })
        );
    }

    #[test]
    fn credit_back_above_zero_is_not_out_of_credit_before_billing_clears_its_mark() {
        // #4754: billing clears credit_exhausted_at only on its next minute's
        // tick, but creates are admitted on the live balance at once. On Dev
        // the owner added $2 and still saw "Out of credit" for 33 s.
        let credited = CreditFacts {
            balance_nano_eur: 2 * EURO,
            has_card: true,
            auto_top_up: false,
            exhausted_at: Some(NOW - 60),
            ..facts()
        };
        assert_eq!(credited.create_refusal(), None);
        assert!(
            banner(&credited, &[standard(true)]).is_none_or(|view| view.tone != "danger"),
            "{:?}",
            banner(&credited, &[standard(true)])
        );
    }

    #[test]
    fn low_credit_counts_whole_hours_at_the_running_sandboxes_rate() {
        // Seven hours and a bit at $0.20127 an hour.
        let low = CreditFacts {
            balance_nano_eur: 1_400_000_000,
            ..facts()
        };
        assert_eq!(
            banner(&low, &[standard(true), standard(false)]),
            Some(BillingBannerView {
                tone: "warning",
                text: "$1.40 of compute credit left, about 6 hours at current use.".into(),
                action: action("Add a card"),
            })
        );
        let with_card = CreditFacts {
            has_card: true,
            auto_top_up: false,
            ..low.clone()
        };
        assert_eq!(
            banner(&with_card, &[standard(true)]).unwrap().action,
            action("Add credit")
        );
        let at = |balance_nano_eur| CreditFacts {
            balance_nano_eur,
            ..facts()
        };
        assert_eq!(
            text(&at(HOURLY), &[standard(true)]),
            "$0.20127 of compute credit left, about 1 hour at current use."
        );
        assert_eq!(
            text(&at(HOURLY - 1), &[standard(true)]),
            "$0.201269 of compute credit left, less than an hour at current use."
        );
        // Two running Sandboxes halve the time.
        assert_eq!(
            text(&at(4 * HOURLY), &[standard(true), standard(true)]),
            "$0.80508 of compute credit left, about 2 hours at current use."
        );
        let seen_by_member = billing_banner(&low, Some(&[standard(true)]), &member(), NOW).unwrap();
        assert_eq!(seen_by_member.tone, "warning");
        assert_eq!(seen_by_member.action, None);
    }

    #[test]
    fn low_is_under_twenty_four_hours_or_under_five_euros() {
        let at = |balance_nano_eur| CreditFacts {
            balance_nano_eur,
            ..facts()
        };
        // $5 or more, a day or more left: nothing to say. Two running
        // Sandboxes put the day at $9.66, above the $5 line.
        let two = [standard(true), standard(true)];
        assert_eq!(banner(&at(48 * HOURLY), &two), None);
        assert_eq!(
            text(&at(48 * HOURLY - 1), &two),
            "$9.660959 of compute credit left, about 23 hours at current use."
        );
        // Under $5 is low whatever runs; nothing running says no time.
        assert_eq!(banner(&at(5 * EURO), &[]), None);
        assert_eq!(
            text(&at(3_200_000_000), &[]),
            "$3.20 of compute credit left."
        );
        assert_eq!(
            text(&at(3_200_000_000), &[standard(false)]),
            "$3.20 of compute credit left."
        );
        // Under $5 but days left at a small rate.
        assert_eq!(
            text(&at(4 * EURO), &[standard(true)]),
            "$4.00 of compute credit left, about 19 hours at current use."
        );
        // An inventory that could not be read: the $5 line alone.
        assert_eq!(
            billing_banner(&at(3 * EURO), None, &admin(), NOW)
                .unwrap()
                .text,
            "$3.00 of compute credit left."
        );
        assert_eq!(billing_banner(&at(20 * EURO), None, &admin(), NOW), None);
    }

    #[test]
    fn low_with_top_up_says_what_it_charges_and_when() {
        assert_eq!(
            banner(&topped_up(3_200_000_000), &[standard(true)]),
            Some(BillingBannerView {
                tone: "warning",
                text: "$3.20 of compute credit left. Automatic top-up charges $20.00 to Visa •••• 4242 in about 15 hours at current use.".into(),
                action: None,
            })
        );
        assert_eq!(
            text(&topped_up(3_200_000_000), &[]),
            "$3.20 of compute credit left. Automatic top-up charges $20.00 to Visa •••• 4242 when it reaches $0."
        );
        assert_eq!(
            billing_banner(&topped_up(3_200_000_000), Some(&[]), &member(), NOW)
                .unwrap()
                .text,
            "$3.20 of compute credit left. Automatic top-up charges $20.00 to the saved card when it reaches $0."
        );
        // A card that Stripe could not read is still the saved card.
        let unread = CreditFacts {
            card: None,
            ..topped_up(HOURLY)
        };
        assert_eq!(
            text(&unread, &[standard(true)]),
            "$0.20127 of compute credit left. Automatic top-up charges $20.00 to the saved card in about 1 hour at current use."
        );
        // Plenty left: nothing to say.
        assert_eq!(banner(&topped_up(50 * EURO), &[standard(true)]), None);
    }

    #[test]
    fn credit_that_is_not_drawn_or_not_enforced_gives_no_banner() {
        let low = CreditFacts {
            balance_nano_eur: HOURLY,
            ..facts()
        };
        let running = [standard(true)];
        assert!(banner(&low, &running).is_some());
        for quiet in [
            CreditFacts {
                unmetered: true,
                ..low.clone()
            },
            CreditFacts {
                billing_enabled: false,
                ..low.clone()
            },
            // Nothing is refused or charged where credit isn't enforced.
            CreditFacts {
                enforced: false,
                ..low.clone()
            },
            // Nothing left is out of credit's to report, once billing says so.
            CreditFacts {
                balance_nano_eur: 0,
                ..low.clone()
            },
        ] {
            assert_eq!(banner(&quiet, &running), None, "{quiet:?}");
        }
        // Free rates never run out, and $5 or more is not low.
        let free = CreditFacts {
            balance_nano_eur: 5 * EURO,
            cpu_nano_eur_per_vcpu_hour: 0,
            memory_nano_eur_per_gib_hour: 0,
            disk_nano_eur_per_gib_hour: 0,
            ..low
        };
        assert_eq!(banner(&free, &running), None);
    }

    #[test]
    fn the_banner_reads_sandboxes_only_when_it_may_show() {
        assert!(facts().banner_needs_sandboxes());
        assert!(topped_up(50 * EURO).banner_needs_sandboxes());
        let out = CreditFacts {
            balance_nano_eur: 0,
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert!(out.banner_needs_sandboxes());
        for quiet in [
            CreditFacts {
                unmetered: true,
                ..facts()
            },
            CreditFacts {
                billing_enabled: false,
                ..facts()
            },
            CreditFacts {
                enforced: false,
                ..facts()
            },
            CreditFacts {
                balance_nano_eur: 0,
                ..facts()
            },
        ] {
            assert!(!quiet.banner_needs_sandboxes(), "{quiet:?}");
        }
    }

    #[test]
    fn create_is_refused_only_while_billing_reports_the_organization_out_of_credit() {
        assert_eq!(facts().create_refusal(), None);
        // Billing reports nothing where it doesn't enforce credit.
        let broke = CreditFacts {
            balance_nano_eur: -5,
            ..facts()
        };
        assert_eq!(broke.create_refusal(), None);
        let out = CreditFacts {
            balance_nano_eur: 0,
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert_eq!(
            out.create_refusal(),
            Some(CreditRefusal {
                has_card: false,
                top_up_charging: false,
            })
        );
        let out_with_card = CreditFacts {
            has_card: true,
            ..out
        };
        assert_eq!(
            out_with_card.create_refusal(),
            Some(CreditRefusal {
                has_card: true,
                top_up_charging: false,
            })
        );
    }

    #[test]
    fn a_sandbox_is_priced_at_the_rate_card_in_euros() {
        // 2 vCPU, 4 GiB and 10 GiB at the regular rate card, three hours.
        let mut row = crate::environment_connect::environment_row(
            codewire_proto::codewire::v1::Environment {
                cpu_millicores: 2_000,
                memory_mb: 4_096,
                disk_gb: 10,
                total_running_seconds: 3 * 3_600,
                ..Default::default()
            },
        );
        price_sandbox(&facts(), &mut row);
        assert_eq!(row.hourly_rate, "$0.14487/h");
        assert_eq!(row.cost, "$0.43461");
        // Never run: nothing spent, at the same rate.
        let mut fresh = crate::environment_connect::environment_row(
            codewire_proto::codewire::v1::Environment {
                cpu_millicores: 1_000,
                memory_mb: 2_048,
                disk_gb: 10,
                ..Default::default()
            },
        );
        price_sandbox(&facts(), &mut fresh);
        assert_eq!(fresh.hourly_rate, "$0.07287/h");
        assert_eq!(fresh.cost, "$0.00");
        // Unlimited, or billing off: no price at all.
        for quiet in [
            CreditFacts {
                unmetered: true,
                ..facts()
            },
            CreditFacts {
                billing_enabled: false,
                ..facts()
            },
        ] {
            let mut row = crate::environment_connect::environment_row(Default::default());
            price_sandbox(&quiet, &mut row);
            assert_eq!((row.cost.as_str(), row.hourly_rate.as_str()), ("", ""));
        }
    }
}
