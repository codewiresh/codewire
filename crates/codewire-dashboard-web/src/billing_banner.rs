//! What the console says about an organization's credit: the banner across
//! the top of its pages, and whether Create Sandbox can run in the cloud.
//! Everything here is a pure function of the billing overview, the
//! organization's Sandboxes and the time, so each state is tested without a
//! billing service.

use crate::{admin_connect::euro_text, time_display::calendar_datetime, view::EnvironmentRow};

/// Running Sandboxes of an organization that ran out of credit stop this long
/// after it ran out (`CREDIT_EXHAUSTED_GRACE_HOURS` in orchestration).
const STOP_AFTER_SECONDS: i64 = 24 * 3_600;
/// Credit that lasts less than this many hours at the current rate is low.
const LOW_HOURS: i128 = 24;
/// Millicores per vCPU times MiB per GiB: a size times a rate per hour, over
/// this, is nano-euros per hour (`usage_nano_eur` in billing).
const SIZE_DENOMINATOR: i128 = 1_000 * 1_024;
const SECONDS_PER_DAY: i64 = 86_400;

/// The billing overview's facts the console acts on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CreditFacts {
    pub(crate) balance_nano_eur: i64,
    pub(crate) has_card: bool,
    pub(crate) auto_top_up: bool,
    pub(crate) billing_enabled: bool,
    pub(crate) unmetered: bool,
    pub(crate) cpu_nano_eur_per_vcpu_hour: i64,
    pub(crate) memory_nano_eur_per_gib_hour: i64,
    pub(crate) disk_nano_eur_per_gib_hour: i64,
    /// When the organization ran out, in Unix seconds. Billing sets it only
    /// while it enforces credit, so it means creates and starts are refused.
    pub(crate) exhausted_at: Option<i64>,
}

impl CreditFacts {
    fn metered(&self) -> bool {
        self.billing_enabled && !self.unmetered
    }

    /// Credit that can run low: metered, some left, and nothing that refills
    /// it on its own.
    fn can_run_low(&self) -> bool {
        self.metered() && self.balance_nano_eur > 0 && !(self.has_card && self.auto_top_up)
    }

    /// The banner needs the organization's Sandboxes only when it may show.
    pub(crate) fn banner_needs_sandboxes(&self) -> bool {
        self.exhausted_at.is_some() || self.can_run_low()
    }

    /// Create Sandbox in the cloud is refused: the organization ran out.
    pub(crate) fn create_refusal(&self) -> Option<CreditRefusal> {
        self.exhausted_at.map(|_| CreditRefusal {
            has_card: self.has_card,
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

/// The banner, first match wins:
///
/// 1. Out of credit: danger, and when Sandboxes are running, when they stop.
/// 2. Low: metered, some credit, no card with automatic top-up, Sandboxes
///    running, and less than 24 hours left at their rate. Warning.
/// 3. Otherwise none.
///
/// `sandboxes` is `None` when the inventory could not be read: an
/// organization out of credit still gets its banner, without a stop time,
/// and low credit, which needs the rate, gets none.
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
    if let Some(exhausted_at) = facts.exhausted_at {
        let any_running = sandboxes.is_some_and(|loads| loads.iter().any(|load| load.running));
        let text = if any_running {
            format!(
                "Out of credit: cloud sandboxes can’t start, and running ones stop {}.",
                stop_time(exhausted_at.saturating_add(STOP_AFTER_SECONDS), now)
            )
        } else {
            "Out of credit: cloud sandboxes can’t start.".to_owned()
        };
        return Some(BillingBannerView {
            tone: "danger",
            text,
            action: action(if facts.has_card {
                "Add credit"
            } else {
                "Add a card"
            }),
        });
    }
    if !facts.can_run_low() {
        return None;
    }
    let hourly = hourly_cost_scaled(facts, sandboxes?);
    let balance = i128::from(facts.balance_nano_eur) * SIZE_DENOMINATOR;
    if hourly <= 0 || balance >= LOW_HOURS * hourly {
        return None;
    }
    let hours = balance / hourly;
    let left = match hours {
        0 => "less than an hour".to_owned(),
        1 => "about 1 hour".to_owned(),
        hours => format!("about {hours} hours"),
    };
    Some(BillingBannerView {
        tone: "warning",
        text: format!(
            "{} of credit left, {left} at this rate.",
            euro_text(facts.balance_nano_eur)
        ),
        action: action("Add credit"),
    })
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
    /// The regular rate card: 2 vCPU, 8 GiB and 10 GiB cost about €0.20 an hour.
    fn facts() -> CreditFacts {
        CreditFacts {
            balance_nano_eur: 50_000_000_000,
            has_card: false,
            auto_top_up: true,
            billing_enabled: true,
            unmetered: false,
            cpu_nano_eur_per_vcpu_hour: 43_800_000,
            memory_nano_eur_per_gib_hour: 14_100_000,
            disk_nano_eur_per_gib_hour: 87_000,
            exhausted_at: None,
        }
    }
    /// 2 vCPU, 8 GiB and 10 GiB: 0.20127 €/h at the rates above.
    fn standard(running: bool) -> SandboxLoad {
        SandboxLoad {
            running,
            cpu_millicores: 2_000,
            memory_mib: 8_192,
            disk_gib: 10,
        }
    }
    const HOURLY: i64 = 2 * 43_800_000 + 8 * 14_100_000 + 10 * 87_000;
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
                text: "Out of credit: cloud sandboxes can’t start, and running ones stop today at 09:12 UTC.".into(),
                action: action("Add a card"),
            })
        );
        let tomorrow = CreditFacts {
            exhausted_at: Some(NOW + 3_600 + 12 * 60),
            ..out.clone()
        };
        assert_eq!(
            banner(&tomorrow, &[standard(true)]).unwrap().text,
            "Out of credit: cloud sandboxes can’t start, and running ones stop tomorrow at 09:12 UTC."
        );
        // A clock behind billing's still names the day.
        let later = CreditFacts {
            exhausted_at: Some(NOW + 2 * SECONDS_PER_DAY),
            ..out.clone()
        };
        assert_eq!(
            banner(&later, &[standard(true)]).unwrap().text,
            "Out of credit: cloud sandboxes can’t start, and running ones stop on Nov 13, 2026, 08:00 UTC."
        );
        let past = CreditFacts {
            exhausted_at: Some(NOW - 2 * SECONDS_PER_DAY),
            ..out.clone()
        };
        assert_eq!(
            banner(&past, &[standard(true)]).unwrap().text,
            "Out of credit: cloud sandboxes can’t start, and running ones stop now."
        );
        // Nothing running, or an inventory that could not be read: no stop time.
        for loads in [Some(&[standard(false)][..]), Some(&[][..]), None] {
            assert_eq!(
                billing_banner(&out, loads, &admin(), NOW).unwrap().text,
                "Out of credit: cloud sandboxes can’t start."
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
        let with_card = CreditFacts {
            has_card: true,
            ..out.clone()
        };
        assert_eq!(
            banner(&with_card, &[]).unwrap().action,
            action("Add credit")
        );
        let seen_by_member = billing_banner(&out, Some(&[]), &member(), NOW).unwrap();
        assert_eq!(seen_by_member.tone, "danger");
        assert_eq!(seen_by_member.action, None);
    }

    #[test]
    fn out_of_credit_comes_before_low_credit() {
        // A balance that would read as low still reports the refusal.
        let both = CreditFacts {
            balance_nano_eur: HOURLY,
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert_eq!(banner(&both, &[standard(true)]).unwrap().tone, "danger");
    }

    #[test]
    fn low_credit_counts_whole_hours_at_the_running_sandboxes_rate() {
        // Seven hours and a bit at €0.20127 an hour.
        let low = CreditFacts {
            balance_nano_eur: 1_400_000_000,
            ..facts()
        };
        assert_eq!(
            banner(&low, &[standard(true), standard(false)]),
            Some(BillingBannerView {
                tone: "warning",
                text: "€1.40 of credit left, about 6 hours at this rate.".into(),
                action: action("Add credit"),
            })
        );
        let one = CreditFacts {
            balance_nano_eur: HOURLY,
            ..facts()
        };
        assert_eq!(
            banner(&one, &[standard(true)]).unwrap().text,
            "€0.20127 of credit left, about 1 hour at this rate."
        );
        let under_an_hour = CreditFacts {
            balance_nano_eur: HOURLY - 1,
            ..facts()
        };
        assert_eq!(
            banner(&under_an_hour, &[standard(true)]).unwrap().text,
            "€0.201269 of credit left, less than an hour at this rate."
        );
        // Two running Sandboxes halve the time.
        let two = CreditFacts {
            balance_nano_eur: 4 * HOURLY,
            ..facts()
        };
        assert_eq!(
            banner(&two, &[standard(true), standard(true)])
                .unwrap()
                .text,
            "€0.80508 of credit left, about 2 hours at this rate."
        );
        let seen_by_member = billing_banner(&low, Some(&[standard(true)]), &member(), NOW).unwrap();
        assert_eq!(seen_by_member.tone, "warning");
        assert_eq!(seen_by_member.action, None);
    }

    #[test]
    fn low_credit_starts_below_twenty_four_hours() {
        let at = |balance_nano_eur| CreditFacts {
            balance_nano_eur,
            ..facts()
        };
        assert_eq!(banner(&at(24 * HOURLY), &[standard(true)]), None);
        assert_eq!(
            banner(&at(24 * HOURLY - 1), &[standard(true)])
                .unwrap()
                .text,
            "€4.830479 of credit left, about 23 hours at this rate."
        );
    }

    #[test]
    fn credit_that_refills_or_is_not_drawn_gives_no_banner() {
        let low = CreditFacts {
            balance_nano_eur: HOURLY,
            ..facts()
        };
        let running = [standard(true)];
        assert!(banner(&low, &running).is_some());
        // A card with automatic top-up refills it.
        let refilled = CreditFacts {
            has_card: true,
            auto_top_up: true,
            ..low.clone()
        };
        assert_eq!(banner(&refilled, &running), None);
        // A card alone, or automatic top-up without a card, does not.
        for (has_card, auto_top_up) in [(true, false), (false, true)] {
            let facts = CreditFacts {
                has_card,
                auto_top_up,
                ..low.clone()
            };
            assert!(
                banner(&facts, &running).is_some(),
                "{has_card} {auto_top_up}"
            );
        }
        let unmetered = CreditFacts {
            unmetered: true,
            ..low.clone()
        };
        assert_eq!(banner(&unmetered, &running), None);
        let billing_off = CreditFacts {
            billing_enabled: false,
            ..low.clone()
        };
        assert_eq!(banner(&billing_off, &running), None);
        // Nothing left is out of credit's to report, once billing says so.
        let empty = CreditFacts {
            balance_nano_eur: 0,
            ..low.clone()
        };
        assert_eq!(banner(&empty, &running), None);
        // Nothing running costs nothing; an unread inventory says nothing.
        assert_eq!(banner(&low, &[standard(false)]), None);
        assert_eq!(banner(&low, &[]), None);
        assert_eq!(billing_banner(&low, None, &admin(), NOW), None);
        // Free rates never run out.
        let free = CreditFacts {
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
        let out = CreditFacts {
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert!(out.banner_needs_sandboxes());
        for quiet in [
            CreditFacts {
                has_card: true,
                ..facts()
            },
            CreditFacts {
                unmetered: true,
                ..facts()
            },
            CreditFacts {
                billing_enabled: false,
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
    fn create_is_refused_only_while_billing_records_the_organization_out_of_credit() {
        assert_eq!(facts().create_refusal(), None);
        let broke = CreditFacts {
            balance_nano_eur: -5,
            ..facts()
        };
        assert_eq!(broke.create_refusal(), None);
        let out = CreditFacts {
            exhausted_at: Some(NOW),
            ..facts()
        };
        assert_eq!(
            out.create_refusal(),
            Some(CreditRefusal { has_card: false })
        );
        let out_with_card = CreditFacts {
            has_card: true,
            ..out
        };
        assert_eq!(
            out_with_card.create_refusal(),
            Some(CreditRefusal { has_card: true })
        );
    }
}
