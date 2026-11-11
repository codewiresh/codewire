//! The account home, "Welcome to Codewire" (owner, 2026-11-10): a Get started
//! checklist that ticks itself off from real state and goes away once all
//! three steps are done, then one card per organization the account belongs
//! to, with its balance, this month's usage, its running Sandboxes and the
//! last 24 hours of cost.
//!
//! The page renders its shell first; the checklist and the cards arrive in one
//! fragment. That fragment reads every organization at once, each read with
//! its own short deadline, so the cards wait for the slowest organization at
//! most that long and never one after another. An organization whose reads
//! fail still gets its card, without the figures it could not read.
//!
//! Everything below `overview` is a pure function of what was read and the
//! time, so each state is tested without the services.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;

use crate::{
    admin_connect::euro_text,
    billing_connect::{self, BillingSummary, HourCost},
    environment_connect,
    state::AppState,
    view::OrganizationRow,
};

/// How long the home waits for any one read of an organization.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Organizations read at once; an account in more waits in turns of this many.
const CONCURRENT_ORGANIZATIONS: usize = 8;
const HOURS: i64 = 24;
const SECONDS_PER_HOUR: i64 = 3_600;
/// The chart's geometry, as on the Billing page: bars stand on the axis at
/// y = 80 and the tallest is 72 high; each slot is 12 wide from x = 4.
const AXIS_Y: i64 = 80;
const BAR_MAX: i64 = 72;
const BAR_MIN: i64 = 2;
const SLOT_START: i64 = 4;
const SLOT_WIDTH: i64 = 12;

/// What the Sandbox list says of an organization: how many run now, and
/// whether it ever had one (destroyed ones included).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SandboxSummary {
    pub(crate) running: usize,
    pub(crate) ever: bool,
}

/// One organization's reads. `None` is a read that failed or ran out of time.
#[derive(Clone, Debug, Default)]
pub(crate) struct OrganizationReads {
    pub(crate) billing: Option<BillingSummary>,
    pub(crate) sandboxes: Option<SandboxSummary>,
    pub(crate) hourly: Option<Vec<HourCost>>,
}

#[derive(Debug, Default)]
pub(crate) struct AccountOverviewView {
    /// Shown until all three steps are done.
    pub(crate) get_started: Option<GetStartedView>,
    pub(crate) organizations: Vec<OrganizationCardView>,
    /// More than one card has a chart, all drawn on the same scale.
    pub(crate) shared_scale: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GetStartedView {
    pub(crate) done: usize,
    pub(crate) cli: bool,
    pub(crate) card: bool,
    /// The card step is done because this organization pays for nothing.
    pub(crate) unmetered: bool,
    pub(crate) sandbox: bool,
    /// The viewer can add the card; otherwise they are told who can.
    pub(crate) can_admin: bool,
    pub(crate) billing_url: String,
    pub(crate) new_sandbox_url: String,
}

#[derive(Debug)]
pub(crate) struct OrganizationCardView {
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) role: &'static str,
    /// `None` when the organization's billing or Sandboxes could not be read.
    pub(crate) stats: Option<CardStats>,
    /// The last 24 hours, when the organization has had a cloud Sandbox and
    /// its usage could be read.
    pub(crate) bars: Vec<UsageBar>,
    /// It has never had a cloud Sandbox: "No cloud usage yet."
    pub(crate) no_usage: bool,
    pub(crate) sandboxes_url: String,
    /// Owners and admins only.
    pub(crate) billing_url: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CardStats {
    /// "Unlimited" for an organization that pays for nothing.
    pub(crate) balance: String,
    pub(crate) month: String,
    pub(crate) running: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UsageBar {
    pub(crate) x: i64,
    pub(crate) y: i64,
    pub(crate) height: i64,
    pub(crate) label: String,
}

/// Read every organization at once and build the home's checklist and cards.
/// `current` is the organization the checklist follows: the remembered one,
/// else the first.
pub(crate) async fn overview(
    state: &AppState,
    cookie: HeaderValue,
    cli_signed_in: bool,
    organizations: &[OrganizationRow],
    current: &str,
) -> AccountOverviewView {
    let mut reads = Vec::with_capacity(organizations.len());
    for batch in organizations.chunks(CONCURRENT_ORGANIZATIONS) {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, organization) in batch.iter().enumerate() {
            let state = state.clone();
            let cookie = cookie.clone();
            let org_id = organization.id.clone();
            tasks.spawn(async move { (index, read(&state, cookie, &org_id).await) });
        }
        let mut batch_reads = vec![OrganizationReads::default(); batch.len()];
        while let Some(result) = tasks.join_next().await {
            if let Ok((index, organization_reads)) = result {
                batch_reads[index] = organization_reads;
            }
        }
        reads.extend(batch_reads);
    }
    build(cli_signed_in, organizations, &reads, current, now())
}

async fn read(state: &AppState, cookie: HeaderValue, org_id: &str) -> OrganizationReads {
    let (billing, sandboxes, hourly) = tokio::join!(
        tokio::time::timeout(
            READ_TIMEOUT,
            billing_connect::account_home_overview(state, cookie.clone(), org_id),
        ),
        // Destroyed Sandboxes too: the checklist asks whether the organization
        // ever had one, and the list keeps every Sandbox it ever created.
        tokio::time::timeout(
            READ_TIMEOUT,
            environment_connect::environments(state, cookie.clone(), org_id, true),
        ),
        tokio::time::timeout(
            READ_TIMEOUT,
            billing_connect::account_home_hourly(state, cookie, org_id),
        ),
    );
    OrganizationReads {
        billing: billing.ok().and_then(Result::ok),
        sandboxes: sandboxes
            .ok()
            .and_then(Result::ok)
            .map(|rows| SandboxSummary {
                running: rows.iter().filter(|row| row.state == "running").count(),
                ever: !rows.is_empty(),
            }),
        hourly: hourly.ok().and_then(Result::ok),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// The checklist and the cards from what was read. `reads` lines up with
/// `organizations`.
pub(crate) fn build(
    cli_signed_in: bool,
    organizations: &[OrganizationRow],
    reads: &[OrganizationReads],
    current: &str,
    now: i64,
) -> AccountOverviewView {
    let empty = OrganizationReads::default();
    let read_of = |index: usize| reads.get(index).unwrap_or(&empty);
    let current_index = organizations
        .iter()
        .position(|organization| organization.slug == current)
        .unwrap_or(0);
    let get_started = organizations.get(current_index).and_then(|organization| {
        let reads = read_of(current_index);
        let unmetered = reads.billing.is_some_and(|billing| !billing.metered);
        let card = reads
            .billing
            .is_some_and(|billing| billing.has_card || !billing.metered);
        let sandbox = reads.sandboxes.is_some_and(|sandboxes| sandboxes.ever);
        let done = [cli_signed_in, card, sandbox]
            .into_iter()
            .filter(|step| *step)
            .count();
        (done < 3).then(|| GetStartedView {
            done,
            cli: cli_signed_in,
            card,
            unmetered,
            sandbox,
            can_admin: organization.can_admin,
            billing_url: format!("/{}/billing/", organization.slug),
            new_sandbox_url: format!("/{}/new/", organization.slug),
        })
    });

    // Every chart shares one scale, so the cards compare at a glance.
    let charts: Vec<Option<[i64; HOURS as usize]>> = organizations
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let reads = read_of(index);
            let ever = reads.sandboxes.is_some_and(|sandboxes| sandboxes.ever);
            reads
                .hourly
                .as_deref()
                .filter(|_| ever)
                .map(|hourly| last_day(hourly, now))
        })
        .collect();
    let scale = charts
        .iter()
        .flatten()
        .flat_map(|hours| hours.iter().copied())
        .max()
        .unwrap_or(0);
    let shared_scale = charts.iter().flatten().count() > 1;
    let first_hour = now - now.rem_euclid(SECONDS_PER_HOUR) - (HOURS - 1) * SECONDS_PER_HOUR;

    let organizations = organizations
        .iter()
        .zip(charts)
        .enumerate()
        .map(|(index, (organization, chart))| {
            let reads = read_of(index);
            let stats = match (reads.billing, reads.sandboxes) {
                (Some(billing), Some(sandboxes)) => Some(CardStats {
                    balance: if billing.metered {
                        euro_text(billing.balance_nano_eur)
                    } else {
                        "Unlimited".to_owned()
                    },
                    month: euro_text(billing.month_nano_eur),
                    running: sandboxes.running,
                }),
                _ => None,
            };
            OrganizationCardView {
                name: organization.display_name().to_owned(),
                slug: organization.slug.clone(),
                role: organization.role,
                stats,
                bars: chart
                    .map(|hours| bars(&hours, scale, first_hour))
                    .unwrap_or_default(),
                no_usage: reads.sandboxes.is_some_and(|sandboxes| !sandboxes.ever),
                sandboxes_url: format!("/{}/", organization.slug),
                billing_url: organization
                    .can_admin
                    .then(|| format!("/{}/billing/", organization.slug)),
            }
        })
        .collect();
    AccountOverviewView {
        get_started,
        organizations,
        shared_scale,
    }
}

/// The cost of each of the last 24 hours, oldest first, the current hour
/// last; an hour billing did not report cost nothing.
fn last_day(hourly: &[HourCost], now: i64) -> [i64; HOURS as usize] {
    let current_hour = now - now.rem_euclid(SECONDS_PER_HOUR);
    let mut hours = [0_i64; HOURS as usize];
    for entry in hourly {
        let hour = entry.hour - entry.hour.rem_euclid(SECONDS_PER_HOUR);
        let back = (current_hour - hour) / SECONDS_PER_HOUR;
        if (0..HOURS).contains(&back) {
            let slot = (HOURS - 1 - back) as usize;
            hours[slot] = hours[slot].saturating_add(i64::from(entry.cost_cents.max(0)));
        }
    }
    hours
}

fn bars(hours: &[i64; HOURS as usize], scale: i64, first_hour: i64) -> Vec<UsageBar> {
    hours
        .iter()
        .enumerate()
        .map(|(slot, cents)| {
            let height = if *cents == 0 || scale == 0 {
                0
            } else {
                (cents * BAR_MAX / scale).max(BAR_MIN)
            };
            let hour =
                (first_hour + slot as i64 * SECONDS_PER_HOUR).rem_euclid(86_400) / SECONDS_PER_HOUR;
            UsageBar {
                x: SLOT_START + slot as i64 * SLOT_WIDTH,
                y: AXIS_Y - height,
                height,
                label: format!(
                    "{hour:02}:00 UTC, {}",
                    euro_text(cents.saturating_mul(10_000_000))
                ),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-10 15:20 UTC.
    const NOW: i64 = 1_794_324_000;

    fn organization(slug: &str, can_admin: bool) -> OrganizationRow {
        OrganizationRow {
            id: format!("id-{slug}"),
            name: slug.to_owned(),
            slug: slug.to_owned(),
            role: if can_admin { "Owner" } else { "Member" },
            can_admin,
            billing_plan: String::new(),
            url: format!("/{slug}/"),
        }
    }

    fn metered(has_card: bool) -> BillingSummary {
        BillingSummary {
            has_card,
            metered: true,
            balance_nano_eur: 42_180_000_000,
            month_nano_eur: 17_820_000_000,
        }
    }

    fn reads(
        billing: Option<BillingSummary>,
        sandboxes: Option<SandboxSummary>,
        hourly: Option<Vec<HourCost>>,
    ) -> OrganizationReads {
        OrganizationReads {
            billing,
            sandboxes,
            hourly,
        }
    }

    fn hour(back: i64, cost_cents: i32) -> HourCost {
        HourCost {
            hour: NOW - NOW % 3_600 - back * 3_600,
            cost_cents,
        }
    }

    const NEVER: SandboxSummary = SandboxSummary {
        running: 0,
        ever: false,
    };
    const RAN: SandboxSummary = SandboxSummary {
        running: 2,
        ever: true,
    };

    #[test]
    fn a_new_account_has_three_steps_to_do() {
        let view = build(
            false,
            &[organization("example-org", true)],
            &[reads(Some(metered(false)), Some(NEVER), Some(Vec::new()))],
            "",
            NOW,
        );
        let steps = view.get_started.expect("the checklist shows");
        assert_eq!(
            steps,
            GetStartedView {
                done: 0,
                cli: false,
                card: false,
                unmetered: false,
                sandbox: false,
                can_admin: true,
                billing_url: "/example-org/billing/".into(),
                new_sandbox_url: "/example-org/new/".into(),
            }
        );
        let card = &view.organizations[0];
        assert_eq!(
            card.stats,
            Some(CardStats {
                balance: "€42.18".into(),
                month: "€17.82".into(),
                running: 0,
            })
        );
        assert!(card.no_usage, "never had a cloud Sandbox");
        assert!(card.bars.is_empty());
        assert_eq!(card.billing_url.as_deref(), Some("/example-org/billing/"));
    }

    /// Each step ticks itself off from its own source, and the card goes away
    /// at 3 of 3.
    #[test]
    fn each_step_ticks_itself_off_and_the_checklist_goes_at_three() {
        let one = [organization("example-org", true)];
        let at = |cli, billing, sandboxes| {
            build(
                cli,
                &one,
                &[reads(billing, sandboxes, Some(Vec::new()))],
                "example-org",
                NOW,
            )
            .get_started
        };
        let only_cli = at(true, Some(metered(false)), Some(NEVER)).unwrap();
        assert_eq!((only_cli.done, only_cli.cli), (1, true));
        let only_card = at(false, Some(metered(true)), Some(NEVER)).unwrap();
        assert_eq!((only_card.done, only_card.card), (1, true));
        let only_sandbox = at(false, Some(metered(false)), Some(RAN)).unwrap();
        assert_eq!((only_sandbox.done, only_sandbox.sandbox), (1, true));
        // A destroyed Sandbox still counts: the list includes it.
        let destroyed = SandboxSummary {
            running: 0,
            ever: true,
        };
        assert!(
            at(false, Some(metered(false)), Some(destroyed))
                .unwrap()
                .sandbox
        );
        assert_eq!(at(true, Some(metered(true)), Some(NEVER)).unwrap().done, 2);
        assert_eq!(at(true, Some(metered(true)), Some(RAN)), None);
        // A read that failed is not done; the step stays to do.
        let unread = at(true, None, None).unwrap();
        assert_eq!(
            (unread.done, unread.card, unread.sandbox),
            (1, false, false)
        );
    }

    /// An organization that pays for nothing has no card to add: the step is
    /// done, and its card says Unlimited instead of a balance.
    #[test]
    fn an_unmetered_organization_has_nothing_to_add() {
        let unmetered = BillingSummary {
            has_card: false,
            metered: false,
            balance_nano_eur: 0,
            month_nano_eur: 0,
        };
        let view = build(
            false,
            &[organization("unlimited", true)],
            &[reads(Some(unmetered), Some(NEVER), Some(Vec::new()))],
            "unlimited",
            NOW,
        );
        let steps = view.get_started.unwrap();
        assert!(steps.card && steps.unmetered);
        assert_eq!(steps.done, 1);
        assert_eq!(
            view.organizations[0].stats.as_ref().unwrap().balance,
            "Unlimited"
        );
    }

    /// The checklist follows the remembered organization, else the first; a
    /// member is told who can add the card.
    #[test]
    fn the_checklist_follows_the_current_organization_and_its_role() {
        let organizations = [organization("mine", true), organization("theirs", false)];
        let all = [
            reads(Some(metered(true)), Some(RAN), Some(Vec::new())),
            reads(Some(metered(false)), Some(NEVER), Some(Vec::new())),
        ];
        assert_eq!(
            build(true, &organizations, &all, "mine", NOW).get_started,
            None
        );
        assert_eq!(
            build(true, &organizations, &all, "", NOW).get_started,
            None,
            "no remembered organization: the first"
        );
        let theirs = build(true, &organizations, &all, "theirs", NOW)
            .get_started
            .unwrap();
        assert!(!theirs.can_admin);
        assert_eq!(theirs.billing_url, "/theirs/billing/");
        assert_eq!(theirs.new_sandbox_url, "/theirs/new/");
        let view = build(true, &organizations, &all, "theirs", NOW);
        assert_eq!(
            view.organizations[1].billing_url, None,
            "members get no Billing link"
        );
        assert_eq!(view.organizations[1].role, "Member");
    }

    /// A failing organization read keeps its card, without the figures it
    /// could not read; it never takes the others with it.
    #[test]
    fn a_failing_organization_keeps_its_card_without_stats() {
        let organizations = [organization("broken", true), organization("fine", true)];
        let view = build(
            true,
            &organizations,
            &[
                reads(None, None, None),
                reads(Some(metered(true)), Some(RAN), Some(vec![hour(0, 21)])),
            ],
            "fine",
            NOW,
        );
        let broken = &view.organizations[0];
        assert_eq!(broken.stats, None);
        assert!(broken.bars.is_empty() && !broken.no_usage);
        assert_eq!(broken.sandboxes_url, "/broken/");
        assert!(view.organizations[1].stats.is_some());
        // Billing without the Sandbox list is no stats either.
        let half = build(
            true,
            &organizations[..1],
            &[reads(Some(metered(true)), None, Some(Vec::new()))],
            "",
            NOW,
        );
        assert_eq!(half.organizations[0].stats, None);
    }

    /// The last 24 hours, oldest first and the current hour last, labelled in
    /// UTC; every card on one scale.
    #[test]
    fn the_charts_cover_the_last_day_on_one_scale() {
        let organizations = [organization("busy", true), organization("quiet", false)];
        let view = build(
            true,
            &organizations,
            &[
                reads(
                    Some(metered(true)),
                    Some(RAN),
                    // The current hour, the oldest shown, and one too old.
                    Some(vec![hour(0, 84), hour(23, 21), hour(24, 999)]),
                ),
                reads(Some(metered(true)), Some(RAN), Some(vec![hour(5, 42)])),
            ],
            "busy",
            NOW,
        );
        assert!(view.shared_scale);
        let busy = &view.organizations[0].bars;
        assert_eq!(busy.len(), 24);
        assert_eq!(
            busy[23],
            UsageBar {
                x: 280,
                y: 8,
                height: 72,
                label: "15:00 UTC, €0.84".into(),
            }
        );
        assert_eq!(
            busy[0],
            UsageBar {
                x: 4,
                y: 62,
                height: 18,
                label: "16:00 UTC, €0.21".into(),
            }
        );
        assert_eq!(busy[1].height, 0);
        assert_eq!(busy[1].label, "17:00 UTC, €0.00");
        let quiet = &view.organizations[1].bars;
        assert_eq!(quiet[18].height, 36, "half the busiest hour, on its scale");
        // One chart alone is on its own scale and says nothing of others.
        let alone = build(
            true,
            &organizations[..1],
            &[reads(
                Some(metered(true)),
                Some(RAN),
                Some(vec![hour(0, 1)]),
            )],
            "",
            NOW,
        );
        assert!(!alone.shared_scale);
        assert_eq!(alone.organizations[0].bars[23].height, 72);
        // Usage that could not be read draws no chart and claims nothing.
        let unread = build(
            true,
            &organizations[..1],
            &[reads(Some(metered(true)), Some(RAN), None)],
            "",
            NOW,
        );
        assert!(unread.organizations[0].bars.is_empty());
        assert!(!unread.organizations[0].no_usage);
    }
}
