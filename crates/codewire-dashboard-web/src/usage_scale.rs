//! The euro scale beside an hourly usage chart (#4959): a few round ticks
//! from €0 up to a top at or above the chart's largest hour. Bars are drawn
//! against that top, so a bar's cost reads off the scale without hovering.
//!
//! Both charts share one geometry: the zero line at `y = 80` and the top at
//! `y = 8` of a `0 0 304 88` view box.

/// The zero line's y.
pub(crate) const ZERO_Y: i64 = 80;
/// The height from the zero line to the scale's top.
pub(crate) const PLOT_HEIGHT: i64 = 72;

// Amounts on the scale are i128: a round top above the largest i64 hour
// does not fit in an i64.
const NANO_EUR_PER_EURO: i128 = 1_000_000_000;
/// The finest step: a millionth of a euro, the finest amount the charts' bar
/// labels show.
const FINEST_STEP: i128 = 1_000;
/// At most this many steps above zero, so a chart has three or four ticks.
const MOST_STEPS: i128 = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UsageScale {
    top_nano_eur: i128,
    /// Highest first, as the scale reads down the page; the last is €0.
    pub(crate) ticks: Vec<ScaleTick>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScaleTick {
    /// Where the tick's gridline crosses the chart.
    pub(crate) y: i64,
    pub(crate) label: String,
}

impl UsageScale {
    /// The scale for a chart whose largest hour is `max_nano_eur`, or `None`
    /// when no hour cost anything.
    pub(crate) fn for_max(max_nano_eur: i64) -> Option<Self> {
        if max_nano_eur <= 0 {
            return None;
        }
        let max = i128::from(max_nano_eur);
        let step = round_steps().find(|step| steps_to(max, *step) <= MOST_STEPS)?;
        let steps = steps_to(max, step);
        let decimals = decimals(step);
        let ticks = (0..=steps)
            .rev()
            .map(|index| ScaleTick {
                y: ZERO_Y - (i128::from(PLOT_HEIGHT) * index / steps) as i64,
                label: tick_text(step * index, decimals),
            })
            .collect();
        Some(Self {
            top_nano_eur: step * steps,
            ticks,
        })
    }

    /// A bar's height for an hour that cost `nano_eur`, against the top.
    pub(crate) fn height(&self, nano_eur: i64) -> i64 {
        (i128::from(nano_eur.max(0)) * i128::from(PLOT_HEIGHT) / self.top_nano_eur) as i64
    }
}

/// 1, 2, 2.5 and 5 times each power of ten, from the finest step up to
/// €5 × 10^9, which covers any i64 hour in three steps.
fn round_steps() -> impl Iterator<Item = i128> {
    (0..16_u32).flat_map(|power| {
        let unit = FINEST_STEP * 10_i128.pow(power);
        [unit, unit * 2, unit * 5 / 2, unit * 5]
    })
}

fn steps_to(max_nano_eur: i128, step: i128) -> i128 {
    max_nano_eur / step + i128::from(max_nano_eur % step != 0)
}

/// The decimals a step needs: none for whole euros, else at least two.
fn decimals(step: i128) -> u32 {
    let mut decimals = 0;
    while step % (NANO_EUR_PER_EURO / 10_i128.pow(decimals)) != 0 {
        decimals += 1;
    }
    if decimals == 0 { 0 } else { decimals.max(2) }
}

fn tick_text(nano_eur: i128, decimals: u32) -> String {
    if nano_eur == 0 {
        return "$0".to_owned();
    }
    let whole = nano_eur / NANO_EUR_PER_EURO;
    if decimals == 0 {
        return format!("${whole}");
    }
    let fraction = nano_eur % NANO_EUR_PER_EURO / 10_i128.pow(9 - decimals);
    format!("${whole}.{fraction:0width$}", width = decimals as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CENT: i64 = 10_000_000;

    fn labels(scale: &UsageScale) -> Vec<&str> {
        scale.ticks.iter().map(|tick| tick.label.as_str()).collect()
    }

    #[test]
    fn no_cost_has_no_scale() {
        assert_eq!(UsageScale::for_max(0), None);
        assert_eq!(UsageScale::for_max(-5), None);
    }

    #[test]
    fn ticks_are_round_euros_from_the_top_down_to_zero() {
        let scale = UsageScale::for_max(84 * CENT).expect("scale");
        assert_eq!(labels(&scale), ["$1.00", "$0.50", "$0"]);
        assert_eq!(
            scale.ticks.iter().map(|tick| tick.y).collect::<Vec<_>>(),
            [8, 44, 80]
        );

        let scale = UsageScale::for_max(63 * CENT).expect("scale");
        assert_eq!(labels(&scale), ["$0.75", "$0.50", "$0.25", "$0"]);

        let scale = UsageScale::for_max(100 * CENT).expect("scale");
        assert_eq!(labels(&scale), ["$1.00", "$0.50", "$0"]);

        let scale = UsageScale::for_max(4 * 100 * CENT).expect("scale");
        assert_eq!(labels(&scale), ["$4", "$2", "$0"]);
    }

    #[test]
    fn an_hour_under_a_cent_gets_a_scale_fine_enough_to_read() {
        // Unlimited's fixture: $0.00105 an hour.
        let scale = UsageScale::for_max(1_050_000).expect("scale");
        assert_eq!(labels(&scale), ["$0.0015", "$0.0010", "$0.0005", "$0"]);

        let scale = UsageScale::for_max(1).expect("scale");
        assert_eq!(labels(&scale), ["$0.000001", "$0"]);
    }

    #[test]
    fn the_top_tick_is_at_least_the_largest_hour_and_bars_sit_on_the_scale() {
        for max in [
            1,
            999,
            1_050_000,
            21 * CENT,
            84 * CENT,
            7_777 * CENT,
            123_456_789_012,
        ] {
            let scale = UsageScale::for_max(max).expect("scale");
            assert!(scale.top_nano_eur >= i128::from(max), "{max}");
            assert!((2..=4).contains(&scale.ticks.len()), "{max}");
            assert!(scale.height(max) <= PLOT_HEIGHT);
            assert_eq!(scale.height(scale.top_nano_eur as i64), PLOT_HEIGHT);
        }
        let scale = UsageScale::for_max(84 * CENT).expect("scale");
        assert_eq!(scale.height(50 * CENT), 36);
        assert_eq!(scale.height(0), 0);
    }

    #[test]
    fn a_huge_hour_does_not_overflow() {
        let scale = UsageScale::for_max(i64::MAX).expect("scale");
        assert!(scale.height(i64::MAX) <= PLOT_HEIGHT);
    }
}
