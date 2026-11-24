//! The front door's refusal reports, as its runner takes them (#5058).
//!
//! The front door terminates the guest's traffic, so nothing it says is
//! trusted. A report is read strictly ([`decode_report`]); one that fails, or
//! arrives past this boot's own rate, is rejected whole. A row whose host is
//! not one this runner bound for the boot is rejected alone. Every rejection
//! is counted in the log and nothing rejected is kept in part. What is kept
//! is filed under this boot, the only one whose front door holds this
//! channel, and never under a name a report gives.

use std::sync::Arc;
use std::time::Duration;

use codewire_egress_policy::intercept::InterceptSet;
use tokio::time::Instant;

use crate::broker_control::{REFUSAL_REPORT_INTERVAL, RunnerRefusalLog, now_unix_ms};
use crate::front_door::refusals::{decode_report, is_refusal_report};

/// How many reports may arrive back to back before the rate applies: the
/// front door sends at most one a second, and one can arrive late.
const REPORT_BURST: u32 = 3;

/// A boot's intake of its front door's reports, from the moment its egress
/// broker is up.
pub(crate) struct FrontDoorReports {
    log: Arc<RunnerRefusalLog>,
    intercepts: InterceptSet,
    budget: ReportBudget,
}

impl FrontDoorReports {
    /// Files into `log` the rows for a host or suffix of `intercepts`, the
    /// bindings this runner gave the boot's front door.
    pub(crate) fn new(log: Arc<RunnerRefusalLog>, intercepts: InterceptSet) -> Self {
        Self {
            log,
            intercepts,
            budget: ReportBudget::new(Instant::now()),
        }
    }

    /// Takes `message` if it is a refusal report, and says whether it was;
    /// any other message is the caller's to read.
    pub(crate) fn take(&mut self, message: &[u8]) -> bool {
        if !is_refusal_report(message) {
            return false;
        }
        if !self.budget.spend(Instant::now()) {
            self.log.reject(1);
            return true;
        }
        let Ok(report) = decode_report(message) else {
            self.log.reject(1);
            return true;
        };
        let (bound, unbound): (Vec<_>, Vec<_>) = report
            .rows
            .into_iter()
            .partition(|row| self.binds(&row.host, row.port));
        self.log
            .reject(u64::try_from(unbound.len()).unwrap_or(u64::MAX));
        self.log
            .file_intercepted(bound, report.dropped, now_unix_ms());
        true
    }

    /// Whether `host` on `port` is a binding or a suffix this runner gave
    /// the front door.
    fn binds(&self, host: &str, port: u16) -> bool {
        self.intercepts
            .bindings()
            .iter()
            .any(|binding| binding.hostname() == host && binding.port() == port)
            || self
                .intercepts
                .suffixes()
                .iter()
                .any(|suffix| suffix.suffix() == host && suffix.port() == port)
    }
}

/// Takes `message` into `reports` when it is a refusal report. A boot with
/// no log yet takes and drops it: its front door serves nothing before the
/// egress broker is up.
pub(super) fn taken(reports: &mut Option<FrontDoorReports>, message: &[u8]) -> bool {
    match reports {
        Some(reports) => reports.take(message),
        None => is_refusal_report(message),
    }
}

/// The runner's own rate for one boot's reports: a burst of
/// [`REPORT_BURST`], then one per [`REFUSAL_REPORT_INTERVAL`].
struct ReportBudget {
    available: Duration,
    at: Instant,
}

impl ReportBudget {
    fn new(now: Instant) -> Self {
        Self {
            available: REFUSAL_REPORT_INTERVAL * REPORT_BURST,
            at: now,
        }
    }

    /// Spends one report's share at `now`, or says there is none left.
    fn spend(&mut self, now: Instant) -> bool {
        self.available = (self.available + now.saturating_duration_since(self.at))
            .min(REFUSAL_REPORT_INTERVAL * REPORT_BURST);
        self.at = now;
        match self.available.checked_sub(REFUSAL_REPORT_INTERVAL) {
            Some(left) => {
                self.available = left;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
