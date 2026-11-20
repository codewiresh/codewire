//! A location that could not be listed: what it says, and the step that
//! recovers it when a retry would fail the same way (#3548, #5559).

use super::{EnvironmentInventory, Location, LocationStatus};

impl EnvironmentInventory {
    /// Reports `location` as unavailable: `recovery`'s summary and step when
    /// the failure names one, else the error's chain, after which a retry
    /// is offered.
    pub(super) fn report_failure(
        &mut self,
        location: Location,
        recovery: Option<(String, String)>,
        error: &anyhow::Error,
    ) {
        match recovery {
            Some((summary, step)) => {
                self.report(location, LocationStatus::Unavailable(summary));
                self.recoveries.push((location, step));
            }
            None => self.report(location, LocationStatus::Unavailable(format!("{error:#}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Charset, Style};

    #[test]
    fn a_refused_credential_is_recovered_by_its_step_not_a_retry() {
        let error = crate::error_report::refused_for_tests(true).context("list orgs");
        let mut inventory = EnvironmentInventory::default();
        inventory.report_failure(
            Location::Cloud,
            crate::error_report::refused_recovery(&error),
            &error,
        );
        let text = super::super::format_unavailable(
            &inventory.unavailable(),
            &inventory.recoveries,
            false,
            Style::new(false, Charset::Unicode),
        );
        assert_eq!(
            text,
            "! Cloud environments could not be listed: the API key in CODEWIRE_API_KEY is no longer accepted\n\
             → set CODEWIRE_API_KEY to a current key, or unset it and run cw login\n"
        );
    }

    #[test]
    fn any_other_failure_keeps_its_chain_and_the_retry() {
        let error = anyhow::anyhow!("connection refused").context("list orgs");
        let mut inventory = EnvironmentInventory::default();
        inventory.report_failure(Location::Cloud, None, &error);
        let text = super::super::format_unavailable(
            &inventory.unavailable(),
            &inventory.recoveries,
            false,
            Style::new(false, Charset::Unicode),
        );
        assert!(
            text.contains("could not be listed: list orgs: connection refused\n"),
            "{text}"
        );
        assert!(text.contains("Retry: cw --cloud ls"), "{text}");
    }
}
