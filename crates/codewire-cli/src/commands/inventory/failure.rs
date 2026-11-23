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
        if let Some(trace_id) = crate::error_report::trace_id(error) {
            self.trace_ids.push((location, trace_id.to_owned()));
        }
        match recovery {
            Some((summary, step)) => {
                self.report(location, LocationStatus::Unavailable(summary));
                self.recoveries.push((location, step));
            }
            None => self.report(location, LocationStatus::Unavailable(format!("{error:#}"))),
        }
    }

    /// The first location that could not be listed, as a command's error. It
    /// keeps the id of the trace that listing's answer named.
    pub(crate) fn listing_failure(&self) -> Option<anyhow::Error> {
        let (location, reason) = self.unavailable().into_iter().next()?;
        let trace_id = self
            .trace_ids
            .iter()
            .find(|(failed, _)| *failed == location)
            .map(|(_, trace_id)| trace_id.as_str());
        Some(crate::reworded::reworded(
            format!("couldn't list {}: {reason}", location.listing()),
            trace_id,
        ))
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

    #[test]
    fn a_failed_listing_keeps_its_trace_id() {
        use crate::error_report::trace_id;
        use crate::reworded::{TRACE_FOR_TESTS, answered_for_tests};
        let answered = anyhow::Error::new(answered_for_tests(
            connectrpc::ConnectError::unavailable("connection closed"),
            "OTHER",
        ))
        .context("list orgs");
        let mut inventory = EnvironmentInventory::default();
        inventory.report(Location::Local, LocationStatus::Listed);
        inventory.report_failure(Location::Cloud, None, &answered);
        let failure = inventory.listing_failure().unwrap();
        assert_eq!(
            failure.to_string(),
            "couldn't list cloud environments: list orgs: connection closed"
        );
        assert_eq!(trace_id(&failure), Some(TRACE_FOR_TESTS));

        let mut unanswered = EnvironmentInventory::default();
        unanswered.report_failure(
            Location::Cloud,
            None,
            &anyhow::anyhow!("connection refused"),
        );
        assert_eq!(trace_id(&unanswered.listing_failure().unwrap()), None);
        assert!(EnvironmentInventory::default().listing_failure().is_none());
    }
}
