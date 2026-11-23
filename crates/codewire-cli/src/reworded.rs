//! A server's error in `cw`'s own words. The words are the whole message, as
//! the site wrote it before, and the answer's trace id stays with them, so
//! the failure still ends with its `trace` line (docs/CONFIGURATION.md,
//! "Tracing").

use std::fmt;

/// Shows only its words, and has no source, so the server's message is
/// never printed after them.
#[derive(Debug)]
pub(crate) struct Reworded {
    text: String,
    trace_id: Option<String>,
}

impl Reworded {
    pub(crate) fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

impl fmt::Display for Reworded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Reworded {}

/// `text` in place of a server's error, keeping the id of the trace its
/// answer named: [`ClientError::trace_id`](codewire_client::ClientError::trace_id),
/// or [`crate::error_report::trace_id`] for an error already in a chain.
pub(crate) fn reworded(text: impl Into<String>, trace_id: Option<&str>) -> anyhow::Error {
    anyhow::Error::new(Reworded {
        text: text.into(),
        trace_id: trace_id.map(str::to_owned),
    })
}

/// A trace id a test's server answer names.
#[cfg(test)]
pub(crate) const TRACE_FOR_TESTS: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// A server's refusal with `reason` whose answer named [`TRACE_FOR_TESTS`].
#[cfg(test)]
pub(crate) fn answered_for_tests(
    error: connectrpc::ConnectError,
    reason: &str,
) -> codewire_client::ClientError {
    use codewire_proto::google::rpc::ErrorInfo;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-codewire-trace-id", TRACE_FOR_TESTS.parse().unwrap());
    codewire_client::ClientError::from(
        error
            .with_detail(connectrpc::ErrorDetail::from_message(
                "google.rpc.ErrorInfo",
                &ErrorInfo {
                    reason: reason.into(),
                    domain: "codewire.sh".into(),
                    ..Default::default()
                },
            ))
            .with_headers(headers),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reworded_error_shows_only_its_words_and_keeps_its_trace_id() {
        let error = reworded(
            "not sent: too many",
            Some("4bf92f3577b34da6a3ce929d0e0e4736"),
        )
        .context("send feedback");
        assert_eq!(format!("{error:#}"), "send feedback: not sent: too many");
        assert_eq!(
            crate::error_report::trace_id(&error),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        let unanswered = reworded("no answer", None);
        assert!(
            std::error::Error::source(unanswered.downcast_ref::<Reworded>().unwrap()).is_none()
        );
        assert_eq!(crate::error_report::trace_id(&unanswered), None);
    }
}
