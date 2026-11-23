//! Server errors this command family puts in its own words. Each keeps the
//! id of the trace its answer named (docs/CONFIGURATION.md, "Tracing").

use super::lifecycle;
use crate::error_report::trace_id;
use crate::reworded::reworded;

/// A delete refusal or failure, with its repair. A scheduled deletion is
/// not an error; [`lifecycle::delete_was_scheduled`] recognises it first.
pub(crate) fn map_env_delete_error(environment_ref: &str, err: anyhow::Error) -> anyhow::Error {
    let trace_id = trace_id(&err);
    if lifecycle::error_has_reason(&err, "environment_protected") {
        return reworded(
            format!(
                "environment {environment_ref} is protected, so nothing was removed; remove the protection first with `cw --cloud unprotect {environment_ref}`"
            ),
            trace_id,
        );
    }
    if lifecycle::error_has_reason(&err, "access_denied") {
        return reworded(
            "access denied: only the environment owner can delete it",
            trace_id,
        );
    }
    reworded(format!("delete environment: {err:#}"), trace_id)
}

/// A create's failure: the one refusal when the server has network policies
/// turned off, otherwise `create environment` and the error.
pub(super) fn create_failed(error: anyhow::Error) -> anyhow::Error {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<codewire_client::ClientError>())
        .find_map(crate::commands::policy::policies_disabled)
        .unwrap_or_else(|| error.context("create environment"))
}

/// A cloud publish refused because the port is already published, as a
/// local one is refused; any other failure, a label in use included, as it
/// came.
pub(super) fn port_create_failed(
    name: &str,
    port: u16,
    labelled: bool,
    error: anyhow::Error,
) -> anyhow::Error {
    if !labelled && lifecycle::error_has_reason(&error, "port_conflict") {
        return crate::commands::lifecycle_output::port_already_published(
            crate::output::VmLocation::Cloud,
            name,
            port,
            trace_id(&error),
        );
    }
    error.context("create port")
}

/// Selecting an environment's network policy, refused or failed.
pub(super) fn network_policy_selection(error: codewire_client::ClientError) -> anyhow::Error {
    crate::commands::policy::policies_disabled(&error).unwrap_or_else(|| {
        reworded(
            format!("select the network policy: {}", error.message()),
            error.trace_id(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::reworded::{TRACE_FOR_TESTS as TRACE, answered_for_tests as answered};

    #[test]
    fn a_delete_refusal_in_cws_words_keeps_its_trace_id() {
        let cases = [
            (
                answered(
                    connectrpc::ConnectError::failed_precondition("protected"),
                    "ENVIRONMENT_PROTECTED",
                ),
                "environment app is protected, so nothing was removed; remove the protection first with `cw --cloud unprotect app`",
            ),
            (
                answered(
                    connectrpc::ConnectError::permission_denied("owners only"),
                    "ACCESS_DENIED",
                ),
                "access denied: only the environment owner can delete it",
            ),
            (
                answered(connectrpc::ConnectError::internal("storage error"), "OTHER"),
                "delete environment: storage error",
            ),
        ];
        for (error, text) in cases {
            let mapped = map_env_delete_error("app", error.into());
            assert_eq!(mapped.to_string(), text);
            assert_eq!(trace_id(&mapped), Some(TRACE), "{text}");
        }
        let local = map_env_delete_error("app", anyhow::anyhow!("no answer"));
        assert_eq!(trace_id(&local), None);
    }

    #[test]
    fn a_network_policy_refusal_in_cws_words_keeps_its_trace_id() {
        let disabled = network_policy_selection(answered(
            connectrpc::ConnectError::failed_precondition("disabled"),
            "NETWORK_POLICIES_DISABLED",
        ));
        assert_eq!(
            crate::error_report::sentence(&disabled),
            "network policies are turned off on this Codewire server; a local VM can still use one"
        );
        assert_eq!(
            crate::error_report::next_step(&disabled).as_deref(),
            Some("cw --local policy")
        );
        assert_eq!(trace_id(&disabled), Some(TRACE));
        let other = network_policy_selection(answered(
            connectrpc::ConnectError::not_found("no such policy"),
            "OTHER",
        ));
        assert_eq!(
            other.to_string(),
            "select the network policy: no such policy"
        );
        assert_eq!(trace_id(&other), Some(TRACE));
    }
}
