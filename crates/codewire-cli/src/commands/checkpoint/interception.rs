//! The next step for a local create, start or restore that the supervisor
//! refused for agent interception, naming its file's real path: the command
//! that changes the `egress-intercept` switch file (#3999), or, for a state
//! disk that couldn't be cleared (#6277), the one that shows in the
//! supervisor's log which step failed.

use codewire_local_vmm::supervisor_client::operation_error_code;

use super::super::native_runtime_config;

/// `error` for the operation `status` failed, carrying the command that
/// undoes or explains the refusal as its next step.
pub(in crate::commands) fn with_refusal_step(
    error: anyhow::Error,
    status: &tonic::Status,
) -> anyhow::Error {
    with_step(error, status, || {
        native_runtime_config().ok().map(|config| Files {
            switch: shell_word(&config.egress_intercept_switch().display().to_string()),
            supervisor_log: shell_word(&config.supervisor_log().display().to_string()),
        })
    })
}

/// The real files a refusal's step names, each as one shell word.
struct Files {
    switch: String,
    supervisor_log: String,
}

fn with_step(
    error: anyhow::Error,
    status: &tonic::Status,
    files: impl FnOnce() -> Option<Files>,
) -> anyhow::Error {
    let Some(code) = operation_error_code(status) else {
        return error;
    };
    let Some(step) = refusal_step(code, files) else {
        return error;
    };
    crate::error_report::with_next_step(error, step)
}

/// `path` as one shell word: as it is when every character is safe, else in
/// single quotes. Only a `CODEWIRE_NATIVE_STATE_ROOT` can put a space or a
/// metacharacter in it.
fn shell_word(path: &str) -> String {
    let safe = |byte: u8| byte.is_ascii_alphanumeric() || b"/._-+,:@%=~".contains(&byte);
    if !path.is_empty() && path.bytes().all(safe) {
        return path.to_owned();
    }
    format!("'{}'", path.replace('\'', "'\\''"))
}

/// The command that undoes or explains the refusal named by `code`.
fn refusal_step(code: &str, files: impl FnOnce() -> Option<Files>) -> Option<String> {
    // Interception is on unless the file holds exactly `off` (#3999).
    let switch_off = code.ends_with("_intercept_unavailable")
        || code.ends_with("_restore_interception_switched_on");
    if switch_off {
        return files().map(|files| format!("printf off > {}", files.switch));
    }
    if code.ends_with("_restore_interception_switched_off") {
        return files().map(|files| format!("rm {}", files.switch));
    }
    // Only the supervisor's log names the step a failed clear stopped at.
    if code.ends_with("_state_disk_not_cleared") {
        return files().map(|files| {
            format!(
                "grep 'state_disk_clear outcome=failed' {}",
                files.supervisor_log
            )
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use codewire_local_vmm::control::v1 as local;
    use codewire_local_vmm::supervisor_client::operation_outcome;

    use super::*;
    use crate::output::{Charset, Style};

    fn files() -> Option<Files> {
        Some(Files {
            switch: "/home/u/.codewire/native-v1/egress-intercept".to_owned(),
            supervisor_log: "/home/u/.codewire/native-v1/logs/supervisor.log".to_owned(),
        })
    }

    fn step(code: &str) -> Option<String> {
        refusal_step(code, files)
    }

    /// What `cw` prints for an operation the supervisor failed with `code`.
    fn printed(code: &str) -> String {
        let status = operation_outcome(local::Operation {
            operation_id: "op-1".to_owned(),
            phase: local::OperationPhase::Failed as i32,
            error_code: code.to_owned(),
            ..Default::default()
        })
        .unwrap_err();
        let error = anyhow::anyhow!("couldn't start w: {}", status.message());
        crate::error_report::render(
            &with_step(error, &status, files),
            Style::new(false, Charset::Unicode),
        )
    }

    #[test]
    fn each_refusal_names_the_command_that_undoes_it() {
        for code in [
            "start_intercept_unavailable",
            "create_intercept_unavailable",
            "start_restore_interception_switched_on",
        ] {
            assert_eq!(
                step(code).as_deref(),
                Some("printf off > /home/u/.codewire/native-v1/egress-intercept"),
                "{code}"
            );
        }
        assert_eq!(
            step("start_restore_interception_switched_off").as_deref(),
            Some("rm /home/u/.codewire/native-v1/egress-intercept")
        );
    }

    #[test]
    fn a_failed_clear_names_the_log_line_that_holds_its_step() {
        for code in [
            "start_state_disk_not_cleared",
            "create_state_disk_not_cleared",
        ] {
            assert_eq!(
                step(code).as_deref(),
                Some(
                    "grep 'state_disk_clear outcome=failed' /home/u/.codewire/native-v1/logs/supervisor.log"
                ),
                "{code}"
            );
        }
    }

    #[test]
    fn each_uncleared_disk_refusal_prints_its_code_and_its_ways_out_in_order() {
        for code in [
            "start_state_disk_not_cleared",
            "create_state_disk_not_cleared",
            "start_checkpoint_disk_uncleared",
            "create_checkpoint_disk_uncleared",
        ] {
            let text = printed(code);
            assert!(text.contains(&format!("failed: {code} (")), "{text}");
            assert!(text.contains("a platform profile refuses"), "{text}");
            let order = if code.ends_with("_state_disk_not_cleared") {
                assert!(
                    text.contains("/home/u/.codewire/native-v1/logs/supervisor.log"),
                    "{text}"
                );
                [
                    "start it again",
                    "--start-with-uncleared-disk once",
                    "recreate it",
                ]
            } else {
                [
                    "sign the provider out",
                    "--start-with-uncleared-disk once",
                    "cw checkpoint rm",
                ]
            };
            let at: Vec<usize> = order
                .iter()
                .map(|way| text.find(way).unwrap_or_else(|| panic!("{way}: {text}")))
                .collect();
            assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        }
    }

    #[test]
    fn a_path_a_shell_would_split_is_quoted() {
        assert_eq!(
            shell_word("/home/u/.codewire/native-v1/egress-intercept"),
            "/home/u/.codewire/native-v1/egress-intercept"
        );
        assert_eq!(
            shell_word("/srv/my state/egress-intercept"),
            "'/srv/my state/egress-intercept'"
        );
        assert_eq!(
            shell_word("/srv/it's/egress-intercept"),
            "'/srv/it'\\''s/egress-intercept'"
        );
    }

    #[test]
    fn any_other_failure_has_no_refusal_step() {
        for code in [
            "start_prepare_failed",
            "start_host_port_unavailable",
            "unknown",
        ] {
            assert_eq!(step(code), None, "{code}");
        }
    }
}
