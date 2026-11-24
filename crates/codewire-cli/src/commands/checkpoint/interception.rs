//! The next step for a local create, start or restore that the
//! `egress-intercept` switch refused (#3999): the command that changes the
//! switch file, with its real path.

use codewire_local_vmm::supervisor_client::operation_error_code;

use super::super::native_runtime_config;

/// `error` for the operation `status` failed, carrying the switch command
/// as its next step when the switch refused it.
pub(in crate::commands) fn with_switch_step(
    error: anyhow::Error,
    status: &tonic::Status,
) -> anyhow::Error {
    let Some(code) = operation_error_code(status) else {
        return error;
    };
    let Some(step) = switch_step(code, || {
        native_runtime_config()
            .ok()
            .map(|config| shell_word(&config.egress_intercept_switch().display().to_string()))
    }) else {
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

/// The command that undoes the switch's refusal named by `code`, given the
/// switch file's path as a shell word.
fn switch_step(code: &str, switch: impl FnOnce() -> Option<String>) -> Option<String> {
    // Interception is on unless the file holds exactly `off` (#3999).
    let switch_off = code.ends_with("_intercept_unavailable")
        || code.ends_with("_restore_interception_switched_on");
    if switch_off {
        return switch().map(|path| format!("printf off > {path}"));
    }
    if code.ends_with("_restore_interception_switched_off") {
        return switch().map(|path| format!("rm {path}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(code: &str) -> Option<String> {
        switch_step(code, || {
            Some("/home/u/.codewire/native-v1/egress-intercept".to_owned())
        })
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
    fn any_other_failure_has_no_switch_step() {
        for code in [
            "start_prepare_failed",
            "start_host_port_unavailable",
            "unknown",
        ] {
            assert_eq!(step(code), None, "{code}");
        }
    }
}
