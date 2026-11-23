//! `Debug` for the requests that carry a run's variables, whose `env` is
//! marked `debug_redact`, which prost's derived `Debug` ignores (#5222). A
//! variable can hold a secret `cw run --env KEY` took from the caller's own
//! environment. build.rs names each message in `skip_debug`.
//!
//! Each impl destructures its message, so a field added later must be listed
//! here before the crate compiles.

use std::fmt;

use crate::daemon::v1::{ExecStartRequest, LaunchSessionRequest, PtyStartRequest};

const REDACTED: &str = "[REDACTED]";

impl fmt::Debug for LaunchSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            command,
            working_dir,
            env: _,
            pty,
            term,
            width,
            height,
            name,
            parent_session_id,
            end_after_detached_seconds,
        } = self;
        formatter
            .debug_struct("LaunchSessionRequest")
            .field("command", command)
            .field("working_dir", working_dir)
            .field("env", &REDACTED)
            .field("pty", pty)
            .field("term", term)
            .field("width", width)
            .field("height", height)
            .field("name", name)
            .field("parent_session_id", parent_session_id)
            .field("end_after_detached_seconds", end_after_detached_seconds)
            .finish()
    }
}

impl fmt::Debug for ExecStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            command,
            working_dir,
            env: _,
        } = self;
        formatter
            .debug_struct("ExecStartRequest")
            .field("command", command)
            .field("working_dir", working_dir)
            .field("env", &REDACTED)
            .finish()
    }
}

impl fmt::Debug for PtyStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            command,
            working_dir,
            env: _,
            term,
            width,
            height,
        } = self;
        formatter
            .debug_struct("PtyStartRequest")
            .field("command", command)
            .field("working_dir", working_dir)
            .field("env", &REDACTED)
            .field("term", term)
            .field("width", width)
            .field("height", height)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::v1::{ExecMessage, PtyMessage, exec_message, pty_message};

    use super::*;

    const MARKER: &str = "synthetic-run-env-canary";

    fn env() -> Vec<String> {
        vec![format!("WALK_TOKEN={MARKER}")]
    }

    fn command() -> Vec<String> {
        vec!["visible-command".to_owned()]
    }

    /// No `Debug` of a request that carries a run's variables shows a value,
    /// nor of the stream message that holds one, and the rest still shows.
    #[test]
    fn a_runs_variables_are_never_in_debug_output() {
        let launch = LaunchSessionRequest {
            command: command(),
            env: env(),
            ..Default::default()
        };
        let exec = ExecStartRequest {
            command: command(),
            env: env(),
            ..Default::default()
        };
        let pty = PtyStartRequest {
            command: command(),
            env: env(),
            ..Default::default()
        };
        for printed in [
            format!("{launch:?}"),
            format!("{launch:#?}"),
            format!("{exec:?}"),
            format!(
                "{:?}",
                ExecMessage {
                    payload: Some(exec_message::Payload::Start(exec.clone())),
                }
            ),
            format!("{pty:?}"),
            format!(
                "{:?}",
                PtyMessage {
                    payload: Some(pty_message::Payload::Start(pty.clone())),
                }
            ),
        ] {
            assert!(!printed.contains(MARKER), "prints a value: {printed}");
            assert!(printed.contains(REDACTED), "{printed}");
            assert!(printed.contains("visible-command"), "{printed}");
        }
    }
}
