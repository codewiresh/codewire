//! Whether an attachment takes this terminal, by the session's state.

use super::EnvironmentSessionView;

/// Whether an attachment to `session` takes this terminal: sized, raw and
/// read. An ended session is attached again only to read the output it
/// still retains, and has no PTY to size: a resize sent to it is refused as
/// a precondition, which `cw shell` then reported as an unsupported
/// operation (#5584).
pub(super) fn attaches_interactively(session: &EnvironmentSessionView) -> bool {
    session.pty && !session_is_terminal(session)
}

pub(super) fn session_is_terminal(session: &EnvironmentSessionView) -> bool {
    matches!(
        session.state.as_str(),
        "Stopped" | "Exited" | "Failed" | "Interrupted"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(name: &str, state: &str) -> EnvironmentSessionView {
        EnvironmentSessionView {
            session_id: "session-11111111-1111-4111-8111-111111111111".into(),
            name: name.into(),
            parent_session_id: String::new(),
            cleanup_unknown: false,
            started_at: String::new(),
            launch_generation: 1,
            state: state.into(),
            command: vec!["sh".into()],
            working_dir: "/workspace".into(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    /// A session that ended is attached again only to read what it retains:
    /// no terminal, so no resize its daemon would refuse (#5584).
    #[test]
    fn only_a_live_pty_session_takes_the_terminal_on_attach() {
        assert!(attaches_interactively(&session("shell", "Running")));
        for ended in ["Exited", "Stopped", "Failed", "Interrupted"] {
            assert!(!attaches_interactively(&session("shell", ended)), "{ended}");
        }
        let mut plain = session("job", "Running");
        plain.pty = false;
        assert!(!attaches_interactively(&plain));
    }
}
