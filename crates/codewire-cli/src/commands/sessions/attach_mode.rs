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

/// Whose attachment it is, which says how it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttachKind {
    /// A plain `cw shell`: every key goes to the session, so it can neither
    /// detach nor move to another session, and it ends with its shell.
    Shell,
    /// A foreground `cw run`: it ends with its command (#6355).
    Run,
    /// `cw attach`: an ended session stays on screen and offers a restart.
    Attach,
}

impl AttachKind {
    pub(super) fn plain(self) -> bool {
        self == Self::Shell
    }

    /// Whether the attachment ends when its program does. Only `cw attach`
    /// at a terminal stays, to offer a restart; with no terminal there is
    /// nothing to offer it on.
    pub(super) fn ends_with_program(self, interactive: bool) -> bool {
        !interactive || self != Self::Attach
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell and a foreground run end with their program; only `cw
    /// attach` at a terminal stays to offer a restart (#6355).
    #[test]
    fn only_attach_at_a_terminal_outlives_its_program() {
        for kind in [AttachKind::Shell, AttachKind::Run, AttachKind::Attach] {
            assert!(kind.ends_with_program(false), "{kind:?}");
        }
        assert!(AttachKind::Shell.ends_with_program(true));
        assert!(AttachKind::Run.ends_with_program(true));
        assert!(!AttachKind::Attach.ends_with_program(true));
        assert!(AttachKind::Shell.plain());
        assert!(!AttachKind::Run.plain() && !AttachKind::Attach.plain());
    }

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
