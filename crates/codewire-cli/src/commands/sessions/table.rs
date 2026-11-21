//! The session table `cw ls ENV`, `cw stop` and `cw restart` print.

use super::short_id::{session_display, short_session_id};
use super::*;

pub(in crate::commands) fn print_environment_sessions(
    sessions: &[EnvironmentSessionView],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&sessions_json(sessions)?)?
        ),
        OutputFormat::Text if sessions.is_empty() => println!("No sessions"),
        OutputFormat::Text => {
            // Only a terminal cuts COMMAND to its width; a pipe gets it whole.
            let width = std::io::stdout().is_terminal().then(|| {
                usize::from(
                    crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
                        .columns,
                )
            });
            print!("{}", format_environment_sessions(sessions, "", width));
        }
    }
    Ok(())
}

/// The narrowest COMMAND keeps, however narrow the terminal.
const MIN_COMMAND_WIDTH: usize = 12;

/// The session table's rows (#5085), shared by `cw ls ENV` and the session
/// picker, the header first: the session, by name or, without one, by the
/// short ID `--session` takes; then its state, with MODE and PARENT only when
/// a row uses them. COMMAND is kept apart, so each caller fits it its own way.
pub(in crate::commands) fn session_rows(
    sessions: &[EnvironmentSessionView],
) -> Vec<(Vec<String>, String)> {
    let parent = |session: &EnvironmentSessionView| match session.parent_session_id.as_str() {
        "" => "-".to_owned(),
        id => sessions
            .iter()
            .find(|candidate| candidate.session_id == id && !candidate.name.is_empty())
            .map_or_else(
                || short_session_id(id).to_owned(),
                |candidate| candidate.name.clone(),
            ),
    };
    let with_mode = sessions
        .iter()
        .any(|session| session_mode(session) != "normal");
    let with_parent = sessions
        .iter()
        .any(|session| !session.parent_session_id.is_empty());
    let mut header = vec!["SESSION", "STATE"];
    header.extend(with_mode.then_some("MODE"));
    header.extend(with_parent.then_some("PARENT"));
    std::iter::once((
        header.into_iter().map(String::from).collect(),
        "COMMAND".to_owned(),
    ))
    .chain(sessions.iter().map(|session| {
        let mut cells = vec![session_display(session).to_owned(), session.state.clone()];
        cells.extend(with_mode.then(|| session_mode(session).to_owned()));
        cells.extend(with_parent.then(|| parent(session)));
        (cells, session_command_label(session))
    }))
    .collect()
}

/// Aligned [`session_rows`]: COMMAND last, cut with `…` to `width` when a
/// terminal gives one, so a wider terminal shows more.
pub(in crate::commands) fn format_environment_sessions(
    sessions: &[EnvironmentSessionView],
    indent: &str,
    width: Option<usize>,
) -> String {
    let rows = session_rows(sessions);
    let widths: Vec<usize> = (0..rows[0].0.len())
        .map(|column| {
            rows.iter()
                .map(|(cells, _)| cells[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let command_width = width.map(|width| {
        let used = indent.chars().count() + widths.iter().map(|width| width + 2).sum::<usize>();
        width.saturating_sub(used).max(MIN_COMMAND_WIDTH)
    });
    let mut output = String::new();
    for (cells, command) in &rows {
        output.push_str(indent);
        for (cell, width) in cells.iter().zip(&widths) {
            output.push_str(&format!("{cell:<width$}  "));
        }
        output.push_str(&fit(command, command_width));
        output.push('\n');
    }
    output
}

/// `text` cut to `width` characters, the last one `…`.
fn fit(text: &str, width: Option<usize>) -> String {
    match width {
        Some(width) if text.chars().count() > width => {
            let kept: String = text.chars().take(width.saturating_sub(1)).collect();
            format!("{kept}…")
        }
        _ => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, name: &str, state: &str, command: &[&str]) -> EnvironmentSessionView {
        EnvironmentSessionView {
            name: name.to_owned(),
            parent_session_id: String::new(),
            started_at: String::new(),
            cleanup_unknown: false,
            launch_generation: 1,
            session_id: id.to_owned(),
            state: state.to_owned(),
            command: command.iter().map(|word| (*word).to_owned()).collect(),
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    /// The owner's `cw ls redteam-codex-handoff` (#5085): an unnamed
    /// dashboard shell and Codex resumed with a long prompt.
    fn owners_sessions() -> [EnvironmentSessionView; 2] {
        [
            session(
                "session-cff391de-5b1c-4c7e-9a40-2f6d1e0b7a11",
                "",
                "Interrupted",
                &["/bin/sh", "-c", DASHBOARD_SHELL],
            ),
            session(
                "session-e684ed7e-0d2a-4f51-8c3b-6a9e7d1f2c34",
                "redteam",
                "Running",
                &[
                    "codex",
                    "resume",
                    "--last",
                    "Continue the redteam archive-v0 work. Read the handoff notes first, then finish the remaining cases and report.",
                ],
            ),
        ]
    }

    #[test]
    fn the_session_comes_first_and_command_is_cut_to_the_terminal() {
        let sessions = owners_sessions();
        let rendered = format_environment_sessions(&sessions, "", Some(100));
        assert_eq!(
            rendered,
            concat!(
                "SESSION   STATE        COMMAND\n",
                "cff391de  Interrupted  bash\n",
                "redteam   Running      codex resume --last Continue the redteam archive-v0 work. Read the handoff n…\n",
            )
        );
        assert!(
            rendered.lines().all(|line| line.chars().count() <= 100),
            "{rendered}"
        );
        // The nameless row's short ID is one `--session` takes.
        assert_eq!(
            requested_environment_session(&sessions, "cff391de").map(|s| s.session_id.as_str()),
            Some(sessions[0].session_id.as_str())
        );
        // A wider terminal shows more of it, and a pipe all of it.
        let wide = format_environment_sessions(&sessions, "", Some(140));
        assert!(wide.contains("then finish the remaining ca…\n"), "{wide}");
        let piped = format_environment_sessions(&sessions, "", None);
        assert!(
            piped.contains("finish the remaining cases and report.\n"),
            "{piped}"
        );
        // However narrow the terminal, the command keeps a readable stub.
        let narrow = format_environment_sessions(&sessions, "", Some(40));
        assert!(narrow.contains("codex resume --l…\n"), "{narrow}");
    }

    #[test]
    fn mode_shows_only_when_a_session_is_managed() {
        let mut sessions = owners_sessions().to_vec();
        assert!(!format_environment_sessions(&sessions, "", None).contains("MODE"));
        sessions[1].command = vec!["cw".to_owned(), "_agent-driver".to_owned()];
        let managed = format_environment_sessions(&sessions, "", None);
        assert!(managed.starts_with("SESSION  "), "{managed}");
        assert!(
            managed.lines().next().unwrap().contains("MODE"),
            "{managed}"
        );
        assert!(managed.contains("managed"), "{managed}");
    }
}
