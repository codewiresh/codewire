//! A session's short ID: the first characters of its ID, which `--session`
//! takes as a unique prefix and the session table shows for a session with
//! no name (#5085).

use super::EnvironmentSessionView;

/// How many characters of the ID the table shows, and the shortest prefix
/// `--session` accepts.
pub(in crate::commands) const SHORT_ID_LEN: usize = 8;

/// `session-cff391de-5b1c-…` as `cff391de`.
pub(in crate::commands) fn short_session_id(session_id: &str) -> &str {
    let id = session_id.strip_prefix("session-").unwrap_or(session_id);
    id.get(..SHORT_ID_LEN).unwrap_or(id)
}

/// How a session is named on screen: its name, or its short ID when it has
/// none, which `--session` accepts either way.
pub(in crate::commands) fn session_display(session: &EnvironmentSessionView) -> &str {
    if session.name.is_empty() {
        short_session_id(&session.session_id)
    } else {
        &session.name
    }
}

/// The sessions whose ID starts with `requested`, a prefix of at least
/// [`SHORT_ID_LEN`] hex characters, with or without `session-`. Anything
/// else matches none, so a name never reads as a prefix.
pub(in crate::commands) fn sessions_with_id_prefix<'a>(
    sessions: &'a [EnvironmentSessionView],
    requested: &str,
) -> Vec<&'a EnvironmentSessionView> {
    let prefix = requested
        .strip_prefix("session-")
        .unwrap_or(requested)
        .to_ascii_lowercase();
    let hex = prefix.chars().filter(char::is_ascii_hexdigit).count();
    if hex < SHORT_ID_LEN || !prefix.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Vec::new();
    }
    sessions
        .iter()
        .filter(|session| {
            session
                .session_id
                .strip_prefix("session-")
                .unwrap_or(&session.session_id)
                .to_ascii_lowercase()
                .starts_with(&prefix)
        })
        .collect()
}

/// The one session `requested` is a prefix of, or none when it is not a
/// prefix or starts several IDs.
pub(super) fn unique_id_prefix<'a>(
    sessions: &'a [EnvironmentSessionView],
    requested: &str,
) -> Option<&'a EnvironmentSessionView> {
    match sessions_with_id_prefix(sessions, requested).as_slice() {
        [session] => Some(session),
        _ => None,
    }
}

/// The refusal for a prefix several sessions' IDs start with, naming each
/// by the name or full ID `--session` takes.
pub(super) fn ambiguous_id_prefix(
    sessions: &[EnvironmentSessionView],
    requested: &str,
    environment: &str,
) -> Option<anyhow::Error> {
    let matches = sessions_with_id_prefix(sessions, requested);
    (matches.len() > 1).then(|| {
        let names: Vec<&str> = matches
            .iter()
            .map(|session| match session.name.as_str() {
                "" => session.session_id.as_str(),
                name => name,
            })
            .collect();
        crate::error_report::with_next_step(
            anyhow::anyhow!(
                "{requested:?} starts the IDs of {} sessions in {environment} ({}); give more of the ID",
                matches.len(),
                names.join(", ")
            ),
            format!("cw ls {environment}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::super::requested_environment_session;
    use super::*;

    fn session(id: &str, name: &str) -> EnvironmentSessionView {
        EnvironmentSessionView {
            name: name.to_owned(),
            parent_session_id: String::new(),
            started_at: String::new(),
            cleanup_unknown: false,
            launch_generation: 1,
            session_id: id.to_owned(),
            state: "Running".to_owned(),
            command: vec!["sh".to_owned()],
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    const SHELL: &str = "session-cff391de-5b1c-4c7e-9a40-2f6d1e0b7a11";
    const CODEX: &str = "session-e684ed7e-0d2a-4f51-8c3b-6a9e7d1f2c34";
    const TWIN: &str = "session-cff391de-0000-4000-8000-000000000000";

    #[test]
    fn a_unique_prefix_of_eight_hex_characters_selects_the_session() {
        let sessions = [session(SHELL, ""), session(CODEX, "redteam")];
        assert_eq!(short_session_id(SHELL), "cff391de");
        for requested in ["cff391de", "session-cff391de", "CFF391DE", "cff391de-5b1c"] {
            assert_eq!(
                requested_environment_session(&sessions, requested).map(|s| s.session_id.as_str()),
                Some(SHELL),
                "{requested}"
            );
        }
        // Too short, or not hex: no prefix match.
        assert!(requested_environment_session(&sessions, "cff391d").is_none());
        assert!(requested_environment_session(&sessions, "cff391dz").is_none());
        // Full IDs and names still match exactly.
        assert_eq!(
            requested_environment_session(&sessions, "redteam").map(|s| s.session_id.as_str()),
            Some(CODEX)
        );
    }

    #[test]
    fn a_prefix_two_sessions_share_selects_neither() {
        let sessions = [session(SHELL, ""), session(TWIN, "")];
        assert!(requested_environment_session(&sessions, "cff391de").is_none());
        let refusal = ambiguous_id_prefix(&sessions, "cff391de", "app").unwrap();
        assert_eq!(
            crate::error_report::sentence(&refusal),
            format!(
                "\"cff391de\" starts the IDs of 2 sessions in app ({SHELL}, {TWIN}); give more of the ID"
            )
        );
        assert_eq!(
            crate::error_report::next_step(&refusal).as_deref(),
            Some("cw ls app")
        );
        // One session: not ambiguous, and not found is said as before.
        assert!(ambiguous_id_prefix(&sessions[..1], "cff391de", "app").is_none());
        assert_eq!(
            requested_environment_session(&sessions, "cff391de-5b1c")
                .map(|s| s.session_id.as_str()),
            Some(SHELL)
        );
    }

    #[test]
    fn a_name_that_looks_like_hex_matches_by_name_first() {
        let sessions = [session(SHELL, ""), session(CODEX, "cff391de")];
        assert_eq!(
            requested_environment_session(&sessions, "cff391de").map(|s| s.session_id.as_str()),
            Some(CODEX)
        );
    }
}
