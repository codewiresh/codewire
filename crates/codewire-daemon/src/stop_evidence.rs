//! What a host daemon writes before it signals a session, so a managed
//! conversation's driver can tell what its stop signal means by reading the
//! disk, whatever became of the conversation's record helper.
//!
//! The daemon signals a session for two reasons and writes one record first
//! for each:
//!
//! - **The whole environment is being taken down:** [`SHUTDOWN_MARKER`] in
//!   the environment's state root. `cw stop ENV`, `restart` and `rm` write it
//!   to ask the daemon to stop. The daemon writes it itself before it cancels
//!   a launch or stops a session for any other shutdown, and removes it when
//!   it starts.
//! - **A client stopped or restarted the session:** a stop intent in the
//!   session's own directory. The conversation's next start acts on it and
//!   clears it.
use std::io::Write;
use std::path::{Path, PathBuf};

/// The environment's takedown marker, in its state root.
pub const SHUTDOWN_MARKER: &str = "shutdown.json";
/// An explicit stop's intent, in the session's directory.
pub(crate) const STOP_INTENT_FILE: &str = "stop-intent.json";

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Marks the environment as being taken down. A marker that is already
/// there is left as it is.
pub fn mark_takedown(state_root: &Path) -> std::io::Result<()> {
    if takedown_marked(state_root) {
        return Ok(());
    }
    write_private(&state_root.join(SHUTDOWN_MARKER), b"true")
}

/// Whether the environment is being taken down, or was and has not started
/// again.
pub fn takedown_marked(state_root: &Path) -> bool {
    state_root.join(SHUTDOWN_MARKER).is_file()
}

/// `None` for an ID that is no session's: it names no directory.
fn stop_intent_path(state_root: &Path, session_id: &str) -> Option<PathBuf> {
    let canonical = session_id
        .strip_prefix("session-")
        .and_then(|id| uuid::Uuid::parse_str(id).ok().map(|uuid| (id, uuid)))
        .is_some_and(|(id, uuid)| uuid.to_string() == id);
    canonical.then(|| {
        state_root
            .join("sessions")
            .join(session_id)
            .join(STOP_INTENT_FILE)
    })
}

/// Records that a client explicitly stopped or restarted the session. Only
/// the host daemon calls it, before anything of that stop can signal the
/// session.
pub fn record_stop_intent(state_root: &Path, session_id: &str) -> std::io::Result<()> {
    let path = stop_intent_path(state_root, session_id)
        .ok_or_else(|| std::io::Error::other("the session identifier is not canonical"))?;
    write_private(&path, b"true")
}

/// Whether an explicit stop or restart of the session is recorded and no
/// start of its conversation has acted on it yet.
pub fn stop_intended(state_root: &Path, session_id: &str) -> bool {
    stop_intent_path(state_root, session_id).is_some_and(|path| path.is_file())
}

/// A conversation's start has acted on the stop intent. Clearing one that is
/// not there succeeds.
pub fn clear_stop_intent(state_root: &Path, session_id: &str) -> std::io::Result<()> {
    let Some(path) = stop_intent_path(state_root, session_id) else {
        return Ok(());
    };
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "session-6f2f3c0e-5a0b-4f58-9d5c-0c9b8f6f1a11";

    #[test]
    fn a_stop_intent_is_recorded_read_and_cleared_in_the_sessions_own_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("sessions").join(SESSION)).unwrap();
        assert!(!stop_intended(root, SESSION));
        clear_stop_intent(root, SESSION).unwrap();

        record_stop_intent(root, SESSION).unwrap();
        record_stop_intent(root, SESSION).unwrap();
        assert!(stop_intended(root, SESSION));
        let path = root.join("sessions").join(SESSION).join(STOP_INTENT_FILE);
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        clear_stop_intent(root, SESSION).unwrap();
        assert!(!stop_intended(root, SESSION) && !path.exists());
        clear_stop_intent(root, SESSION).unwrap();

        // An ID that is no session's names no path, and a session without a
        // directory cannot be recorded as stopped.
        for id in ["session", "../session", "session-not-a-uuid", ""] {
            assert!(!stop_intended(root, id), "{id}");
            assert!(record_stop_intent(root, id).is_err(), "{id}");
            clear_stop_intent(root, id).unwrap();
        }
        let other = "session-00000000-0000-4000-8000-000000000000";
        assert!(record_stop_intent(root, other).is_err());
    }

    #[test]
    fn a_takedown_is_marked_once_and_an_existing_marker_is_kept() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        assert!(!takedown_marked(root));
        mark_takedown(root).unwrap();
        assert!(takedown_marked(root));
        // `cw stop ENV` wrote its own: it is left as it is.
        std::fs::write(root.join(SHUTDOWN_MARKER), b"true\n").unwrap();
        mark_takedown(root).unwrap();
        assert_eq!(
            std::fs::read(root.join(SHUTDOWN_MARKER)).unwrap(),
            b"true\n"
        );
        assert!(mark_takedown(&root.join("absent")).is_err());
    }
}
