//! What the running host agent last reported, for `cw host status`: one
//! owner-private file the agent rewrites on each change of state (#4438).

use std::fs;
use std::path::Path;

/// The file, in the host's directory.
pub(super) const AGENT_STATUS_FILE: &str = "host-agent.json";

/// What the running agent last reported.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentStatus {
    pub pid: u32,
    /// `attaching`, `attached`, `waiting_for_key`, `reconnecting`,
    /// `unrecognised`, `revoked` or `stopped`.
    pub state: String,
    pub detail: String,
    pub since: String,
}

pub(super) fn write_agent_status(dir: &Path, state: &str, detail: impl Into<String>) {
    let status = next_agent_status(
        read_agent_status(dir),
        std::process::id(),
        state,
        detail.into(),
        chrono::Utc::now(),
    );
    // The status file is a convenience for `cw host status`; failing to
    // write it never stops the agent.
    let _ = super::super::host::write_private_json(&dir.join(AGENT_STATUS_FILE), &status);
}

/// The status to write. `since` is when this agent entered this state: a
/// retry that writes the same state again, such as waiting for the key every
/// 30 s, keeps it whatever its detail says (#4438). A new state or a new agent
/// starts it again, so "attached since" is the latest attach.
fn next_agent_status(
    previous: Option<AgentStatus>,
    pid: u32,
    state: &str,
    detail: String,
    now: chrono::DateTime<chrono::Utc>,
) -> AgentStatus {
    let since = previous
        .filter(|previous| previous.pid == pid && previous.state == state)
        .map(|previous| previous.since)
        .unwrap_or_else(|| now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    AgentStatus {
        pid,
        state: state.into(),
        detail,
        since,
    }
}

pub(super) fn read_agent_status(dir: &Path) -> Option<AgentStatus> {
    serde_json::from_slice(&fs::read(dir.join(AGENT_STATUS_FILE)).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_status_keeps_since_while_its_state_holds() {
        let at = |s: &str| chrono::DateTime::parse_from_rfc3339(s).unwrap().to_utc();
        let waiting = next_agent_status(
            None,
            478,
            "waiting_for_key",
            "the keyring is locked".into(),
            at("2026-11-13T10:31:44Z"),
        );
        assert_eq!(waiting.since, "2026-11-13T10:31:44Z");
        // A retry, worded differently, is the same wait.
        let retry = next_agent_status(
            Some(waiting),
            478,
            "waiting_for_key",
            "still locked".into(),
            at("2026-11-13T10:38:16Z"),
        );
        assert_eq!(retry.since, "2026-11-13T10:31:44Z");
        assert_eq!(retry.detail, "still locked");
        // Each new state starts its own clock, so attached is the latest attach.
        let attaching = next_agent_status(
            Some(retry),
            478,
            "attaching",
            String::new(),
            at("2026-11-13T10:40:00Z"),
        );
        assert_eq!(attaching.since, "2026-11-13T10:40:00Z");
        let attached = next_agent_status(
            Some(attaching),
            478,
            "attached",
            String::new(),
            at("2026-11-13T10:40:02Z"),
        );
        assert_eq!(attached.since, "2026-11-13T10:40:02Z");
        let reconnecting = next_agent_status(
            Some(attached),
            478,
            "reconnecting",
            "the connection dropped".into(),
            at("2026-11-13T10:50:00Z"),
        );
        let reattached = next_agent_status(
            Some(reconnecting),
            478,
            "attached",
            String::new(),
            at("2026-11-13T10:50:05Z"),
        );
        assert_eq!(reattached.since, "2026-11-13T10:50:05Z");
        // A new agent process starts again even in the same state.
        let restarted = next_agent_status(
            Some(reattached),
            512,
            "attached",
            String::new(),
            at("2026-11-13T11:00:00Z"),
        );
        assert_eq!(restarted.since, "2026-11-13T11:00:00Z");
    }

    #[test]
    fn the_status_file_keeps_since_across_writes_of_one_state() {
        let root = tempfile::tempdir().unwrap();
        // The agent writes into its owner-private runtime directory.
        let dir = root.path().join("host");
        super::super::ensure_private_dir(&dir).unwrap();
        let dir = dir.as_path();
        write_agent_status(dir, "waiting_for_key", "locked");
        let first = read_agent_status(dir).unwrap();
        let earlier = AgentStatus {
            since: "2026-11-13T10:31:44Z".into(),
            ..first
        };
        super::super::super::host::write_private_json(&dir.join(AGENT_STATUS_FILE), &earlier)
            .unwrap();
        write_agent_status(dir, "waiting_for_key", "still locked");
        assert_eq!(
            read_agent_status(dir).unwrap().since,
            "2026-11-13T10:31:44Z"
        );
        write_agent_status(dir, "attaching", "");
        assert_ne!(
            read_agent_status(dir).unwrap().since,
            "2026-11-13T10:31:44Z"
        );
    }
}
