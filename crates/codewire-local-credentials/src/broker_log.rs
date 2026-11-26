//! The authority's durable record of its credential broker children (#2763).
//!
//! A broker may end without a word, and the authority restarts it on a
//! backoff. This log keeps one line per lifecycle event under the credential
//! root (`logs/brokers.log`, 0600) so a failing environment can be diagnosed
//! from the product: when a child started, whether it became ready, and how
//! it ended (exit code or signal, the lease channel's typed outcome, the
//! restart delay chosen, and the broker's own exit line). Only fixed event
//! names, identifiers, durations and typed outcomes are written. Of a child's
//! stderr, a pipe the authority drains, only its `CW_BROKER_EXIT stage=…
//! kind=…` line is kept, both fixed names, and any run of 20 or more token
//! characters in it is redacted besides; never request contents, error
//! messages, credential values or other child output. Writing is best effort
//! and never affects the broker.
//!
//! While a broker runs, its refusals to deliver an agent's login are kept too
//! (`claude_login_refused` and `codex_login_refused`), so a VM whose agent is
//! not logged in says why. The broker writes `CW_BROKER_LOGIN_REFUSED
//! agent=<agent> reason=<reason>`; only a line whose agent and reason are
//! both in the closed sets below is recorded, with the environment,
//! generation and pid this authority already knows, at most once per reason
//! and child in [`LOGIN_REFUSAL_INTERVAL`], counting the ones held back.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The file starts over (keeping one previous file) beyond this size.
const MAX_BYTES: u64 = 1024 * 1024;
const FILE: &str = "brokers.log";

pub(crate) struct BrokerLog {
    path: Option<PathBuf>,
    write: Mutex<()>,
}

impl BrokerLog {
    /// `logs/brokers.log` under the credential root.
    pub(crate) fn in_root(root: &Path) -> Self {
        Self {
            path: Some(root.join("logs").join(FILE)),
            write: Mutex::new(()),
        }
    }

    /// Records nothing.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            path: None,
            write: Mutex::new(()),
        }
    }

    /// Appends `time_unix_ms=… event=<event> <key>=<value>…`. Values are
    /// written as given after any byte outside `[A-Za-z0-9._:/-]` becomes
    /// `_`, so a line stays one line of plain fields.
    pub(crate) fn record(&self, event: &str, fields: &[(&str, &dyn std::fmt::Display)]) {
        let Some(path) = &self.path else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        let mut line = format!("time_unix_ms={now} event={}", plain(event));
        for (key, value) in fields {
            line.push(' ');
            line.push_str(&plain(key));
            line.push('=');
            line.push_str(&plain(&value.to_string()));
        }
        line.push('\n');
        let _guard = self.write.lock();
        let _ = append(path, line.as_bytes());
    }
}

fn plain(value: &str) -> String {
    value
        .chars()
        .take(240)
        .map(|character| {
            if character.is_ascii_alphanumeric() || "._:/-".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn append(path: &Path, line: &[u8]) -> std::io::Result<()> {
    if let Some(directory) = path.parent() {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.len() > MAX_BYTES) {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(line)
}

/// The last bytes a broker child wrote to its stderr pipe. A task drains
/// the pipe so the child can never block on it, keeping only the tail.
pub(crate) struct StderrTail {
    tail: std::sync::Arc<Mutex<Vec<u8>>>,
    reader: Option<tokio::task::JoinHandle<()>>,
}

const TAIL_BYTES: usize = 4096;
/// The line a local broker writes when it refuses to deliver an agent's login.
pub const AGENT_LOGIN_REFUSED_MARKER: &str = "CW_BROKER_LOGIN_REFUSED";
/// The agents whose login a broker may refuse.
pub const AGENT_LOGIN_REFUSAL_AGENTS: &[&str] = &["antigravity", "claude", "codex"];
/// Every reason a broker gives for refusing an agent's login. A broker that
/// adds a reason adds it here: its own test refuses a reason missing from
/// this list, and this log ignores one.
pub const AGENT_LOGIN_REFUSAL_REASONS: &[&str] = &[
    "deadline_passed_before_seal",
    "scopes_outside_sign_in",
    // Beside an environment's front door (#3999): it is not paired, or the
    // agent's login has no placeholder to deliver.
    "front_door_not_paired",
    "no_placeholder_beside_front_door",
];
/// One line per reason and child at most this often: the guest asks for a
/// login every two minutes, so a lasting refusal would otherwise repeat.
pub(crate) const LOGIN_REFUSAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// A longer stderr line is not a refusal line and is never looked at.
const REFUSAL_LINE_BYTES: usize = 128;
/// The one line of a broker's stderr the log keeps (see the broker's
/// `BROKER_EXIT_MARKER`).
const EXIT_MARKER: &str = "CW_BROKER_EXIT ";
/// A run of token characters this long is redacted from what is logged.
const REDACT_RUN: usize = 20;
/// How long an exited child's pipe may take to reach end of file.
const EXITED_DRAIN: std::time::Duration = std::time::Duration::from_millis(250);

impl BrokerLog {
    /// The stderr tail of broker `pid` for one environment generation, which
    /// also records the broker's login refusals as they arrive.
    pub(crate) fn tail(
        self: &std::sync::Arc<Self>,
        stderr: tokio::process::ChildStderr,
        environment: &impl std::fmt::Display,
        generation: u64,
        pid: Option<u32>,
    ) -> StderrTail {
        StderrTail::spawn_reporting(
            stderr,
            Some(LoginRefusals {
                log: std::sync::Arc::clone(self),
                environment: environment.to_string(),
                generation,
                pid: pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
                line: Vec::new(),
                last: std::collections::HashMap::new(),
            }),
        )
    }
}

/// A running broker's login refusals, recorded as its stderr arrives.
struct LoginRefusals {
    log: std::sync::Arc<BrokerLog>,
    environment: String,
    generation: u64,
    pid: String,
    /// The current line, while it can still be a refusal line.
    line: Vec<u8>,
    /// Per agent and reason: when it was last recorded, and how many were
    /// held back since.
    last: std::collections::HashMap<(&'static str, &'static str), (std::time::Instant, u64)>,
}

impl LoginRefusals {
    fn read(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.line);
                if let Some((agent, reason)) = refusal_line(&line) {
                    self.refused(agent, reason, std::time::Instant::now());
                }
            } else if self.line.len() <= REFUSAL_LINE_BYTES {
                self.line.push(byte);
            }
        }
    }

    fn refused(&mut self, agent: &'static str, reason: &'static str, now: std::time::Instant) {
        if let Some((at, held)) = self.last.get_mut(&(agent, reason))
            && now.duration_since(*at) < LOGIN_REFUSAL_INTERVAL
        {
            *held += 1;
            return;
        }
        let held = self
            .last
            .insert((agent, reason), (now, 0))
            .map_or(0, |(_, held)| held);
        self.log.record(
            &format!("{agent}_login_refused"),
            &[
                ("environment", &self.environment),
                ("generation", &self.generation),
                ("pid", &self.pid),
                ("reason", &reason),
                ("held_back", &held),
            ],
        );
    }
}

/// The agent and reason of a broker's refusal line, both from the closed
/// sets; anything else is not one.
fn refusal_line(line: &[u8]) -> Option<(&'static str, &'static str)> {
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut words = line.split(' ');
    if words.next()? != AGENT_LOGIN_REFUSED_MARKER {
        return None;
    }
    let agent = words.next()?.strip_prefix("agent=")?;
    let reason = words.next()?.strip_prefix("reason=")?;
    if words.next().is_some() {
        return None;
    }
    let agent = AGENT_LOGIN_REFUSAL_AGENTS
        .iter()
        .find(|known| **known == agent)?;
    let reason = AGENT_LOGIN_REFUSAL_REASONS
        .iter()
        .find(|known| **known == reason)?;
    Some((agent, reason))
}

impl StderrTail {
    /// A tail that records nothing as it reads.
    #[cfg(test)]
    pub(crate) fn spawn(stderr: tokio::process::ChildStderr) -> Self {
        Self::spawn_reporting(stderr, None)
    }

    fn spawn_reporting(
        mut stderr: tokio::process::ChildStderr,
        mut refusals: Option<LoginRefusals>,
    ) -> Self {
        use tokio::io::AsyncReadExt as _;
        let tail = std::sync::Arc::new(Mutex::new(Vec::new()));
        let shared = std::sync::Arc::clone(&tail);
        let reader = tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            while let Ok(count) = stderr.read(&mut buffer).await {
                if count == 0 {
                    break;
                }
                if let Some(refusals) = &mut refusals {
                    refusals.read(&buffer[..count]);
                }
                let mut tail = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                tail.extend_from_slice(&buffer[..count]);
                if tail.len() > TAIL_BYTES {
                    let excess = tail.len() - TAIL_BYTES;
                    tail.drain(..excess);
                }
            }
        });
        Self {
            tail,
            reader: Some(reader),
        }
    }

    /// The fields of the broker's last exit line, if it wrote one; for an
    /// exited child, after its pipe reaches end of file (bounded). Any other
    /// output is ignored.
    pub(crate) async fn exit_line(&mut self, exited: bool) -> String {
        if exited && let Some(reader) = self.reader.take() {
            let _ = tokio::time::timeout(EXITED_DRAIN, reader).await;
        }
        let tail = self
            .tail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let text = String::from_utf8_lossy(&tail);
        text.lines()
            .rev()
            .find_map(|line| line.trim().strip_prefix(EXIT_MARKER))
            .map(redact_long_runs)
            .unwrap_or_default()
    }
}

/// Replaces each run of `REDACT_RUN` or more `[A-Za-z0-9_-]` characters, the
/// alphabet of tokens and keys, so no such value can reach the log.
fn redact_long_runs(text: &str) -> String {
    fn flush(run: &mut String, output: &mut String) {
        if run.chars().count() >= REDACT_RUN {
            output.push_str("REDACTED");
        } else {
            output.push_str(run);
        }
        run.clear();
    }
    let mut output = String::with_capacity(text.len());
    let mut run = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            run.push(character);
        } else {
            flush(&mut run, &mut output);
            output.push(character);
        }
    }
    flush(&mut run, &mut output);
    output
}

/// How a child process ended, for the log.
pub(crate) fn exit_status(status: Option<std::process::ExitStatus>) -> String {
    use std::os::unix::process::ExitStatusExt as _;
    match status {
        None => "running".to_owned(),
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit:{code}"),
            (None, Some(signal)) => format!("signal:{signal}"),
            (None, None) => "unknown".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_one_plain_line_per_event_in_a_private_file() {
        let root = tempfile::tempdir().unwrap();
        let log = BrokerLog::in_root(root.path());
        log.record(
            "broker_ended",
            &[
                ("environment", &"0f8e…\nforged=1"),
                ("status", &exit_status(None)),
                ("ran_ms", &1234_u128),
            ],
        );
        log.record("broker_spawned", &[("pid", &42_u32)]);
        let path = root.path().join("logs/brokers.log");
        let text = fs::read_to_string(&path).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[0].contains(
                " event=broker_ended environment=0f8e__forged_1 status=running ran_ms=1234"
            )
        );
        assert!(lines[1].ends_with(" event=broker_spawned pid=42"));
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        BrokerLog::disabled().record("ignored", &[]);
    }

    #[tokio::test]
    async fn keeps_only_an_exited_brokers_exit_line_and_redacts_token_runs() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'Error: secret ghu_0123456789abcdefghij\\n\\nCW_BROKER_EXIT stage=bridge.run kind=bridge.unavailable\\nnoise\\n' >&2; exit 1",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut tail = StderrTail::spawn(child.stderr.take().unwrap());
        let status = child.wait().await.unwrap();
        assert_eq!(exit_status(Some(status)), "exit:1");
        assert_eq!(
            tail.exit_line(true).await,
            "stage=bridge.run kind=bridge.unavailable"
        );

        let mut silent = tokio::process::Command::new("/bin/sh")
            .args(["-c", "echo 'Error: sk-0123456789abcdefghijklmn' >&2"])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut tail = StderrTail::spawn(silent.stderr.take().unwrap());
        silent.wait().await.unwrap();
        assert_eq!(tail.exit_line(true).await, "", "other output is never kept");

        assert_eq!(
            redact_long_runs("stage=x kind=ghu_0123456789abcdefghij/sk-ABCDEFGHIJKLMNOPQRSTU"),
            "stage=x kind=REDACTED/REDACTED"
        );
        assert_eq!(
            redact_long_runs("stage=lease.refresh_in_progress kind=status.failed_precondition"),
            "stage=lease.refresh_in_progress kind=status.failed_precondition"
        );
    }

    /// Only the marker with an agent and a reason from the closed sets, and
    /// nothing after them, is a refusal line.
    #[test]
    fn a_refusal_line_is_the_marker_with_known_words_only() {
        let line = |text: &str| refusal_line(text.as_bytes());
        assert_eq!(
            line("CW_BROKER_LOGIN_REFUSED agent=claude reason=scopes_outside_sign_in"),
            Some(("claude", "scopes_outside_sign_in"))
        );
        assert_eq!(
            line("CW_BROKER_LOGIN_REFUSED agent=codex reason=deadline_passed_before_seal\r"),
            Some(("codex", "deadline_passed_before_seal"))
        );
        // The three reasons a broker gives beside a front door.
        for (agent, reason) in [
            ("codex", "front_door_not_paired"),
            ("codex", "no_placeholder_beside_front_door"),
            ("claude", "no_placeholder_beside_front_door"),
        ] {
            assert_eq!(
                line(&format!(
                    "CW_BROKER_LOGIN_REFUSED agent={agent} reason={reason}"
                )),
                Some((agent, reason))
            );
        }
        for other in [
            "CW_BROKER_LOGIN_REFUSED agent=gemini reason=scopes_outside_sign_in",
            "CW_BROKER_LOGIN_REFUSED agent=claude reason=sk-0123456789abcdefghij",
            "CW_BROKER_LOGIN_REFUSED agent=claude reason=scopes_outside_sign_in extra=1",
            "CW_BROKER_LOGIN_REFUSED agent=claude",
            "CW_BROKER_EXIT agent=claude reason=scopes_outside_sign_in",
            " CW_BROKER_LOGIN_REFUSED agent=claude reason=scopes_outside_sign_in",
        ] {
            assert_eq!(line(other), None, "{other}");
        }
    }

    /// A running broker's refusal is recorded as it arrives, with what the
    /// authority knows of the child; no other stderr reaches the log.
    #[tokio::test]
    async fn a_running_brokers_login_refusal_is_recorded_once_with_its_child() {
        let root = tempfile::tempdir().unwrap();
        let log = std::sync::Arc::new(BrokerLog::in_root(root.path()));
        let mut child = tokio::process::Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'CW_BROKER_LOGIN_REFUSED agent=claude reason=scopes_outside_sign_in\\nError: ghu_0123456789abcdefghij\\nCW_BROKER_LOGIN_REFUSED agent=claude reason=scopes_outside_sign_in\\nCW_BROKER_LOGIN_REFUSED agent=claude reason=unheard_of\\n' >&2",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut tail = log.tail(child.stderr.take().unwrap(), &"env-1", 3, Some(42));
        child.wait().await.unwrap();
        assert_eq!(tail.exit_line(true).await, "");
        let text = fs::read_to_string(root.path().join("logs/brokers.log")).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(
            lines[0].ends_with(
                " event=claude_login_refused environment=env-1 generation=3 pid=42 reason=scopes_outside_sign_in held_back=0"
            ),
            "{text}"
        );
    }

    /// A lasting refusal is recorded once per interval, with how many were
    /// held back in between.
    #[test]
    fn a_repeated_refusal_is_held_back_and_counted() {
        let root = tempfile::tempdir().unwrap();
        let mut refusals = LoginRefusals {
            log: std::sync::Arc::new(BrokerLog::in_root(root.path())),
            environment: "env-1".into(),
            generation: 3,
            pid: "42".into(),
            line: Vec::new(),
            last: std::collections::HashMap::new(),
        };
        let start = std::time::Instant::now();
        let reason = "deadline_passed_before_seal";
        refusals.refused("codex", reason, start);
        refusals.refused("codex", reason, start + std::time::Duration::from_secs(120));
        refusals.refused("codex", reason, start + std::time::Duration::from_secs(240));
        refusals.refused(
            "claude",
            reason,
            start + std::time::Duration::from_secs(240),
        );
        refusals.refused("codex", reason, start + LOGIN_REFUSAL_INTERVAL);
        let text = fs::read_to_string(root.path().join("logs/brokers.log")).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(
            lines[0].contains(" event=codex_login_refused ") && lines[0].ends_with(" held_back=0")
        );
        assert!(
            lines[1].contains(" event=claude_login_refused ") && lines[1].ends_with(" held_back=0")
        );
        assert!(
            lines[2].contains(" event=codex_login_refused ") && lines[2].ends_with(" held_back=2")
        );
    }
}
