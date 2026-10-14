//! The authority's durable record of its credential broker children (#2763).
//!
//! Each broker runs with its standard streams on `/dev/null` and may end
//! without a word, and the authority restarts it on a backoff. This log keeps
//! one line per lifecycle event under the credential root
//! (`logs/brokers.log`, 0600) so a failing environment can be diagnosed from
//! the product: when a child started, whether it became ready, and how it
//! ended (exit code or signal, the lease channel's typed error, and the
//! restart delay chosen). Only fixed event names, identifiers, durations and
//! typed outcomes are written, never request contents, credential values or
//! child output. Writing is best effort and never affects the broker.

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
/// The broker log keeps this many of the last non-empty lines.
const TAIL_LINES: usize = 3;
/// How long an exited child's pipe may take to reach end of file.
const EXITED_DRAIN: std::time::Duration = std::time::Duration::from_millis(250);

impl StderrTail {
    pub(crate) fn spawn(mut stderr: tokio::process::ChildStderr) -> Self {
        use tokio::io::AsyncReadExt as _;
        let tail = std::sync::Arc::new(Mutex::new(Vec::new()));
        let shared = std::sync::Arc::clone(&tail);
        let reader = tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            while let Ok(count) = stderr.read(&mut buffer).await {
                if count == 0 {
                    break;
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

    /// The last few non-empty lines written so far; for an exited child, after
    /// its pipe reaches end of file (bounded).
    pub(crate) async fn last_line(&mut self, exited: bool) -> String {
        if exited && let Some(reader) = self.reader.take() {
            let _ = tokio::time::timeout(EXITED_DRAIN, reader).await;
        }
        let tail = self
            .tail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let text = String::from_utf8_lossy(&tail);
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .rev()
            .take(TAIL_LINES)
            .collect::<Vec<_>>();
        lines.reverse();
        lines.join(" | ")
    }
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
    async fn keeps_the_last_lines_of_an_exited_childs_stderr() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "printf 'one\\ntwo\\n\\nthree\\nfour\\n' >&2; exit 1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut tail = StderrTail::spawn(child.stderr.take().unwrap());
        let status = child.wait().await.unwrap();
        assert_eq!(exit_status(Some(status)), "exit:1");
        assert_eq!(tail.last_line(true).await, "two | three | four");
    }
}
