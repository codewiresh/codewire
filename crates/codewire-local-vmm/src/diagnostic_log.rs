//! Bounded, owner-only diagnostic logs for the detached native supervisor and
//! its environment runners (#2595).
//!
//! The process that spawns either one opens `<state root>/logs/<name>` (0600,
//! in a 0700 directory) and gives the file to the child as stdout and stderr,
//! so the child's exit error or panic is kept instead of discarded. The child
//! appends one line per diagnostic event through [`DiagnosticLog`] and never
//! past [`MAXIMUM_LOG_BYTES`]. A spawn that finds the log past
//! [`ROTATE_AT_BYTES`] moves it to `<name>.1` first; a smaller one is kept
//! and appended to, so a child that fails and is started again, however
//! often, does not push its own failure out of the log (#5144). Each log
//! therefore holds at most two bounded files, and each child's lines begin at
//! its own `*_started` event.
//!
//! An event field is a name compiled into this binary, a journaled error code,
//! an identifier or a number. There is no free-text field, so no secret or
//! application-secret value, credential, launch value, path or guest output can
//! be written through an event.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use uuid::Uuid;

use crate::host::path::{PathError, PrivateRoot, current_uid};

/// The directory under the native state root that holds every log.
pub(crate) const LOG_DIRECTORY: &str = "logs";
/// The supervisor's log.
pub(crate) const SUPERVISOR_LOG: &str = "supervisor.log";
/// The size at which a log stops growing until its next rotation.
pub(crate) const MAXIMUM_LOG_BYTES: u64 = 1024 * 1024;
/// The size past which the next spawn moves a log to `<name>.1`: half the
/// bound, so the child it is opened for always has the other half to write.
pub(crate) const ROTATE_AT_BYTES: u64 = MAXIMUM_LOG_BYTES / 2;
const MAXIMUM_TOKEN_BYTES: usize = 64;

/// The log of the runner for one environment.
pub(crate) fn runner_log_name(environment_id: Uuid) -> String {
    format!("runner-{environment_id}.log")
}

/// One event field. Values are closed by construction.
#[derive(Debug, Clone, Copy)]
pub(crate) enum LogField<'a> {
    /// A name compiled into this binary, such as an effect or a cause.
    Name(&'static str),
    /// An error code from the same `[a-z_]{1,64}` vocabulary the operation
    /// journal admits. Anything else is written as `invalid`.
    Code(&'a str),
    Id(Uuid),
    Count(u64),
    /// A SHA-256 digest as 64 lowercase hex digits. Anything else is written
    /// as `invalid`.
    Digest(&'a str),
    /// How a process ended, and its exit code's name where this binary has
    /// one: `code_72_egress_broker_protocol`, `code_1`, `signal_9`.
    Exit(crate::process_end::ProcessEnd, Option<&'static str>),
}

/// Opens (creating 0600) the named log for a child about to be spawned, after
/// moving earlier content past [`ROTATE_AT_BYTES`] to `<name>.1`, the only
/// older file. The file appends.
pub(crate) fn open_child_log(root: &PrivateRoot, name: &str) -> Result<File, DiagnosticLogError> {
    let directory = Path::new(LOG_DIRECTORY);
    root.ensure_dir(directory, 0o700)?;
    let logs = root.open_private_directory(directory, 0o700)?;
    let mut current = logs
        .create_regular(Path::new(name), 0o600, false)?
        .into_file();
    let length = current.metadata()?.len();
    if length > ROTATE_AT_BYTES {
        // A log can pass its bound only by the child's own exit or panic
        // output; keep the newest bounded tail.
        current.seek(SeekFrom::Start(length.saturating_sub(MAXIMUM_LOG_BYTES)))?;
        let mut previous = Vec::new();
        (&mut current)
            .take(MAXIMUM_LOG_BYTES)
            .read_to_end(&mut previous)?;
        logs.atomic_replace(Path::new(&format!("{name}.1")), &previous, 0o600)?;
        current.set_len(0)?;
    }
    append(&current)?;
    Ok(current)
}

/// The child's stdout and stderr: its log, or nothing when the log cannot be
/// opened safely. A log never decides whether the child starts.
pub(crate) fn child_stdio(root: &PrivateRoot, name: &str) -> (Stdio, Stdio) {
    match open_child_log(root, name).and_then(|stderr| Ok((stderr.try_clone()?, stderr))) {
        Ok((stdout, stderr)) => (stdout.into(), stderr.into()),
        Err(_) => (Stdio::null(), Stdio::null()),
    }
}

/// The name a failed create's runner log is kept under (#5238): one per
/// environment name, since the environment itself is removed.
pub(crate) fn failed_create_log_name(name: &str) -> String {
    format!("runner-failed-create-{name}.log")
}

/// Keeps the runner log of a create that failed under the environment's
/// name, by a rename, so what the runner still writes as it is removed
/// follows it. It replaces the log an earlier failed create of that name
/// left; a create that left no log of its own removes that one, which would
/// otherwise be read as its. Best effort: a log never decides whether the
/// environment is removed.
pub(crate) fn keep_failed_create_log(root: &PrivateRoot, environment_id: Uuid, name: &str) {
    let Ok(logs) = root.open_private_directory(Path::new(LOG_DIRECTORY), 0o700) else {
        return;
    };
    let log = runner_log_name(environment_id);
    let kept = failed_create_log_name(name);
    let moved = logs.rename_private_regular(Path::new(&log), Path::new(&kept), 0o600);
    if !matches!(moved, Ok(true)) {
        remove_log(root, &kept);
    }
}

/// Removes a log and its rotated generation, as a deleted environment's
/// runner log. Best effort.
pub(crate) fn remove_log(root: &PrivateRoot, name: &str) {
    let Ok(logs) = root.open_private_directory(Path::new(LOG_DIRECTORY), 0o700) else {
        return;
    };
    for name in [name.to_owned(), format!("{name}.1")] {
        let _ = logs.remove_private_regular(Path::new(&name), 0o600);
    }
}

/// This process's diagnostic log.
#[derive(Debug)]
pub(crate) struct DiagnosticLog {
    file: Mutex<File>,
}

impl DiagnosticLog {
    /// Adopts this process's stderr when its spawner made it a private log,
    /// and nothing otherwise (a terminal, a pipe, or `/dev/null`).
    pub(crate) fn inherited() -> Option<Self> {
        let stderr = io::stderr().as_fd().try_clone_to_owned().ok()?;
        Self::adopt(File::from(stderr))
    }

    /// Adopts an open log: a single-link 0600 regular file this user owns.
    pub(crate) fn adopt(file: File) -> Option<Self> {
        let metadata = file.metadata().ok()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != current_uid()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return None;
        }
        append(&file).ok()?;
        Some(Self {
            file: Mutex::new(file),
        })
    }

    /// Appends one event line. Best effort: a full or failing log drops it.
    pub(crate) fn record(&self, event: &'static str, fields: &[(&'static str, LogField<'_>)]) {
        let line = event_line(unix_millis(), event, fields);
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let Ok(metadata) = file.metadata() else {
            return;
        };
        if metadata
            .len()
            .saturating_add(u64::try_from(line.len()).unwrap_or(u64::MAX))
            > MAXIMUM_LOG_BYTES
        {
            return;
        }
        let _ = file.write_all(line.as_bytes());
    }
}

/// Records on an optional log.
pub(crate) fn record(
    log: Option<&DiagnosticLog>,
    event: &'static str,
    fields: &[(&'static str, LogField<'_>)],
) {
    if let Some(log) = log {
        log.record(event, fields);
    }
}

fn event_line(
    time_unix_ms: u64,
    event: &'static str,
    fields: &[(&'static str, LogField<'_>)],
) -> String {
    let mut line = format!("time_unix_ms={time_unix_ms} event={}", token(event));
    for (key, value) in fields {
        let value = match value {
            LogField::Name(name) => token(name).to_owned(),
            LogField::Code(code) if valid_code(code) => (*code).to_owned(),
            LogField::Code(_) => "invalid".to_owned(),
            LogField::Id(id) => id.to_string(),
            LogField::Count(count) => count.to_string(),
            LogField::Digest(digest) if crate::state::valid_root_generation(digest) => {
                (*digest).to_owned()
            }
            LogField::Digest(_) => "invalid".to_owned(),
            LogField::Exit(end, name) => exit_token(*end, *name),
        };
        line.push_str(&format!(" {}={value}", token(key)));
    }
    line.push('\n');
    line
}

fn token(name: &'static str) -> &'static str {
    let valid = !name.is_empty()
        && name.len() <= MAXIMUM_TOKEN_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid { name } else { "invalid" }
}

fn exit_token(end: crate::process_end::ProcessEnd, name: Option<&'static str>) -> String {
    use crate::process_end::ProcessEnd;
    match (end, name) {
        (ProcessEnd::Code(code), Some(name)) => format!("code_{code}_{}", token(name)),
        (ProcessEnd::Code(code), None) => format!("code_{code}"),
        (ProcessEnd::Signal(signal), _) => format!("signal_{signal}"),
        (ProcessEnd::Unknown, _) => "unknown".to_owned(),
    }
}

fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAXIMUM_TOKEN_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn append(file: &File) -> io::Result<()> {
    let flags = fcntl_getfl(file)?;
    fcntl_setfl(file, flags | OFlags::APPEND)?;
    Ok(())
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DiagnosticLogError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests;
