//! What the hosted daemon's two agent login writers share: Codex's own
//! ChatGPT login ([`crate::codex_home::login`]) and Claude Code's own
//! claude.ai login ([`crate::claude_home::login`]), the listed direct delivery
//! exceptions (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions").
//!
//! Each writer owns its file's format and its rule for which file is
//! Codewire's. This module holds what does not depend on either: a parsed JSON
//! document whose strings are zeroized on drop, the container-local records of
//! what Codewire last wrote and which credentials the user logged out of, and
//! the check loop with its jittered backoff. Nothing here logs a token, file
//! content or path.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_workload_secrets::CodexLoginBinding;
use serde_json::{Map, Value};
use tokio::sync::watch;
use zeroize::{Zeroize as _, Zeroizing};

use crate::private_files::{Entry, PrivateDirectory, ensure_private_directory};

/// With no delivery for this long while the bridge fails (no epoch, no
/// capability, or unavailable), Codewire's login is removed: when the whole
/// Sandbox loses credential authority, the relay reports the broker's
/// refusal as an epoch failure, never as an explicit denial.
pub const LOGIN_LAPSE: Duration = Duration::from_secs(600);
/// The first retry after a check that delivered nothing.
pub(crate) const LOGIN_RETRY_MIN: Duration = Duration::from_secs(2);
/// Mode of a record, and of every file a writer creates.
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
const STATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_STATE_BYTES: u64 = 4096;

/// What removing Codewire's login found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    Removed,
    Absent,
    /// The user's login, or Codewire's that the caller chose to keep.
    Kept,
}

/// A parsed login file. Every string in it is zeroized on drop.
pub(crate) struct Document(pub(crate) Value);

impl Drop for Document {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// Zeroize every string in `value`.
pub(crate) fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub),
        Value::Object(object) => object.values_mut().for_each(scrub),
        _ => {}
    }
}

impl Document {
    /// A JSON object, or nothing.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let document = Self(serde_json::from_slice(bytes).ok()?);
        document.object()?;
        Some(document)
    }

    pub(crate) fn object(&self) -> Option<&Map<String, Value>> {
        self.0.as_object()
    }

    pub(crate) fn to_bytes(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        // Sized so serialization does not reallocate and leave a copy behind.
        let mut bytes = Zeroizing::new(Vec::with_capacity(2 * json_size(&self.0) + 4096));
        serde_json::to_writer_pretty(&mut *bytes, &self.0).map_err(io::Error::other)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn json_size(value: &Value) -> usize {
    match value {
        Value::String(text) => text.len() + 2,
        Value::Array(values) => values.iter().map(json_size).sum::<usize>() + 2,
        Value::Object(object) => {
            object
                .iter()
                .map(|(key, value)| key.len() + 8 + json_size(value))
                .sum::<usize>()
                + 2
        }
        _ => 8,
    }
}

/// The container-local records of one writer: which login Codewire last
/// wrote, and which credentials the user logged out of, for one environment
/// generation. Kept in memory and, best effort, under the writer's own state
/// directory in the container's `/tmp`, so a daemon restart keeps them and a
/// new container (a Sandbox restart) starts empty.
#[derive(Debug)]
pub(crate) struct LoginState {
    directory: PathBuf,
    generation: u64,
    /// The agent the records belong to, for secret-free log lines.
    agent: &'static str,
    pub(crate) written: Option<CodexLoginBinding>,
    logged_out: BTreeSet<String>,
}

impl LoginState {
    pub(crate) fn load(directory: PathBuf, generation: u64, agent: &'static str) -> Self {
        let mut state = Self {
            directory,
            generation,
            agent,
            written: None,
            logged_out: BTreeSet::new(),
        };
        if let Some(records) = state.open(false)
            && let Ok(Entry::Owned(entry)) = records.read(&state.written_name(), MAX_STATE_BYTES)
        {
            state.written = parse_written(&entry.contents);
        }
        state
    }

    fn written_name(&self) -> String {
        format!("generation-{}.written", self.generation)
    }

    fn logout_name(&self, credential_id: &str) -> String {
        format!("generation-{}.logged-out.{credential_id}", self.generation)
    }

    fn open(&self, create: bool) -> Option<PrivateDirectory> {
        match PrivateDirectory::open(&self.directory) {
            Ok(records) => records,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                ensure_private_directory(&self.directory, STATE_DIRECTORY_MODE).ok()?;
                PrivateDirectory::open(&self.directory).ok().flatten()
            }
            Err(_) => None,
        }
    }

    pub(crate) fn is_logged_out(&mut self, credential_id: &str) -> bool {
        if self.logged_out.contains(credential_id) {
            return true;
        }
        let marked = self.open(false).is_some_and(|records| {
            matches!(
                records.read(&self.logout_name(credential_id), MAX_STATE_BYTES),
                Ok(Entry::Owned(_))
            )
        });
        if marked {
            self.logged_out.insert(credential_id.to_owned());
        }
        marked
    }

    pub(crate) fn record_logout(&mut self, credential_id: &str) {
        self.logged_out.insert(credential_id.to_owned());
        let name = self.logout_name(credential_id);
        let persisted = self.open(true).is_some_and(|records| {
            match records.write_new(&name, b"", PRIVATE_FILE_MODE) {
                Ok(()) => records.sync().is_ok(),
                Err(error) => error.kind() == io::ErrorKind::AlreadyExists,
            }
        });
        if !persisted {
            tracing::warn!(
                agent = self.agent,
                "agent logout recorded for this daemon only; its container record is unavailable"
            );
        }
    }

    pub(crate) fn record_written(&mut self, binding: CodexLoginBinding) {
        if self.written.as_ref() == Some(&binding) {
            return;
        }
        let record = format!(
            "{}\n{}\n{}\n",
            binding.credential_id, binding.revocation_generation, binding.material_generation
        );
        self.written = Some(binding);
        let name = self.written_name();
        let persisted = self.open(true).is_some_and(|records| {
            let temporary = format!(".{name}.{}", uuid::Uuid::new_v4().simple());
            let result = records
                .write_new(&temporary, record.as_bytes(), PRIVATE_FILE_MODE)
                .and_then(|()| records.rename(&temporary, &name))
                .and_then(|()| records.sync());
            if result.is_err() {
                let _ = records.unlink(&temporary);
            }
            result.is_ok()
        });
        if !persisted {
            tracing::warn!(
                agent = self.agent,
                "agent login record kept for this daemon only"
            );
        }
    }

    pub(crate) fn forget_written(&mut self) {
        self.written = None;
        if let Some(records) = self.open(false) {
            let _ = records
                .unlink(&self.written_name())
                .and_then(|()| records.sync());
        }
    }
}

fn parse_written(bytes: &[u8]) -> Option<CodexLoginBinding> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.strip_suffix('\n')?.split('\n');
    let (Some(credential_id), Some(revocation), Some(material), None) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return None;
    };
    Some(CodexLoginBinding {
        credential_id: credential_id.to_owned(),
        revocation_generation: revocation.parse().ok()?,
        material_generation: material.parse().ok()?,
    })
}

/// One check's outcome, as the loop sees it.
pub(crate) trait LoginOutcome: Copy + Eq + Debug + Send + 'static {
    /// The outcome of a check that failed with an I/O error.
    const FAILED: Self;
    /// Whether the next check comes sooner, with backoff: nothing was
    /// delivered.
    fn retries_soon(self) -> bool;
}

/// One agent's writer, driven by [`run_login_writer`].
pub(crate) trait LoginWriter: Send + 'static {
    type Delivery: Send + 'static;
    type Outcome: LoginOutcome;
    /// Apply one bridge answer at `now_unix` (Unix seconds).
    fn apply(&mut self, delivery: Self::Delivery, now_unix: u64) -> io::Result<Self::Outcome>;
    /// Log a changed outcome: a closed state only.
    fn checked(outcome: Self::Outcome);
    /// Log a failed check: its error kind only.
    fn failed(error: &io::Error);
    /// Log that the blocking check task ended without an answer.
    fn stopped_unexpectedly();
}

/// The hosted daemon's login task: ask at start, then every `check_period`,
/// retrying sooner with jittered backoff while nothing is delivered. Stops
/// when `shutdown` turns true.
pub(crate) async fn run_login_writer<W, F, A>(
    mut writer: W,
    mut ask: A,
    check_period: Duration,
    mut shutdown: watch::Receiver<bool>,
) where
    W: LoginWriter,
    F: Future<Output = W::Delivery> + Send,
    A: FnMut() -> F + Send,
{
    let mut retry = Retry::new(check_period);
    let mut previous = None;
    loop {
        let delivery = tokio::select! {
            biased;
            () = stopped(&mut shutdown) => return,
            delivery = ask() => delivery,
        };
        let checked = tokio::task::spawn_blocking(move || {
            let result = writer.apply(delivery, unix_now());
            (writer, result)
        })
        .await;
        let Ok((returned, result)) = checked else {
            W::stopped_unexpectedly();
            return;
        };
        writer = returned;
        let delay = match result {
            Ok(outcome) => {
                if previous != Some(outcome) {
                    W::checked(outcome);
                    previous = Some(outcome);
                }
                retry.after(outcome)
            }
            Err(error) => {
                W::failed(&error);
                previous = None;
                retry.after(W::Outcome::FAILED)
            }
        };
        tokio::select! {
            biased;
            () = stopped(&mut shutdown) => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

pub(crate) async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// When to check next: the period after a decision, jittered backoff from
/// [`LOGIN_RETRY_MIN`] up to the period while nothing was delivered.
#[derive(Debug)]
pub(crate) struct Retry {
    failures: u32,
    period: Duration,
}

impl Retry {
    pub(crate) fn new(period: Duration) -> Self {
        Self {
            failures: 0,
            period,
        }
    }

    pub(crate) fn after(&mut self, outcome: impl LoginOutcome) -> Duration {
        if outcome.retries_soon() {
            let ceiling = LOGIN_RETRY_MIN
                .saturating_mul(1 << self.failures.min(16))
                .min(self.period);
            self.failures = self.failures.saturating_add(1);
            jitter(ceiling, 50)
        } else {
            self.failures = 0;
            jitter(self.period, 90)
        }
    }
}

/// A uniformly random duration between `floor_percent`% of `ceiling` and
/// `ceiling`, so many Sandboxes do not check in step.
fn jitter(ceiling: Duration, floor_percent: u32) -> Duration {
    let floor = ceiling * floor_percent / 100;
    let span = ceiling.saturating_sub(floor).as_millis().max(1);
    let random = uuid::Uuid::new_v4().as_u128() % span;
    floor + Duration::from_millis(u64::try_from(random).unwrap_or(0))
}
