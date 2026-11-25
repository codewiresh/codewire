//! The one task that keeps the token files current: a queue of due times,
//! one call at a time, at most [`BUDGET`] calls a minute, the
//! soonest-expiring file first.

use std::collections::{BTreeMap, VecDeque};
use std::hash::BuildHasher as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::directory::{self, MemoryCheck, TokenDirectory, Unusable};
use super::{IdentityFile, IdentityFiles};
use crate::access::WorkspaceAccessGrant;
use crate::identity_socket::{IdentityRefusal, IdentityTokenSource, IdentityTokens};
use crate::private_files::PrivateDirectory;

/// At start, and whenever several files are due, one call every this often.
const SPACING: Duration = Duration::from_millis(500);
/// The most calls in any [`BUDGET_WINDOW`]: eight files with one-minute
/// tokens, renewed at half life. The Sandbox's limit, 30 a minute, leaves the
/// rest to the socket.
const BUDGET: usize = 16;
const BUDGET_WINDOW: Duration = Duration::from_secs(60);
/// A file whose token can't be renewed goes this long before its `exp`.
const DELETE_BEFORE_EXPIRY: i64 = 10;
/// Longer than the binding client's own deadline for the call. Past it the
/// call is a deadline.
const CALL_TIMEOUT: Duration = Duration::from_secs(45);

/// A backoff that starts at `first` and doubles to `most`.
#[derive(Clone, Copy)]
struct Backoff {
    first: Duration,
    most: Duration,
}

const EXHAUSTED: Backoff = Backoff {
    first: Duration::from_secs(2),
    most: Duration::from_secs(30),
};
const UNAVAILABLE: Backoff = Backoff {
    first: Duration::from_secs(5),
    most: Duration::from_secs(60),
};
/// Capped at a minute, so a resumed Sandbox gets its file back within one.
const REFUSED: Backoff = UNAVAILABLE;

/// Keep the files at `path` current from each grant's list, until
/// `shutdown` changes.
pub async fn serve<S: IdentityTokenSource>(
    path: PathBuf,
    grants: watch::Receiver<WorkspaceAccessGrant>,
    tokens: Arc<IdentityTokens<S>>,
    shutdown: watch::Receiver<bool>,
) {
    run(
        path,
        PrivateDirectory::is_in_memory,
        grants,
        tokens,
        shutdown,
    )
    .await;
}

/// [`serve`] with the memory check given.
pub(super) async fn run<S: IdentityTokenSource>(
    path: PathBuf,
    in_memory: MemoryCheck,
    mut grants: watch::Receiver<WorkspaceAccessGrant>,
    tokens: Arc<IdentityTokens<S>>,
    mut shutdown: watch::Receiver<bool>,
) {
    if let Err(error) = directory::remove_leftovers(&path) {
        tracing::warn!(error = %error, "sandbox identity files left over could not be listed");
    }
    let mut files = Files {
        tokens,
        path,
        in_memory,
        directory: None,
        served: BTreeMap::new(),
        calls: VecDeque::new(),
    };
    let first = grants.borrow_and_update().identity_files().cloned();
    if let Some(list) = first
        && files.follow(&list).is_err()
    {
        return;
    }
    loop {
        let wake = files.next_wake();
        tokio::select! {
            _ = shutdown.changed() => return,
            changed = grants.changed() => {
                if changed.is_err() {
                    return;
                }
                let list = grants.borrow_and_update().identity_files().cloned();
                if let Some(list) = list
                    && files.follow(&list).is_err()
                {
                    return;
                }
            }
            () = sleep_until(wake) => files.step().await,
        }
    }
}

async fn sleep_until(wake: Option<Instant>) {
    match wake {
        Some(wake) => tokio::time::sleep_until(wake).await,
        None => std::future::pending().await,
    }
}

/// The directory is unusable: the task ends, having logged why.
struct Stopped;

struct Files<S> {
    tokens: Arc<IdentityTokens<S>>,
    path: PathBuf,
    in_memory: MemoryCheck,
    /// Opened at the first list with a file in it.
    directory: Option<TokenDirectory>,
    /// By file name.
    served: BTreeMap<String, Served>,
    /// The calls of the last [`BUDGET_WINDOW`], oldest first.
    calls: VecDeque<Instant>,
}

struct Served {
    file: IdentityFile,
    /// The token on disk: `None` while there is no file.
    written: Option<Written>,
    /// When to ask for its token next.
    due: Instant,
    /// The last failure's backoff, until a token is written.
    backoff: Option<Duration>,
}

#[derive(Clone, Copy)]
struct Written {
    /// Unix seconds, for which file goes first.
    expires_at: i64,
    /// [`DELETE_BEFORE_EXPIRY`] before it.
    delete_at: Instant,
}

/// What a failed renewal does to the file.
enum Failure {
    /// `identity_unavailable`, a deadline or `resource_exhausted`: kept
    /// while it is valid.
    Passing(&'static str, Backoff),
    /// Every other refusal, any added later included: deleted at once.
    Final(&'static str),
}

impl Failure {
    fn of(refusal: IdentityRefusal) -> Self {
        match refusal {
            IdentityRefusal::ResourceExhausted => Self::Passing(refusal.name(), EXHAUSTED),
            IdentityRefusal::IdentityUnavailable => Self::Passing(refusal.name(), UNAVAILABLE),
            refusal => Self::Final(refusal.name()),
        }
    }
}

impl<S: IdentityTokenSource> Files<S> {
    /// Serve `list`: a file no longer named, or renamed, is deleted; a new
    /// one is due at once.
    fn follow(&mut self, list: &IdentityFiles) -> Result<(), Stopped> {
        let now = Instant::now();
        let gone: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| !list.files().contains(&served.file))
            .map(|(name, _)| name.clone())
            .collect();
        for name in gone {
            if let Some(served) = self.served.remove(&name) {
                tracing::info!(
                    audience = %served.file.audience(),
                    file = %served.file.file_name(),
                    "sandbox identity file deleted: the grant no longer lists it"
                );
                self.remove(&served.file);
            }
        }
        for file in list.files() {
            if !self.served.contains_key(file.name()) {
                self.served.insert(
                    file.name().to_owned(),
                    Served {
                        file: file.clone(),
                        written: None,
                        due: now,
                        backoff: None,
                    },
                );
            }
        }
        if self.directory.is_none() && !self.served.is_empty() {
            match TokenDirectory::open(&self.path, self.in_memory) {
                Ok(directory) => self.directory = Some(directory),
                Err(unusable) => {
                    log_unusable(unusable);
                    return Err(Stopped);
                }
            }
        }
        Ok(())
    }

    /// The next deletion, or the next call the spacing and the budget allow.
    fn next_wake(&self) -> Option<Instant> {
        let deletion = self.next_deletion();
        let allowed = self.call_allowed_at();
        let call = self
            .served
            .values()
            .map(|served| served.due)
            .min()
            .map(|due| allowed.map_or(due, |allowed| due.max(allowed)));
        [deletion, call].into_iter().flatten().min()
    }

    fn next_deletion(&self) -> Option<Instant> {
        self.served
            .values()
            .filter_map(|served| served.written.map(|written| written.delete_at))
            .min()
    }

    /// Delete every file whose token expires within 10 seconds.
    fn delete_expiring(&mut self) {
        let now = Instant::now();
        let expiring: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| {
                served
                    .written
                    .is_some_and(|written| written.delete_at <= now)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in expiring {
            if let Some(served) = self.served.get_mut(&name) {
                served.written = None;
                let file = served.file.clone();
                tracing::info!(
                    audience = %file.audience(),
                    file = %file.file_name(),
                    "sandbox identity file deleted: its token expires in 10 seconds"
                );
                self.remove(&file);
            }
        }
    }

    /// When the spacing and the budget next allow a call; `None` before the
    /// first.
    fn call_allowed_at(&self) -> Option<Instant> {
        let spaced = self.calls.back().map(|last| *last + SPACING);
        let budgeted = (self.calls.len() >= BUDGET)
            .then(|| self.calls.front().map(|oldest| *oldest + BUDGET_WINDOW))
            .flatten();
        [spaced, budgeted].into_iter().flatten().max()
    }

    /// Delete what is due for deletion, then make the one call that is due,
    /// if the spacing and the budget allow it.
    async fn step(&mut self) {
        self.delete_expiring();
        let now = Instant::now();
        while self
            .calls
            .front()
            .is_some_and(|oldest| *oldest + BUDGET_WINDOW <= now)
        {
            self.calls.pop_front();
        }
        if self.call_allowed_at().is_some_and(|allowed| allowed > now) {
            return;
        }
        if let Some(name) = soonest_due(&self.served, now) {
            self.renew(&name).await;
        }
    }

    async fn renew(&mut self, name: &str) {
        let Some(file) = self.served.get(name).map(|served| served.file.clone()) else {
            return;
        };
        self.calls.push_back(Instant::now());
        let tokens = Arc::clone(&self.tokens);
        let audience = file.audience().to_owned();
        let call = tokio::time::timeout(CALL_TIMEOUT, async move { tokens.token(&audience).await });
        tokio::pin!(call);
        // A slow call holds up no deletion.
        let answer = loop {
            tokio::select! {
                answer = &mut call => break answer,
                () = sleep_until(self.next_deletion()) => self.delete_expiring(),
            }
        };
        let failure = match answer {
            Ok(Ok(token)) => {
                let written = self
                    .directory
                    .as_ref()
                    .map(|directory| directory.write(&file, token.token.as_bytes()));
                match written {
                    Some(Ok(())) => {
                        self.written(name, token.expires_at, token.stale_at);
                        return;
                    }
                    Some(Err(error)) => {
                        tracing::warn!(
                            audience = %file.audience(),
                            file = %file.file_name(),
                            error = %error,
                            "sandbox identity file could not be written"
                        );
                    }
                    None => {}
                }
                // The file it has, if any, stays until 10 seconds before its exp.
                Failure::Passing("write_failed", UNAVAILABLE)
            }
            Ok(Err(refusal)) => Failure::of(refusal),
            Err(_elapsed) => Failure::Passing("deadline", UNAVAILABLE),
        };
        self.failed(name, failure);
    }

    /// A token is in place: renew it when the cache would mint again.
    fn written(&mut self, name: &str, expires_at: i64, stale_at: i64) {
        let now_unix = self.tokens.now();
        let now = Instant::now();
        let in_seconds = |unix: i64| {
            now + Duration::from_secs(u64::try_from(unix.saturating_sub(now_unix)).unwrap_or(0))
        };
        if let Some(served) = self.served.get_mut(name) {
            if served.written.is_none() {
                tracing::info!(
                    audience = %served.file.audience(),
                    file = %served.file.file_name(),
                    "sandbox identity file written"
                );
            }
            served.written = Some(Written {
                expires_at,
                delete_at: in_seconds(expires_at.saturating_sub(DELETE_BEFORE_EXPIRY)),
            });
            served.due = in_seconds(stale_at).max(now + SPACING);
            served.backoff = None;
        }
    }

    fn failed(&mut self, name: &str, failure: Failure) {
        let now = Instant::now();
        let Some(served) = self.served.get_mut(name) else {
            return;
        };
        let (refusal, backoff, delete) = match failure {
            Failure::Passing(refusal, backoff) => (refusal, backoff, false),
            Failure::Final(refusal) => (refusal, REFUSED, true),
        };
        let delay = served.backoff.map_or(backoff.first, |last| {
            last.saturating_mul(2).clamp(backoff.first, backoff.most)
        });
        served.backoff = Some(delay);
        served.due = now + jittered(delay);
        if delete {
            served.written = None;
        } else if let Some(written) = served.written {
            // Never past the deletion: the retry comes at it at the latest.
            served.due = served.due.min(written.delete_at);
        }
        let file = served.file.clone();
        tracing::info!(
            audience = %file.audience(),
            file = %file.file_name(),
            refusal,
            retry_in_seconds = served.due.saturating_duration_since(now).as_secs(),
            kept = !delete && served.written.is_some(),
            "sandbox identity file not renewed"
        );
        if delete {
            self.remove(&file);
        }
    }

    fn remove(&self, file: &IdentityFile) {
        if let Some(directory) = &self.directory
            && let Err(error) = directory.remove(file)
        {
            tracing::warn!(
                audience = %file.audience(),
                file = %file.file_name(),
                error = %error,
                "sandbox identity file could not be deleted"
            );
        }
    }
}

/// The due file whose token expires soonest; one with no file before any,
/// then by name.
fn soonest_due(served: &BTreeMap<String, Served>, now: Instant) -> Option<String> {
    served
        .iter()
        .filter(|(_, served)| served.due <= now)
        .min_by_key(|(name, served)| {
            (
                served
                    .written
                    .map_or(i64::MIN, |written| written.expires_at),
                *name,
            )
        })
        .map(|(name, _)| name.clone())
}

/// Half of `delay` and a random part of the other half, so Sandboxes that
/// failed together don't retry together.
fn jittered(delay: Duration) -> Duration {
    let half = delay / 2;
    let random = std::collections::hash_map::RandomState::new().hash_one(());
    let spread = u64::try_from(half.as_millis()).unwrap_or(u64::MAX).max(1);
    half + Duration::from_millis(random % spread)
}

fn log_unusable(unusable: Unusable) {
    match unusable {
        Unusable::NotPrivate => tracing::warn!(
            "sandbox identity files are off: /codewire/run/identity is a symlink, not a directory, or not the daemon's"
        ),
        Unusable::OnDisk => tracing::warn!(
            "sandbox identity files are off: /codewire/run is not memory-backed; make the Sandbox again to get them"
        ),
        Unusable::Failed(error) => tracing::warn!(
            error = %error,
            "sandbox identity files are off: their directory could not be opened"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn served(name: &str, due: Instant, expires_at: Option<i64>) -> (String, Served) {
        (
            name.to_owned(),
            Served {
                file: IdentityFile {
                    audience: format!("https://{name}.example"),
                    name: name.to_owned(),
                },
                written: expires_at.map(|expires_at| Written {
                    expires_at,
                    delete_at: due + Duration::from_secs(60),
                }),
                due,
                backoff: None,
            },
        )
    }

    #[test]
    fn of_the_due_files_the_soonest_expiring_goes_first() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut queue: BTreeMap<String, Served> = [
            served("a", now, Some(2_000)),
            served("b", now, Some(1_500)),
            served("c", later, Some(1_000)),
            served("d", now, Some(1_800)),
        ]
        .into_iter()
        .collect();
        // c expires soonest but isn't due yet.
        assert_eq!(soonest_due(&queue, now).as_deref(), Some("b"));
        assert_eq!(soonest_due(&queue, later).as_deref(), Some("c"));
        // A file with no file on disk goes before any.
        queue.extend([served("z", now, None)]);
        assert_eq!(soonest_due(&queue, now).as_deref(), Some("z"));
        assert_eq!(soonest_due(&queue, now - Duration::from_secs(1)), None);
    }

    #[test]
    fn a_jittered_delay_is_between_half_of_it_and_it() {
        for seconds in [2, 5, 30, 60] {
            let delay = Duration::from_secs(seconds);
            for _ in 0..100 {
                let jittered = jittered(delay);
                assert!(jittered >= delay / 2 && jittered <= delay, "{jittered:?}");
            }
        }
    }
}
