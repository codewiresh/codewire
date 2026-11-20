//! Signed leaves for a pair's front door (#4001; `SPEC.md`, cw-egress's
//! front door; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Hosted interception
//! leaves").
//!
//! Once a pair with a front door has started, cw-egress asks orchestration
//! for leaves for the front door's own key, installs every leaf of the answer
//! at once, and asks again at the answer's `renew_at`. A failed ask or a
//! refused install is retried with backoff, [`FIRST_RETRY`] doubling to
//! [`LAST_RETRY`], never past the end of the leaves installed. There is no
//! fallback and no CA on the node: until an install succeeds the front door
//! has no leaf, or keeps its current ones, and its hosts fail closed. A
//! [`Renewal`] belongs to one pair and ends with it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::orchestration::CallError;

/// The first retry after a failure.
pub const FIRST_RETRY: Duration = Duration::from_secs(5);
/// The longest wait between retries.
pub const LAST_RETRY: Duration = Duration::from_secs(60);
/// The furthest ahead a `renew_at` is believed. A leaf lives at most an hour
/// (`SPEC.md`), so anything later is wrong, and a wrong one must not become
/// a long sleep.
pub const LONGEST_RENEWAL: Duration = Duration::from_secs(3600);

/// One answer from the signer.
pub struct IssuedLeaves {
    /// DER certificates for the front door's key.
    pub certificates: Vec<Vec<u8>>,
    pub renew_at_unix: i64,
}

impl std::fmt::Debug for IssuedLeaves {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the certificates' bodies.
        formatter
            .debug_struct("IssuedLeaves")
            .field("leaves", &self.certificates.len())
            .field("renew_at_unix", &self.renew_at_unix)
            .finish()
    }
}

/// Who signs a front door's leaves: orchestration's
/// `EgressService.SignInterceptionLeaves`.
pub trait LeafSigner: Send + Sync + 'static {
    fn sign(
        &self,
        pod_uid: &str,
        pod_name: &str,
        public_key: &[u8],
    ) -> impl Future<Output = Result<IssuedLeaves, CallError>> + Send;
}

/// How one ask ended.
#[derive(Debug)]
pub enum Settled<E> {
    /// This many leaves are installed.
    Installed(usize),
    /// The front door refused them and kept what it had.
    Refused(E),
    Unanswered(CallError),
}

/// When a pair's front door asks next, and what it has.
pub struct Renewal<S> {
    signer: Arc<S>,
    pod_uid: String,
    pod_name: String,
    public_key: Vec<u8>,
    /// The wall clock at `started`. `renew_at` and a leaf's end are
    /// wall-clock times; they are measured from here on the runtime's clock.
    started_unix: i64,
    started: Instant,
    due: Instant,
    retry: Duration,
    /// When the earliest installed leaf ends, if any is installed.
    leaves_end: Option<Instant>,
}

impl<S: LeafSigner> Renewal<S> {
    /// A renewal whose first ask is due at once. `now_unix` is the wall
    /// clock now.
    pub fn new(
        signer: Arc<S>,
        pod_uid: String,
        pod_name: String,
        public_key: Vec<u8>,
        now_unix: i64,
    ) -> Self {
        let now = Instant::now();
        Self {
            signer,
            pod_uid,
            pod_name,
            public_key,
            started_unix: now_unix,
            started: now,
            due: now,
            retry: FIRST_RETRY,
            leaves_end: None,
        }
    }

    /// Waits until the next ask is due, then asks. Dropping it loses
    /// nothing: the next call waits for the same moment and asks again.
    pub async fn ask(&self) -> Result<IssuedLeaves, CallError> {
        if Instant::now() < self.due {
            tokio::time::sleep_until(self.due).await;
        }
        self.signer
            .sign(&self.pod_uid, &self.pod_name, &self.public_key)
            .await
    }

    /// `issued` is installed: the next ask is at its `renew_at`, or after
    /// the backoff when that is not between now and [`LONGEST_RENEWAL`]
    /// ahead.
    fn installed(&mut self, issued: &IssuedLeaves) {
        self.leaves_end = issued
            .certificates
            .iter()
            .map(|certificate| not_after_unix(certificate))
            .collect::<Option<Vec<_>>>()
            .and_then(|ends| ends.into_iter().min())
            .map(|end| self.instant_at(end));
        let ahead = issued.renew_at_unix.saturating_sub(self.now_unix());
        let wait = u64::try_from(ahead)
            .ok()
            .filter(|ahead| *ahead > 0)
            .map(Duration::from_secs)
            .filter(|wait| *wait <= LONGEST_RENEWAL);
        match wait {
            Some(wait) => {
                self.retry = FIRST_RETRY;
                self.due = self.before_the_end(Instant::now() + wait);
            }
            None => self.back_off(),
        }
    }

    /// Installs a successful ask's leaves with `install`, all of them at
    /// once, and schedules the next ask: at `renew_at` once installed, after
    /// the backoff when the ask failed or the front door refused them and
    /// kept what it had.
    pub async fn settle<E>(
        &mut self,
        asked: Result<IssuedLeaves, CallError>,
        install: impl AsyncFnOnce(&[Vec<u8>]) -> Result<(), E>,
    ) -> Settled<E> {
        let issued = match asked {
            Ok(issued) => issued,
            Err(error) => {
                self.back_off();
                return Settled::Unanswered(error);
            }
        };
        match install(&issued.certificates).await {
            Ok(()) => {
                self.installed(&issued);
                Settled::Installed(issued.certificates.len())
            }
            Err(error) => {
                self.back_off();
                Settled::Refused(error)
            }
        }
    }

    /// When the next ask is due.
    pub fn due(&self) -> Instant {
        self.due
    }

    fn back_off(&mut self) {
        self.due = self.before_the_end(Instant::now() + self.retry);
        self.retry = (self.retry * 2).min(LAST_RETRY);
    }

    /// `due`, or the installed leaves' end when that comes first and has not
    /// passed.
    fn before_the_end(&self, due: Instant) -> Instant {
        match self.leaves_end {
            Some(end) if end > Instant::now() => due.min(end),
            _ => due,
        }
    }

    fn now_unix(&self) -> i64 {
        let elapsed = i64::try_from(self.started.elapsed().as_secs()).unwrap_or(i64::MAX);
        self.started_unix.saturating_add(elapsed)
    }

    /// The runtime's instant for the wall-clock second `unix`.
    fn instant_at(&self, unix: i64) -> Instant {
        let ahead = u64::try_from(unix.saturating_sub(self.now_unix())).unwrap_or(0);
        Instant::now() + Duration::from_secs(ahead)
    }
}

/// A certificate's end, in Unix seconds; `None` for one that does not
/// parse, which the front door refuses anyway.
fn not_after_unix(certificate: &[u8]) -> Option<i64> {
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate).ok()?;
    Some(certificate.validity().not_after.timestamp())
}

#[cfg(test)]
mod tests;
