//! Credential uses through the broker, for the Sandbox audit log (#6189;
//! SPEC.md "Sandbox audit log", "The other sources"). A use is a request that
//! left the broker for a host with a leased credential's value swapped in.
//! Uses fold here, in memory, per workspace binding, credential, host and
//! hour; the credential service takes the folds and sends them to
//! orchestration as count deltas.
//!
//! Recording never waits on a send and never fails a request: a use past the
//! bounds is dropped and counted. A use holds the credential's id and
//! provider, a host that passed #6144's check and a count; never a value, a
//! placeholder, a method, a path, a header or a body.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_egress_policy::record::Destination;
use url::Url;
use uuid::Uuid;

use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    BrokerUpstreamUpgrade,
};

/// The most folds held between two takes, across every binding.
pub const MAX_PENDING_FOLDS: usize = 4_096;
/// The most folds one binding holds between two takes, and so the most one
/// report carries: orchestration's limit for a report, from the one shared
/// value. A take every few seconds keeps a binding far under SPEC's 1,000
/// subjects for one Sandbox and hour, which orchestration's writer bounds.
pub const MAX_BINDING_FOLDS: usize = codewire_daemon_proto::CREDENTIAL_USES_PER_REPORT;

const HOUR_MS: u64 = 60 * 60 * 1000;

/// What one fold is about, inside its binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Subject {
    credential: String,
    /// `None` when the name failed the host check.
    host: Option<String>,
    hour: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fold {
    provider: String,
    first_unix_ms: u64,
    last_unix_ms: u64,
    count: u64,
}

/// Uses of one credential at one host within one hour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedUse {
    pub credential: String,
    pub provider: String,
    /// A checked host, lowercase; `None` when the name failed the check and
    /// is withheld.
    pub host: Option<String>,
    pub first_unix_ms: u64,
    pub last_unix_ms: u64,
    pub count: u64,
}

/// One workspace binding's folds: the Pod UID of the binding a hosted epoch
/// served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingUses {
    pub binding: Uuid,
    pub uses: Vec<FoldedUse>,
}

impl BindingUses {
    /// How many uses the folds count.
    pub fn count(&self) -> u64 {
        self.uses
            .iter()
            .fold(0, |total, folded| total.saturating_add(folded.count))
    }
}

#[derive(Default)]
struct Pending {
    bindings: HashMap<Uuid, HashMap<Subject, Fold>>,
    folds: usize,
}

/// One process's folds, shared by every hosted epoch of one bridge service.
#[derive(Default)]
pub struct CredentialUses {
    pending: Mutex<Pending>,
    dropped: AtomicU64,
}

impl CredentialUses {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Adds one use to its fold. A use whose fold would pass a bound is
    /// dropped and counted.
    pub fn record(
        &self,
        binding: Uuid,
        credential: &str,
        provider: &str,
        host: &str,
        at: SystemTime,
    ) {
        let at = at.duration_since(UNIX_EPOCH).map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
        let host = match Destination::checked_name(host) {
            Destination::Name(name) => Some(name),
            Destination::Address(_) | Destination::Withheld => None,
        };
        let subject = Subject {
            credential: credential.to_owned(),
            host,
            hour: at / HOUR_MS,
        };
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let Pending { bindings, folds } = &mut *pending;
        let held = bindings.get(&binding).map_or(0, HashMap::len);
        if let Some(fold) = bindings
            .get_mut(&binding)
            .and_then(|subjects| subjects.get_mut(&subject))
        {
            fold.first_unix_ms = fold.first_unix_ms.min(at);
            fold.last_unix_ms = fold.last_unix_ms.max(at);
            fold.count = fold.count.saturating_add(1);
            return;
        }
        if *folds >= MAX_PENDING_FOLDS || held >= MAX_BINDING_FOLDS {
            drop(pending);
            self.count_dropped(1);
            return;
        }
        bindings.entry(binding).or_default().insert(
            subject,
            Fold {
                provider: provider.to_owned(),
                first_unix_ms: at,
                last_unix_ms: at,
                count: 1,
            },
        );
        *folds += 1;
    }

    /// Takes every fold, grouped by binding, and starts again from none.
    pub fn take(&self) -> Vec<BindingUses> {
        let taken =
            std::mem::take(&mut *self.pending.lock().unwrap_or_else(PoisonError::into_inner));
        let bindings: BTreeMap<_, _> = taken.bindings.into_iter().collect();
        bindings
            .into_iter()
            .map(|(binding, subjects)| {
                let subjects: BTreeMap<_, _> = subjects.into_iter().collect();
                BindingUses {
                    binding,
                    uses: subjects
                        .into_iter()
                        .map(|(subject, fold)| FoldedUse {
                            credential: subject.credential,
                            provider: fold.provider,
                            host: subject.host,
                            first_unix_ms: fold.first_unix_ms,
                            last_unix_ms: fold.last_unix_ms,
                            count: fold.count,
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// Counts `uses` that will never be reported.
    pub fn count_dropped(&self, uses: u64) {
        self.dropped.fetch_add(uses, Ordering::Relaxed);
    }

    /// Every use dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Where a hosted epoch's uses fold, and the workspace binding they are
/// filed under: the Pod UID the epoch's workspace identity was reviewed as.
#[derive(Clone)]
pub struct EpochUses {
    uses: Arc<CredentialUses>,
    binding: Uuid,
}

impl EpochUses {
    pub fn new(uses: Arc<CredentialUses>, binding: Uuid) -> Self {
        Self { uses, binding }
    }
}

/// The credential a request swapped in, until it is sent.
struct Swapped {
    epoch: EpochUses,
    credential: String,
    provider: String,
}

tokio::task_local! {
    static SWAPPED: RefCell<Option<Swapped>>;
}

/// Serves one request with its own record of what it swapped in. A request
/// served outside one records no use.
pub(crate) async fn scoped<F: Future>(request: F) -> F::Output {
    SWAPPED.scope(RefCell::new(None), request).await
}

/// The request being served swapped `credential`'s value in. Each send that
/// follows is a use of the credential swapped in last.
#[cfg(feature = "platform")]
pub(crate) fn swapped(epoch: &EpochUses, credential: &str, provider: &str) {
    // Outside a served request there is nothing to record a use for.
    let _ = SWAPPED.try_with(|current| {
        if let Ok(mut current) = current.try_borrow_mut() {
            *current = Some(Swapped {
                epoch: epoch.clone(),
                credential: credential.to_owned(),
                provider: provider.to_owned(),
            });
        }
    });
}

/// The request being served is sent to `target`: one use, when it swapped a
/// credential in.
fn sent(target: &Url) {
    // Outside a served request there is nothing to record a use for.
    let _ = SWAPPED.try_with(|current| {
        if let Ok(current) = current.try_borrow()
            && let Some(swapped) = current.as_ref()
        {
            swapped.epoch.uses.record(
                swapped.epoch.binding,
                &swapped.credential,
                &swapped.provider,
                target.host_str().unwrap_or_default(),
                SystemTime::now(),
            );
        }
    });
}

/// A broker transport that records each send after a swap as a use.
/// [`BrokerUpstreamTransport::forward_github`] carries nothing of the
/// broker's, so it records nothing.
#[derive(Clone)]
pub struct RecordingUses<U>(pub U);

#[async_trait]
impl<U: BrokerUpstreamTransport> BrokerUpstreamTransport for RecordingUses<U> {
    fn slot_unserved(&self, slot: &str) -> bool {
        self.0.slot_unserved(slot)
    }

    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        sent(request.destination().1);
        self.0.execute(request).await
    }

    async fn upgrade(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
        sent(request.destination().1);
        self.0.upgrade(request).await
    }

    async fn forward_github(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.0.forward_github(request).await
    }
}

#[cfg(test)]
mod tests;
