//! Hosted interception CAs, part 2 (#5030): the Pod check `EnsureInterceptionCa`
//! runs before a Pod's CA is created, and the sweep that forgets an unbound
//! Pod's CA once the Pod has left the cluster
//! (docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception CA").
//!
//! Both read a Pod only by a namespace this service was configured with or
//! stored itself, and by name, never by a namespace a caller supplies. A bound
//! Pod's CA is deleted by its binding's release, not here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use codewire_credential_broker::platform::bridge::{
    InterceptionCaError, InterceptionCas, LeafRequest, SignedLeaf,
};
use codewire_platform_credentials::{
    InterceptedPod, LeafRefusal, PlatformCredentialError, PlatformCredentialStore,
    UnboundInterceptionCa,
};
use k8s_openapi::api::core::v1::Pod;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The label orchestration renders on every broker-mode Sandbox Pod
/// (`codewire_orchestration::egress::admission::EGRESS_MODE_LABEL`).
pub const EGRESS_MODE_LABEL: &str = "codewire.sh/egress";
pub const EGRESS_MODE_BROKER: &str = "broker";
/// How often the sweep reads the unbound rows' Pods.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How long a Pod stays absent, from the first sweep that found it absent,
/// before its CA is forgotten (cw-test-health, #5030).
pub const ABSENT_GRACE: Duration = Duration::from_secs(10 * 60);

/// One read of a Pod by namespace and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PodRead {
    Found {
        uid: String,
        broker_mode: bool,
        terminating: bool,
    },
    /// The API answered that no Pod has that name.
    NotFound,
    /// The API didn't answer: an error, a timeout or a refusal.
    Unavailable,
}

#[async_trait]
pub trait PodReader: Send + Sync {
    async fn read(&self, namespace: &str, name: &str) -> PodRead;
}

/// The cluster's Pods, read with this service's own `get pods` grant.
pub struct KubernetesPods {
    client: kube::Client,
}

impl KubernetesPods {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PodReader for KubernetesPods {
    async fn read(&self, namespace: &str, name: &str) -> PodRead {
        match kube::Api::<Pod>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
        {
            Ok(Some(pod)) => {
                let Some(uid) = pod.metadata.uid else {
                    return PodRead::Unavailable;
                };
                PodRead::Found {
                    uid,
                    broker_mode: pod
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(EGRESS_MODE_LABEL))
                        .is_some_and(|mode| mode == EGRESS_MODE_BROKER),
                    terminating: pod.metadata.deletion_timestamp.is_some(),
                }
            }
            Ok(None) => PodRead::NotFound,
            Err(_) => PodRead::Unavailable,
        }
    }
}

/// Why a Pod gets no CA. Carries no input, so it may be logged. The first
/// is a denial; `Unavailable` is the API's, and worth a retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PodRefusal {
    #[error("no Pod with that name and UID is in the sandbox namespace")]
    NotFoundOrOtherUid,
    #[error("the Pod is not a broker-mode Sandbox")]
    NotBrokerMode,
    #[error("the Pod is terminating")]
    Terminating,
    #[error("the Kubernetes API is unavailable")]
    Unavailable,
}

/// A Pod the check found as it must be: its UID, in the sandbox namespace,
/// broker-mode and running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedPod {
    uid: String,
    namespace: String,
    name: String,
}

impl CheckedPod {
    /// The Pod as the store takes it.
    pub fn intercepted(&self) -> InterceptedPod<'_> {
        InterceptedPod {
            uid: &self.uid,
            namespace: &self.namespace,
            name: &self.name,
        }
    }
}

/// The sandbox namespace's Pods, as `EnsureInterceptionCa` checks one.
pub struct SandboxPods<R> {
    reader: R,
    namespace: String,
}

impl<R: PodReader> SandboxPods<R> {
    /// `namespace` comes from this service's configuration, never a request.
    pub fn new(reader: R, namespace: String) -> Self {
        Self { reader, namespace }
    }

    /// The Pod `name` in the sandbox namespace, when it is the Pod `uid`, a
    /// broker-mode Sandbox and not terminating (cw-security, #4001).
    pub async fn check(&self, uid: &str, name: &str) -> Result<CheckedPod, PodRefusal> {
        match self.reader.read(&self.namespace, name).await {
            PodRead::Found {
                uid: found,
                broker_mode,
                terminating,
            } => {
                if found != uid {
                    Err(PodRefusal::NotFoundOrOtherUid)
                } else if !broker_mode {
                    Err(PodRefusal::NotBrokerMode)
                } else if terminating {
                    Err(PodRefusal::Terminating)
                } else {
                    Ok(CheckedPod {
                        uid: found,
                        namespace: self.namespace.clone(),
                        name: name.to_owned(),
                    })
                }
            }
            PodRead::NotFound => Err(PodRefusal::NotFoundOrOtherUid),
            PodRead::Unavailable => Err(PodRefusal::Unavailable),
        }
    }
}

/// The rows the sweep works on.
#[async_trait]
pub trait InterceptionCaRows: Send + Sync {
    async fn unbound(&self) -> Result<Vec<UnboundInterceptionCa>, PlatformCredentialError>;
    /// True when the row was removed; false when the Pod is bound by now.
    async fn forget(&self, pod_uid: &str) -> Result<bool, PlatformCredentialError>;
}

#[async_trait]
impl InterceptionCaRows for Arc<PlatformCredentialStore> {
    async fn unbound(&self) -> Result<Vec<UnboundInterceptionCa>, PlatformCredentialError> {
        self.unbound_interception_cas().await
    }

    async fn forget(&self, pod_uid: &str) -> Result<bool, PlatformCredentialError> {
        self.forget_interception_ca(pod_uid).await
    }
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepCounts {
    /// Rows whose Pod is there.
    pub present: usize,
    /// Rows whose Pod is absent, not yet past the grace.
    pub absent: usize,
    /// Rows forgotten this sweep.
    pub forgotten: usize,
    /// Rows the API couldn't read, or the store couldn't forget; their
    /// clocks neither started nor moved.
    pub skipped: usize,
    /// False when the rows themselves couldn't be read.
    pub complete: bool,
}

/// Forgets an unbound Pod's CA once the Pod has been absent from the cluster
/// for [`ABSENT_GRACE`] since the first sweep that found it absent. Absent
/// means only a definite NotFound, or the name now held by another UID; an
/// API error neither starts nor advances that clock, since a deleted Pod
/// never returns with its UID and a wrongly forgotten CA strands a live
/// Sandbox's interception (#5006).
pub struct InterceptionCaSweep<S, R> {
    rows: S,
    pods: R,
    absent_since: Mutex<HashMap<String, Instant>>,
    started: AtomicBool,
    stop: CancellationToken,
    tasks: TaskTracker,
}

impl<S, R> InterceptionCaSweep<S, R>
where
    S: InterceptionCaRows + 'static,
    R: PodReader + 'static,
{
    pub fn new(rows: S, pods: R) -> Self {
        Self {
            rows,
            pods,
            absent_since: Mutex::new(HashMap::new()),
            started: AtomicBool::new(false),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }

    /// Start the periodic sweep once, a quarter interval after start.
    pub fn start(self: &Arc<Self>) {
        if self.stop.is_cancelled() || self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let owner = Arc::clone(self);
        self.tasks.spawn(async move { owner.run().await });
        tracing::info!(
            interval_seconds = SWEEP_INTERVAL.as_secs(),
            grace_seconds = ABSENT_GRACE.as_secs(),
            "interception CA sweep started"
        );
    }

    pub fn start_shutdown(&self) {
        self.stop.cancel();
        self.tasks.close();
    }

    pub async fn shutdown(&self) {
        self.start_shutdown();
        self.tasks.wait().await;
    }

    async fn run(&self) {
        let mut wait = SWEEP_INTERVAL / 4;
        loop {
            tokio::select! {
                biased;
                _ = self.stop.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            let sweep = self.sweep_once(Instant::now()).await;
            // Every pass logs, so a clean pass is told apart from a sweep
            // that died or hung (cw-security, #4001).
            tracing::info!(
                rows = sweep.present + sweep.absent + sweep.forgotten + sweep.skipped,
                present = sweep.present,
                absent = sweep.absent,
                forgotten = sweep.forgotten,
                skipped = sweep.skipped,
                complete = sweep.complete,
                "interception CA sweep pass"
            );
            wait = SWEEP_INTERVAL;
        }
    }

    /// One sweep at `now`.
    pub async fn sweep_once(&self, now: Instant) -> SweepCounts {
        let mut counts = SweepCounts::default();
        let Ok(rows) = self.rows.unbound().await else {
            return counts;
        };
        counts.complete = true;
        // A row no longer unbound (attached or deleted since) drops its clock.
        self.absent_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|uid, _| rows.iter().any(|row| &row.pod_uid == uid));
        for row in rows {
            let absent = match self.pods.read(&row.pod_namespace, &row.pod_name).await {
                PodRead::Found { uid, .. } => uid != row.pod_uid,
                PodRead::NotFound => true,
                PodRead::Unavailable => {
                    counts.skipped += 1;
                    continue;
                }
            };
            if !absent {
                self.clock().remove(&row.pod_uid);
                counts.present += 1;
                continue;
            }
            let since = *self.clock().entry(row.pod_uid.clone()).or_insert(now);
            if now.duration_since(since) < ABSENT_GRACE {
                counts.absent += 1;
                continue;
            }
            match self.rows.forget(&row.pod_uid).await {
                Ok(true) => {
                    self.clock().remove(&row.pod_uid);
                    counts.forgotten += 1;
                }
                // Bound since the read: its release deletes it instead.
                Ok(false) => {
                    self.clock().remove(&row.pod_uid);
                    counts.present += 1;
                }
                Err(_) => counts.skipped += 1,
            }
        }
        counts
    }

    fn clock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        self.absent_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The interception CAs as the bridge service serves them (#4001): the Pod
/// check, then the store, which alone holds the keys.
pub struct PlatformInterceptionCas<R> {
    pods: SandboxPods<R>,
    store: Arc<PlatformCredentialStore>,
}

impl<R: PodReader> PlatformInterceptionCas<R> {
    pub fn new(pods: SandboxPods<R>, store: Arc<PlatformCredentialStore>) -> Self {
        Self { pods, store }
    }
}

#[async_trait]
impl<R: PodReader + 'static> InterceptionCas for PlatformInterceptionCas<R> {
    async fn ensure(&self, pod_uid: &str, pod_name: &str) -> Result<Vec<u8>, InterceptionCaError> {
        let checked = self
            .pods
            .check(pod_uid, pod_name)
            .await
            .map_err(pod_refusal)?;
        self.store
            .ensure_interception_ca(checked.intercepted())
            .await
            .map_err(store_error)
    }

    async fn sign(&self, request: LeafRequest<'_>) -> Result<SignedLeaf, InterceptionCaError> {
        let ca = self
            .store
            .open_interception_ca(request.pod_uid, request.environment_id)
            .await
            .map_err(store_error)?;
        // The leaf ends at the earlier of its lifetime and its CA's end. Taken
        // before signing, whole seconds down, this is never later than the
        // certificate's own notAfter.
        let requested_end = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| InterceptionCaError::Unavailable)?
            .saturating_add(request.lifetime)
            .as_secs();
        let certificate_der = ca
            .sign_leaf(request.public_key, request.hosts, request.lifetime)
            .map_err(leaf_refusal)?;
        let ca_end = u64::try_from(ca.not_after().unix_timestamp())
            .map_err(|_| InterceptionCaError::Unavailable)?;
        Ok(SignedLeaf {
            certificate_der,
            not_after_unix: requested_end.min(ca_end),
        })
    }
}

/// A Pod that isn't the one named, live and broker-mode is a denial; only an
/// unanswered read is worth a retry.
fn pod_refusal(refusal: PodRefusal) -> InterceptionCaError {
    match refusal {
        PodRefusal::NotFoundOrOtherUid | PodRefusal::NotBrokerMode | PodRefusal::Terminating => {
            InterceptionCaError::Denied
        }
        PodRefusal::Unavailable => InterceptionCaError::Unavailable,
    }
}

/// No row for that Pod and environment, or a released binding, is a denial.
fn store_error(error: PlatformCredentialError) -> InterceptionCaError {
    match error {
        PlatformCredentialError::NotFound => InterceptionCaError::Denied,
        _ => InterceptionCaError::Unavailable,
    }
}

fn leaf_refusal(refusal: LeafRefusal) -> InterceptionCaError {
    match refusal {
        LeafRefusal::InvalidPublicKey => InterceptionCaError::InvalidKey,
        _ => InterceptionCaError::Unavailable,
    }
}

#[cfg(test)]
mod tests;
