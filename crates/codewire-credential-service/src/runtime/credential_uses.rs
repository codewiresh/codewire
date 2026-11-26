//! Reports the broker's credential uses to orchestration for the Sandbox
//! audit log (#6189; SPEC.md "Sandbox audit log", "The other sources").
//!
//! Every [`REPORT_INTERVAL`] the reporter takes the folds the broker made and
//! sends each workspace binding's as one `ReportCredentialUses` call. It is
//! best effort and off the request path: a failed or slow call drops what it
//! carried, and what was not yet sent, and counts it; nothing is retried. An
//! orchestration older than this service answers UNIMPLEMENTED, which is
//! logged once and dropped quietly. No log line names a binding, credential
//! or host: only counts.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use codewire_credential_broker::credential_uses::{BindingUses, CredentialUses};
use codewire_proto::codewire::internal::v1::{
    CredentialUse, ReportCredentialUsesRequest, SandboxAuditServiceClient,
};
use codewire_tls::ConnectOriginTransport;
use connectrpc::ErrorCode;
use connectrpc::client::{CallOptions, ClientConfig};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use zeroize::Zeroizing;

use super::RuntimeError;

/// How often the folds are sent.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(5);
/// The longest one call may take.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(5);

const URL: &str = "CREDENTIAL_AUDIT_ORCHESTRATION_URL";
const ROOTS: &str = "CREDENTIAL_AUDIT_ORCHESTRATION_ROOTS";
const TOKEN: &str = "CREDENTIAL_AUDIT_TOKEN_FILE";

/// Where orchestration's internal listener is and how this service proves
/// who it is there: its own projected token for the credential-service
/// audience, read again for every call because the kubelet rotates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrchestrationAudit {
    url: String,
    roots: PathBuf,
    token_path: PathBuf,
}

/// The reporting inputs: all three, or none, which leaves reporting off.
pub(crate) fn config(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<OrchestrationAudit>, RuntimeError> {
    let read = |name: &'static str| {
        lookup(name)
            .map(|value| {
                value
                    .into_string()
                    .ok()
                    .filter(|value| !value.is_empty())
                    .ok_or(RuntimeError::Configuration(name))
            })
            .transpose()
    };
    let path = |name: &'static str| {
        read(name)?
            .map(PathBuf::from)
            .map(|path| {
                path.is_absolute()
                    .then_some(path)
                    .ok_or(RuntimeError::Configuration(name))
            })
            .transpose()
    };
    match (read(URL)?, path(ROOTS)?, path(TOKEN)?) {
        (None, None, None) => Ok(None),
        (Some(url), Some(roots), Some(token_path)) => {
            ConnectOriginTransport::for_origin(&url, &roots)
                .map_err(|_| RuntimeError::Configuration(URL))?;
            Ok(Some(OrchestrationAudit {
                url,
                roots,
                token_path,
            }))
        }
        _ => Err(RuntimeError::Configuration(
            "credential use reporting needs its URL, roots and token file",
        )),
    }
}

/// Why a report was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportFailure {
    /// Orchestration is older and has no such method.
    Unimplemented,
    Failed,
}

#[async_trait]
pub(crate) trait UseReports: Send + Sync {
    async fn report(&self, uses: &BindingUses) -> Result<(), ReportFailure>;
}

/// The wire form of one binding's folds: the Pod UID, the credential's id
/// and provider, the checked host and counts, and nothing else.
pub(crate) fn request(uses: &BindingUses) -> ReportCredentialUsesRequest {
    ReportCredentialUsesRequest {
        pod_uid: uses.binding.to_string(),
        uses: uses
            .uses
            .iter()
            .map(|folded| CredentialUse {
                credential_id: folded.credential.clone(),
                provider: folded.provider.clone(),
                host: folded.host.clone().unwrap_or_default(),
                host_withheld: folded.host.is_none(),
                first_unix_ms: folded.first_unix_ms,
                last_unix_ms: folded.last_unix_ms,
                count: folded.count,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

pub(crate) fn failure(code: ErrorCode) -> ReportFailure {
    match code {
        ErrorCode::Unimplemented => ReportFailure::Unimplemented,
        _ => ReportFailure::Failed,
    }
}

#[async_trait]
impl UseReports for OrchestrationAudit {
    async fn report(&self, uses: &BindingUses) -> Result<(), ReportFailure> {
        let config = ClientConfig::new(self.url.parse().map_err(|_| ReportFailure::Failed)?)
            .with_default_timeout(CALL_TIMEOUT);
        let transport = ConnectOriginTransport::for_origin(&self.url, &self.roots)
            .map_err(|_| ReportFailure::Failed)?;
        let token = Zeroizing::new(
            std::fs::read_to_string(&self.token_path).map_err(|_| ReportFailure::Failed)?,
        );
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
            .map_err(|_| ReportFailure::Failed)?;
        bearer.set_sensitive(true);
        let options = CallOptions::default()
            .try_with_header(AUTHORIZATION, bearer)
            .map_err(|_| ReportFailure::Failed)?;
        SandboxAuditServiceClient::new(transport, config)
            .report_credential_uses_with_options(request(uses), options)
            .await
            .map(drop)
            .map_err(|error| failure(error.code))
    }
}

/// What one flush did, in uses.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flushed {
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
}

pub(crate) struct Reporter<C> {
    uses: Arc<CredentialUses>,
    client: C,
    unimplemented_logged: AtomicBool,
}

impl<C: UseReports> Reporter<C> {
    pub(crate) fn new(uses: Arc<CredentialUses>, client: C) -> Self {
        Self {
            uses,
            client,
            unimplemented_logged: AtomicBool::new(false),
        }
    }

    /// Sends every binding's folds, one call each, until one fails; that
    /// one's and the rest are dropped and counted.
    pub(crate) async fn flush(&self) -> Flushed {
        let mut flushed = Flushed::default();
        let mut batches = self.uses.take().into_iter();
        while let Some(batch) = batches.next() {
            let sent = tokio::time::timeout(CALL_TIMEOUT, self.client.report(&batch))
                .await
                .unwrap_or(Err(ReportFailure::Failed));
            match sent {
                Ok(()) => flushed.sent = flushed.sent.saturating_add(batch.count()),
                Err(failure) => {
                    let dropped = batches.fold(batch.count(), |total, rest| {
                        total.saturating_add(rest.count())
                    });
                    self.uses.count_dropped(dropped);
                    flushed.dropped = dropped;
                    self.log(failure, dropped);
                    break;
                }
            }
        }
        flushed
    }

    fn log(&self, failure: ReportFailure, dropped: u64) {
        match failure {
            ReportFailure::Unimplemented => {
                if !self.unimplemented_logged.swap(true, Ordering::Relaxed) {
                    tracing::info!(
                        dropped,
                        "orchestration takes no credential use reports yet; dropping them until it does"
                    );
                }
            }
            ReportFailure::Failed => tracing::warn!(
                dropped,
                total = self.uses.dropped(),
                "credential use report failed; its uses are dropped"
            ),
        }
    }

    /// Flushes every [`REPORT_INTERVAL`], for as long as the process runs.
    pub(crate) async fn run(self) {
        let mut interval = tokio::time::interval(REPORT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.flush().await;
        }
    }
}

/// How the reporter's task ended. It runs for the process's life, so any
/// end but the runtime's own shutdown is a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    Panicked,
    Returned,
    /// The runtime is shutting down.
    Cancelled,
}

/// Runs `reporter` for the process's life, watched: a panic in it would
/// otherwise stop every report without a word.
pub(crate) fn spawn<C: UseReports + 'static>(reporter: Reporter<C>) {
    let task = tokio::spawn(reporter.run());
    // The watcher outlives this call on purpose; nothing joins it.
    drop(tokio::spawn(watch(task)));
}

/// Waits for the reporter's task and logs an error if it ended for any
/// reason but shutdown.
pub(crate) async fn watch(task: tokio::task::JoinHandle<()>) -> Ended {
    let ended = match task.await {
        Ok(()) => Ended::Returned,
        Err(error) if error.is_panic() => Ended::Panicked,
        Err(_) => Ended::Cancelled,
    };
    match ended {
        Ended::Panicked => tracing::error!(
            "credential use reporting panicked; no credential uses are reported until the service restarts"
        ),
        Ended::Returned => tracing::error!(
            "credential use reporting stopped; no credential uses are reported until the service restarts"
        ),
        Ended::Cancelled => {}
    }
    ended
}

#[cfg(test)]
mod tests;
