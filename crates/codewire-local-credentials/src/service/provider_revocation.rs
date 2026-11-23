//! The authority's side of revoking a local credential at its provider
//! (#4717). Codewire's revoke commits first; then, for an active Codex
//! sign-in, one confined executor leases that generation, asks OpenAI, and
//! reports only the outcome class. The authority itself makes no request.
//! When a refresh had started, the stored token may already be rotated, so
//! no executor runs and the answer is NOT_READ.

use std::sync::Arc;
use std::time::Duration;

use codewire_access::{CredentialAuthKind, CredentialId, CredentialStatus};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::control::v1;
use crate::provider_revocation::{
    LocalRevocationProcessConfig, LocalRevocationProcessSpawner, RevocationLease,
    serve_revocation_lease_channel,
};
use crate::{CredentialRecord, LocalCredentialAuthority, LocalCredentialError};

/// The executor's whole run: start, lease, the provider's 8 s bound, report.
const EXECUTOR_BOUND: Duration = Duration::from_secs(20);
const REAP_BOUND: Duration = Duration::from_secs(5);

pub(crate) struct ProviderRevocations<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Option<Arc<dyn LocalRevocationProcessSpawner>>,
}

impl<S: ProtectedStore + 'static> ProviderRevocations<S> {
    pub(crate) fn start(
        authority: &Arc<LocalCredentialAuthority<S>>,
        spawner: Option<Arc<dyn LocalRevocationProcessSpawner>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            authority: Arc::clone(authority),
            spawner,
        })
    }

    /// Revokes `id`, then asks its provider. The answer is unset when the
    /// credential was not active, NOT_AVAILABLE when Codewire cannot ask its
    /// provider here, and FAILED/NOT_READ when a refresh had started or the
    /// executor did not report.
    pub(crate) async fn revoke_at_provider(
        &self,
        id: CredentialId,
    ) -> Result<(CredentialRecord, Option<v1::ProviderRevocation>), LocalCredentialError> {
        self.revoke_and_ask(id, Revoking::Revoke).await
    }

    /// As [`Self::revoke_at_provider`], for a delete (#6128): the store
    /// refuses before any change while the credential is in use, and the
    /// executor reads the generation the delete has moved out of `ready`.
    pub(crate) async fn revoke_for_delete(
        &self,
        id: CredentialId,
    ) -> Result<(CredentialRecord, Option<v1::ProviderRevocation>), LocalCredentialError> {
        self.revoke_and_ask(id, Revoking::ForDelete).await
    }

    async fn revoke_and_ask(
        &self,
        id: CredentialId,
        revoking: Revoking,
    ) -> Result<(CredentialRecord, Option<v1::ProviderRevocation>), LocalCredentialError> {
        let authority = Arc::clone(&self.authority);
        let revoked = id.clone();
        let (record, material_generation, was_active) =
            tokio::task::spawn_blocking(move || match revoking {
                Revoking::Revoke => authority.revoke_for_provider(&revoked),
                Revoking::ForDelete => authority.revoke_for_delete(&revoked),
            })
            .await
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)??;
        if !was_active {
            return Ok((record, None));
        }
        let codex = record.metadata.provider.as_str() == "openai"
            && record.metadata.authentication_kind == CredentialAuthKind::OAuth;
        let Some(spawner) = self.spawner.as_ref().filter(|_| codex) else {
            return Ok((
                record,
                Some(outcome(v1::ProviderRevocationOutcome::NotAvailable)),
            ));
        };
        let Some(material_generation) = material_generation else {
            return Ok((record, Some(not_read())));
        };
        // The executor opens no store: the authority reads the revoked
        // generation, within the run's bound, and its lease carries it (#4984).
        // A locked keyring that never answers is NOT_READ at the bound.
        let authority = Arc::clone(&self.authority);
        let reading = id.clone();
        let read = tokio::task::spawn_blocking(move || match revoking {
            Revoking::Revoke => authority.executor_lease_material(
                &reading,
                material_generation,
                CredentialStatus::Revoked,
            ),
            Revoking::ForDelete => authority.deleting_lease_material(&reading, material_generation),
        });
        let Ok(Ok(Ok(material))) = tokio::time::timeout(EXECUTOR_BOUND, read).await else {
            return Ok((record, Some(not_read())));
        };
        let lease = RevocationLease {
            request_id: Uuid::new_v4(),
            credential_id: id.as_str().to_owned(),
            material_generation,
        };
        let reported = run_executor(spawner.as_ref(), lease, material)
            .await
            .unwrap_or_else(|()| not_read());
        Ok((record, Some(reported)))
    }
}

/// Which revoke runs before the provider is asked.
#[derive(Clone, Copy)]
enum Revoking {
    Revoke,
    ForDelete,
}

async fn run_executor(
    spawner: &dyn LocalRevocationProcessSpawner,
    lease: RevocationLease,
    material: ProtectedValue,
) -> Result<v1::ProviderRevocation, ()> {
    let config = LocalRevocationProcessConfig {
        request_id: lease.request_id,
    };
    config.validate().map_err(|_| ())?;
    let (authority_stream, executor_stream) =
        std::os::unix::net::UnixStream::pair().map_err(|_| ())?;
    authority_stream.set_nonblocking(true).map_err(|_| ())?;
    let authority_stream = UnixStream::from_std(authority_stream).map_err(|_| ())?;
    let mut child = spawner.spawn(&config, executor_stream).map_err(|_| ())?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let (report_tx, report_rx) = oneshot::channel();
    let server = tokio::spawn(serve_revocation_lease_channel(
        authority_stream,
        lease,
        material,
        ready_tx,
        report_tx,
    ));
    let reported = tokio::time::timeout(EXECUTOR_BOUND, async {
        ready_rx.await.ok()?;
        report_rx.await.ok()
    })
    .await
    .ok()
    .flatten();
    // One shot: the child is stopped and reaped whatever it reported.
    let _ = child.start_kill();
    let _ = tokio::time::timeout(REAP_BOUND, child.wait()).await;
    server.abort();
    reported.ok_or(())
}

fn outcome(outcome: v1::ProviderRevocationOutcome) -> v1::ProviderRevocation {
    v1::ProviderRevocation {
        outcome: outcome.into(),
        failure: v1::ProviderRevocationFailure::Unspecified.into(),
        http_status: 0,
    }
}

fn not_read() -> v1::ProviderRevocation {
    v1::ProviderRevocation {
        outcome: v1::ProviderRevocationOutcome::Failed.into(),
        failure: v1::ProviderRevocationFailure::NotRead.into(),
        http_status: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use codewire_access::{CredentialStatus, ProviderId, builtin_provider_catalog};
    use codewire_protected_store::ProtectedValue;

    use super::*;
    use crate::provider_revocation::LocalRevocationSpawnError;
    use crate::tests::TestProtectedStore;
    use crate::{LocalRevocationLeaseClient, NewCredential};

    /// An executor that starts, leases and then never reports. It records
    /// what the credential's status was when it was spawned, and its PID.
    struct SilentSpawner {
        authority: Arc<LocalCredentialAuthority<TestProtectedStore>>,
        id: CredentialId,
        status_at_spawn: Mutex<Option<CredentialStatus>>,
        pid: Mutex<Option<u32>>,
    }

    impl LocalRevocationProcessSpawner for SilentSpawner {
        fn spawn(
            &self,
            config: &LocalRevocationProcessConfig,
            authority_peer: std::os::unix::net::UnixStream,
        ) -> Result<tokio::process::Child, LocalRevocationSpawnError> {
            let status = self
                .authority
                .get_credential(&self.id)
                .ok()
                .map(|record| record.metadata.status);
            *self.status_at_spawn.lock().unwrap() = status;
            authority_peer
                .set_nonblocking(true)
                .map_err(|_| LocalRevocationSpawnError::Spawn)?;
            let stream = UnixStream::from_std(authority_peer)
                .map_err(|_| LocalRevocationSpawnError::Spawn)?;
            let request_id = config.request_id;
            tokio::spawn(async move {
                let Ok(mut client) = LocalRevocationLeaseClient::connect(stream, request_id).await
                else {
                    return;
                };
                if client.report_ready().await.is_ok() && client.lease().await.is_ok() {
                    // Never reports, and keeps the channel open.
                    std::future::pending::<()>().await;
                }
            });
            let child = tokio::process::Command::new("/bin/sleep")
                .arg("300")
                .env_clear()
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| LocalRevocationSpawnError::Spawn)?;
            *self.pid.lock().unwrap() = child.id();
            Ok(child)
        }
    }

    /// The process is gone or a zombie, so no longer running.
    #[cfg(target_os = "linux")]
    fn stopped(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_executor_that_never_reports_is_not_read_at_the_bound_and_stopped() {
        let temp = tempfile::tempdir().unwrap();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                TestProtectedStore::new(
                    codewire_protected_store::ProtectedStorePersistence::OperatingSystem,
                ),
                builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "silent-executor".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-codex-bundle").unwrap(),
            )
            .unwrap();
        let spawner = Arc::new(SilentSpawner {
            authority: Arc::clone(&authority),
            id: credential.metadata.id.clone(),
            status_at_spawn: Mutex::new(None),
            pid: Mutex::new(None),
        });
        let revocations = ProviderRevocations::start(
            &authority,
            Some(Arc::clone(&spawner) as Arc<dyn LocalRevocationProcessSpawner>),
        );
        let started = tokio::time::Instant::now();
        let (record, answer) = revocations
            .revoke_at_provider(credential.metadata.id.clone())
            .await
            .unwrap();
        assert!(
            started.elapsed() >= EXECUTOR_BOUND,
            "answered before the bound"
        );
        assert_eq!(answer, Some(not_read()));
        assert_eq!(record.metadata.status, CredentialStatus::Revoked);
        assert_eq!(
            *spawner.status_at_spawn.lock().unwrap(),
            Some(CredentialStatus::Revoked),
            "Codewire's revoke commits before the executor starts"
        );
        let pid = spawner.pid.lock().unwrap().expect("the executor started");
        assert!(pid > 0, "the executor is a real process");
        // `/proc` shows whether it stopped; elsewhere only the answer is checked.
        #[cfg(target_os = "linux")]
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !stopped(pid) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(stopped(pid), "the executor is still running");
        }
    }
}
