//! One-shot provider revocation for a local credential (#4717). The
//! authority revokes the credential first, reads the revoked generation, then
//! spawns a confined executor over an inherited stream. The executor's one
//! lease carries that generation's value, and it opens no store (#4984). It
//! asks the provider through a transport that admits only the revocation
//! route, and reports only the outcome class. The authority process makes no
//! network request.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_protected_store::ProtectedValue;
use futures::StreamExt as _;
use futures::stream::{once, pending};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::local_credential_revocation_lease_service_client::LocalCredentialRevocationLeaseServiceClient;
use crate::control::v1::local_credential_revocation_lease_service_server::{
    LocalCredentialRevocationLeaseService, LocalCredentialRevocationLeaseServiceServer,
};
use crate::repository::ObservedRepositoryStream;

pub const REVOCATION_LEASE_PROTOCOL_VERSION: u32 = 2;
const REVOCATION_LEASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REVOCATION_LEASE_RPC_MESSAGE_BYTES: usize = 16 * 1024;
/// One executor's launch: its request identity. It needs no directory: it
/// writes nothing, and its one value arrives through its lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRevocationProcessConfig {
    pub request_id: Uuid,
}

impl LocalRevocationProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalRevocationSpawnError> {
        if self.request_id.is_nil() {
            return Err(LocalRevocationSpawnError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalRevocationSpawnError {
    #[error("local provider revocation executor launch configuration is invalid")]
    InvalidConfiguration,
    #[error("spawn local provider revocation executor failed")]
    Spawn,
}

/// Authority-owned one-shot provider revocation launcher. The lease stream is
/// transferred directly into the child and never exposed at a socket path.
pub trait LocalRevocationProcessSpawner: Send + Sync + 'static {
    fn spawn(
        &self,
        config: &LocalRevocationProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRevocationSpawnError>;
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RevocationLeaseChannelError {
    #[error("provider revocation lease request is invalid")]
    InvalidRequest,
    #[error("provider revocation lease was denied")]
    Denied,
    #[error("provider revocation lease authority is unavailable")]
    Unavailable,
}

/// The one credential generation an executor may lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevocationLease {
    pub request_id: Uuid,
    pub credential_id: String,
    pub material_generation: u64,
}

struct RevocationLeaseRpc {
    lease: RevocationLease,
    /// The leased generation's entry, taken by the one lease (#4984).
    material: Mutex<Option<ProtectedValue>>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    report: Mutex<Option<oneshot::Sender<v1::ProviderRevocation>>>,
    leased: AtomicBool,
}

impl RevocationLeaseRpc {
    fn same_request(&self, request_id: &str) -> Result<(), Status> {
        if request_id == self.lease.request_id.to_string() {
            Ok(())
        } else {
            Err(Status::permission_denied("not this executor's request"))
        }
    }
}

#[tonic::async_trait]
impl LocalCredentialRevocationLeaseService for RevocationLeaseRpc {
    async fn report_revocation_executor_ready(
        &self,
        request: Request<v1::RevocationExecutorReadyRequest>,
    ) -> Result<Response<v1::RevocationExecutorReadyResponse>, Status> {
        let request = request.into_inner();
        if request.protocol_version != REVOCATION_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "revocation lease protocol mismatch",
            ));
        }
        self.same_request(&request.request_id)?;
        let ready = self.ready.lock().await.take();
        ready
            .ok_or_else(|| Status::failed_precondition("ready already reported"))?
            .send(())
            .map_err(|_| Status::unavailable("authority stopped waiting"))?;
        Ok(Response::new(v1::RevocationExecutorReadyResponse {}))
    }

    async fn lease_revocation_credential(
        &self,
        request: Request<v1::RevocationCredentialLeaseRequest>,
    ) -> Result<Response<v1::RevocationCredentialLeaseResponse>, Status> {
        self.same_request(&request.into_inner().request_id)?;
        if self.ready.lock().await.is_some() || self.leased.swap(true, Ordering::SeqCst) {
            return Err(Status::failed_precondition("one lease, after ready"));
        }
        let material = self
            .material
            .lock()
            .await
            .take()
            .ok_or_else(|| Status::failed_precondition("one lease, after ready"))?;
        Ok(Response::new(v1::RevocationCredentialLeaseResponse {
            credential_id: self.lease.credential_id.clone(),
            material_generation: self.lease.material_generation,
            material: material.expose_secret().to_vec(),
        }))
    }

    async fn report_provider_revocation(
        &self,
        request: Request<v1::ProviderRevocationReportRequest>,
    ) -> Result<Response<v1::ProviderRevocationReportResponse>, Status> {
        let request = request.into_inner();
        self.same_request(&request.request_id)?;
        if !self.leased.load(Ordering::SeqCst) {
            return Err(Status::failed_precondition("report follows the lease"));
        }
        let outcome = request
            .outcome
            .ok_or_else(|| Status::invalid_argument("report names no outcome"))?;
        let report = self.report.lock().await.take();
        report
            .ok_or_else(|| Status::failed_precondition("outcome already reported"))?
            .send(outcome)
            .map_err(|_| Status::unavailable("authority stopped waiting"))?;
        Ok(Response::new(v1::ProviderRevocationReportResponse {}))
    }
}

/// Serve one executor's lease channel until it closes: ready, one lease of
/// `lease` carrying `material`, one outcome report. Only the executor holding
/// `stream`, the one spawned for this lease, can ask for it.
pub(crate) async fn serve_revocation_lease_channel(
    stream: UnixStream,
    lease: RevocationLease,
    material: ProtectedValue,
    ready: oneshot::Sender<()>,
    report: oneshot::Sender<v1::ProviderRevocation>,
) -> Result<(), RevocationLeaseChannelError> {
    if lease.request_id.is_nil() {
        return Err(RevocationLeaseChannelError::InvalidRequest);
    }
    let service = RevocationLeaseRpc {
        lease,
        material: Mutex::new(Some(material)),
        ready: Mutex::new(Some(ready)),
        report: Mutex::new(Some(report)),
        leased: AtomicBool::new(false),
    };
    let (closed_tx, closed_rx) = oneshot::channel();
    let incoming = once(async move {
        Ok::<_, io::Error>(ObservedRepositoryStream {
            inner: stream,
            closed: Some(closed_tx),
        })
    })
    .chain(pending());
    Server::builder()
        .concurrency_limit_per_connection(1)
        .add_service(
            LocalCredentialRevocationLeaseServiceServer::new(service)
                .max_decoding_message_size(MAX_REVOCATION_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_REVOCATION_LEASE_RPC_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = closed_rx.await;
        })
        .await
        .map_err(|_| RevocationLeaseChannelError::Unavailable)
}

/// The executor's side of its inherited lease stream.
pub struct LocalRevocationLeaseClient {
    inner: LocalCredentialRevocationLeaseServiceClient<Channel>,
    request_id: Uuid,
}

impl LocalRevocationLeaseClient {
    pub async fn connect(
        stream: UnixStream,
        request_id: Uuid,
    ) -> Result<Self, RevocationLeaseChannelError> {
        if request_id.is_nil() {
            return Err(RevocationLeaseChannelError::InvalidRequest);
        }
        let stream = Arc::new(Mutex::new(Some(stream)));
        let channel = Endpoint::from_static("http://codewire-local-revocation-lease")
            .timeout(REVOCATION_LEASE_REQUEST_TIMEOUT)
            .connect_with_connector(tower::service_fn(move |_| {
                let stream = Arc::clone(&stream);
                async move {
                    stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "revocation lease channel already consumed",
                        )
                    })
                }
            }))
            .await
            .map_err(|_| RevocationLeaseChannelError::Unavailable)?;
        Ok(Self {
            inner: LocalCredentialRevocationLeaseServiceClient::new(channel)
                .max_decoding_message_size(MAX_REVOCATION_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_REVOCATION_LEASE_RPC_MESSAGE_BYTES),
            request_id,
        })
    }

    pub async fn report_ready(&mut self) -> Result<(), RevocationLeaseChannelError> {
        self.inner
            .report_revocation_executor_ready(v1::RevocationExecutorReadyRequest {
                protocol_version: REVOCATION_LEASE_PROTOCOL_VERSION,
                request_id: self.request_id.to_string(),
            })
            .await
            .map(|_| ())
            .map_err(map_status)
    }

    /// The one value the executor revokes, from its lease (#4984): it opens no
    /// store. `None` when the lease carries none.
    pub async fn lease(&mut self) -> Result<Option<ProtectedValue>, RevocationLeaseChannelError> {
        let mut lease = self
            .inner
            .lease_revocation_credential(v1::RevocationCredentialLeaseRequest {
                request_id: self.request_id.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(ProtectedValue::new(std::mem::take(&mut lease.material)).ok())
    }

    pub async fn report(
        &mut self,
        outcome: v1::ProviderRevocation,
    ) -> Result<(), RevocationLeaseChannelError> {
        self.inner
            .report_provider_revocation(v1::ProviderRevocationReportRequest {
                request_id: self.request_id.to_string(),
                outcome: Some(outcome),
            })
            .await
            .map(|_| ())
            .map_err(map_status)
    }
}

fn map_status(status: Status) -> RevocationLeaseChannelError {
    match status.code() {
        tonic::Code::InvalidArgument => RevocationLeaseChannelError::InvalidRequest,
        tonic::Code::PermissionDenied | tonic::Code::FailedPrecondition => {
            RevocationLeaseChannelError::Denied
        }
        _ => RevocationLeaseChannelError::Unavailable,
    }
}

/// The executor's run on its connected channel: ready, its one lease and the
/// value it carries, `ask`, then its one report. A lease without a value is
/// reported NOT_READ and the provider is not asked.
pub async fn run_revocation_executor<F, Fut>(
    client: &mut LocalRevocationLeaseClient,
    ask: F,
) -> Result<(), RevocationLeaseChannelError>
where
    F: FnOnce(ProtectedValue) -> Fut,
    Fut: std::future::Future<Output = v1::ProviderRevocation>,
{
    client.report_ready().await?;
    let outcome = match client.lease().await? {
        Some(material) => ask(material).await,
        None => v1::ProviderRevocation {
            outcome: v1::ProviderRevocationOutcome::Failed.into(),
            failure: v1::ProviderRevocationFailure::NotRead.into(),
            http_status: 0,
        },
    };
    client.report(outcome).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(request_id: Uuid) -> RevocationLease {
        RevocationLease {
            request_id,
            credential_id: "synthetic-credential".into(),
            material_generation: 3,
        }
    }

    fn value() -> ProtectedValue {
        ProtectedValue::from_slice(b"synthetic-codex-bundle").unwrap()
    }

    #[tokio::test]
    async fn the_channel_leases_once_after_ready_then_takes_one_report() {
        let request_id = Uuid::new_v4();
        let (authority, executor) = UnixStream::pair().unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (report_tx, report_rx) = oneshot::channel();
        let server = tokio::spawn(serve_revocation_lease_channel(
            authority,
            lease(request_id),
            value(),
            ready_tx,
            report_tx,
        ));
        let mut client = LocalRevocationLeaseClient::connect(executor, request_id)
            .await
            .unwrap();
        assert!(
            matches!(
                client.lease().await,
                Err(RevocationLeaseChannelError::Denied)
            ),
            "no lease before ready"
        );
        client.report_ready().await.unwrap();
        ready_rx.await.unwrap();
        let leased = client
            .lease()
            .await
            .unwrap()
            .expect("the lease carries its value");
        assert_eq!(leased.expose_secret(), b"synthetic-codex-bundle");
        // Once means once: a repeated lease gets no second copy.
        assert!(
            matches!(
                client.lease().await,
                Err(RevocationLeaseChannelError::Denied)
            ),
            "one lease"
        );
        let reported = v1::ProviderRevocation {
            outcome: v1::ProviderRevocationOutcome::Confirmed.into(),
            failure: v1::ProviderRevocationFailure::Unspecified.into(),
            http_status: 0,
        };
        client.report(reported).await.unwrap();
        assert_eq!(report_rx.await.unwrap(), reported);
        assert_eq!(
            client.report(reported).await,
            Err(RevocationLeaseChannelError::Denied),
            "one report"
        );
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn another_executors_request_is_refused() {
        let (authority, executor) = UnixStream::pair().unwrap();
        let (ready_tx, _ready_rx) = oneshot::channel();
        let (report_tx, _report_rx) = oneshot::channel();
        let server = tokio::spawn(serve_revocation_lease_channel(
            authority,
            lease(Uuid::new_v4()),
            value(),
            ready_tx,
            report_tx,
        ));
        let mut client = LocalRevocationLeaseClient::connect(executor, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(
            client.report_ready().await,
            Err(RevocationLeaseChannelError::Denied)
        );
        // Another request's lease gets no value.
        assert!(matches!(
            client.lease().await,
            Err(RevocationLeaseChannelError::Denied)
        ));
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_report_under_another_request_is_refused() {
        let request_id = Uuid::new_v4();
        let (authority, executor) = UnixStream::pair().unwrap();
        let (ready_tx, _ready_rx) = oneshot::channel();
        let (report_tx, mut report_rx) = oneshot::channel();
        let server = tokio::spawn(serve_revocation_lease_channel(
            authority,
            lease(request_id),
            value(),
            ready_tx,
            report_tx,
        ));
        let mut client = LocalRevocationLeaseClient::connect(executor, request_id)
            .await
            .unwrap();
        client.report_ready().await.unwrap();
        client.lease().await.unwrap();
        let refused = client
            .inner
            .report_provider_revocation(v1::ProviderRevocationReportRequest {
                request_id: Uuid::new_v4().to_string(),
                outcome: Some(v1::ProviderRevocation {
                    outcome: v1::ProviderRevocationOutcome::Confirmed.into(),
                    failure: v1::ProviderRevocationFailure::Unspecified.into(),
                    http_status: 0,
                }),
            })
            .await;
        assert!(refused.is_err(), "another request's report was taken");
        assert!(report_rx.try_recv().is_err(), "the authority received it");
        // The executor's own report is still taken.
        let reported = v1::ProviderRevocation {
            outcome: v1::ProviderRevocationOutcome::Confirmed.into(),
            failure: v1::ProviderRevocationFailure::Unspecified.into(),
            http_status: 0,
        };
        client.report(reported).await.unwrap();
        assert_eq!(report_rx.await.unwrap(), reported);
        drop(client);
        let _ = server.await;
    }

    /// An authority that predates #4984: its lease names the generation and
    /// carries no value.
    struct ValuelessLease(Uuid);

    #[tonic::async_trait]
    impl LocalCredentialRevocationLeaseService for ValuelessLease {
        async fn report_revocation_executor_ready(
            &self,
            _request: Request<v1::RevocationExecutorReadyRequest>,
        ) -> Result<Response<v1::RevocationExecutorReadyResponse>, Status> {
            Ok(Response::new(v1::RevocationExecutorReadyResponse {}))
        }

        async fn lease_revocation_credential(
            &self,
            _request: Request<v1::RevocationCredentialLeaseRequest>,
        ) -> Result<Response<v1::RevocationCredentialLeaseResponse>, Status> {
            Ok(Response::new(v1::RevocationCredentialLeaseResponse {
                credential_id: self.0.to_string(),
                material_generation: 3,
                material: Vec::new(),
            }))
        }

        async fn report_provider_revocation(
            &self,
            _request: Request<v1::ProviderRevocationReportRequest>,
        ) -> Result<Response<v1::ProviderRevocationReportResponse>, Status> {
            Ok(Response::new(v1::ProviderRevocationReportResponse {}))
        }
    }

    /// The executor's run against a lease from `authority`: whether it asked
    /// the provider.
    async fn executor_asks(valueless: bool) -> bool {
        let request_id = Uuid::new_v4();
        let (authority, executor) = UnixStream::pair().unwrap();
        let (ready_tx, _ready_rx) = oneshot::channel();
        let (report_tx, _report_rx) = oneshot::channel();
        let server = if valueless {
            tokio::spawn(async move {
                let incoming = once(async move { Ok::<_, io::Error>(authority) }).chain(pending());
                let _ = Server::builder()
                    .add_service(LocalCredentialRevocationLeaseServiceServer::new(
                        ValuelessLease(request_id),
                    ))
                    .serve_with_incoming(incoming)
                    .await;
                Ok::<(), RevocationLeaseChannelError>(())
            })
        } else {
            tokio::spawn(serve_revocation_lease_channel(
                authority,
                lease(request_id),
                value(),
                ready_tx,
                report_tx,
            ))
        };
        let mut client = LocalRevocationLeaseClient::connect(executor, request_id)
            .await
            .unwrap();
        let asked = Arc::new(AtomicBool::new(false));
        let asking = Arc::clone(&asked);
        run_revocation_executor(&mut client, |material| async move {
            assert_eq!(material.expose_secret(), b"synthetic-codex-bundle");
            asking.store(true, Ordering::SeqCst);
            v1::ProviderRevocation {
                outcome: v1::ProviderRevocationOutcome::Confirmed.into(),
                failure: v1::ProviderRevocationFailure::Unspecified.into(),
                http_status: 0,
            }
        })
        .await
        .unwrap();
        drop(client);
        server.abort();
        asked.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn the_executor_asks_only_with_a_leased_value() {
        assert!(
            executor_asks(false).await,
            "the leased value was not asked about"
        );
        // An authority that sends no value: the executor refuses, NOT_READ,
        // and never reads a store.
        assert!(
            !executor_asks(true).await,
            "the provider was asked without a value"
        );
    }
}
