//! One owned relay over existing private RPCs, not an application endpoint.
//! The daemon leg retains the existing authenticated plaintext cluster trust;
//! the broker leg reloads TLS trust and verifies both exact projected Pods.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_daemon::client::{CredentialBridgeResponseSender, SessionClient};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_gateway_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_tls::ClientTlsEndpoint;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;
use tonic::{Status, Streaming};
use uuid::Uuid;

use crate::credentials::{credential_metadata, read_gateway_token};

const PREPARE_TIMEOUT: Duration = Duration::from_secs(10);
const BROKER_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const EPOCH_MAX_LIFETIME: Duration = Duration::from_secs(600);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_BUFFER: usize = 32;

#[derive(Clone)]
pub(crate) struct HostedBridgeConfig {
    environment_id: Uuid,
    generation: u64,
    gateway_token: PathBuf,
    broker: BrokerEndpoint,
}

#[derive(Clone)]
enum BrokerEndpoint {
    Tls(ClientTlsEndpoint),
    #[cfg(test)]
    Preconfigured(tonic::transport::Channel),
}

impl HostedBridgeConfig {
    pub(crate) fn new(
        environment_id: Uuid,
        generation: u64,
        gateway_token: PathBuf,
        broker: ClientTlsEndpoint,
    ) -> Self {
        Self {
            environment_id,
            generation,
            gateway_token,
            broker: BrokerEndpoint::Tls(broker),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("hosted credential bridge transport did not drain")]
struct DrainFailure;

/// Readiness never awaits this owner. Before initial broker admission a launch
/// may wait only within its existing finite projection deadline. New epochs
/// reread tokens; no request from an old epoch is retained or replayed.
pub(crate) async fn run(
    config: HostedBridgeConfig,
    daemon: SessionClient,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let service = async {
        loop {
            if run_epoch(&config, &daemon, cancellation.child_token())
                .await
                .is_err()
            {
                return Err(DrainFailure.into());
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(RETRY_DELAY) => {},
            }
        }
    };
    tokio::pin!(service);
    tokio::select! {
        result = &mut service => result,
        _ = async { while !*shutdown.borrow() { if shutdown.changed().await.is_err() { break; } } } => {
            cancellation.cancel();
            // Do not drop the relay future: it owns both stream halves and
            // must observe the outgoing tonic producer's terminal boundary.
            service.await
        }
    }
}

async fn run_epoch(
    config: &HostedBridgeConfig,
    daemon: &SessionClient,
    cancellation: CancellationToken,
) -> Result<(), DrainFailure> {
    run_epoch_with_lifetime(config, daemon, cancellation, EPOCH_MAX_LIFETIME).await
}

async fn run_epoch_with_lifetime(
    config: &HostedBridgeConfig,
    daemon: &SessionClient,
    cancellation: CancellationToken,
    lifetime: Duration,
) -> Result<(), DrainFailure> {
    let Ok((daemon_drain, preparation)) =
        daemon.prepare_hosted_credential_bridge(config.environment_id, config.generation)
    else {
        return Ok(());
    };
    let result = async {
        let prepare = async {
            let (prepared, output) = preparation.await.map_err(|_| ())?;
            let gateway = read_gateway_token(&config.gateway_token)
                .await
                .map_err(|_| ())?;
            let metadata = credential_metadata(&gateway, prepared.workspace_authorization())
                .map_err(|_| ())?;
            let channel = match &config.broker {
                BrokerEndpoint::Tls(endpoint) => endpoint.connect().await.map_err(|_| ())?,
                #[cfg(test)]
                BrokerEndpoint::Preconfigured(channel) => channel.clone(),
            };
            Ok::<_, ()>((prepared, output, metadata, channel))
        };
        let (prepared, output, metadata, channel) = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            result = tokio::time::timeout(PREPARE_TIMEOUT, prepare) => match result {
                Ok(Ok(prepared)) => prepared,
                _ => return Ok(()),
            },
        };
        let (sender, receiver) = mpsc::channel(FRAME_BUFFER);
        // Forward the actual daemon Ready; never synthesize claimed Pod identity.
        sender
            .try_send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                    prepared.ready().clone(),
                )),
            })
            .map_err(|_| DrainFailure)?;
        let (closed, closed_rx) = oneshot::channel();
        let outgoing = RelayOutput {
            frames: ReceiverStream::new(receiver),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
            closed: Some(closed),
        };
        let mut request = tonic::Request::new(outgoing);
        *request.metadata_mut() = metadata;
        let mut broker = CredentialBrokerServiceClient::new(channel)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        let pump_cancellation = cancellation.clone();
        let pump = tokio::spawn(async move {
            forward_guest(output, sender, &pump_cancellation).await;
            pump_cancellation.cancel();
        });
        let exchange = async {
            let response =
                tokio::time::timeout(BROKER_ADMISSION_TIMEOUT, broker.credential_bridge(request))
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            // Successful TLS/RPC headers certify the broker's dual TokenReview,
            // live Ready Pods, Running DB state, exact generation and real Ready.
            let sender = prepared.activate().await.map_err(|_| ())?;
            let mut responses = response.into_inner();
            loop {
                let frame = match responses.message().await {
                    Ok(Some(frame)) => frame,
                    _ => break,
                };
                if forward_host(&sender, frame).await.is_err() {
                    break;
                }
            }
            Ok::<(), ()>(())
        };
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {},
            _ = tokio::time::sleep(lifetime) => {},
            _ = exchange => {},
        }
        cancellation.cancel();
        daemon_drain.cancel();
        let pump_result = pump.await.map_err(|_| DrainFailure);
        let broker_result = tokio::time::timeout(DRAIN_TIMEOUT, closed_rx)
            .await
            .map_err(|_| DrainFailure)?
            .map_err(|_| DrainFailure);
        pump_result.and(broker_result)
    }
    .await;
    cancellation.cancel();
    // Always await this second producer, including preparation timeout,
    // activation failure and broker rejection; do not use `?` before cleanup.
    let daemon_result = daemon_drain
        .cancel_and_drain()
        .await
        .map_err(|_| DrainFailure);
    result.and(daemon_result)
}

async fn forward_guest(
    mut output: Streaming<v1::CredentialBridgeGuestMessage>,
    sender: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    cancellation: &CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            frame = output.message() => match frame { Ok(Some(frame)) => frame, _ => return },
        };
        if matches!(
            frame.payload,
            None | Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ) {
            return;
        }
        if let Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) = &frame.payload {
            if codewire_gateway_proto::ssh::validate_request(request).is_err() {
                return;
            }
            let Ok(remaining) =
                codewire_gateway_proto::ssh::remaining_deadline(request.deadline_unix_ms)
            else {
                return;
            };
            // Preserve the original deadline through this bounded relay queue.
            // The authority and pending-response owner recheck at their own
            // boundaries; the gateway adds no request or credential selector.
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return,
                _ = tokio::time::sleep(remaining) => return,
                result = sender.send(frame) => if result.is_err() { return; },
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = sender.send(frame) => if result.is_err() { return; },
        }
    }
}

async fn forward_host(
    sender: &CredentialBridgeResponseSender,
    frame: v1::CredentialBridgeHostMessage,
) -> Result<(), Status> {
    use v1::credential_bridge_host_message::Payload;
    let result = match frame.payload {
        Some(Payload::ResponseStart(value)) => sender.send_response_start(value).await,
        Some(Payload::ResponseBody(value)) => sender.send_response_body(value).await,
        Some(Payload::ResponseEnd(value)) => sender.send_response_end(value).await,
        Some(Payload::ResponseFailure(value)) => sender.send_response_failure(value).await,
        Some(Payload::Ssh(value)) => sender.send_ssh(value).await,
        Some(Payload::EnvironmentProjection(value)) => {
            sender.send_environment_projection(value).await
        }
        Some(Payload::Open(_)) | None => {
            return Err(Status::unavailable(
                "hosted credential bridge frame is invalid",
            ));
        }
    };
    result.map_err(|_| Status::unavailable("hosted credential bridge stream is unavailable"))
}

/// Cancelling an epoch wins over queued frames. Its owner waits for this exact
/// tonic producer to finish, not merely for its forwarding task to stop.
struct RelayOutput {
    frames: ReceiverStream<v1::CredentialBridgeGuestMessage>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: Option<oneshot::Sender<()>>,
}
impl RelayOutput {
    fn finish(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
impl Stream for RelayOutput {
    type Item = v1::CredentialBridgeGuestMessage;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed.is_none() {
            return Poll::Ready(None);
        }
        if self.cancelled.as_mut().poll(context).is_ready() {
            self.finish();
            return Poll::Ready(None);
        }
        let result = Pin::new(&mut self.frames).poll_next(context);
        if matches!(result, Poll::Ready(None)) {
            self.finish();
        }
        result
    }
}
impl Drop for RelayOutput {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests;
