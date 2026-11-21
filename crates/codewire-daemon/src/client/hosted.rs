//! Cancellation-first ownership of the hosted daemon request body.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;

use zeroize::Zeroizing;

use super::{
    CredentialBridgeResponseSender, SessionClientError, known_credential_bridge_capabilities,
};
use codewire_daemon_proto::codewire::bridge::v1;

/// The admitted hosted daemon response, still inactive until the broker opens
/// it. Its request producer remains owned by the separately returned drain.
pub type HostedCredentialBridgePrepared = (
    PreparedHostedCredentialBridge,
    tonic::Streaming<v1::CredentialBridgeGuestMessage>,
);

pub(super) struct HostedLifetime(CancellationToken);
impl Drop for HostedLifetime {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Must remain owned from preparation through teardown. Cancellation is not
/// proof of closure: await cancel_and_drain before admitting another epoch.
#[must_use = "cancel and await the hosted daemon producer on every terminal path"]
pub struct HostedCredentialBridgeDrain {
    cancellation: CancellationToken,
    closed: Option<oneshot::Receiver<()>>,
}
impl HostedCredentialBridgeDrain {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub async fn cancel_and_drain(mut self) -> Result<(), SessionClientError> {
        self.cancel();
        let closed = self
            .closed
            .take()
            .ok_or(SessionClientError::RequestClosed)?;
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .map_err(|_| SessionClientError::RequestClosed)?
            .map_err(|_| SessionClientError::RequestClosed)
    }
}
impl Drop for HostedCredentialBridgeDrain {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) fn channel() -> (
    mpsc::Sender<v1::CredentialBridgeHostMessage>,
    HostedRequestBody,
    Arc<HostedLifetime>,
    HostedCredentialBridgeDrain,
) {
    let (input, frames) = mpsc::channel(32);
    let cancellation = CancellationToken::new();
    let (closed, receiver) = oneshot::channel();
    (
        input,
        HostedRequestBody {
            frames: ReceiverStream::new(frames),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
            closed: Some(closed),
        },
        Arc::new(HostedLifetime(cancellation.clone())),
        HostedCredentialBridgeDrain {
            cancellation,
            closed: Some(receiver),
        },
    )
}

pub(super) struct HostedRequestBody {
    frames: ReceiverStream<v1::CredentialBridgeHostMessage>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: Option<oneshot::Sender<()>>,
}
impl HostedRequestBody {
    fn finish(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
impl Stream for HostedRequestBody {
    type Item = v1::CredentialBridgeHostMessage;
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
impl Drop for HostedRequestBody {
    fn drop(&mut self) {
        self.finish();
    }
}

/// An inactive hosted stream. No Open has been sent and no live daemon epoch
/// replaced. Its fixed-purpose token is never exposed by Debug or a session RPC.
pub struct PreparedHostedCredentialBridge {
    pub(super) input: mpsc::Sender<v1::CredentialBridgeHostMessage>,
    pub(super) ready: v1::CredentialBridgeReady,
    pub(super) workspace_authorization: Zeroizing<Vec<u8>>,
    pub(super) hosted_lifetime: Arc<HostedLifetime>,
}

impl PreparedHostedCredentialBridge {
    pub fn ready(&self) -> &v1::CredentialBridgeReady {
        &self.ready
    }
    pub fn workspace_authorization(&self) -> &[u8] {
        &self.workspace_authorization
    }

    /// Call only after the isolated broker returned authenticated admission
    /// headers for this stream's real Ready and both exact Pod tokens.
    /// `capabilities` are the optional operations that broker listed in those
    /// headers; the daemon sends such an operation only when its Open lists
    /// it. Only bounded, canonical names this build knows are forwarded.
    /// `placeholders` are the ones an intercepted epoch's broker derived
    /// (#4001), already read whole from its admission; empty for any other.
    pub async fn activate(
        self,
        capabilities: &[String],
        placeholders: &codewire_access::ProjectedPlaceholders,
    ) -> Result<CredentialBridgeResponseSender, SessionClientError> {
        let forwarded =
            known_credential_bridge_capabilities(capabilities.iter().map(String::as_str));
        self.input
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::Open(
                    v1::CredentialBridgeOpen {
                        protocol_version: self.ready.protocol_version,
                        environment_id: self.ready.environment_id.clone(),
                        environment_generation: self.ready.environment_generation,
                        capabilities: forwarded,
                        placeholders: placeholders
                            .entries()
                            .map(|(slot, placeholder)| v1::CredentialBridgePlaceholder {
                                capability_slot: slot.to_owned(),
                                placeholder: placeholder.as_str().to_owned(),
                            })
                            .collect(),
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        Ok(CredentialBridgeResponseSender {
            input: self.input,
            _hosted_lifetime: Some(self.hosted_lifetime),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn cancel_wins_over_queued_open_projection_and_http_frames() {
        let (sender, mut body, _lifetime, drain) = channel();
        for payload in [
            v1::credential_bridge_host_message::Payload::Open(v1::CredentialBridgeOpen::default()),
            v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionResponse::default(),
            ),
            v1::credential_bridge_host_message::Payload::ResponseBody(
                v1::CredentialBridgeResponseBody::default(),
            ),
        ] {
            sender
                .send(v1::CredentialBridgeHostMessage {
                    payload: Some(payload),
                })
                .await
                .unwrap();
        }
        drain.cancel();
        assert!(body.next().await.is_none());
        drain.cancel_and_drain().await.unwrap();
        assert!(body.next().await.is_none());
    }

    #[tokio::test]
    async fn dropping_unpolled_preparation_and_last_response_owner_cancel_producer() {
        let (_sender, body, _lifetime, drain) = channel();
        drop(body);
        drain.cancel_and_drain().await.unwrap();
        let (sender, mut body, lifetime, drain) = channel();
        sender
            .send(v1::CredentialBridgeHostMessage::default())
            .await
            .unwrap();
        drop(lifetime);
        assert!(body.next().await.is_none());
        drain.cancel_and_drain().await.unwrap();
    }
}
