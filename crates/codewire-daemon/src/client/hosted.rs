//! Cancellation-first ownership of the hosted daemon request body.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;

use super::SessionClientError;
use codewire_gateway_proto::codewire::bridge::v1;

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
