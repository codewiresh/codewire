use async_trait::async_trait;
use futures::{StreamExt as _, stream};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::*;

#[derive(Clone)]
struct FakeResponseSink(mpsc::Sender<v1::credential_bridge_host_message::Payload>);

#[async_trait]
impl CredentialBridgeResponseSink for FakeResponseSink {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError> {
        self.0
            .send(payload)
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

struct FakeBridge {
    input: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    output: FakeResponseSink,
}

#[async_trait]
impl CredentialBridgeTransport for FakeBridge {
    type ResponseSink = FakeResponseSink;

    fn response_sink(&self) -> Self::ResponseSink {
        self.output.clone()
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        Ok(self.input.recv().await)
    }
}

fn ready(environment_id: Uuid, generation: u64) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
            v1::CredentialBridgeReady {
                protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment_id.to_string(),
                environment_generation: generation,
            },
        )),
    }
}

#[tokio::test]
async fn relay_preserves_actual_ready_and_forwards_only_remaining_frames() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(2);
    let (host_tx, mut host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 9)).await.unwrap();
    let cancel = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
            v1::CredentialBridgeCancel {
                request_id: Uuid::new_v4().to_string(),
            },
        )),
    };
    guest_tx.send(cancel.clone()).await.unwrap();
    drop(guest_tx);
    let admitted = super::super::admit_credential_bridge(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        9,
    )
    .await
    .unwrap();
    let response = v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: "request".into(),
            },
        )),
    };
    let expected_response = response.payload.clone().unwrap();

    let result = run_admitted_credential_bridge_relay(admitted, move |actual, mut input| {
        assert_eq!(actual.environment_id, environment_id.to_string());
        assert_eq!(actual.environment_generation, 9);
        async move {
            assert_eq!(input.next().await, Some(cancel));
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([Ok(response)])) as CredentialBridgeRelayOutput)
        }
    })
    .await;

    assert_eq!(result, Err(BrokerBridgeError::Unavailable));
    assert_eq!(host_rx.recv().await, Some(expected_response));
}

#[tokio::test]
async fn relay_rejects_a_missing_host_payload() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(1);
    let (host_tx, mut host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 3)).await.unwrap();
    let admitted = super::super::admit_credential_bridge(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        3,
    )
    .await
    .unwrap();

    let result = run_admitted_credential_bridge_relay(admitted, |_actual, _input| async {
        Ok(Box::pin(stream::iter([Ok(
            v1::CredentialBridgeHostMessage::default(),
        )])) as CredentialBridgeRelayOutput)
    })
    .await;

    assert_eq!(result, Err(BrokerBridgeError::InvalidProtocol));
    assert!(host_rx.try_recv().is_err());
}
