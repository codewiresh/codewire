use async_trait::async_trait;
use futures::stream;
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

/// A local VM's broker lists the Codex login on its epoch, so the relay
/// carries the request to the platform and its answer back, instead of ending
/// the epoch on it.
#[tokio::test]
async fn relay_carries_the_codex_login_request_and_its_answer() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(2);
    let (host_tx, mut host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 4)).await.unwrap();
    let request_id = Uuid::new_v4().to_string();
    let login = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
            v1::CodexLoginRequest {
                request_id: request_id.clone(),
                recipient_public_key: vec![7; 32],
                deadline_unix_ms: 1,
            },
        )),
    };
    guest_tx.send(login.clone()).await.unwrap();
    drop(guest_tx);
    let admitted = super::super::admit_credential_bridge(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        4,
    )
    .await
    .unwrap();
    let answer = v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::CodexLogin(
            v1::CodexLoginResponse {
                request_id,
                result: Some(v1::codex_login_response::Result::Failure(
                    v1::CredentialBridgeFailureReason::Denied as i32,
                )),
            },
        )),
    };
    let expected = answer.payload.clone().unwrap();

    let result =
        run_admitted_credential_bridge_relay(admitted, move |_actual, mut input| async move {
            assert_eq!(input.next().await, Some(login));
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([Ok(answer)])) as CredentialBridgeRelayOutput)
        })
        .await;

    assert_eq!(result, Err(BrokerBridgeError::Unavailable));
    assert_eq!(host_rx.recv().await, Some(expected));
}

/// A local VM's broker lists the Claude login on its epoch too, so the relay
/// carries the request to the platform and its answer back, instead of ending
/// the epoch on it.
#[tokio::test]
async fn relay_carries_the_claude_login_request_and_its_answer() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(2);
    let (host_tx, mut host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 4)).await.unwrap();
    let request_id = Uuid::new_v4().to_string();
    let login = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::ClaudeLogin(
            v1::ClaudeLoginRequest {
                request_id: request_id.clone(),
                recipient_public_key: vec![7; 32],
                deadline_unix_ms: 1,
            },
        )),
    };
    guest_tx.send(login.clone()).await.unwrap();
    drop(guest_tx);
    let admitted = super::super::admit_credential_bridge(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        4,
    )
    .await
    .unwrap();
    let answer = v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::ClaudeLogin(
            v1::ClaudeLoginResponse {
                request_id,
                result: Some(v1::claude_login_response::Result::Failure(
                    v1::CredentialBridgeFailureReason::Denied as i32,
                )),
            },
        )),
    };
    let expected = answer.payload.clone().unwrap();

    let result =
        run_admitted_credential_bridge_relay(admitted, move |_actual, mut input| async move {
            assert_eq!(input.next().await, Some(login));
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([Ok(answer)])) as CredentialBridgeRelayOutput)
        })
        .await;

    assert_eq!(result, Err(BrokerBridgeError::Unavailable));
    assert_eq!(host_rx.recv().await, Some(expected));
}

fn front_door_guest_payloads() -> Vec<v1::credential_bridge_guest_message::Payload> {
    use v1::credential_bridge_guest_message::Payload;
    vec![
        Payload::Upgrade(v1::CredentialBridgeUpgrade {
            request_id: Uuid::new_v4().to_string(),
            method: "GET".into(),
            path: "/v1/responses".into(),
            intercepted_host: "chatgpt.com".into(),
            initial_credit_bytes: 65_536,
            ..Default::default()
        }),
        Payload::StreamData(v1::CredentialBridgeStreamData {
            request_id: Uuid::new_v4().to_string(),
            data: b"frame".to_vec(),
        }),
        Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
            request_id: Uuid::new_v4().to_string(),
            credit_bytes: 1024,
        }),
        Payload::StreamClose(v1::CredentialBridgeStreamClose {
            request_id: Uuid::new_v4().to_string(),
            kind: v1::CredentialBridgeStreamCloseKind::Reset as i32,
        }),
    ]
}

fn front_door_host_payloads() -> Vec<v1::credential_bridge_host_message::Payload> {
    use v1::credential_bridge_host_message::Payload;
    vec![
        Payload::UpgradeAccepted(v1::CredentialBridgeUpgradeAccepted {
            request_id: Uuid::new_v4().to_string(),
            headers: Vec::new(),
        }),
        Payload::StreamData(v1::CredentialBridgeStreamData {
            request_id: Uuid::new_v4().to_string(),
            data: b"frame".to_vec(),
        }),
        Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
            request_id: Uuid::new_v4().to_string(),
            credit_bytes: 1024,
        }),
        Payload::StreamClose(v1::CredentialBridgeStreamClose {
            request_id: Uuid::new_v4().to_string(),
            kind: v1::CredentialBridgeStreamCloseKind::HalfClose as i32,
        }),
        Payload::InterceptionHint(v1::CredentialBridgeInterceptionHint {
            request_id: Uuid::new_v4().to_string(),
            origin: "https://chatgpt.com".into(),
        }),
    ]
}

/// A front-door guest frame ends the relayed input exactly as an unknown
/// frame (an empty payload, which an older guest's frame decodes as) does:
/// the remote authority sees the stream end, never the frame.
#[tokio::test]
async fn relay_ends_the_input_on_a_front_door_guest_frame_as_on_an_unknown_one() {
    for payload in std::iter::once(None).chain(front_door_guest_payloads().into_iter().map(Some)) {
        let environment_id = Uuid::new_v4();
        let (guest_tx, guest_rx) = mpsc::channel(2);
        let (host_tx, mut host_rx) = mpsc::channel(1);
        guest_tx.send(ready(environment_id, 5)).await.unwrap();
        guest_tx
            .send(v1::CredentialBridgeGuestMessage { payload })
            .await
            .unwrap();
        let admitted = super::super::admit_credential_bridge(
            FakeBridge {
                input: guest_rx,
                output: FakeResponseSink(host_tx),
            },
            environment_id,
            5,
        )
        .await
        .unwrap();

        let result =
            run_admitted_credential_bridge_relay(admitted, |_actual, mut input| async move {
                assert!(input.next().await.is_none());
                Ok(Box::pin(stream::empty()) as CredentialBridgeRelayOutput)
            })
            .await;

        assert_eq!(result, Err(BrokerBridgeError::Unavailable));
        assert!(host_rx.try_recv().is_err());
        drop(guest_tx);
    }
}

/// A front-door host frame ends the relay exactly as an unknown frame does:
/// with InvalidProtocol, and the guest is sent nothing.
#[tokio::test]
async fn relay_refuses_a_front_door_host_frame_as_an_unknown_one() {
    for payload in std::iter::once(None).chain(front_door_host_payloads().into_iter().map(Some)) {
        let environment_id = Uuid::new_v4();
        let (guest_tx, guest_rx) = mpsc::channel(1);
        let (host_tx, mut host_rx) = mpsc::channel(1);
        guest_tx.send(ready(environment_id, 6)).await.unwrap();
        let admitted = super::super::admit_credential_bridge(
            FakeBridge {
                input: guest_rx,
                output: FakeResponseSink(host_tx),
            },
            environment_id,
            6,
        )
        .await
        .unwrap();

        let result = run_admitted_credential_bridge_relay(admitted, |_actual, _input| async {
            Ok(Box::pin(stream::iter([Ok(v1::CredentialBridgeHostMessage {
                payload,
            })])) as CredentialBridgeRelayOutput)
        })
        .await;

        assert_eq!(result, Err(BrokerBridgeError::InvalidProtocol));
        assert!(host_rx.try_recv().is_err());
        drop(guest_tx);
    }
}
