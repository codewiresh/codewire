use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Relay `bridge` to an authority that admits at once and, once the guest's
/// bridge is open, answers with what `connect` returns: `connect` reads the
/// guest's frames, so it runs only then.
async fn relay<C, F>(
    bridge: FakeBridge,
    environment_id: Uuid,
    generation: u64,
    network_policy: RelayNetworkPolicy,
    connect: C,
) -> Result<(), BrokerBridgeError>
where
    C: FnOnce(v1::CredentialBridgeReady, CredentialBridgeRelayInput) -> F + Send + 'static,
    F: Future<Output = Result<CredentialBridgeRelayOutput, BrokerBridgeError>> + Send + 'static,
{
    run_credential_bridge_relay(
        environment_id,
        generation,
        network_policy,
        move |ready, input| async move {
            let output =
                stream::once(connect(ready, input)).flat_map(|connected| match connected {
                    Ok(output) => output,
                    Err(error) => {
                        Box::pin(stream::iter([Err(error)])) as CredentialBridgeRelayOutput
                    }
                });
            Ok((
                Box::pin(output) as CredentialBridgeRelayOutput,
                std::future::ready(Ok(())),
            ))
        },
        std::future::ready(Ok(bridge)),
    )
    .await
}

/// A guest bridge that records when it is opened, which is when the guest is
/// sent its Open.
fn recorded_open(
    bridge: FakeBridge,
) -> (
    Arc<AtomicBool>,
    impl Future<Output = Result<FakeBridge, BrokerBridgeError>>,
) {
    let opened = Arc::new(AtomicBool::new(false));
    let open = {
        let opened = Arc::clone(&opened);
        async move {
            opened.store(true, Ordering::SeqCst);
            Ok(bridge)
        }
    };
    (opened, open)
}

/// #5957: a relay its authority refuses never opens the guest's bridge, so
/// the guest has no lost epoch and its startup launch waits for the next
/// relay. Before, the Open went first and the refusal powered the VM off.
#[tokio::test]
async fn a_relay_its_authority_refuses_never_opens_the_guest_bridge() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(1);
    let (host_tx, mut host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 3)).await.unwrap();
    let (opened, open) = recorded_open(FakeBridge {
        input: guest_rx,
        output: FakeResponseSink(host_tx),
    });

    let result = run_credential_bridge_relay(
        environment_id,
        3,
        RelayNetworkPolicy::AllowsGitHub,
        |_ready, _input| async {
            Err::<(CredentialBridgeRelayOutput, std::future::Ready<_>), _>(
                BrokerBridgeError::Unavailable,
            )
        },
        open,
    )
    .await;

    assert_eq!(result, Err(BrokerBridgeError::Unavailable));
    assert!(!opened.load(Ordering::SeqCst));
    assert!(host_rx.try_recv().is_err());
}

/// The authority is shown the relay's own Ready before the guest's bridge
/// opens, and the relay is ready only after it has.
#[tokio::test]
async fn the_authority_admits_the_relays_own_ready_before_the_guest_bridge_opens() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(1);
    let (host_tx, _host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 7)).await.unwrap();
    let (opened, open) = recorded_open(FakeBridge {
        input: guest_rx,
        output: FakeResponseSink(host_tx),
    });
    let ready_after_open = Arc::new(AtomicBool::new(false));

    let result = run_credential_bridge_relay(
        environment_id,
        7,
        RelayNetworkPolicy::AllowsGitHub,
        {
            let opened = Arc::clone(&opened);
            let ready_after_open = Arc::clone(&ready_after_open);
            move |actual, _input| async move {
                assert_eq!(
                    actual,
                    v1::CredentialBridgeReady {
                        protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: environment_id.to_string(),
                        environment_generation: 7,
                    }
                );
                assert!(!opened.load(Ordering::SeqCst), "admitted before the open");
                let reported = async move {
                    ready_after_open.store(opened.load(Ordering::SeqCst), Ordering::SeqCst);
                    Ok(())
                };
                Ok((
                    Box::pin(stream::empty()) as CredentialBridgeRelayOutput,
                    reported,
                ))
            }
        },
        open,
    )
    .await;

    assert_eq!(result, Err(BrokerBridgeError::Unavailable));
    assert!(ready_after_open.load(Ordering::SeqCst));
}

/// A guest whose Ready isn't the relay's own is refused, and the relay never
/// reports itself ready.
#[tokio::test]
async fn a_guest_ready_other_than_the_relays_own_is_refused() {
    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(1);
    let (host_tx, _host_rx) = mpsc::channel(1);
    guest_tx.send(ready(environment_id, 8)).await.unwrap();
    let reported = Arc::new(AtomicBool::new(false));

    let result = run_credential_bridge_relay(
        environment_id,
        7,
        RelayNetworkPolicy::AllowsGitHub,
        {
            let reported = Arc::clone(&reported);
            move |_ready, _input| async move {
                let report = async move {
                    reported.store(true, Ordering::SeqCst);
                    Ok(())
                };
                Ok((
                    Box::pin(stream::empty()) as CredentialBridgeRelayOutput,
                    report,
                ))
            }
        },
        std::future::ready(Ok(FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        })),
    )
    .await;

    assert_eq!(result, Err(BrokerBridgeError::InvalidIdentity));
    assert!(!reported.load(Ordering::SeqCst));
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
    let response = v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: "request".into(),
            },
        )),
    };
    let expected_response = response.payload.clone().unwrap();

    let result = relay(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        9,
        RelayNetworkPolicy::AllowsGitHub,
        move |actual, mut input| {
            assert_eq!(actual.environment_id, environment_id.to_string());
            assert_eq!(actual.environment_generation, 9);
            async move {
                assert_eq!(input.next().await, Some(cancel));
                assert!(input.next().await.is_none());
                Ok(Box::pin(stream::iter([Ok(response)])) as CredentialBridgeRelayOutput)
            }
        },
    )
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

    let result = relay(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        3,
        RelayNetworkPolicy::AllowsGitHub,
        |_actual, _input| async {
            Ok(Box::pin(stream::iter([Ok(
                v1::CredentialBridgeHostMessage::default(),
            )])) as CredentialBridgeRelayOutput)
        },
    )
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

    let result = relay(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        4,
        RelayNetworkPolicy::AllowsGitHub,
        move |_actual, mut input| async move {
            assert_eq!(input.next().await, Some(login));
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([Ok(answer)])) as CredentialBridgeRelayOutput)
        },
    )
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

    let result = relay(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        4,
        RelayNetworkPolicy::AllowsGitHub,
        move |_actual, mut input| async move {
            assert_eq!(input.next().await, Some(login));
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([Ok(answer)])) as CredentialBridgeRelayOutput)
        },
    )
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

        let result = relay(
            FakeBridge {
                input: guest_rx,
                output: FakeResponseSink(host_tx),
            },
            environment_id,
            5,
            RelayNetworkPolicy::AllowsGitHub,
            |_actual, mut input| async move {
                assert!(input.next().await.is_none());
                Ok(Box::pin(stream::empty()) as CredentialBridgeRelayOutput)
            },
        )
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

        let result = relay(
            FakeBridge {
                input: guest_rx,
                output: FakeResponseSink(host_tx),
            },
            environment_id,
            6,
            RelayNetworkPolicy::AllowsGitHub,
            |_actual, _input| async {
                Ok(Box::pin(stream::iter([Ok(v1::CredentialBridgeHostMessage {
                    payload,
                })])) as CredentialBridgeRelayOutput)
            },
        )
        .await;

        assert_eq!(result, Err(BrokerBridgeError::InvalidProtocol));
        assert!(host_rx.try_recv().is_err());
        drop(guest_tx);
    }
}

fn request(slot: &str, route: &str) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Request(
            v1::CredentialBridgeRequest {
                capability_slot: slot.into(),
                route: route.into(),
                request_id: Uuid::new_v4().to_string(),
                method: "GET".into(),
                path: "/user".into(),
                ..Default::default()
            },
        )),
    }
}

fn request_id(frame: &v1::CredentialBridgeGuestMessage) -> String {
    match &frame.payload {
        Some(v1::credential_bridge_guest_message::Payload::Request(request)) => {
            request.request_id.clone()
        }
        _ => panic!("not a request"),
    }
}

/// #4926: the remote authority has no network policy in hand, so a relay
/// told that the policy does not allow GitHub answers a GitHub request
/// itself, whole, and relays everything else. Before the fix the GitHub
/// request reached the remote authority.
#[tokio::test]
async fn a_relay_refuses_github_itself_when_the_network_policy_does() {
    use v1::credential_bridge_host_message::Payload;

    let environment_id = Uuid::new_v4();
    let (guest_tx, guest_rx) = mpsc::channel(4);
    let (host_tx, mut host_rx) = mpsc::channel(8);
    guest_tx.send(ready(environment_id, 9)).await.unwrap();
    let github = request("github", "github-api");
    let codex = request("codex", "openai-api");
    guest_tx.send(github.clone()).await.unwrap();
    guest_tx.send(codex.clone()).await.unwrap();
    drop(guest_tx);

    let result = relay(
        FakeBridge {
            input: guest_rx,
            output: FakeResponseSink(host_tx),
        },
        environment_id,
        9,
        RelayNetworkPolicy::RefusesGitHub,
        move |_actual, mut input| async move {
            assert_eq!(input.next().await, Some(codex), "only the other slot");
            assert!(input.next().await.is_none());
            Ok(Box::pin(stream::iter([])) as CredentialBridgeRelayOutput)
        },
    )
    .await;
    assert_eq!(result, Err(BrokerBridgeError::Unavailable));

    let id = request_id(&github);
    match host_rx.recv().await {
        Some(Payload::ResponseStart(start)) => {
            assert_eq!((start.request_id, start.status_code), (id.clone(), 403));
        }
        other => panic!("expected the refusal's start, got {other:?}"),
    }
    match host_rx.recv().await {
        Some(Payload::ResponseBody(body)) => {
            assert_eq!(body.request_id, id);
            let json: serde_json::Value = serde_json::from_slice(&body.data).unwrap();
            assert_eq!(json["code"], "network_policy_refuses_github");
        }
        other => panic!("expected the refusal's body, got {other:?}"),
    }
    assert_eq!(
        host_rx.recv().await,
        Some(Payload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: id
        }))
    );
    assert_eq!(host_rx.recv().await, None);
}
