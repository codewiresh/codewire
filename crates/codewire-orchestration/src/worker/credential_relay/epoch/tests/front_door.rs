//! A front-door session's frames and capabilities never cross a daemon's
//! epoch. Each frame, in either direction, ends the epoch exactly as an
//! unknown frame (an empty payload, which an older peer decodes one as)
//! does, and the front-door capabilities a broker lists never reach the
//! daemon's Open.
use super::budgets::admitted;
use super::*;

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

#[tokio::test]
async fn a_front_door_guest_frame_ends_the_epoch_as_an_unknown_frame_does() {
    let mut fixture = Fixture::new().await;
    for payload in std::iter::once(None).chain(front_door_guest_payloads().into_iter().map(Some)) {
        let (_cancel, task) = fixture.epoch();
        let (daemon, mut broker) = admitted(&mut fixture).await;
        daemon
            .output
            .send(Ok(v1::CredentialBridgeGuestMessage { payload }))
            .await
            .unwrap();
        bounded(task).await.unwrap().unwrap();
        // The broker saw the stream end, never the frame.
        assert!(!matches!(
            bounded(broker.input.message()).await,
            Ok(Some(_))
        ));
        drop((daemon, broker));
    }
    fixture.stop().await;
}

#[tokio::test]
async fn a_front_door_host_frame_ends_the_epoch_as_an_unknown_frame_does() {
    let mut fixture = Fixture::new().await;
    for payload in std::iter::once(None).chain(front_door_host_payloads().into_iter().map(Some)) {
        let (_cancel, task) = fixture.epoch();
        let (mut daemon, broker) = admitted(&mut fixture).await;
        broker
            .output
            .send(Ok(v1::CredentialBridgeHostMessage { payload }))
            .await
            .unwrap();
        bounded(task).await.unwrap().unwrap();
        // The daemon saw the stream end, never the frame.
        assert!(!matches!(
            bounded(daemon.input.message()).await,
            Ok(Some(_))
        ));
        drop((daemon, broker));
    }
    fixture.stop().await;
}

#[tokio::test]
async fn front_door_capabilities_a_broker_lists_never_reach_the_daemon() {
    let mut fixture = Fixture::new().await;
    let mut listed = vec!["codex-login"];
    listed.extend(codewire_daemon_proto::CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES);
    *fixture.broker_capabilities.lock().unwrap() = listed;
    let (cancel, task) = fixture.epoch();
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let mut broker = bounded(fixture.broker_calls.recv()).await.unwrap();
    let accept = std::mem::replace(&mut broker.accept, oneshot::channel().0);
    accept.send(Ok(())).unwrap();
    let Some(v1::credential_bridge_host_message::Payload::Open(open)) =
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload
    else {
        panic!("Open must follow broker admission");
    };
    assert_eq!(open.capabilities, ["codex-login"]);
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    drop((daemon, broker));
    fixture.stop().await;
}
