//! A front door's WebSocket handshake through the broker (#3999): only
//! Codex's model call upgrades, the swap rule applies to the handshake, and
//! the `101` reaches the front door without cookies, framing or our
//! credential.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::runtime::upgrade::BrokerUpgradeOutcome;

const MODEL_CALL: &str = "/backend-api/codex/responses";

/// Codex's handshake for `path`, as the front door's bridge sends it.
fn handshake(path: &str, credential: Option<String>) -> v1::CredentialBridgeUpgrade {
    let request = codex("GET", path, credential);
    let mut headers = request.headers;
    headers.retain(|header| header.name != "content-type");
    headers.push(v1::CredentialHttpHeader {
        name: "sec-websocket-key".into(),
        value: b"test-nonce".to_vec(),
    });
    headers.push(v1::CredentialHttpHeader {
        name: "sec-websocket-version".into(),
        value: b"13".to_vec(),
    });
    v1::CredentialBridgeUpgrade {
        request_id: request.request_id,
        method: "GET".into(),
        path: request.path,
        query: request.query,
        headers,
        capability_slot: request.capability_slot,
        route: request.route,
        intercepted_host: request.intercepted_host,
        initial_credit_bytes: codewire_daemon_proto::CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
        intercept_decision: Vec::new(),
    }
}

fn signed_in() -> Recorded {
    Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        ..Recorded::default()
    }
}

#[tokio::test]
async fn codex_s_placeholder_on_the_handshake_is_swapped_and_the_101_is_cleaned() {
    let recorded = signed_in();
    let broker = recorded.broker();
    let Ok(BrokerUpgradeOutcome::Switched { headers, grant, .. }) = broker
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await
    else {
        panic!("the handshake switches");
    };
    assert!(grant.is_some(), "a swapped socket is leased again");
    assert_eq!(headers["sec-websocket-accept"], "test-accept");
    for gone in ["set-cookie", "connection", "upgrade"] {
        assert!(headers.get(gone).is_none(), "{gone} reached the front door");
    }
    let outbound = recorded.outbound();
    let sent = &outbound[0];
    assert_eq!(sent.1, format!("https://chatgpt.com{MODEL_CALL}"));
    assert!(header(sent, "authorization")[0].starts_with(b"Bearer ey"));
    assert_eq!(header(sent, "connection"), [&b"Upgrade"[..]]);
    assert_eq!(header(sent, "upgrade"), [&b"websocket"[..]]);
    assert_eq!(header(sent, "sec-websocket-key"), [&b"test-nonce"[..]]);
    assert!(
        sent.2.iter().all(|(_, value)| !contains(value, OURS)),
        "the placeholder never leaves"
    );
    assert_eq!(recorded.leases(), 1);
}

#[tokio::test]
async fn a_users_own_token_opens_its_socket_untouched_and_without_a_lease() {
    let recorded = signed_in();
    let broker = recorded.broker();
    let Ok(BrokerUpgradeOutcome::Switched { grant, .. }) = broker
        .execute_front_door_upgrade(handshake(
            MODEL_CALL,
            Some("Bearer users-own-token".to_owned()),
        ))
        .await
    else {
        panic!("the handshake switches");
    };
    assert!(grant.is_none(), "nothing of ours to renew");
    assert_eq!(recorded.leases(), 0);
    assert_eq!(
        header(&recorded.outbound()[0], "authorization"),
        [&b"Bearer users-own-token"[..]]
    );
}

#[tokio::test]
async fn only_the_model_call_upgrades_and_only_with_a_whole_handshake() {
    let recorded = signed_in();
    let broker = recorded.broker();
    let other_path = broker
        .execute_front_door_upgrade(handshake(
            "/backend-api/codex/models",
            Some(format!("Bearer {OURS}")),
        ))
        .await;
    assert!(matches!(
        other_path,
        Err(BrokerRequestError::InvalidRequest)
    ));
    let mut keyless = handshake(MODEL_CALL, Some(format!("Bearer {OURS}")));
    keyless
        .headers
        .retain(|header| header.name != "sec-websocket-key");
    assert!(matches!(
        broker.execute_front_door_upgrade(keyless).await,
        Err(BrokerRequestError::InvalidRequest)
    ));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

#[tokio::test]
async fn a_101_that_echoes_our_credential_fails_the_upgrade() {
    let recorded = Recorded {
        echo_credential: true,
        ..signed_in()
    };
    let broker = recorded.broker();
    assert!(matches!(
        broker
            .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
            .await,
        Err(BrokerRequestError::UpstreamFailed)
    ));
}

#[tokio::test]
async fn a_sockets_grant_holds_while_its_credential_still_leases() {
    let recorded = signed_in();
    let broker = recorded.broker();
    let Ok(BrokerUpgradeOutcome::Switched {
        grant: Some(grant), ..
    }) = broker
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await
    else {
        panic!("the handshake switches with a grant");
    };
    assert!(broker.socket_grant_holds(&grant).await);
    assert_eq!(recorded.leases(), 2);
}

/// The front door's bridge, the session socket and the broker's runner,
/// end to end: the session's Open lists WebSockets, the handshake is
/// swapped, and bytes cross the socket both ways.
#[tokio::test]
async fn a_websocket_crosses_the_front_door_session_end_to_end() {
    let recorded = signed_in();
    let sessions = TwoSessions::start(&recorded).await;
    let request = http::Request::get(format!("/v1{MODEL_CALL}"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "test-nonce")
        .header("sec-websocket-version", "13")
        .header("authorization", format!("Bearer {OURS}"))
        .body(())
        .unwrap();
    let codewire_credential_bridge::UpgradeAnswer::Switched {
        response,
        mut socket,
    } = sessions
        .guest
        .upgrade_intercepted("chatgpt.com", request)
        .await
    else {
        panic!("the front door's handshake switches");
    };
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.headers()["sec-websocket-accept"], "test-accept");
    let mut provider = recorded.sockets.lock().unwrap().pop().unwrap();
    socket.write_all(b"hello").await.unwrap();
    let mut got = [0_u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        provider.read_exact(&mut got),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&got, b"hello");
    provider.write_all(b"world").await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        socket.read_exact(&mut got),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&got, b"world");
}

/// A provider's 401 to the handshake is handled like a request's: the
/// sign-in is fetched again outside the environment and the handshake
/// retried once. Here the second lease already holds a newer sign-in, so the
/// retry needs no refresh, and the socket opens.
#[tokio::test]
async fn a_401_to_the_handshake_is_retried_once_with_a_newer_sign_in() {
    let recorded = Recorded {
        unauthorized_upgrades: Arc::new(AtomicUsize::new(1)),
        ..signed_in()
    };
    recorded
        .plan
        .lock()
        .unwrap()
        .extend([LeasePlan::Ordinary, LeasePlan::NewerSignIn]);
    let broker = recorded.broker();
    let outcome = broker
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await;
    assert!(matches!(outcome, Ok(BrokerUpgradeOutcome::Switched { .. })));
    let outbound = recorded.outbound();
    assert_eq!(outbound.len(), 2, "one handshake, then one retry");
    for sent in &outbound {
        assert!(header(sent, "authorization")[0].starts_with(b"Bearer ey"));
    }
}

/// The handshake's 401 of a sign-in refreshed under ten minutes ago is
/// answered as it came, with no refresh and no second handshake (#4974).
#[tokio::test]
async fn a_401_to_the_handshake_of_a_sign_in_refreshed_just_now_refreshes_nothing() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let recorded = Recorded {
        unauthorized_upgrades: Arc::new(AtomicUsize::new(1)),
        refreshes: Some(Arc::clone(&refreshes)),
        ..signed_in()
    };
    recorded
        .plan
        .lock()
        .unwrap()
        .extend([LeasePlan::RefreshedJustNow]);
    let broker = recorded.broker();
    let Ok(BrokerUpgradeOutcome::Response(response)) = broker
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await
    else {
        panic!("the provider's 401 is answered");
    };
    assert_eq!(response.into_parts().0, http::StatusCode::UNAUTHORIZED);
    assert_eq!(refreshes.load(Ordering::Relaxed), 0);
    assert_eq!(recorded.outbound().len(), 1);
}

/// When the sign-in the provider refused is still the newest, it must be
/// refreshed; a refresh the authority refuses ends the handshake there,
/// without a second one.
#[tokio::test]
async fn a_401_whose_sign_in_cannot_be_refreshed_opens_no_socket() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let recorded = Recorded {
        unauthorized_upgrades: Arc::new(AtomicUsize::new(1)),
        refreshes: Some(Arc::clone(&refreshes)),
        ..signed_in()
    };
    let broker = recorded.broker();
    let outcome = broker
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await;
    assert!(outcome.is_err(), "a refused refresh opens no socket");
    assert_eq!(refreshes.load(Ordering::Relaxed), 1);
    assert_eq!(recorded.outbound().len(), 1);
}

/// A handshake to a provider the transport has no address for is refused
/// as an upstream failure before any lease, and nothing is sent (#5286).
#[tokio::test]
async fn a_handshake_to_a_provider_with_no_address_takes_no_lease_and_opens_no_socket() {
    let recorded = Recorded {
        unserved_slot: Some("codex"),
        ..signed_in()
    };
    let outcome = recorded
        .broker()
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await;
    assert!(matches!(outcome, Err(BrokerRequestError::UpstreamFailed)));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// A refresh has its own check, behind the entry's: no refresh is begun
/// toward a provider with no address (#5286). Here the entry's check is
/// passed once, the provider answers the handshake 401, and the refresh that
/// 401 forces is not begun: the handshake fails as an upstream failure and
/// the sign-in is as it was.
#[tokio::test]
async fn a_forced_refresh_is_not_begun_toward_a_provider_with_no_address() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let recorded = Recorded {
        unauthorized_upgrades: Arc::new(AtomicUsize::new(1)),
        refreshes: Some(Arc::clone(&refreshes)),
        unserved_slot: Some("codex"),
        served_asks: Arc::new(AtomicUsize::new(1)),
        ..signed_in()
    };
    let outcome = recorded
        .broker()
        .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
        .await;
    assert!(matches!(outcome, Err(BrokerRequestError::UpstreamFailed)));
    assert_eq!(refreshes.load(Ordering::Relaxed), 0);
    assert_eq!(recorded.outbound().len(), 1, "no second handshake");
}

/// A socket's grant holds only while the same credential leases with the
/// same revocation generation.
#[tokio::test]
async fn a_sockets_grant_lapses_on_a_refusal_another_credential_or_a_revocation() {
    for lapse in [
        LeasePlan::Denied,
        LeasePlan::OtherCredential,
        LeasePlan::NewRevocation,
    ] {
        let recorded = signed_in();
        let broker = recorded.broker();
        let Ok(BrokerUpgradeOutcome::Switched {
            grant: Some(grant), ..
        }) = broker
            .execute_front_door_upgrade(handshake(MODEL_CALL, Some(format!("Bearer {OURS}"))))
            .await
        else {
            panic!("the handshake switches with a grant");
        };
        recorded.plan.lock().unwrap().push_back(lapse);
        assert!(!broker.socket_grant_holds(&grant).await);
    }
}

/// #5555: a handshake that lacks this environment's placeholder opens no
/// socket to a host the policy's answer doesn't name.
#[tokio::test]
async fn without_the_policys_answer_a_users_own_token_opens_no_socket() {
    let recorded = signed_in();
    let refused = recorded
        .broker_without_answer()
        .execute_front_door_upgrade(handshake(
            MODEL_CALL,
            Some("Bearer users-own-token".to_owned()),
        ))
        .await;
    assert!(matches!(refused, Err(BrokerRequestError::NameNotAllowed)));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}
