//! An SSH request's deadline fails only that request (#2767). The relay checks
//! an SSH frame's shape on receipt and forwards it with its original deadline,
//! whether that deadline is out of range on arrival or passes while the frame
//! waits to be queued. The broker refuses such a request with a typed failure
//! to it alone, and the epoch serves the next one. A malformed frame still
//! ends the epoch.
use super::budgets::admitted;
use super::*;

use v1::credential_ssh_response::Result as SshResult;

/// One environment's whole budget is one stream's, so a test can hold it all.
const LIMITS: Limits = Limits {
    stream: 64 * 1024,
    environment: 64 * 1024,
    stall: Duration::from_secs(3),
};

fn unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn identities(deadline_unix_ms: u64) -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string(),
        deadline_unix_ms,
        operation: Some(v1::credential_ssh_request::Operation::Identities(
            v1::CredentialSshIdentitiesRequest {},
        )),
    }
}

fn guest(request: v1::CredentialSshRequest) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(request)),
    }
}

/// The relay forwarded `request` exactly; the synthetic broker answers it as
/// the broker's SSH handler does, refusing an expired or out-of-range deadline
/// with a typed Denied, and the daemon receives that answer.
async fn answer(
    daemon: &mut DaemonCall,
    broker: &mut BrokerCall,
    request: v1::CredentialSshRequest,
) -> Option<SshResult> {
    assert_eq!(
        bounded(broker.input.message()).await.unwrap().unwrap(),
        guest(request.clone())
    );
    let result = match codewire_daemon_proto::ssh::remaining_deadline(request.deadline_unix_ms) {
        Ok(_) => SshResult::Identity(v1::CredentialSshIdentity {
            public_key_blob: vec![1; 32],
        }),
        Err(_) => SshResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
    };
    let response = v1::CredentialSshResponse {
        request_id: request.request_id,
        result: Some(result),
    };
    broker
        .output
        .send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                response.clone(),
            )),
        }))
        .await
        .unwrap();
    let Some(v1::credential_bridge_host_message::Payload::Ssh(received)) =
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload
    else {
        panic!("the broker's SSH answer must reach the daemon");
    };
    assert_eq!(received, response);
    received.result
}

async fn serve(
    daemon: &mut DaemonCall,
    broker: &mut BrokerCall,
    request: v1::CredentialSshRequest,
) -> Option<SshResult> {
    daemon
        .output
        .send(Ok(guest(request.clone())))
        .await
        .unwrap();
    answer(daemon, broker, request).await
}

fn denied() -> Option<SshResult> {
    Some(SshResult::Failure(
        v1::CredentialBridgeFailureReason::Denied as i32,
    ))
}

#[tokio::test]
async fn an_out_of_range_ssh_deadline_fails_only_its_request() {
    let mut fixture = Fixture::new().await;
    let (cancel, task) = fixture.epoch();
    let (mut daemon, mut broker) = admitted(&mut fixture).await;
    let now = unix_ms();
    // An older guest asking for 30 s with its clock a second ahead, an
    // expired deadline, and nonsense ones.
    for deadline in [now + 31_000, now - 1_000, 1, u64::MAX] {
        assert_eq!(
            serve(&mut daemon, &mut broker, identities(deadline)).await,
            denied(),
            "{deadline}"
        );
        // The same epoch serves the next request.
        assert!(matches!(
            serve(&mut daemon, &mut broker, identities(unix_ms() + 28_000)).await,
            Some(SshResult::Identity(_))
        ));
    }
    assert!(!task.is_finished());
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    drop((daemon, broker));
    fixture.stop().await;
}

#[tokio::test]
async fn an_ssh_deadline_that_passes_while_queued_fails_only_its_request() {
    let mut fixture = Fixture::with_limits(LIMITS).await;
    let budget = fixture.config.budget.clone();
    let (cancel, task) = fixture.epoch();
    let (mut daemon, mut broker) = admitted(&mut fixture).await;
    // Another epoch of this environment holds its whole budget, so the next
    // frame waits to be queued.
    let held = budget.stream().charge(LIMITS.environment).await.unwrap();
    let request = identities(unix_ms() + 200);
    daemon
        .output
        .send(Ok(guest(request.clone())))
        .await
        .unwrap();
    // Its deadline passes while it waits, within the stall bound.
    assert!(
        tokio::time::timeout(Duration::from_millis(600), broker.input.message())
            .await
            .is_err()
    );
    assert!(!task.is_finished());
    drop(held);
    assert_eq!(answer(&mut daemon, &mut broker, request).await, denied());
    assert!(matches!(
        serve(&mut daemon, &mut broker, identities(unix_ms() + 28_000)).await,
        Some(SshResult::Identity(_))
    ));
    assert!(!task.is_finished());
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    assert_eq!(budget.available(), LIMITS.environment);
    drop((daemon, broker));
    fixture.stop().await;
}

#[tokio::test]
async fn a_malformed_ssh_frame_still_ends_the_epoch() {
    let mut fixture = Fixture::new().await;
    let no_operation = v1::CredentialSshRequest {
        operation: None,
        ..identities(unix_ms() + 28_000)
    };
    let non_canonical_id = v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string().to_uppercase(),
        ..identities(unix_ms() + 28_000)
    };
    let unknown_flags = v1::CredentialSshRequest {
        operation: Some(v1::credential_ssh_request::Operation::Sign(
            v1::CredentialSshSignRequest {
                public_key_blob: vec![1; 32],
                data: vec![2; 64],
                flags: 1,
            },
        )),
        ..identities(unix_ms() + 28_000)
    };
    for malformed in [no_operation, non_canonical_id, unknown_flags] {
        let (_cancel, task) = fixture.epoch();
        let (daemon, mut broker) = admitted(&mut fixture).await;
        daemon.output.send(Ok(guest(malformed))).await.unwrap();
        bounded(task).await.unwrap().unwrap();
        // The broker saw the stream end, never the malformed frame.
        assert!(!matches!(
            bounded(broker.input.message()).await,
            Ok(Some(_))
        ));
        drop((daemon, broker));
    }
    fixture.stop().await;
}
