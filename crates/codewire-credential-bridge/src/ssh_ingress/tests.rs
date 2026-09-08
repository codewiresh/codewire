use tokio::io::{DuplexStream, duplex};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use super::*;
use crate::{CredentialBridgeOutput, HOST_OUTPUT_BUFFER, guest_message};

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("bounded synthetic agent stream")
}

struct Fixture {
    bridge: CredentialBridge,
    client: DuplexStream,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), Status>>>,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    driver: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(capacity: usize, timeout: Duration) -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        let (input, receiver) = mpsc::channel(4);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        let driver = tokio::spawn(connection.run());
        let (client, stream) = duplex(capacity);
        let (shutdown, stopped) = oneshot::channel();
        let adapter_bridge = bridge.clone();
        let task = tokio::spawn(async move {
            serve(
                &adapter_bridge,
                stream,
                async {
                    let _ = stopped.await;
                },
                timeout,
            )
            .await
        });
        Self {
            bridge,
            client,
            shutdown: Some(shutdown),
            task: Some(task),
            input,
            output,
            driver,
        }
    }

    async fn request(
        &mut self,
        operation: &v1::credential_ssh_request::Operation,
    ) -> v1::CredentialSshRequest {
        write_frame(&mut self.client, &agent::encode_request(operation).unwrap())
            .await
            .unwrap();
        let frame = bounded(self.output.next()).await.unwrap().unwrap();
        let Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) = frame.payload else {
            panic!("expected typed SSH request");
        };
        assert_eq!(request.operation.as_ref(), Some(operation));
        assert!(codewire_gateway_proto::ssh::valid_request_id(
            &request.request_id
        ));
        assert!(remaining_deadline(request.deadline_unix_ms).unwrap() <= MAX_DEADLINE);
        request
    }

    async fn reply(
        &self,
        request: &v1::CredentialSshRequest,
        result: v1::credential_ssh_response::Result,
    ) {
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                    v1::CredentialSshResponse {
                        request_id: request.request_id.clone(),
                        result: Some(result),
                    },
                )),
            }))
            .await
            .unwrap();
    }

    async fn result(&mut self) -> Result<(), Status> {
        bounded(self.task.take().unwrap()).await.unwrap()
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = bounded(task).await.unwrap();
        }
        drop(self.input);
        bounded(self.driver).await.unwrap();
    }
}

fn identities() -> v1::credential_ssh_request::Operation {
    v1::credential_ssh_request::Operation::Identities(v1::CredentialSshIdentitiesRequest {})
}

fn sign() -> v1::credential_ssh_request::Operation {
    v1::credential_ssh_request::Operation::Sign(v1::CredentialSshSignRequest {
        public_key_blob: b"synthetic-public-key".to_vec(),
        data: b"synthetic-signing-input".to_vec(),
        flags: 4,
    })
}

fn signature() -> v1::credential_ssh_response::Result {
    v1::credential_ssh_response::Result::Signature(v1::CredentialSshSignature {
        signature_blob: b"synthetic-signature".to_vec(),
    })
}

async fn wait_pending(bridge: &CredentialBridge, request_id: &str, cancelled: bool) {
    bounded(async {
        loop {
            let state = bridge.inner.lock().await;
            let matches = if cancelled {
                state
                    .ssh
                    .get(request_id)
                    .is_some_and(|pending| pending.response.is_none())
            } else {
                !state.ssh.contains_key(request_id)
            };
            drop(state);
            if matches {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn sequential_identities_sign_and_failure_use_actual_shared_epoch() {
    let mut fixture = Fixture::new(4096, Duration::from_secs(2)).await;
    let mut previous = None;
    for (operation, kind, result) in [
        (
            identities(),
            SshOperation::Identities,
            v1::credential_ssh_response::Result::Identity(v1::CredentialSshIdentity {
                public_key_blob: b"synthetic-public-key".to_vec(),
            }),
        ),
        (sign(), SshOperation::Sign, signature()),
        (
            sign(),
            SshOperation::Sign,
            v1::credential_ssh_response::Result::Failure(
                v1::CredentialBridgeFailureReason::Denied as i32,
            ),
        ),
    ] {
        let request = fixture.request(&operation).await;
        assert_ne!(previous.as_ref(), Some(&request.request_id));
        previous = Some(request.request_id.clone());
        fixture.reply(&request, result.clone()).await;
        let payload = bounded(read_frame(&mut fixture.client))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent::decode_response(&payload, kind).unwrap(), result);
    }
    fixture.client.shutdown().await.unwrap();
    fixture.result().await.unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn unavailable_authority_is_fixed_failure_without_activating_a_host() {
    let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
    let adapter_bridge = bridge.clone();
    let (mut client, stream) = duplex(64);
    let task = tokio::spawn(async move {
        serve_ssh_agent(&adapter_bridge, stream, std::future::pending()).await
    });
    write_frame(&mut client, &agent::encode_request(&identities()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        bounded(read_frame(&mut client)).await.unwrap().unwrap(),
        [5]
    );
    let state = bridge.inner.lock().await;
    assert!(state.active.is_none());
    assert_eq!(state.next_epoch, 0);
    assert_eq!(state.in_flight(), 0);
    drop(state);
    client.shutdown().await.unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn unsupported_and_malformed_bounded_frames_fail_without_dispatch_then_allow_next_request() {
    let mut fixture = Fixture::new(4096, Duration::from_secs(2)).await;
    for payload in [&[17][..], &[27][..], &[11, 0][..]] {
        write_frame(&mut fixture.client, payload).await.unwrap();
        assert_eq!(
            bounded(read_frame(&mut fixture.client))
                .await
                .unwrap()
                .unwrap(),
            [5]
        );
        assert_eq!(fixture.bridge.inner.lock().await.in_flight(), 0);
    }
    // Any unsupported dispatch would precede this frame in the same output.
    let request = fixture.request(&identities()).await;
    fixture
        .reply(
            &request,
            v1::credential_ssh_response::Result::Failure(
                v1::CredentialBridgeFailureReason::Denied as i32,
            ),
        )
        .await;
    assert_eq!(
        bounded(read_frame(&mut fixture.client))
            .await
            .unwrap()
            .unwrap(),
        [5]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn outer_length_is_rejected_before_payload_and_truncated_frames_close() {
    for bytes in [
        0_u32.to_be_bytes().to_vec(),
        (agent::MAX_PAYLOAD_BYTES as u32 + 1).to_be_bytes().to_vec(),
        u32::MAX.to_be_bytes().to_vec(),
        vec![0, 0],
        vec![0, 0, 0, 8, 13, 0],
    ] {
        let mut fixture = Fixture::new(64, Duration::from_secs(2)).await;
        fixture.client.write_all(&bytes).await.unwrap();
        fixture.client.shutdown().await.unwrap();
        assert_eq!(
            fixture.result().await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(fixture.bridge.inner.lock().await.in_flight(), 0);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn pending_peer_eof_owner_stop_pipeline_and_future_drop_retain_cancelled_slot_until_terminal()
{
    for cause in 0..4 {
        let mut fixture = Fixture::new(4096, Duration::from_secs(2)).await;
        let request = fixture.request(&sign()).await;
        match cause {
            0 => fixture.client.shutdown().await.unwrap(),
            1 => fixture.shutdown.take().unwrap().send(()).unwrap(),
            2 => fixture.client.write_all(&[0]).await.unwrap(),
            3 => fixture.task.as_ref().unwrap().abort(),
            _ => unreachable!(),
        }
        let joined = bounded(fixture.task.take().unwrap()).await;
        match cause {
            0 => joined.unwrap().unwrap(),
            1 => assert_eq!(joined.unwrap().unwrap_err().code(), tonic::Code::Cancelled),
            2 => assert_eq!(
                joined.unwrap().unwrap_err().code(),
                tonic::Code::InvalidArgument
            ),
            3 => assert!(joined.unwrap_err().is_cancelled()),
            _ => unreachable!(),
        }
        let frame = bounded(fixture.output.next()).await.unwrap().unwrap();
        assert!(
            matches!(frame.payload, Some(v1::credential_bridge_guest_message::Payload::Cancel(cancel)) if cancel.request_id == request.request_id)
        );
        wait_pending(&fixture.bridge, &request.request_id, true).await;
        assert_eq!(fixture.bridge.inner.lock().await.in_flight(), 1);
        fixture.reply(&request, signature()).await;
        wait_pending(&fixture.bridge, &request.request_id, false).await;
        // A retained reader receives no signature after cancellation.
        let mut byte = [0];
        assert_eq!(bounded(fixture.client.read(&mut byte)).await.unwrap(), 0);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn full_cancel_queue_still_retains_tombstone_until_exact_terminal() {
    let mut fixture = Fixture::new(4096, Duration::from_secs(2)).await;
    let request = fixture.request(&sign()).await;
    let output = fixture
        .bridge
        .inner
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .output
        .clone();
    for _ in 0..HOST_OUTPUT_BUFFER {
        output
            .try_send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Cancel(v1::CredentialBridgeCancel {
                    request_id: Uuid::new_v4().to_string(),
                }),
            )))
            .unwrap();
    }
    fixture.client.shutdown().await.unwrap();
    fixture.result().await.unwrap();
    wait_pending(&fixture.bridge, &request.request_id, true).await;
    assert_eq!(fixture.bridge.inner.lock().await.in_flight(), 1);
    fixture.reply(&request, signature()).await;
    wait_pending(&fixture.bridge, &request.request_id, false).await;
    fixture.stop().await;
}

#[tokio::test]
async fn idle_partial_frame_and_pending_relay_share_a_bounded_deadline() {
    for phase in 0..3 {
        let mut fixture = Fixture::new(4096, Duration::from_millis(120)).await;
        let request = match phase {
            0 => None,
            1 => {
                fixture.client.write_all(&[0]).await.unwrap();
                None
            }
            2 => Some(fixture.request(&sign()).await),
            _ => unreachable!(),
        };
        assert_eq!(
            fixture.result().await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        if let Some(request) = request {
            wait_pending(&fixture.bridge, &request.request_id, true).await;
            fixture.reply(&request, signature()).await;
            wait_pending(&fixture.bridge, &request.request_id, false).await;
        }
        fixture.stop().await;
    }
}

#[tokio::test]
async fn backpressured_terminal_uses_original_deadline_and_owner_stop() {
    for stop in [false, true] {
        let mut fixture = Fixture::new(64, Duration::from_millis(200)).await;
        let request = fixture.request(&sign()).await;
        fixture
            .reply(
                &request,
                v1::credential_ssh_response::Result::Signature(v1::CredentialSshSignature {
                    signature_blob: vec![7; codewire_gateway_proto::ssh::MAX_SIGNATURE_BYTES],
                }),
            )
            .await;
        wait_pending(&fixture.bridge, &request.request_id, false).await;
        // Synchronize with the actual terminal write, not merely acceptance
        // by the shared host driver. The remaining signature exceeds capacity.
        let mut prefix = [0; 4];
        bounded(fixture.client.read_exact(&mut prefix))
            .await
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(prefix) as usize,
            5 + codewire_gateway_proto::ssh::MAX_SIGNATURE_BYTES
        );
        if stop {
            fixture.shutdown.take().unwrap().send(()).unwrap();
        }
        let expected = if stop {
            tonic::Code::Cancelled
        } else {
            tonic::Code::DeadlineExceeded
        };
        assert_eq!(fixture.result().await.unwrap_err().code(), expected);
        // The synthetic pipe capacity cannot hold a complete signature. A
        // stalled reader never causes the adapter to renew its request budget.
        let mut received = [0; 128];
        let count = fixture.client.read(&mut received).await.unwrap();
        assert!(count <= 64);
        assert_eq!(fixture.bridge.inner.lock().await.in_flight(), 0);
        fixture.stop().await;
    }
}

type AlternateRequest = (
    v1::CredentialSshRequest,
    oneshot::Sender<Result<v1::CredentialSshResponse, Status>>,
);

struct AlternateRelay {
    requests: mpsc::Sender<AlternateRequest>,
    dropped_waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[tonic::async_trait]
impl SshAgentRelay for AlternateRelay {
    async fn relay_ssh(
        &self,
        request: v1::CredentialSshRequest,
    ) -> Result<v1::CredentialSshResponse, Status> {
        struct Waiter(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Waiter {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Release);
            }
        }
        let _waiter = Waiter(self.dropped_waiters.clone());
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send((request, sender))
            .await
            .map_err(|_| transport_failed())?;
        receiver.await.map_err(|_| transport_failed())?
    }
}

struct AlternateFixture {
    client: DuplexStream,
    requests: mpsc::Receiver<AlternateRequest>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), Status>>,
    dropped_waiters: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AlternateFixture {
    fn new(timeout: Duration) -> Self {
        let (requests, receiver) = mpsc::channel(1);
        let dropped_waiters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // An alternate transport has no CredentialBridge/environment epoch.
        // Also exercise the object-safe form used by injected backends.
        let relay: Box<dyn SshAgentRelay> = Box::new(AlternateRelay {
            requests,
            dropped_waiters: dropped_waiters.clone(),
        });
        let (client, stream) = duplex(4096);
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            serve(
                &*relay,
                stream,
                async {
                    let _ = stopped.await;
                },
                timeout,
            )
            .await
        });
        Self {
            client,
            requests: receiver,
            shutdown,
            task,
            dropped_waiters,
        }
    }

    async fn sign(&mut self) -> AlternateRequest {
        write_frame(&mut self.client, &agent::encode_request(&sign()).unwrap())
            .await
            .unwrap();
        let request = bounded(self.requests.recv()).await.unwrap();
        assert_eq!(validate_request(&request.0).unwrap(), SshOperation::Sign);
        assert_eq!(request.0.operation, Some(sign()));
        request
    }
}

#[tokio::test]
async fn alternate_typed_relay_uses_same_closed_framing_and_original_request() {
    let mut fixture = AlternateFixture::new(Duration::from_secs(2));
    write_frame(&mut fixture.client, &[27]).await.unwrap();
    assert_eq!(
        bounded(read_frame(&mut fixture.client))
            .await
            .unwrap()
            .unwrap(),
        [5]
    );
    assert!(matches!(
        fixture.requests.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let (request, response) = fixture.sign().await;
    assert!(remaining_deadline(request.deadline_unix_ms).unwrap() <= Duration::from_secs(2));
    response
        .send(Ok(v1::CredentialSshResponse {
            request_id: request.request_id,
            result: Some(signature()),
        }))
        .unwrap();
    let payload = bounded(read_frame(&mut fixture.client))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        agent::decode_response(&payload, SshOperation::Sign).unwrap(),
        signature()
    );
    fixture.client.shutdown().await.unwrap();
    bounded(fixture.task).await.unwrap().unwrap();
}

#[tokio::test]
async fn alternate_response_id_type_bounds_and_closed_failure_are_validated_before_output() {
    for invalid in 0..6 {
        let mut fixture = AlternateFixture::new(Duration::from_secs(2));
        let (request, response) = fixture.sign().await;
        let mut result = v1::CredentialSshResponse {
            request_id: request.request_id,
            result: Some(signature()),
        };
        match invalid {
            0 => result.request_id = Uuid::new_v4().to_string(),
            1 => {
                result.result = Some(v1::credential_ssh_response::Result::Identity(
                    v1::CredentialSshIdentity {
                        public_key_blob: b"synthetic-public-key".to_vec(),
                    },
                ))
            }
            2 | 3 => {
                result.result = Some(v1::credential_ssh_response::Result::Signature(
                    v1::CredentialSshSignature {
                        signature_blob: if invalid == 2 {
                            Vec::new()
                        } else {
                            vec![7; codewire_gateway_proto::ssh::MAX_SIGNATURE_BYTES + 1]
                        },
                    },
                ))
            }
            4 => result.result = Some(v1::credential_ssh_response::Result::Failure(i32::MAX)),
            5 => result.result = None,
            _ => unreachable!(),
        }
        response.send(Ok(result)).unwrap();
        assert_eq!(
            bounded(fixture.task).await.unwrap().unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let mut byte = [0];
        assert_eq!(bounded(fixture.client.read(&mut byte)).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn alternate_waiter_is_dropped_on_eof_owner_stop_original_deadline_and_task_loss() {
    for cause in 0..4 {
        let mut fixture = AlternateFixture::new(Duration::from_millis(120));
        let (request, response) = fixture.sign().await;
        // This sender models work retained elsewhere by an authority. A
        // dropped waiter is observable, but it does not prove remote drain.
        assert!(!response.is_closed());
        let original_deadline = request.deadline_unix_ms;
        match cause {
            0 => fixture.client.shutdown().await.unwrap(),
            1 => fixture.shutdown.send(()).unwrap(),
            2 => {}
            3 => fixture.task.abort(),
            _ => unreachable!(),
        }
        let result = bounded(fixture.task).await;
        match cause {
            0 => result.unwrap().unwrap(),
            1 => assert_eq!(result.unwrap().unwrap_err().code(), tonic::Code::Cancelled),
            2 => {
                assert_eq!(
                    result.unwrap().unwrap_err().code(),
                    tonic::Code::DeadlineExceeded
                );
                assert!(remaining_deadline(original_deadline).is_err());
            }
            3 => assert!(result.unwrap_err().is_cancelled()),
            _ => unreachable!(),
        }
        assert!(response.is_closed());
        assert_eq!(
            fixture
                .dropped_waiters
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
        let mut byte = [0];
        assert_eq!(bounded(fixture.client.read(&mut byte)).await.unwrap(), 0);
    }
}
