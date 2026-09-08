//! Trusted typed-stream composition only: no owner OAuth authentication claim.

use super::*;

type Input = mpsc::Sender<Result<v1::CredentialBridgeGuestMessage, Status>>;
type Output = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;

// Deliberately a different authority type and identity variant from the Pod
// authenticator. Both must use the original service's capacity and lifecycle.
struct OwnerAuthority(Authority);

#[async_trait]
impl PlatformRuntimeAuthority for OwnerAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        self.0.current_session().await
    }
}

fn owner_authority(fixture: &Fixture) -> Arc<OwnerAuthority> {
    let mut context = fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .context
        .clone();
    context.placement = GrantPlacement::PlatformToLocal;
    let session = PlatformRuntimeSession::owner_local(
        context.clone(),
        Owner::User(context.user_id),
        None,
        [7; 32],
        crate::platform::unix_now().unwrap() + 3600,
    )
    .unwrap();
    Arc::new(OwnerAuthority(Authority {
        session: Mutex::new(session),
        calls: AtomicUsize::new(0),
        captured: Notify::new(),
    }))
}

async fn open_direct(fixture: &Fixture, authority: Arc<OwnerAuthority>) -> (Input, Output) {
    let (input, receiver) = mpsc::channel(4);
    input.send(Ok(fixture.ready())).await.unwrap();
    let output = tokio::time::timeout(
        TEST_TIMEOUT,
        fixture
            .service
            .clone()
            .serve_authenticated(async move { Ok((authority, ReceiverStream::new(receiver))) }),
    )
    .await
    .unwrap()
    .unwrap();
    (input, output)
}

async fn rejected_without_polling(
    fixture: &Fixture,
    authority: Arc<OwnerAuthority>,
    expected: Code,
) {
    let polled = AtomicBool::new(false);
    let result = tokio::time::timeout(
        TEST_TIMEOUT,
        fixture.service.serve_authenticated(async {
            polled.store(true, Ordering::SeqCst);
            Ok((
                authority,
                futures::stream::pending::<Result<v1::CredentialBridgeGuestMessage, Status>>(),
            ))
        }),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code(), expected);
    assert!(!polled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn mixed_authorities_share_capacity_and_closed_admission_never_polls_lazy_work() {
    let fixture = Fixture::new().await;
    let authority = owner_authority(&fixture);
    let mut pod_streams = Vec::new();
    let mut owner_streams = Vec::new();
    for _ in 0..PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS / 2 {
        let (input, output) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        pod_streams.push((input, output.unwrap().into_inner()));
        owner_streams.push(open_direct(&fixture, authority.clone()).await);
    }
    assert_eq!(
        fixture.service.state.workers.len(),
        PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS
    );
    rejected_without_polling(&fixture, authority.clone(), Code::ResourceExhausted).await;
    let calls = fixture.authenticator.calls.load(Ordering::SeqCst);
    let (input, rejected) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert_eq!(rejected.unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(fixture.authenticator.calls.load(Ordering::SeqCst), calls);
    drop(input);

    // Direct output drop reaches the owned mpsc receiver immediately even with
    // the input sender retained; remote tonic still requires both halves.
    for (input, output) in owner_streams {
        drop(output);
        tokio::time::timeout(TEST_TIMEOUT, input.closed())
            .await
            .unwrap();
    }
    drop(pod_streams);
    fixture.slots_released().await;
    fixture.service.shutdown().await.unwrap();
    rejected_without_polling(&fixture, authority, Code::Unavailable).await;
    fixture.finish().await;
}

#[tokio::test]
async fn lazy_selection_consumption_and_authority_construction_share_original_timeout() {
    let fixture = Fixture::new().await;
    let authority = owner_authority(&fixture);
    let (_input, mut selection) = mpsc::channel::<()>(1);
    let polled = AtomicBool::new(false);
    let mut admission = Box::pin(fixture.service.serve_authenticated(async {
        polled.store(true, Ordering::SeqCst);
        // Models first selection-frame consumption, not a second bridge frame.
        selection.recv().await.unwrap();
        Ok((
            authority.clone(),
            futures::stream::pending::<Result<v1::CredentialBridgeGuestMessage, Status>>(),
        ))
    }));
    assert!(futures::poll!(admission.as_mut()).is_pending());
    assert!(polled.load(Ordering::SeqCst));
    assert_eq!(
        fixture.service.state.permits.available_permits(),
        PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS - 1
    );
    tokio::time::pause();
    tokio::time::advance(ADMISSION_TIMEOUT + Duration::from_millis(1)).await;
    assert_eq!(admission.await.unwrap_err().code(), Code::DeadlineExceeded);
    tokio::time::resume();
    assert_eq!(authority.0.calls.load(Ordering::SeqCst), 0);
    assert!(fixture.service.state.workers.is_empty());
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn dropping_pending_ready_admission_closes_input_without_starting_worker() {
    let fixture = Fixture::new().await;
    let authority = owner_authority(&fixture);
    let (input, receiver) = mpsc::channel(1);
    let mut admission = Box::pin(
        fixture
            .service
            .serve_authenticated(async { Ok((authority.clone(), ReceiverStream::new(receiver))) }),
    );
    assert!(futures::poll!(admission.as_mut()).is_pending());
    assert_eq!(authority.0.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.service.state.permits.available_permits(),
        PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS - 1
    );
    drop(admission);
    tokio::time::timeout(TEST_TIMEOUT, input.closed())
        .await
        .unwrap();
    assert_eq!(authority.0.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.service.state.workers.is_empty());
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn owner_shutdown_cancels_pending_ready_and_prevents_late_admission() {
    let fixture = Fixture::new().await;
    let authority = owner_authority(&fixture);
    let (input, receiver) = mpsc::channel(1);
    let mut admission = Box::pin(
        fixture
            .service
            .serve_authenticated(async { Ok((authority.clone(), ReceiverStream::new(receiver))) }),
    );
    assert!(futures::poll!(admission.as_mut()).is_pending());
    fixture.service.shutdown().await.unwrap();
    assert_eq!(admission.await.unwrap_err().code(), Code::Unavailable);
    tokio::time::timeout(TEST_TIMEOUT, input.closed())
        .await
        .unwrap();
    assert_eq!(authority.0.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.service.state.workers.is_empty());
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn owner_ready_recheck_rejects_changed_operation_binding() {
    let fixture = Fixture::new().await;
    let authority = owner_authority(&fixture);
    let (input, receiver) = mpsc::channel(1);
    let mut admission = Box::pin(
        fixture
            .service
            .serve_authenticated(async { Ok((authority.clone(), ReceiverStream::new(receiver))) }),
    );
    assert!(futures::poll!(admission.as_mut()).is_pending());
    authority
        .0
        .session
        .lock()
        .unwrap()
        .context
        .environment_generation += 1;
    input.send(Ok(fixture.ready())).await.unwrap();
    assert_eq!(admission.await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(authority.0.calls.load(Ordering::SeqCst), 2);
    assert!(fixture.service.state.workers.is_empty());
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn typed_stream_error_is_value_blind_and_terminates_owned_epoch() {
    let fixture = Fixture::new().await;
    let (input, mut output) = open_direct(&fixture, owner_authority(&fixture)).await;
    input
        .send(Err(Status::internal("synthetic-sensitive-source-detail")))
        .await
        .unwrap();
    let error = tokio::time::timeout(TEST_TIMEOUT, output.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(!format!("{error:?} {error}").contains("synthetic-sensitive-source-detail"));
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, output.next())
            .await
            .unwrap()
            .is_none()
    );
    fixture.slots_released().await;
    fixture.finish().await;
}
