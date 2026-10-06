//! The bound workspace's daemon credential (Program #2238 B2): fetched through
//! the gateway's own binding before the daemon connect, retried without
//! exiting, and refreshed when the daemon refuses it.
use super::*;
use crate::binding::BindingPollConfig;
use axum::Router;
use codewire_gateway_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_proto::codewire::internal::v1::{
    GatewayBindingService, IssueGatewayBindingRequest, IssueGatewayBindingResponse,
    IssueGatewayDaemonCredentialRequest, IssueGatewayDaemonCredentialResponse,
};
use connectrpc::{ConnectError, ErrorCode, RequestContext, ServiceRequest, ServiceResult};
use std::sync::Mutex;

const FIRST_POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const REPLACEMENT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const FIRST_CREDENTIAL: &str = "synthetic-first-pod-daemon-credential";
const REPLACEMENT_CREDENTIAL: &str = "synthetic-replacement-pod-daemon-credential";

const FAST: DaemonConnectBackoff = DaemonConnectBackoff {
    fast_delay: Duration::from_millis(10),
    fast_window: Duration::from_secs(60),
    slow_delay: Duration::from_millis(10),
    attempt_timeout: Duration::from_secs(1),
};

/// A gateway binding listener that answers the daemon credential call from a
/// script, then repeats its last answer.
struct ScriptedBinding {
    answers: Mutex<Vec<Result<(&'static str, &'static str), ErrorCode>>>,
    calls: Arc<Mutex<u32>>,
}

#[allow(refining_impl_trait)]
impl GatewayBindingService for ScriptedBinding {
    async fn issue_gateway_binding(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, IssueGatewayBindingRequest>,
    ) -> ServiceResult<IssueGatewayBindingResponse> {
        Err(ConnectError::not_found(
            "coordinate material waits for running",
        ))
    }

    async fn issue_gateway_daemon_credential(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, IssueGatewayDaemonCredentialRequest>,
    ) -> ServiceResult<IssueGatewayDaemonCredentialResponse> {
        *self.calls.lock().unwrap() += 1;
        let answer = {
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0]
            }
        };
        match answer {
            Ok((daemon_credential, workspace_pod_uid)) => {
                connectrpc::Response::ok(IssueGatewayDaemonCredentialResponse {
                    daemon_credential: daemon_credential.into(),
                    workspace_pod_uid: workspace_pod_uid.into(),
                    ..Default::default()
                })
            }
            Err(code) => Err(ConnectError::new(code, "scripted")),
        }
    }
}

async fn binding(
    answers: Vec<Result<(&'static str, &'static str), ErrorCode>>,
) -> (
    BindingPollConfig,
    Arc<Mutex<u32>>,
    (tempfile::TempDir, codewire_tls::test_support::SyntheticPki),
) {
    let calls = Arc::new(Mutex::new(0));
    let connect = connectrpc::Router::new().add_service(Arc::new(ScriptedBinding {
        answers: Mutex::new(answers),
        calls: calls.clone(),
    }));
    let app = Router::new().fallback_service(connect.into_axum_service());
    // Orchestration's internal listener is TLS-only, as in production.
    let pki = codewire_tls::test_support::SyntheticPki::new("localhost");
    let address = pki.serve(app).await;
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "synthetic.projected.gateway-binding").unwrap();
    (
        BindingPollConfig::for_test(
            format!("https://localhost:{}", address.port()),
            token,
            pki.roots.clone(),
        ),
        calls,
        (directory, pki),
    )
}

/// A daemon that accepts only the credential currently in `expected`.
async fn authenticating_daemon(expected: Arc<Mutex<String>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .add_service(DaemonServiceServer::with_interceptor(
                MinimalDaemon,
                move |request: Request<()>| {
                    let presented = request
                        .metadata()
                        .get(DAEMON_AUTH_TOKEN_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    if presented.as_deref() == Some(expected.lock().unwrap().as_str()) {
                        Ok(request)
                    } else {
                        Err(Status::unauthenticated("daemon credential refused"))
                    }
                },
            ))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    address.to_string()
}

fn token(value: &str) -> DaemonAuthToken {
    DaemonAuthToken::new(value).unwrap()
}

#[tokio::test]
async fn the_credential_fetch_waits_for_a_binding_without_ever_giving_up() {
    let (config, calls, _directory) = binding(vec![
        Err(ErrorCode::NotFound),
        Err(ErrorCode::Unavailable),
        Err(ErrorCode::NotFound),
        // A refused call is retried too: exiting would only crash-loop.
        Err(ErrorCode::PermissionDenied),
        Ok((FIRST_CREDENTIAL, FIRST_POD)),
    ])
    .await;
    let issued = timeout(
        Duration::from_secs(5),
        fetch_daemon_credential_with_retry(&config, FAST),
    )
    .await
    .expect("credential fetch followed the recorded binding")
    .expect("credential fetch gave up");
    assert_eq!(issued.token.expose_secret(), FIRST_CREDENTIAL);
    assert_eq!(issued.workspace_pod_uid, FIRST_POD);
    assert_eq!(*calls.lock().unwrap(), 5);
}

#[test]
fn the_credential_fetch_shares_the_daemon_connect_schedule() {
    // Same retry cadence; only the per-attempt timeout differs (a same-node
    // daemon connect against a cross-node orchestration RPC).
    assert_eq!(
        DaemonConnectBackoff {
            attempt_timeout: DAEMON_CONNECT_BACKOFF.attempt_timeout,
            ..DAEMON_CREDENTIAL_BACKOFF
        },
        DAEMON_CONNECT_BACKOFF
    );
    assert_eq!(
        DAEMON_CONNECT_BACKOFF.attempt_timeout,
        Duration::from_secs(1)
    );
    assert_eq!(
        DAEMON_CREDENTIAL_BACKOFF.attempt_timeout,
        Duration::from_secs(5)
    );
    assert_eq!(
        DAEMON_CREDENTIAL_BACKOFF.delay_after(Duration::ZERO),
        Duration::from_millis(250)
    );
    assert_eq!(
        DAEMON_CREDENTIAL_BACKOFF.delay_after(Duration::from_secs(60)),
        Duration::from_secs(2)
    );
}

#[tokio::test]
async fn a_refusal_installs_the_replaced_pods_credential_and_shutdown_ends_the_refresher() {
    let (config, calls, _directory) =
        binding(vec![Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD))]).await;
    let credential = DaemonCredential::issued(token(FIRST_CREDENTIAL), FIRST_POD.into());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_daemon_credential(
        credential.clone(),
        config,
        shutdown_rx,
    ));
    // Nothing is fetched until the daemon refuses the credential.
    sleep(Duration::from_millis(100)).await;
    assert_eq!(*calls.lock().unwrap(), 0);

    credential.report_unauthenticated();
    timeout(Duration::from_secs(5), async {
        while credential.workspace_pod_uid().as_deref() != Some(REPLACEMENT_POD) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("refresher installed the replacement credential");
    assert_eq!(credential.token().expose_secret(), REPLACEMENT_CREDENTIAL);

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), refresher)
        .await
        .expect("refresher stopped on shutdown")
        .expect("refresher task")
        .expect("refresher result");
}

#[test]
fn refreshes_that_find_nothing_new_back_off_exponentially_to_the_cap() {
    let backoff = DAEMON_CREDENTIAL_REFRESH_BACKOFF;
    assert_eq!(backoff.base, Duration::from_secs(1));
    assert_eq!(backoff.cap, Duration::from_secs(60));
    let mut schedule = RefreshSchedule::default();
    let pauses: Vec<u64> = (0..9)
        .map(|_| schedule.after(RefreshOutcome::Unchanged, backoff).as_secs())
        .collect();
    assert_eq!(pauses, [2, 4, 8, 16, 32, 60, 60, 60, 60]);
    // Failures back off the same way, and the doubling never overflows.
    let mut failing = RefreshSchedule {
        fruitless: u32::MAX - 1,
    };
    assert_eq!(failing.after(RefreshOutcome::Failed, backoff), backoff.cap);
    assert_eq!(failing.after(RefreshOutcome::Failed, backoff), backoff.cap);
}

#[test]
fn a_changed_credential_or_an_accepted_call_resets_the_backoff() {
    let backoff = DAEMON_CREDENTIAL_REFRESH_BACKOFF;
    let mut schedule = RefreshSchedule::default();
    for _ in 0..5 {
        schedule.after(RefreshOutcome::Unchanged, backoff);
    }
    assert_eq!(
        schedule.after(RefreshOutcome::Changed, backoff),
        Duration::from_secs(1)
    );
    for _ in 0..5 {
        schedule.after(RefreshOutcome::Failed, backoff);
    }
    schedule.authenticated();
    assert_eq!(
        schedule.after(RefreshOutcome::Unchanged, backoff),
        Duration::from_secs(2)
    );
}

/// A daemon that refuses every call as fast as it can drives no more than the
/// backoff allows, and each outcome is observed.
#[tokio::test]
async fn a_refusal_loop_is_throttled_and_every_outcome_is_observed() {
    let (config, calls, _directory) = binding(vec![
        Err(ErrorCode::NotFound),
        Ok((FIRST_CREDENTIAL, FIRST_POD)),
        Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD)),
        Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD)),
    ])
    .await;
    let credential = DaemonCredential::issued(token(FIRST_CREDENTIAL), FIRST_POD.into());
    let observed = Arc::new(Mutex::new(
        Vec::<(tokio::time::Instant, RefreshOutcome)>::new(),
    ));
    let record = observed.clone();
    let backoff = RefreshBackoff {
        base: Duration::from_millis(20),
        cap: Duration::from_millis(160),
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_daemon_credential_with(
        credential.clone(),
        config,
        shutdown_rx,
        backoff,
        move |outcome| {
            record
                .lock()
                .unwrap()
                .push((tokio::time::Instant::now(), outcome))
        },
    ));
    let refusing = {
        let credential = credential.clone();
        tokio::spawn(async move {
            loop {
                credential.report_unauthenticated();
                sleep(Duration::from_millis(1)).await;
            }
        })
    };
    sleep(Duration::from_millis(1_200)).await;
    refusing.abort();
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), refresher)
        .await
        .expect("refresher stopped")
        .expect("refresher task")
        .expect("refresher result");

    let observed = observed.lock().unwrap().clone();
    let outcomes: Vec<RefreshOutcome> = observed.iter().map(|(_, outcome)| *outcome).collect();
    assert!(outcomes.len() >= 5, "{outcomes:?}");
    assert_eq!(
        outcomes[..4],
        [
            RefreshOutcome::Failed,
            RefreshOutcome::Unchanged,
            RefreshOutcome::Changed,
            RefreshOutcome::Unchanged,
        ]
    );
    assert!(
        outcomes[4..]
            .iter()
            .all(|outcome| *outcome == RefreshOutcome::Unchanged)
    );
    // Shutdown may cancel one call the binding already counted; every
    // completed call's outcome is observed.
    let calls = *calls.lock().unwrap() as usize;
    assert!(
        calls == outcomes.len() || calls == outcomes.len() + 1,
        "{calls} calls for {} observed outcomes",
        outcomes.len()
    );
    // Each pause is at least what the schedule asked for: 40, 80, then 20
    // after the change, then 40, 80, 160, 160 ms.
    let mut schedule = RefreshSchedule::default();
    for (pair, outcome) in observed.windows(2).zip(&outcomes) {
        let pause = schedule.after(*outcome, backoff);
        assert!(
            pair[1].0.duration_since(pair[0].0) >= pause,
            "refreshed after {:?}, before the {pause:?} pause",
            pair[1].0.duration_since(pair[0].0)
        );
    }
    // Unthrottled, a 1 ms refusal loop would have driven hundreds.
    assert!(outcomes.len() <= 12, "{outcomes:?}");
    assert_eq!(
        credential.workspace_pod_uid().as_deref(),
        Some(REPLACEMENT_POD)
    );
}

/// One refusal is enough: a replacement Pod that is not bound yet is retried
/// on the backoff schedule until its credential is issued.
#[tokio::test]
async fn a_failed_refresh_retries_without_another_refusal() {
    let (config, calls, _directory) = binding(vec![
        Err(ErrorCode::NotFound),
        Err(ErrorCode::Unavailable),
        Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD)),
        Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD)),
    ])
    .await;
    let credential = DaemonCredential::issued(token(FIRST_CREDENTIAL), FIRST_POD.into());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_daemon_credential_with(
        credential.clone(),
        config,
        shutdown_rx,
        RefreshBackoff {
            base: Duration::from_millis(10),
            cap: Duration::from_millis(40),
        },
        |_| {},
    ));
    credential.report_unauthenticated();
    timeout(Duration::from_secs(5), async {
        while credential.workspace_pod_uid().as_deref() != Some(REPLACEMENT_POD) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("refresher retried until the replacement was bound");
    // Once issued, it waits for the next refusal instead of polling.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(*calls.lock().unwrap(), 3);

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), refresher)
        .await
        .expect("refresher stopped")
        .expect("refresher task")
        .expect("refresher result");
}

#[tokio::test]
async fn the_daemon_client_follows_a_replaced_pod_behind_the_same_service() {
    // The daemon Service now reaches a replacement Pod, which accepts only its
    // own credential; the binding issues that credential.
    let expected = Arc::new(Mutex::new(REPLACEMENT_CREDENTIAL.to_owned()));
    let daemon = authenticating_daemon(expected.clone()).await;
    let (config, _calls, _directory) =
        binding(vec![Ok((REPLACEMENT_CREDENTIAL, REPLACEMENT_POD))]).await;
    let credential = DaemonCredential::issued(token(FIRST_CREDENTIAL), FIRST_POD.into());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_daemon_credential(
        credential.clone(),
        config,
        shutdown_rx,
    ));
    let client = connect_daemon_with_retry(&daemon, credential.clone(), FAST)
        .await
        .expect("daemon connected");

    // The first call presents the old Pod's credential and is refused.
    match crate::daemon::DaemonClient::list(&client, "/").await {
        Err(DaemonClientError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::Unauthenticated)
        }
        other => panic!("unexpected {:?}", other.map(|_| ())),
    }
    // The refusal refreshed the credential; a later call is authenticated
    // (the fixture daemon then answers unimplemented).
    timeout(Duration::from_secs(5), async {
        loop {
            match crate::daemon::DaemonClient::list(&client, "/").await {
                Err(DaemonClientError::Status(status))
                    if status.code() == tonic::Code::Unimplemented =>
                {
                    return;
                }
                _ => sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("daemon client followed the refreshed credential");

    // The credential-bridge client of the next relay epoch follows too.
    let bridge = client.credential_client();
    match bridge.get_health().await {
        Err(codewire_daemon::client::SessionClientError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::Unimplemented)
        }
        other => panic!("unexpected {:?}", other.map(|_| ())),
    }

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), refresher)
        .await
        .expect("refresher stopped")
        .expect("refresher task")
        .expect("refresher result");
}

#[tokio::test]
async fn a_rendered_token_is_never_refreshed() {
    let expected = Arc::new(Mutex::new("synthetic-other-token".to_owned()));
    let daemon = authenticating_daemon(expected).await;
    let client = connect_daemon_with_retry(&daemon, token("synthetic-rendered-token"), FAST)
        .await
        .expect("daemon connected");
    assert!(!client.credential().refreshable());
    assert!(
        crate::daemon::DaemonClient::list(&client, "/")
            .await
            .is_err()
    );
    assert_eq!(
        client.credential().token().expose_secret(),
        "synthetic-rendered-token"
    );
}
