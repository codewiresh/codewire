use std::collections::VecDeque;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use axum::Router;
use codewire_daemon::HostedDaemonMode;
use codewire_daemon::config::{WORKSPACE_BINDING_URL_ENV, WORKSPACE_POD_UID_ENV};
use codewire_proto::codewire::internal::v1::WorkspaceBindingService;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use tempfile::TempDir;
use tokio::net::TcpListener;

use super::*;

const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const OTHER_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
const SYNTHETIC_CREDENTIAL: &str = "synthetic-workspace-daemon-credential";
const SYNTHETIC_PROJECTED_TOKEN: &str = "synthetic.projected.workspace-binding";

/// One scripted answer of the fake listener.
enum Answer {
    Bound,
    BoundFor(&'static str),
    Error(ErrorCode),
}

#[derive(Default)]
struct Recorded {
    authorizations: Vec<String>,
    waits: Vec<u32>,
    versions: Vec<http::Version>,
    at: Vec<tokio::time::Instant>,
}

struct ScriptedService {
    answers: Mutex<VecDeque<Answer>>,
    recorded: Arc<Mutex<Recorded>>,
}

#[allow(refining_impl_trait)]
impl WorkspaceBindingService for ScriptedService {
    async fn bind_workspace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BindWorkspaceRequest>,
    ) -> ServiceResult<BindWorkspaceResponse> {
        {
            let mut recorded = self.recorded.lock().unwrap();
            recorded.authorizations.push(
                ctx.headers()
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned(),
            );
            recorded.waits.push(request.wait_seconds);
            recorded.at.push(tokio::time::Instant::now());
        }
        let answer = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Answer::Bound);
        let pod_uid = match answer {
            Answer::Bound => POD,
            Answer::BoundFor(pod) => pod,
            Answer::Error(code) => return Err(ConnectError::new(code, "scripted")),
        };
        connectrpc::Response::ok(BindWorkspaceResponse {
            environment_id: ENVIRONMENT.into(),
            pod_uid: pod_uid.into(),
            operation_generation: 4,
            daemon_credential: SYNTHETIC_CREDENTIAL.into(),
            projection_selection_sha256: String::new(),
            managed_credential_clients: "v1:none".into(),
            ..Default::default()
        })
    }

    async fn refresh_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, codewire_proto::codewire::internal::v1::RefreshAccessRequest>,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::RefreshAccessResponse> {
        Err(ConnectError::unimplemented("not scripted"))
    }

    async fn record_host_key(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, codewire_proto::codewire::internal::v1::RecordHostKeyRequest>,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::RecordHostKeyResponse> {
        Err(ConnectError::unimplemented("not scripted"))
    }

    async fn allocate_peer_relay(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<
            '_,
            codewire_proto::codewire::internal::v1::AllocatePeerRelayRequest,
        >,
    ) -> ServiceResult<codewire_proto::codewire::internal::v1::AllocatePeerRelayResponse> {
        Err(ConnectError::unimplemented("not scripted"))
    }
}

struct Fixture {
    client: BindingClient,
    config: WorkspaceBindingConfig,
    recorded: Arc<Mutex<Recorded>>,
    token: PathBuf,
    _directory: TempDir,
}

fn timing() -> BindTiming {
    BindTiming {
        wait_seconds: 20,
        deadline_margin: Duration::from_secs(10),
        initial_backoff: Duration::from_millis(80),
        max_backoff: Duration::from_millis(160),
        minimum_attempt: Duration::from_millis(30),
    }
}

async fn fixture(answers: Vec<Answer>) -> Fixture {
    fixture_with(answers, timing()).await
}

async fn fixture_with(answers: Vec<Answer>, timing: BindTiming) -> Fixture {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let service = Arc::new(ScriptedService {
        answers: Mutex::new(answers.into()),
        recorded: recorded.clone(),
    });
    let versions = recorded.clone();
    let connect = connectrpc::Router::new().add_service(service);
    let app = Router::new()
        .fallback_service(connect.into_axum_service())
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                versions.lock().unwrap().versions.push(request.version());
                next.run(request)
            },
        ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, SYNTHETIC_PROJECTED_TOKEN).unwrap();
    let url = format!("http://{address}");
    let values = [
        (
            WORKSPACE_BINDING_URL_ENV,
            "http://binding.test:8087".to_owned(),
        ),
        (WORKSPACE_POD_UID_ENV, POD.to_owned()),
    ];
    let HostedDaemonMode::Binding(config) = HostedDaemonMode::from_lookup(|name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(value))
    })
    .unwrap() else {
        panic!("binding mode expected");
    };
    let config = config.with_token_path(&token);
    Fixture {
        client: BindingClient::new(&url, config.token_path(), timing).unwrap(),
        config,
        recorded,
        token,
        _directory: directory,
    }
}

#[tokio::test]
async fn an_accepted_binding_carries_the_credential_and_requested_wait() {
    let fixture = fixture(vec![Answer::Bound]).await;
    let binding = fixture.client.attempt(&fixture.config).await.unwrap();
    assert_eq!(binding.environment_id().to_string(), ENVIRONMENT);
    assert_eq!(binding.operation_generation(), 4);
    assert_eq!(
        binding.daemon_credential().expose_secret(),
        SYNTHETIC_CREDENTIAL
    );
    let recorded = fixture.recorded.lock().unwrap();
    assert_eq!(recorded.waits, [20]);
    assert_eq!(
        recorded.authorizations,
        [format!("Bearer {SYNTHETIC_PROJECTED_TOKEN}")]
    );
    // The tenant-reachable listener accepts HTTP/1.1 only.
    assert_eq!(recorded.versions, [http::Version::HTTP_11]);
}

#[tokio::test]
async fn not_found_is_called_again_at_once_until_bound() {
    // A backoff this long makes any wrongful backoff (at least half of it,
    // with jitter) unmistakable, so a loaded machine's slower attempts can
    // never be mistaken for one.
    let timing = BindTiming {
        initial_backoff: Duration::from_secs(10),
        max_backoff: Duration::from_secs(10),
        ..timing()
    };
    let fixture = fixture_with(
        vec![
            Answer::Error(ErrorCode::NotFound),
            Answer::Error(ErrorCode::NotFound),
            Answer::Bound,
        ],
        timing,
    )
    .await;
    let started = tokio::time::Instant::now();
    let binding = bind_until_accepted(&fixture.client, &fixture.config).await;
    assert_eq!(
        binding.daemon_credential().expose_secret(),
        SYNTHETIC_CREDENTIAL
    );
    let recorded = fixture.recorded.lock().unwrap();
    assert_eq!(recorded.at.len(), 3);
    // Paced only to the minimum attempt, never to the error backoff.
    for pair in recorded.at.windows(2) {
        let gap = pair[1] - pair[0];
        // Server-side stamps trail the client's attempt start slightly.
        assert!(
            gap + Duration::from_millis(10) >= timing.minimum_attempt,
            "{gap:?}"
        );
        assert!(gap < timing.initial_backoff / 2, "{gap:?}");
    }
    assert!(started.elapsed() < timing.initial_backoff / 2);
}

#[tokio::test]
async fn other_errors_back_off_exponentially_and_never_give_up() {
    let fixture = fixture(vec![
        Answer::Error(ErrorCode::Unavailable),
        Answer::Error(ErrorCode::ResourceExhausted),
        Answer::Error(ErrorCode::PermissionDenied),
        Answer::Error(ErrorCode::Unauthenticated),
        Answer::Bound,
    ])
    .await;
    bind_until_accepted(&fixture.client, &fixture.config).await;
    let recorded = fixture.recorded.lock().unwrap();
    assert_eq!(recorded.at.len(), 5);
    let gaps: Vec<_> = recorded
        .at
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();
    // Jitter keeps each pause within [backoff / 2, backoff]; the backoff
    // doubles from 80 ms to its 160 ms ceiling.
    let slack = Duration::from_millis(5);
    assert!(gaps[0] + slack >= Duration::from_millis(40), "{gaps:?}");
    for gap in &gaps[1..] {
        assert!(*gap + slack >= Duration::from_millis(80), "{gaps:?}");
    }
}

#[tokio::test]
async fn another_pods_binding_is_never_accepted() {
    let fixture = fixture(vec![Answer::BoundFor(OTHER_POD), Answer::Bound]).await;
    assert_eq!(
        fixture.client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::InvalidResponse
    );
    // The loop treats it as a failure and backs off, then accepts its own.
    let binding = bind_until_accepted(&fixture.client, &fixture.config).await;
    assert_eq!(binding.environment_id().to_string(), ENVIRONMENT);
}

#[tokio::test]
async fn the_projected_token_is_reread_on_every_attempt() {
    let fixture = fixture(vec![Answer::Error(ErrorCode::NotFound), Answer::Bound]).await;
    assert_eq!(
        fixture.client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::NotFound
    );
    std::fs::write(&fixture.token, "rotated.projected.workspace-binding").unwrap();
    fixture.client.attempt(&fixture.config).await.unwrap();
    assert_eq!(
        fixture.recorded.lock().unwrap().authorizations,
        [
            format!("Bearer {SYNTHETIC_PROJECTED_TOKEN}"),
            "Bearer rotated.projected.workspace-binding".to_owned(),
        ]
    );
}

#[tokio::test]
async fn a_missing_or_malformed_token_never_reaches_the_listener() {
    let fixture = fixture(vec![]).await;
    for invalid in [
        &b""[..],
        b" token",
        b"token\n",
        b"to ken",
        "t\u{f6}ken".as_bytes(),
    ] {
        std::fs::write(&fixture.token, invalid).unwrap();
        assert_eq!(
            fixture.client.attempt(&fixture.config).await.unwrap_err(),
            AttemptError::IdentityUnavailable
        );
    }
    std::fs::write(&fixture.token, vec![b'a'; MAX_BINDING_TOKEN_BYTES + 1]).unwrap();
    assert_eq!(
        fixture.client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::IdentityUnavailable
    );
    std::fs::remove_file(&fixture.token).unwrap();
    assert_eq!(
        fixture.client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::IdentityUnavailable
    );
    assert!(fixture.recorded.lock().unwrap().at.is_empty());
}

#[test]
fn attempt_outcomes_are_value_blind_and_only_not_found_is_immediate() {
    assert_eq!(
        classify(&ConnectError::not_found("x")),
        AttemptError::NotFound
    );
    for code in [
        ErrorCode::Unauthenticated,
        ErrorCode::PermissionDenied,
        ErrorCode::ResourceExhausted,
        ErrorCode::Unavailable,
        ErrorCode::DeadlineExceeded,
        ErrorCode::Internal,
    ] {
        let error = classify(&ConnectError::new(code, "value-bearing detail"));
        assert_eq!(error, AttemptError::Rejected(code));
        assert!(!error.label().contains("detail"));
    }
    assert_eq!(BindTiming::default().wait_seconds, 20);
    assert_eq!(BindTiming::default().deadline(), Duration::from_secs(30));
    assert_eq!(
        BindTiming::default().initial_backoff,
        Duration::from_millis(500)
    );
    assert_eq!(BindTiming::default().max_backoff, Duration::from_secs(10));
}

#[test]
fn jitter_stays_within_half_to_full_backoff() {
    for _ in 0..200 {
        let pause = jittered(Duration::from_millis(500));
        assert!(pause >= Duration::from_millis(250) && pause <= Duration::from_millis(500));
    }
}

#[test]
fn binding_authorization_is_sensitive() {
    let options = call_options(SYNTHETIC_PROJECTED_TOKEN).unwrap();
    assert!(!format!("{options:?}").contains(SYNTHETIC_PROJECTED_TOKEN));
}
