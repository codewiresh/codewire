use std::collections::VecDeque;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use super::*;
use axum::Router;
use codewire_daemon::HostedDaemonMode;
use codewire_daemon::config::{WORKSPACE_BINDING_URL_ENV, WORKSPACE_POD_UID_ENV};
use codewire_proto::codewire::internal::v1::{
    IssueMeshEnrollmentRequest, IssueMeshEnrollmentResponse, RecordHostKeyResponse,
    RefreshAccessResponse, ReportMeshAttachmentRequest, ReportMeshAttachmentResponse,
    WorkspaceBindingService,
};
use codewire_tls::test_support::SyntheticPki;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use tempfile::TempDir;

const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const OTHER_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
const SYNTHETIC_CREDENTIAL: &str = "synthetic-workspace-daemon-credential";
const SYNTHETIC_PROJECTED_TOKEN: &str = "synthetic.projected.workspace-binding";
const SYNTHETIC_PEER_TOKEN: &str = "synthetic.peer.token";
const HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const OTHER_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7FpOVbm/6E3nHvH0r0IGM2xQtW2X5nOkjLwFvbTgbM";

fn synthetic_access(generation: i64) -> WorkspaceAccess {
    let expires = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    WorkspaceAccess {
        peer_token: SYNTHETIC_PEER_TOKEN.into(),
        peer_token_expires_at: i64::try_from(expires).unwrap(),
        operation_generation: generation,
        coordinator_url: "https://codewire.test".into(),
        direct_udp_endpoints: vec!["203.0.113.7:41641".into()],
        peer_relay_endpoints: vec!["relay.codewire.test:41641".into()],
        ..Default::default()
    }
}

/// One scripted answer of the fake listener.
enum Answer {
    Bound,
    BoundFor(&'static str),
    /// Bound, with an access grant for this generation.
    BoundWithAccess(i64),
    /// Bound, with an already-expired access grant.
    BoundWithExpiredAccess,
    Error(ErrorCode),
}

#[derive(Default)]
struct Recorded {
    authorizations: Vec<String>,
    waits: Vec<u32>,
    versions: Vec<http::Version>,
    at: Vec<tokio::time::Instant>,
    host_key: Option<String>,
    relay_requests: Vec<(Vec<String>, u32)>,
    /// The code `IssueMeshEnrollment` answers with; `None` refuses.
    mesh_code: Option<String>,
    mesh_reports: Vec<i32>,
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
        let (pod_uid, access) = match answer {
            Answer::Bound => (POD, None),
            Answer::BoundFor(pod) => (pod, None),
            Answer::BoundWithAccess(generation) => (POD, Some(synthetic_access(generation))),
            Answer::BoundWithExpiredAccess => (
                POD,
                Some(WorkspaceAccess {
                    peer_token_expires_at: 1,
                    ..synthetic_access(4)
                }),
            ),
            Answer::Error(code) => return Err(ConnectError::new(code, "scripted")),
        };
        connectrpc::Response::ok(BindWorkspaceResponse {
            environment_id: ENVIRONMENT.into(),
            pod_uid: pod_uid.into(),
            operation_generation: 4,
            daemon_credential: SYNTHETIC_CREDENTIAL.into(),
            projection_selection_sha256: String::new(),
            managed_credential_clients: "v1:none".into(),
            access: access.map(::buffa::MessageField::some).unwrap_or_default(),
            working_directory: "/workspace/app".into(),
            ..Default::default()
        })
    }

    async fn refresh_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, RefreshAccessRequest>,
    ) -> ServiceResult<RefreshAccessResponse> {
        connectrpc::Response::ok(RefreshAccessResponse {
            access: ::buffa::MessageField::some(synthetic_access(5)),
            ..Default::default()
        })
    }

    async fn record_host_key(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RecordHostKeyRequest>,
    ) -> ServiceResult<RecordHostKeyResponse> {
        let mut recorded = self.recorded.lock().unwrap();
        let key = request.public_key_openssh.to_string();
        match recorded.host_key.as_deref() {
            Some(existing) if existing != key => Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "a different key is recorded",
            )),
            _ => {
                recorded.host_key = Some(key);
                connectrpc::Response::ok(RecordHostKeyResponse::default())
            }
        }
    }

    async fn allocate_peer_relay(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AllocatePeerRelayRequest>,
    ) -> ServiceResult<AllocatePeerRelayResponse> {
        let disco_keys: Vec<String> = request
            .disco_keys
            .iter()
            .map(|key| key.to_string())
            .collect();
        self.recorded
            .lock()
            .unwrap()
            .relay_requests
            .push((disco_keys.clone(), request.relay_generation));
        connectrpc::Response::ok(AllocatePeerRelayResponse {
            relay_generation: request.relay_generation,
            server_disco_key: "discokey:00".into(),
            disco_keys,
            lamport_id: 1,
            vni: 7,
            bind_lifetime_ns: 1,
            steady_state_lifetime_ns: 2,
            addr_ports: vec!["203.0.113.9:41641".into()],
            ..Default::default()
        })
    }

    async fn issue_mesh_enrollment(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, IssueMeshEnrollmentRequest>,
    ) -> ServiceResult<IssueMeshEnrollmentResponse> {
        let Some(code) = self.recorded.lock().unwrap().mesh_code.clone() else {
            return Err(ConnectError::failed_precondition("no Mesh network"));
        };
        connectrpc::Response::ok(IssueMeshEnrollmentResponse {
            enrollment_code: code,
            expires_at: 1,
            attachment: ::buffa::MessageField::some(
                codewire_proto::codewire::internal::v1::WorkspaceMeshAttachment {
                    mesh_url: "https://mesh.codewire.test".into(),
                    org_id: "org-1".into(),
                    network_id: "work".into(),
                    node_name: "app-1".into(),
                    ..Default::default()
                },
            ),
            ..Default::default()
        })
    }

    async fn report_mesh_attachment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReportMeshAttachmentRequest>,
    ) -> ServiceResult<ReportMeshAttachmentResponse> {
        self.recorded
            .lock()
            .unwrap()
            .mesh_reports
            .push(request.report.to_i32());
        connectrpc::Response::ok(ReportMeshAttachmentResponse::default())
    }
}

struct Fixture {
    client: BindingClient,
    config: WorkspaceBindingConfig,
    recorded: Arc<Mutex<Recorded>>,
    token: PathBuf,
    url: String,
    _pki: SyntheticPki,
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
    // The listener serves TLS only, as in production.
    let pki = SyntheticPki::new("localhost");
    let address = pki.serve(app).await;
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, SYNTHETIC_PROJECTED_TOKEN).unwrap();
    let url = format!("https://localhost:{}", address.port());
    let values = [
        (
            WORKSPACE_BINDING_URL_ENV,
            "https://binding.test:8087".to_owned(),
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
    // The synthetic listener's roots stand in for the mounted internal CA.
    let config = config
        .with_token_path(&token)
        .with_tls_roots_file(&pki.roots);
    Fixture {
        client: BindingClient::new(&url, config.tls_roots_file(), config.token_path(), timing)
            .unwrap(),
        config,
        recorded,
        token,
        url,
        _pki: pki,
        _directory: directory,
    }
}

#[tokio::test]
async fn an_accepted_binding_carries_the_credential_and_requested_wait() {
    let fixture = fixture(vec![Answer::Bound]).await;
    let bound = fixture.client.attempt(&fixture.config).await.unwrap();
    assert!(bound.access.is_none());
    let binding = bound.binding;
    assert_eq!(binding.environment_id().to_string(), ENVIRONMENT);
    assert_eq!(binding.operation_generation(), 4);
    assert_eq!(
        binding.daemon_credential().expose_secret(),
        SYNTHETIC_CREDENTIAL
    );
    // Unlisted sessions start in the environment's declared directory.
    assert_eq!(
        fixture
            .config
            .clone()
            .into_config(&binding)
            .session_working_dir,
        Some(std::path::PathBuf::from("/workspace/app"))
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
        minimum_attempt: Duration::from_millis(300),
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
    let binding = bind_until_accepted(&fixture.client, &fixture.config)
        .await
        .binding;
    assert_eq!(
        binding.daemon_credential().expose_secret(),
        SYNTHETIC_CREDENTIAL
    );
    let recorded = fixture.recorded.lock().unwrap();
    assert_eq!(recorded.at.len(), 3);
    // Paced only to the minimum attempt, never to the error backoff. Each
    // server-side stamp trails its attempt's start by a TLS handshake, so
    // attempt k arrives no earlier than k minimum attempts after the start;
    // gaps between stamps alone would carry two handshakes' jitter.
    for (attempt, at) in recorded.at.iter().enumerate() {
        let since_start = *at - started;
        let paced = timing.minimum_attempt * u32::try_from(attempt).unwrap();
        assert!(since_start >= paced, "attempt {attempt} at {since_start:?}");
    }
    for pair in recorded.at.windows(2) {
        let gap = pair[1] - pair[0];
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
    let bound = bind_until_accepted(&fixture.client, &fixture.config).await;
    assert_eq!(bound.binding.environment_id().to_string(), ENVIRONMENT);
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

#[tokio::test]
async fn an_access_grant_is_validated_with_the_binding() {
    let fixture = fixture(vec![
        Answer::BoundWithAccess(4),
        Answer::BoundWithAccess(6),
        Answer::BoundWithExpiredAccess,
    ])
    .await;
    let bound = fixture.client.attempt(&fixture.config).await.unwrap();
    let access = bound.access.expect("access grant");
    assert_eq!(access.peer_token().expose_secret(), SYNTHETIC_PEER_TOKEN);
    assert_eq!(access.operation_generation(), 4);
    assert_eq!(access.coordinator_url(), "https://codewire.test");
    assert_eq!(access.direct_udp_endpoints(), ["203.0.113.7:41641"]);
    assert_eq!(access.peer_relay_endpoints(), ["relay.codewire.test:41641"]);
    // The grant names the environment's current generation, which may have
    // moved on after the binding's (4).
    let bound = fixture.client.attempt(&fixture.config).await.unwrap();
    assert_eq!(bound.binding.operation_generation(), 4);
    assert_eq!(bound.access.unwrap().operation_generation(), 6);
    // An invalid grant fails the whole response.
    assert_eq!(
        fixture.client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::InvalidResponse
    );
}

#[tokio::test]
async fn refresh_record_and_allocate_use_the_bound_exchange() {
    let fixture = fixture(vec![]).await;
    let access = fixture.client.refresh_access().await.unwrap();
    assert_eq!(access.operation_generation(), 5);
    // The same key is recorded again idempotently; another is refused.
    fixture.client.record_host_key(HOST_KEY).await.unwrap();
    fixture.client.record_host_key(HOST_KEY).await.unwrap();
    assert_eq!(
        fixture
            .client
            .record_host_key(OTHER_HOST_KEY)
            .await
            .unwrap_err(),
        AttemptError::Rejected(ErrorCode::FailedPrecondition)
    );
    let keys = ["discokey:aa".to_owned(), "discokey:bb".to_owned()];
    let allocation = fixture
        .client
        .allocate_peer_relay(keys.clone(), 9)
        .await
        .unwrap();
    assert_eq!(allocation.relay_generation, 9);
    assert_eq!(allocation.addr_ports, ["203.0.113.9:41641"]);
    let recorded = fixture.recorded.lock().unwrap();
    assert_eq!(recorded.relay_requests, [(keys.to_vec(), 9)]);
    // Every call carried the projected token, over HTTP/1.1.
    assert!(
        recorded
            .authorizations
            .iter()
            .all(|value| value == &format!("Bearer {SYNTHETIC_PROJECTED_TOKEN}"))
    );
    assert!(
        recorded
            .versions
            .iter()
            .all(|version| *version == http::Version::HTTP_11)
    );
}

#[tokio::test]
async fn the_listener_must_present_a_certificate_from_the_mounted_roots() {
    let fixture = fixture(vec![]).await;
    // Roots from another authority: no call ever succeeds.
    let other = SyntheticPki::new("localhost");
    let client = BindingClient::new(
        &fixture.url,
        &other.roots,
        fixture.config.token_path(),
        timing(),
    )
    .unwrap();
    assert_eq!(
        client.attempt(&fixture.config).await.unwrap_err(),
        AttemptError::Rejected(ErrorCode::Unavailable)
    );
    assert!(fixture.recorded.lock().unwrap().at.is_empty());
    // An absent roots mount never falls back to other trust.
    let unmounted = tempfile::tempdir().unwrap();
    let client = BindingClient::new(
        &fixture.url,
        &unmounted.path().join("ca.crt"),
        fixture.config.token_path(),
        timing(),
    )
    .unwrap();
    assert!(client.attempt(&fixture.config).await.is_err());
    assert!(fixture.recorded.lock().unwrap().at.is_empty());
    // Plaintext origins and relative roots are refused outright.
    assert!(
        BindingClient::new(
            "http://localhost:8087",
            &other.roots,
            fixture.config.token_path(),
            timing()
        )
        .is_err()
    );
    assert!(
        BindingClient::new(
            &fixture.url,
            Path::new("ca.crt"),
            fixture.config.token_path(),
            timing()
        )
        .is_err()
    );
}

#[test]
fn binding_authorization_is_sensitive() {
    let options = call_options(SYNTHETIC_PROJECTED_TOKEN).unwrap();
    assert!(!format!("{options:?}").contains(SYNTHETIC_PROJECTED_TOKEN));
}

#[tokio::test]
async fn mesh_enrollment_returns_one_code_and_its_network_and_refuses_malformed_ones() {
    use codewire_proto::codewire::internal::v1::MeshAttachmentReport;

    let fixture = fixture(Vec::new()).await;
    // An environment without a network is refused for good.
    assert_eq!(
        fixture.client.issue_mesh_enrollment().await.unwrap_err(),
        AttemptError::Rejected(ErrorCode::FailedPrecondition)
    );
    let code = format!("cw_eenr_{}", "ab".repeat(32));
    fixture.recorded.lock().unwrap().mesh_code = Some(code.clone());
    let (issued, target) = fixture.client.issue_mesh_enrollment().await.unwrap();
    assert_eq!(issued.as_str(), code);
    assert_eq!(
        (
            target.mesh_url(),
            target.org_id(),
            target.network_id(),
            target.node_name()
        ),
        ("https://mesh.codewire.test", "org-1", "work", "app-1")
    );
    for malformed in ["", "cw_eenr_short", "cw_enr_abababab"] {
        fixture.recorded.lock().unwrap().mesh_code = Some(malformed.to_owned());
        assert_eq!(
            fixture.client.issue_mesh_enrollment().await.unwrap_err(),
            AttemptError::InvalidResponse,
            "{malformed}"
        );
    }
    fixture
        .client
        .report_mesh_attachment(MeshAttachmentReport::NotAMember)
        .await
        .unwrap();
    assert_eq!(
        fixture.recorded.lock().unwrap().mesh_reports,
        [MeshAttachmentReport::NotAMember as i32]
    );
}
