use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_client::{CODEWIRE_CLI_OAUTH_CLIENT_ID, CredentialStore as _, OAuthCredentials};
use codewire_project::PlatformProjectionSelection;
use futures::FutureExt as _;
use tokio::sync::mpsc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

/// How long a test waits for an event, such as a relay message, before it
/// fails.
const WAIT: Duration = Duration::from_secs(2);

/// A deadline no test reaches. These tests check who a saved login belongs
/// to and what it reaches, not timing, so a loaded host's scheduling must not
/// decide them (#3081). The deadline itself is tested on its own, with one
/// that has already passed.
fn no_deadline() -> Instant {
    Instant::now() + Duration::from_secs(24 * 60 * 60)
}

/// The authority as production builds it, but with no connect timeout of
/// its own: these tests check whose login is used and what it reaches, so a
/// starved host must not turn a slow connection into a refusal (#3123).
fn connector() -> NativePlatformCredentialConnector {
    NativePlatformCredentialConnector {
        connect_timeout: None,
    }
}

/// What the mock server saw, to read beside a refusal or a failure: a
/// request that never reached it failed in transport, which the authority
/// reports as a refusal too (#3123).
async fn reached(server: &MockServer) -> String {
    match server.received_requests().await.unwrap().len() {
        0 => "the mock server received no request, so this failed in transport".into(),
        received => format!("the mock server received {received} requests"),
    }
}

fn binding(directory: &Path, server: &str) -> PlatformCredentialBinding {
    PlatformCredentialBinding {
        config_directory: directory.to_owned(),
        server_url: server.to_owned(),
        selection: PlatformProjectionSelection {
            creator: "synthetic-owner".into(),
            organization: "pinned-org".into(),
            organization_selected: true,
            project_id: Some("f1911149-cfb5-4bcb-bd9c-a33cdeec8da1".into()),
            user_selected: true,
            profile: None,
            ordinary_keys: BTreeSet::from(["ORDINARY".into()]),
            reserved_keys: BTreeSet::from(["CODEWIRE_ENV_ID".into()]),
        },
        selection_sha256: [7; 32],
    }
}

fn ready() -> bridge::CredentialBridgeReady {
    bridge::CredentialBridgeReady {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
        environment_generation: 7,
    }
}

fn saved(directory: &Path, server: &str, token: &str, fresh: bool) {
    config::save_platform_config(
        directory,
        &config::PlatformConfig {
            server_url: server.into(),
            // This unrelated current CLI default must not retarget the saved VM.
            default_org: "another-current-default".into(),
            deployment_ca: None,
        },
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    FileCredentialStore::new(directory)
        .save(
            &OAuthCredentials::new(
                server,
                CODEWIRE_CLI_OAUTH_CLIENT_ID,
                token,
                "synthetic-refresh-token",
                if fresh { now + 3600 } else { now - 1 },
                "openid codewire.api",
            )
            .unwrap(),
        )
        .unwrap();
}

async fn userinfo(server: &MockServer, token: &str, owner: &str) {
    userinfo_after(server, token, owner, Duration::ZERO).await;
}

/// UserInfo for `token`, answered after `delay`.
async fn userinfo_after(server: &MockServer, token: &str, owner: &str, delay: Duration) {
    Mock::given(method("GET"))
        .and(path("/api/oauth/userinfo"))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"sub": owner}))
                .set_delay(delay),
        )
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn explicit_saved_oauth_rejects_missing_malformed_api_key_and_origin_mismatch_without_network()
 {
    let server = MockServer::start().await;
    for attack in [
        "missing",
        "malformed",
        "api key",
        "saved server",
        "credential issuer",
    ] {
        let directory = tempfile::tempdir().unwrap();
        saved(directory.path(), &server.uri(), "synthetic-access", true);
        let selected = binding(directory.path(), &server.uri());
        let credentials = config::oauth_credentials_path(directory.path());
        match attack {
            "missing" => FileCredentialStore::new(directory.path()).delete().unwrap(),
            "malformed" => std::fs::write(&credentials, b"{}").unwrap(),
            "api key" => saved(
                directory.path(),
                &server.uri(),
                "cw_synthetic-api-key",
                true,
            ),
            "saved server" => config::save_platform_config(
                directory.path(),
                &config::PlatformConfig {
                    server_url: "https://different.invalid".into(),
                    default_org: String::new(),
                    deployment_ca: None,
                },
            )
            .unwrap(),
            "credential issuer" => {
                let other = tempfile::tempdir().unwrap();
                saved(
                    other.path(),
                    "https://different.invalid",
                    "synthetic-access",
                    true,
                );
                let other_creds = FileCredentialStore::new(other.path())
                    .load()
                    .unwrap()
                    .unwrap();
                FileCredentialStore::new(directory.path())
                    .save(&other_creds)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let error = authenticated_client(&selected, no_deadline(), None)
            .await
            .err()
            .expect(attack);
        assert_eq!(error.code(), tonic::Code::PermissionDenied, "{attack}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_saved_oauth_binds_user_and_ignores_changed_default_organization() {
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    saved(directory.path(), &server.uri(), "synthetic-original", true);
    // A provider slower than WAIT, as a loaded host makes it, still gets the
    // ownership decision, not a deadline (#3081).
    userinfo_after(
        &server,
        "synthetic-original",
        "another-owner",
        WAIT + Duration::from_millis(500),
    )
    .await;
    let selected = binding(directory.path(), &server.uri());
    let error = authenticated_client(&selected, no_deadline(), None)
        .await
        .err()
        .unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "{error:?}: {}",
        reached(&server).await
    );
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(opening(&selected, ready()).unwrap().org_id, "pinned-org");
}

#[tokio::test]
async fn saved_refresh_is_once_and_userinfo_and_returned_client_share_original_bearer() {
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    saved(directory.path(), &server.uri(), "synthetic-expired", false);
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-refreshed", "refresh_token": "synthetic-rotated",
            "token_type": "Bearer", "expires_in": 3600, "scope": "openid codewire.api",
        })))
        .expect(1)
        .mount(&server)
        .await;
    userinfo(&server, "synthetic-refreshed", "synthetic-owner").await;
    let selected = binding(directory.path(), &server.uri());
    let client = match authenticated_client(&selected, no_deadline(), None).await {
        Ok(client) => client,
        Err(error) => panic!("{error:?}: {}", reached(&server).await),
    };
    // Simulate a subsequent login replacing the normal saved pair. The admitted
    // client must retain the original UserInfo bearer, not load this new login.
    saved(
        directory.path(),
        &server.uri(),
        "synthetic-later-login",
        true,
    );
    assert_eq!(
        client.bearer_token().await.unwrap().expose_secret(),
        "synthetic-refreshed"
    );
    assert_eq!(
        client.bearer_token().await.unwrap().expose_secret(),
        "synthetic-refreshed"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn saved_auth_original_deadline_and_noncanonical_or_nonprivate_paths_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    saved(
        directory.path(),
        "https://synthetic.invalid",
        "synthetic-access",
        true,
    );
    let selected = binding(directory.path(), "https://synthetic.invalid");
    assert_eq!(
        authenticated_client(&selected, Instant::now(), None)
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    let outside = tempfile::tempdir().unwrap();
    let link = outside.path().join("linked");
    std::os::unix::fs::symlink(directory.path(), &link).unwrap();
    assert!(validate_directory(&link).is_err());
    let credentials = config::oauth_credentials_path(directory.path());
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(validate_file(&credentials).is_err());
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file_link = outside.path().join("credentials.json");
    std::os::unix::fs::symlink(&credentials, &file_link).unwrap();
    assert!(validate_file(&file_link).is_err());
    let oversized = outside.path().join("large");
    std::fs::write(&oversized, vec![0; MAX_AUTH_FILE_BYTES as usize + 1]).unwrap();
    std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(validate_file(&oversized).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(validate_directory(directory.path()).is_err());
}

fn cancel() -> bridge::CredentialBridgeGuestMessage {
    bridge::CredentialBridgeGuestMessage {
        payload: Some(bridge::credential_bridge_guest_message::Payload::Cancel(
            bridge::CredentialBridgeCancel {
                request_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
            },
        )),
    }
}

fn response(frame: bridge::CredentialBridgeHostMessage) -> DelegateCredentialsResponse {
    DelegateCredentialsResponse {
        output: Some(delegate_credentials_response::Output::Frame(Box::new(
            public_bridge::CredentialBridgeHostMessage::decode_from_slice(&frame.encode_to_vec())
                .unwrap(),
        ))),
        ..Default::default()
    }
}

fn output() -> bridge::CredentialBridgeHostMessage {
    bridge::CredentialBridgeHostMessage {
        payload: Some(
            bridge::credential_bridge_host_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionResponse {
                    request_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
                    result: Some(
                        bridge::environment_projection_response::Result::SealedProjection(
                            b"synthetic-recipient-ciphertext".to_vec(),
                        ),
                    ),
                },
            ),
        ),
    }
}

#[test]
fn relay_conversion_preserves_exact_operation_bytes_and_rejects_re_admission() {
    for frame in [
        cancel(),
        bridge::CredentialBridgeGuestMessage {
            payload: Some(
                bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(
                    bridge::EnvironmentProjectionRequest {
                        request_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
                        selection_sha256: vec![7; 32],
                        recipient_public_key: vec![8; 32],
                        deadline_unix_ms: 123456,
                        local_inventories: Vec::new(),
                    },
                ),
            ),
        },
        bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Ssh(
                bridge::CredentialSshRequest {
                    request_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
                    deadline_unix_ms: 123456,
                    operation: Some(bridge::credential_ssh_request::Operation::Identities(
                        bridge::CredentialSshIdentitiesRequest {},
                    )),
                },
            )),
        },
    ] {
        let expected = frame.encode_to_vec();
        let Some(delegate_credentials_request::Input::Frame(actual)) = encode(frame).unwrap().input
        else {
            panic!("frame")
        };
        assert_eq!(actual.encode_to_vec(), expected);
    }
    assert_eq!(decode(response(output())).unwrap(), output());
    assert!(encode(bridge::CredentialBridgeGuestMessage::default()).is_err());
    assert!(
        encode(bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                ready()
            ))
        })
        .is_err()
    );
    assert!(decode(DelegateCredentialsResponse::default()).is_err());
    assert!(
        decode(DelegateCredentialsResponse {
            output: Some(delegate_credentials_response::Output::Admitted(
                Box::default()
            )),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        decode(response(bridge::CredentialBridgeHostMessage {
            payload: Some(bridge::credential_bridge_host_message::Payload::Open(
                bridge::CredentialBridgeOpen::default()
            ))
        }))
        .is_err()
    );
    assert!(decode(response(bridge::CredentialBridgeHostMessage::default())).is_err());
}

#[test]
fn relay_conversion_rejects_oversized_frames_before_second_encoding() {
    let mut frame = cancel();
    frame.payload = Some(bridge::credential_bridge_guest_message::Payload::Request(
        bridge::CredentialBridgeRequest {
            body: vec![0; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1],
            ..Default::default()
        },
    ));
    assert!(encode(frame).is_err());
    let mut reply = output();
    if let Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(reply)) =
        &mut reply.payload
    {
        reply.result = Some(
            bridge::environment_projection_response::Result::SealedProjection(vec![
                0;
                CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
                    + 1
            ]),
        );
    }
    assert!(decode(response(reply)).is_err());
}

/// A front-door session's frames cross the delegation in neither direction:
/// each is refused exactly as an unknown frame (an empty payload, which an
/// older peer decodes one as) is.
#[test]
fn relay_conversion_refuses_front_door_frames_as_unknown_frames() {
    use bridge::credential_bridge_guest_message::Payload as Guest;
    use bridge::credential_bridge_host_message::Payload as Host;
    let request_id = "10000000-0000-0000-0000-000000000001".to_owned();
    for payload in [
        None,
        Some(Guest::Upgrade(bridge::CredentialBridgeUpgrade {
            request_id: request_id.clone(),
            method: "GET".into(),
            path: "/v1/responses".into(),
            intercepted_host: "chatgpt.com".into(),
            initial_credit_bytes: 65_536,
            ..Default::default()
        })),
        Some(Guest::StreamData(bridge::CredentialBridgeStreamData {
            request_id: request_id.clone(),
            data: b"frame".to_vec(),
        })),
        Some(Guest::StreamCredit(bridge::CredentialBridgeStreamCredit {
            request_id: request_id.clone(),
            credit_bytes: 1024,
        })),
        Some(Guest::StreamClose(bridge::CredentialBridgeStreamClose {
            request_id: request_id.clone(),
            kind: bridge::CredentialBridgeStreamCloseKind::Reset as i32,
        })),
    ] {
        assert!(encode(bridge::CredentialBridgeGuestMessage { payload }).is_err());
    }
    for payload in [
        None,
        Some(Host::UpgradeAccepted(
            bridge::CredentialBridgeUpgradeAccepted {
                request_id: request_id.clone(),
                headers: Vec::new(),
            },
        )),
        Some(Host::StreamData(bridge::CredentialBridgeStreamData {
            request_id: request_id.clone(),
            data: b"frame".to_vec(),
        })),
        Some(Host::StreamCredit(bridge::CredentialBridgeStreamCredit {
            request_id: request_id.clone(),
            credit_bytes: 1024,
        })),
        Some(Host::StreamClose(bridge::CredentialBridgeStreamClose {
            request_id: request_id.clone(),
            kind: bridge::CredentialBridgeStreamCloseKind::HalfClose as i32,
        })),
        Some(Host::InterceptionHint(
            bridge::CredentialBridgeInterceptionHint {
                request_id: request_id.clone(),
                origin: "https://chatgpt.com".into(),
            },
        )),
    ] {
        assert!(decode(response(bridge::CredentialBridgeHostMessage { payload })).is_err());
    }
}

struct FakeUpstream {
    responses: mpsc::Receiver<Result<DelegateCredentialsResponse, Status>>,
    sent: Arc<Mutex<Vec<DelegateCredentialsRequest>>>,
    dropped: Arc<AtomicUsize>,
    block_send: bool,
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl Upstream for FakeUpstream {
    async fn send(&mut self, request: DelegateCredentialsRequest) -> Result<(), Status> {
        self.sent.lock().unwrap().push(request);
        if self.block_send {
            futures::future::pending().await
        } else {
            Ok(())
        }
    }
    async fn receive(&mut self) -> Result<Option<DelegateCredentialsResponse>, Status> {
        self.responses.recv().await.transpose()
    }
}

#[tokio::test]
async fn relay_observes_input_and_output_then_input_eof_drops_both_owners() {
    let (requests_tx, requests_rx) = mpsc::channel(1);
    let (responses_tx, responses_rx) = mpsc::channel(1);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let input = Box::pin(tokio_stream::wrappers::ReceiverStream::new(requests_rx));
    let mut relay = relay(
        FakeUpstream {
            responses: responses_rx,
            sent: sent.clone(),
            dropped: dropped.clone(),
            block_send: false,
        },
        false,
        input,
    );
    requests_tx.send(Ok(cancel())).await.unwrap();
    assert!(relay.next().now_or_never().is_none());
    assert_eq!(sent.lock().unwrap().len(), 1);
    responses_tx.send(Ok(response(output()))).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, relay.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        output()
    );
    drop(requests_tx);
    assert!(
        tokio::time::timeout(WAIT, relay.next())
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::timeout(WAIT, responses_tx.closed())
        .await
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_drop_while_send_pending_closes_input_and_upstream_without_detached_pump() {
    let (requests_tx, requests_rx) = mpsc::channel(1);
    let (responses_tx, responses_rx) = mpsc::channel(1);
    let dropped = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let input = Box::pin(tokio_stream::wrappers::ReceiverStream::new(requests_rx));
    let mut output = relay(
        FakeUpstream {
            responses: responses_rx,
            sent: sent.clone(),
            dropped: dropped.clone(),
            block_send: true,
        },
        false,
        input,
    );
    requests_tx.send(Ok(cancel())).await.unwrap();
    assert!(output.next().now_or_never().is_none());
    assert_eq!(sent.lock().unwrap().len(), 1);
    drop(output);
    tokio::time::timeout(WAIT, requests_tx.closed())
        .await
        .unwrap();
    tokio::time::timeout(WAIT, responses_tx.closed())
        .await
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_invalid_response_ends_stream_and_closes_both_directions() {
    let (requests_tx, requests_rx) = mpsc::channel(1);
    let (responses_tx, responses_rx) = mpsc::channel(1);
    let dropped = Arc::new(AtomicUsize::new(0));
    let input = Box::pin(tokio_stream::wrappers::ReceiverStream::new(requests_rx));
    let mut output = relay(
        FakeUpstream {
            responses: responses_rx,
            sent: Arc::new(Mutex::new(Vec::new())),
            dropped: dropped.clone(),
            block_send: false,
        },
        false,
        input,
    );
    responses_tx
        .send(Ok(DelegateCredentialsResponse::default()))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, output.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!(output.next().await.is_none());
    tokio::time::timeout(WAIT, requests_tx.closed())
        .await
        .unwrap();
    tokio::time::timeout(WAIT, responses_tx.closed())
        .await
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

/// A local VM asks, at each start, whether the creator's GitHub connection is
/// usable now. Only an active, unexpired GitHub OAuth credential counts; the
/// answer is read as the pinned creator, from metadata alone.
#[tokio::test]
async fn github_connection_state_is_read_as_the_creator_from_metadata_only() {
    use codewire_client as rpc;
    let github = |status: rpc::CredentialStatus, expires_at_unix: Option<u64>| rpc::Credential {
        id: "github-credential".into(),
        provider: "github".into(),
        authentication_kind: rpc::CredentialAuthenticationKind::Oauth.into(),
        status: status.into(),
        expires_at_unix,
        ..Default::default()
    };
    let other = rpc::Credential {
        id: "openai-credential".into(),
        provider: "openai".into(),
        authentication_kind: rpc::CredentialAuthenticationKind::Oauth.into(),
        status: rpc::CredentialStatus::Active.into(),
        ..Default::default()
    };
    for (credentials, expected) in [
        (
            vec![other.clone(), github(rpc::CredentialStatus::Active, None)],
            true,
        ),
        (
            vec![github(rpc::CredentialStatus::Active, Some(u64::MAX / 2))],
            true,
        ),
        (vec![], false),
        (vec![other.clone()], false),
        (vec![github(rpc::CredentialStatus::Revoked, None)], false),
        (
            vec![github(rpc::CredentialStatus::RefreshFailed, None)],
            false,
        ),
        (vec![github(rpc::CredentialStatus::Active, Some(1))], false),
    ] {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        saved(directory.path(), &server.uri(), "synthetic-access", true);
        userinfo(&server, "synthetic-access", "synthetic-owner").await;
        Mock::given(method("POST"))
            .and(path("/codewire.v1.CredentialService/ListCredentials"))
            .and(header("authorization", "Bearer synthetic-access"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListCredentialsResponse {
                            credentials: credentials.clone(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let connected = match connector()
            .github_connected(binding(directory.path(), &server.uri()), no_deadline())
            .await
        {
            Ok(connected) => connected,
            Err(error) => panic!("{error:?}: {}", reached(&server).await),
        };
        assert_eq!(connected, expected, "{credentials:?}");
    }

    // Another account's login is refused before any metadata is read.
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    saved(directory.path(), &server.uri(), "synthetic-access", true);
    userinfo(&server, "synthetic-access", "another-owner").await;
    let error = connector()
        .github_connected(binding(directory.path(), &server.uri()), no_deadline())
        .await
        .unwrap_err();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "{error:?}: {}",
        reached(&server).await
    );
    assert_eq!(error.code(), tonic::Code::PermissionDenied);

    // A saved API key, or a login saved for another server, is refused before
    // any request, as when a delegation opens.
    for attack in ["api key", "saved server"] {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        saved(directory.path(), &server.uri(), "synthetic-access", true);
        match attack {
            "api key" => saved(
                directory.path(),
                &server.uri(),
                "cw_synthetic-api-key",
                true,
            ),
            _ => config::save_platform_config(
                directory.path(),
                &config::PlatformConfig {
                    server_url: "https://different.invalid".into(),
                    default_org: String::new(),
                    deployment_ca: None,
                },
            )
            .unwrap(),
        }
        let error = connector()
            .github_connected(binding(directory.path(), &server.uri()), no_deadline())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied, "{attack}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "{attack}"
        );
    }
}

fn keepalive_answer() -> DelegateCredentialsResponse {
    DelegateCredentialsResponse {
        output: Some(delegate_credentials_response::Output::Keepalive(
            Box::default(),
        )),
        ..Default::default()
    }
}

fn kinds(sent: &Mutex<Vec<DelegateCredentialsRequest>>) -> Vec<&'static str> {
    sent.lock()
        .unwrap()
        .iter()
        .map(|request| match request.input {
            Some(delegate_credentials_request::Input::Keepalive(_)) => "keepalive",
            Some(delegate_credentials_request::Input::Frame(_)) => "frame",
            _ => "other",
        })
        .collect()
}

struct KeepaliveRelay {
    requests: mpsc::Sender<Result<bridge::CredentialBridgeGuestMessage, Status>>,
    responses: mpsc::Sender<Result<DelegateCredentialsResponse, Status>>,
    sent: Arc<Mutex<Vec<DelegateCredentialsRequest>>>,
    output: PlatformCredentialOutput,
}

fn keepalive_relay(keepalive: bool, block_send: bool) -> KeepaliveRelay {
    let (requests, requests_rx) = mpsc::channel(1);
    let (responses, responses_rx) = mpsc::channel(1);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let output = relay(
        FakeUpstream {
            responses: responses_rx,
            sent: sent.clone(),
            dropped: Arc::new(AtomicUsize::new(0)),
            block_send,
        },
        keepalive,
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(requests_rx)),
    );
    KeepaliveRelay {
        requests,
        responses,
        sent,
        output,
    }
}

/// Poll the relay for `duration` of paused time; it must yield nothing.
async fn idle(output: &mut PlatformCredentialOutput, duration: Duration) {
    assert!(
        tokio::time::timeout(duration, output.next()).await.is_err(),
        "the relay yielded or ended while idle"
    );
}

#[tokio::test(start_paused = true)]
async fn relay_sends_one_keepalive_after_upstream_idleness_and_waits_for_its_answer() {
    let mut relay = keepalive_relay(true, false);
    idle(&mut relay.output, KEEPALIVE_IDLE - Duration::from_secs(1)).await;
    assert!(kinds(&relay.sent).is_empty());
    // A frame sent upstream restarts the idle period.
    relay.requests.send(Ok(cancel())).await.unwrap();
    idle(&mut relay.output, KEEPALIVE_IDLE - Duration::from_secs(1)).await;
    assert_eq!(kinds(&relay.sent), ["frame"]);
    idle(&mut relay.output, Duration::from_secs(2)).await;
    assert_eq!(kinds(&relay.sent), ["frame", "keepalive"]);
    // No second keepalive while the first waits for its answer.
    idle(&mut relay.output, KEEPALIVE_IDLE * 3).await;
    assert_eq!(kinds(&relay.sent), ["frame", "keepalive"]);
    // The answer is consumed, never passed to the broker. The next keepalive
    // was due one idle period after the previous one, so it goes at once.
    relay.responses.send(Ok(keepalive_answer())).await.unwrap();
    idle(&mut relay.output, Duration::from_secs(1)).await;
    assert_eq!(kinds(&relay.sent), ["frame", "keepalive", "keepalive"]);
    relay.responses.send(Ok(keepalive_answer())).await.unwrap();
    idle(&mut relay.output, Duration::from_secs(1)).await;
    assert_eq!(kinds(&relay.sent), ["frame", "keepalive", "keepalive"]);
    // Operations still flow both ways.
    relay.responses.send(Ok(response(output()))).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, relay.output.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        output()
    );
}

#[tokio::test(start_paused = true)]
async fn relay_sends_no_keepalive_to_a_server_that_did_not_offer_them() {
    let mut relay = keepalive_relay(false, false);
    idle(&mut relay.output, KEEPALIVE_IDLE * 20).await;
    assert!(kinds(&relay.sent).is_empty());
    // And an answer it never asked for ends the epoch.
    relay.responses.send(Ok(keepalive_answer())).await.unwrap();
    assert_eq!(
        relay.output.next().await.unwrap().unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(relay.output.next().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn relay_unsolicited_keepalive_answer_ends_the_epoch() {
    let mut relay = keepalive_relay(true, false);
    relay.responses.send(Ok(keepalive_answer())).await.unwrap();
    assert_eq!(
        relay.output.next().await.unwrap().unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(relay.output.next().await.is_none());
    assert!(kinds(&relay.sent).is_empty());
}

#[tokio::test(start_paused = true)]
async fn relay_keepalive_send_timeout_ends_the_epoch_like_a_frame() {
    let mut relay = keepalive_relay(true, true);
    let started = Instant::now();
    assert_eq!(
        relay.output.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= KEEPALIVE_IDLE + SEND_TIMEOUT && elapsed < KEEPALIVE_IDLE + SEND_TIMEOUT * 2
    );
    assert_eq!(kinds(&relay.sent), ["keepalive"]);
    assert!(relay.output.next().await.is_none());
    drop(relay.requests);
}
