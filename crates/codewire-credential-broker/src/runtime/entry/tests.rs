use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use codewire_access::{BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use prost::Message as _;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::*;
use crate::bridge::{BrokerRequestExecutor as _, FrontDoorExecutor};
use crate::http_test_support::Lease;
use crate::{
    BrokerBridgeError, BrokerCredentialRefreshRequest, BrokerLeaseError, BrokerRefreshAdmission,
    BrokerRefreshError, BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
    CanonicalCodexOAuthBundle, CredentialBridgeResponseSink, CredentialBridgeTransport,
    admit_credential_bridge, run_admitted_credential_bridge, run_admitted_front_door_bridge,
};

type Payload = v1::credential_bridge_host_message::Payload;

/// One outbound provider request as the upstream received it: method,
/// target, every header in order, and body.
type Outbound = (Method, String, Vec<(String, Vec<u8>)>, Vec<u8>);

const GENERATION: u64 = 3;

/// Every host some route sends to.
const ROUTE_HOSTS: [&str; 5] = [
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "api.github.com",
    "github.com",
];

/// One request per provider route, and the hosts its slot's route sends to.
struct Case {
    slot: &'static str,
    route: &'static str,
    method: &'static str,
    path: &'static str,
    body: &'static [u8],
    media: &'static str,
    hosts: &'static [&'static str],
}

fn cases() -> [Case; 5] {
    [
        Case {
            slot: "codex",
            route: "openai-api",
            method: "POST",
            path: "/responses",
            body: b"{}",
            media: "application/json",
            hosts: &["api.openai.com", "chatgpt.com"],
        },
        Case {
            slot: "openai",
            route: "openai-api",
            method: "POST",
            path: "/responses",
            body: b"{}",
            media: "application/json",
            hosts: &["api.openai.com"],
        },
        Case {
            slot: "anthropic",
            route: "anthropic-api",
            method: "POST",
            path: "/v1/messages",
            body: b"{}",
            media: "application/json",
            hosts: &["api.anthropic.com"],
        },
        Case {
            slot: "github",
            route: "github-api",
            method: "GET",
            path: "/user",
            body: b"",
            media: "application/json",
            hosts: &["api.github.com"],
        },
        Case {
            slot: "github",
            route: "github-https",
            method: "POST",
            path: "/owner/repo.git/git-upload-pack",
            body: b"0000",
            media: "application/x-git-upload-pack-request",
            hosts: &["github.com"],
        },
    ]
}

impl Case {
    fn request(&self, intercepted_host: &str) -> v1::CredentialBridgeRequest {
        let mut headers = vec![v1::CredentialHttpHeader {
            name: "content-type".into(),
            value: self.media.as_bytes().to_vec(),
        }];
        if self.slot == "anthropic" {
            headers.push(v1::CredentialHttpHeader {
                name: "anthropic-version".into(),
                value: b"2023-06-01".to_vec(),
            });
        }
        v1::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(),
            method: self.method.into(),
            path: self.path.into(),
            query: String::new(),
            headers,
            body: self.body.to_vec(),
            capability_slot: self.slot.into(),
            route: self.route.into(),
            intercepted_host: intercepted_host.into(),
            streamed_body: false,
        }
    }
}

/// Names a front-door peer could send that are not one of `host`'s exact,
/// canonical, bindable forms.
fn malformed(host: &str) -> Vec<String> {
    vec![
        String::new(),
        host.to_ascii_uppercase(),
        format!("{host}."),
        format!(" {host}"),
        format!("*.{host}"),
        "*".into(),
        format!("{host}:443"),
        format!("https://{host}"),
        "192.0.2.1".into(),
        "2001:db8::1".into(),
        "[2001:db8::1]".into(),
        "localhost".into(),
        "metadata.google.internal".into(),
        format!("{host}.internal"),
    ]
}

/// Counts leases and records every outbound request; nothing refreshes.
#[derive(Clone, Default)]
struct Recorded {
    leases: Arc<AtomicUsize>,
    outbound: Arc<Mutex<Vec<Outbound>>>,
}

impl Recorded {
    fn broker(&self) -> OpenAiBroker<Authority, Upstream> {
        OpenAiBroker::new(
            Authority {
                leases: Arc::clone(&self.leases),
            },
            Upstream {
                outbound: Arc::clone(&self.outbound),
            },
        )
        .unwrap()
    }

    fn leases(&self) -> usize {
        self.leases.load(Ordering::Relaxed)
    }

    fn outbound(&self) -> Vec<Outbound> {
        self.outbound.lock().unwrap().clone()
    }
}

struct Authority {
    leases: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerLeaseProvider for Authority {
    type Lease = Lease;
    type RefreshReservation = ();
    type StartedRefresh = ();

    async fn lease_operation(
        &self,
        _id: Uuid,
        slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        self.leases.fetch_add(1, Ordering::Relaxed);
        let (provider, kind) = match slot.as_str() {
            "codex" | "openai" => ("openai", CredentialAuthKind::ApiKey),
            "anthropic" => ("anthropic", CredentialAuthKind::ApiKey),
            "github" => ("github", CredentialAuthKind::OAuth),
            _ => return Err(BrokerLeaseError::Denied),
        };
        Ok(Lease::new(
            provider,
            kind,
            slot.as_str(),
            operation.as_str(),
            route.as_str(),
        ))
    }

    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

struct Upstream {
    outbound: Arc<Mutex<Vec<Outbound>>>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        let media = if target.host_str() == Some("github.com") {
            "application/x-git-upload-pack-result"
        } else {
            "application/json"
        };
        self.outbound.lock().unwrap().push((
            method,
            target.to_string(),
            headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body,
        ));
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(http::header::CONTENT_TYPE, HeaderValue::from_static(media))]),
            Box::pin(futures::stream::iter([Ok(Bytes::from_static(b"{}"))])),
        ))
    }
}

async fn collect(response: BrokerHttpResponse) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (status, headers, mut body) = response.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend(chunk.unwrap());
    }
    (status, headers, bytes)
}

/// A front-door request naming one of its route's hosts is served exactly as
/// the same request on a loopback session: one lease each, and the provider
/// receives the same request, headers and all (the request id never leaves
/// the broker), and the guest the same response. The validated request keeps
/// the host it named.
#[tokio::test]
async fn a_front_door_request_naming_a_host_of_its_route_is_served_as_on_loopback() {
    for case in cases() {
        for host in case.hosts {
            let recorded = Recorded::default();
            let broker = recorded.broker();
            let loopback = collect(broker.execute(case.request("")).await.unwrap()).await;
            let front_door =
                collect(broker.execute_front_door(case.request(host)).await.unwrap()).await;
            assert_eq!(loopback.0, StatusCode::OK, "{}/{}", case.slot, case.route);
            assert_eq!(
                front_door, loopback,
                "{}/{} via {host}",
                case.slot, case.route
            );
            let outbound = recorded.outbound();
            assert_eq!(outbound.len(), 2);
            assert_eq!(
                outbound[1], outbound[0],
                "{}/{} via {host}",
                case.slot, case.route
            );
            assert_eq!(recorded.leases(), 2);

            let validated =
                ValidatedGuestRequest::parse(BridgeEntry::FrontDoor, case.request(host), false)
                    .unwrap();
            assert_eq!(
                validated.intercepted_host.map(RouteHost::as_str),
                Some(*host)
            );
            let validated =
                ValidatedGuestRequest::parse(BridgeEntry::Loopback, case.request(""), false)
                    .unwrap();
            assert_eq!(validated.intercepted_host, None);
        }
    }
}

/// A front-door request that names no host, a malformed one, or another
/// route's is refused before any lease.
#[tokio::test]
async fn a_front_door_request_without_a_host_of_its_route_is_refused_before_any_lease() {
    for case in cases() {
        let recorded = Recorded::default();
        let broker = recorded.broker();
        let other_routes = ROUTE_HOSTS
            .iter()
            .filter(|host| !case.hosts.contains(*host))
            .map(|host| (*host).to_owned());
        for host in malformed(case.hosts[0]).into_iter().chain(other_routes) {
            assert!(
                matches!(
                    broker.execute_front_door(case.request(&host)).await,
                    Err(BrokerRequestError::InvalidRequest)
                ),
                "{}/{} via {host:?}",
                case.slot,
                case.route
            );
        }
        assert_eq!(recorded.leases(), 0);
        assert!(recorded.outbound().is_empty());
    }
}

struct Session {
    input: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    output: mpsc::Sender<Payload>,
}

#[derive(Clone)]
struct Output(mpsc::Sender<Payload>);

#[async_trait]
impl CredentialBridgeTransport for Session {
    type ResponseSink = Output;

    fn response_sink(&self) -> Output {
        Output(self.output.clone())
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        Ok(self.input.recv().await)
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for Output {
    async fn send(&self, payload: Payload) -> Result<(), BrokerBridgeError> {
        self.0
            .send(payload)
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

/// Everything a front-door peer sends: a Ready that is the bytes of an Open
/// listing every front-door capability (a Ready cannot carry one, so they
/// decode away), then a request naming the host it was intercepted for.
fn front_door_frames(environment_id: Uuid) -> [v1::CredentialBridgeGuestMessage; 2] {
    let open = v1::CredentialBridgeOpen {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: environment_id.to_string(),
        environment_generation: GENERATION,
        capabilities: CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
    };
    let ready = v1::CredentialBridgeReady::decode(open.encode_to_vec().as_slice()).unwrap();
    let request = cases()[0].request("chatgpt.com");
    [
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(ready)),
        },
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                request,
            )),
        },
    ]
}

/// Admit a session carrying `front_door_frames`, run it on the runner for
/// `entry`, and return the frames sent back for its request and how the
/// runner ended once the peer disconnected.
async fn serve_on(
    entry: BridgeEntry,
    recorded: &Recorded,
) -> (Vec<Payload>, Result<(), BrokerBridgeError>) {
    let environment_id = Uuid::new_v4();
    let (input_tx, input) = mpsc::channel(2);
    let (output, mut output_rx) = mpsc::channel(8);
    for frame in front_door_frames(environment_id) {
        input_tx.send(frame).await.unwrap();
    }
    let admitted = admit_credential_bridge(Session { input, output }, environment_id, GENERATION)
        .await
        .unwrap();
    let broker = recorded.broker();
    let runner = tokio::spawn(async move {
        match entry {
            BridgeEntry::Loopback => run_admitted_credential_bridge(broker, admitted).await,
            BridgeEntry::FrontDoor => run_admitted_front_door_bridge(broker, admitted).await,
        }
    });
    let mut frames = Vec::new();
    loop {
        let frame = output_rx.recv().await.unwrap();
        let terminal = matches!(frame, Payload::ResponseEnd(_) | Payload::ResponseFailure(_));
        frames.push(frame);
        if terminal {
            break;
        }
    }
    drop(input_tx);
    (frames, runner.await.unwrap())
}

/// Whether a session is a front door's is the runner's choice, never its
/// peer's: a loopback session whose peer sends everything a front-door peer
/// would is still loopback, and its request naming an intercepted host is
/// refused before any lease, on the engine and through the runner.
#[tokio::test]
async fn a_loopback_session_whose_peer_sends_what_a_front_door_sends_stays_loopback() {
    let recorded = Recorded::default();
    let broker = recorded.broker();
    for case in cases() {
        for host in case.hosts {
            assert!(matches!(
                broker.execute(case.request(host)).await,
                Err(BrokerRequestError::InvalidRequest)
            ));
        }
    }

    let (frames, ended) = serve_on(BridgeEntry::Loopback, &recorded).await;
    let [Payload::ResponseFailure(failure)] = frames.as_slice() else {
        panic!("expected only a failure, got {frames:?}");
    };
    assert_eq!(
        failure.reason,
        v1::CredentialBridgeFailureReason::Denied as i32
    );
    assert_eq!(ended, Err(BrokerBridgeError::Unavailable));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// The same frames on the runner the front door's host calls are served:
/// one lease, one provider request, and a whole response.
#[tokio::test]
async fn the_front_door_runner_serves_the_frames_a_loopback_session_refuses() {
    let recorded = Recorded::default();
    let (frames, ended) = serve_on(BridgeEntry::FrontDoor, &recorded).await;
    let Some(Payload::ResponseStart(start)) = frames.first() else {
        panic!("expected a response, got {frames:?}");
    };
    assert_eq!(start.status_code, 200);
    assert!(matches!(frames.last(), Some(Payload::ResponseEnd(_))));
    assert_eq!(ended, Err(BrokerBridgeError::Unavailable));
    assert_eq!(recorded.leases(), 1);
    let outbound = recorded.outbound();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].1, "https://api.openai.com/v1/responses");
}

/// A front-door session serves HTTP requests only: its executor keeps the
/// denial for SSH, both projections and both logins, and none takes a lease.
#[tokio::test]
async fn a_front_door_session_denies_every_operation_but_an_http_request() {
    let recorded = Recorded::default();
    let executor = FrontDoorExecutor(recorded.broker());
    assert!(matches!(
        executor
            .execute_ssh(
                v1::CredentialSshRequest::default(),
                CancellationToken::new()
            )
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert!(matches!(
        executor
            .project_environment(v1::EnvironmentProjectionRequest::default())
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert!(matches!(
        executor
            .project_environment_fragment(v1::EnvironmentProjectionRequest::default())
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert!(matches!(
        executor.codex_login(v1::CodexLoginRequest::default()).await,
        Err(BrokerRequestError::Denied)
    ));
    assert!(matches!(
        executor
            .claude_login(v1::ClaudeLoginRequest::default())
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}
