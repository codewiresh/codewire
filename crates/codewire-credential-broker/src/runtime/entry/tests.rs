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

use base64::Engine as _;

use super::*;
use crate::bridge::AdmittedCredentialBridge;
use crate::bridge::{BrokerRequestExecutor as _, FrontDoorExecutor};
use crate::http_test_support::Lease;
use crate::{
    BrokerBridgeError, BrokerCredentialRefreshRequest, BrokerLeaseError, BrokerRefreshAdmission,
    BrokerRefreshError, BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
    CanonicalCodexOAuthBundle, CredentialBridgeResponseSink, CredentialBridgeTransport,
    FrontDoorTransport, admit_credential_bridge, run_admitted_credential_bridge,
    run_admitted_credential_bridge_with_front_doors, run_admitted_credential_bridges,
    run_admitted_front_door_bridge,
};
use codewire_credential_bridge::{
    CredentialBridge, FrontDoorSessionError, serve_front_door_session,
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
    /// The placeholder every lease carries.
    placeholder: Option<&'static str>,
    /// The upstream echoes the credential it received in a reply header and
    /// the body.
    echo_credential: bool,
    /// The authority refuses every lease.
    deny: bool,
}

impl Recorded {
    fn broker(&self) -> OpenAiBroker<Authority, Upstream> {
        OpenAiBroker::new(
            Authority {
                leases: Arc::clone(&self.leases),
                placeholder: self.placeholder,
                deny: self.deny,
            },
            Upstream {
                outbound: Arc::clone(&self.outbound),
                echo_credential: self.echo_credential,
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
    placeholder: Option<&'static str>,
    deny: bool,
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
        if self.deny {
            return Err(BrokerLeaseError::Denied);
        }
        let (provider, kind) = match slot.as_str() {
            "codex" | "openai" => ("openai", CredentialAuthKind::ApiKey),
            "anthropic" => ("anthropic", CredentialAuthKind::ApiKey),
            "github" => ("github", CredentialAuthKind::OAuth),
            _ => return Err(BrokerLeaseError::Denied),
        };
        let mut lease = Lease::new(
            provider,
            kind,
            slot.as_str(),
            operation.as_str(),
            route.as_str(),
        );
        lease.placeholder = self
            .placeholder
            .map(|value| codewire_access::CredentialPlaceholder::parse(value).unwrap());
        Ok(lease)
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
    echo_credential: bool,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        let echoed = headers
            .get("x-api-key")
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
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
        let mut reply_headers =
            HeaderMap::from_iter([(http::header::CONTENT_TYPE, HeaderValue::from_static(media))]);
        let reply_body = if self.echo_credential {
            reply_headers.insert("x-echo", HeaderValue::from_bytes(&echoed).unwrap());
            let mut body = b"{\"echo\":\"".to_vec();
            body.extend_from_slice(&echoed);
            body.extend_from_slice(b"\"}");
            Bytes::from(body)
        } else {
            Bytes::from_static(b"{}")
        };
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            reply_headers,
            Box::pin(futures::stream::iter([Ok(reply_body)])),
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

/// A front-door request naming one of its route's hosts is validated with
/// that host. Only the Anthropic route has the swap rule yet: a front-door
/// request on any other route is refused before a lease, never served by
/// always injecting; an Anthropic one with no credential is forwarded as the
/// environment sent it, without a lease.
#[tokio::test]
async fn a_front_door_request_is_served_only_on_a_route_with_the_swap_rule() {
    for case in cases() {
        for host in case.hosts {
            let recorded = Recorded::default();
            let broker = recorded.broker();
            let front_door = broker.execute_front_door(case.request(host)).await;
            if case.slot == "anthropic" {
                let (status, _, body) = collect(front_door.unwrap()).await;
                assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"{}"[..]));
                assert_eq!(recorded.leases(), 0);
                let outbound = recorded.outbound();
                assert_eq!(outbound.len(), 1);
                assert!(
                    outbound[0]
                        .2
                        .iter()
                        .all(|(name, _)| name != "authorization" && name != "x-api-key"),
                    "nothing is injected into a forwarded request"
                );
            } else {
                assert!(
                    matches!(front_door, Err(BrokerRequestError::InvalidRequest)),
                    "{}/{} via {host}",
                    case.slot,
                    case.route
                );
                assert_eq!(recorded.leases(), 0);
                assert!(recorded.outbound().is_empty());
            }

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

const OURS: &str = "cwp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// Another environment's placeholder: the right shape, not this lease's.
const THEIRS: &str = "cwp1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

fn anthropic(intercepted_host: &str, credential: &[(&str, String)]) -> v1::CredentialBridgeRequest {
    let mut request = cases()[2].request(intercepted_host);
    assert_eq!(request.capability_slot, "anthropic");
    request.headers.extend(
        credential
            .iter()
            .map(|(name, value)| v1::CredentialHttpHeader {
                name: (*name).into(),
                value: value.as_bytes().to_vec(),
            }),
    );
    request
}

fn header<'a>(outbound: &'a Outbound, name: &str) -> Vec<&'a [u8]> {
    outbound
        .2
        .iter()
        .filter(|(header, _)| header == name)
        .map(|(_, value)| value.as_slice())
        .collect()
}

/// This environment's placeholder, in either header the rule swaps, is
/// swapped: one lease, and the provider receives exactly what a loopback
/// request without a credential sends, the leased key and never the
/// placeholder.
#[tokio::test]
async fn this_environments_placeholder_is_swapped_for_the_leased_credential() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let broker = recorded.broker();
    collect(broker.execute(anthropic("", &[])).await.unwrap()).await;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("user:{OURS}"));
    for credential in [
        ("authorization", format!("Bearer {OURS}")),
        ("authorization", format!("Token {OURS}")),
        ("authorization", format!("Basic {basic}")),
        ("x-api-key", OURS.to_owned()),
    ] {
        let (status, _, _) = collect(
            broker
                .execute_front_door(anthropic(
                    "api.anthropic.com",
                    std::slice::from_ref(&credential),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let outbound = recorded.outbound();
        let (loopback, swapped) = (&outbound[0], outbound.last().unwrap());
        assert_eq!(swapped, loopback, "{credential:?}");
        assert!(
            swapped.2.iter().all(|(_, value)| !value
                .windows(OURS.len())
                .any(|window| window == OURS.as_bytes())),
            "the placeholder never leaves"
        );
        assert_eq!(
            header(swapped, "x-api-key"),
            [crate::http_test_support::TOKEN]
        );
    }
    assert_eq!(recorded.leases(), 5);
}

/// This environment's placeholder with a lease the authority denies sends
/// nothing upstream and never forwards the placeholder.
#[tokio::test]
async fn a_denied_lease_sends_nothing_upstream() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        deny: true,
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let served = broker
        .execute_front_door(anthropic(
            "api.anthropic.com",
            &[("x-api-key", OURS.to_owned())],
        ))
        .await;
    if let Ok(response) = served {
        let (status, _, _) = collect(response).await;
        assert_ne!(status, StatusCode::OK);
    }
    assert_eq!(recorded.leases(), 1);
    assert!(recorded.outbound().is_empty());
}

/// A user's own key takes no lease and reaches the provider as it was sent;
/// another environment's placeholder takes the lease, doesn't match it, and
/// is forwarded the same way. Neither reply is redacted.
#[tokio::test]
async fn anything_but_this_environments_placeholder_is_forwarded_untouched() {
    for (credential, leases) in [
        (("x-api-key", "sk-ant-users-own-key".to_owned()), 0),
        (
            ("authorization", "Bearer sk-ant-users-own-key".to_owned()),
            0,
        ),
        (("authorization", format!("Bearer {THEIRS}")), 1),
    ] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            ..Recorded::default()
        };
        let broker = recorded.broker();
        let (status, _, body) = collect(
            broker
                .execute_front_door(anthropic(
                    "api.anthropic.com",
                    std::slice::from_ref(&credential),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"{}"[..]));
        assert_eq!(recorded.leases(), leases, "{credential:?}");
        let outbound = recorded.outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(
            header(&outbound[0], credential.0),
            [credential.1.as_bytes()]
        );
        assert_eq!(
            header(&outbound[0], "anthropic-version"),
            [&b"2023-06-01"[..]]
        );
        let other = if credential.0 == "x-api-key" {
            "authorization"
        } else {
            "x-api-key"
        };
        assert!(header(&outbound[0], other).is_empty(), "{credential:?}");
    }
}

/// A placeholder beside another credential header is refused before any
/// lease with its own answer, telling the client to send one, and nothing is
/// sent.
#[tokio::test]
async fn a_placeholder_beside_another_credential_is_refused() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let (status, _, body) = collect(
        broker
            .execute_front_door(anthropic(
                "api.anthropic.com",
                &[
                    ("x-api-key", OURS.to_owned()),
                    ("authorization", "Bearer sk-ant-users-own-key".to_owned()),
                ],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["error"]["code"],
        super::super::swap::CREDENTIAL_CONFLICT_CODE
    );
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// A lease that names no placeholder, as every hosted lease does today, swaps
/// nothing: a placeholder-shaped value is forwarded as sent, after one lease,
/// and the leased key never leaves.
#[tokio::test]
async fn a_lease_without_a_placeholder_swaps_nothing() {
    let recorded = Recorded::default();
    let broker = recorded.broker();
    let credential = ("authorization", format!("Bearer {OURS}"));
    let (status, _, _) = collect(
        broker
            .execute_front_door(anthropic(
                "api.anthropic.com",
                std::slice::from_ref(&credential),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recorded.leases(), 1);
    let outbound = recorded.outbound();
    assert_eq!(outbound.len(), 1);
    assert_eq!(
        header(&outbound[0], "authorization"),
        [credential.1.as_bytes()]
    );
    assert!(header(&outbound[0], "x-api-key").is_empty());
    assert!(outbound[0].2.iter().all(|(_, value)| {
        !value
            .windows(crate::http_test_support::TOKEN.len())
            .any(|window| window == crate::http_test_support::TOKEN)
    }));
}

/// A placeholder that is not this environment's costs one lease, not one per
/// request: while the lease's placeholder is fresh, a mismatch is forwarded
/// without another. This environment's placeholder still takes a lease each
/// time, since only a lease carries the key.
#[tokio::test]
async fn a_foreign_placeholder_costs_one_lease_while_ours_is_fresh() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let broker = recorded.broker();
    for _ in 0..3 {
        collect(
            broker
                .execute_front_door(anthropic(
                    "api.anthropic.com",
                    &[("authorization", format!("Bearer {THEIRS}"))],
                ))
                .await
                .unwrap(),
        )
        .await;
    }
    assert_eq!(recorded.leases(), 1);
    collect(
        broker
            .execute_front_door(anthropic(
                "api.anthropic.com",
                &[("x-api-key", OURS.to_owned())],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(recorded.leases(), 2);
    let outbound = recorded.outbound();
    assert_eq!(
        header(outbound.last().unwrap(), "x-api-key"),
        [crate::http_test_support::TOKEN]
    );
}

/// A swapped request's reply is redacted on the front door as on the loopback
/// path: an upstream that echoes the leased key in a header and the body
/// returns neither.
#[tokio::test]
async fn a_swapped_reply_that_echoes_the_key_is_redacted() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        echo_credential: true,
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let (status, headers, body) = collect(
        broker
            .execute_front_door(anthropic(
                "api.anthropic.com",
                &[("x-api-key", OURS.to_owned())],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = crate::http_test_support::TOKEN;
    let echoed = headers.get("x-echo").unwrap().as_bytes();
    assert!(!echoed.windows(token.len()).any(|window| window == token));
    assert!(!body.windows(token.len()).any(|window| window == token));
    assert!(!body.is_empty());
}

/// A forwarded request carries the user's own key through the broker; no log
/// line, at any level, names it.
#[tokio::test]
async fn a_forwarded_credential_is_never_logged() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let users_key = "sk-ant-users-own-key-never-logged";
    let recorded = Recorded {
        placeholder: Some(OURS),
        echo_credential: true,
        ..Recorded::default()
    };
    let broker = recorded.broker();
    for credential in [
        ("x-api-key", users_key.to_owned()),
        ("authorization", format!("Bearer {users_key}")),
    ] {
        collect(
            broker
                .execute_front_door(anthropic(
                    "api.anthropic.com",
                    std::slice::from_ref(&credential),
                ))
                .await
                .unwrap(),
        )
        .await;
    }
    assert_eq!(recorded.outbound().len(), 2);
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains(users_key), "{text}");
}

/// The loopback path is unchanged by the rule: whatever credential the
/// environment sends, a placeholder or its own key, is dropped and the leased
/// one injected, and the provider receives the same bytes as for a request
/// that sent none.
#[tokio::test]
async fn a_loopback_request_always_has_its_credential_replaced() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let broker = recorded.broker();
    for credential in [
        vec![],
        vec![("x-api-key", OURS.to_owned())],
        vec![("authorization", format!("Bearer {THEIRS}"))],
        vec![("x-api-key", "sk-ant-users-own-key".to_owned())],
        vec![
            ("x-api-key", OURS.to_owned()),
            ("authorization", "Bearer sk-ant-users-own-key".to_owned()),
        ],
    ] {
        collect(broker.execute(anthropic("", &credential)).await.unwrap()).await;
    }
    let outbound = recorded.outbound();
    assert_eq!(outbound.len(), 5);
    assert!(outbound.iter().all(|request| request == &outbound[0]));
    assert_eq!(
        header(&outbound[0], "x-api-key"),
        [crate::http_test_support::TOKEN]
    );
    assert_eq!(recorded.leases(), 5);
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
    let request = anthropic("api.anthropic.com", &[("x-api-key", OURS.to_owned())]);
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
            BridgeEntry::FrontDoor => {
                run_admitted_front_door_bridge(Arc::new(broker), admitted).await
            }
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
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
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
    assert_eq!(outbound[0].1, "https://api.anthropic.com/v1/messages");
}

/// A front-door session serves HTTP requests only: its executor keeps the
/// denial for SSH, both projections and both logins, and none takes a lease.
#[tokio::test]
async fn a_front_door_session_denies_every_operation_but_an_http_request() {
    let recorded = Recorded::default();
    let executor = FrontDoorExecutor(Arc::new(recorded.broker()));
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

/// A loopback session the test drives by hand, admitted with its Ready.
async fn loopback_session(
    environment_id: Uuid,
) -> (
    AdmittedCredentialBridge<Session>,
    mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    mpsc::Receiver<Payload>,
) {
    let (input_tx, input) = mpsc::channel(4);
    let (output, output_rx) = mpsc::channel(8);
    input_tx
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: environment_id.to_string(),
                    environment_generation: GENERATION,
                },
            )),
        })
        .await
        .unwrap();
    let admitted = admit_credential_bridge(Session { input, output }, environment_id, GENERATION)
        .await
        .unwrap();
    (admitted, input_tx, output_rx)
}

/// One environment's two sessions on one broker: the loopback one driven by
/// hand, and a front door's guest side serving on a real Unix socket pair.
struct TwoSessions {
    guest: CredentialBridge,
    guest_task: tokio::task::JoinHandle<Result<(), FrontDoorSessionError>>,
    loopback_input: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    loopback_output: mpsc::Receiver<Payload>,
    runner: tokio::task::JoinHandle<Result<(), BrokerBridgeError>>,
}

impl TwoSessions {
    async fn start(recorded: &Recorded) -> Self {
        let environment_id = Uuid::new_v4();
        let (front_door_end, broker_end) = tokio::net::UnixStream::pair().unwrap();
        let guest = CredentialBridge::new(environment_id, GENERATION).unwrap();
        let serving = guest.clone();
        let guest_task =
            tokio::spawn(async move { serve_front_door_session(&serving, front_door_end).await });
        let front_door = FrontDoorTransport::open(broker_end, environment_id, GENERATION)
            .await
            .unwrap();
        let front_door = admit_credential_bridge(front_door, environment_id, GENERATION)
            .await
            .unwrap();
        let (loopback, loopback_input, loopback_output) = loopback_session(environment_id).await;
        let broker = recorded.broker();
        let runner = tokio::spawn(async move {
            run_admitted_credential_bridges(broker, loopback, front_door).await
        });
        Self {
            guest,
            guest_task,
            loopback_input,
            loopback_output,
            runner,
        }
    }

    async fn loopback_request(&mut self) -> Vec<Payload> {
        self.loopback_input
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                    cases()[1].request(""),
                )),
            })
            .await
            .unwrap();
        let mut frames = Vec::new();
        loop {
            let frame = self.loopback_output.recv().await.unwrap();
            let terminal = matches!(frame, Payload::ResponseEnd(_) | Payload::ResponseFailure(_));
            frames.push(frame);
            if terminal {
                return frames;
            }
        }
    }
}

/// An Anthropic request as the front door hands it to the bridge, carrying
/// this environment's placeholder.
fn intercepted_anthropic_request() -> http::Request<axum::body::Body> {
    http::Request::post(format!(
        "{}/v1/messages",
        codewire_access::MANAGED_ANTHROPIC_API_PREFIX
    ))
    .header("content-type", "application/json")
    .header("anthropic-version", "2023-06-01")
    .header("x-api-key", OURS)
    .body(axum::body::Body::from("{}"))
    .unwrap()
}

/// A request the front door makes for its bound host crosses the session
/// socket as bytes and is served on the front-door entry beside the loopback
/// session on one broker: its placeholder is swapped for the leased key,
/// which only the provider sees, and its answer returns.
#[tokio::test]
async fn a_front_door_request_crosses_its_socket_and_is_served_beside_the_loopback_session() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let mut sessions = TwoSessions::start(&recorded).await;

    let response = sessions
        .guest
        .respond_intercepted("api.anthropic.com", intercepted_anthropic_request())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(recorded.leases(), 1);
    let outbound = recorded.outbound();
    assert_eq!(
        header(&outbound[0], "x-api-key"),
        [crate::http_test_support::TOKEN]
    );
    assert!(
        outbound[0].2.iter().all(|(_, value)| !value
            .windows(OURS.len())
            .any(|window| window == OURS.as_bytes())),
        "the placeholder never leaves"
    );

    let frames = sessions.loopback_request().await;
    assert!(
        matches!(frames.first(), Some(Payload::ResponseStart(start)) if start.status_code == 200),
        "{frames:?}"
    );
    assert_eq!(recorded.leases(), 2);
    assert_eq!(recorded.outbound().len(), 2);
}

/// The front-door entry still checks the host: one its slot's route never
/// sends to is refused before any lease.
#[tokio::test]
async fn a_front_door_request_for_a_host_its_route_never_reaches_takes_no_lease() {
    let recorded = Recorded::default();
    let sessions = TwoSessions::start(&recorded).await;
    let response = sessions
        .guest
        .respond_intercepted("api.openai.com", intercepted_anthropic_request())
        .await;
    assert_ne!(response.status(), StatusCode::OK);
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// When the loopback session ends, the broker ends with the loopback
/// session's own result: the front door's session is closed with it, and its
/// guest side sees the end.
#[tokio::test]
async fn the_loopback_session_ending_ends_the_front_door_session() {
    let recorded = Recorded::default();
    let sessions = TwoSessions::start(&recorded).await;
    drop(sessions.loopback_input);
    assert_eq!(
        sessions.runner.await.unwrap(),
        Err(BrokerBridgeError::Unavailable)
    );
    assert_eq!(sessions.guest_task.await.unwrap(), Ok(()));
}

/// A front door that dies fails closed on its own; the environment's
/// loopback session keeps being served.
#[tokio::test]
async fn a_front_door_that_dies_leaves_the_loopback_session_serving() {
    let recorded = Recorded::default();
    let mut sessions = TwoSessions::start(&recorded).await;
    sessions.guest_task.abort();
    assert!((&mut sessions.guest_task).await.unwrap_err().is_cancelled());

    let frames = sessions.loopback_request().await;
    assert!(
        matches!(frames.first(), Some(Payload::ResponseStart(start)) if start.status_code == 200),
        "{frames:?}"
    );
    assert!(!sessions.runner.is_finished());
}

/// A front door's guest side serving on a real socket pair, and the broker's
/// admitted end of it.
async fn front_door_pair(
    environment_id: Uuid,
) -> (
    CredentialBridge,
    tokio::task::JoinHandle<Result<(), FrontDoorSessionError>>,
    AdmittedCredentialBridge<FrontDoorTransport>,
) {
    let (front_door_end, broker_end) = tokio::net::UnixStream::pair().unwrap();
    let guest = CredentialBridge::new(environment_id, GENERATION).unwrap();
    let serving = guest.clone();
    let guest_task =
        tokio::spawn(async move { serve_front_door_session(&serving, front_door_end).await });
    let front_door = FrontDoorTransport::open(broker_end, environment_id, GENERATION)
        .await
        .unwrap();
    let front_door = admit_credential_bridge(front_door, environment_id, GENERATION)
        .await
        .unwrap();
    (guest, guest_task, front_door)
}

/// A front-door session that joins later (a hosted relay epoch, #4001) is
/// served beside the running loopback session; when it ends, the next one to
/// join is served on the same broker.
#[tokio::test]
async fn a_front_door_that_ends_is_replaced_by_the_next_one_to_join() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let environment_id = Uuid::new_v4();
    let (loopback, _loopback_input, _loopback_output) = loopback_session(environment_id).await;
    let (joins, joining) = mpsc::channel(1);
    let broker = recorded.broker();
    let runner = tokio::spawn(async move {
        run_admitted_credential_bridge_with_front_doors(broker, loopback, joining).await
    });

    let (first, first_task, first_session) = front_door_pair(environment_id).await;
    joins.send(first_session).await.unwrap();
    let response = first
        .respond_intercepted("api.anthropic.com", intercepted_anthropic_request())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    first_task.abort();

    let (second, _second_task, second_session) = front_door_pair(environment_id).await;
    joins.send(second_session).await.unwrap();
    let response = second
        .respond_intercepted("api.anthropic.com", intercepted_anthropic_request())
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the next session joins the same broker"
    );
    assert_eq!(recorded.leases(), 2);
    assert!(!runner.is_finished(), "loopback keeps serving throughout");
}

/// Once the loopback session ends, the serving front-door session is ended
/// with it and no other can join.
#[tokio::test]
async fn once_the_loopback_session_ends_no_front_door_joins() {
    let recorded = Recorded::default();
    let environment_id = Uuid::new_v4();
    let (loopback, loopback_input, _loopback_output) = loopback_session(environment_id).await;
    let (joins, joining) = mpsc::channel(1);
    let broker = recorded.broker();
    let runner = tokio::spawn(async move {
        run_admitted_credential_bridge_with_front_doors(broker, loopback, joining).await
    });
    let (_first, first_task, first_session) = front_door_pair(environment_id).await;
    joins.send(first_session).await.unwrap();

    drop(loopback_input);
    assert_eq!(runner.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(
        first_task.await.unwrap(),
        Ok(()),
        "the serving session ends with loopback"
    );
    let (_late, _late_task, late_session) = front_door_pair(environment_id).await;
    assert!(
        joins.send(late_session).await.is_err(),
        "nothing joins an ended loopback session"
    );
}
