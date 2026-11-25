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

use super::super::routed::Carried;
use super::*;
use crate::CommitFailure;
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

mod idle;

/// Every host some route sends to.
const ROUTE_HOSTS: [&str; 6] = [
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "platform.claude.com",
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
            destination_ip: String::new(),
            streamed_body: false,
            intercept_decision: Vec::new(),
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
    /// Every lease was due a placeholder whose key could not be read.
    placeholder_failed: bool,
    /// The upstream echoes the credential it received in a reply header and
    /// the body.
    echo_credential: bool,
    /// The authority refuses every lease.
    deny: bool,
    /// The codex slot holds a ChatGPT sign-in instead of an API key.
    codex_sign_in: bool,
    /// The one slot the authority refuses.
    denied: Option<&'static str>,
    /// Holds every upstream request until notified.
    hold: Option<Arc<tokio::sync::Notify>>,
    /// The environment whose Codex login the authority delivers, if any.
    codex_login_environment: Option<Uuid>,
    /// The environment whose Claude sign-in login the authority delivers, if
    /// any.
    claude_login_environment: Option<Uuid>,
    /// Counts the leases asked for a sealed agent login.
    login_leases: Arc<AtomicUsize>,
    /// The provider's ends of the sockets its WebSocket handshakes opened.
    sockets: Arc<Mutex<Vec<tokio::io::DuplexStream>>>,
    /// Handshakes the provider answers 401 before it switches one.
    unauthorized_upgrades: Arc<AtomicUsize>,
    /// Counts refresh attempts and refuses each, instead of failing the test.
    refreshes: Option<Arc<AtomicUsize>>,
    /// What the next leases do, in order; then every lease is ordinary.
    plan: Arc<Mutex<std::collections::VecDeque<LeasePlan>>>,
    /// How many of `outbound` went by the transport's forward path, which
    /// holds no request to its route's grammar.
    forwarded: Arc<AtomicUsize>,
    /// A slot whose provider the transport has no address for (#5286).
    unserved_slot: Option<&'static str>,
    /// How many times the transport first answers that the slot is served.
    /// A real transport's answer never changes; a test sets this only to
    /// reach a check that stands behind an earlier one.
    served_asks: Arc<AtomicUsize>,
    /// The workspace origin the upstream's `accounts/check` reply names for
    /// the sign-in's account.
    routing: Option<&'static str>,
    /// Each outbound request's pinned address, in order.
    pinned: Arc<Mutex<Vec<Option<std::net::SocketAddr>>>>,
    /// The credential every lease names, when a test changes it.
    credential: Arc<Mutex<Option<&'static str>>>,
}

/// One planned lease.
#[derive(Clone, Copy)]
enum LeasePlan {
    Ordinary,
    Denied,
    /// The slot now holds a different credential.
    OtherCredential,
    /// The same credential, revoked and reissued since.
    NewRevocation,
    /// The same credential, refreshed since.
    NewerSignIn,
    /// The sign-in, last refreshed just now (#4974).
    RefreshedJustNow,
}

/// Every host a route table may bind, and every name under the routed
/// suffix: what a policy allowing them all gives a broker at launch, so an
/// untouched forward is sent (#5555).
pub(super) const EVERY_BOUND_HOST: [&str; 7] = [
    "*.chatgpt.com",
    "api.anthropic.com",
    "platform.claude.com",
    "api.openai.com",
    "chatgpt.com",
    "github.com",
    "api.github.com",
];

impl Recorded {
    /// A broker whose environment's policy allows every bound host by rule.
    fn broker(&self) -> OpenAiBroker<Authority, Upstream> {
        self.broker_without_answer()
            .with_network_policy_allowing_hosts(EVERY_BOUND_HOST)
    }

    /// A broker started without the policy's answer for any host.
    fn broker_without_answer(&self) -> OpenAiBroker<Authority, Upstream> {
        OpenAiBroker::new(
            Authority {
                leases: Arc::clone(&self.leases),
                placeholder: self.placeholder,
                placeholder_failed: self.placeholder_failed,
                deny: self.deny,
                codex_sign_in: self.codex_sign_in,
                denied: self.denied,
                refreshes: self.refreshes.clone(),
                plan: Arc::clone(&self.plan),
                codex_login_environment: self.codex_login_environment,
                claude_login_environment: self.claude_login_environment,
                login_leases: Arc::clone(&self.login_leases),
                credential: Arc::clone(&self.credential),
            },
            Upstream {
                outbound: Arc::clone(&self.outbound),
                echo_credential: self.echo_credential,
                hold: self.hold.clone(),
                sockets: Arc::clone(&self.sockets),
                unauthorized_upgrades: Arc::clone(&self.unauthorized_upgrades),
                forwarded: Arc::clone(&self.forwarded),
                unserved_slot: self.unserved_slot,
                served_asks: Arc::clone(&self.served_asks),
                routing: self.routing,
                pinned: Arc::clone(&self.pinned),
            },
        )
        .unwrap()
    }

    fn forwarded(&self) -> usize {
        self.forwarded.load(Ordering::Relaxed)
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
    placeholder_failed: bool,
    deny: bool,
    codex_sign_in: bool,
    denied: Option<&'static str>,
    refreshes: Option<Arc<AtomicUsize>>,
    plan: Arc<Mutex<std::collections::VecDeque<LeasePlan>>>,
    codex_login_environment: Option<Uuid>,
    claude_login_environment: Option<Uuid>,
    login_leases: Arc<AtomicUsize>,
    credential: Arc<Mutex<Option<&'static str>>>,
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
        let planned = self
            .plan
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(LeasePlan::Ordinary);
        if self.deny || self.denied == Some(slot.as_str()) || matches!(planned, LeasePlan::Denied) {
            return Err(BrokerLeaseError::Denied);
        }
        let (provider, kind) = match slot.as_str() {
            "codex" if self.codex_sign_in => ("openai", CredentialAuthKind::OAuth),
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
        lease.placeholder_failed = self.placeholder_failed;
        if kind == CredentialAuthKind::OAuth && slot.as_str() == "codex" {
            lease.material = codex_sign_in();
        }
        if let Some(credential) = *self.credential.lock().unwrap() {
            let credential = codewire_access::CredentialId::parse(credential).unwrap();
            lease.metadata.id = credential.clone();
            lease.grant.credential_id = credential;
        }
        match planned {
            LeasePlan::OtherCredential => {
                lease.metadata.id =
                    codewire_access::CredentialId::parse("33333333-3333-4333-8333-333333333333")
                        .unwrap();
            }
            LeasePlan::NewRevocation => lease.metadata.revocation_generation += 1,
            LeasePlan::NewerSignIn => lease.material_generation += 1,
            LeasePlan::RefreshedJustNow => lease.material = codex_sign_in_refreshed_ago(0),
            LeasePlan::Ordinary | LeasePlan::Denied => {}
        }
        Ok(lease)
    }

    /// The codex slot's sign-in for `codex_login_environment`, when set.
    async fn lease_codex_login(&self, _id: Uuid) -> Result<Lease, BrokerLeaseError> {
        self.login_leases.fetch_add(1, Ordering::Relaxed);
        let Some(environment_id) = self.codex_login_environment.filter(|_| self.codex_sign_in)
        else {
            return Err(BrokerLeaseError::Denied);
        };
        let permission = codewire_access::codex_login_permission();
        let mut lease = Lease::new(
            "openai",
            CredentialAuthKind::OAuth,
            "codex",
            permission.operation.as_str(),
            permission.route.as_str(),
        );
        lease.grant.environment_id =
            codewire_access::EnvironmentId::parse(environment_id.to_string()).unwrap();
        lease.material = codex_sign_in();
        lease.placeholder = self
            .placeholder
            .map(|value| codewire_access::CredentialPlaceholder::parse(value).unwrap());
        Ok(lease)
    }

    /// The anthropic slot's Claude sign-in for `claude_login_environment`,
    /// when set.
    async fn lease_claude_login(&self, _id: Uuid) -> Result<Lease, BrokerLeaseError> {
        self.login_leases.fetch_add(1, Ordering::Relaxed);
        let Some(environment_id) = self.claude_login_environment else {
            return Err(BrokerLeaseError::Denied);
        };
        let permission = codewire_access::claude_login_permission();
        let mut lease = Lease::new(
            "anthropic",
            CredentialAuthKind::ClaudeSignIn,
            "anthropic",
            permission.operation.as_str(),
            permission.route.as_str(),
        );
        lease.grant.environment_id =
            codewire_access::EnvironmentId::parse(environment_id.to_string()).unwrap();
        lease.material = claude_sign_in();
        lease.placeholder = self
            .placeholder
            .map(|value| codewire_access::CredentialPlaceholder::parse(value).unwrap());
        Ok(lease)
    }

    async fn begin_credential_refresh(
        &self,
        _: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        let Some(refreshes) = &self.refreshes else {
            panic!("non-refreshing identity attempted refresh")
        };
        refreshes.fetch_add(1, Ordering::Relaxed);
        Err(BrokerRefreshError::Unavailable)
    }

    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        panic!("non-refreshing identity attempted refresh")
    }

    async fn commit_credential_refresh(
        &self,
        _: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
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
    hold: Option<Arc<tokio::sync::Notify>>,
    sockets: Arc<Mutex<Vec<tokio::io::DuplexStream>>>,
    unauthorized_upgrades: Arc<AtomicUsize>,
    forwarded: Arc<AtomicUsize>,
    unserved_slot: Option<&'static str>,
    served_asks: Arc<AtomicUsize>,
    routing: Option<&'static str>,
    pinned: Arc<Mutex<Vec<Option<std::net::SocketAddr>>>>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    fn slot_unserved(&self, slot: &str) -> bool {
        self.unserved_slot == Some(slot)
            && self
                .served_asks
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_err()
    }

    async fn execute(
        &self,
        mut request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.pinned.lock().unwrap().push(request.pinned());
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        let streamed = request.take_body_stream();
        let (method, target, headers, mut body) = request.into_parts();
        // A streamed body is recorded whole, as the provider would read it.
        if let Some(mut stream) = streamed {
            while let Some(chunk) = stream.next().await {
                body.extend_from_slice(&chunk.map_err(|_| BrokerUpstreamError::Protocol)?);
            }
        }
        let routing = self
            .routing
            .filter(|_| target.path() == super::super::routed::ACCOUNTS_CHECK_PATH);
        let echoed = headers
            .get("x-api-key")
            .or_else(|| headers.get("authorization"))
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        let account = headers
            .get("chatgpt-account-id")
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
        let reply_body = if let Some(origin) = routing {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "accounts": [
                        {"id": SIGN_IN_ACCOUNT, "workspace_backend_origin": origin,
                            "account_routing_override": "us", "structure": "workspace"},
                        {"id": OTHER_ACCOUNT, "workspace_backend_origin": OTHER_ORIGIN,
                            "account_routing_override": "us", "structure": "workspace"},
                    ],
                    "account_ordering": [SIGN_IN_ACCOUNT, OTHER_ACCOUNT],
                }))
                .unwrap(),
            )
        } else if self.echo_credential {
            reply_headers.insert("x-echo", HeaderValue::from_bytes(&echoed).unwrap());
            let mut body = b"{\"echo\":\"".to_vec();
            body.extend_from_slice(&echoed);
            body.extend_from_slice(b"\",\"account\":\"");
            body.extend_from_slice(&account);
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

    /// Records and answers like [`Self::execute`], and counts the request as
    /// forwarded.
    async fn forward_github(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
        self.execute(request).await
    }

    /// Records the handshake like a request and switches it, keeping the
    /// provider's end of a pipe; with `echo_credential` its `101` names the
    /// credential it received.
    async fn upgrade(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<crate::BrokerUpstreamUpgrade, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        let received = headers
            .get("authorization")
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        self.outbound.lock().unwrap().push((
            method,
            target.to_string(),
            headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body,
        ));
        if self
            .unauthorized_upgrades
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Ok(crate::BrokerUpstreamUpgrade::Response(
                BrokerUpstreamResponse::new(
                    StatusCode::UNAUTHORIZED,
                    HeaderMap::from_iter([(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    )]),
                    Box::pin(futures::stream::iter([Ok(Bytes::from_static(b"{}"))])),
                ),
            ));
        }
        let mut reply = HeaderMap::new();
        reply.insert(
            "sec-websocket-accept",
            HeaderValue::from_static("test-accept"),
        );
        reply.insert("set-cookie", HeaderValue::from_static("provider-session=1"));
        reply.insert("connection", HeaderValue::from_static("upgrade"));
        reply.insert("upgrade", HeaderValue::from_static("websocket"));
        if self.echo_credential {
            reply.insert("x-echo", HeaderValue::from_bytes(&received).unwrap());
        }
        let (broker_end, provider_end) = tokio::io::duplex(8 * 1024);
        self.sockets.lock().unwrap().push(provider_end);
        Ok(crate::BrokerUpstreamUpgrade::Switched {
            headers: reply,
            stream: Box::new(broker_end),
        })
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
/// that host. The Anthropic route, Codex at `chatgpt.com` and GitHub's two
/// hosts have the swap rule: a front-door request on any other route is
/// refused before a lease, never served by always injecting; one with the
/// rule and no credential is forwarded as the environment sent it, without a
/// lease.
#[tokio::test]
async fn a_front_door_request_is_served_only_on_a_route_with_the_swap_rule() {
    for case in cases() {
        for host in case.hosts {
            let recorded = Recorded::default();
            let broker = recorded.broker();
            let swapped = matches!(case.slot, "anthropic" | "github")
                || (case.slot == "codex" && *host == "chatgpt.com");
            let mut request = case.request(host);
            if case.slot == "codex" && *host == "chatgpt.com" {
                // A front-door path on chatgpt.com is the whole path.
                request.path = "/backend-api/codex/responses".into();
            }
            let front_door = broker.execute_front_door(request).await;
            if swapped {
                let (status, _, body) = collect(front_door.unwrap()).await;
                assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"{}"[..]));
                assert_eq!(recorded.leases(), 0);
                assert_eq!(recorded.forwarded(), usize::from(case.slot == "github"));
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

/// A request to a provider the transport has no address for is refused as
/// an upstream failure before any lease, and nothing is sent (#5286).
/// Another slot's request is served as ever.
#[tokio::test]
async fn a_request_to_a_provider_with_no_address_takes_no_lease_and_sends_nothing() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        unserved_slot: Some("anthropic"),
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let refused = broker
        .execute_front_door(anthropic(
            "api.anthropic.com",
            &[("x-api-key", OURS.to_owned())],
        ))
        .await;
    assert!(
        matches!(refused, Err(BrokerRequestError::UpstreamFailed)),
        "{:?}",
        refused.err()
    );
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());

    let served = Recorded {
        placeholder: Some(OURS),
        unserved_slot: Some("github"),
        ..Recorded::default()
    };
    let response = served
        .broker()
        .execute_front_door(anthropic(
            "api.anthropic.com",
            &[("x-api-key", OURS.to_owned())],
        ))
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    assert_eq!(served.leases(), 1);
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
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "Codewire: this request carries the Codewire placeholder and another credential; send only one.\n"
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

/// A lease whose placeholder key could not be read refuses the request, for
/// this environment's placeholder and a foreign value alike, and is never
/// remembered: held past the cache's 60 s window, every request takes a lease
/// and is refused, and nothing is sent upstream (#4001 step C3).
#[tokio::test(start_paused = true)]
async fn a_failed_key_read_refuses_every_request_across_the_window() {
    let recorded = Recorded {
        placeholder_failed: true,
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let mut sent = 0;
    for wait in [0, 30, 31, 1] {
        tokio::time::advance(std::time::Duration::from_secs(wait)).await;
        for presented in [OURS, THEIRS] {
            let answer = broker
                .execute_front_door(anthropic(
                    "api.anthropic.com",
                    &[("authorization", format!("Bearer {presented}"))],
                ))
                .await;
            sent += 1;
            assert!(
                matches!(answer, Err(BrokerRequestError::AuthorityUnavailable)),
                "refused, never forwarded"
            );
        }
    }
    assert_eq!(recorded.leases(), sent);
    assert!(recorded.outbound().is_empty());
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
    crate::timing::tests::keep_interest_peer();
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
        placeholders: Vec::new(),
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
                run_admitted_front_door_bridge(Arc::new(broker), admitted, None).await
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

/// The Open a front-door transport writes lists what the front-door executor
/// serves: `websocket.v1` exactly when it serves upgrades (#4973).
#[tokio::test]
async fn the_front_door_open_lists_what_its_executor_serves() {
    use tokio::io::AsyncReadExt as _;

    let executor = FrontDoorExecutor::new(Arc::new(Recorded::default().broker()));
    let (mut front_door_end, broker_end) = tokio::net::UnixStream::pair().unwrap();
    let _transport = FrontDoorTransport::open(broker_end, Uuid::new_v4(), GENERATION)
        .await
        .unwrap();
    let mut prefix = [0; 4];
    front_door_end.read_exact(&mut prefix).await.unwrap();
    let mut frame = vec![0; u32::from_be_bytes(prefix) as usize];
    front_door_end.read_exact(&mut frame).await.unwrap();
    let open = v1::CredentialBridgeHostMessage::decode(frame.as_slice()).unwrap();
    let Some(Payload::Open(open)) = open.payload else {
        panic!("the first host frame is the Open");
    };
    assert_eq!(
        open.capabilities,
        codewire_credential_bridge::front_door_capabilities(executor.serves_upgrades())
    );
}

/// A front-door session serves HTTP requests only: its executor keeps the
/// denial for SSH, both projections and both logins, and none takes a lease.
#[tokio::test]
async fn a_front_door_session_denies_every_operation_but_an_http_request() {
    let recorded = Recorded::default();
    let executor = FrontDoorExecutor::new(Arc::new(recorded.broker()));
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
        Self::start_in(recorded, Uuid::new_v4()).await
    }

    async fn start_in(recorded: &Recorded, environment_id: Uuid) -> Self {
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

/// #4926: a credential route on the host never passes the environment's
/// network policy, so the policy's answer for GitHub is applied to a
/// loopback request before any lease. Before the fix every case here was
/// served.
#[tokio::test]
async fn a_loopback_github_request_follows_the_network_policy() {
    let recorded = Recorded::default();
    let refusing = recorded.broker().with_network_policy_allowing_github(false);
    for case in cases().iter().filter(|case| case.slot == "github") {
        let response = refusing.execute(case.request("")).await.unwrap();
        let (status, headers, mut body) = response.into_parts();
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", case.route);
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        let mut text = Vec::new();
        while let Some(chunk) = body.next().await {
            text.extend_from_slice(&chunk.unwrap());
        }
        let text = String::from_utf8(text).unwrap();
        for part in ["network policy", "github.com", "api.github.com"] {
            assert!(text.contains(part), "{}: {text}", case.route);
        }
    }
    assert_eq!(recorded.leases(), 0, "refused before any lease");
    assert!(recorded.outbound().is_empty(), "GitHub is never contacted");

    // The rule is about GitHub alone: the same broker serves every other slot.
    for case in cases().iter().filter(|case| case.slot != "github") {
        let (status, _, _) = refusing
            .execute(case.request(""))
            .await
            .unwrap()
            .into_parts();
        assert_eq!(status, StatusCode::OK, "{} {}", case.slot, case.route);
    }
    let others = recorded.leases();
    assert_eq!(others, 3);

    // With a rule for GitHub's hosts, and wherever no policy is in hand (the
    // constructor's default, which the hosted service uses), it is served.
    for broker in [
        recorded.broker().with_network_policy_allowing_github(true),
        recorded.broker(),
    ] {
        for case in cases().iter().filter(|case| case.slot == "github") {
            let (status, _, _) = broker.execute(case.request("")).await.unwrap().into_parts();
            assert_eq!(status, StatusCode::OK, "{}", case.route);
        }
    }
    assert_eq!(recorded.leases(), others + 4);
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
    let broker = recorded.broker().paired_with_front_door();
    let runner = tokio::spawn(async move {
        run_admitted_credential_bridge_with_front_doors(broker, loopback, joining, None).await
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
    let broker = recorded.broker().paired_with_front_door();
    let runner = tokio::spawn(async move {
        run_admitted_credential_bridge_with_front_doors(broker, loopback, joining, None).await
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

/// The runner never serves a front door beside an agent's real login,
/// however it was reached (#4001): with a Real-delivery broker it refuses
/// before serving either session.
#[tokio::test]
async fn a_front_door_is_never_served_beside_a_real_login() {
    let recorded = Recorded::default();
    let environment_id = Uuid::new_v4();
    let (loopback, _loopback_input, _loopback_output) = loopback_session(environment_id).await;
    let (joins, joining) = mpsc::channel(1);
    let (_front_door, _front_door_task, session) = front_door_pair(environment_id).await;
    joins.send(session).await.unwrap();
    assert!(matches!(
        run_admitted_credential_bridge_with_front_doors(recorded.broker(), loopback, joining, None)
            .await,
        Err(BrokerBridgeError::Unavailable)
    ));
}

// ---------------------------------------------------------------------------
// Codex at chatgpt.com (#3999 change 8)

/// The ChatGPT sign-in the codex slot holds when `codex_sign_in` is set: an
/// access token that expires in a day, so nothing refreshes.
const SIGN_IN_ACCOUNT: &str = "account-work";

fn jwt(payload: serde_json::Value) -> String {
    use base64::Engine as _;
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    format!(
        "{}.{}.synthetic-signature",
        encode(br#"{"alg":"none"}"#),
        encode(&serde_json::to_vec(&payload).unwrap())
    )
}

fn sign_in_access_token() -> String {
    let in_a_day = crate::runtime::current_unix_time().unwrap() + 24 * 60 * 60;
    jwt(serde_json::json!({ "exp": in_a_day }))
}

/// The Claude sign-in's access token, which must never leave the broker
/// beside the front door.
const CLAUDE_SIGN_IN_ACCESS_TOKEN: &str = "sk-ant-oat01-synthetic-sign-in-access";

fn claude_sign_in() -> zeroize::Zeroizing<Vec<u8>> {
    let imported = crate::claude_oauth::import_claude_tokens(
        crate::claude_oauth::ClaudeIssuedTokens {
            access_token: zeroize::Zeroizing::new(CLAUDE_SIGN_IN_ACCESS_TOKEN.to_owned()),
            refresh_token: Some(zeroize::Zeroizing::new(
                "sk-ant-ort01-synthetic-refresh".to_owned(),
            )),
            expires_in: 8 * 60 * 60,
            refresh_token_expires_in: None,
            scope: Some("user:inference user:profile".to_owned()),
        },
        crate::claude_oauth::ClaudeProfile {
            email: Some("developer@example.test".to_owned()),
            subscription_type: Some(crate::claude_oauth::ClaudeSubscriptionType::Max),
            rate_limit_tier: Some("default_claude_max_20x".to_owned()),
        },
    )
    .unwrap();
    zeroize::Zeroizing::new(imported.into_parts().0.as_bytes().to_vec())
}

/// The sign-in, last refreshed eleven minutes ago, so a 401 may force a
/// refresh of it (#4974).
fn codex_sign_in() -> zeroize::Zeroizing<Vec<u8>> {
    codex_sign_in_refreshed_ago(11 * 60)
}

fn codex_sign_in_refreshed_ago(seconds: u64) -> zeroize::Zeroizing<Vec<u8>> {
    let id_token = jwt(serde_json::json!({
        "email": "developer@example.test",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": SIGN_IN_ACCOUNT,
            "chatgpt_account_is_fedramp": false
        }
    }));
    let bundle = crate::codex_oauth::import_codex_tokens_at(
        zeroize::Zeroizing::new(id_token),
        zeroize::Zeroizing::new(sign_in_access_token()),
        zeroize::Zeroizing::new("synthetic-refresh-token".to_owned()),
        crate::runtime::current_unix_time().unwrap() - seconds,
    )
    .unwrap()
    .into_parts()
    .0;
    zeroize::Zeroizing::new(bundle.as_bytes().to_vec())
}

/// A front-door Codex request to chatgpt.com, as Codex sends it: the whole
/// path, its credential, and the account it names.
fn codex(method: &str, path: &str, credential: Option<String>) -> v1::CredentialBridgeRequest {
    let mut request = cases()[0].request("chatgpt.com");
    assert_eq!(request.capability_slot, "codex");
    request.method = method.into();
    request.path = path.into();
    request.headers.push(v1::CredentialHttpHeader {
        name: "chatgpt-account-id".into(),
        value: b"guest-named-account".to_vec(),
    });
    if let Some(credential) = credential {
        request.headers.push(v1::CredentialHttpHeader {
            name: "authorization".into(),
            value: credential.into_bytes(),
        });
    }
    request
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The paths the pinned Codex sends its credential to (#3999): with this
/// environment's placeholder, each reaches chatgpt.com at its own path with
/// the sign-in's access token and account, and the placeholder never leaves.
#[tokio::test]
async fn codex_s_placeholder_at_chatgpt_com_is_swapped_for_the_sign_in() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        ..Recorded::default()
    };
    let broker = recorded.broker();
    let paths = [
        ("POST", "/backend-api/codex/responses"),
        ("GET", "/backend-api/codex/models"),
        ("GET", "/backend-api/wham/accounts/check"),
        ("GET", "/backend-api/wham/usage"),
        ("GET", "/backend-api/plugins/featured"),
        ("POST", "/backend-api/ps/mcp"),
        ("GET", "/backend-api/accounts/verified_access"),
    ];
    for (method, path) in paths {
        let response = broker
            .execute_front_door(codex(method, path, Some(format!("Bearer {OURS}"))))
            .await
            .unwrap();
        assert_eq!(collect(response).await.0, StatusCode::OK, "{path}");
        let outbound = recorded.outbound();
        let sent = outbound.last().unwrap();
        assert_eq!(sent.1, format!("https://chatgpt.com{path}"));
        let authorization = header(sent, "authorization");
        assert_eq!(authorization.len(), 1);
        assert!(authorization[0].starts_with(b"Bearer ey"), "{path}");
        assert_eq!(
            header(sent, "chatgpt-account-id"),
            [SIGN_IN_ACCOUNT.as_bytes()]
        );
        assert!(
            sent.2.iter().all(|(_, value)| !contains(value, OURS)),
            "the placeholder never leaves: {path}"
        );
    }
    assert_eq!(recorded.leases(), paths.len());
}

/// A user's own token takes no lease and reaches chatgpt.com as Codex sent
/// it, account header and all; so does a request with no credential.
#[tokio::test]
async fn codex_without_this_environments_placeholder_is_forwarded_untouched() {
    for credential in [Some("Bearer users-own-token".to_owned()), None] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            codex_sign_in: true,
            ..Recorded::default()
        };
        let response = recorded
            .broker()
            .execute_front_door(codex("GET", "/backend-api/wham/usage", credential.clone()))
            .await
            .unwrap();
        assert_eq!(collect(response).await.0, StatusCode::OK);
        assert_eq!(recorded.leases(), 0);
        let outbound = recorded.outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].1, "https://chatgpt.com/backend-api/wham/usage");
        let sent: Vec<&[u8]> = header(&outbound[0], "authorization");
        assert_eq!(
            sent,
            credential
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            header(&outbound[0], "chatgpt-account-id"),
            [&b"guest-named-account"[..]]
        );
    }
}

/// Every other chatgpt.com path is refused before any lease, whatever it
/// carries: the front door maps the host whole, and only Codex's own paths
/// are admitted.
#[tokio::test]
async fn a_chatgpt_com_path_codex_does_not_use_is_refused_before_any_lease() {
    for path in [
        "/",
        "/backend-api/conversation",
        "/backend-api/accounts/check",
        "/backend-api/accounts/verified_access/x",
        "/backend-api/wham",
        "/backend-api/codexx/responses",
        "/backend-api/codex/../conversation",
        "/backend-api/codex/%2e%2e/conversation",
        "/backend-api/codex/%2E%2E/conversation",
        "/backend-api/codex/.%2e/conversation",
        "/backend-api/codex/%2e/responses",
        "/backend-api/wham/%2e%2e/%2e%2e/conversation",
        "/backend-api/codex/a b",
        "/backend-api/codex/..%2f..%2fconversation",
        "/backend-api/codex/..%2F..%2Fconversation",
        "/backend-api/codex/..%5cconversation",
        "/backend-api/codex/..%5C..%5Cconversation",
        "/backend-api/wham%2fusage",
        "/public-api/conversation",
        "/responses",
    ] {
        for credential in [
            Some(format!("Bearer {OURS}")),
            Some("Bearer theirs".into()),
            None,
        ] {
            let recorded = Recorded {
                placeholder: Some(OURS),
                codex_sign_in: true,
                ..Recorded::default()
            };
            let refused = recorded
                .broker()
                .execute_front_door(codex("GET", path, credential))
                .await;
            assert!(refused.is_err(), "{path}");
            assert_eq!(recorded.leases(), 0, "{path}");
            assert!(recorded.outbound().is_empty(), "{path}");
        }
    }
}

/// A codex slot holding an API key never sends it to chatgpt.com, even for
/// this environment's placeholder; nor does a placeholder beside another
/// credential reach anything.
#[tokio::test]
async fn a_key_never_goes_to_chatgpt_com_and_a_mixed_credential_is_refused() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    let refused = recorded
        .broker()
        .execute_front_door(codex(
            "POST",
            "/backend-api/codex/responses",
            Some(format!("Bearer {OURS}")),
        ))
        .await;
    assert!(matches!(refused, Err(BrokerRequestError::Denied)));
    assert!(recorded.outbound().is_empty());

    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        ..Recorded::default()
    };
    let mut mixed = codex(
        "POST",
        "/backend-api/codex/responses",
        Some(format!("Bearer {OURS}")),
    );
    mixed.headers.push(v1::CredentialHttpHeader {
        name: "cookie".into(),
        value: b"session=users-own".to_vec(),
    });
    let (status, _, body) =
        collect(recorded.broker().execute_front_door(mixed).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "Codewire: this request carries the Codewire placeholder and another credential; send only one.\n"
    );
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// The loopback Codex route keeps its base: a provider-relative path goes
/// under `/backend-api/codex`, with the sign-in, exactly as before.
#[tokio::test]
async fn a_loopback_codex_request_keeps_its_base() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        ..Recorded::default()
    };
    let mut request = cases()[0].request("");
    request.path = "/responses".into();
    let response = recorded.broker().execute(request).await.unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    let outbound = recorded.outbound();
    assert_eq!(
        outbound[0].1,
        "https://chatgpt.com/backend-api/codex/responses"
    );
    assert_eq!(
        header(&outbound[0], "chatgpt-account-id"),
        [SIGN_IN_ACCOUNT.as_bytes()]
    );
}

/// The other swap shapes carry the placeholder as Codex's own Bearer does:
/// `Token`, the Basic password, and `x-api-key` are each swapped for the
/// sign-in's Bearer, and the placeholder header is gone.
#[tokio::test]
async fn codex_s_placeholder_in_every_swap_shape_is_swapped() {
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("codex:{OURS}"));
    for (name, value) in [
        ("authorization", format!("Token {OURS}")),
        ("authorization", format!("Basic {basic}")),
        ("x-api-key", OURS.to_owned()),
    ] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            codex_sign_in: true,
            ..Recorded::default()
        };
        let mut request = codex("GET", "/backend-api/wham/usage", None);
        request.headers.push(v1::CredentialHttpHeader {
            name: name.into(),
            value: value.clone().into_bytes(),
        });
        let response = recorded.broker().execute_front_door(request).await.unwrap();
        assert_eq!(collect(response).await.0, StatusCode::OK, "{name}: {value}");
        assert_eq!(recorded.leases(), 1);
        let outbound = recorded.outbound();
        let authorization = header(&outbound[0], "authorization");
        assert_eq!(authorization.len(), 1, "{name}: {value}");
        assert!(
            authorization[0].starts_with(b"Bearer ey"),
            "{name}: {value}"
        );
        assert!(header(&outbound[0], "x-api-key").is_empty());
        assert!(
            outbound[0]
                .2
                .iter()
                .all(|(_, value)| !contains(value, OURS))
        );
    }
}

/// Another environment's placeholder takes the lease, does not match it, and
/// reaches chatgpt.com as Codex sent it, unredacted.
#[tokio::test]
async fn another_environments_codex_placeholder_is_forwarded_untouched() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        ..Recorded::default()
    };
    let response = recorded
        .broker()
        .execute_front_door(codex(
            "GET",
            "/backend-api/wham/usage",
            Some(format!("Bearer {THEIRS}")),
        ))
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    assert_eq!(recorded.leases(), 1);
    let outbound = recorded.outbound();
    assert_eq!(
        header(&outbound[0], "authorization"),
        [format!("Bearer {THEIRS}").as_bytes()]
    );
    assert_eq!(
        header(&outbound[0], "chatgpt-account-id"),
        [&b"guest-named-account"[..]]
    );
}

/// A swapped reply that echoes the sign-in's Bearer has it redacted, in its
/// headers and body. The account id is not: the environment's own login
/// file holds it, and Codex finds its workspace in `accounts/check` by it.
#[tokio::test]
async fn a_swapped_codex_reply_redacts_the_token_and_keeps_the_account() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        echo_credential: true,
        ..Recorded::default()
    };
    let (status, headers, body) = collect(
        recorded
            .broker()
            .execute_front_door(codex(
                "GET",
                "/backend-api/wham/accounts/check",
                Some(format!("Bearer {OURS}")),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sent = recorded.outbound();
    let bearer = header(&sent[0], "authorization")[0].to_vec();
    let token = &bearer[b"Bearer ".len()..];
    let echoed = headers.get("x-echo").unwrap().as_bytes();
    assert!(!echoed.windows(token.len()).any(|window| window == token));
    assert!(!body.windows(token.len()).any(|window| window == token));
    assert!(
        contains(&body, SIGN_IN_ACCOUNT),
        "{}",
        String::from_utf8_lossy(&body)
    );
}

/// One Codex login through a loopback session, opened as the guest daemon
/// opens it.
async fn codex_login_through(
    input: &mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    output: &mut mpsc::Receiver<Payload>,
    environment_id: Uuid,
) -> codewire_workload_secrets::OpenedCodexLogin {
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    let request = v1::CodexLoginRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        deadline_unix_ms: crate::runtime::current_unix_time_ms().unwrap()
            + codewire_workload_secrets::MAX_CODEX_LOGIN_LIFETIME_MS,
    };
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
                request.clone(),
            )),
        })
        .await
        .unwrap();
    let Payload::CodexLogin(v1::CodexLoginResponse {
        result: Some(v1::codex_login_response::Result::SealedLogin(sealed)),
        ..
    }) = output.recv().await.unwrap()
    else {
        panic!("expected a sealed Codex login");
    };
    let context = codewire_workload_secrets::CodexLoginContext {
        environment_id: *environment_id.as_bytes(),
        environment_generation: GENERATION,
        request_id: *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
        deadline_unix_ms: request.deadline_unix_ms,
    };
    recipient
        .open_codex_login(
            &sealed,
            &context,
            crate::runtime::current_unix_time_ms().unwrap(),
        )
        .unwrap()
}

/// The pairing is `run_admitted_credential_bridges`' own (#3999): served
/// there beside a front door, a broker seals the loopback session's Codex
/// login with this environment's placeholder and a placeholder ID token; the
/// same broker served alone seals the sign-in's own tokens, the listed direct
/// delivery exception.
#[tokio::test]
async fn only_a_broker_beside_a_front_door_seals_a_placeholder_codex_login() {
    let environment_id = Uuid::new_v4();
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        codex_login_environment: Some(environment_id),
        ..Recorded::default()
    };
    let mut sessions = TwoSessions::start_in(&recorded, environment_id).await;
    let paired = codex_login_through(
        &sessions.loopback_input,
        &mut sessions.loopback_output,
        environment_id,
    )
    .await;
    assert_eq!(paired.login.access_token(), OURS);
    assert!(paired.login.id_token().ends_with(".codewire-placeholder"));
    assert_eq!(paired.login.account_id(), SIGN_IN_ACCOUNT);

    let (alone, input, mut output) = loopback_session(environment_id).await;
    let broker = recorded.broker();
    let runner = tokio::spawn(async move { run_admitted_credential_bridge(broker, alone).await });
    let direct = codex_login_through(&input, &mut output, environment_id).await;
    assert_ne!(direct.login.access_token(), OURS);
    assert!(direct.login.access_token().starts_with("ey"));
    assert!(direct.login.id_token().ends_with(".synthetic-signature"));
    drop(input);
    assert_eq!(runner.await.unwrap(), Err(BrokerBridgeError::Unavailable));
}

/// A broker that cannot pair with the front door its environment was started
/// with seals no agent login at all: both are refused before any lease, so
/// it never hands the environment the sign-in's tokens instead (#3999).
#[tokio::test]
async fn a_broker_whose_front_door_is_gone_refuses_every_agent_login() {
    let environment_id = Uuid::new_v4();
    let recorded = Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        codex_login_environment: Some(environment_id),
        ..Recorded::default()
    };
    let broker = recorded.broker().with_agent_logins_refused();
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    let deadline_unix_ms = crate::runtime::current_unix_time_ms().unwrap()
        + codewire_workload_secrets::MAX_CODEX_LOGIN_LIFETIME_MS;
    assert!(matches!(
        broker
            .codex_login(v1::CodexLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: recipient.public_key().to_vec(),
                deadline_unix_ms,
            })
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert!(matches!(
        broker
            .claude_login(v1::ClaudeLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: recipient.public_key().to_vec(),
                deadline_unix_ms,
            })
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert_eq!(recorded.login_leases.load(Ordering::Relaxed), 0);
    assert_eq!(recorded.leases(), 0);
}

fn claude_login_request(
    recipient: &codewire_workload_secrets::ProjectionRecipient,
) -> v1::ClaudeLoginRequest {
    v1::ClaudeLoginRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        deadline_unix_ms: crate::runtime::current_unix_time_ms().unwrap()
            + codewire_workload_secrets::MAX_CODEX_LOGIN_LIFETIME_MS,
    }
}

/// Beside the front door the Claude login's access token is this
/// environment's placeholder, never the sign-in's (#3999); the rest is the
/// sign-in's own, so Claude Code shows its plan and refreshes at its expiry.
#[tokio::test]
async fn beside_the_front_door_the_claude_login_carries_the_placeholder() {
    let environment_id = Uuid::new_v4();
    let recorded = Recorded {
        placeholder: Some(OURS),
        claude_login_environment: Some(environment_id),
        ..Recorded::default()
    };
    let broker = recorded.broker().paired_with_front_door();
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    let request = claude_login_request(&recipient);
    let sealed = broker.claude_login(request.clone()).await.unwrap();
    let context = codewire_workload_secrets::CodexLoginContext {
        environment_id: *environment_id.as_bytes(),
        environment_generation: GENERATION,
        request_id: *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
        deadline_unix_ms: request.deadline_unix_ms,
    };
    let opened = recipient
        .open_claude_login(
            &sealed,
            &context,
            crate::runtime::current_unix_time_ms().unwrap(),
        )
        .unwrap();
    let login = &opened.login;
    assert_eq!(login.access_token(), OURS);
    assert_eq!(login.subscription_type(), Some("max"));
    assert_eq!(login.rate_limit_tier(), Some("default_claude_max_20x"));
    assert!(login.expires_at_unix_ms() > crate::runtime::current_unix_time_ms().unwrap());
    assert!(!login.access_token().contains(CLAUDE_SIGN_IN_ACCESS_TOKEN));
}

/// Beside the front door, a lease without a placeholder delivers no Claude
/// login at all: never the sign-in's token in its place.
#[tokio::test]
async fn beside_the_front_door_a_claude_lease_without_a_placeholder_delivers_nothing() {
    let recorded = Recorded {
        claude_login_environment: Some(Uuid::new_v4()),
        ..Recorded::default()
    };
    let broker = recorded.broker().paired_with_front_door();
    let recipient = codewire_workload_secrets::ProjectionRecipient::new();
    assert!(matches!(
        broker.claude_login(claude_login_request(&recipient)).await,
        Err(BrokerRequestError::Denied)
    ));
}

mod github;
mod upgrade;

/// #5555: a front-door request carrying none of this environment's
/// placeholders goes untouched only to a host the policy allows by rule. A
/// broker started without that answer (`locked`, or any policy with no rule
/// for the host) refuses the user's own key, no credential and another
/// environment's placeholder alike, as `name_not_allowed`, with nothing
/// dialled. The first two take no lease; the third needs one to tell, and
/// drops it unused.
#[tokio::test]
async fn without_the_policys_answer_nothing_without_our_placeholder_is_sent() {
    for (credential, leases) in [
        (vec![("x-api-key", "sk-ant-users-own-key".to_owned())], 0),
        (Vec::new(), 0),
        (vec![("authorization", format!("Bearer {THEIRS}"))], 1),
    ] {
        for allowed in [&[][..], &["chatgpt.com"][..]] {
            let recorded = Recorded {
                placeholder: Some(OURS),
                ..Recorded::default()
            };
            let broker = recorded
                .broker_without_answer()
                .with_network_policy_allowing_hosts(allowed);
            let refused = broker
                .execute_front_door(anthropic("api.anthropic.com", &credential))
                .await;
            assert!(
                matches!(refused, Err(BrokerRequestError::NameNotAllowed)),
                "{credential:?} {allowed:?}"
            );
            assert_eq!(recorded.leases(), leases, "{credential:?}");
            assert!(recorded.outbound().is_empty(), "{credential:?}");
        }
    }
    for credential in [Some("Bearer users-own-token".to_owned()), None] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            codex_sign_in: true,
            ..Recorded::default()
        };
        let refused = recorded
            .broker_without_answer()
            .with_network_policy_allowing_hosts(["api.anthropic.com"])
            .execute_front_door(codex("GET", "/backend-api/wham/usage", credential.clone()))
            .await;
        assert!(
            matches!(refused, Err(BrokerRequestError::NameNotAllowed)),
            "{credential:?}"
        );
        assert_eq!(recorded.leases(), 0);
        assert!(recorded.outbound().is_empty());
    }
}

/// #5555: the policy's answer never stands between this environment's
/// placeholder and its own route: with no answer at all, ours is served.
#[tokio::test]
async fn our_placeholder_is_served_without_the_policys_answer() {
    let recorded = Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    };
    for broker in [
        recorded.broker_without_answer(),
        recorded
            .broker_without_answer()
            .with_untouched_forwards_refused(),
    ] {
        let (status, _, _) = collect(
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
    }
    assert_eq!(recorded.outbound().len(), 2);
}

/// #5555: a hosted broker sends nothing that lacks the Sandbox's own
/// placeholder, whatever it is told about the policy, and says so with its
/// own refusal rather than blaming the policy.
#[tokio::test]
async fn a_hosted_broker_refuses_every_request_without_our_placeholder() {
    for credential in [
        vec![("x-api-key", "sk-ant-users-own-key".to_owned())],
        Vec::new(),
        vec![("authorization", format!("Bearer {THEIRS}"))],
    ] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            ..Recorded::default()
        };
        let broker = recorded
            .broker_without_answer()
            .with_network_policy_allowing_hosts(EVERY_BOUND_HOST)
            .with_untouched_forwards_refused();
        let refused = broker
            .execute_front_door(anthropic("api.anthropic.com", &credential))
            .await;
        assert!(
            matches!(refused, Err(BrokerRequestError::SelectedCredentialOnly)),
            "{credential:?}"
        );
        assert!(recorded.outbound().is_empty(), "{credential:?}");
    }
}

/// #5215: the OpenAI API host is bound for a selected OpenAI API key, whose
/// key is served only by the base URL's loopback route. A hosted broker
/// refuses every front-door request to it by name before any lease, the
/// managed stand-in included, and dials nothing; elsewhere it keeps the
/// answer every front-door request without a swap rule gets.
#[tokio::test]
async fn a_hosted_broker_refuses_the_openai_api_host_by_name() {
    for case in cases()
        .into_iter()
        .filter(|case| case.route == "openai-api")
    {
        for credential in [
            Some("Bearer codewire-managed".to_owned()),
            Some("Bearer sk-users-own-key".to_owned()),
            None,
        ] {
            let mut request = case.request("api.openai.com");
            if let Some(value) = &credential {
                request.headers.push(v1::CredentialHttpHeader {
                    name: "authorization".into(),
                    value: value.as_bytes().to_vec(),
                });
            }
            let recorded = Recorded::default();
            let hosted = recorded
                .broker_without_answer()
                .with_network_policy_allowing_hosts(EVERY_BOUND_HOST)
                .with_untouched_forwards_refused();
            assert!(
                matches!(
                    hosted.execute_front_door(request.clone()).await,
                    Err(BrokerRequestError::SelectedCredentialOnly)
                ),
                "{} {credential:?}",
                case.slot
            );
            assert_eq!(recorded.leases(), 0);
            assert!(recorded.outbound().is_empty(), "nothing is dialled");
            assert!(matches!(
                recorded.broker().execute_front_door(request).await,
                Err(BrokerRequestError::InvalidRequest)
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Codex's routed origin (#3999 change 11)

const ROUTED: &str = "routed.chatgpt.com";
// Any public address the broker would dial; this one is on the repository's
// public-address list.
const ADMITTED: &str = "1.1.1.1";
const MODEL: &str = "/backend-api/codex/responses";
/// The account `codex()` names, which the routing reply lists beside the
/// sign-in's with an origin of its own.
const OTHER_ACCOUNT: &str = "guest-named-account";
const OTHER_ORIGIN: &str = "https://other.chatgpt.com";
const OTHER: &str = "other.chatgpt.com";

fn routed_broker(routing: &'static str) -> Recorded {
    Recorded {
        placeholder: Some(OURS),
        codex_sign_in: true,
        routing: Some(routing),
        ..Recorded::default()
    }
}

/// Codex's routing discovery carrying `credential` and naming `account`.
fn accounts_check_naming(credential: &str, account: &str) -> v1::CredentialBridgeRequest {
    let mut request = codex(
        "GET",
        super::super::routed::ACCOUNTS_CHECK_PATH,
        Some(credential.to_owned()),
    );
    for header in &mut request.headers {
        if header.name == "chatgpt-account-id" {
            header.value = account.as_bytes().to_vec();
        }
    }
    request
}

/// Codex's routing discovery with this environment's placeholder, naming
/// its own account, as Codex sends it.
fn accounts_check() -> v1::CredentialBridgeRequest {
    accounts_check_naming(&format!("Bearer {OURS}"), SIGN_IN_ACCOUNT)
}

/// A front-door request to `host`, as the front door names its admitted
/// address.
fn routed(
    host: &str,
    path: &str,
    credential: Option<String>,
    destination: &str,
) -> v1::CredentialBridgeRequest {
    let mut request = codex("POST", path, credential);
    request.intercepted_host = host.into();
    request.destination_ip = destination.into();
    request
}

/// Serves `request`, an `accounts/check`, on `session` and reads its reply
/// to the end.
async fn discover_with(
    broker: &OpenAiBroker<Authority, Upstream>,
    session: &Arc<FrontDoorSession>,
    request: v1::CredentialBridgeRequest,
) {
    let response = broker
        .execute_front_door_in(request, session)
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
}

async fn discover(broker: &OpenAiBroker<Authority, Upstream>, session: &Arc<FrontDoorSession>) {
    discover_with(broker, session, accounts_check()).await;
}

/// Once a session's `accounts/check` names a workspace origin under
/// chatgpt.com, Codex's model call there is served: swapped for the sign-in,
/// or forwarded untouched, and either way dialled at the admitted address.
#[tokio::test]
async fn the_recorded_origin_is_served_at_its_admitted_address() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover(&broker, &session).await;
    assert_eq!(session.recorded(Carried::Swapped).as_deref(), Some(ROUTED));
    let admitted: std::net::SocketAddr = format!("{ADMITTED}:443").parse().unwrap();

    let response = broker
        .execute_front_door_in(
            routed(ROUTED, MODEL, Some(format!("Bearer {OURS}")), ADMITTED),
            &session,
        )
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    let outbound = recorded.outbound();
    let sent = outbound.last().unwrap();
    assert_eq!(sent.1, format!("https://{ROUTED}{MODEL}"));
    assert!(header(sent, "authorization")[0].starts_with(b"Bearer ey"));
    assert_eq!(
        header(sent, "chatgpt-account-id"),
        [SIGN_IN_ACCOUNT.as_bytes()]
    );
    assert!(sent.2.iter().all(|(_, value)| !contains(value, OURS)));
    assert_eq!(
        recorded.pinned.lock().unwrap().last(),
        Some(&Some(admitted))
    );

    // The user's own login discovers its routing too, into its own record.
    discover_with(
        &broker,
        &session,
        accounts_check_naming("Bearer users-own", SIGN_IN_ACCOUNT),
    )
    .await;
    assert_eq!(
        session.recorded(Carried::Forwarded).as_deref(),
        Some(ROUTED)
    );
    let leases = recorded.leases();
    let response = broker
        .execute_front_door_in(
            routed(ROUTED, MODEL, Some("Bearer users-own".into()), ADMITTED),
            &session,
        )
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    assert_eq!(
        recorded.leases(),
        leases,
        "a foreign credential takes no lease"
    );
    let outbound = recorded.outbound();
    let sent = outbound.last().unwrap();
    assert_eq!(sent.1, format!("https://{ROUTED}{MODEL}"));
    assert_eq!(header(sent, "authorization"), [&b"Bearer users-own"[..]]);
    assert_eq!(
        recorded.pinned.lock().unwrap().last(),
        Some(&Some(admitted))
    );
    // The routing reply itself went to chatgpt.com, resolved as ever.
    assert_eq!(recorded.pinned.lock().unwrap()[0], None);
}

/// Under the suffix, only the recorded origin's model path at an address the
/// broker would dial is served: another name, another path, no or a
/// protected address, an encoded separator, or another session's origin is
/// refused before any lease, with nothing sent.
#[tokio::test]
async fn nothing_else_under_the_suffix_is_served() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover(&broker, &session).await;
    let (leases, sent) = (recorded.leases(), recorded.outbound().len());
    let ours = || Some(format!("Bearer {OURS}"));
    for (request, on) in [
        (
            routed("other.chatgpt.com", MODEL, ours(), ADMITTED),
            &session,
        ),
        (
            routed(ROUTED, "/backend-api/wham/usage", ours(), ADMITTED),
            &session,
        ),
        (
            routed(ROUTED, "/backend-api/codex/%2fx", ours(), ADMITTED),
            &session,
        ),
        (
            routed(ROUTED, "/backend-api/codex/%2e%2e/x", ours(), ADMITTED),
            &session,
        ),
        (routed(ROUTED, MODEL, ours(), ""), &session),
        (routed(ROUTED, MODEL, ours(), "10.0.0.1"), &session),
        (routed(ROUTED, MODEL, ours(), "127.0.0.1"), &session),
        (routed(ROUTED, MODEL, ours(), "169.254.169.254"), &session),
    ] {
        let path = request.path.clone();
        assert!(
            broker.execute_front_door_in(request, on).await.is_err(),
            "{path}"
        );
    }
    let stale = Arc::new(FrontDoorSession::default());
    assert!(
        broker
            .execute_front_door_in(routed(ROUTED, MODEL, ours(), ADMITTED), &stale)
            .await
            .is_err(),
        "another session never recorded this origin"
    );
    assert_eq!(recorded.leases(), leases);
    assert_eq!(recorded.outbound().len(), sent);
}

/// A routing reply that names NO_CONSTRAINT, chatgpt.com itself or an origin
/// outside the list records nothing, so nothing under the suffix is served.
#[tokio::test]
async fn a_reply_naming_no_routed_origin_records_nothing() {
    for routing in [
        "NO_CONSTRAINT",
        "https://chatgpt.com",
        "https://evil.example.com",
    ] {
        let recorded = routed_broker(routing);
        let broker = recorded.broker();
        let session = Arc::new(FrontDoorSession::default());
        discover(&broker, &session).await;
        assert_eq!(session.recorded(Carried::Swapped), None, "{routing}");
        assert!(
            broker
                .execute_front_door_in(
                    routed(ROUTED, MODEL, Some(format!("Bearer {OURS}")), ADMITTED),
                    &session
                )
                .await
                .is_err()
        );
    }
}

/// The environment controls every field of a loopback request, so one that
/// names an admitted address is refused before any lease.
#[tokio::test]
async fn a_loopback_request_naming_an_admitted_address_is_refused_before_any_lease() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let mut request = cases()[0].request("");
    request.destination_ip = ADMITTED.into();
    assert!(matches!(
        recorded.broker().execute(request).await,
        Err(BrokerRequestError::InvalidRequest)
    ));
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// (a) A swapped `accounts/check` is read for the credential's own account,
/// the one the broker sent, whatever account the environment named.
#[tokio::test]
async fn a_swapped_reply_is_read_for_the_credentials_own_account() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover_with(
        &broker,
        &session,
        accounts_check_naming(&format!("Bearer {OURS}"), OTHER_ACCOUNT),
    )
    .await;
    assert_eq!(session.recorded(Carried::Swapped).as_deref(), Some(ROUTED));
    assert_eq!(session.recorded(Carried::Forwarded), None);
}

/// (b) An origin recorded from a forwarded reply never admits a swapped
/// model call.
#[tokio::test]
async fn a_forwarded_record_never_admits_a_swapped_model_call() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover_with(
        &broker,
        &session,
        accounts_check_naming("Bearer users-own", OTHER_ACCOUNT),
    )
    .await;
    assert_eq!(session.recorded(Carried::Forwarded).as_deref(), Some(OTHER));
    let (leases, sent) = (recorded.leases(), recorded.outbound().len());
    for host in [OTHER, ROUTED] {
        assert!(
            broker
                .execute_front_door_in(
                    routed(host, MODEL, Some(format!("Bearer {OURS}")), ADMITTED),
                    &session
                )
                .await
                .is_err(),
            "{host}"
        );
    }
    assert_eq!(recorded.leases(), leases);
    assert_eq!(recorded.outbound().len(), sent);
}

/// (c) An origin recorded from a swapped reply never admits a forwarded
/// model call.
#[tokio::test]
async fn a_swapped_record_never_admits_a_forwarded_model_call() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover(&broker, &session).await;
    assert_eq!(session.recorded(Carried::Swapped).as_deref(), Some(ROUTED));
    let (leases, sent) = (recorded.leases(), recorded.outbound().len());
    for credential in [Some("Bearer users-own".to_owned()), None] {
        assert!(
            broker
                .execute_front_door_in(routed(ROUTED, MODEL, credential, ADMITTED), &session)
                .await
                .is_err()
        );
    }
    assert_eq!(recorded.leases(), leases);
    assert_eq!(recorded.outbound().len(), sent);
}

/// (d) A placeholder that proves after its lease not to be ours is not
/// forwarded to a routed origin the swapped record alone admits.
#[tokio::test]
async fn a_placeholder_not_ours_is_not_forwarded_on_the_swapped_record() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover(&broker, &session).await;
    let sent = recorded.outbound().len();
    assert!(matches!(
        broker
            .execute_front_door_in(
                routed(ROUTED, MODEL, Some(format!("Bearer {THEIRS}")), ADMITTED),
                &session
            )
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert_eq!(recorded.outbound().len(), sent, "nothing is sent");
    // With the forwarded record naming the same origin, it is forwarded.
    discover_with(
        &broker,
        &session,
        accounts_check_naming("Bearer users-own", SIGN_IN_ACCOUNT),
    )
    .await;
    let response = broker
        .execute_front_door_in(
            routed(ROUTED, MODEL, Some(format!("Bearer {THEIRS}")), ADMITTED),
            &session,
        )
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
    let outbound = recorded.outbound();
    assert_eq!(
        header(outbound.last().unwrap(), "authorization"),
        [format!("Bearer {THEIRS}").as_bytes()]
    );
}

/// A front-door session refuses an admitted address that is not one address
/// in text form, before any lease.
#[tokio::test]
async fn a_malformed_destination_ip_on_a_front_door_session_is_refused() {
    for malformed in [
        "not-an-address",
        "300.1.1.1",
        "1.1.1.1:443",
        " 1.1.1.1",
        "[::1]",
        "1.1.1",
    ] {
        let recorded = routed_broker("https://routed.chatgpt.com");
        for host in [ROUTED, "chatgpt.com"] {
            let refused = recorded
                .broker()
                .execute_front_door(routed(
                    host,
                    MODEL,
                    Some(format!("Bearer {OURS}")),
                    malformed,
                ))
                .await;
            assert!(
                matches!(refused, Err(BrokerRequestError::InvalidRequest)),
                "{host} {malformed:?}"
            );
        }
        assert_eq!(recorded.leases(), 0, "{malformed:?}");
        assert!(recorded.outbound().is_empty(), "{malformed:?}");
    }
}

/// When the credential behind this environment's placeholder changes, the
/// origin recorded for the old one no longer admits a model call: the
/// request is refused with nothing sent, and the record is cleared until
/// the next routing reply.
#[tokio::test]
async fn a_new_credential_never_goes_to_the_old_credentials_routed_origin() {
    let recorded = routed_broker("https://routed.chatgpt.com");
    let broker = recorded.broker();
    let session = Arc::new(FrontDoorSession::default());
    discover(&broker, &session).await;
    assert_eq!(session.recorded(Carried::Swapped).as_deref(), Some(ROUTED));
    *recorded.credential.lock().unwrap() = Some("33333333-3333-4333-8333-333333333333");
    let sent = recorded.outbound().len();
    assert!(matches!(
        broker
            .execute_front_door_in(
                routed(ROUTED, MODEL, Some(format!("Bearer {OURS}")), ADMITTED),
                &session
            )
            .await,
        Err(BrokerRequestError::Denied)
    ));
    assert_eq!(recorded.outbound().len(), sent);
    assert_eq!(session.recorded(Carried::Swapped), None);
    // The next routing reply, read for the new credential, admits it again.
    discover(&broker, &session).await;
    let response = broker
        .execute_front_door_in(
            routed(ROUTED, MODEL, Some(format!("Bearer {OURS}")), ADMITTED),
            &session,
        )
        .await
        .unwrap();
    assert_eq!(collect(response).await.0, StatusCode::OK);
}

/// Claude Code's own requests to its API host, which carry no placeholder,
/// are forwarded asking for an uncompressed answer whatever the guest asked
/// for (#6362): the transport passes on no reply in a content coding, so the
/// guest's `gzip, br` ended Claude Code's MCP registry fetch and event export
/// in a 502. Every other header is the guest's.
#[tokio::test]
async fn an_untouched_forward_asks_for_an_uncompressed_answer() {
    for (method, path) in [
        ("GET", "/api/directory/server-urls"),
        ("POST", "/api/event_logging/batch"),
    ] {
        let recorded = Recorded {
            placeholder: Some(OURS),
            ..Recorded::default()
        };
        let broker = recorded.broker();
        let mut request = anthropic(
            "api.anthropic.com",
            &[("accept-encoding", "gzip, compress, deflate, br".to_owned())],
        );
        request.method = method.into();
        request.path = path.into();
        let (status, _, _) = collect(broker.execute_front_door(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{method} {path}");
        assert_eq!(recorded.leases(), 0, "no placeholder costs no lease");
        let outbound = recorded.outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(header(&outbound[0], "accept-encoding"), [&b"identity"[..]]);
        assert_eq!(
            header(&outbound[0], "anthropic-version"),
            [&b"2023-06-01"[..]]
        );
    }
}
