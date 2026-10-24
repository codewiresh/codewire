//! Hosted environment members end to end (#3350): Mesh against a scripted
//! orchestration that serves `EnvironmentMeshService` behind the real
//! service-only boundary, over TLS, with the same derived key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use codewire_proto::codewire::internal::v1::{
    CheckEnvironmentMembersRequest, CheckEnvironmentMembersResponse, EnvironmentMeshMember,
    EnvironmentMeshMemberStatus, EnvironmentMeshService, MeshAuthorizationContext,
    MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind, MeshAuthorizationService,
    MeshCoordinateHello, MeshCoordinateRole, MeshCoordinatorServiceClient,
    MeshCoordinatorServiceCoordinateRequest, MeshCoordinatorServiceCoordinateResponse,
    RedeemEnvironmentEnrollmentRequest, RedeemEnvironmentEnrollmentResponse,
    ResolveMeshAuthorizationRequest, ResolveMeshAuthorizationResponse,
    mesh_coordinator_service_coordinate_request, mesh_coordinator_service_coordinate_response,
};
use codewire_proto::codewire::v1::{
    DeleteMeshNetworkRequest, MeshNetworkServiceClient, MeshNodeServiceClient, OrgRole,
    RevokeMeshNodeRequest,
};
use codewire_server_core::connect::InternalServiceLayer;
use codewire_server_core::http::AppBuilder;
use connectrpc::client::{BidiStream, ClientConfig, ClientTransport, HttpClient};
use connectrpc::{ConnectError, ErrorCode, RequestContext, ServiceRequest, ServiceResult};

use super::*;
use crate::config::{Config, MeshAuthorizationConfig};
use crate::server::AppState;
use crate::store::{MemoryStore, MeshStore, NETWORK_ROLE_MEMBER, NetworkMember, NodeRecord};

const SECRET: &str = "synthetic-internal-secret";
const ORG: &str = "org-test";
const NETWORK: &str = "network-test";
const OWNER: &str = "user-owner";
const MEMBER: &str = "user-member";
const ENV: &str = "env-1";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";

fn code(n: u8) -> String {
    format!(
        "{ENVIRONMENT_ENROLLMENT_PREFIX}{}",
        format!("{n:02x}").repeat(32)
    )
}

fn member(environment: &str, node: &str, attached_by: &str) -> EnvironmentMember {
    EnvironmentMember {
        environment_id: environment.to_owned(),
        org_id: ORG.to_owned(),
        network_id: NETWORK.to_owned(),
        node_name: node.to_owned(),
        pod_uid: POD.to_owned(),
        operation_generation: 3,
        attached_by_user_id: attached_by.to_owned(),
    }
}

/// What the scripted orchestration answers.
#[derive(Default)]
struct Script {
    /// Unused codes and the member each admits.
    codes: HashMap<String, EnvironmentMember>,
    /// Status by (environment, Pod); absent is live.
    statuses: HashMap<(String, String), MemberStatus>,
    unavailable: bool,
    checks: usize,
}

#[derive(Clone)]
struct EnvironmentMesh(Arc<Mutex<Script>>);

#[allow(refining_impl_trait)]
impl EnvironmentMeshService for EnvironmentMesh {
    async fn redeem_environment_enrollment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RedeemEnvironmentEnrollmentRequest>,
    ) -> ServiceResult<RedeemEnvironmentEnrollmentResponse> {
        let request = request.to_owned_message();
        let mut script = self.0.lock().unwrap();
        if script.unavailable {
            return Err(ConnectError::unavailable("scripted"));
        }
        let admitted = script
            .codes
            .remove(&request.enrollment_code)
            .filter(|member| {
                member.org_id == request.org_id && member.network_id == request.network_id
            });
        let Some(member) = admitted else {
            return Err(ConnectError::permission_denied("not admitted"));
        };
        connectrpc::Response::ok(RedeemEnvironmentEnrollmentResponse {
            member: Some(EnvironmentMeshMember {
                environment_id: member.environment_id,
                org_id: member.org_id,
                network_id: member.network_id,
                node_name: member.node_name,
                pod_uid: member.pod_uid,
                operation_generation: member.operation_generation,
                attached_by_user_id: member.attached_by_user_id,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }

    async fn check_environment_members(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckEnvironmentMembersRequest>,
    ) -> ServiceResult<CheckEnvironmentMembersResponse> {
        let request = request.to_owned_message();
        let mut script = self.0.lock().unwrap();
        if script.unavailable {
            return Err(ConnectError::unavailable("scripted"));
        }
        script.checks += 1;
        let statuses = request
            .members
            .iter()
            .map(|member| {
                match script
                    .statuses
                    .get(&(member.environment_id.clone(), member.pod_uid.clone()))
                    .copied()
                    .unwrap_or(MemberStatus::Live)
                {
                    MemberStatus::Live => EnvironmentMeshMemberStatus::Live,
                    MemberStatus::Stale => EnvironmentMeshMemberStatus::Stale,
                    MemberStatus::Gone => EnvironmentMeshMemberStatus::Gone,
                }
                .into()
            })
            .collect();
        connectrpc::Response::ok(CheckEnvironmentMembersResponse {
            statuses,
            ..Default::default()
        })
    }
}

/// Resolves `cw_owner` and `cw_member` API keys to the network's users.
struct Authorization;

#[allow(refining_impl_trait)]
impl MeshAuthorizationService for Authorization {
    async fn resolve_mesh_authorization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ResolveMeshAuthorizationRequest>,
    ) -> ServiceResult<ResolveMeshAuthorizationResponse> {
        let forwarded = ctx
            .headers()
            .get("codewire-forwarded-authorization-bin")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(value)
                    .ok()
            })
            .and_then(|value| String::from_utf8(value).ok());
        let principal = match forwarded.as_deref() {
            Some("Bearer cw_owner") => OWNER,
            Some("Bearer cw_member") => MEMBER,
            _ => return Err(ConnectError::unauthenticated("unknown")),
        };
        connectrpc::Response::ok(ResolveMeshAuthorizationResponse {
            context: Some(MeshAuthorizationContext {
                principal_id: principal.to_owned(),
                principal_kind: MeshAuthorizationPrincipalKind::User.into(),
                org_id: request.view().org_id.to_owned(),
                role: OrgRole::Member.into(),
                credential_kind: MeshAuthorizationCredentialKind::ApiKey.into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }
}

struct Harness {
    script: Arc<Mutex<Script>>,
    store: Arc<MemoryStore>,
    state: AppState,
    address: std::net::SocketAddr,
    _pki: codewire_tls::test_support::SyntheticPki,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn harness() -> Harness {
    let script = Arc::new(Mutex::new(Script::default()));
    // Orchestration's internal listener: TLS, and the real service-only
    // boundary with this hop's derived key.
    let pki = codewire_tls::test_support::SyntheticPki::new("localhost");
    let key = codewire_server_core::internal_hmac::derive_internal_hmac_secret(
        SECRET,
        ENVIRONMENT_MESH_HMAC_LABEL,
    )
    .unwrap();
    let orchestration = AppBuilder::new("synthetic-orchestration")
        .with_unary_connect_routes_internal_service(
            connectrpc::Router::new().add_service(Arc::new(EnvironmentMesh(script.clone()))),
            InternalServiceLayer::new(key, ENVIRONMENT_MESH_CALLER, [REDEEM_METHOD, CHECK_METHOD]),
        )
        .with_connect_routes(connectrpc::Router::new().add_service(Arc::new(Authorization)))
        .into_router();
    let orchestration_address = pki.serve(orchestration).await;

    let store = Arc::new(MemoryStore::new());
    store
        .network_create_with_owner(NETWORK, ORG, OWNER, chrono::Utc::now())
        .await
        .unwrap();
    store
        .network_member_upsert(NetworkMember {
            network_id: NETWORK.to_owned(),
            subject: MEMBER.to_owned(),
            role: NETWORK_ROLE_MEMBER.to_owned(),
            created_at: chrono::Utc::now(),
            created_by: OWNER.to_owned(),
        })
        .await
        .unwrap();
    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        base_url: "http://mesh.test".to_owned(),
        derp_url: None,
        stun_servers: Vec::new(),
        database_url: None,
        mesh_authorization: Some(MeshAuthorizationConfig::for_test(
            &format!("https://localhost:{}", orchestration_address.port()),
            SECRET,
            &pki.roots,
        )),
        derp_verify_addr: None,
        local_authorization: None,
    };
    let state = AppState::new(config, store.clone());
    let app = crate::server::router_from_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        codewire_server_core::serve_with_listener_h2_keepalive(
            app,
            listener,
            codewire_server_core::Http2KeepaliveConfig::new(
                Duration::from_secs(15),
                Duration::from_secs(20),
            ),
        )
        .await
        .unwrap();
    });
    Harness {
        script,
        store,
        state,
        address,
        _pki: pki,
        server,
    }
}

type Stream = BidiStream<
    <HttpClient as ClientTransport>::ResponseBody,
    MeshCoordinatorServiceCoordinateRequest,
    codewire_proto::codewire::internal::v1::MeshCoordinatorServiceCoordinateResponseView<'static>,
>;

impl Harness {
    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    fn admit(&self, code: &str, member: EnvironmentMember) {
        self.script().codes.insert(code.to_owned(), member);
    }

    fn connect_url(&self) -> axum::http::Uri {
        format!("http://{}", self.address).parse().unwrap()
    }

    /// A peer stream presenting `bearer`, after its hello for `org`.
    async fn peer(&self, bearer: &str, org: &str, role: MeshCoordinateRole) -> Stream {
        let client = MeshCoordinatorServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(self.connect_url()).with_default_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {bearer}"),
            ),
        );
        let mut stream = client.coordinate().await.unwrap();
        stream
            .send(MeshCoordinatorServiceCoordinateRequest {
                msg: Some(mesh_coordinator_service_coordinate_request::Msg::Hello(
                    Box::new(MeshCoordinateHello {
                        org_id: org.to_owned(),
                        network_id: NETWORK.to_owned(),
                        role: role.into(),
                        ..Default::default()
                    }),
                )),
                ..Default::default()
            })
            .await
            .unwrap();
        stream
    }

    fn nodes(&self) -> MeshNodeServiceClient<HttpClient> {
        MeshNodeServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(self.connect_url())
                .with_default_header(axum::http::header::AUTHORIZATION, "Bearer cw_owner"),
        )
    }

    fn networks(&self) -> MeshNetworkServiceClient<HttpClient> {
        MeshNetworkServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(self.connect_url())
                .with_default_header(axum::http::header::AUTHORIZATION, "Bearer cw_owner"),
        )
    }

    async fn node(&self, name: &str) -> Option<NodeRecord> {
        self.store.node_get(NETWORK, name).await.unwrap()
    }
}

async fn first(stream: &mut Stream) -> Result<MeshCoordinatorServiceCoordinateResponse, ErrorCode> {
    tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("Mesh coordinate response timed out")
        .map(|message| message.expect("stream ended").to_owned_message())
        .map_err(|error| error.code)
}

async fn admitted(stream: &mut Stream) {
    let message = first(stream).await.expect("the member is admitted");
    assert!(matches!(
        message.msg,
        Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
            _
        ))
    ));
}

/// Reads past heartbeats until the stream ends. A revoked or replaced stream
/// ends cleanly; the next enrollment says why.
async fn ended(stream: &mut Stream) {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("the stream did not end");
        match next {
            Ok(Some(_)) => continue,
            Ok(None) => return,
            Err(error) => panic!("the stream ended with {error:?}"),
        }
    }
}

#[tokio::test]
async fn an_environment_joins_once_with_its_own_name_and_owner() {
    let harness = harness().await;
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    let mut stream = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut stream).await;
    let node = harness.node("app-1").await.expect("the environment's node");
    assert_eq!(node.owner_subject, "environment:env-1");
    assert_eq!(node.authorized_by, MEMBER);

    // Used once: orchestration refuses the same code again.
    let mut replay = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    assert_eq!(
        first(&mut replay).await.unwrap_err(),
        ErrorCode::Unauthenticated
    );

    // The same environment's next code (a reconnect) keeps its own row.
    harness.admit(&code(2), member(ENV, "app-1", MEMBER));
    let mut reconnect = harness.peer(&code(2), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut reconnect).await;
    // The newer stream replaced the older one, which ends.
    ended(&mut stream).await;
}

#[tokio::test]
async fn refusals_name_why_the_environment_cannot_join() {
    let harness = harness().await;
    // A code is never a dial credential.
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    let mut dial = harness.peer(&code(1), ORG, MeshCoordinateRole::Dial).await;
    assert_eq!(
        first(&mut dial).await.unwrap_err(),
        ErrorCode::PermissionDenied
    );
    // Another organization's network reads as absent.
    let mut other_org = harness
        .peer(&code(1), "org-other", MeshCoordinateRole::Peer)
        .await;
    assert_eq!(
        first(&mut other_org).await.unwrap_err(),
        ErrorCode::NotFound
    );
    // The attaching user is not a member of the network.
    harness.admit(&code(2), member(ENV, "app-1", "user-outsider"));
    let mut outsider = harness.peer(&code(2), ORG, MeshCoordinateRole::Peer).await;
    assert_eq!(
        first(&mut outsider).await.unwrap_err(),
        ErrorCode::PermissionDenied
    );
    assert!(harness.node("app-1").await.is_none());
    // Another node already has the name.
    harness
        .store
        .node_register(NodeRecord {
            network_id: NETWORK.to_owned(),
            name: "taken".to_owned(),
            peer_url: String::new(),
            github_id: None,
            owner_subject: MEMBER.to_owned(),
            authorized_by: MEMBER.to_owned(),
            enrollment_id: String::new(),
            authorized_at: chrono::Utc::now(),
            last_seen_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    harness.admit(&code(3), member(ENV, "taken", MEMBER));
    let mut taken = harness.peer(&code(3), ORG, MeshCoordinateRole::Peer).await;
    assert_eq!(
        first(&mut taken).await.unwrap_err(),
        ErrorCode::AlreadyExists
    );
    assert_eq!(harness.node("taken").await.unwrap().owner_subject, MEMBER);
    // Orchestration unreachable.
    harness.script().unavailable = true;
    let mut unreachable = harness.peer(&code(4), ORG, MeshCoordinateRole::Peer).await;
    assert_eq!(
        first(&mut unreachable).await.unwrap_err(),
        ErrorCode::Unavailable
    );
    // A code is not a user credential for Mesh's product API either.
    harness.script().unavailable = false;
    let error = MeshNodeServiceClient::new(
        HttpClient::plaintext_http2_only(),
        ClientConfig::new(harness.connect_url()).with_default_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", code(5)),
        ),
    )
    .revoke_mesh_node(RevokeMeshNodeRequest {
        org_id: ORG.to_owned(),
        network_id: NETWORK.to_owned(),
        node_name: "taken".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unauthenticated);
}

#[tokio::test]
async fn an_owner_revocation_closes_the_node_and_refuses_it_for_good() {
    let harness = harness().await;
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    let mut stream = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut stream).await;
    harness
        .nodes()
        .revoke_mesh_node(RevokeMeshNodeRequest {
            org_id: ORG.to_owned(),
            network_id: NETWORK.to_owned(),
            node_name: "app-1".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    ended(&mut stream).await;
    assert!(harness.node("app-1").await.is_none());
    harness.admit(&code(2), member(ENV, "app-1", MEMBER));
    let mut again = harness.peer(&code(2), ORG, MeshCoordinateRole::Peer).await;
    assert_eq!(
        first(&mut again).await.unwrap_err(),
        ErrorCode::FailedPrecondition
    );
    assert!(harness.node("app-1").await.is_none());
}

#[tokio::test]
async fn the_recheck_ends_stale_streams_and_removes_gone_nodes() {
    let harness = harness().await;
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    harness.admit(&code(2), member("env-2", "app-2", MEMBER));
    let mut first_stream = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut first_stream).await;
    let mut second_stream = harness.peer(&code(2), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut second_stream).await;

    // Live members stay.
    recheck(&harness.state).await;
    assert_eq!(
        harness.state.mesh_coordinate.environment_sessions().len(),
        2
    );

    // env-1's Pod was replaced or stopped: its stream ends, its node stays.
    harness
        .script()
        .statuses
        .insert((ENV.to_owned(), POD.to_owned()), MemberStatus::Stale);
    recheck(&harness.state).await;
    ended(&mut first_stream).await;
    assert!(harness.node("app-1").await.is_some());

    // env-1 is destroyed: its node goes too.
    harness
        .script()
        .statuses
        .insert((ENV.to_owned(), String::new()), MemberStatus::Gone);
    recheck(&harness.state).await;
    assert!(harness.node("app-1").await.is_none());

    // The attaching user leaves the network: env-2's stream ends.
    harness
        .store
        .network_member_upsert(NetworkMember {
            network_id: NETWORK.to_owned(),
            subject: MEMBER.to_owned(),
            role: "removed".to_owned(),
            created_at: chrono::Utc::now(),
            created_by: OWNER.to_owned(),
        })
        .await
        .unwrap();
    recheck(&harness.state).await;
    ended(&mut second_stream).await;
    assert!(
        harness
            .state
            .mesh_coordinate
            .environment_sessions()
            .is_empty()
    );
}

#[tokio::test]
async fn without_an_answer_no_decision_outlives_sixty_seconds() {
    let harness = harness().await;
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    let mut stream = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut stream).await;
    harness.script().unavailable = true;
    // A recent decision survives a failed round.
    recheck(&harness.state).await;
    assert_eq!(
        harness.state.mesh_coordinate.environment_sessions().len(),
        1
    );
    // One older than the limit does not.
    let session = harness
        .state
        .mesh_coordinate
        .environment_sessions()
        .remove(0);
    let old = tokio::time::Instant::now()
        .checked_sub(RECHECK_MAX_AGE + Duration::from_secs(1))
        .unwrap();
    harness.state.mesh_coordinate.confirm_environment_session(
        session.peer_id,
        session.session_id,
        old,
    );
    recheck(&harness.state).await;
    ended(&mut stream).await;
    // An unanswered recheck never removes a node.
    assert!(harness.node("app-1").await.is_some());
}

#[tokio::test]
async fn a_destroyed_environment_never_blocks_network_deletion() {
    let harness = harness().await;
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    let mut stream = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut stream).await;
    let delete = || async {
        harness
            .networks()
            .delete_mesh_network(DeleteMeshNetworkRequest {
                org_id: ORG.to_owned(),
                network_id: NETWORK.to_owned(),
                ..Default::default()
            })
            .await
    };
    // A live environment still holds the network.
    assert_eq!(
        delete().await.unwrap_err().code,
        ErrorCode::FailedPrecondition
    );
    harness
        .script()
        .statuses
        .insert((ENV.to_owned(), String::new()), MemberStatus::Gone);
    delete().await.unwrap();
    ended(&mut stream).await;
}

fn node(byte: u8) -> codewire_tailnet::node::Node {
    let id = uuid::Uuid::new_v4();
    codewire_tailnet::node::Node {
        id,
        as_of: "2026-10-24T12:00:00Z".parse().unwrap(),
        key: codewire_tailnet::node::NodePublic::from_raw([byte; 32]),
        disco_key: codewire_tailnet::node::DiscoPublic::from_raw([byte + 1; 32]),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses: vec![codewire_tailnet::node::prefix_from_uuid(&id)],
    }
}

async fn send(stream: &mut Stream, msg: mesh_coordinator_service_coordinate_request::Msg) {
    stream
        .send(MeshCoordinatorServiceCoordinateRequest {
            msg: Some(msg),
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn publish(stream: &mut Stream, byte: u8) {
    send(
        stream,
        mesh_coordinator_service_coordinate_request::Msg::Node(Box::new(
            crate::mesh_coordinate::tailnet_node_to_proto(node(byte)).unwrap(),
        )),
    )
    .await;
}

async fn subscribe(stream: &mut Stream, target: &str) {
    send(
        stream,
        mesh_coordinator_service_coordinate_request::Msg::Subscribe(Box::new(
            codewire_proto::codewire::internal::v1::MeshCoordinateSubscribe {
                target_node: target.to_owned(),
                ..Default::default()
            },
        )),
    )
    .await;
}

/// The node key of the next peer update, past heartbeats.
async fn next_peer_key(stream: &mut Stream) -> String {
    loop {
        let message = first(stream).await.expect("the stream stays open");
        if let Some(mesh_coordinator_service_coordinate_response::Msg::PeerUpdate(update)) =
            message.msg
        {
            return update.nodes[0].key.clone();
        }
    }
}

#[tokio::test]
async fn members_reach_each_other_and_never_another_networks_node() {
    let harness = harness().await;
    harness
        .store
        .network_create_with_owner("network-other", ORG, OWNER, chrono::Utc::now())
        .await
        .unwrap();
    harness
        .store
        .network_member_upsert(NetworkMember {
            network_id: "network-other".to_owned(),
            subject: MEMBER.to_owned(),
            role: NETWORK_ROLE_MEMBER.to_owned(),
            created_at: chrono::Utc::now(),
            created_by: OWNER.to_owned(),
        })
        .await
        .unwrap();
    harness.admit(&code(1), member(ENV, "app-1", MEMBER));
    harness.admit(&code(2), member("env-2", "app-2", MEMBER));
    harness.admit(
        &code(3),
        EnvironmentMember {
            network_id: "network-other".to_owned(),
            ..member("env-3", "app-3", MEMBER)
        },
    );
    let mut first_member = harness.peer(&code(1), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut first_member).await;
    let mut second_member = harness.peer(&code(2), ORG, MeshCoordinateRole::Peer).await;
    admitted(&mut second_member).await;
    publish(&mut first_member, 0x11).await;
    publish(&mut second_member, 0x21).await;

    // app-1 reaches app-2 by name; each learns only the other.
    subscribe(&mut first_member, "app-2").await;
    let key = |byte| {
        crate::mesh_coordinate::tailnet_node_to_proto(node(byte))
            .unwrap()
            .key
    };
    assert_eq!(next_peer_key(&mut first_member).await, key(0x21));
    assert_eq!(next_peer_key(&mut second_member).await, key(0x11));

    // A member of another network names app-1 and learns nothing; app-1
    // never learns it.
    let client = MeshCoordinatorServiceClient::new(
        HttpClient::plaintext_http2_only(),
        ClientConfig::new(harness.connect_url()).with_default_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", code(3)),
        ),
    );
    let mut outsider = client.coordinate().await.unwrap();
    outsider
        .send(MeshCoordinatorServiceCoordinateRequest {
            msg: Some(mesh_coordinator_service_coordinate_request::Msg::Hello(
                Box::new(MeshCoordinateHello {
                    org_id: ORG.to_owned(),
                    network_id: "network-other".to_owned(),
                    role: MeshCoordinateRole::Peer.into(),
                    ..Default::default()
                }),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
    admitted(&mut outsider).await;
    publish(&mut outsider, 0x31).await;
    subscribe(&mut outsider, "app-1").await;
    // Only heartbeats arrive within a few seconds, on both sides.
    for stream in [&mut outsider, &mut first_member] {
        let quiet = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let message = first(stream).await.expect("the stream stays open");
                if matches!(
                    message.msg,
                    Some(mesh_coordinator_service_coordinate_response::Msg::PeerUpdate(_))
                ) {
                    return;
                }
            }
        })
        .await;
        assert!(quiet.is_err(), "a node of another network was exchanged");
    }

    // A node never subscribes to itself.
    subscribe(&mut second_member, "app-2").await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match second_member.message().await {
                    Ok(Some(_)) => continue,
                    Ok(None) => return None,
                    Err(error) => return Some(error.code),
                }
            }
        })
        .await
        .unwrap(),
        Some(ErrorCode::InvalidArgument)
    );
}
