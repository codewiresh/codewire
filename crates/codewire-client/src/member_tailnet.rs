//! Mesh-owned member TCP transport. This never selects a primary environment,
//! spawns an owner, retries an enrollment, or falls back to WebSocket/SSH.
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, ensure};
use codewire_tailnet::conn::{Conn, Options, PeerPath};
use codewire_tailnet::derp_transport::{
    DerpTarget, DerpTransport, connect_derp_transport, connect_derp_transport_absolute,
};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::DiscoPrivate;
use codewire_tailnet::netstack::{TcpListener, TcpStream};
use codewire_tailnet::node::{Node, NodePublic, prefix_from_uuid};
use codewire_tailnet::wg::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::{
    CodewireClient, CoordinatorHandlers, MeshCoordinateIdentity, MeshCoordinatorPeerSession,
};

pub const HOST_MEMBER_PORT: u16 = 7769;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PEERS: usize = 64;

#[derive(Clone, Copy)]
enum MemberSetupPhase {
    Peer,
    Dial,
}

fn member_setup_error(phase: MemberSetupPhase, error: crate::coordinator::Error) -> anyhow::Error {
    use crate::coordinator::Error;
    let phase = match phase {
        MemberSetupPhase::Peer => "peer",
        MemberSetupPhase::Dial => "dial",
    };
    let (class, rpc) = match error {
        Error::Credential(_) => ("credential", "none"),
        Error::Connect(error) => ("connect", error.code.as_str()),
        Error::Json(_) => ("json", "none"),
        Error::Url(_) => ("url", "none"),
        Error::SetupTimeout(_) => ("setup_timeout", "none"),
        Error::InvalidSetupResponse => ("invalid_setup_response", "none"),
        Error::DerpMapTooLarge => ("derp_map_too_large", "none"),
        Error::Trust => ("trust", "none"),
    };
    // Ordinary CLI failures may render their entire anyhow source chain. Do
    // not retain the original error: its URL, credential, RPC message/details,
    // headers or JSON context are outside this closed diagnostic boundary.
    anyhow::Error::new(MemberSetupError { phase, class, rpc })
}

/// Why a member's coordinate setup failed, as closed labels only: the phase,
/// the error class, and the Connect code name (`none` without one). A caller
/// that must tell refusals apart downcasts to it; nothing dynamic is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("member Mesh {phase} setup failed: class={class} rpc={rpc}")]
pub struct MemberSetupError {
    pub phase: &'static str,
    pub class: &'static str,
    pub rpc: &'static str,
}

/// Policy is explicit; a disabled direct path still uses the real TLS DERP
/// transport, not a packet shim. Production TLS remains certificate-verified.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemberTransportOptions {
    pub derp_only: bool,
    /// Look up the Mesh origin, DERP and STUN hosts as absolute DNS names, so
    /// a Pod resolver's search domains are never tried (#2701). TLS and the
    /// HTTP authority keep the names as configured.
    pub absolute_dns: bool,
}

pub struct MemberTailnet {
    conn: Arc<Conn>,
    peers: watch::Receiver<Vec<Node>>,
    coordinator_task: tokio::task::JoinHandle<()>,
    direct: Option<direct_udp::Handle>,
    refused: Arc<AtomicBool>,
}

impl MemberTailnet {
    pub async fn dial(
        client: &CodewireClient,
        org: &str,
        network: &str,
        target_node: &str,
        options: MemberTransportOptions,
    ) -> anyhow::Result<Self> {
        let mut coordinator = client
            .connect_mesh_coordinator_with_setup_timeout(
                MeshCoordinateIdentity::dial(org, network),
                SETUP_TIMEOUT,
            )
            .await
            .map_err(|error| member_setup_error(MemberSetupPhase::Dial, error))?;
        coordinator
            .subscribe(target_node)
            .await
            .context("member subscription failed")?;
        Self::assemble(
            coordinator,
            Uuid::new_v4(),
            StaticSecret::random_from_rng(OsRng),
            options,
            client.config.mesh_url().scheme() == "http" && is_loopback(client.config.mesh_url()),
        )
        .await
    }

    /// Enrollment is consumed by this one coordinate connection only.
    pub async fn peer(
        origin: &str,
        enrollment: &str,
        org: &str,
        network: &str,
        environment_id: Uuid,
        secret: StaticSecret,
        options: MemberTransportOptions,
    ) -> anyhow::Result<Self> {
        let origin_url = url::Url::parse(origin).context("invalid member Mesh origin")?;
        let identity = MeshCoordinateIdentity::peer(org, network);
        let coordinator = if options.absolute_dns {
            let host = origin_url
                .host_str()
                .context("member Mesh origin needs a host")?;
            let port = origin_url
                .port_or_known_default()
                .context("member Mesh origin needs a port")?;
            let addresses = tokio::net::lookup_host((
                codewire_tailnet::dns::absolute_dns_name(host).as_ref(),
                port,
            ))
            .await
            .context("resolve the member Mesh origin")?
            .collect::<Vec<_>>();
            MeshCoordinatorPeerSession::connect_resolved_with_setup_timeout(
                origin,
                enrollment,
                identity,
                addresses,
                SETUP_TIMEOUT,
            )
            .await
        } else {
            MeshCoordinatorPeerSession::connect_with_setup_timeout(
                origin,
                enrollment,
                identity,
                SETUP_TIMEOUT,
            )
            .await
        }
        .map_err(|error| member_setup_error(MemberSetupPhase::Peer, error))?;
        Self::assemble(
            coordinator,
            environment_id,
            secret,
            options,
            origin_url.scheme() == "http" && is_loopback(&origin_url),
        )
        .await
    }

    async fn assemble(
        mut coordinator: MeshCoordinatorPeerSession,
        id: Uuid,
        secret: StaticSecret,
        options: MemberTransportOptions,
        local_fixture_origin: bool,
    ) -> anyhow::Result<Self> {
        let map = coordinator
            .take_setup_derp_map()
            .context("member DERP map missing")?;
        let target = member_derp_target(&map, local_fixture_origin)?;
        let fallback = if options.absolute_dns {
            connect_derp_transport_absolute(&target, &secret).await
        } else {
            connect_derp_transport(&target, &secret).await
        }
        .context("member TLS DERP connection failed")?;
        let disco = DiscoPrivate::generate(&mut OsRng);
        let public = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
        let (transport, direct) = if options.derp_only {
            (fallback, None)
        } else {
            let mut servers = crate::tailnet::stun_servers_from_map(Some(&map));
            if options.absolute_dns {
                for server in &mut servers {
                    server.host =
                        codewire_tailnet::dns::absolute_dns_name(&server.host).into_owned();
                }
            }
            let stun = crate::tailnet::resolve_stun_servers(servers)
                .await
                .context("member STUN map resolution failed")?;
            let (transport, handle) = direct_udp::wrap_transport(
                fallback,
                direct_udp::Options::new(
                    "0.0.0.0:0".parse().expect("fixed UDP bind"),
                    Vec::new(),
                    public,
                    disco.clone(),
                )
                .with_stun_servers(stun),
            )
            .await
            .context("member direct UDP setup failed")?;
            (transport, Some(handle))
        };
        let mut config = Options::new(id);
        config.addresses = vec![prefix_from_uuid(&id)];
        config.endpoints = direct
            .as_ref()
            .map(|handle| handle.advertised_endpoints())
            .unwrap_or_default();
        config.private_key = Some(secret);
        config.disco_private = Some(disco);
        let conn = Arc::new(Conn::new(config, transport).context("member WireGuard setup failed")?);
        conn.set_preferred_derp(1);
        let (updates, update_rx) = mpsc::unbounded_channel();
        conn.set_node_callback(move |node| {
            let _ = updates.send(node.clone());
        });
        let (peer_tx, peers) = watch::channel(Vec::new());
        let refused = Arc::new(AtomicBool::new(false));
        let peer_refused = Arc::clone(&refused);
        let map_refused = Arc::clone(&refused);
        let task_conn = Arc::clone(&conn);
        let map_conn = Arc::clone(&conn);
        let coordinator_task = tokio::spawn(async move {
            let update_conn = Arc::clone(&task_conn);
            let _ = coordinator
                .run_with_node_updates(
                    update_rx,
                    CoordinatorHandlers {
                        on_peers: move |nodes| {
                            let mut keys = HashSet::new();
                            let valid = nodes.len() <= MAX_PEERS
                                && nodes.iter().all(|node| {
                                    keys.insert(*node.key.as_bytes()) && node.addresses.len() <= 16
                                });
                            if valid && update_conn.update_peers(nodes).is_ok() {
                                let _ = peer_tx.send(nodes.to_vec());
                            } else {
                                peer_refused.store(true, Ordering::Release);
                                update_conn.close();
                                let _ = peer_tx.send(Vec::new());
                            }
                        },
                        on_derp_map: move |current| {
                            if current != &map {
                                map_refused.store(true, Ordering::Release);
                                map_conn.close();
                            }
                        },
                    },
                )
                .await;
            task_conn.close();
        });
        Ok(Self {
            conn,
            peers,
            coordinator_task,
            direct,
            refused,
        })
    }

    fn ready(&self) -> anyhow::Result<()> {
        ensure!(
            !self.coordinator_task.is_finished(),
            "member coordinate owner is unavailable"
        );
        ensure!(
            !self.refused.load(Ordering::Acquire),
            "member topology was refused"
        );
        Ok(())
    }

    /// The member's tailnet connection, to serve its own ports on.
    pub fn conn(&self) -> Arc<Conn> {
        Arc::clone(&self.conn)
    }

    pub async fn listen_member(&self) -> anyhow::Result<TcpListener> {
        self.ready()?;
        self.conn
            .listen("tcp", ":7769")
            .await
            .context("member listener failed")
    }

    pub async fn dial_member(
        &mut self,
        key: [u8; 32],
        environment: Uuid,
    ) -> anyhow::Result<(TcpStream, Node)> {
        let expected = prefix_from_uuid(&environment);
        let peer = tokio::time::timeout(SETUP_TIMEOUT, async {
            loop {
                self.ready()?;
                let current = self.peers.borrow().clone();
                let matching = current
                    .iter()
                    .filter(|node| node.key.as_bytes() == &key)
                    .collect::<Vec<_>>();
                ensure!(matching.len() <= 1, "member full key is ambiguous");
                if let Some(node) = matching.first() {
                    ensure!(
                        node.addresses.iter().any(|prefix| prefix == &expected),
                        "member key/address binding changed"
                    );
                    return Ok::<_, anyhow::Error>((*node).clone());
                }
                self.peers
                    .changed()
                    .await
                    .context("member peer owner closed")?;
            }
        })
        .await
        .context("member peer wait timed out")??;
        let stream = tokio::time::timeout(
            SETUP_TIMEOUT,
            self.conn
                .dial_context_tcp(SocketAddr::new(expected.addr(), HOST_MEMBER_PORT)),
        )
        .await
        .context("member TCP dial timed out")?
        .context("member TCP dial failed")?;
        self.ready()?;
        Ok((stream, peer))
    }

    pub fn path(&self, peer: &Node) -> anyhow::Result<PeerPath> {
        self.ready()?;
        self.conn
            .probe_peer_path(peer)
            .context("member path unavailable")
    }

    pub fn has_verified_direct(&self, peer: &Node) -> bool {
        self.direct
            .as_ref()
            .is_some_and(|handle| handle.has_verified_endpoint(&peer.key))
    }

    pub fn direct_stats(&self) -> Option<direct_udp::Stats> {
        self.direct.as_ref().map(direct_udp::Handle::stats)
    }

    pub fn is_ready(&self) -> bool {
        self.ready().is_ok()
    }
}

impl Drop for MemberTailnet {
    fn drop(&mut self) {
        self.conn.close();
        self.coordinator_task.abort();
    }
}

fn is_loopback(url: &url::Url) -> bool {
    url.host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

fn member_derp_target(
    map: &serde_json::Value,
    local_fixture_origin: bool,
) -> anyhow::Result<DerpTarget> {
    let mut target = crate::tailnet::derp_target_from_map(Some(map))
        .context("member requires a DERP map, without origin fallback")?;
    let allowed_fixture_tls = local_fixture_origin
        && target
            .host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
        && map
            .get("Regions")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|regions| {
                regions.values().any(|region| {
                    region
                        .get("Nodes")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|nodes| {
                            nodes.iter().any(|node| {
                                node.get("HostName").and_then(serde_json::Value::as_str)
                                    == Some(target.host.as_str())
                                    && node.get("DERPPort").and_then(serde_json::Value::as_u64)
                                        == Some(u64::from(target.port))
                                    && node
                                        .get("InsecureForTests")
                                        .and_then(serde_json::Value::as_bool)
                                        == Some(true)
                            })
                        })
                })
            });
    // A local coordinator alone cannot opt a public DERP server out of TLS
    // verification. Only its explicitly marked loopback fixture may do that.
    target.transport = DerpTransport::Tls {
        skip_verify: allowed_fixture_tls,
    };
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connectrpc::{ConnectError, ErrorCode, ErrorDetail};
    use serde_json::json;

    const DIAGNOSTIC_CANARY: &str = "cw-member-diagnostic-secret-canary";

    fn assert_closed_setup_error(error: anyhow::Error, expected: &str) {
        assert_eq!(error.to_string(), expected);
        assert_eq!(
            format!("local Mesh helper failed: {error}"),
            format!("local Mesh helper failed: {expected}")
        );
        assert_eq!(format!("{error:#}"), expected);
        assert_eq!(
            error.chain().count(),
            1,
            "dynamic sources must be discarded"
        );
        for rendered in [format!("{error:?}"), format!("{error:#?}")] {
            assert!(!rendered.contains(DIAGNOSTIC_CANARY));
        }
    }

    #[test]
    fn member_setup_diagnostic_classifies_all_errors_without_dynamic_sources() {
        use crate::coordinator::Error;
        for (phase, name) in [
            (MemberSetupPhase::Peer, "peer"),
            (MemberSetupPhase::Dial, "dial"),
        ] {
            let json_error = serde_json::from_value::<u8>(json!(DIAGNOSTIC_CANARY)).unwrap_err();
            let errors = [
                (
                    Error::Credential(crate::ClientError::new(
                        ErrorCode::Unauthenticated,
                        DIAGNOSTIC_CANARY,
                    )),
                    "credential",
                    "none",
                ),
                (
                    Error::Connect(ConnectError::permission_denied(DIAGNOSTIC_CANARY)),
                    "connect",
                    "permission_denied",
                ),
                (Error::Json(json_error), "json", "none"),
                (
                    Error::Url(format!("https://{DIAGNOSTIC_CANARY}@invalid.test")),
                    "url",
                    "none",
                ),
                (
                    Error::SetupTimeout(Duration::from_secs(u64::MAX)),
                    "setup_timeout",
                    "none",
                ),
                (
                    Error::InvalidSetupResponse,
                    "invalid_setup_response",
                    "none",
                ),
                (Error::DerpMapTooLarge, "derp_map_too_large", "none"),
                (Error::Trust, "trust", "none"),
            ];
            for (error, class, rpc) in errors {
                assert_closed_setup_error(
                    member_setup_error(phase, error),
                    &format!("member Mesh {name} setup failed: class={class} rpc={rpc}"),
                );
            }
        }
    }

    #[test]
    fn member_setup_diagnostic_rpc_code_excludes_messages_details_headers_and_trailers() {
        let codes = [
            ErrorCode::Canceled,
            ErrorCode::Unknown,
            ErrorCode::InvalidArgument,
            ErrorCode::DeadlineExceeded,
            ErrorCode::NotFound,
            ErrorCode::AlreadyExists,
            ErrorCode::PermissionDenied,
            ErrorCode::ResourceExhausted,
            ErrorCode::FailedPrecondition,
            ErrorCode::Aborted,
            ErrorCode::OutOfRange,
            ErrorCode::Unimplemented,
            ErrorCode::Internal,
            ErrorCode::Unavailable,
            ErrorCode::DataLoss,
            ErrorCode::Unauthenticated,
        ];
        for code in codes {
            let mut error = ConnectError::new(code, DIAGNOSTIC_CANARY);
            error.details.push(ErrorDetail {
                type_url: format!("https://{DIAGNOSTIC_CANARY}.invalid/detail"),
                value: Some(DIAGNOSTIC_CANARY.into()),
                debug: Some(json!({"private": DIAGNOSTIC_CANARY})),
            });
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "authorization",
                http::HeaderValue::from_static(DIAGNOSTIC_CANARY),
            );
            error.set_response_headers(headers.clone());
            error.set_trailers(headers);
            assert_closed_setup_error(
                member_setup_error(
                    MemberSetupPhase::Peer,
                    crate::coordinator::Error::Connect(error),
                ),
                &format!(
                    "member Mesh peer setup failed: class=connect rpc={}",
                    code.as_str()
                ),
            );
        }
    }

    #[tokio::test]
    async fn member_setup_diagnostic_is_used_by_actual_dial_failure_path() {
        struct RefusedCredential;
        #[async_trait::async_trait]
        impl crate::TokenProvider for RefusedCredential {
            async fn token(&self) -> Result<crate::BearerToken, crate::ClientError> {
                Err(crate::ClientError::new(
                    ErrorCode::Unauthenticated,
                    DIAGNOSTIC_CANARY,
                ))
            }
        }
        let client = CodewireClient::new(
            crate::ClientConfig::new("http://127.0.0.1:9").unwrap(),
            RefusedCredential,
        )
        .unwrap();
        let error = MemberTailnet::dial(
            &client,
            "org",
            "network",
            "target",
            MemberTransportOptions::default(),
        )
        .await
        .err()
        .expect("credential refusal before transport");
        assert_closed_setup_error(
            error,
            "member Mesh dial setup failed: class=credential rpc=none",
        );
    }

    #[tokio::test]
    async fn member_setup_diagnostic_is_used_by_actual_peer_failure_path() {
        let error = MemberTailnet::peer(
            &format!("{DIAGNOSTIC_CANARY}://127.0.0.1"),
            DIAGNOSTIC_CANARY,
            "org",
            "network",
            Uuid::new_v4(),
            StaticSecret::random_from_rng(OsRng),
            MemberTransportOptions::default(),
        )
        .await
        .err()
        .expect("unsupported URL before transport");
        assert_closed_setup_error(error, "member Mesh peer setup failed: class=url rpc=none");
    }

    fn map(host: &str, fixture: bool) -> serde_json::Value {
        json!({"Regions":{"1":{"Nodes":[{
            "HostName":host,"DERPPort":24443,"InsecureForTests":fixture
        }]}}})
    }

    #[test]
    fn member_tls_fixture_requires_selected_loopback_ip_and_local_origin() {
        for host in ["127.0.0.1", "::1"] {
            let target = member_derp_target(&map(host, true), true).unwrap();
            assert_eq!(target.host, host);
            assert_eq!(target.port, 24443);
            assert_eq!(target.transport, DerpTransport::Tls { skip_verify: true });
        }
        for host in ["192.0.2.1", "derp.example.test", "localhost"] {
            // Even an explicit insecure marker delivered by a local fixture
            // cannot disable certificate verification for this selected host.
            let target = member_derp_target(&map(host, true), true).unwrap();
            assert_eq!(target.host, host);
            assert_eq!(target.transport, DerpTransport::Tls { skip_verify: false });
        }
        for (fixture, local_origin) in [(false, true), (true, false)] {
            let target = member_derp_target(&map("127.0.0.1", fixture), local_origin).unwrap();
            assert_eq!(target.transport, DerpTransport::Tls { skip_verify: false });
        }
        assert!(member_derp_target(&json!({}), true).is_err());
    }
}
