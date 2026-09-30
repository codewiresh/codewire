use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_gateway_proto::GATEWAY_BINDING_TOKEN_PATH;
use codewire_proto::codewire::internal::v1::{
    DirectUdpTransport as ProtoDirectUdpTransport, EndpointList as ProtoEndpointList,
    GatewayBindingServiceClient, IssueGatewayBindingRequest,
    PeerRelayTransport as ProtoPeerRelayTransport, RuntimeTransport as ProtoRuntimeTransport,
};
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use connectrpc::{ConnectError, ErrorCode};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio::time::sleep;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{DEFAULT_TAILNET_UDP_LISTEN_ADDR, GatewayConfig, TailnetConfig};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_BINDING_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPollConfig {
    pub binding_url: String,
    pub coordinator_url: String,
    binding_token_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPollResult {
    pub tailnet: TailnetConfig,
    pub workspace_pod_ip: Option<String>,
    pub app_ports: Vec<u16>,
    pub runtime_transport: Option<RuntimeTransportBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportBinding {
    pub runtime_region: String,
    pub transport_zone: String,
    pub peer_relay: Option<PeerRelayTransport>,
    pub direct_udp: Option<DirectUdpTransport>,
    pub stun: Option<EndpointList>,
    pub derp: Option<EndpointList>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelayTransport {
    pub public_endpoints: Vec<String>,
    pub dns: Option<String>,
    pub allocator_url: String,
    pub bind_addrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectUdpTransport {
    pub vip: Option<String>,
    pub port_start: Option<i32>,
    pub port_end: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointList {
    pub endpoints: Vec<String>,
}

#[derive(Debug, Error)]
pub enum BindingError {
    #[error("parse gateway binding Connect base URL: {0}")]
    BaseUrl(#[from] http::uri::InvalidUri),
    #[error("poll gateway binding: {0}")]
    Connect(#[from] ConnectError),
    #[error("parse binding environment_id: {0}")]
    InvalidEnvironmentId(String),
    #[error("gateway binding identity is unavailable")]
    IdentityUnavailable,
    #[error("gateway binding identity is invalid")]
    InvalidIdentity,
}

impl BindingPollConfig {
    pub fn from_gateway_config(config: &GatewayConfig) -> Option<Self> {
        Self::from_gateway_config_parts(config)
    }

    fn from_gateway_config_parts(config: &GatewayConfig) -> Option<Self> {
        let binding_url = config
            .binding_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_string)?;
        let coordinator_url = config.coordinator_url.as_deref()?.trim();
        if coordinator_url.is_empty() {
            return None;
        }
        Some(Self {
            binding_url,
            coordinator_url: coordinator_url.into(),
            binding_token_path: PathBuf::from(GATEWAY_BINDING_TOKEN_PATH),
        })
    }

    pub(crate) fn client(&self) -> Result<GatewayBindingServiceClient<HttpClient>, BindingError> {
        let config = ClientConfig::new(self.binding_url.parse()?)
            .with_default_timeout(Duration::from_secs(5));
        Ok(GatewayBindingServiceClient::new(
            HttpClient::plaintext(),
            config,
        ))
    }
}

pub async fn poll_binding_until_ready(
    config: BindingPollConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<Option<BindingPollResult>, BindingError> {
    let client = config.client()?;

    loop {
        if *shutdown_rx.borrow() {
            return Ok(None);
        }

        match poll_binding_once(&client, &config).await {
            Ok(Some(binding)) => return Ok(Some(binding)),
            Ok(None) => {}
            Err(err) => return Err(err),
        }

        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(None);
                }
            }
            _ = sleep(POLL_INTERVAL) => {}
        }
    }
}

pub async fn poll_binding_once(
    client: &GatewayBindingServiceClient<HttpClient>,
    config: &BindingPollConfig,
) -> Result<Option<BindingPollResult>, BindingError> {
    let token = read_binding_token(&config.binding_token_path).await?;
    let options = binding_call_options(&token)?;
    let binding = match client
        .issue_gateway_binding_with_options(IssueGatewayBindingRequest::default(), options)
        .await
    {
        Ok(binding) => binding.into_owned(),
        Err(error) if binding_not_ready(&error) => return Ok(None),
        Err(error) => return Err(BindingError::Connect(error)),
    };
    let environment_id = Uuid::parse_str(&binding.environment_id)
        .map_err(|err| BindingError::InvalidEnvironmentId(err.to_string()))?;

    Ok(Some(BindingPollResult {
        tailnet: TailnetConfig {
            environment_id,
            gateway_token: binding.sidecar_token,
            coordinator_url: config.coordinator_url.clone(),
        },
        workspace_pod_ip: Some(binding.workspace_pod_ip)
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty()),
        app_ports: binding
            .app_ports
            .into_iter()
            .filter_map(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .collect(),
        runtime_transport: binding.runtime_transport.into_option().map(Into::into),
    }))
}

async fn read_binding_token(path: &Path) -> Result<Zeroizing<String>, BindingError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| BindingError::IdentityUnavailable)?;
    let mut token = Zeroizing::new(String::with_capacity(2048));
    file.take((MAX_BINDING_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut token)
        .await
        .map_err(|_| BindingError::InvalidIdentity)?;
    if token.is_empty()
        || token.len() > MAX_BINDING_TOKEN_BYTES
        || !token.is_ascii()
        || token.chars().any(char::is_whitespace)
        || token.chars().any(char::is_control)
    {
        return Err(BindingError::InvalidIdentity);
    }
    Ok(token)
}

fn binding_authorization_value(token: &str) -> Result<HeaderValue, BindingError> {
    let authorization = Zeroizing::new(format!("Bearer {token}"));
    let mut value =
        HeaderValue::try_from(authorization.as_str()).map_err(|_| BindingError::InvalidIdentity)?;
    value.set_sensitive(true);
    Ok(value)
}

fn binding_call_options(token: &str) -> Result<CallOptions, BindingError> {
    CallOptions::default()
        .try_with_header(AUTHORIZATION, binding_authorization_value(token)?)
        .map_err(|_| BindingError::InvalidIdentity)
}

fn binding_not_ready(error: &ConnectError) -> bool {
    matches!(error.code, ErrorCode::NotFound | ErrorCode::Unavailable)
}

impl From<ProtoRuntimeTransport> for RuntimeTransportBinding {
    fn from(value: ProtoRuntimeTransport) -> Self {
        Self {
            runtime_region: value.runtime_region,
            transport_zone: value.transport_zone,
            peer_relay: value.peer_relay.into_option().map(Into::into),
            direct_udp: value.direct_udp.into_option().map(Into::into),
            stun: value.stun.into_option().map(Into::into),
            derp: value.derp.into_option().map(Into::into),
        }
    }
}

impl From<ProtoPeerRelayTransport> for PeerRelayTransport {
    fn from(value: ProtoPeerRelayTransport) -> Self {
        Self {
            public_endpoints: value.public_endpoints,
            dns: value.dns,
            allocator_url: value.allocator_url,
            bind_addrs: value.bind_addrs,
        }
    }
}

impl From<ProtoDirectUdpTransport> for DirectUdpTransport {
    fn from(value: ProtoDirectUdpTransport) -> Self {
        Self {
            vip: value.vip,
            port_start: value.port_start,
            port_end: value.port_end,
        }
    }
}

impl From<ProtoEndpointList> for EndpointList {
    fn from(value: ProtoEndpointList) -> Self {
        Self {
            endpoints: value.endpoints,
        }
    }
}

impl RuntimeTransportBinding {
    pub fn apply_to_gateway_config(&self, config: &mut GatewayConfig) {
        let Some(peer_relay) = self.peer_relay.as_ref() else {
            return;
        };
        let allocator_url = peer_relay.allocator_url.trim();
        if !allocator_url.is_empty() {
            config.udp_relay_allocator_url = Some(allocator_url.to_string());
        }
        let bind_addrs: Vec<String> = peer_relay
            .bind_addrs
            .iter()
            .map(|addr| addr.trim())
            .filter(|addr| !addr.is_empty())
            .map(str::to_string)
            .collect();
        if !bind_addrs.is_empty() {
            config.udp_relay_bind_addrs = bind_addrs;
        }
        if config.tailnet_udp_listen_addr.is_none() {
            config.tailnet_udp_listen_addr =
                DEFAULT_TAILNET_UDP_LISTEN_ADDR.parse::<SocketAddr>().ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use codewire_gateway_proto::DaemonAuthToken;
    use codewire_proto::codewire::internal::v1::{
        DirectUdpTransport as ProtoDirectUdpTransport, EndpointList as ProtoEndpointList,
        GatewayBindingService, IssueGatewayBindingResponse,
        PeerRelayTransport as ProtoPeerRelayTransport, RuntimeTransport as ProtoRuntimeTransport,
    };
    use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    const SYNTHETIC_BINDING_TOKEN: &str = "synthetic.projected.binding-token";

    fn gateway_config(api_url: Option<&str>, binding_url: Option<&str>) -> GatewayConfig {
        GatewayConfig {
            shim_addr: "127.0.0.1:7777".into(),
            ssh_listen_addr: "127.0.0.1:2222".into(),
            readyz_listen_addr: "127.0.0.1:2223".into(),
            host_key_path: "/tmp/key".into(),
            listener_self_check_interval: None,
            api_url: api_url.map(str::to_string),
            binding_url: binding_url.map(str::to_string),
            coordinator_url: Some("http://coordinator:8080".into()),
            daemon_auth_token: DaemonAuthToken::new("gateway-binding-test-token").unwrap(),
            derp_url: None,
            stun: None,
            stun_servers: Vec::new(),
            tailnet_udp_listen_addr: None,
            tailnet_direct_udp_advertise_endpoints: Vec::new(),
            udp_relay_allocator_url: None,
            udp_relay_allocator_token: None,
            udp_relay_bind_addrs: Vec::new(),
            tailnet: None,
            credentials: None,
            docker_proxy: None,
            debug_tailnet: false,
        }
    }

    fn binding_config(binding_url: String) -> (BindingPollConfig, TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let binding_token_path = directory.path().join("token");
        std::fs::write(&binding_token_path, SYNTHETIC_BINDING_TOKEN).unwrap();
        (
            BindingPollConfig {
                binding_url,
                coordinator_url: "http://coordinator:8080".into(),
                binding_token_path,
            },
            directory,
        )
    }

    struct ReadyBindingService;

    #[allow(refining_impl_trait)]
    impl GatewayBindingService for ReadyBindingService {
        async fn issue_gateway_binding(
            &self,
            ctx: RequestContext,
            _request: ServiceRequest<'_, IssueGatewayBindingRequest>,
        ) -> ServiceResult<IssueGatewayBindingResponse> {
            assert_eq!(
                ctx.headers()
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer synthetic.projected.binding-token")
            );
            connectrpc::Response::ok(IssueGatewayBindingResponse {
                environment_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                sidecar_token: "test-token".into(),
                workspace_pod_ip: "10.244.0.42".into(),
                app_ports: vec![5173, 3000],
                runtime_transport: Some(ProtoRuntimeTransport {
                    runtime_region: "dev-eu".into(),
                    transport_zone: "prod-node".into(),
                    peer_relay: Some(ProtoPeerRelayTransport {
                        public_endpoints: vec!["192.0.2.35:41641".into()],
                        dns: Some("prod-node.mesh.codewire-dev.sh".into()),
                        allocator_url: "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations".into(),
                        bind_addrs: vec!["codewire-udp-relay.dev.svc.cluster.local:41641".into()],
                        ..Default::default()
                    })
                    .into(),
                    direct_udp: Some(ProtoDirectUdpTransport {
                        vip: Some("192.0.2.36".into()),
                        port_start: Some(32000),
                        port_end: Some(32031),
                        ..Default::default()
                    })
                    .into(),
                    stun: Some(ProtoEndpointList {
                        endpoints: vec!["stun.codewire-dev.sh:3478".into()],
                        ..Default::default()
                    })
                    .into(),
                    derp: Some(ProtoEndpointList {
                        endpoints: vec!["derp.codewire-dev.sh:443".into()],
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
        }
    }

    struct NotReadyBindingService;

    #[allow(refining_impl_trait)]
    impl GatewayBindingService for NotReadyBindingService {
        async fn issue_gateway_binding(
            &self,
            _ctx: RequestContext,
            _request: ServiceRequest<'_, IssueGatewayBindingRequest>,
        ) -> ServiceResult<IssueGatewayBindingResponse> {
            Err(ConnectError::not_found("binding not ready"))
        }
    }

    async fn start_binding_service(service: Arc<impl GatewayBindingService>) -> String {
        let connect = connectrpc::Router::new().add_service(service);
        let app = Router::new().fallback_service(connect.into_axum_service());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn from_gateway_config_requires_explicit_binding_url() {
        let config = gateway_config(Some("https://codewire.example"), None);

        assert!(BindingPollConfig::from_gateway_config_parts(&config).is_none());
    }

    #[test]
    fn from_gateway_config_uses_explicit_binding_url() {
        let config = gateway_config(
            Some("https://codewire.example"),
            Some("http://codewire-orchestration.dev.svc.cluster.local:8085"),
        );

        let poll =
            BindingPollConfig::from_gateway_config_parts(&config).expect("binding poll config");

        assert_eq!(
            poll.binding_url,
            "http://codewire-orchestration.dev.svc.cluster.local:8085"
        );
        assert_eq!(
            poll.binding_token_path,
            PathBuf::from(GATEWAY_BINDING_TOKEN_PATH)
        );
    }

    #[tokio::test]
    async fn poll_binding_success_builds_tailnet_config() {
        let (config, _token_directory) =
            binding_config(start_binding_service(Arc::new(ReadyBindingService)).await);
        let client = config.client().unwrap();
        let binding = poll_binding_once(&client, &config).await.unwrap().unwrap();
        let tailnet = binding.tailnet;

        assert_eq!(
            tailnet.environment_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        assert_eq!(tailnet.gateway_token, "test-token");
        assert_eq!(tailnet.coordinator_url, "http://coordinator:8080");
        assert_eq!(binding.workspace_pod_ip.as_deref(), Some("10.244.0.42"));
        assert_eq!(binding.app_ports, vec![5173, 3000]);
        let runtime_transport = binding.runtime_transport.unwrap();
        assert_eq!(runtime_transport.runtime_region, "dev-eu");
        assert_eq!(runtime_transport.transport_zone, "prod-node");
        assert_eq!(
            runtime_transport
                .peer_relay
                .as_ref()
                .unwrap()
                .public_endpoints,
            vec!["192.0.2.35:41641"]
        );
        assert_eq!(
            runtime_transport.direct_udp,
            Some(DirectUdpTransport {
                vip: Some("192.0.2.36".into()),
                port_start: Some(32000),
                port_end: Some(32031),
            })
        );
        assert_eq!(
            runtime_transport.stun,
            Some(EndpointList {
                endpoints: vec!["stun.codewire-dev.sh:3478".into()],
            })
        );
        assert_eq!(
            runtime_transport.derp,
            Some(EndpointList {
                endpoints: vec!["derp.codewire-dev.sh:443".into()],
            })
        );
    }

    #[test]
    fn runtime_transport_binding_overlays_peer_relay_gateway_config() {
        let mut config = gateway_config(
            None,
            Some("http://codewire-orchestration.dev.svc.cluster.local:8085"),
        );
        let runtime_transport = RuntimeTransportBinding {
            runtime_region: "dev-eu".into(),
            transport_zone: "prod-node".into(),
            peer_relay: Some(PeerRelayTransport {
                public_endpoints: vec!["192.0.2.35:41641".into()],
                dns: Some("prod-node.mesh.codewire-dev.sh".into()),
                allocator_url:
                    "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
                        .into(),
                bind_addrs: vec!["codewire-udp-relay.dev.svc.cluster.local:41641".into()],
            }),
            direct_udp: None,
            stun: None,
            derp: None,
        };

        runtime_transport.apply_to_gateway_config(&mut config);

        assert_eq!(
            config.udp_relay_allocator_url.as_deref(),
            Some(
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
            )
        );
        assert_eq!(
            config.udp_relay_bind_addrs,
            vec!["codewire-udp-relay.dev.svc.cluster.local:41641"]
        );
        assert_eq!(
            config.tailnet_udp_listen_addr.unwrap().to_string(),
            DEFAULT_TAILNET_UDP_LISTEN_ADDR
        );
    }

    #[tokio::test]
    async fn poll_binding_not_found_keeps_waiting() {
        let (config, _token_directory) =
            binding_config(start_binding_service(Arc::new(NotReadyBindingService)).await);
        let client = config.client().unwrap();
        assert!(poll_binding_once(&client, &config).await.unwrap().is_none());
    }

    #[test]
    fn only_not_found_and_unavailable_are_pollable() {
        assert!(binding_not_ready(&ConnectError::not_found(
            "binding not ready"
        )));
        assert!(binding_not_ready(&ConnectError::unavailable(
            "listener starting"
        )));
        assert!(!binding_not_ready(&ConnectError::new(
            ErrorCode::InvalidArgument,
            "bad request"
        )));
    }

    #[tokio::test]
    async fn binding_identity_file_is_bounded_and_canonical() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");

        for invalid in ["", " token", "token\n", "to ken", "tökén"] {
            std::fs::write(&path, invalid).unwrap();
            assert!(matches!(
                read_binding_token(&path).await,
                Err(BindingError::InvalidIdentity)
            ));
        }

        std::fs::write(&path, vec![b'a'; MAX_BINDING_TOKEN_BYTES + 1]).unwrap();
        assert!(matches!(
            read_binding_token(&path).await,
            Err(BindingError::InvalidIdentity)
        ));
        assert!(matches!(
            read_binding_token(&directory.path().join("missing")).await,
            Err(BindingError::IdentityUnavailable)
        ));
    }

    #[test]
    fn binding_authorization_metadata_is_sensitive() {
        let value = binding_authorization_value(SYNTHETIC_BINDING_TOKEN).unwrap();
        assert!(value.is_sensitive());
        assert_eq!(
            value.to_str().unwrap(),
            "Bearer synthetic.projected.binding-token"
        );
    }

    struct RecordingBindingService {
        authorizations: Arc<Mutex<Vec<String>>>,
    }

    #[allow(refining_impl_trait)]
    impl GatewayBindingService for RecordingBindingService {
        async fn issue_gateway_binding(
            &self,
            ctx: RequestContext,
            _request: ServiceRequest<'_, IssueGatewayBindingRequest>,
        ) -> ServiceResult<IssueGatewayBindingResponse> {
            self.authorizations.lock().unwrap().push(
                ctx.headers()
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned(),
            );
            connectrpc::Response::ok(IssueGatewayBindingResponse {
                environment_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                sidecar_token: "synthetic-coordinate-token".into(),
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn every_binding_poll_rereads_the_rotated_projected_token() {
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let binding_url = start_binding_service(Arc::new(RecordingBindingService {
            authorizations: authorizations.clone(),
        }))
        .await;
        let (config, _token_directory) = binding_config(binding_url);
        let client = config.client().unwrap();

        poll_binding_once(&client, &config).await.unwrap();
        std::fs::write(
            &config.binding_token_path,
            "rotated.projected.binding-token",
        )
        .unwrap();
        poll_binding_once(&client, &config).await.unwrap();

        assert_eq!(
            *authorizations.lock().unwrap(),
            [
                "Bearer synthetic.projected.binding-token",
                "Bearer rotated.projected.binding-token",
            ]
        );
    }
}
