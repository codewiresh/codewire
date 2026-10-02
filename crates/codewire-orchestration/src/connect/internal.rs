//! Connect-RPC adapters for the cluster-local `codewire.internal.v1` surface.
//!
//! The binding service authenticates an exact-audience, Pod-bound Kubernetes
//! service-account token before it performs any Pod or environment lookup.

use std::sync::Arc;

use codewire_proto::codewire::internal::v1::{
    DirectUdpTransport as ProtoDirectUdpTransport, EndpointList as ProtoEndpointList,
    GatewayBindingService, IssueGatewayBindingRequest, IssueGatewayBindingResponse,
    IssueGatewayDaemonCredentialRequest, IssueGatewayDaemonCredentialResponse,
    PeerRelayTransport as ProtoPeerRelayTransport, RuntimeTransport as ProtoRuntimeTransport,
};
use codewire_server_core::AppError;
use codewire_server_core::connect::rpc_app_error;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::internal::{
    GatewayBinding, issue_gateway_binding_core, issue_gateway_daemon_credential_core,
};
use crate::gateway_binding_identity::{
    GatewayBindingAuthenticator, GatewayBindingIdentityError, KubernetesGatewayBindingAuthenticator,
};
use crate::runtime_transport::{
    DirectUdpTransport, EndpointList, PeerRelayTransport, RuntimeTransportBinding,
};

/// Registers the projected-Kubernetes-identity binding command.
pub fn gateway_binding_router(state: ApiState) -> connectrpc::Router {
    let authenticator = Arc::new(KubernetesGatewayBindingAuthenticator::new(
        state.kube.clone(),
    ));
    connectrpc::Router::new().add_service(Arc::new(GatewayBindingConnectService {
        state,
        authenticator,
    }))
}

struct GatewayBindingConnectService {
    state: ApiState,
    authenticator: Arc<dyn GatewayBindingAuthenticator>,
}

#[allow(refining_impl_trait)]
impl GatewayBindingService for GatewayBindingConnectService {
    async fn issue_gateway_binding(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, IssueGatewayBindingRequest>,
    ) -> ServiceResult<IssueGatewayBindingResponse> {
        let identity = self
            .authenticator
            .authenticate(ctx.headers())
            .await
            .map_err(|error| gateway_binding_identity_rpc_error(error, &ctx))?;
        let binding = issue_gateway_binding_core(&self.state, &identity)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(proto_gateway_binding(binding))
    }

    /// The daemon credential for the environment's bound workspace Pod. The
    /// projected identity is reviewed first; the ownership-chain check and
    /// binding lookup live in the shared service layer.
    async fn issue_gateway_daemon_credential(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, IssueGatewayDaemonCredentialRequest>,
    ) -> ServiceResult<IssueGatewayDaemonCredentialResponse> {
        let identity = self
            .authenticator
            .authenticate(ctx.headers())
            .await
            .map_err(|error| gateway_binding_identity_rpc_error(error, &ctx))?;
        let credential = issue_gateway_daemon_credential_core(&self.state, &identity)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(IssueGatewayDaemonCredentialResponse {
            daemon_credential: credential.daemon_credential,
            workspace_pod_uid: credential.workspace_pod_uid,
            ..Default::default()
        })
    }
}

fn gateway_binding_identity_rpc_error(
    error: GatewayBindingIdentityError,
    ctx: &RequestContext,
) -> connectrpc::ConnectError {
    let error = match error {
        GatewayBindingIdentityError::Unauthenticated => AppError::Unauthorized,
        GatewayBindingIdentityError::PermissionDenied => AppError::Forbidden,
        GatewayBindingIdentityError::Unavailable => {
            AppError::ServiceUnavailable("gateway binding identity verification unavailable".into())
        }
    };
    rpc_app_error(&error, ctx)
}

fn proto_gateway_binding(binding: GatewayBinding) -> IssueGatewayBindingResponse {
    IssueGatewayBindingResponse {
        environment_id: binding.environment_id,
        sidecar_token: binding.sidecar_token,
        workspace_pod_ip: binding.workspace_pod_ip.unwrap_or_default(),
        app_ports: binding.app_ports,
        runtime_transport: binding
            .runtime_transport
            .map(proto_runtime_transport)
            .into(),
        ..Default::default()
    }
}

fn proto_runtime_transport(value: RuntimeTransportBinding) -> ProtoRuntimeTransport {
    ProtoRuntimeTransport {
        runtime_region: value.runtime_region,
        transport_zone: value.transport_zone,
        peer_relay: value.peer_relay.map(proto_peer_relay).into(),
        direct_udp: value.direct_udp.map(proto_direct_udp).into(),
        stun: value.stun.map(proto_endpoint_list).into(),
        derp: value.derp.map(proto_endpoint_list).into(),
        ..Default::default()
    }
}

fn proto_peer_relay(value: PeerRelayTransport) -> ProtoPeerRelayTransport {
    ProtoPeerRelayTransport {
        public_endpoints: value.public_endpoints,
        dns: value.dns,
        allocator_url: value.allocator_url,
        bind_addrs: value.bind_addrs,
        ..Default::default()
    }
}

fn proto_direct_udp(value: DirectUdpTransport) -> ProtoDirectUdpTransport {
    ProtoDirectUdpTransport {
        vip: value.vip,
        port_start: value.port_start,
        port_end: value.port_end,
        ..Default::default()
    }
}

fn proto_endpoint_list(value: EndpointList) -> ProtoEndpointList {
    ProtoEndpointList {
        endpoints: value.endpoints,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_binding_identity_failures_keep_distinct_connect_codes() {
        let context = RequestContext::new(Default::default());
        assert_eq!(
            gateway_binding_identity_rpc_error(
                GatewayBindingIdentityError::Unauthenticated,
                &context,
            )
            .code,
            connectrpc::ErrorCode::Unauthenticated
        );
        assert_eq!(
            gateway_binding_identity_rpc_error(
                GatewayBindingIdentityError::PermissionDenied,
                &context,
            )
            .code,
            connectrpc::ErrorCode::PermissionDenied
        );
        assert_eq!(
            gateway_binding_identity_rpc_error(GatewayBindingIdentityError::Unavailable, &context)
                .code,
            connectrpc::ErrorCode::Unavailable
        );
    }

    #[test]
    fn runtime_transport_conversion_preserves_every_optional_surface() {
        const MARKER: &str = "synthetic-sidecar-token-canary";
        let binding = GatewayBinding {
            environment_id: "env-1".to_string(),
            sidecar_token: MARKER.to_string(),
            workspace_pod_ip: Some("10.0.0.3".to_string()),
            app_ports: vec![3000],
            runtime_transport: Some(RuntimeTransportBinding {
                runtime_region: "ams".to_string(),
                transport_zone: "prod-node-1".to_string(),
                peer_relay: Some(PeerRelayTransport {
                    public_endpoints: vec!["203.0.113.10:3478".to_string()],
                    dns: Some("relay.example.test".to_string()),
                    allocator_url: "https://allocator.example.test".to_string(),
                    bind_addrs: vec!["0.0.0.0:3478".to_string()],
                }),
                direct_udp: Some(DirectUdpTransport {
                    vip: Some("198.51.100.2".to_string()),
                    port_start: Some(40000),
                    port_end: Some(40100),
                }),
                stun: Some(EndpointList {
                    endpoints: vec!["stun.example.test:3478".to_string()],
                }),
                derp: Some(EndpointList {
                    endpoints: vec!["https://derp.example.test".to_string()],
                }),
            }),
        };

        let debug = format!("{binding:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(MARKER));

        let proto = proto_gateway_binding(binding);
        let transport = proto
            .runtime_transport
            .as_option()
            .expect("transport is present");
        assert_eq!(transport.runtime_region, "ams");
        assert_eq!(transport.transport_zone, "prod-node-1");
        assert_eq!(
            transport.peer_relay.as_option().unwrap().dns,
            Some("relay.example.test".to_string())
        );
        assert_eq!(
            transport.direct_udp.as_option().unwrap().port_end,
            Some(40100)
        );
        assert_eq!(
            transport.stun.as_option().unwrap().endpoints,
            ["stun.example.test:3478"]
        );
        assert_eq!(
            transport.derp.as_option().unwrap().endpoints,
            ["https://derp.example.test"]
        );
    }
}
